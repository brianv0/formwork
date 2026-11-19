//! Supervised connect on a real Linux kernel (FW-EGR7, FW-ISO11, FW-ISO12, FW-ISO34): the confined
//! process's `connect()`, addressed `sendto()` and `listen()` are decided outside the sandbox. A
//! loopback listener stands in for the Gateway; counting listeners show where connections actually
//! land. Skips cleanly on a host without the facilities (`detect().connect_supervision`).

#![cfg(target_os = "linux")]

use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use formwork_blueprint::{
    Blueprint, HostRule, HostTable, NetPosture, PathPattern, ReadMode, ResolvedCatalog,
};
use formwork_compile::{Capability, CompiledPolicy, Fidelity};
use formwork_confine::SupervisorConfig;
use formwork_detect::detect;

fn supervision_available() -> bool {
    let host = detect();
    host.connect_supervision && host.seccomp && host.landlock_abi.is_some()
}

/// A test that cannot exercise its mechanism on this host says so; on a CI runner, where
/// `FW_REQUIRE_EXERCISED=1`, that is a failure rather than a skip.
fn not_exercised(reason: &str) {
    if std::env::var("FW_REQUIRE_EXERCISED").as_deref() == Ok("1") {
        panic!("not exercised on a CI runner: {reason}");
    }
    eprintln!("skipping: {reason}");
}

/// A listener that counts the connections it accepts.
struct Counting {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

impl Counting {
    fn start() -> Counting {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        std::thread::spawn(move || {
            for s in listener.incoming() {
                if s.is_ok() {
                    count.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        Counting { addr, accepted }
    }
    fn count(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Scratch {
        let p = std::env::temp_dir().join(format!("fw-sup-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Scratch(fs::canonicalize(&p).unwrap())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn subtree(p: &Path) -> PathPattern {
    PathPattern::parse(&format!("{}/**", p.display())).unwrap()
}

fn probe(name: &str) -> PathBuf {
    match name {
        "connect" => PathBuf::from(env!("CARGO_BIN_EXE_fw-connect-probe")),
        "udp" => PathBuf::from(env!("CARGO_BIN_EXE_fw-udp-probe")),
        "unix" => PathBuf::from(env!("CARGO_BIN_EXE_fw-unix-probe")),
        "race" => PathBuf::from(env!("CARGO_BIN_EXE_fw-race-probe")),
        "family" => PathBuf::from(env!("CARGO_BIN_EXE_fw-family-probe")),
        "tfo" => PathBuf::from(env!("CARGO_BIN_EXE_fw-tfo-probe")),
        "listen" => PathBuf::from(env!("CARGO_BIN_EXE_fw-listen-probe")),
        "registry" => PathBuf::from(env!("CARGO_BIN_EXE_fw-registry-probe")),
        other => panic!("no probe {other}"),
    }
}

/// A host-rule blueprint: closed reads of the probes, writes to `work` (subtree), plus any literal
/// socket grants.
fn policy(work: &Path, literal_grants: &[&Path]) -> CompiledPolicy {
    let mut bp = Blueprint::empty();
    bp.fs.read_mode = ReadMode::Closed;
    bp.fs.reads = vec![subtree(probe("connect").parent().unwrap())];
    bp.fs.writes = vec![subtree(work)];
    for g in literal_grants {
        bp.fs
            .writes
            .push(PathPattern::parse(g.to_str().unwrap()).unwrap());
    }
    let rule: HostRule = serde_json::from_str("\"tunnel:allowed.test\"").unwrap();
    bp.net = NetPosture::AllowHosts(HostTable::new(vec![rule]));
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    formwork_compile::compile(
        &bp,
        &detect(),
        &ResolvedCatalog::builtin_for_home(&home).unwrap(),
    )
}

/// Start `cmd` confined and supervised, and leave it running.
fn spawn(
    policy: &CompiledPolicy,
    gateway: SocketAddr,
    registry: Arc<Mutex<HashSet<u16>>>,
    mut cmd: Command,
) -> Child {
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let pending = formwork_confine::spawn_confined_supervised(&mut cmd, policy)
        .expect("confinement applies")
        .expect("a host-rule policy needs the supervisor");
    let child = cmd.spawn().expect("child spawns");
    let unix_grants = match &policy.confiner {
        formwork_compile::ConfinerPolicy::Linux(l) => l.unix_socket_grants.clone(),
        _ => unreachable!(),
    };
    pending
        .start(SupervisorConfig {
            gateway,
            registry,
            unix_grants,
            refused_sockets: Default::default(),
        })
        .expect("supervisor starts");
    child
}

fn run(
    policy: &CompiledPolicy,
    gateway: SocketAddr,
    registry: Arc<Mutex<HashSet<u16>>>,
    cmd: Command,
) -> i32 {
    exit_code(spawn(policy, gateway, registry, cmd))
}

fn exit_code(mut child: Child) -> i32 {
    child.wait().unwrap().code().unwrap_or(-1)
}

/// `cmd` with no confinement: the control that shows what a probe does where nothing refuses it.
fn spawn_unconfined(mut cmd: Command) -> Child {
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    cmd.spawn().expect("control spawns")
}

/// Poll for `ready` until `child` exits or 30 s pass.
fn wait_for<T>(child: &mut Child, what: &str, mut ready: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(found) = ready() {
            return found;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("the probe exited ({status}) before {what}");
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn cmd(p: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(p);
    c.args(args);
    c
}

/// FW-E2E-075 (Linux half): the Gateway listener is the sole inet destination. A connect to it
/// lands (from a registered source port); a direct connect to another loopback listener, to the
/// metadata address, and a UDP socket are each refused, and nothing reaches the other listener.
#[test]
fn fw_e2e_075_gateway_is_the_sole_egress_path() {
    if !supervision_available() {
        eprintln!("skipping: connect supervision unavailable on this host");
        return;
    }
    let work = Scratch::new("075");
    let gateway = Counting::start();
    let other = Counting::start();
    let registry = Arc::new(Mutex::new(HashSet::new()));
    let pol = policy(&work.0, &[]);
    assert!(matches!(
        pol.report.per_capability[&Capability::NetDefaultDeny],
        Fidelity::Enforced { .. }
    ));

    let to_gateway = run(
        &pol,
        gateway.addr,
        registry.clone(),
        cmd(&probe("connect"), &[&gateway.addr.to_string()]),
    );
    assert_eq!(to_gateway, 0, "the Gateway listener is reachable");
    assert!(
        !registry.lock().unwrap().is_empty(),
        "the source port was registered first (FW-EGR9)"
    );

    let direct = run(
        &pol,
        gateway.addr,
        registry.clone(),
        cmd(&probe("connect"), &[&other.addr.to_string()]),
    );
    assert_eq!(
        direct, 7,
        "a direct connect elsewhere is refused with EACCES"
    );
    let metadata = run(
        &pol,
        gateway.addr,
        registry.clone(),
        cmd(&probe("connect"), &["169.254.169.254:80"]),
    );
    assert_eq!(metadata, 7);
    let udp = run(
        &pol,
        gateway.addr,
        registry.clone(),
        cmd(&probe("udp"), &[]),
    );
    assert_eq!(udp, 7, "UDP stays closed under host rules (FW-ISO11)");
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(other.count(), 0, "nothing reached the other listener");
    assert!(gateway.count() >= 1);
}

/// FW-E2E-076: three pathname sockets. One bound outside the session (inside a writable subtree,
/// which admits no socket) is refused; one granted by a literal write grant connects; one bound by
/// the session itself connects. Addressed datagrams follow the same rule.
#[test]
fn fw_e2e_076_pathname_sockets_are_mediated() {
    if !supervision_available() {
        eprintln!("skipping: connect supervision unavailable on this host");
        return;
    }
    let work = Scratch::new("076");
    let gateway = Counting::start();
    let registry = Arc::new(Mutex::new(HashSet::new()));

    let foreign = work.0.join("foreign.sock");
    let _foreign = UnixListener::bind(&foreign).unwrap();
    let granted = work.0.join("granted.sock");
    let _granted = UnixListener::bind(&granted).unwrap();
    let foreign_dgram = work.0.join("foreign.dgram");
    let _fd = UnixDatagram::bind(&foreign_dgram).unwrap();
    let granted_dgram = work.0.join("granted.dgram");
    let _gd = UnixDatagram::bind(&granted_dgram).unwrap();
    let own = work.0.join("own.sock");

    // Controls: each out-of-session socket is live for an unconfined client.
    assert!(std::os::unix::net::UnixStream::connect(&foreign).is_ok());

    let pol = policy(&work.0, &[&granted, &granted_dgram]);
    let unix = probe("unix");
    let s = |p: &Path| p.to_str().unwrap().to_string();
    assert_eq!(
        run(
            &pol,
            gateway.addr,
            registry.clone(),
            cmd(&unix, &["connect", &s(&foreign)])
        ),
        7
    );
    assert_eq!(
        run(
            &pol,
            gateway.addr,
            registry.clone(),
            cmd(&unix, &["connect", &s(&granted)])
        ),
        0
    );
    assert_eq!(
        run(
            &pol,
            gateway.addr,
            registry.clone(),
            cmd(&unix, &["selfbind", &s(&own)])
        ),
        0
    );
    assert_eq!(
        run(
            &pol,
            gateway.addr,
            registry.clone(),
            cmd(&unix, &["sendto", &s(&foreign_dgram)])
        ),
        7
    );
    assert_eq!(
        run(
            &pol,
            gateway.addr,
            registry.clone(),
            cmd(&unix, &["sendto", &s(&granted_dgram)])
        ),
        0
    );
    let mut buf = [0u8; 4];
    _gd.set_nonblocking(true).unwrap();
    assert_eq!(
        _gd.recv(&mut buf).unwrap_or(0),
        1,
        "the granted datagram arrived"
    );
    _fd.set_nonblocking(true).unwrap();
    assert!(
        _fd.recv(&mut buf).is_err(),
        "the refused datagram never arrived"
    );
}

/// FW-ADV-018: rewriting the `sockaddr` from another thread while `connect()` is pending cannot
/// redirect the connection -- the supervisor connects to its own copy of the checked address.
#[test]
fn fw_adv_018_supervisor_race_cannot_redirect() {
    if !supervision_available() {
        eprintln!("skipping: connect supervision unavailable on this host");
        return;
    }
    let work = Scratch::new("018");
    let gateway = Counting::start();
    let denied = Counting::start();
    let registry = Arc::new(Mutex::new(HashSet::new()));
    let pol = policy(&work.0, &[]);
    let code = run(
        &pol,
        gateway.addr,
        registry,
        cmd(
            &probe("race"),
            &[&gateway.addr.to_string(), &denied.addr.to_string(), "300"],
        ),
    );
    assert_eq!(code, 0);
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(
        denied.count(),
        0,
        "a racing rewrite reached the denied listener"
    );
    assert!(
        gateway.count() > 0,
        "the race probe did connect to the allowed destination"
    );
}

/// FW-ISO28 / FW-ISO29 / FW-ISO35 under host rules, the other posture that admits stream sockets
/// (the port tier is FW-E2E-185 and FW-E2E-187 in `linux_confine.rs`): an inet socket is created
/// only as a TCP stream, and a `MSG_FASTOPEN` send to a listener the supervisor would refuse is
/// answered by the filter and reaches nothing. The supervisor sees `sendto` alone; the flag
/// refusal is what covers `sendmsg` and `sendmmsg` here.
#[test]
fn fw_iso28_fw_iso29_hold_under_supervised_connect() {
    use std::io::{Read, Write};
    if !supervision_available() {
        not_exercised("connect supervision unavailable on this host");
        return;
    }
    let work = Scratch::new("iso29");
    let gateway = Counting::start();
    let other = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let other_addr = other.local_addr().unwrap();
    let registry = Arc::new(Mutex::new(HashSet::new()));
    let pol = policy(&work.0, &[]);

    let family = run(
        &pol,
        gateway.addr,
        registry.clone(),
        cmd(&probe("family"), &["stream"]),
    );
    assert_eq!(
        family, 0,
        "host rules admit an inet socket only as a TCP stream (10+n = check n of the probe's \
         table answered wrongly); got {family}"
    );

    let tfo = run(
        &pol,
        gateway.addr,
        registry,
        cmd(&probe("tfo"), &[&other_addr.to_string()]),
    );
    assert_eq!(
        tfo, 0,
        "each MSG_FASTOPEN send must be refused with EOPNOTSUPP (40+n = send n opened a \
         connection; 80+n = another errno); got {tfo}"
    );
    // The accept queue is in arrival order: a connection from the session would come out first.
    std::net::TcpStream::connect(other_addr)
        .unwrap()
        .write_all(b"S")
        .unwrap();
    let mut first = [0u8; 1];
    other.accept().unwrap().0.read_exact(&mut first).unwrap();
    assert_eq!(
        first[0], b'S',
        "nothing from the session reached the listener"
    );
}

/// The process a connected UNIX socket's peer credentials name (`SO_PEERCRED`).
fn peer_pid(stream: &UnixStream) -> u32 {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes one ucred.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0, "SO_PEERCRED");
    cred.pid as u32
}

/// One `listen` attempt of `fw-listen-probe inet`, and whether a peer outside the session then
/// connected to the port the socket ended on.
struct Attempt {
    port: u16,
    rc: i32,
    errno: i32,
    reachable: bool,
}

const ATTEMPTS: [&str; 6] = [
    "AF_INET wildcard-bound",
    "AF_INET loopback-bound",
    "AF_INET unbound",
    "AF_INET6 wildcard-bound",
    "AF_INET6 loopback-bound",
    "AF_INET6 unbound",
];

/// Follow `fw-listen-probe inet` running as `child` in `dir`: read its report, try each port from
/// here while the probe holds the sockets open, then release it. Also returns what
/// `io_uring_setup` answered, as `(rc, errno)`.
fn inet_attempts(dir: &Path, mut child: Child) -> (Vec<Attempt>, (i32, i32)) {
    let ports = dir.join("ports");
    let report = wait_for(&mut child, "the probe's report", || {
        fs::read_to_string(&ports).ok()
    });
    let mut attempts = Vec::new();
    let mut uring = None;
    for line in report.lines() {
        let field: Vec<&str> = line.split(' ').collect();
        let int = |i: usize| field[i].parse::<i32>().unwrap();
        if field[0] == "uring" {
            uring = Some((int(1), int(2)));
            continue;
        }
        let port: u16 = field[1].parse().unwrap();
        // A wildcard AF_INET6 listener takes IPv4 peers too.
        let peers: &[IpAddr] = if attempts.len() < 3 {
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)]
        } else {
            &[
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ]
        };
        let reachable = port != 0
            && peers.iter().any(|ip| {
                TcpStream::connect_timeout(&SocketAddr::new(*ip, port), Duration::from_secs(2))
                    .is_ok()
            });
        attempts.push(Attempt {
            port,
            rc: int(2),
            errno: int(3),
            reachable,
        });
    }
    fs::write(dir.join("done"), b"").unwrap();
    assert_eq!(exit_code(child), 0, "the listen probe ran to its end");
    assert_eq!(attempts.len(), ATTEMPTS.len(), "{report}");
    (
        attempts,
        uring.expect("the report carries the io_uring line"),
    )
}

/// FW-E2E-206: under host rules no inet socket listens, so no peer outside the session connects
/// in (FW-ISO34). An unconfined control first shows each socket listening and reachable from this
/// process; an attempt the host does not carry even then (no IPv6) is reported not exercised. The
/// session is then refused `listen` on each with `EACCES` and this process cannot connect to any
/// of the ports, the unbound sockets included, which `listen` would have bound to the wildcard
/// address. A UNIX-socket listener still binds, listens and takes a peer, which sees the
/// supervisor's process in the listener's peer credentials, and the Gateway listener is still
/// reachable.
#[test]
fn fw_e2e_206_no_inet_listener_under_host_rules() {
    use std::io::Write;
    if !supervision_available() {
        not_exercised("connect supervision unavailable on this host");
        return;
    }
    let work = Scratch::new("206");
    let gateway = Counting::start();
    let registry = Arc::new(Mutex::new(HashSet::new()));
    let pol = policy(&work.0, &[]);
    let listen = probe("listen");
    let dir = |name: &str| {
        let d = work.0.join(name);
        fs::create_dir_all(&d).unwrap();
        d
    };

    let control_dir = dir("control");
    let (control, _) = inet_attempts(
        &control_dir,
        spawn_unconfined(cmd(&listen, &["inet", control_dir.to_str().unwrap()])),
    );
    let exercised: Vec<usize> = (0..ATTEMPTS.len())
        .filter(|&n| control[n].rc == 0 && control[n].reachable)
        .collect();
    if exercised.is_empty() {
        not_exercised("no inet socket listens on this host even unconfined");
        return;
    }

    let confined_dir = dir("confined");
    let (confined, uring) = inet_attempts(
        &confined_dir,
        spawn(
            &pol,
            gateway.addr,
            registry.clone(),
            cmd(&listen, &["inet", confined_dir.to_str().unwrap()]),
        ),
    );
    for &n in &exercised {
        let got = &confined[n];
        assert!(
            got.rc == -1 && got.errno == libc::EACCES,
            "listen on an {} socket must be refused with EACCES; got rc {} errno {}",
            ATTEMPTS[n],
            got.rc,
            got.errno
        );
        assert!(
            !got.reachable,
            "a peer outside the session connected to the {} socket on port {}",
            ATTEMPTS[n], got.port
        );
    }
    assert_eq!(
        uring,
        (-1, libc::EPERM),
        "io_uring stays refused: its IORING_OP_LISTEN is a listen the supervisor never sees"
    );

    let sock = work.0.join("listener.sock");
    let mut server = spawn(
        &pol,
        gateway.addr,
        registry.clone(),
        cmd(&listen, &["unix", sock.to_str().unwrap()]),
    );
    let mut peer = wait_for(&mut server, "the UNIX listener", || {
        UnixStream::connect(&sock).ok()
    });
    // The kernel stamps a listener with the credentials of the process that called listen().
    assert_eq!(
        peer_pid(&peer),
        std::process::id(),
        "the supervisor, hosted by this process, made the listen() call for the session"
    );
    peer.write_all(b"S").unwrap();
    let served = exit_code(server);
    assert_eq!(
        served, 0,
        "a UNIX-socket listener must bind, listen and take a peer (7 = listen refused; 30+k = \
         check k got another answer to listen than the kernel's); got {served}"
    );

    let to_gateway = run(
        &pol,
        gateway.addr,
        registry,
        cmd(&probe("connect"), &[&gateway.addr.to_string()]),
    );
    assert_eq!(to_gateway, 0, "the Gateway listener is still reachable");
    let deadline = Instant::now() + Duration::from_secs(5);
    while gateway.count() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(gateway.count() >= 1, "the connection landed on the Gateway");

    if exercised.len() < ATTEMPTS.len() {
        let missing: Vec<&str> = (0..ATTEMPTS.len())
            .filter(|n| !exercised.contains(n))
            .map(|n| ATTEMPTS[n])
            .collect();
        not_exercised(&format!(
            "these sockets do not listen on this host even unconfined: {}",
            missing.join(", ")
        ));
    }
}

/// FW-ISO34: `listen` takes effect on the socket whose family the supervisor read, never on
/// another one presented under the same descriptor number. The probe offers a UNIX socket to the
/// check and an inet socket to the call two ways: from a thread with its own descriptor table,
/// and by flipping the number between the two from a second thread. Unconfined, the first way
/// makes the inet socket listen, which is what the control checks.
#[test]
fn fw_iso34_listen_acts_on_the_socket_it_checked() {
    if !supervision_available() {
        not_exercised("connect supervision unavailable on this host");
        return;
    }
    let work = Scratch::new("iso34");
    let gateway = Counting::start();
    let pol = policy(&work.0, &[]);
    let dir = |name: &str| {
        let d = work.0.join(name);
        fs::create_dir_all(&d).unwrap();
        d.to_str().unwrap().to_string()
    };

    let control = exit_code(spawn_unconfined(cmd(
        &probe("listen"),
        &["swap", &dir("control"), "1"],
    )));
    if control != 21 {
        not_exercised(&format!(
            "the control did not make its inet socket listen (exit {control})"
        ));
        return;
    }
    let swapped = run(
        &pol,
        gateway.addr,
        Arc::new(Mutex::new(HashSet::new())),
        cmd(&probe("listen"), &["swap", &dir("confined"), "300"]),
    );
    assert_eq!(
        swapped, 0,
        "no inet socket may listen (21 = through a thread's own descriptor table; 22 = by \
         flipping the descriptor during the call); got {swapped}"
    );
}

/// A Gateway stand-in that sends each peer one byte once it holds the connection. With a
/// registry it first does what the Gateway's listener does on accept (FW-EGR9) and removes the
/// peer's source port; without one it stands for a Gateway that has yet to reach its accept.
fn signalling_listener(admit_from: Option<Arc<Mutex<HashSet<u16>>>>) -> SocketAddr {
    use std::io::Write;
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for mut stream in listener.incoming().flatten() {
            if let (Some(registry), Ok(peer)) = (&admit_from, stream.peer_addr()) {
                registry.lock().unwrap().remove(&peer.port());
            }
            let _ = stream.write_all(b"A");
            held.push(stream);
        }
    });
    addr
}

/// A loopback port that refuses connections for as long as the returned socket lives. The socket
/// is bound and never listens, so the port cannot be handed to a listener of another test.
fn refusing_port() -> (OwnedFd, SocketAddr) {
    // SAFETY: socket() returns a descriptor owned from here; bind and getsockname read and write
    // one sockaddr_in alive for the calls.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        assert!(fd >= 0, "socket");
        let sock = OwnedFd::from_raw_fd(fd);
        let mut sin: libc::sockaddr_in = std::mem::zeroed();
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let addr = (&mut sin as *mut libc::sockaddr_in).cast::<libc::sockaddr>();
        assert_eq!(libc::bind(fd, addr, len), 0, "bind");
        assert_eq!(libc::getsockname(fd, addr, &mut len), 0, "getsockname");
        let port = u16::from_be(sin.sin_port);
        (sock, SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
    }
}

/// FW-E2E-213: a supervised connect that makes no connection leaves no source port in the
/// admission registry (FW-EGR37). Three ways to make none: a blocking connect that is refused, a
/// non-blocking connect whose handshake fails after the call returned, and a second connect on a
/// socket whose connection the listener already accepted and which the session then closes. The
/// same second connect, made while the listener has yet to take the first one's registration,
/// must leave that registration in place.
#[test]
fn fw_e2e_213_a_failed_connect_leaves_no_registered_port() {
    if !supervision_available() {
        not_exercised("connect supervision unavailable on this host");
        return;
    }
    let work = Scratch::new("213");
    let pol = policy(&work.0, &[]);
    let registered = |registry: &Arc<Mutex<HashSet<u16>>>| -> Vec<u16> {
        registry.lock().unwrap().iter().copied().collect()
    };

    // An address the supervisor takes for the Gateway, with nothing listening on it.
    let (_held, closed) = refusing_port();
    let registry = Arc::new(Mutex::new(HashSet::new()));
    let refused = run(
        &pol,
        closed,
        registry.clone(),
        cmd(&probe("registry"), &["refused", &closed.to_string()]),
    );
    assert_eq!(
        refused, 0,
        "the supervisor makes the connect and it is refused; got {refused}"
    );
    assert_eq!(
        registered(&registry),
        Vec::<u16>::new(),
        "a refused connect left its source port registered"
    );

    let in_progress = run(
        &pol,
        closed,
        registry.clone(),
        cmd(&probe("registry"), &["nonblocking", &closed.to_string()]),
    );
    assert!(
        in_progress == 0 || in_progress == 2,
        "the non-blocking connect must fail, during the call (2) or after it (0); got \
         {in_progress}"
    );
    assert_eq!(
        registered(&registry),
        Vec::<u16>::new(),
        "a non-blocking connect that failed left its source port registered"
    );

    let registry = Arc::new(Mutex::new(HashSet::new()));
    let gateway = signalling_listener(Some(registry.clone()));
    let twice = run(
        &pol,
        gateway,
        registry.clone(),
        cmd(&probe("registry"), &["twice", &gateway.to_string()]),
    );
    assert_eq!(
        twice, 0,
        "the first connect is admitted and the second answers EISCONN; got {twice}"
    );
    assert_eq!(
        registered(&registry),
        Vec::<u16>::new(),
        "a connect on an already connected socket left its source port registered"
    );

    let registry = Arc::new(Mutex::new(HashSet::new()));
    let gateway = signalling_listener(None);
    let twice = run(
        &pol,
        gateway,
        registry.clone(),
        cmd(&probe("registry"), &["twice", &gateway.to_string()]),
    );
    assert_eq!(twice, 0, "the second connect answers EISCONN; got {twice}");
    assert_eq!(
        registered(&registry).len(),
        1,
        "a failing second connect dropped the registration the Gateway had yet to take"
    );
    if in_progress == 2 {
        not_exercised("the non-blocking connect was refused before it returned");
    }
}
