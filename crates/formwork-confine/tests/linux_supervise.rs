//! Supervised connect on a real Linux kernel (FW-EGR7, FW-ISO11, FW-ISO12): the confined process's
//! `connect()` and addressed `sendto()` are decided outside the sandbox. A loopback listener stands
//! in for the Gateway; counting listeners show where connections actually land. Skips cleanly on a
//! host without the facilities (`detect().connect_supervision`).

#![cfg(target_os = "linux")]

use std::collections::HashSet;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::{UnixDatagram, UnixListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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
    let rule: HostRule = serde_json::from_str("\"https:allowed.test\"").unwrap();
    bp.net = NetPosture::AllowHosts(HostTable::new(vec![rule]));
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    formwork_compile::compile(
        &bp,
        &detect(),
        &ResolvedCatalog::builtin_for_home(&home).unwrap(),
    )
}

fn run(
    policy: &CompiledPolicy,
    gateway: SocketAddr,
    registry: Arc<Mutex<HashSet<u16>>>,
    mut cmd: Command,
) -> i32 {
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let pending = formwork_confine::spawn_confined_supervised(&mut cmd, policy)
        .expect("confinement applies")
        .expect("a host-rule policy needs the supervisor");
    let mut child = cmd.spawn().expect("child spawns");
    let unix_grants = match &policy.confiner {
        formwork_compile::ConfinerPolicy::Linux(l) => l.unix_socket_grants.clone(),
        _ => unreachable!(),
    };
    let _sup = pending
        .start(SupervisorConfig {
            gateway,
            registry,
            unix_grants,
            refused_sockets: Default::default(),
        })
        .expect("supervisor starts");
    child.wait().unwrap().code().unwrap_or(-1)
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
