//! The `connect()` supervisor (FW-EGR7, FW-ISO12): the Linux transport of host-scoped egress.
//!
//! A second seccomp filter, installed after the baseline, returns `SECCOMP_RET_USER_NOTIF` for
//! `connect()` and for `sendto()` with a destination address. The listener descriptor goes to the
//! spawning `formwork` process over a socketpair; that process -- outside the sandbox -- services
//! each notification:
//!
//! 1. copy the `sockaddr` out of the target once and validate the notification id;
//! 2. decide on that copy;
//! 3. if allowed, take a duplicate of the target's socket (`pidfd_getfd`) and perform the
//!    operation on it, then return its result; otherwise return `EACCES`.
//!
//! The kernel never re-reads the target's buffer for an inet or UNIX socket (the notification is
//! never answered with CONTINUE for those families), so rewriting the address after the check
//! changes nothing (FW-ADV-018). Admitted destinations: the session Gateway listener (the source
//! port is registered with the Gateway before connecting, FW-EGR9) and pathname sockets that are
//! granted or were bound by a process in the session. Netlink sockets continue in the kernel: their
//! family is fixed at creation, so a rewritten address still names a netlink peer.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use formwork_blueprint::PathPattern;

use super::ConfineError;

// <linux/seccomp.h> ioctl encodings: _IOWR('!', 0, struct seccomp_notif) etc. Identical on
// x86_64 and aarch64, the two architectures built here.
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;
// <asm-generic/socket.h>
const SO_DOMAIN: libc::c_int = 39;
// <linux/netlink.h>, <linux/sock_diag.h>, <linux/unix_diag.h>
const NETLINK_SOCK_DIAG: libc::c_int = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const UDIAG_SHOW_VFS: u32 = 0x2;
const UNIX_DIAG_VFS: u16 = 1;
// <linux/audit.h>
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;
/// Distinct refused socket paths kept for `learn` (FW-DISC12).
const MAX_RECORDED_REFUSALS: usize = 1024;
/// Largest datagram the supervisor sends on a target's behalf.
const MAX_DATAGRAM: usize = 256 * 1024;

/// What the parent needs to service a session's notifications.
#[derive(Clone)]
pub struct SupervisorConfig {
    /// The Gateway egress listener: the one inet destination (FW-EGR8/EGR9).
    pub gateway: SocketAddr,
    /// Source ports registered for connections the supervisor makes to the Gateway (FW-EGR9).
    pub registry: Arc<Mutex<HashSet<u16>>>,
    /// Pathname sockets admitted besides in-session ones (FW-ISO12).
    pub unix_grants: Vec<PathPattern>,
    /// Every pathname socket refused, as the supervisor resolved it, for `learn` to map onto the
    /// channels behind them (FW-DISC12).
    pub refused_sockets: Arc<Mutex<Vec<PathBuf>>>,
}

/// The filter program and the child's end of the listener handoff, built before the fork so the
/// child only issues syscalls.
pub struct Plan {
    filter: Vec<libc::sock_filter>,
    child_end: RawFd,
}

impl Plan {
    /// The descriptor the child sends its listener over.
    pub(crate) fn child_end(&self) -> RawFd {
        self.child_end
    }

    /// The child side rebuilt in the isolation stage from the inherited handoff descriptor.
    pub(crate) fn from_handoff(child_end: RawFd) -> Plan {
        Plan {
            filter: notify_filter(),
            child_end,
        }
    }
}

/// The parent's half before the child exists.
pub struct Pending {
    parent_end: UnixStream,
    child_end: OwnedFd,
}

/// Build the notification filter and the handoff socketpair (parent side, allocation allowed).
pub fn prepare() -> Result<(Plan, Pending), ConfineError> {
    let (parent, child) = UnixStream::pair()?;
    let child_end = OwnedFd::from(child);
    Ok((
        Plan {
            filter: notify_filter(),
            child_end: child_end.as_raw_fd(),
        },
        Pending {
            parent_end: parent,
            child_end,
        },
    ))
}

/// A classic-BPF program: notify on `connect`, and on `sendto` whose destination pointer is set;
/// allow everything else (the baseline filter, stacked before this one, already decided it). On
/// x86_64, x32 syscalls are refused: this filter matches only the native numbers.
fn notify_filter() -> Vec<libc::sock_filter> {
    use libc::{BPF_ABS, BPF_JEQ, BPF_JGE, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W};
    let ld = |off: u32| libc::sock_filter {
        code: (BPF_LD | BPF_W | BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k: off,
    };
    let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: (BPF_JMP | BPF_JEQ | BPF_K) as u16,
        jt,
        jf,
        k,
    };
    let jge = |k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: (BPF_JMP | BPF_JGE | BPF_K) as u16,
        jt,
        jf,
        k,
    };
    let ret = |k: u32| libc::sock_filter {
        code: (BPF_RET | BPF_K) as u16,
        jt: 0,
        jf: 0,
        k,
    };
    // seccomp_data: nr @0, arch @4, args[i] @16 + 8*i (little-endian low word first).
    // Offsets below are relative jumps to: NOTIFY (index 10), ALLOW (11), ERRNO (12).
    vec![
        ld(4),                                             // 0
        jeq(AUDIT_ARCH, 0, 9),                             // 1: foreign arch -> ALLOW
        ld(0),                                             // 2
        jge(0x4000_0000, 8, 0),                            // 3: x32 -> ERRNO
        jeq(libc::SYS_connect as u32, 5, 0),               // 4: connect -> NOTIFY
        jeq(libc::SYS_sendto as u32, 0, 5),                // 5: not sendto -> ALLOW
        ld(16 + 8 * 4),                                    // 6: sendto dest_addr, low word
        jeq(0, 0, 2),                                      // 7: nonzero -> NOTIFY
        ld(16 + 8 * 4 + 4),                                // 8: high word
        jeq(0, 1, 0),                                      // 9: zero -> ALLOW, else NOTIFY
        ret(libc::SECCOMP_RET_USER_NOTIF),                 // 10: NOTIFY
        ret(libc::SECCOMP_RET_ALLOW),                      // 11: ALLOW
        ret(libc::SECCOMP_RET_ERRNO | libc::EPERM as u32), // 12: ERRNO
    ]
}

/// Runs in the forked child after the baseline filter: install the notification filter, hand the
/// listener to the parent, and close every copy of it -- the workload must never hold its own
/// supervisor's listener. Syscalls only; no allocation.
pub fn install(plan: &Plan) -> io::Result<()> {
    let prog = libc::sock_fprog {
        len: plan.filter.len() as u16,
        filter: plan.filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: `prog` points at a filter owned by the plan, alive for the call; NO_NEW_PRIVS is set.
    let listener = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    };
    if listener < 0 {
        return Err(io::Error::last_os_error());
    }
    let listener = listener as RawFd;
    let sent = send_fd_raw(plan.child_end, listener);
    // SAFETY: both descriptors belong to this child; closing them is the point.
    unsafe {
        libc::close(listener);
        libc::close(plan.child_end);
    }
    sent
}

/// `sendmsg` one descriptor with `SCM_RIGHTS`, stack buffers only (post-fork safe).
fn send_fd_raw(sock: RawFd, fd: RawFd) -> io::Result<()> {
    #[repr(C, align(8))]
    struct Cmsg([u8; 64]);
    let mut cmsg = Cmsg([0u8; 64]);
    let mut byte = *b"L";
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: zeroed POD, then fully initialized; pointers refer to stack locals alive across the
    // call; the control buffer is aligned and larger than CMSG_SPACE(4).
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.0.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            (&fd as *const RawFd).cast::<u8>(),
            libc::CMSG_DATA(c),
            std::mem::size_of::<RawFd>(),
        );
        if libc::sendmsg(sock, &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn recv_fd(sock: &UnixStream) -> io::Result<OwnedFd> {
    #[repr(C, align(8))]
    struct Cmsg([u8; 64]);
    let mut cmsg = Cmsg([0u8; 64]);
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: as in `send_fd_raw`; the received descriptor is owned exactly once.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.0.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
        let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let c = libc::CMSG_FIRSTHDR(&msg);
        if n == 0 || c.is_null() || (*c).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::other(
                "the confined child exited before handing over its supervisor listener",
            ));
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(c),
            (&mut fd as *mut RawFd).cast::<u8>(),
            std::mem::size_of::<RawFd>(),
        );
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// The running supervisor. Dropping it detaches the thread, which ends when every process holding
/// the filter has exited (the listener reports hang-up).
pub struct Supervisor {
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Supervisor {
    pub fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .map(|t| !t.is_finished())
            .unwrap_or(false)
    }
}

impl Pending {
    /// Call after the child is spawned: receive its listener and start servicing notifications.
    /// Makes this process a child subreaper, so a session process that double-forks stays a
    /// descendant and its sockets still count as bound in the session.
    pub fn start(self, config: SupervisorConfig) -> Result<Supervisor, ConfineError> {
        let Pending {
            parent_end,
            child_end,
        } = self;
        // The parent's copy must close for EOF to report a child that died before the handoff.
        drop(child_end);
        parent_end.set_read_timeout(Some(Duration::from_secs(30)))?;
        let listener = recv_fd(&parent_end).map_err(|e| {
            ConfineError::MechanismFailed(format!("connect supervisor handoff failed: {e}"))
        })?;
        // SAFETY: PR_SET_CHILD_SUBREAPER takes a scalar flag and affects only this process.
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        let thread = std::thread::Builder::new()
            .name("formwork-supervisor".into())
            .spawn(move || serve(listener, config))?;
        tracing::info!("connect supervisor running (FW-EGR7)");
        Ok(Supervisor {
            thread: Some(thread),
        })
    }
}

fn serve(listener: OwnedFd, config: SupervisorConfig) {
    let fd = listener.as_raw_fd();
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, 500) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if rc == 0 {
            continue;
        }
        if pfd.revents & libc::POLLIN == 0 {
            // POLLHUP: every process that carried the filter has exited.
            break;
        }
        // SAFETY: a zeroed seccomp_notif is the documented RECV input.
        let mut notif: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: RECV writes one notification into `notif`.
        if unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV as _, &mut notif) } < 0 {
            // ENOENT: the target died between poll and recv. Keep serving the rest.
            continue;
        }
        let reply = handle(fd, &notif, &config);
        let mut resp = libc::seccomp_notif_resp {
            id: notif.id,
            val: 0,
            error: 0,
            flags: 0,
        };
        match reply {
            Reply::Value(v) => resp.val = v,
            Reply::Errno(e) => resp.error = -e,
            Reply::Continue => resp.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
        }
        // SAFETY: SEND reads one response; a stale id fails with ENOENT, which is harmless.
        unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND as _, &mut resp) };
    }
}

enum Reply {
    Value(i64),
    Errno(i32),
    Continue,
}

/// Is notification `id` still pending? Guards every use of `pid` against reuse.
fn id_valid(listener: RawFd, id: u64) -> bool {
    let mut id = id;
    // SAFETY: ID_VALID reads one u64.
    unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID as _, &mut id) == 0 }
}

/// Copy `len` bytes at `addr` out of process `pid`, once.
fn read_remote(pid: libc::pid_t, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    if len == 0 {
        return Ok(buf);
    }
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    // SAFETY: one local iovec over our buffer, one remote iovec in the target.
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

fn thread_group(tid: u32) -> Option<libc::pid_t> {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// A duplicate of the target's socket descriptor `fd`, taken through a pidfd of its thread group.
fn take_socket(listener: RawFd, id: u64, tid: u32, fd: i32) -> Result<OwnedFd, i32> {
    let tgid = thread_group(tid).ok_or(libc::ESRCH)?;
    // SAFETY: pidfd_open on a pid; the result is owned below.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, tgid, 0) };
    if pidfd < 0 {
        return Err(libc::ESRCH);
    }
    // SAFETY: pidfd_open returned a new descriptor we own.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };
    if !id_valid(listener, id) {
        return Err(libc::ESRCH);
    }
    // SAFETY: pidfd_getfd returns a new descriptor we own, or fails.
    let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
    if dup < 0 {
        return Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EACCES));
    }
    // SAFETY: as above.
    Ok(unsafe { OwnedFd::from_raw_fd(dup as RawFd) })
}

fn sockopt_int(fd: RawFd, opt: libc::c_int) -> Option<libc::c_int> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt writes one int.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some(v)
}

fn last_errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// A parsed destination, from the supervisor's own copy of the target's `sockaddr`.
enum Dest {
    Inet(SocketAddr),
    Unix(Vec<u8>),
    Abstract,
    Unspec,
    Other,
}

fn parse_sockaddr(raw: &[u8]) -> Dest {
    if raw.len() < 2 {
        return Dest::Other;
    }
    let family = u16::from_ne_bytes([raw[0], raw[1]]) as libc::c_int;
    match family {
        libc::AF_INET if raw.len() >= 8 => {
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
            Dest::Inet(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 if raw.len() >= 24 => {
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let mut o = [0u8; 16];
            o.copy_from_slice(&raw[8..24]);
            let ip = Ipv6Addr::from(o);
            Dest::Inet(match ip.to_ipv4_mapped() {
                Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
                None => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
            })
        }
        libc::AF_UNIX => {
            let path = &raw[2..];
            if path.first() == Some(&0) {
                return Dest::Abstract;
            }
            let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
            Dest::Unix(path[..end].to_vec())
        }
        libc::AF_UNSPEC => Dest::Unspec,
        _ => Dest::Other,
    }
}

fn handle(listener: RawFd, notif: &libc::seccomp_notif, config: &SupervisorConfig) -> Reply {
    let nr = notif.data.nr as i64;
    let args = notif.data.args;
    let (addr_ptr, addr_len) = if nr == libc::SYS_connect {
        (args[1], args[2] as usize)
    } else {
        (args[4], args[5] as usize)
    };
    let pid = notif.pid as libc::pid_t;
    let raw = match read_remote(pid, addr_ptr, addr_len.min(128)) {
        Ok(raw) => raw,
        Err(_) => return Reply::Errno(libc::EFAULT),
    };
    if !id_valid(listener, notif.id) {
        return Reply::Errno(libc::ESRCH);
    }
    let sock = match take_socket(listener, notif.id, notif.pid, args[0] as i32) {
        Ok(s) => s,
        Err(e) => return Reply::Errno(e),
    };
    let domain = sockopt_int(sock.as_raw_fd(), SO_DOMAIN).unwrap_or(-1);
    match domain {
        // A netlink socket can only reach netlink peers whatever address is swapped in.
        libc::AF_NETLINK => return Reply::Continue,
        libc::AF_INET | libc::AF_INET6 | libc::AF_UNIX => {}
        _ => {
            refuse(
                pid,
                "a socket family the session may not use",
                "formwork explain --hosts",
            );
            return Reply::Errno(libc::EACCES);
        }
    }
    let dest = parse_sockaddr(&raw);
    if nr == libc::SYS_connect {
        connect_for(sock, dest, domain, pid, config)
    } else {
        sendto_for(sock, dest, domain, pid, notif, config)
    }
}

fn refuse(pid: libc::pid_t, what: &str, reproduce: &str) {
    // FW-FID9: the operator line; the confined process sees only EACCES.
    tracing::warn!(
        pid,
        reproduce,
        "formwork: refused connect to {what} (supervised connect, FW-EGR7)"
    );
}

fn connect_for(
    sock: OwnedFd,
    dest: Dest,
    domain: libc::c_int,
    pid: libc::pid_t,
    config: &SupervisorConfig,
) -> Reply {
    match dest {
        Dest::Unspec => {
            // Dissolving an association is harmless, and done on our copy of the address.
            let sa = libc::sockaddr {
                sa_family: libc::AF_UNSPEC as libc::sa_family_t,
                sa_data: [0; 14],
            };
            // SAFETY: a valid sockaddr of the stated length.
            let rc = unsafe {
                libc::connect(
                    sock.as_raw_fd(),
                    &sa,
                    std::mem::size_of::<libc::sockaddr>() as libc::socklen_t,
                )
            };
            if rc == 0 {
                Reply::Value(0)
            } else {
                Reply::Errno(last_errno())
            }
        }
        Dest::Inet(addr) if (domain == libc::AF_INET || domain == libc::AF_INET6) => {
            if addr != config.gateway {
                refuse(
                    pid,
                    &format!("{addr}: egress goes through the Gateway (HTTP(S)_PROXY)"),
                    "formwork explain --hosts",
                );
                return Reply::Errno(libc::EACCES);
            }
            connect_gateway(sock, addr, domain, config)
        }
        Dest::Unix(path) if domain == libc::AF_UNIX => match admit_unix(pid, &path, config) {
            Ok(opened) => {
                let via = format!("/proc/self/fd/{}", opened.as_raw_fd());
                match connect_unix(sock.as_raw_fd(), &via) {
                    Ok(()) => Reply::Value(0),
                    Err(e) => Reply::Errno(e),
                }
            }
            Err(e) => Reply::Errno(e),
        },
        Dest::Abstract => {
            refuse(pid, "an abstract UNIX socket", "formwork explain --hosts");
            Reply::Errno(libc::EACCES)
        }
        _ => Reply::Errno(libc::EAFNOSUPPORT),
    }
}

/// Connect the target's socket to the Gateway from a source port registered first, so the Gateway
/// admits exactly this connection (FW-EGR9).
fn connect_gateway(
    sock: OwnedFd,
    gateway: SocketAddr,
    domain: libc::c_int,
    config: &SupervisorConfig,
) -> Reply {
    let fd = sock.as_raw_fd();
    let port = match local_port(fd) {
        Some(0) | None => {
            let bind_to = if domain == libc::AF_INET6 {
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
                    0,
                    0,
                    0,
                ))
            } else {
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            };
            if let Err(e) = bind_inet(fd, bind_to) {
                return Reply::Errno(e);
            }
            match local_port(fd) {
                Some(p) => p,
                None => return Reply::Errno(libc::EIO),
            }
        }
        Some(p) => p,
    };
    if let Ok(mut r) = config.registry.lock() {
        r.insert(port);
    }
    let target = if domain == libc::AF_INET6 {
        match gateway.ip() {
            IpAddr::V4(v4) => {
                SocketAddr::V6(SocketAddrV6::new(v4.to_ipv6_mapped(), gateway.port(), 0, 0))
            }
            IpAddr::V6(_) => gateway,
        }
    } else {
        gateway
    };
    match connect_inet(fd, target) {
        Ok(()) => Reply::Value(0),
        Err(e) => Reply::Errno(e),
    }
}

fn to_raw(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: zeroed storage is a valid initial value; we fill the family-specific prefix.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_in fits in sockaddr_storage.
            unsafe { std::ptr::write((&mut ss as *mut libc::sockaddr_storage).cast(), sin) };
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: a.ip().octets(),
                },
                sin6_scope_id: 0,
            };
            // SAFETY: sockaddr_in6 fits in sockaddr_storage.
            unsafe { std::ptr::write((&mut ss as *mut libc::sockaddr_storage).cast(), sin6) };
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (ss, len as libc::socklen_t)
}

fn bind_inet(fd: RawFd, addr: SocketAddr) -> Result<(), i32> {
    let (ss, len) = to_raw(addr);
    // SAFETY: a valid sockaddr of `len` bytes.
    if unsafe { libc::bind(fd, (&ss as *const libc::sockaddr_storage).cast(), len) } == 0 {
        Ok(())
    } else {
        Err(last_errno())
    }
}

fn connect_inet(fd: RawFd, addr: SocketAddr) -> Result<(), i32> {
    let (ss, len) = to_raw(addr);
    // SAFETY: a valid sockaddr of `len` bytes.
    if unsafe { libc::connect(fd, (&ss as *const libc::sockaddr_storage).cast(), len) } == 0 {
        Ok(())
    } else {
        Err(last_errno())
    }
}

fn local_port(fd: RawFd) -> Option<u16> {
    // SAFETY: getsockname writes at most `len` bytes into the storage.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            fd,
            (&mut ss as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    } != 0
    {
        return None;
    }
    // Both sockaddr_in and sockaddr_in6 carry the port at the same offset, network order.
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts((&ss as *const libc::sockaddr_storage).cast::<u8>(), 4)
    };
    Some(u16::from_be_bytes([bytes[2], bytes[3]]))
}

fn unix_addr(path: &str) -> Option<(libc::sockaddr_un, libc::socklen_t)> {
    // SAFETY: zeroed sockaddr_un is valid; the path is copied in bounds below.
    let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    if bytes.len() >= sun.sun_path.len() {
        return None;
    }
    for (i, b) in bytes.iter().enumerate() {
        sun.sun_path[i] = *b as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
    Some((sun, len as libc::socklen_t))
}

fn connect_unix(fd: RawFd, path: &str) -> Result<(), i32> {
    let (sun, len) = unix_addr(path).ok_or(libc::ENAMETOOLONG)?;
    // SAFETY: a valid sockaddr_un of `len` bytes.
    if unsafe { libc::connect(fd, (&sun as *const libc::sockaddr_un).cast(), len) } == 0 {
        Ok(())
    } else {
        Err(last_errno())
    }
}

/// Resolve a pathname socket as the target would see it (its root and working directory), open
/// it `O_PATH` on this side, and admit it if it is granted or bound in the session (FW-ISO12).
/// Returns the open descriptor, through which the connection is made, so the path cannot be
/// swapped between the check and the connect.
fn admit_unix(
    pid: libc::pid_t,
    raw_path: &[u8],
    config: &SupervisorConfig,
) -> Result<OwnedFd, i32> {
    if raw_path.is_empty() {
        return Err(libc::EINVAL);
    }
    let path = std::str::from_utf8(raw_path).map_err(|_| libc::EACCES)?;
    let seen_from = if path.starts_with('/') {
        format!("/proc/{pid}/root{path}")
    } else {
        format!("/proc/{pid}/cwd/{path}")
    };
    let c = CString::new(seen_from).map_err(|_| libc::EINVAL)?;
    // SAFETY: open with a NUL-terminated path; the result is owned below.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(last_errno());
    }
    // SAFETY: open returned a new descriptor we own.
    let opened = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: fstat into a zeroed stat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(opened.as_raw_fd(), &mut st) } != 0 {
        return Err(last_errno());
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(libc::ECONNREFUSED);
    }
    let real = std::fs::read_link(format!("/proc/self/fd/{}", opened.as_raw_fd()))
        .unwrap_or_else(|_| PathBuf::from(path));
    if config.unix_grants.iter().any(|g| g.matches_path(&real)) {
        return Ok(opened);
    }
    if bound_in_session(st.st_ino, st.st_dev) {
        return Ok(opened);
    }
    refuse(
        pid,
        &format!(
            "the UNIX socket {} (not granted, not bound in the session)",
            real.display()
        ),
        &format!("formwork explain {}", real.display()),
    );
    if let Ok(mut refused) = config.refused_sockets.lock() {
        // Bounded: a session looping on a refused connect must not grow this without limit.
        if refused.len() < MAX_RECORDED_REFUSALS && !refused.contains(&real) {
            refused.push(real);
        }
    }
    Err(libc::EACCES)
}

/// Was the socket file (`ino`, `dev`) bound by a process in this session? The session is every
/// descendant of this process, and one of them must hold the listening socket bound to that file.
/// The kernel's UNIX socket diagnostics map the file to the socket directly; on a kernel built
/// without them (`CONFIG_UNIX_DIAG`), `/proc/net/unix` gives each held socket's bound path, which
/// is resolved from the holder's view and compared with the file.
fn bound_in_session(ino: u64, dev: u64) -> bool {
    let held = session_sockets();
    if held.is_empty() {
        return false;
    }
    if let Some(sockets) = sockets_bound_to(ino, dev) {
        return held.iter().any(|(_, s)| sockets.contains(s));
    }
    let bound = proc_net_unix_paths();
    held.iter().any(|(pid, sock)| {
        let Some(path) = bound.get(sock) else {
            return false;
        };
        let seen = if path.starts_with('/') {
            format!("/proc/{pid}/root{path}")
        } else {
            format!("/proc/{pid}/cwd/{path}")
        };
        std::fs::metadata(&seen)
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.ino() == ino && m.dev() == dev
            })
            .unwrap_or(false)
    })
}

/// `(pid, socket inode)` for every socket a session process holds.
fn session_sockets() -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for pid in session_pids() {
        let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for e in entries.flatten() {
            let inode = std::fs::read_link(e.path())
                .ok()
                .and_then(|l| l.to_str().map(str::to_string))
                .and_then(|l| {
                    l.strip_prefix("socket:[")
                        .and_then(|r| r.strip_suffix(']'))
                        .and_then(|n| n.parse::<u32>().ok())
                });
            if let Some(inode) = inode {
                out.push((pid, inode));
            }
        }
    }
    out
}

/// Socket inode -> bound pathname, from `/proc/net/unix` (abstract names, `@…`, are skipped).
fn proc_net_unix_paths() -> HashMap<u32, String> {
    let mut out = HashMap::new();
    let Ok(text) = std::fs::read_to_string("/proc/net/unix") else {
        return out;
    };
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Num RefCount Protocol Flags Type St Inode [Path]
        if fields.len() >= 8 && !fields[7].starts_with('@') {
            if let Ok(inode) = fields[6].parse::<u32>() {
                out.insert(inode, fields[7..].join(" "));
            }
        }
    }
    out
}

/// Every descendant of this process (its child subreaper tree): the session.
fn session_pids() -> Vec<u32> {
    let me = std::process::id();
    let mut parent_of: HashMap<u32, u32> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                // `pid (comm) state ppid ...`; comm may hold spaces and parens, so split after the
                // last `)`.
                if let Some(rest) = stat.rfind(')').map(|i| &stat[i + 2..]) {
                    if let Some(ppid) = rest.split(' ').nth(1).and_then(|p| p.parse::<u32>().ok()) {
                        parent_of.insert(pid, ppid);
                    }
                }
            }
        }
    }
    parent_of
        .keys()
        .copied()
        .filter(|&pid| {
            let mut cur = pid;
            for _ in 0..4096 {
                match parent_of.get(&cur) {
                    Some(&p) if p == me => return true,
                    Some(&p) if p > 1 => cur = p,
                    _ => return false,
                }
            }
            false
        })
        .collect()
}

/// Socket inodes whose bound file is (`ino`, `dev`), from a `SOCK_DIAG_BY_FAMILY` dump of UNIX
/// sockets with `UDIAG_SHOW_VFS`.
fn sockets_bound_to(ino: u64, dev: u64) -> Option<HashSet<u32>> {
    // SAFETY: a netlink socket we own and close via OwnedFd.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if raw < 0 {
        return None;
    }
    // SAFETY: socket returned a new descriptor we own.
    let nl = unsafe { OwnedFd::from_raw_fd(raw) };
    // nlmsghdr (16) + unix_diag_req (24)
    let mut req = [0u8; 40];
    req[0..4].copy_from_slice(&40u32.to_ne_bytes());
    req[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    req[6..8].copy_from_slice(&flags.to_ne_bytes());
    req[16] = libc::AF_UNIX as u8; // sdiag_family
    req[20..24].copy_from_slice(&u32::MAX.to_ne_bytes()); // udiag_states: all
    req[28..32].copy_from_slice(&UDIAG_SHOW_VFS.to_ne_bytes());
    // SAFETY: send a buffer we own.
    if unsafe { libc::send(nl.as_raw_fd(), req.as_ptr().cast(), req.len(), 0) } < 0 {
        return None;
    }
    let mut found = HashSet::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: recv into a buffer we own.
        let n = unsafe { libc::recv(nl.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            return None;
        }
        let mut off = 0usize;
        let n = n as usize;
        while off + 16 <= n {
            let len = u32::from_ne_bytes(buf[off..off + 4].try_into().ok()?) as usize;
            let kind = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().ok()?);
            if len < 16 || off + len > n {
                return None;
            }
            if kind == libc::NLMSG_DONE as u16 {
                return Some(found);
            }
            if kind == libc::NLMSG_ERROR as u16 {
                return None;
            }
            // unix_diag_msg (16 bytes) after the header: family, type, state, pad, ino, cookie.
            let body = &buf[off + 16..off + len];
            if body.len() >= 16 {
                let sock_ino = u32::from_ne_bytes(body[4..8].try_into().ok()?);
                let mut a = 16usize;
                while a + 4 <= body.len() {
                    let alen = u16::from_ne_bytes(body[a..a + 2].try_into().ok()?) as usize;
                    let atype = u16::from_ne_bytes(body[a + 2..a + 4].try_into().ok()?);
                    if alen < 4 || a + alen > body.len() {
                        break;
                    }
                    if atype == UNIX_DIAG_VFS && alen >= 12 {
                        let vfs_ino = u32::from_ne_bytes(body[a + 4..a + 8].try_into().ok()?);
                        let vfs_dev = u32::from_ne_bytes(body[a + 8..a + 12].try_into().ok()?);
                        if u64::from(vfs_ino) == ino && same_dev(vfs_dev, dev) {
                            found.insert(sock_ino);
                        }
                    }
                    a += (alen + 3) & !3;
                }
            }
            off += (len + 3) & !3;
        }
    }
}

/// `unix_diag_vfs` carries the device in the kernel's `new_encode_dev` form; `stat` reports the
/// glibc encoding. Compare major and minor.
fn same_dev(diag: u32, st_dev: u64) -> bool {
    let (dmaj, dmin) = (
        (diag & 0xfff00) >> 8,
        (diag & 0xff) | ((diag >> 12) & 0xfff00),
    );
    let smaj = libc::major(st_dev as libc::dev_t);
    let smin = libc::minor(st_dev as libc::dev_t);
    dmaj == smaj && dmin == smin
}

/// An addressed `sendto` (FW-EGR7): a UNIX datagram to an admitted socket is sent by the
/// supervisor from its copy of the payload and address; inet destinations are refused (UDP never
/// reaches here, and TCP Fast Open would bypass `connect()`).
fn sendto_for(
    sock: OwnedFd,
    dest: Dest,
    domain: libc::c_int,
    pid: libc::pid_t,
    notif: &libc::seccomp_notif,
    config: &SupervisorConfig,
) -> Reply {
    let args = notif.data.args;
    match dest {
        Dest::Unix(path) if domain == libc::AF_UNIX => {
            let opened = match admit_unix(pid, &path, config) {
                Ok(o) => o,
                Err(e) => return Reply::Errno(e),
            };
            let len = (args[2] as usize).min(MAX_DATAGRAM);
            let payload = match read_remote(pid, args[1], len) {
                Ok(p) => p,
                Err(_) => return Reply::Errno(libc::EFAULT),
            };
            let via = format!("/proc/self/fd/{}", opened.as_raw_fd());
            let Some((sun, sunlen)) = unix_addr(&via) else {
                return Reply::Errno(libc::ENAMETOOLONG);
            };
            // SAFETY: send our copy of the payload to our copy of the address.
            let n = unsafe {
                libc::sendto(
                    sock.as_raw_fd(),
                    payload.as_ptr().cast(),
                    payload.len(),
                    args[3] as libc::c_int,
                    (&sun as *const libc::sockaddr_un).cast(),
                    sunlen,
                )
            };
            if n < 0 {
                Reply::Errno(last_errno())
            } else {
                Reply::Value(n as i64)
            }
        }
        Dest::Abstract => {
            refuse(pid, "an abstract UNIX socket", "formwork explain --hosts");
            Reply::Errno(libc::EACCES)
        }
        Dest::Inet(addr) => {
            refuse(
                pid,
                &format!("{addr} (an addressed send)"),
                "formwork explain --hosts",
            );
            Reply::Errno(libc::EACCES)
        }
        _ => Reply::Errno(libc::EACCES),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_jumps_land_on_the_named_returns() {
        const NOTIFY: usize = 10;
        const ALLOW: usize = 11;
        const ERRNO: usize = 12;
        let f = notify_filter();
        assert_eq!(f.len(), 13);
        let target =
            |i: usize, taken: bool| i + 1 + usize::from(if taken { f[i].jt } else { f[i].jf });
        assert_eq!(
            target(1, false),
            ALLOW,
            "a foreign arch is left to the baseline"
        );
        assert_eq!(target(3, true), ERRNO, "x32 syscalls are refused");
        assert_eq!(target(4, true), NOTIFY, "connect is supervised");
        assert_eq!(target(5, false), ALLOW, "other syscalls pass");
        assert_eq!(target(7, false), NOTIFY, "sendto with a low-word address");
        assert_eq!(target(9, true), ALLOW, "sendto with no address");
        assert_eq!(target(9, false), NOTIFY, "sendto with a high-word address");
        assert_eq!(f[NOTIFY].k, libc::SECCOMP_RET_USER_NOTIF);
        assert_eq!(f[ALLOW].k, libc::SECCOMP_RET_ALLOW);
        assert_eq!(f[ERRNO].k, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32);
    }

    #[test]
    fn socket_diagnostics_find_the_socket_bound_to_a_file() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("fw-diag-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.sock");
        let _l = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let md = std::fs::metadata(&path).unwrap();
        let found = sockets_bound_to(md.ino(), md.dev());
        let paths = proc_net_unix_paths();
        let _ = std::fs::remove_dir_all(&dir);
        match found {
            Some(found) => assert_eq!(found.len(), 1, "one socket is bound to the file: {found:?}"),
            // A kernel without CONFIG_UNIX_DIAG: the /proc/net/unix fallback must see the path.
            None => assert!(
                paths.values().any(|p| p == path.to_str().unwrap()),
                "the fallback lists the bound path"
            ),
        }
    }

    #[test]
    fn sockaddrs_parse_from_raw_bytes() {
        let mut v4 = vec![0u8; 16];
        v4[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        v4[2..4].copy_from_slice(&8080u16.to_be_bytes());
        v4[4..8].copy_from_slice(&[127, 0, 0, 1]);
        assert!(
            matches!(parse_sockaddr(&v4), Dest::Inet(a) if a == "127.0.0.1:8080".parse().unwrap())
        );
        let mut un = (libc::AF_UNIX as u16).to_ne_bytes().to_vec();
        un.extend_from_slice(b"/run/x.sock\0");
        assert!(matches!(parse_sockaddr(&un), Dest::Unix(p) if p == b"/run/x.sock"));
        let mut abs = (libc::AF_UNIX as u16).to_ne_bytes().to_vec();
        abs.extend_from_slice(b"\0x11");
        assert!(matches!(parse_sockaddr(&abs), Dest::Abstract));
    }
}
