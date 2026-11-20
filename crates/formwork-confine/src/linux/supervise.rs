//! The `connect()` supervisor (FW-EGR7, FW-ISO12): the Linux transport of host-scoped egress.
//!
//! A second seccomp filter, installed after the baseline, returns `SECCOMP_RET_USER_NOTIF` for
//! `connect()`, for `sendto()` with a destination address, for every `sendmsg()` and `sendmmsg()`,
//! and for `listen()`. The workload's process tells the spawning `formwork` process the listener's
//! descriptor number over a socketpair, and that process -- outside the sandbox -- takes the
//! listener with `pidfd_getfd` and services each notification. For `connect()` and the sends:
//!
//! 1. copy the `sockaddr`, and for a send the `msghdr`, its payload and its control messages, out
//!    of the target once, and validate the notification id;
//! 2. decide on that copy;
//! 3. if allowed, take a duplicate of the target's socket (`pidfd_getfd`) and perform the
//!    operation on it, then return its result; otherwise return `EACCES`.
//!
//! The supervisor never answers CONTINUE: the kernel would then read the target's memory and look
//! the descriptor number up again, and a second thread can have changed either since the check
//! (FW-ADV-018). Admitted destinations: the session Gateway listener (the source port is
//! registered with the Gateway before connecting, FW-EGR9), pathname sockets that are granted or
//! were bound by a process in the session, and route netlink peers. `sendmsg()` and `sendmmsg()`
//! are delivered whether or not they name a destination, because seccomp cannot read the
//! `msghdr` that would say so (FW-ISO30); one that names none is sent unchanged.
//!
//! `listen()` is supervised because egress is not the only direction (FW-ISO34): a listening inet
//! socket takes connections from peers outside the session, and seccomp sees a descriptor number,
//! not the family behind it. The supervisor takes the socket the same way, refuses an inet one,
//! and puts any other into the listening state itself.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

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
pub(super) const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
pub(super) const AUDIT_ARCH: u32 = 0xc000_00b7;
/// Distinct refused socket paths kept for `learn` (FW-DISC12).
const MAX_RECORDED_REFUSALS: usize = 1024;
/// The most payload bytes the supervisor sends for one message. A stream send of more returns
/// the short count a stream socket may return; a larger message on a datagram socket is refused
/// with `EMSGSIZE`.
const MAX_SEND: usize = 256 * 1024;
/// The most control-message bytes copied for one message; more is refused with `ENOBUFS`, as the
/// kernel refuses more than its option-memory limit.
const MAX_CONTROL: usize = 64 * 1024;
/// The most entries of one `sendmmsg()` the supervisor carries out (the kernel's `UIO_MAXIOV`).
const MAX_ENTRIES: usize = 1024;
/// How long a worker waiting for a blocked send sleeps between checks that its caller still waits.
const SEND_POLL: Duration = Duration::from_millis(50);
/// How long the parent waits for the child to report its listener.
const HANDOFF_WAIT: Duration = Duration::from_secs(30);
/// **handshake-wait** (FW-EGR37): how long a registration outlives a `connect()` to the Gateway
/// that returned with its handshake still in progress.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(2);

/// What the parent needs to service a session's notifications.
#[derive(Clone)]
pub struct SupervisorConfig {
    /// The Gateway egress listener: the one inet destination (FW-EGR8/EGR9).
    pub gateway: SocketAddr,
    /// Source ports registered for connections the supervisor makes to the Gateway (FW-EGR9). The
    /// Gateway listener removes a port when it accepts from it; the supervisor removes one whose
    /// `connect()` made no connection (FW-EGR37).
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
    child_end: OwnedFd,
    /// The listener, from the thread that takes it during the spawn.
    handoff: mpsc::Receiver<io::Result<OwnedFd>>,
}

/// Build the notification filter and the handoff socketpair (parent side, allocation allowed).
pub fn prepare() -> Result<(Plan, Pending), ConfineError> {
    let (parent, child) = UnixStream::pair()?;
    // The kernel attaches the writer's credentials to what the child writes, translated into this
    // process's PID namespace: that names the process holding the listener, isolated or not.
    let on: libc::c_int = 1;
    // SAFETY: setsockopt reads one int.
    check(unsafe {
        libc::setsockopt(
            parent.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    })
    .map_err(io::Error::from_raw_os_error)?;
    parent.set_read_timeout(Some(HANDOFF_WAIT))?;
    // The child waits in `install` until this side holds the listener, and `Command::spawn`
    // returns only once the child has run `execve`: the listener is taken on a thread of its own.
    let (tx, handoff) = mpsc::channel();
    std::thread::Builder::new()
        .name("formwork-supervisor-handoff".into())
        .spawn(move || {
            let taken = take_handoff(parent);
            if let Err(e) = &taken {
                tracing::error!("formwork: connect supervisor handoff failed: {e} (FW-EGR7)");
            }
            let _ = tx.send(taken);
        })?;
    let child_end = OwnedFd::from(child);
    Ok((
        Plan {
            filter: notify_filter(),
            child_end: child_end.as_raw_fd(),
        },
        Pending { child_end, handoff },
    ))
}

/// A classic-BPF program: notify on `connect`, on `listen`, on `sendmsg` and `sendmmsg`, and on
/// `sendto` whose destination pointer is set; allow everything else (the baseline filter, stacked
/// before this one, already decided it). On x86_64, x32 syscalls are refused: this filter matches
/// only the native numbers.
pub(super) fn notify_filter() -> Vec<libc::sock_filter> {
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
    // Offsets below are relative jumps to: NOTIFY (index 13), ALLOW (14), ERRNO (15).
    vec![
        ld(4),                                             // 0
        jeq(AUDIT_ARCH, 0, 12),                            // 1: foreign arch -> ALLOW
        ld(0),                                             // 2
        jge(0x4000_0000, 11, 0),                           // 3: x32 -> ERRNO
        jeq(libc::SYS_connect as u32, 8, 0),               // 4: connect -> NOTIFY
        jeq(libc::SYS_listen as u32, 7, 0),                // 5: listen -> NOTIFY
        jeq(libc::SYS_sendmsg as u32, 6, 0),               // 6: sendmsg -> NOTIFY
        jeq(libc::SYS_sendmmsg as u32, 5, 0),              // 7: sendmmsg -> NOTIFY
        jeq(libc::SYS_sendto as u32, 0, 5),                // 8: not sendto -> ALLOW
        ld(16 + 8 * 4),                                    // 9: sendto dest_addr, low word
        jeq(0, 0, 2),                                      // 10: nonzero -> NOTIFY
        ld(16 + 8 * 4 + 4),                                // 11: high word
        jeq(0, 1, 0),                                      // 12: zero -> ALLOW, else NOTIFY
        ret(libc::SECCOMP_RET_USER_NOTIF),                 // 13: NOTIFY
        ret(libc::SECCOMP_RET_ALLOW),                      // 14: ALLOW
        ret(libc::SECCOMP_RET_ERRNO | libc::EPERM as u32), // 15: ERRNO
    ]
}

/// Runs in the forked child after the baseline filter: install the notification filter, tell the
/// parent the listener's descriptor number, wait until the parent has taken its own copy, and
/// close every copy here -- the workload must never hold its own supervisor's listener. The
/// number goes by `write`, which the filter does not deliver: a `sendmsg` carrying the listener
/// would wait for a supervisor that does not have it yet. Syscalls only; no allocation.
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
    let handed = hand_over(plan.child_end, listener);
    // SAFETY: both descriptors belong to this child; closing them is the point.
    unsafe {
        libc::close(listener);
        libc::close(plan.child_end);
    }
    handed
}

/// The child's half of the handoff: the number out, one acknowledging byte back.
fn hand_over(sock: RawFd, listener: RawFd) -> io::Result<()> {
    // A fork of a `formwork` process that brokers a credential is not dumpable (FW-CRED16), and
    // `pidfd_getfd` refuses a non-dumpable target. This process runs only formwork code until its
    // `execve`, which makes it dumpable again in any case.
    // SAFETY: prctl with scalar arguments.
    unsafe {
        if libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0 {
            libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
        }
    }
    let number = listener.to_ne_bytes();
    // SAFETY: write from a stack buffer alive for the call.
    if unsafe { libc::write(sock, number.as_ptr().cast(), number.len()) } != number.len() as isize {
        return Err(io::Error::last_os_error());
    }
    let mut ack = [0u8; 1];
    loop {
        // SAFETY: read into a stack buffer alive for the call.
        let n = unsafe { libc::read(sock, ack.as_mut_ptr().cast(), 1) };
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if n == 1 && ack[0] == b'L' {
            return Ok(());
        }
        // The parent closed its end: it could not take the listener, and the child must not run
        // without a supervisor (FW-INV6).
        return Err(io::Error::from_raw_os_error(libc::EPIPE));
    }
}

/// The parent's half: the listener's number and the credentials of the process that wrote it.
fn recv_number(sock: &UnixStream) -> io::Result<(libc::pid_t, RawFd)> {
    #[repr(C, align(8))]
    struct Cmsg([u8; 64]);
    let mut cmsg = Cmsg([0u8; 64]);
    let mut number = [0u8; 4];
    let mut iov = libc::iovec {
        iov_base: number.as_mut_ptr().cast(),
        iov_len: number.len(),
    };
    // SAFETY: zeroed POD, then fully initialized; pointers refer to locals alive across the call;
    // the control buffer is aligned and larger than CMSG_SPACE(sizeof(ucred)).
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.0.as_mut_ptr().cast();
        msg.msg_controllen = cmsg.0.len() as _;
        let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let c = libc::CMSG_FIRSTHDR(&msg);
        if n != number.len() as isize
            || msg.msg_flags & libc::MSG_CTRUNC != 0
            || c.is_null()
            || (*c).cmsg_level != libc::SOL_SOCKET
            || (*c).cmsg_type != libc::SCM_CREDENTIALS
        {
            return Err(io::Error::other(
                "the confined child exited before handing over its supervisor listener",
            ));
        }
        let mut cred: libc::ucred = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(c),
            (&mut cred as *mut libc::ucred).cast::<u8>(),
            std::mem::size_of::<libc::ucred>(),
        );
        Ok((cred.pid, RawFd::from_ne_bytes(number)))
    }
}

/// Take descriptor `number` from process `pid`, and only if it is a seccomp listener.
fn take_listener(pid: libc::pid_t, number: RawFd) -> io::Result<OwnedFd> {
    let pidfd = pidfd_open(pid).ok_or_else(io::Error::last_os_error)?;
    // SAFETY: pidfd_getfd returns a new descriptor we own, or fails.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), number, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    let kind = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
    if kind.as_os_str() != "anon_inode:seccomp notify" {
        return Err(io::Error::other(format!(
            "the confined child's descriptor {number} is {}, not its supervisor listener",
            kind.display()
        )));
    }
    Ok(fd)
}

/// The parent's whole handoff: the number, the listener behind it, and the acknowledgement that
/// lets the child close its copy and go on to `execve`.
fn take_handoff(mut parent: UnixStream) -> io::Result<OwnedFd> {
    use std::io::Write;
    let (pid, number) = recv_number(&parent)?;
    let listener = take_listener(pid, number)?;
    parent.write_all(b"L")?;
    Ok(listener)
}

impl Pending {
    /// Call after the child is spawned: take its listener and start servicing notifications on
    /// a detached thread, which ends when every process holding the filter has exited (the
    /// listener reports hang-up). Makes this process a child subreaper, so a session process that
    /// double-forks stays a descendant and its sockets still count as bound in the session.
    pub fn start(self, config: SupervisorConfig) -> Result<(), ConfineError> {
        let Pending { child_end, handoff } = self;
        // The parent's copy must close for EOF to report a child that died before the handoff.
        drop(child_end);
        let failed = |e: String| {
            ConfineError::MechanismFailed(format!("connect supervisor handoff failed: {e}"))
        };
        let listener = handoff
            .recv_timeout(HANDOFF_WAIT + Duration::from_secs(1))
            .map_err(|e| failed(e.to_string()))?
            .map_err(|e| failed(e.to_string()))?;
        // SAFETY: PR_SET_CHILD_SUBREAPER takes a scalar flag and affects only this process.
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        std::thread::Builder::new()
            .name("formwork-supervisor".into())
            .spawn(move || serve(listener, config))?;
        tracing::info!("connect supervisor running (FW-EGR7)");
        Ok(())
    }
}

fn serve(listener: OwnedFd, config: SupervisorConfig) {
    let listener = Arc::new(listener);
    let fd = listener.as_raw_fd();
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        if unsafe { libc::poll(&mut pfd, 1, -1) } < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
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
        if let Some(reply) = handle(&listener, &notif, &config) {
            respond(fd, notif.id, notif.pid, reply);
        }
    }
}

/// Answer notification `id`, raised by thread `tid`.
fn respond(listener: RawFd, id: u64, tid: u32, reply: Reply) {
    let mut resp = libc::seccomp_notif_resp {
        id,
        val: 0,
        error: 0,
        flags: 0,
    };
    match reply {
        Reply::Value(v) => resp.val = v,
        Reply::Errno(e) => resp.error = -e,
        Reply::BrokenPipe => resp.error = -libc::EPIPE,
    }
    // SAFETY: SEND reads one response; a stale id fails with ENOENT, which is harmless.
    let sent = unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND as _, &mut resp) } == 0;
    if sent && matches!(reply, Reply::BrokenPipe) {
        // The kernel signals the thread whose send met a closed peer; the send here ran with
        // MSG_NOSIGNAL so that the signal goes to the target and not to this process.
        if let Some(tgid) = thread_group(tid).filter(|&g| g > 1 && tid > 1) {
            // SAFETY: tgkill with scalars; the thread is named within its own thread group.
            unsafe { libc::syscall(libc::SYS_tgkill, tgid, tid as libc::pid_t, libc::SIGPIPE) };
        }
    }
}

#[derive(Clone, Copy)]
enum Reply {
    Value(i64),
    Errno(i32),
    /// `EPIPE`, and `SIGPIPE` to the caller, which did not ask for `MSG_NOSIGNAL`.
    BrokenPipe,
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

fn pidfd_open(pid: libc::pid_t) -> Option<OwnedFd> {
    // SAFETY: pidfd_open on a pid; the result is owned below.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    // SAFETY: pidfd_open returned a new descriptor we own.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// A pidfd of the thread group of `tid`, opened while notification `id` is still pending. The
/// notifying thread is usually its group's leader, whose tid opens the pidfd directly; any other
/// thread's group is looked up first.
fn target_pidfd(listener: RawFd, id: u64, tid: u32) -> Result<OwnedFd, i32> {
    let pidfd = pidfd_open(tid as libc::pid_t)
        .or_else(|| thread_group(tid).and_then(pidfd_open))
        .ok_or(libc::ESRCH)?;
    if !id_valid(listener, id) {
        return Err(libc::ESRCH);
    }
    Ok(pidfd)
}

/// A duplicate of the target's descriptor `fd`.
fn getfd(pidfd: &OwnedFd, fd: i32) -> Result<OwnedFd, i32> {
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

/// A duplicate of the target's socket descriptor `fd`, taken through a pidfd of its thread group.
fn take_socket(listener: RawFd, id: u64, tid: u32, fd: i32) -> Result<OwnedFd, i32> {
    getfd(&target_pidfd(listener, id, tid)?, fd)
}

/// One `SOL_SOCKET` integer option, or the errno (`ENOTSOCK` for a descriptor that is no socket).
fn sockopt_int(fd: RawFd, opt: libc::c_int) -> Result<libc::c_int, i32> {
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
    check(rc).map(|()| v)
}

fn last_errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// A zero-or-minus-one syscall result as `Ok` or the errno.
fn check(rc: libc::c_int) -> Result<(), i32> {
    if rc == 0 {
        Ok(())
    } else {
        Err(last_errno())
    }
}

/// A path as process `pid` sees it: through its root, or relative to its working directory.
fn seen_from(pid: impl std::fmt::Display, path: &str) -> String {
    if path.starts_with('/') {
        format!("/proc/{pid}/root{path}")
    } else {
        format!("/proc/{pid}/cwd/{path}")
    }
}

/// The one refusal every addressed-send and connect path shares for abstract sockets.
fn refuse_abstract(pid: libc::pid_t) -> Reply {
    refuse(pid, "an abstract UNIX socket", "formwork explain --hosts");
    Reply::Errno(libc::EACCES)
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

/// Decide one notification. `None` when a worker thread answers it later (a send that would
/// block a caller that asked to block).
fn handle(
    listener: &Arc<OwnedFd>,
    notif: &libc::seccomp_notif,
    config: &SupervisorConfig,
) -> Option<Reply> {
    match notif.data.nr as i64 {
        libc::SYS_listen => Some(listen_for(listener.as_raw_fd(), notif)),
        libc::SYS_connect => Some(connect_call(listener.as_raw_fd(), notif, config)),
        _ => send_call(listener, notif, config),
    }
}

fn connect_call(listener: RawFd, notif: &libc::seccomp_notif, config: &SupervisorConfig) -> Reply {
    let args = notif.data.args;
    let pid = notif.pid as libc::pid_t;
    let raw = match read_remote(pid, args[1], (args[2] as usize).min(128)) {
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
        libc::AF_NETLINK => connect_netlink(sock, &raw),
        libc::AF_INET | libc::AF_INET6 | libc::AF_UNIX => {
            connect_for(sock, parse_sockaddr(&raw), domain, pid, config)
        }
        _ => {
            refuse(
                pid,
                "a socket family the session may not use",
                "formwork explain --hosts",
            );
            Reply::Errno(libc::EACCES)
        }
    }
}

/// A `sockaddr_nl`, as the kernel checks one: `AF_NETLINK` and at least its 12 bytes. Returns the
/// address and its `(nl_pid, nl_groups)`.
fn netlink_addr(raw: &[u8]) -> Result<([u8; 12], u32, u32), i32> {
    if raw.len() < 12 || u16::from_ne_bytes([raw[0], raw[1]]) as libc::c_int != libc::AF_NETLINK {
        return Err(libc::EINVAL);
    }
    let mut addr = [0u8; 12];
    addr.copy_from_slice(&raw[..12]);
    let word = |at: usize| u32::from_ne_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]);
    Ok((addr, word(4), word(8)))
}

/// A route netlink `connect()`, made on the supervisor's copy of the socket and of the address
/// (FW-ADV-018): a netlink socket reaches only netlink peers, but after a CONTINUE the kernel
/// would look the descriptor number up again, and a second thread can have put a TCP socket
/// under it. The kernel checks a non-kernel peer or a multicast group against the calling
/// process's `CAP_NET_ADMIN`; that process is now this one, so the supervisor answers what the
/// kernel answers a caller without it, and its own privileges never stand in for the session's.
fn connect_netlink(sock: OwnedFd, raw: &[u8]) -> Reply {
    if raw.len() >= 2 && u16::from_ne_bytes([raw[0], raw[1]]) as libc::c_int == libc::AF_UNSPEC {
        return connect_unspec(&sock);
    }
    let (addr, peer, groups) = match netlink_addr(raw) {
        Ok(a) => a,
        Err(e) => return Reply::Errno(e),
    };
    if peer != 0 || groups != 0 {
        return Reply::Errno(libc::EPERM);
    }
    // SAFETY: connect reads a 12-byte sockaddr_nl from our buffer.
    let rc = unsafe { libc::connect(sock.as_raw_fd(), addr.as_ptr().cast(), addr.len() as _) };
    match check(rc) {
        Ok(()) => Reply::Value(0),
        Err(e) => Reply::Errno(e),
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

/// A `listen()` (FW-ISO34). An inet socket is refused, loopback included: once it listens, a peer
/// outside the session can connect to it, and under host rules nothing else stands in the way.
/// Any other socket is put into the listening state here, on the descriptor whose domain was
/// read. Answering CONTINUE instead would have the kernel look the descriptor number up again,
/// and by then a second thread can have put an inet socket under it, or the caller can be a
/// thread whose descriptor table is not the one `pidfd_getfd` read.
fn listen_for(listener: RawFd, notif: &libc::seccomp_notif) -> Reply {
    let args = notif.data.args;
    let sock = match take_socket(listener, notif.id, notif.pid, args[0] as i32) {
        Ok(s) => s,
        Err(e) => return Reply::Errno(e),
    };
    match sockopt_int(sock.as_raw_fd(), SO_DOMAIN) {
        Ok(libc::AF_INET | libc::AF_INET6) => {
            // FW-FID9, as `refuse` does for a connect.
            tracing::warn!(
                pid = notif.pid,
                reproduce = "formwork explain --hosts",
                "formwork: refused listen on an inet socket: host rules admit no inbound \
                 connection (supervised connect, FW-ISO34)"
            );
            Reply::Errno(libc::EACCES)
        }
        // SAFETY: listen takes a descriptor we own and a scalar backlog.
        Ok(_) => match check(unsafe { libc::listen(sock.as_raw_fd(), args[1] as libc::c_int) }) {
            Ok(()) => Reply::Value(0),
            Err(e) => Reply::Errno(e),
        },
        Err(e) => Reply::Errno(e),
    }
}

/// Dissolve an association: harmless, and done on our copy of the address.
fn connect_unspec(sock: &OwnedFd) -> Reply {
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
    match check(rc) {
        Ok(()) => Reply::Value(0),
        Err(e) => Reply::Errno(e),
    }
}

fn connect_for(
    sock: OwnedFd,
    dest: Dest,
    domain: libc::c_int,
    pid: libc::pid_t,
    config: &SupervisorConfig,
) -> Reply {
    match dest {
        Dest::Unspec => connect_unspec(&sock),
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
        Dest::Abstract => refuse_abstract(pid),
        _ => Reply::Errno(libc::EAFNOSUPPORT),
    }
}

/// Connect the target's socket to the Gateway from a source port registered first, so the Gateway
/// admits exactly this connection (FW-EGR9). The port is registered before the connect, not after
/// it succeeds: the Gateway listener can accept the connection before `connect()` returns here.
/// A registration this call added is taken back when the call made no connection (FW-EGR37).
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
    // False when the port is already registered: an earlier connect from it that the Gateway has
    // yet to accept, whose registration a failing repeat call must leave alone.
    let registered = config
        .registry
        .lock()
        .map(|mut r| r.insert(port))
        .unwrap_or(false);
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
    let result = connect_inet(fd, target);
    let made = match result {
        Ok(()) => true,
        // A non-blocking socket, or a signal here: the handshake goes on after the call returned.
        Err(libc::EINPROGRESS | libc::EINTR) => established(fd),
        Err(_) => false,
    };
    if registered && !made {
        if let Ok(mut r) = config.registry.lock() {
            r.remove(&port);
        }
    }
    match result {
        Ok(()) => Reply::Value(0),
        Err(e) => Reply::Errno(e),
    }
}

/// Wait up to **handshake-wait** for a TCP handshake in progress on `fd`; true once it is
/// established. `poll` leaves the pending error on the socket for the target to read.
fn established(fd: RawFd) -> bool {
    let deadline = Instant::now() + HANDSHAKE_WAIT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, left.as_millis() as libc::c_int) };
        if rc < 0 && last_errno() == libc::EINTR && !left.is_zero() {
            continue;
        }
        return rc == 1
            && pfd.revents & libc::POLLOUT != 0
            && pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0;
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
    check(unsafe { libc::bind(fd, (&ss as *const libc::sockaddr_storage).cast(), len) })
}

fn connect_inet(fd: RawFd, addr: SocketAddr) -> Result<(), i32> {
    let (ss, len) = to_raw(addr);
    // SAFETY: a valid sockaddr of `len` bytes.
    check(unsafe { libc::connect(fd, (&ss as *const libc::sockaddr_storage).cast(), len) })
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
    check(unsafe { libc::connect(fd, (&sun as *const libc::sockaddr_un).cast(), len) })
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
    let c = CString::new(seen_from(pid, path)).map_err(|_| libc::EINVAL)?;
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
    // One netlink dump first: a file no socket is bound to needs no walk of the session's fds.
    let bound_to = sockets_bound_to(ino, dev);
    if bound_to.as_ref().is_some_and(HashSet::is_empty) {
        return false;
    }
    let held = session_sockets();
    if let Some(sockets) = bound_to {
        return held.iter().any(|(_, s)| sockets.contains(s));
    }
    let bound = proc_net_unix_paths();
    held.iter().any(|(pid, sock)| {
        let Some(path) = bound.get(sock) else {
            return false;
        };
        std::fs::metadata(seen_from(pid, path))
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
                        // The record carries `i_ino` truncated to 32 bits.
                        if vfs_ino == ino as u32 && same_dev(vfs_dev, dev) {
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

/// `unix_diag_vfs` carries the superblock's raw kernel `dev_t` (`sk_diag_dump_vfs` copies
/// `d_sb->s_dev`): major in the top 12 bits, minor in the low 20. `stat` reports the glibc
/// encoding. Compare major and minor. (The two agree only for major 0 with a minor below 256 --
/// tmpfs and the like -- which is why a disk-backed socket path once never matched.)
fn same_dev(diag: u32, st_dev: u64) -> bool {
    let (dmaj, dmin) = (diag >> 20, diag & 0xf_ffff);
    let smaj = libc::major(st_dev as libc::dev_t);
    let smin = libc::minor(st_dev as libc::dev_t);
    dmaj == smaj && dmin == smin
}

/// Write `bytes` at `addr` in process `pid`.
fn write_remote(pid: libc::pid_t, addr: u64, bytes: &[u8]) -> bool {
    let local = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: one local iovec over our buffer, one remote iovec in the target.
    unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) == bytes.len() as isize }
}

// The LP64 layouts of `struct msghdr` and `struct mmsghdr`, identical on x86_64 and aarch64.
const MSGHDR_LEN: usize = 56;
const MMSGHDR_LEN: usize = 64;
const CMSGHDR_LEN: usize = 16;

fn word(raw: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&raw[at..at + 8]);
    u64::from_ne_bytes(b)
}

fn half(raw: &[u8], at: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&raw[at..at + 4]);
    u32::from_ne_bytes(b)
}

fn cmsg_align(len: usize) -> usize {
    (len + 7) & !7
}

/// One message as copied out of the target, before any decision.
struct Copied {
    /// The destination, empty when the call names none.
    name: Vec<u8>,
    data: Vec<u8>,
    /// The message holds more than `MAX_SEND` bytes and `data` is its head.
    truncated: bool,
    control: Vec<u8>,
}

/// Copy the payload an iovec array at `iov` (`count` entries) describes, up to `MAX_SEND` bytes.
fn gather(pid: libc::pid_t, iov: u64, count: usize) -> Result<(Vec<u8>, bool), i32> {
    if count > MAX_ENTRIES {
        return Err(libc::EMSGSIZE);
    }
    let raw = read_remote(pid, iov, count * 16).map_err(|_| libc::EFAULT)?;
    if raw.len() != count * 16 {
        return Err(libc::EFAULT);
    }
    let mut remote = Vec::with_capacity(count);
    let (mut total, mut taken) = (0usize, 0usize);
    for i in 0..count {
        let (base, len) = (word(&raw, 16 * i), word(&raw, 16 * i + 8) as usize);
        total = total
            .checked_add(len)
            .filter(|t| *t <= isize::MAX as usize)
            .ok_or(libc::EINVAL)?;
        let take = len.min(MAX_SEND - taken);
        if take > 0 {
            remote.push(libc::iovec {
                iov_base: base as *mut libc::c_void,
                iov_len: take,
            });
            taken += take;
        }
    }
    let mut data = vec![0u8; taken];
    if taken > 0 {
        let local = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: taken,
        };
        // SAFETY: one local iovec over our buffer; remote iovecs in the target, at most
        // MAX_ENTRIES of them.
        let n = unsafe {
            libc::process_vm_readv(pid, &local, 1, remote.as_ptr(), remote.len() as _, 0)
        };
        if n != taken as isize {
            return Err(libc::EFAULT);
        }
    }
    Ok((data, total > taken))
}

/// Copy a destination of `len` bytes at `addr`; none when either is zero, as the kernel reads it.
fn copy_name(pid: libc::pid_t, addr: u64, len: usize) -> Result<Vec<u8>, i32> {
    if addr == 0 || len == 0 {
        return Ok(Vec::new());
    }
    let name = read_remote(pid, addr, len).map_err(|_| libc::EFAULT)?;
    if name.len() != len {
        return Err(libc::EFAULT);
    }
    Ok(name)
}

/// The message of a `sendto(fd, buf, len, flags, dest, destlen)`.
fn copy_sendto(pid: libc::pid_t, args: [u64; 6]) -> Result<Copied, i32> {
    let namelen = args[5] as u32 as i32;
    if !(0..=128).contains(&namelen) {
        return Err(libc::EINVAL);
    }
    let name = copy_name(pid, args[4], namelen as usize)?;
    let take = (args[2] as usize).min(MAX_SEND);
    let data = read_remote(pid, args[1], take).map_err(|_| libc::EFAULT)?;
    if data.len() != take {
        return Err(libc::EFAULT);
    }
    Ok(Copied {
        name,
        data,
        truncated: args[2] as usize > take,
        control: Vec::new(),
    })
}

/// The message a `struct msghdr` (already copied, `MSGHDR_LEN` bytes) describes.
fn copy_message(pid: libc::pid_t, hdr: &[u8]) -> Result<Copied, i32> {
    let namelen = half(hdr, 8) as i32;
    if namelen < 0 {
        return Err(libc::EINVAL);
    }
    // The kernel clamps an over-long name to a sockaddr_storage rather than refusing it.
    let name = copy_name(pid, word(hdr, 0), (namelen as usize).min(128))?;
    let (data, truncated) = gather(pid, word(hdr, 16), word(hdr, 24) as usize)?;
    let (control_at, control_len) = (word(hdr, 32), word(hdr, 40) as usize);
    if control_len > MAX_CONTROL {
        return Err(libc::ENOBUFS);
    }
    let control = if control_len > 0 {
        let c = read_remote(pid, control_at, control_len).map_err(|_| libc::EFAULT)?;
        if c.len() != control_len {
            return Err(libc::EFAULT);
        }
        c
    } else {
        Vec::new()
    };
    Ok(Copied {
        name,
        data,
        truncated,
        control,
    })
}

fn copy_sendmsg(pid: libc::pid_t, at: u64) -> Result<Copied, i32> {
    let hdr = read_remote(pid, at, MSGHDR_LEN).map_err(|_| libc::EFAULT)?;
    if hdr.len() != MSGHDR_LEN {
        return Err(libc::EFAULT);
    }
    copy_message(pid, &hdr)
}

/// The entries of a `sendmmsg(fd, vec, vlen, flags)`, and the errno of the first one that could
/// not be copied: the kernel sends the entries before it and stops there.
fn copy_sendmmsg(pid: libc::pid_t, vec: u64, vlen: u64) -> (Vec<Copied>, Option<i32>) {
    let count = (vlen as u32 as usize).min(MAX_ENTRIES);
    let raw = match read_remote(pid, vec, count * MMSGHDR_LEN) {
        Ok(raw) if raw.len() == count * MMSGHDR_LEN => raw,
        _ => return (Vec::new(), Some(libc::EFAULT)),
    };
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        match copy_message(pid, &raw[i * MMSGHDR_LEN..i * MMSGHDR_LEN + MSGHDR_LEN]) {
            Ok(m) => out.push(m),
            Err(e) => return (out, Some(e)),
        }
    }
    (out, None)
}

/// The control messages as the supervisor sends them: each descriptor an `SCM_RIGHTS` message
/// names is replaced by the supervisor's duplicate of the target's (kept alive in the returned
/// vector until the send), and an `SCM_CREDENTIALS` message is dropped -- the kernel checks one
/// against the sending process, which is this one, so the receiver gets this process's
/// credentials, as `SO_PEERCRED` names it for a connection it made. Everything else is copied.
fn translate_control(pidfd: &OwnedFd, raw: &[u8]) -> Result<(Vec<u8>, Vec<OwnedFd>), i32> {
    let (mut out, mut fds) = (Vec::new(), Vec::new());
    let mut at = 0;
    while at + CMSGHDR_LEN <= raw.len() {
        let len = word(raw, at) as usize;
        if len < CMSGHDR_LEN || len > raw.len() - at {
            return Err(libc::EINVAL);
        }
        let (level, kind) = (half(raw, at + 8) as i32, half(raw, at + 12) as i32);
        let body = &raw[at + CMSGHDR_LEN..at + len];
        match (level, kind) {
            (libc::SOL_SOCKET, libc::SCM_CREDENTIALS) => {}
            (libc::SOL_SOCKET, libc::SCM_RIGHTS) => {
                out.extend_from_slice(&raw[at..at + CMSGHDR_LEN]);
                for fd in body.chunks_exact(4) {
                    let dup = getfd(pidfd, half(fd, 0) as i32).map_err(|_| libc::EBADF)?;
                    out.extend_from_slice(&dup.as_raw_fd().to_ne_bytes());
                    fds.push(dup);
                }
                out.extend_from_slice(&body[body.len() / 4 * 4..]);
            }
            _ => out.extend_from_slice(&raw[at..at + len]),
        }
        out.resize(cmsg_align(out.len()), 0);
        at += cmsg_align(len);
    }
    Ok((out, fds))
}

/// Where one message goes, decided on the supervisor's copy of its destination.
enum To {
    /// The call named none: the socket's own peer.
    Connected,
    /// An admitted pathname socket, opened `O_PATH` here and reached through that descriptor.
    Unix(OwnedFd),
    /// A route netlink peer.
    Netlink([u8; 12]),
}

struct Message {
    to: To,
    data: Vec<u8>,
    control: Vec<u8>,
    /// Descriptors `control` carries, open until the message is sent.
    _fds: Vec<OwnedFd>,
}

/// The rule for one destination (FW-ISO30): an inet or abstract destination is refused, a
/// pathname one is admitted as `connect()` admits it (FW-ISO12), and a netlink one as the kernel
/// admits it for a caller without `CAP_NET_ADMIN` (see `connect_netlink`).
fn decide(
    pidfd: &OwnedFd,
    copied: Copied,
    domain: libc::c_int,
    stream: bool,
    pid: libc::pid_t,
    config: &SupervisorConfig,
) -> Result<Message, i32> {
    let to = if copied.name.is_empty() {
        To::Connected
    } else if domain == libc::AF_NETLINK {
        let (addr, _, groups) = netlink_addr(&copied.name)?;
        if groups != 0 {
            return Err(libc::EPERM);
        }
        To::Netlink(addr)
    } else {
        match parse_sockaddr(&copied.name) {
            Dest::Inet(addr) => {
                refuse(
                    pid,
                    &format!("{addr} (an addressed send)"),
                    "formwork explain --hosts",
                );
                return Err(libc::EACCES);
            }
            Dest::Unix(path) if domain == libc::AF_UNIX => {
                To::Unix(admit_unix(pid, &path, config)?)
            }
            Dest::Abstract => {
                refuse_abstract(pid);
                return Err(libc::EACCES);
            }
            _ => return Err(libc::EACCES),
        }
    };
    if copied.truncated && !stream {
        return Err(libc::EMSGSIZE);
    }
    let (control, fds) = translate_control(pidfd, &copied.control)?;
    Ok(Message {
        to,
        data: copied.data,
        control,
        _fds: fds,
    })
}

/// What a finished send returns: one count, or `sendmmsg`'s count of entries with each entry's
/// `msg_len` written back into the target's array.
enum Shape {
    One,
    Many { pid: libc::pid_t, vec: u64 },
}

/// A send the supervisor carries out for a target: the socket, the decided messages, and how far
/// it got. Every attempt is non-blocking; a caller that asked to block waits in a worker thread
/// while the supervisor serves the session's other calls.
struct Job {
    sock: OwnedFd,
    shape: Shape,
    messages: Vec<Message>,
    /// Why the message after the last decided one is not sent.
    refused: Option<i32>,
    /// The caller's flags, with `MSG_DONTWAIT` and `MSG_NOSIGNAL` added.
    flags: libc::c_int,
    /// The caller asked for `MSG_NOSIGNAL`.
    nosignal: bool,
    blocking: bool,
    stream: bool,
    /// The socket's `SO_SNDTIMEO`, from the first time the send blocked.
    deadline: Option<Instant>,
    at: usize,
    sent: usize,
    lens: Vec<u32>,
}

enum Progress {
    Done(Reply),
    Blocked,
}

impl Job {
    fn advance(&mut self) -> Progress {
        while self.at < self.messages.len() {
            match self.attempt() {
                Ok(n) => {
                    self.sent += n;
                    let whole = self.sent >= self.messages[self.at].data.len();
                    if self.stream && !whole && n > 0 && self.blocking {
                        continue;
                    }
                    self.next();
                }
                Err(libc::EAGAIN) if self.blocking && !self.timed_out() => {
                    return Progress::Blocked
                }
                Err(e) => {
                    if self.sent > 0 {
                        self.next();
                    }
                    return Progress::Done(self.finish(Some(e)));
                }
            }
        }
        Progress::Done(self.finish(self.refused))
    }

    fn next(&mut self) {
        self.lens.push(self.sent as u32);
        self.at += 1;
        self.sent = 0;
    }

    fn timed_out(&mut self) -> bool {
        let deadline = *self.deadline.get_or_insert_with(|| {
            send_timeout(self.sock.as_raw_fd()).map_or(
                Instant::now() + Duration::from_secs(u64::from(u32::MAX)),
                |t| Instant::now() + t,
            )
        });
        Instant::now() >= deadline
    }

    fn attempt(&self) -> Result<usize, i32> {
        let m = &self.messages[self.at];
        let rest = &m.data[self.sent..];
        let mut iov = libc::iovec {
            iov_base: rest.as_ptr() as *mut libc::c_void,
            iov_len: rest.len(),
        };
        let via;
        let (name, namelen): (*const u8, usize) = match &m.to {
            To::Connected => (std::ptr::null(), 0),
            To::Unix(opened) => {
                via = unix_addr(&format!("/proc/self/fd/{}", opened.as_raw_fd()))
                    .ok_or(libc::ENAMETOOLONG)?;
                ((&via.0 as *const libc::sockaddr_un).cast(), via.1 as usize)
            }
            To::Netlink(addr) => (addr.as_ptr(), addr.len()),
        };
        // SAFETY: zeroed POD, then filled with pointers to buffers alive for the call. Control
        // messages ride the first part of a message only, as the kernel attaches them.
        let n = unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_name = name as *mut libc::c_void;
            msg.msg_namelen = namelen as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if self.sent == 0 && !m.control.is_empty() {
                msg.msg_control = m.control.as_ptr() as *mut libc::c_void;
                msg.msg_controllen = m.control.len() as _;
            }
            libc::sendmsg(self.sock.as_raw_fd(), &msg, self.flags)
        };
        if n < 0 {
            Err(last_errno())
        } else {
            Ok(n as usize)
        }
    }

    fn finish(&self, error: Option<i32>) -> Reply {
        let failed = |e: i32| {
            if e == libc::EPIPE && !self.nosignal {
                Reply::BrokenPipe
            } else {
                Reply::Errno(e)
            }
        };
        match self.shape {
            Shape::One => match (self.lens.first(), error) {
                (Some(&n), _) => Reply::Value(i64::from(n)),
                (None, Some(e)) => failed(e),
                (None, None) => Reply::Value(0),
            },
            Shape::Many { pid, vec } => {
                for (i, len) in self.lens.iter().enumerate() {
                    let at = vec + (i * MMSGHDR_LEN + MSGHDR_LEN) as u64;
                    if !write_remote(pid, at, &len.to_ne_bytes()) {
                        return Reply::Errno(libc::EFAULT);
                    }
                }
                match (self.lens.len(), error) {
                    (0, Some(e)) => failed(e),
                    (n, _) => Reply::Value(n as i64),
                }
            }
        }
    }
}

/// The socket's `SO_SNDTIMEO`, `None` when it has none.
fn send_timeout(fd: RawFd) -> Option<Duration> {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    // SAFETY: getsockopt writes one timeval.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&mut tv as *mut libc::timeval).cast(),
            &mut len,
        )
    };
    let t = Duration::new(tv.tv_sec.max(0) as u64, (tv.tv_usec.max(0) as u32) * 1000);
    (rc == 0 && !t.is_zero()).then_some(t)
}

/// `sendto` with a destination, and every `sendmsg` and `sendmmsg` (FW-ISO30, FW-ISO12). The
/// supervisor copies the call's messages once, decides each destination on its copy, and sends
/// the copy itself on its duplicate of the socket. Answering CONTINUE instead, even for a call
/// that names no destination, would let the kernel read the `msghdr` and look the descriptor up
/// again after the check (FW-ADV-018).
fn send_call(
    listener: &Arc<OwnedFd>,
    notif: &libc::seccomp_notif,
    config: &SupervisorConfig,
) -> Option<Reply> {
    let nr = notif.data.nr as i64;
    let args = notif.data.args;
    let pid = notif.pid as libc::pid_t;
    let flags = (if nr == libc::SYS_sendmsg {
        args[2]
    } else {
        args[3]
    }) as libc::c_int;
    // The baseline refuses Fast Open first (FW-ISO29). Zero-copy would hand the kernel pages of a
    // buffer freed when this call returns; ENOBUFS is the answer on which a zero-copy sender
    // falls back to copying.
    if flags & libc::MSG_FASTOPEN != 0 {
        return Some(Reply::Errno(libc::EOPNOTSUPP));
    }
    if flags & libc::MSG_ZEROCOPY != 0 {
        return Some(Reply::Errno(libc::ENOBUFS));
    }
    let (copied, mut refused, shape) = match nr {
        libc::SYS_sendto => match copy_sendto(pid, args) {
            Ok(m) => (vec![m], None, Shape::One),
            Err(e) => return Some(Reply::Errno(e)),
        },
        libc::SYS_sendmsg => match copy_sendmsg(pid, args[1]) {
            Ok(m) => (vec![m], None, Shape::One),
            Err(e) => return Some(Reply::Errno(e)),
        },
        libc::SYS_sendmmsg => {
            let (m, e) = copy_sendmmsg(pid, args[1], args[2]);
            (m, e, Shape::Many { pid, vec: args[1] })
        }
        _ => return Some(Reply::Errno(libc::ENOSYS)),
    };
    let fd = listener.as_raw_fd();
    let pidfd = match target_pidfd(fd, notif.id, notif.pid) {
        Ok(p) => p,
        Err(e) => return Some(Reply::Errno(e)),
    };
    let sock = match getfd(&pidfd, args[0] as i32) {
        Ok(s) => s,
        Err(e) => return Some(Reply::Errno(e)),
    };
    let domain = match sockopt_int(sock.as_raw_fd(), SO_DOMAIN) {
        Ok(d @ (libc::AF_INET | libc::AF_INET6 | libc::AF_UNIX | libc::AF_NETLINK)) => d,
        Ok(_) => {
            refuse(
                pid,
                "a socket family the session may not use",
                "formwork explain --hosts",
            );
            return Some(Reply::Errno(libc::EACCES));
        }
        Err(e) => return Some(Reply::Errno(e)),
    };
    let stream = sockopt_int(sock.as_raw_fd(), libc::SO_TYPE) == Ok(libc::SOCK_STREAM);
    let mut messages = Vec::with_capacity(copied.len());
    for c in copied {
        match decide(&pidfd, c, domain, stream, pid, config) {
            Ok(m) => messages.push(m),
            Err(e) => {
                refused = Some(e);
                break;
            }
        }
    }
    // SAFETY: F_GETFL on a descriptor we own; the open file description is the target's.
    let nonblocking =
        unsafe { libc::fcntl(sock.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK != 0;
    let mut job = Job {
        sock,
        shape,
        messages,
        refused,
        flags: flags | libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        nosignal: flags & libc::MSG_NOSIGNAL != 0,
        blocking: flags & libc::MSG_DONTWAIT == 0 && !nonblocking,
        stream,
        deadline: None,
        at: 0,
        sent: 0,
        lens: Vec::new(),
    };
    match job.advance() {
        Progress::Done(reply) => Some(reply),
        Progress::Blocked => {
            let (listener, id, tid) = (listener.clone(), notif.id, notif.pid);
            let spawned = std::thread::Builder::new()
                .name("formwork-supervisor-send".into())
                .spawn(move || wait_and_send(listener, id, tid, job));
            match spawned {
                Ok(_) => None,
                Err(_) => Some(Reply::Errno(libc::ENOBUFS)),
            }
        }
    }
}

/// A blocked send: retry when the socket is writable, for as long as its caller still waits. A
/// caller that is interrupted or killed ends the notification, and then the wait.
fn wait_and_send(listener: Arc<OwnedFd>, id: u64, tid: u32, mut job: Job) {
    let fd = listener.as_raw_fd();
    while id_valid(fd, id) {
        let mut pfd = libc::pollfd {
            fd: job.sock.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        unsafe { libc::poll(&mut pfd, 1, SEND_POLL.as_millis() as libc::c_int) };
        if let Progress::Done(reply) = job.advance() {
            respond(fd, id, tid, reply);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The notify filter's verdict for each call it decides, interpreted (FW-ISO30, FW-ISO34,
    /// FW-EGR7). `sendmsg` and `sendmmsg` are delivered with and without a destination, because
    /// the filter cannot read the `msghdr` that would tell them apart.
    #[test]
    fn fw_iso30_the_notify_filter_delivers_every_sendmsg_and_sendmmsg() {
        use super::super::bpf_eval::eval;
        const NOTIFY: u32 = libc::SECCOMP_RET_USER_NOTIF;
        const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
        const AUDIT_ARCH_I386: u32 = 0x4000_0003;
        let f = notify_filter();
        let at = |nr: libc::c_long, args: [u64; 6]| eval(&f, AUDIT_ARCH, nr as u32, args);
        let with = |i: usize, v: u64| {
            let mut a = [0u64; 6];
            a[i] = v;
            a
        };
        for nr in [libc::SYS_connect, libc::SYS_listen] {
            assert_eq!(at(nr, [0; 6]), NOTIFY, "{nr}");
        }
        for nr in [libc::SYS_sendmsg, libc::SYS_sendmmsg] {
            for args in [[0; 6], with(1, 0x7fff_0000_1000), with(2, 0x4000)] {
                assert_eq!(at(nr, args), NOTIFY, "{nr} {args:?}");
            }
        }
        assert_eq!(
            at(libc::SYS_sendto, [0; 6]),
            ALLOW,
            "sendto with no address"
        );
        assert_eq!(
            at(libc::SYS_sendto, with(4, 0x1000)),
            NOTIFY,
            "a low-word address"
        );
        assert_eq!(
            at(libc::SYS_sendto, with(4, 0x7fff_0000_0000)),
            NOTIFY,
            "a high-word address"
        );
        for nr in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_recvmsg,
            libc::SYS_bind,
        ] {
            assert_eq!(at(nr, [0; 6]), ALLOW, "{nr}");
        }
        let x32 = (libc::SYS_sendmsg as u32) | 0x4000_0000;
        assert_eq!(
            eval(&f, AUDIT_ARCH, x32, [0; 6]),
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            "x32 syscalls are refused"
        );
        assert_eq!(
            eval(&f, AUDIT_ARCH_I386, libc::SYS_sendmsg as u32, [0; 6]),
            ALLOW,
            "a foreign arch is left to the baseline"
        );
    }

    #[test]
    fn diag_devices_decode_the_kernel_encoding() {
        for (maj, min) in [(8u32, 1u32), (259, 3), (0, 34), (0, 300), (253, 70_000)] {
            let st_dev = libc::makedev(maj, min) as u64;
            assert!(same_dev((maj << 20) | min, st_dev), "{maj}:{min}");
            assert!(
                !same_dev((maj << 20) | (min + 1), st_dev),
                "{maj}:{min} vs a neighbour"
            );
        }
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
