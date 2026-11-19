//! Test-support binary: the listening-socket probe (FW-E2E-206, FW-ISO34). Run inside
//! confinement it tries to become reachable from outside the session; run unconfined it is the
//! control that shows each attempt works where nothing refuses it.
//!
//! `fw-listen-probe inet <dir>` calls `listen` on six inet stream sockets -- bound to the wildcard
//! address, bound to loopback, and unbound (which `listen` binds to the wildcard address itself),
//! for `AF_INET` then `AF_INET6` -- and asks for an io_uring, whose `IORING_OP_LISTEN` would be a
//! second way in. It writes one line per attempt to `<dir>/ports` and holds every socket open
//! until `<dir>/done` appears, so the test can try to connect from outside. Lines:
//!
//!   `<n> <port> <rc> <errno>`   attempt `n` (0..6): the port the socket ended on (0 if none),
//!                               `listen`'s result, and its errno; `rc` is -2 when the socket
//!                               could not be created or bound, with that errno
//!   `uring <rc> <errno>`        `io_uring_setup`'s result and errno
//!
//! Exit 0 once `done` is seen, 8 on a failure of the probe itself.
//!
//! `fw-listen-probe unix <path>` binds and listens on a pathname stream socket, checks that the
//! kernel's own answers to `listen` still arrive (a second `listen`, a pipe, a closed descriptor,
//! an unbound socket), then accepts one connection and reads a byte from it.
//!
//!   0   listened, accepted, and read the byte
//!   7   `listen` on the UNIX socket was refused with EACCES/EPERM
//!   8   any other failure of the listener
//!   30+k  transparency check `k` got another answer than the kernel's
//!
//! `fw-listen-probe swap <dir> <ms>` tries to make `listen` act on an inet socket by presenting
//! another descriptor to the check. First a thread with its own descriptor table (`unshare`) puts
//! the inet socket under a number that names a UNIX socket in the main table. Then, for `ms`
//! milliseconds, one thread flips a number between the two sockets while another calls `listen`
//! on it.
//!
//!   0   neither inet socket listens
//!   21  the inet socket of the first attempt listens
//!   22  the inet socket of the race listens
//!   8   a failure of the probe itself
//!
//! Deliberately libc-only so it starts wherever `/bin/cat` does under Closed-mode essentials.

#[cfg(target_os = "linux")]
mod probe {
    use std::io::Write;
    use std::mem::{size_of, zeroed};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    #[derive(Clone, Copy)]
    enum Bind {
        Wildcard,
        Loopback,
        Unbound,
    }

    fn bind_inet(fd: i32, family: i32, to: Bind) -> i32 {
        let loopback = matches!(to, Bind::Loopback);
        // SAFETY: a zeroed sockaddr of the family's size, filled below, alive for the call.
        unsafe {
            if family == libc::AF_INET {
                let mut sin: libc::sockaddr_in = zeroed();
                sin.sin_family = libc::AF_INET as libc::sa_family_t;
                if loopback {
                    sin.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
                }
                libc::bind(
                    fd,
                    (&sin as *const libc::sockaddr_in).cast(),
                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            } else {
                let mut sin6: libc::sockaddr_in6 = zeroed();
                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                if loopback {
                    sin6.sin6_addr.s6_addr[15] = 1;
                }
                libc::bind(
                    fd,
                    (&sin6 as *const libc::sockaddr_in6).cast(),
                    size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    }

    fn local_port(fd: i32) -> u16 {
        // SAFETY: getsockname writes at most `len` bytes into the zeroed storage.
        unsafe {
            let mut ss: libc::sockaddr_storage = zeroed();
            let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            if libc::getsockname(
                fd,
                (&mut ss as *mut libc::sockaddr_storage).cast(),
                &mut len,
            ) != 0
            {
                return 0;
            }
            // sockaddr_in and sockaddr_in6 carry the port at the same offset, network order.
            let bytes = std::slice::from_raw_parts((&ss as *const _ as *const u8).add(2), 2);
            u16::from_be_bytes([bytes[0], bytes[1]])
        }
    }

    fn stream(family: i32) -> i32 {
        // SAFETY: socket() takes scalar args.
        unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) }
    }

    fn unix_bound(path: &str) -> Option<i32> {
        let fd = stream(libc::AF_UNIX);
        if fd < 0 {
            return None;
        }
        // SAFETY: a zeroed sockaddr_un with the path copied in bounds.
        unsafe {
            let mut sun: libc::sockaddr_un = zeroed();
            sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
            if path.len() >= sun.sun_path.len() {
                return None;
            }
            for (i, b) in path.bytes().enumerate() {
                sun.sun_path[i] = b as libc::c_char;
            }
            let len = size_of::<libc::sa_family_t>() + path.len() + 1;
            let rc = libc::bind(
                fd,
                (&sun as *const libc::sockaddr_un).cast(),
                len as libc::socklen_t,
            );
            (rc == 0).then_some(fd)
        }
    }

    fn listening(fd: i32) -> bool {
        let mut v: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt writes one int.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                (&mut v as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        rc == 0 && v != 0
    }

    pub fn inet(dir: &str) -> i32 {
        let mut report = String::new();
        let mut n = 0;
        for family in [libc::AF_INET, libc::AF_INET6] {
            for to in [Bind::Wildcard, Bind::Loopback, Bind::Unbound] {
                let fd = stream(family);
                let bound =
                    fd >= 0 && (matches!(to, Bind::Unbound) || bind_inet(fd, family, to) == 0);
                let (rc, e) = if bound {
                    // SAFETY: listen takes a descriptor and a scalar backlog.
                    let rc = unsafe { libc::listen(fd, 8) };
                    (rc, if rc == 0 { 0 } else { errno() })
                } else {
                    (-2, errno())
                };
                let port = if fd >= 0 { local_port(fd) } else { 0 };
                report.push_str(&format!("{n} {port} {rc} {e}\n"));
                n += 1;
            }
        }
        // SAFETY: io_uring_setup reads a zeroed io_uring_params (120 bytes).
        let ring = unsafe {
            let mut params = [0u8; 120];
            libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr())
        };
        let e = if ring < 0 { errno() } else { 0 };
        report.push_str(&format!("uring {} {e}\n", ring.min(0)));

        let dir = Path::new(dir);
        let staged = dir.join("ports.tmp");
        let wrote = std::fs::File::create(&staged)
            .and_then(|mut f| f.write_all(report.as_bytes()))
            .and_then(|()| std::fs::rename(&staged, dir.join("ports")));
        if wrote.is_err() {
            return 8;
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        while !dir.join("done").exists() {
            if Instant::now() > deadline {
                return 8;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        0
    }

    pub fn unix(path: &str) -> i32 {
        let Some(fd) = unix_bound(path) else {
            return 8;
        };
        // SAFETY (each call below): listen/pipe/close/accept/read on descriptors owned here.
        if unsafe { libc::listen(fd, 4) } != 0 {
            return match errno() {
                libc::EACCES | libc::EPERM => 7,
                _ => 8,
            };
        }
        if !listening(fd) {
            return 8;
        }
        // The kernel's own answers must still arrive.
        if unsafe { libc::listen(fd, 16) } != 0 {
            return 30;
        }
        let mut pipe = [0i32; 2];
        if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
            return 8;
        }
        if unsafe { libc::listen(pipe[0], 1) } != -1 || errno() != libc::ENOTSOCK {
            return 31;
        }
        unsafe { libc::close(pipe[1]) };
        if unsafe { libc::listen(pipe[1], 1) } != -1 || errno() != libc::EBADF {
            return 32;
        }
        let unbound = stream(libc::AF_UNIX);
        if unsafe { libc::listen(unbound, 1) } != -1 || errno() != libc::EINVAL {
            return 33;
        }
        let conn = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if conn < 0 {
            return 8;
        }
        let mut byte = [0u8; 1];
        let n = unsafe { libc::read(conn, byte.as_mut_ptr().cast(), 1) };
        if n == 1 && byte[0] == b'S' {
            0
        } else {
            8
        }
    }

    /// A UNIX socket bound at `path`, a loopback-bound inet socket, and a duplicate of the first.
    fn pair(path: &Path) -> Option<(i32, i32, i32)> {
        let unix = unix_bound(path.to_str()?)?;
        let inet = stream(libc::AF_INET);
        if inet < 0 || bind_inet(inet, libc::AF_INET, Bind::Loopback) != 0 {
            return None;
        }
        // SAFETY: dup of a descriptor owned here.
        let number = unsafe { libc::dup(unix) };
        (number >= 0).then_some((unix, inet, number))
    }

    pub fn swap(dir: &str, ms: u64) -> i32 {
        let dir = Path::new(dir);

        let Some((_unix, inet, number)) = pair(&dir.join("swap-a.sock")) else {
            return 8;
        };
        let own_table = std::thread::spawn(move || {
            // SAFETY: unshare, dup2 and listen take scalars; the descriptors outlive the thread.
            unsafe {
                if libc::unshare(libc::CLONE_FILES) != 0 || libc::dup2(inet, number) < 0 {
                    return false;
                }
                libc::listen(number, 1);
            }
            true
        });
        if !own_table.join().unwrap_or(false) {
            return 8;
        }
        if listening(inet) {
            return 21;
        }

        let Some((unix, inet, number)) = pair(&dir.join("swap-b.sock")) else {
            return 8;
        };
        let stop = Arc::new(AtomicBool::new(false));
        let flipping = stop.clone();
        let flipper = std::thread::spawn(move || {
            while !flipping.load(Ordering::Relaxed) {
                // SAFETY: dup2 between descriptors owned by this process.
                unsafe {
                    libc::dup2(inet, number);
                    libc::dup2(unix, number);
                }
            }
        });
        let deadline = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < deadline {
            // SAFETY: listen takes a descriptor and a scalar backlog.
            unsafe { libc::listen(number, 1) };
        }
        stop.store(true, Ordering::Relaxed);
        let _ = flipper.join();
        if listening(inet) {
            return 22;
        }
        0
    }

    pub fn main() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let arg = |i: usize| args.get(i).map(String::as_str);
        match (arg(0), arg(1)) {
            (Some("inet"), Some(dir)) => inet(dir),
            (Some("unix"), Some(path)) => unix(path),
            (Some("swap"), Some(dir)) => {
                swap(dir, arg(2).and_then(|ms| ms.parse().ok()).unwrap_or(300))
            }
            _ => 8,
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(probe::main());
}

#[cfg(not(target_os = "linux"))]
fn main() {}
