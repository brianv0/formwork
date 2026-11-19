//! Test-support binary: connects that make no connection (FW-E2E-213, FW-EGR37). Each mode aims
//! at `argv[2]`, an IPv4 `ip:port` the supervisor takes for the Gateway listener, and reports via
//! exit code whether the call ended the way the mode needs for the test to mean anything.
//!
//! `fw-registry-probe refused <ip:port>`: a blocking `connect()` to a port nothing listens on.
//!
//!   0   `connect()` returned ECONNREFUSED
//!   1   the connection was made
//!   8   anything else
//!
//! `fw-registry-probe nonblocking <ip:port>`: the same on a non-blocking socket.
//!
//!   0   `connect()` returned EINPROGRESS and the handshake then failed with ECONNREFUSED
//!   2   `connect()` itself returned ECONNREFUSED
//!   1   the connection was made
//!   8   anything else
//!
//! `fw-registry-probe twice <ip:port>`: `connect()`, wait for one byte from the listener (it has
//! accepted by then), and `connect()` again on the connected socket.
//!
//!   0   the second call returned EISCONN
//!   1   the second call succeeded
//!   8   anything else
//!
//! Deliberately libc-only so it starts wherever `/bin/cat` does under Closed-mode essentials.

#[cfg(target_os = "linux")]
mod probe {
    use std::mem::{size_of, zeroed};
    use std::net::SocketAddrV4;

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn connect(fd: i32, to: SocketAddrV4) -> i32 {
        // SAFETY: a zeroed sockaddr_in, filled below and alive for the call.
        unsafe {
            let mut sin: libc::sockaddr_in = zeroed();
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = to.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(to.ip().octets());
            libc::connect(
                fd,
                (&sin as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
    }

    fn refused(to: SocketAddrV4) -> i32 {
        // SAFETY: socket() takes scalar args.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return 8;
        }
        if connect(fd, to) == 0 {
            return 1;
        }
        if errno() == libc::ECONNREFUSED {
            0
        } else {
            8
        }
    }

    fn nonblocking(to: SocketAddrV4) -> i32 {
        // SAFETY: socket() takes scalar args.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
        if fd < 0 {
            return 8;
        }
        if connect(fd, to) == 0 {
            return 1;
        }
        match errno() {
            libc::ECONNREFUSED => return 2,
            libc::EINPROGRESS => {}
            _ => return 8,
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let mut pending: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: one valid pollfd; getsockopt writes one int.
        let read = unsafe {
            libc::poll(&mut pfd, 1, 5000) == 1
                && libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut pending as *mut libc::c_int).cast(),
                    &mut len,
                ) == 0
        };
        match (read, pending) {
            (true, libc::ECONNREFUSED) => 0,
            (true, 0) => 1,
            _ => 8,
        }
    }

    fn twice(to: SocketAddrV4) -> i32 {
        // SAFETY: socket() takes scalar args.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if fd < 0 || connect(fd, to) != 0 {
            return 8;
        }
        let mut byte = [0u8; 1];
        // SAFETY: read into a one-byte buffer owned here.
        if unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) } != 1 {
            return 8;
        }
        if connect(fd, to) == 0 {
            return 1;
        }
        if errno() == libc::EISCONN {
            0
        } else {
            8
        }
    }

    pub fn main() -> i32 {
        let mut args = std::env::args().skip(1);
        let (Some(mode), Some(Ok(to))) = (args.next(), args.next().map(|a| a.parse())) else {
            return 8;
        };
        match mode.as_str() {
            "refused" => refused(to),
            "nonblocking" => nonblocking(to),
            "twice" => twice(to),
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
