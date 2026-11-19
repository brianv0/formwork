//! Test-support binary: the TCP Fast Open probe (FW-E2E-185). `MSG_FASTOPEN` on a send opens a TCP
//! connection without `connect()`, the one call the port tier and the connect supervisor mediate
//! (FW-ISO29). The probe makes each of `sendto`, `sendmsg` and `sendmmsg` to `argv[1]` (an IPv4
//! `ip:port`) on a fresh unconnected stream socket and reports purely via exit code. `n` is 0 for
//! `sendto`, 1 for `sendmsg`, 2 for `sendmmsg`.
//!
//!   0     every send was refused with EOPNOTSUPP (PASS)
//!   40+n  send `n` was not refused -- a connection was opened by a send (FAIL)
//!   80+n  send `n` failed with another errno (the kernel, not the sandbox, said no)
//!   3     setup failed (no socket, bad argument)
//!
//! With `argv[2] = plain` it is the allow half: it `connect()`s first and sends without the flag,
//! and exits 0 when all three sends deliver, 80+n when send `n` fails.
//!
//! Deliberately libc-only so it starts wherever `/bin/cat` does under Closed-mode essentials.

#[cfg(target_os = "linux")]
fn main() {
    use std::mem::{size_of, zeroed};
    use std::net::SocketAddrV4;
    use std::process::exit;

    let mut args = std::env::args().skip(1);
    let Some(addr) = args.next().and_then(|a| a.parse::<SocketAddrV4>().ok()) else {
        exit(3);
    };
    let plain = args.next().as_deref() == Some("plain");
    let dest = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(*addr.ip()).to_be(),
        },
        sin_zero: [0; 8],
    };
    let dest_ptr = (&dest as *const libc::sockaddr_in).cast::<libc::sockaddr>();
    let dest_len = size_of::<libc::sockaddr_in>() as libc::socklen_t;

    for n in 0..3 {
        // SAFETY: socket() takes scalar args; the fd is owned here and closed below.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            exit(3);
        }
        let (flags, name, name_len) = if plain {
            // SAFETY: `dest` is a valid sockaddr_in of `dest_len` bytes.
            if unsafe { libc::connect(fd, dest_ptr, dest_len) } != 0 {
                exit(3);
            }
            (libc::MSG_NOSIGNAL, std::ptr::null(), 0)
        } else {
            (libc::MSG_FASTOPEN, dest_ptr, dest_len)
        };
        let mut byte = *b"x";
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        // SAFETY: an all-zero msghdr is valid; the fields set below point at live locals.
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_name = name.cast_mut().cast();
        msg.msg_namelen = name_len;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        // SAFETY: every pointer names a live local of the stated length; the kernel only reads them.
        let sent = unsafe {
            match n {
                0 => libc::sendto(fd, byte.as_ptr().cast(), 1, flags, name, name_len),
                1 => libc::sendmsg(fd, &msg, flags),
                _ => {
                    let mut batch = libc::mmsghdr {
                        msg_hdr: msg,
                        msg_len: 0,
                    };
                    libc::sendmmsg(fd, &mut batch, 1, flags as _) as isize
                }
            }
        };
        let errno = std::io::Error::last_os_error().raw_os_error();
        // SAFETY: closing the fd created above.
        unsafe { libc::close(fd) };
        let held = if plain {
            sent >= 1
        } else {
            sent < 0 && errno == Some(libc::EOPNOTSUPP)
        };
        if !held {
            exit(if sent >= 0 { 40 } else { 80 } + n);
        }
    }
    exit(0);
}

#[cfg(not(target_os = "linux"))]
fn main() {}
