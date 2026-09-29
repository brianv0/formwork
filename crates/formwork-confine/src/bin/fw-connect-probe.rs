//! Test-support binary: a self-contained outbound-egress probe the Seatbelt tests run *inside* the
//! sandbox. It is not part of the shipped `formwork` binary (releases build only `formwork-cli`).
//!
//! It attempts one TCP connect and reports the outcome purely via exit code, so a confined parent
//! can tell a policy denial apart from any other failure:
//!   0  connected            -- egress LEAKED
//!   7  connect() -> EPERM/EACCES -- the sandbox denied it at connect()
//!   8  reached connect() but failed for another reason (timeout, refused, ...)
//!
//! With `fastopen` as argv[2] (Linux) it connects by TCP Fast Open instead: one `sendmsg` carrying
//! the address and `MSG_FASTOPEN`, which never calls `connect(2)`.
//!
//! Deliberately std-only, so it links just libSystem and starts under Formwork's read-only Seatbelt
//! policy wherever `/bin/cat` does. The probe previously shelled out to `/usr/bin/python3`, but on
//! hosts whose `xcode-select` points into `/Applications/Xcode.app` (e.g. GitHub's macOS runners)
//! that CLT stub routes to an interpreter outside the read scope and dies before `connect()`.

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

fn main() {
    // Static IP -- no DNS, which would need lookups/reads beyond the probe's point. Under net=deny
    // the kernel rejects connect() immediately, so the address is never actually routed to.
    // The port is argv[1] (default 80), so the port-tier test can aim at a granted and a
    // non-granted port with one binary.
    // argv[1] is a port on the static address, or a full `ip:port` (the supervised-connect tests
    // aim at their loopback Gateway stand-in).
    let arg = std::env::args().nth(1);
    let addr = match arg.as_deref() {
        Some(a) if a.contains(':') => a.parse().expect("ip:port"),
        Some(p) => SocketAddr::from(([93, 184, 216, 34], p.parse().unwrap_or(80))),
        None => SocketAddr::from(([93, 184, 216, 34], 80)),
    };
    let outcome = match std::env::args().nth(2).as_deref() {
        #[cfg(target_os = "linux")]
        Some("fastopen") => fastopen(addr),
        _ => TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map(drop),
    };
    let code = match outcome {
        Ok(()) => 0,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => 7,
        Err(_) => 8,
    };
    std::process::exit(code);
}

#[cfg(target_os = "linux")]
fn fastopen(addr: SocketAddr) -> std::io::Result<()> {
    let SocketAddr::V4(v4) = addr else {
        return Err(ErrorKind::Unsupported.into());
    };
    let mut sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: v4.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(*v4.ip()).to_be(),
        },
        sin_zero: [0; 8],
    };
    let mut payload = *b"fastopen";
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: a zeroed msghdr is valid; every pointer set below outlives the sendmsg call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&mut sin as *mut libc::sockaddr_in).cast();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: plain syscalls on a socket this function owns and closes.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let sent = libc::sendmsg(fd, &msg, libc::MSG_FASTOPEN);
        let result = if sent < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        };
        libc::close(fd);
        result
    }
}
