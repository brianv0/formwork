//! Test-support binary (FW-ADV-006): attempts to connect to the UNIX socket named in argv[1] and
//! reports the outcome purely via exit code. A leading `@` names an abstract-namespace socket
//! (`@name`); anything else is a pathname socket. Landlock ABI v6 scoping covers abstract sockets
//! and signals only, so the two address families are the two arms of the test: an out-of-domain
//! abstract socket must be unreachable on a capable kernel, while a pathname socket stays reachable
//! and is reported as the residual (formwork.md section 9).
//!   0  connect failed
//!   4  connect succeeded
//!   8  no socket argument
//!
//! Deliberately std-only so it starts wherever `/bin/cat` does under Closed-mode essentials.

fn main() {
    let target = match std::env::args().nth(1) {
        Some(p) => p,
        None => std::process::exit(8),
    };
    let connected = match target.strip_prefix('@') {
        Some(name) => connect_abstract(name),
        None => std::os::unix::net::UnixStream::connect(&target).is_ok(),
    };
    std::process::exit(if connected { 4 } else { 0 });
}

#[cfg(target_os = "linux")]
fn connect_abstract(name: &str) -> bool {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixStream};
    match SocketAddr::from_abstract_name(name.as_bytes()) {
        Ok(addr) => UnixStream::connect_addr(&addr).is_ok(),
        Err(_) => false,
    }
}

#[cfg(not(target_os = "linux"))]
fn connect_abstract(_name: &str) -> bool {
    false
}
