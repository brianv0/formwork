//! Test-support binary: a UDP egress probe -- the datagram sibling of `fw-connect-probe`. Formwork
//! never grants UDP egress (net-deny blocks inet `socket(2)` *creation*, which covers TCP, UDP, and
//! raw alike), so even binding a UDP socket must fail. Reports purely via exit code:
//!   0  socket created (+ sendto attempted) -- UDP egress LEAKED
//!   7  socket()/sendto() -> EPERM/EACCES   -- the sandbox denied it
//!   8  reached the socket but failed for another reason
//!
//! Deliberately std-only, so it starts wherever `/bin/cat` does under Closed-mode essentials.

use std::io::ErrorKind;
use std::net::UdpSocket;

fn main() {
    // `bind` performs socket(AF_INET, SOCK_DGRAM); under net-deny the seccomp family filter rejects it
    // at creation, so the datagram is never actually routed to the (static, no-DNS) address.
    let code = match UdpSocket::bind(("0.0.0.0", 0)) {
        Ok(sock) => match sock.send_to(b"x", "93.184.216.34:53") {
            Ok(_) => 0,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => 7,
            Err(_) => 8,
        },
        Err(e) if e.kind() == ErrorKind::PermissionDenied => 7,
        Err(_) => 8,
    };
    std::process::exit(code);
}
