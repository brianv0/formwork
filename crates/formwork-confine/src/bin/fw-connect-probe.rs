//! Test-support binary: a self-contained outbound-egress probe the Seatbelt tests run *inside* the
//! sandbox. It is not part of the shipped `formwork` binary (releases build only `formwork-cli`).
//!
//! It attempts one TCP connect and reports the outcome purely via exit code, so a confined parent
//! can tell a policy denial apart from any other failure:
//!   0  connected            -- egress LEAKED
//!   7  connect() -> EPERM/EACCES -- the sandbox denied it at connect()
//!   8  reached connect() but failed for another reason (timeout, refused, ...)
//!
//! The destination port defaults to 80 but can be overridden by argv[1], so the Landlock port-tier
//! test can probe a *granted* port (expects not-EPERM) and a *non-granted* port (expects EPERM) with
//! the same binary. `socket(AF_INET, SOCK_STREAM)` itself stays allowed under the port tier -- only
//! the connect() to a non-granted port is denied by Landlock.
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
    // the kernel rejects connect() immediately, so the address is never actually routed to. The port
    // is argv[1] (default 80) so the port-tier test can aim at a granted vs a non-granted port.
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let addr = SocketAddr::from(([93, 184, 216, 34], port));
    let code = match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        Ok(_) => 0,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => 7,
        Err(_) => 8,
    };
    std::process::exit(code);
}
