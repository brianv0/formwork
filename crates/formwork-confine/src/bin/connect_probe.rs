//! Test-support binary: a self-contained outbound-egress probe the Seatbelt tests run *inside* the
//! sandbox. It is not part of the shipped `formwork` binary (releases build only `formwork-cli`).
//!
//! It attempts one TCP connect and reports the outcome purely via exit code, so a confined parent
//! can tell a policy denial apart from any other failure:
//!   0  connected            -- egress LEAKED
//!   7  connect() -> EPERM/EACCES -- the sandbox denied it at connect()
//!   8  reached connect() but failed for another reason (timeout, refused, ...)
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
    let addr: SocketAddr = "93.184.216.34:80".parse().expect("static addr literal");
    let code = match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        Ok(_) => 0,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => 7,
        Err(_) => 8,
    };
    std::process::exit(code);
}
