//! Test-support binary: probes whether the macOS system resolver is reachable from inside the
//! sandbox. Seatbelt classifies an AF_UNIX connect as `network-outbound`, so FW-ISO3's blanket
//! `(deny network*)` also severs `getaddrinfo` -- an FW-ISO5 port tier that cannot resolve a name
//! reaches literal IPs only. Reports purely via exit code:
//!   0  connected to the resolver socket -- name resolution can proceed
//!   7  connect() -> EPERM/EACCES        -- the sandbox denied it
//!   8  reached connect() but failed for another reason
//!
//! Connecting to the socket is the boundary itself, and unlike a real `getaddrinfo` it needs no
//! working DNS, so the paired allow/deny probes are deterministic offline. `localhost` would not
//! serve: libinfo answers it without ever reaching mDNSResponder, so it passes under both policies.
//! Whether the socket exists at all is the caller's precondition to check -- confinement must not be
//! given the chance to disguise a denial as absence.
//!
//! Deliberately std-only, so it starts wherever `/bin/cat` does under the read-only policy.

use std::io::ErrorKind;
use std::os::unix::net::UnixStream;

fn main() {
    let code = match UnixStream::connect(formwork_compile::MACOS_RESOLVER_SOCKET) {
        Ok(_) => 0,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => 7,
        Err(_) => 8,
    };
    std::process::exit(code);
}
