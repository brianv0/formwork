//! Test-support binary (FW-ADV-006): attempts to connect to the pathname UNIX socket named in
//! argv[1] -- used to prove a confined process cannot reach an out-of-domain UNIX socket on a
//! scope-capable (Landlock ABI v6) kernel. Reports purely via exit code:
//!   0  connect failed -- blocked (expected once UNIX-socket scoping is in force)
//!   4  connect succeeded -- reached an out-of-domain socket (LEAK/FAIL)
//!   8  no socket-path argument
//!
//! Deliberately std-only so it starts wherever `/bin/cat` does under Closed-mode essentials.

use std::os::unix::net::UnixStream;

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => std::process::exit(8),
    };
    match UnixStream::connect(&path) {
        Ok(_) => std::process::exit(4),
        Err(_) => std::process::exit(0),
    }
}
