//! Test-support binary: pathname UNIX-socket probe for supervised connect (FW-ISO12, FW-E2E-076).
//! Reports via exit code:
//!   0  connected (and, for `selfbind`, bound first)
//!   7  refused with EACCES/EPERM -- the supervisor or the sandbox denied it
//!   8  any other failure
//!
//! `fw-unix-probe connect <path>` connects to an existing socket; `fw-unix-probe selfbind <path>`
//! binds a listener at `path` inside the session, then connects to it.

use std::io::ErrorKind;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};

fn code(e: &std::io::Error) -> i32 {
    if e.kind() == ErrorKind::PermissionDenied {
        7
    } else {
        8
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mode, path) = match (args.next(), args.next()) {
        (Some(m), Some(p)) => (m, p),
        _ => std::process::exit(8),
    };
    let result = match mode.as_str() {
        "connect" => UnixStream::connect(&path).map(|_| ()),
        "selfbind" => match UnixListener::bind(&path) {
            Ok(_listener) => UnixStream::connect(&path).map(|_| ()),
            Err(e) => Err(e),
        },
        "sendto" => UnixDatagram::unbound().and_then(|d| d.send_to(b"x", &path).map(|_| ())),
        _ => std::process::exit(8),
    };
    std::process::exit(match result {
        Ok(()) => 0,
        Err(e) => code(&e),
    });
}
