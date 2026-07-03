//! Test helper: the in-sandbox "agent" side of the fd seam (FW-E2E-010/011/012). It reaches its
//! "gateway" only through inherited/`SCM_RIGHTS`-passed descriptors -- never `connect()`, never a
//! socket path (FW-XR7). Exit codes the harness asserts:
//!
//! - `0` round-trip completed (and, when asked, a direct connect was denied by the sandbox);
//! - `3` seam workload failed;
//! - `4` a direct connect unexpectedly succeeded -- an egress leak, kept loud and distinct so it is
//!   never mistaken for a generic failure.
//!
//! Scenarios (argv[1]): `preopen <name> <msg> [--assert-net-denied]`, `mint <name> <msg> [...]`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Duration;

use formwork_seam::child;

const EXIT_OK: u8 = 0;
const EXIT_WORKLOAD_FAILED: u8 = 3;
const EXIT_NET_LEAK: u8 = 4;

/// A trivial stand-in for an MCP round-trip: the seam tests care only that a full exchange
/// completes over the injected fd.
fn roundtrip(mut sock: UnixStream, message: &str) -> Result<(), String> {
    sock.write_all(format!("{message}\n").as_bytes())
        .map_err(|e| format!("write request: {e}"))?;
    sock.flush().map_err(|e| format!("flush request: {e}"))?;

    let mut resp: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match sock
            .read(&mut byte)
            .map_err(|e| format!("read response: {e}"))?
        {
            0 => return Err("connection closed before a full response arrived".into()),
            _ => {
                if byte[0] == b'\n' {
                    break;
                }
                resp.push(byte[0]);
            }
        }
    }
    let got = String::from_utf8(resp).map_err(|e| format!("non-utf8 response: {e}"))?;
    let want = format!("ok:{message}");
    if got == want {
        Ok(())
    } else {
        Err(format!("unexpected response: got {got:?}, want {want:?}"))
    }
}

/// Attempt a direct TCP connect the sandbox must deny at the syscall (EPERM -> PermissionDenied).
/// `Ok(true)` denied (expected), `Ok(false)` connected (a LEAK), `Err` some other failure
/// (inconclusive as a sandbox proof).
fn direct_connect_denied() -> Result<bool, String> {
    // A routable public address; we never send bytes -- reaching connect() is the point.
    let addr = "93.184.216.34:80".parse().expect("static addr parses");
    match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(true),
        Err(e) => Err(format!("connect failed but not with EPERM: {:?}", e.kind())),
    }
}

fn run() -> Result<(), u8> {
    let args: Vec<String> = std::env::args().collect();
    let scenario = args.get(1).map(String::as_str).unwrap_or("");
    let assert_net_denied = args.iter().any(|a| a == "--assert-net-denied");

    let result = match scenario {
        "preopen" => {
            let name = args.get(2).ok_or(EXIT_WORKLOAD_FAILED)?;
            let message = args.get(3).ok_or(EXIT_WORKLOAD_FAILED)?;
            match child::connection(name) {
                Ok(sock) => roundtrip(sock, message),
                Err(e) => Err(format!("adopt connection {name:?}: {e}")),
            }
        }
        "mint" => {
            let name = args.get(2).ok_or(EXIT_WORKLOAD_FAILED)?;
            let message = args.get(3).ok_or(EXIT_WORKLOAD_FAILED)?;
            match child::control().and_then(|mut ctl| child::mint(&mut ctl, name)) {
                Ok(sock) => roundtrip(sock, message),
                Err(e) => Err(format!("mint connection {name:?}: {e}")),
            }
        }
        other => Err(format!("unknown scenario {other:?}")),
    };

    if let Err(msg) = result {
        eprintln!("fw-seam-child: {msg}");
        return Err(EXIT_WORKLOAD_FAILED);
    }

    if assert_net_denied {
        match direct_connect_denied() {
            Ok(true) => {}
            Ok(false) => {
                eprintln!(
                    "fw-seam-child: EGRESS LEAK — direct TCP connect() succeeded under net=Deny"
                );
                return Err(EXIT_NET_LEAK);
            }
            Err(msg) => {
                eprintln!("fw-seam-child: net-deny probe inconclusive: {msg}");
                return Err(EXIT_WORKLOAD_FAILED);
            }
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(code) => ExitCode::from(code),
    }
}
