//! Shared test scaffolding: locating the in-sandbox helper binary and a stub "gateway" echo
//! responder that stands in for an MCP backend on the launcher side of the seam.
#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// Canonicalized so it matches the real path the confiner grants on macOS (where `/var` etc. are
/// symlinks).
pub fn helper_path() -> PathBuf {
    let p = PathBuf::from(env!("CARGO_BIN_EXE_fw-seam-child"));
    std::fs::canonicalize(&p).unwrap_or(p)
}

/// The newline is consumed, not returned.
pub fn read_line(stream: &mut UnixStream) -> io::Result<String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte)? {
            0 => {
                if buf.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed before sending a line",
                    ));
                }
                break;
            }
            _ => {
                if byte[0] == b'\n' {
                    break;
                }
                buf.push(byte[0]);
            }
        }
    }
    String::from_utf8(buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "line was not valid UTF-8"))
}

/// A read timeout keeps the test from hanging if the confined child never writes; its exit code
/// is the real signal.
pub fn serve_ok(stream: &mut UnixStream) -> io::Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let req = read_line(stream)?;
    stream.write_all(format!("ok:{req}\n").as_bytes())?;
    stream.flush()?;
    Ok(req)
}
