//! The egress listener's peer-process check (FW-EGR9 on macOS; FEP-5 §3.1, characterization C2).
//!
//! SBPL remote filters accept only `*` or `localhost` as the host, so the profile confines the
//! session to the listener's port but cannot keep another local process from reaching it. The
//! per-session proxy credential is the first gate; this is the second: an accepted loopback
//! connection is admitted only when a process of the session holds its client end. Membership is
//! asked of each process's sandbox, never inferred from ancestry, so a reparented or regrouped
//! descendant still counts: every session process carries the profile, whose marker
//! ([`SessionMarker`]) only this session's processes answer to.

use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::raw::{c_char, c_int, c_void};

use formwork_compile::SessionMarker;

extern "C" {
    // libsystem_sandbox; variadic, the filter argument follows `filter_type`.
    fn sandbox_check(pid: libc::pid_t, operation: *const c_char, filter_type: c_int, ...) -> c_int;
}

const SANDBOX_FILTER_GLOBAL_NAME: c_int = 2;
/// Ask without a violation record: the check must not feed `learn` (FW-DISC2).
const SANDBOX_CHECK_NO_REPORT: c_int = 0x4000_0000;

/// `struct socket_fdinfo` from <sys/proc_info.h>, as byte offsets, characterized on macOS 14 and
/// 15 (C2): the kernel copies this many bytes for `PROC_PIDFDSOCKETINFO`.
const SOCKET_FDINFO_SIZE: usize = 792;
const PROC_PIDFDSOCKETINFO: c_int = 3;
const PROX_FDTYPE_SOCKET: u32 = 2;
const SOI_KIND: usize = 256;
const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;
/// `in_sockinfo` at the start of `soi_proto`: ports in network byte order in the low 16 bits.
const INSI_FPORT: usize = 264;
const INSI_LPORT: usize = 268;
const INSI_VFLAG: usize = 288;
const INI_IPV4: u8 = 0x1;
/// 16-byte address unions; an IPv4 address is the last four bytes.
const INSI_FADDR: usize = 296;
const INSI_LADDR: usize = 312;

/// Whether `pid` is confined by a profile that carries `marker`: denied its first service and
/// allowed its second. An unconfined process is allowed both; another sandbox denies both or
/// allows both.
pub fn carries_marker(pid: libc::pid_t, marker: &SessionMarker) -> bool {
    let check = |name: String| -> Option<c_int> {
        let op = CString::new("mach-lookup").ok()?;
        let name = CString::new(name).ok()?;
        // SAFETY: both strings are NUL-terminated and outlive the call; the variadic argument is
        // the C string the GLOBAL_NAME filter takes.
        Some(unsafe {
            sandbox_check(
                pid,
                op.as_ptr(),
                SANDBOX_FILTER_GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT,
                name.as_ptr(),
            )
        })
    };
    check(marker.denied_service()) == Some(1) && check(marker.allowed_service()) == Some(0)
}

/// One TCP endpoint pair a process holds, as the kernel reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldSocket {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// The TCP sockets `pid` holds. Empty when the process is gone or not ours to inspect.
pub fn held_sockets(pid: libc::pid_t) -> Vec<HeldSocket> {
    let mut fds: Vec<libc::proc_fdinfo> = Vec::new();
    // SAFETY: a null buffer asks for the size; the second call writes at most `bytes` bytes into
    // a buffer of that capacity.
    unsafe {
        let bytes = libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0);
        if bytes <= 0 {
            return Vec::new();
        }
        let room = bytes as usize / std::mem::size_of::<libc::proc_fdinfo>() + 16;
        fds.reserve_exact(room);
        let got = libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr() as *mut c_void,
            (room * std::mem::size_of::<libc::proc_fdinfo>()) as c_int,
        );
        if got <= 0 {
            return Vec::new();
        }
        fds.set_len(got as usize / std::mem::size_of::<libc::proc_fdinfo>());
    }
    fds.iter()
        .filter(|f| f.proc_fdtype == PROX_FDTYPE_SOCKET)
        .filter_map(|f| socket_info(pid, f.proc_fd))
        .collect()
}

fn socket_info(pid: libc::pid_t, fd: i32) -> Option<HeldSocket> {
    let mut buf = [0u8; SOCKET_FDINFO_SIZE];
    // SAFETY: the kernel writes at most `buf.len()` bytes.
    let got = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as c_int,
        )
    };
    if got < (INSI_LADDR + 16) as c_int {
        return None;
    }
    parse_socket_fdinfo(&buf)
}

/// Read the TCP or IP endpoints out of a `socket_fdinfo`; `None` for any other socket kind.
fn parse_socket_fdinfo(buf: &[u8]) -> Option<HeldSocket> {
    let i32_at = |off: usize| i32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
    let kind = i32_at(SOI_KIND);
    if kind != SOCKINFO_IN && kind != SOCKINFO_TCP {
        return None;
    }
    let port = |off: usize| u16::from_be_bytes([buf[off], buf[off + 1]]);
    let addr = |off: usize| -> IpAddr {
        if buf[INSI_VFLAG] & INI_IPV4 != 0 {
            IpAddr::V4(Ipv4Addr::new(
                buf[off + 12],
                buf[off + 13],
                buf[off + 14],
                buf[off + 15],
            ))
        } else {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[off..off + 16]);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    };
    Some(HeldSocket {
        local: SocketAddr::new(addr(INSI_LADDR), port(INSI_LPORT)),
        remote: SocketAddr::new(addr(INSI_FADDR), port(INSI_FPORT)),
    })
}

/// Every process on the host.
fn all_pids() -> Vec<libc::pid_t> {
    // SAFETY: a null buffer asks for the count; the second call writes at most the buffer's size.
    unsafe {
        let count = libc::proc_listallpids(std::ptr::null_mut(), 0);
        if count <= 0 {
            return Vec::new();
        }
        let room = count as usize + 64;
        let mut pids: Vec<libc::pid_t> = vec![0; room];
        let got = libc::proc_listallpids(
            pids.as_mut_ptr() as *mut c_void,
            (room * std::mem::size_of::<libc::pid_t>()) as c_int,
        );
        pids.truncate(got.max(0) as usize);
        pids
    }
}

/// FW-EGR9: whether a process of the session marked by `marker` holds the client end of the
/// connection the listener at `listener` accepted from `peer`. Unresolvable is `false`.
pub fn session_holds_connection(
    marker: &SessionMarker,
    peer: SocketAddr,
    listener: SocketAddr,
) -> bool {
    let me = std::process::id() as libc::pid_t;
    all_pids()
        .into_iter()
        .filter(|&pid| pid > 0 && pid != me)
        .filter(|&pid| carries_marker(pid, marker))
        .any(|pid| {
            held_sockets(pid)
                .iter()
                .any(|s| same_endpoint(s.local, peer) && same_endpoint(s.remote, listener))
        })
}

/// Loopback endpoints compare by port and address, an IPv4-mapped IPv6 address equal to its IPv4.
fn same_endpoint(a: SocketAddr, b: SocketAddr) -> bool {
    let canon = |ip: IpAddr| match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    a.port() == b.port() && canon(a.ip()) == canon(b.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_its_own_loopback_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let held = held_sockets(std::process::id() as libc::pid_t);
        let want = HeldSocket {
            local: client.local_addr().unwrap(),
            remote: listener.local_addr().unwrap(),
        };
        assert!(held.contains(&want), "{want:?} not in {held:?}");
    }

    #[test]
    fn an_unconfined_process_does_not_carry_a_marker() {
        let marker = SessionMarker::new("0123456789abcdef");
        assert!(!carries_marker(std::process::id() as libc::pid_t, &marker));
    }
}
