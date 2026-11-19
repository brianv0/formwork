//! Test-support binary: the socket-family probe (FW-E2E-187). Run inside confinement, it asks for
//! sockets inside and outside the posture's admitted set (FW-ISO28, FW-ISO35) and reports purely
//! via exit code. A refusal counts only as `EPERM`: the filter answers before the kernel looks at
//! the family, so any other errno means the kernel, not the sandbox, said no.
//!
//!   0     every check held (PASS)
//!   10+n  check `n` of the mode's table was answered wrongly (FAIL)
//!   40    an AF_UNIX socketpair was refused -- local IPC is broken (FAIL)
//!   41    a socketpair of a family outside the set was not refused with EPERM (FAIL)
//!
//! `argv[1]` picks the table: none for `net = "deny"`, `stream` for a posture that admits inet TCP
//! streams (port tier, host rules).
//!
//! Deliberately libc-only so it starts wherever `/bin/cat` does under Closed-mode essentials.

#[cfg(target_os = "linux")]
fn main() {
    use libc::{
        AF_INET, AF_INET6, AF_NETLINK, AF_PACKET, AF_UNIX, AF_VSOCK, IPPROTO_ICMP, IPPROTO_MPTCP,
        IPPROTO_SCTP, IPPROTO_TCP, NETLINK_ROUTE, NETLINK_SOCK_DIAG, SOCK_CLOEXEC, SOCK_DGRAM,
        SOCK_NONBLOCK, SOCK_RAW, SOCK_SEQPACKET, SOCK_STREAM,
    };
    // <linux/socket.h>; not in every libc the probe builds against.
    const AF_ALG: i32 = 38;
    const AF_SMC: i32 = 43;
    // One above AF_MCTP, the highest family Linux 6.18 assigns: the family a later kernel adds.
    const UNASSIGNED: i32 = 46;
    // ETH_P_ALL in network byte order, what a packet sniffer asks for.
    const ETH_P_ALL: i32 = 0x0300;

    // (domain, type, protocol, admitted)
    const NET_DENY: &[(i32, i32, i32, bool)] = &[
        (AF_UNIX, SOCK_STREAM, 0, true),
        (AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, true),
        (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE, true),
        (AF_VSOCK, SOCK_STREAM, 0, false),
        (AF_ALG, SOCK_SEQPACKET, 0, false),
        (AF_PACKET, SOCK_RAW, ETH_P_ALL, false),
        (AF_PACKET, SOCK_DGRAM, 0, false),
        (AF_SMC, SOCK_STREAM, 0, false),
        (UNASSIGNED, SOCK_STREAM, 0, false),
        (AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG, false),
        (AF_INET, SOCK_STREAM, 0, false),
        (AF_INET6, SOCK_DGRAM, 0, false),
    ];
    const STREAM: &[(i32, i32, i32, bool)] = &[
        (AF_INET, SOCK_STREAM, 0, true),
        (
            AF_INET,
            SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
            IPPROTO_TCP,
            true,
        ),
        (AF_UNIX, SOCK_STREAM, 0, true),
        (AF_INET, SOCK_STREAM, IPPROTO_MPTCP, false),
        (AF_INET6, SOCK_STREAM, IPPROTO_MPTCP, false),
        (AF_INET, SOCK_STREAM, IPPROTO_SCTP, false),
        (AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP, false),
        (AF_INET, SOCK_DGRAM, 0, false),
        (AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0, false),
        (AF_INET, SOCK_RAW, IPPROTO_ICMP, false),
        (AF_SMC, SOCK_STREAM, 0, false),
        (AF_VSOCK, SOCK_STREAM, 0, false),
    ];

    let table = match std::env::args().nth(1).as_deref() {
        Some("stream") => STREAM,
        _ => NET_DENY,
    };
    for (n, &(domain, ty, protocol, admitted)) in table.iter().enumerate() {
        // SAFETY: socket() takes scalar args; a returned fd is owned here and closed.
        let fd = unsafe { libc::socket(domain, ty, protocol) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        if fd >= 0 {
            // SAFETY: closing the fd socket() just returned.
            unsafe { libc::close(fd) };
        }
        let held = if admitted {
            fd >= 0
        } else {
            fd < 0 && errno == Some(libc::EPERM)
        };
        if !held {
            std::process::exit(10 + n as i32);
        }
    }

    let mut sv = [0i32; 2];
    // SAFETY: socketpair writes two fds into the owned array on success.
    if unsafe { libc::socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        std::process::exit(40);
    }
    // SAFETY: closing the two fds socketpair just returned.
    unsafe {
        libc::close(sv[0]);
        libc::close(sv[1]);
    }
    // The kernel creates both sockets before it finds that the family has no pairs.
    // SAFETY: as above; nothing is written on failure.
    let rc = unsafe { libc::socketpair(AF_VSOCK, SOCK_STREAM, 0, sv.as_mut_ptr()) };
    if rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
        std::process::exit(41);
    }
    std::process::exit(0);
}

#[cfg(not(target_os = "linux"))]
fn main() {}
