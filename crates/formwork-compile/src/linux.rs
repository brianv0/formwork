//! Linux confiner-policy construction: the seccomp baseline (FW-ISO8) and the net plan.
//!
//! The seccomp baseline is deny-list shaped, not allow-list shaped: an allow-list breaks the moment
//! a toolchain reaches for a forgotten syscall, which is the transparency failure FW-TRA2 forbids.
//! So it blocks a small fixed set of shedding/escalation surfaces and lets everything else through;
//! Landlock, not seccomp, carries the filesystem boundary. Socket creation is the exception
//! (FW-ISO28): the families a session needs are few and known, and a deny-list of the rest is wrong
//! again at the next kernel release.

use formwork_blueprint::NetPosture;
use formwork_detect::HostProfile;

use crate::policy::{LinuxNetPlan, SeccompPlan, SocketFamily};

/// Landlock ABI at which TCP network rules (`ACCESS_NET_CONNECT_TCP`) become available.
pub const LANDLOCK_NET_ABI: u32 = 4;

/// Escalation and confinement-shedding syscalls denied outright (EPERM). Sorted for byte-identical
/// output (FW-FID4); none is touched by an ordinary build/test/vcs toolchain.
const BASELINE_DENY: &[&str] = &[
    "add_key",
    "bpf",
    "finit_module",
    "init_module",
    // io_uring submits file/net operations through a ring that has historically bypassed seccomp and
    // LSM checks -- a classic sandbox-escape surface, denied outright.
    "io_uring_enter",
    "io_uring_register",
    "io_uring_setup",
    "kexec_file_load",
    "kexec_load",
    "keyctl",
    "mount",
    "mount_setattr",
    "move_mount",
    "open_by_handle_at",
    "perf_event_open",
    // Cross-process reach-in: steal a live fd (e.g. a connected socket) from, or write the memory of,
    // an *unconfined* same-uid sibling to hijack it. `ptrace` denial does not cover these -- they gate
    // on `ptrace_may_access`, not the ptrace syscall.
    "pidfd_getfd",
    "pivot_root",
    "process_vm_readv",
    "process_vm_writev",
    "ptrace",
    "request_key",
    "setns",
];

/// Which inet sockets the seccomp allow-list admits for a net plan. Landlock net governs only
/// TCP, so seccomp carries at least the UDP/raw half of net default-deny on every Linux path
/// (FW-ISO11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InetSeccompDeny {
    /// No inet socket is admitted: TCP, UDP and raw are refused at creation.
    FullInet,
    /// Inet TCP stream sockets are admitted; every other inet socket is refused.
    DgramRawOnly,
}

/// Build the seccomp baseline, the socket allow-list `inet_deny` calls for, and the flag refusals.
pub fn seccomp_plan(
    inet_deny: InetSeccompDeny,
    supervise_connect: bool,
    exec_allowlist: bool,
) -> SeccompPlan {
    let deny_syscalls: Vec<String> = BASELINE_DENY.iter().map(|s| s.to_string()).collect();
    debug_assert!(
        deny_syscalls.windows(2).all(|w| w[0] < w[1]),
        "BASELINE_DENY must stay sorted"
    );

    // FW-ISO28. Order is fixed for byte-identical output (FW-FID4).
    let mut allow_socket_families = vec![SocketFamily::Unix, SocketFamily::NetlinkRoute];
    if inet_deny == InetSeccompDeny::DgramRawOnly {
        // STREAM survives for the Landlock TCP port rules, or the supervisor, to govern.
        allow_socket_families.extend([SocketFamily::InetTcpStream, SocketFamily::Inet6TcpStream]);
    }

    SeccompPlan {
        deny_syscalls,
        allow_socket_families,
        // FW-ISO29 binds the postures that admit stream sockets; an inherited stream socket is the
        // same door under `net = "deny"`, so the refusal is not conditioned on the posture.
        deny_send_fastopen: true,
        deny_exec_by_descriptor: exec_allowlist,
        supervise_connect,
        restrict_userns: true,
        set_no_new_privs: true,
    }
}

/// Returns `(plan, inet_deny, port_tier)`.
pub fn net_plan(host: &HostProfile, net: &NetPosture) -> (LinuxNetPlan, InetSeccompDeny, PortTier) {
    let abi = host.landlock_abi.unwrap_or(0);
    match net {
        // No inet socket is admitted (TCP, UDP and raw refused at creation), matching macOS
        // `(deny network*)`. AF_UNIX (local IPC) stays allowed.
        NetPosture::Deny => (
            LinuxNetPlan::SeccompDenyInet,
            InetSeccompDeny::FullInet,
            PortTier::NotRequested,
        ),
        NetPosture::Ports(ports) => {
            if abi >= LANDLOCK_NET_ABI {
                // Landlock allow-connects the granted TCP ports; seccomp admits no inet socket but a
                // TCP stream, so the TCP-only Landlock grant cannot be sidestepped with a UDP/raw
                // socket (FW-ISO3/INV3).
                (
                    LinuxNetPlan::LandlockTcpSeccompDgramRawDeny {
                        ports: ports.clone(),
                    },
                    InetSeccompDeny::DgramRawOnly,
                    PortTier::Enforced,
                )
            } else {
                // Cannot honor the port tier; fall back to full seccomp deny (fail-closed) and
                // report the tier unenforceable -- no silent open (FW-INV6).
                (
                    LinuxNetPlan::SeccompDenyInet,
                    InetSeccompDeny::FullInet,
                    PortTier::UnenforceableBelowAbi4,
                )
            }
        }
        // FW-EGR7: the supervisor mediates every connect; without it the posture fails closed to
        // the full inet deny and the report says so (FW-INV6).
        NetPosture::AllowHosts(_) if host.can_supervise_connect() => (
            LinuxNetPlan::SupervisedConnect,
            InetSeccompDeny::DgramRawOnly,
            PortTier::NotRequested,
        ),
        NetPosture::AllowHosts(_) => (
            LinuxNetPlan::SeccompDenyInet,
            InetSeccompDeny::FullInet,
            PortTier::NotRequested,
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortTier {
    NotRequested,
    Enforced,
    UnenforceableBelowAbi4,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_is_sorted_and_denies_escalation_surfaces() {
        // The escalation/shedding baseline is present regardless of which socket allow-list rides along.
        let plan = seccomp_plan(InetSeccompDeny::FullInet, false, false);
        assert!(plan.deny_syscalls.windows(2).all(|w| w[0] < w[1]));
        assert!(plan.deny_syscalls.iter().any(|s| s == "bpf"));
        assert!(plan.deny_syscalls.iter().any(|s| s == "setns"));
        // Escape surfaces added in the hardening pass: io_uring (seccomp/LSM bypass) and cross-process
        // reach-in (fd theft / memory write into an unconfined sibling).
        for s in [
            "io_uring_setup",
            "pidfd_getfd",
            "process_vm_readv",
            "process_vm_writev",
        ] {
            assert!(plan.deny_syscalls.iter().any(|d| d == s), "missing {s}");
        }
        assert!(plan.restrict_userns);
        assert!(plan.set_no_new_privs);
    }

    #[test]
    fn fw_iso28_net_deny_admits_unix_and_route_netlink_only() {
        let plan = seccomp_plan(InetSeccompDeny::FullInet, false, false);
        assert_eq!(
            plan.allow_socket_families,
            [SocketFamily::Unix, SocketFamily::NetlinkRoute],
            "no inet family is admitted under an outright deny"
        );
    }

    #[test]
    fn fw_iso28_fw_iso35_stream_postures_add_inet_tcp_streams_only() {
        // The only inet entries are the TCP-stream ones: there is no entry that admits a datagram,
        // raw, MPTCP or SCTP socket (FW-ISO11, FW-ISO35).
        for supervised in [false, true] {
            let plan = seccomp_plan(InetSeccompDeny::DgramRawOnly, supervised, false);
            assert_eq!(
                plan.allow_socket_families,
                [
                    SocketFamily::Unix,
                    SocketFamily::NetlinkRoute,
                    SocketFamily::InetTcpStream,
                    SocketFamily::Inet6TcpStream,
                ]
            );
        }
    }

    #[test]
    fn fw_iso29_every_posture_that_admits_streams_refuses_fastopen_sends() {
        for inet_deny in [InetSeccompDeny::DgramRawOnly, InetSeccompDeny::FullInet] {
            for supervised in [false, true] {
                assert!(seccomp_plan(inet_deny, supervised, false).deny_send_fastopen);
            }
        }
    }

    #[test]
    fn fw_iso31_only_an_exec_allowlist_refuses_exec_by_descriptor() {
        assert!(seccomp_plan(InetSeccompDeny::FullInet, false, true).deny_exec_by_descriptor);
        assert!(
            !seccomp_plan(InetSeccompDeny::FullInet, false, false).deny_exec_by_descriptor,
            "unrestricted exec keeps fexecve (FW-TRA2)"
        );
    }

    #[test]
    fn net_deny_always_uses_seccomp_inet_deny() {
        // Deny is carried by seccomp at every ABI so UDP/raw are covered, not just TCP.
        for abi in [1, 4, 6] {
            let host = HostProfile::synthetic_linux(Some(abi));
            let (plan, inet_deny, tier) = net_plan(&host, &NetPosture::Deny);
            assert!(
                matches!(plan, LinuxNetPlan::SeccompDenyInet),
                "abi {abi}: net-deny must be the complete seccomp inet deny"
            );
            assert_eq!(inet_deny, InetSeccompDeny::FullInet);
            assert_eq!(tier, PortTier::NotRequested);
        }
    }

    #[test]
    fn port_tier_pairs_landlock_tcp_with_seccomp_dgram_raw_deny() {
        let old = HostProfile::synthetic_linux(Some(1));
        let (plan, inet_deny, tier) = net_plan(&old, &NetPosture::Ports(vec![8080]));
        assert!(matches!(plan, LinuxNetPlan::SeccompDenyInet));
        assert_eq!(inet_deny, InetSeccompDeny::FullInet);
        assert_eq!(tier, PortTier::UnenforceableBelowAbi4);

        let new = HostProfile::synthetic_linux(Some(4));
        let (plan, inet_deny, tier) = net_plan(&new, &NetPosture::Ports(vec![8080]));
        assert!(
            matches!(&plan, LinuxNetPlan::LandlockTcpSeccompDgramRawDeny { ports } if ports == &vec![8080])
        );
        assert_eq!(plan.landlock_tcp_ports(), Some(&[8080][..]));
        // The port tier is NOT Landlock-only: seccomp must carry the DGRAM/RAW deny, or UDP/raw leaks.
        assert_eq!(inet_deny, InetSeccompDeny::DgramRawOnly);
        assert_eq!(tier, PortTier::Enforced);
    }
}
