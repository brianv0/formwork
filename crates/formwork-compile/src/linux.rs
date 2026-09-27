//! Linux confiner-policy construction: the seccomp baseline (FW-ISO8) and the net plan.
//!
//! The seccomp baseline is deny-list shaped, not allow-list shaped: an allow-list breaks the moment
//! a toolchain reaches for a forgotten syscall, which is the transparency failure FW-TRA2 forbids.
//! So it blocks a small fixed set of shedding/escalation surfaces and lets everything else through;
//! Landlock, not seccomp, carries the filesystem boundary.

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

/// How the seccomp filter carries the inet-egress deny for a given net plan. Landlock net governs
/// only TCP, so seccomp always carries at least the UDP/raw half of net default-deny on Linux -- there
/// is no "Landlock-only" net-deny variant, which is exactly what closes the port-tier UDP/raw hole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InetSeccompDeny {
    /// Deny inet `socket(2)` at the family level: TCP + UDP + raw blocked at creation. The outright
    /// net-deny, and the sub-ABI-v4 port-tier fallback.
    FullInet,
    /// The port tier: deny inet/inet6 DGRAM and RAW `socket(2)` while allowing STREAM, so the Landlock
    /// per-port TCP rules govern TCP and direct UDP/raw egress fails closed (FW-ISO3/FW-INV3).
    DgramRawOnly,
}

/// Build the seccomp baseline plus whatever inet-egress deny `inet_deny` calls for.
pub fn seccomp_plan(inet_deny: InetSeccompDeny) -> SeccompPlan {
    let deny_syscalls: Vec<String> = BASELINE_DENY.iter().map(|s| s.to_string()).collect();
    debug_assert!(
        deny_syscalls.windows(2).all(|w| w[0] < w[1]),
        "BASELINE_DENY must stay sorted"
    );

    // AF_UNIX and socketpair are never listed, so the injected-fd seam stays untouched (FW-XR7).
    let (deny_socket_families, deny_inet_dgram_raw) = match inet_deny {
        // Full inet deny: block the whole inet/inet6 families plus packet + non-route netlink.
        InetSeccompDeny::FullInet => (
            vec![
                SocketFamily::Inet,
                SocketFamily::Inet6,
                SocketFamily::Packet,
                SocketFamily::NetlinkNonRoute,
            ],
            false,
        ),
        // Port tier: keep packet + non-route netlink denied, but replace the blanket inet/inet6 deny
        // with a DGRAM/RAW-only deny so STREAM survives for the Landlock TCP port rules to govern.
        InetSeccompDeny::DgramRawOnly => (
            vec![SocketFamily::Packet, SocketFamily::NetlinkNonRoute],
            true,
        ),
    };

    SeccompPlan {
        deny_syscalls,
        deny_socket_families,
        deny_inet_dgram_raw,
        restrict_userns: true,
        set_no_new_privs: true,
    }
}

/// Returns `(plan, inet_deny, port_tier)`. `inet_deny` tells the compiler which seccomp inet deny to
/// build and lets the report state honestly that net-deny is (at least partly) seccomp-carried.
pub fn net_plan(host: &HostProfile, net: &NetPosture) -> (LinuxNetPlan, InetSeccompDeny, PortTier) {
    let abi = host.landlock_abi.unwrap_or(0);
    match net {
        NetPosture::Deny => {
            // Deny ALL inet egress via seccomp (blocks TCP, UDP, and raw at the socket-family level),
            // matching macOS `(deny network*)`. Landlock net governs *only* TCP, so carrying deny with
            // it would leave UDP/raw open -- an exfil channel. AF_UNIX (the injected-fd seam) stays
            // allowed. Landlock net is reserved for the port tier, where per-port TCP allow is needed.
            (
                LinuxNetPlan::SeccompDenyInet,
                InetSeccompDeny::FullInet,
                PortTier::NotRequested,
            )
        }
        NetPosture::Ports(ports) => {
            if abi >= LANDLOCK_NET_ABI {
                // Landlock allow-connects the granted TCP ports; seccomp denies inet DGRAM/RAW so the
                // TCP-only Landlock grant cannot be sidestepped with a UDP/raw socket (FW-ISO3/INV3).
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
        // The escalation/shedding baseline is present regardless of which inet deny rides along.
        let plan = seccomp_plan(InetSeccompDeny::FullInet);
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
    fn full_inet_deny_blocks_whole_families() {
        let plan = seccomp_plan(InetSeccompDeny::FullInet);
        assert!(plan.deny_socket_families.contains(&SocketFamily::Inet));
        assert!(plan.deny_socket_families.contains(&SocketFamily::Inet6));
        assert!(plan.deny_socket_families.contains(&SocketFamily::Packet));
        assert!(plan
            .deny_socket_families
            .contains(&SocketFamily::NetlinkNonRoute));
        // The whole family is denied at the domain level, so no type-conditioned rule is needed.
        assert!(!plan.deny_inet_dgram_raw);
    }

    #[test]
    fn port_tier_seccomp_denies_dgram_raw_but_not_stream() {
        // Under the port tier the blanket inet/inet6 deny is replaced by a DGRAM/RAW-only deny (so
        // STREAM survives for Landlock), while packet + non-route netlink stay blocked.
        let plan = seccomp_plan(InetSeccompDeny::DgramRawOnly);
        assert!(plan.deny_inet_dgram_raw, "UDP/raw must be denied");
        assert!(
            !plan.deny_socket_families.contains(&SocketFamily::Inet)
                && !plan.deny_socket_families.contains(&SocketFamily::Inet6),
            "the inet families must NOT be denied wholesale, or TCP STREAM dies too"
        );
        assert!(plan.deny_socket_families.contains(&SocketFamily::Packet));
        assert!(plan
            .deny_socket_families
            .contains(&SocketFamily::NetlinkNonRoute));
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
