//! Linux confiner-policy construction: the seccomp baseline (FW-ISO8) and the net plan.
//!
//! The seccomp baseline is deny-list shaped, not allow-list shaped: an allow-list breaks the moment
//! a toolchain reaches for a forgotten syscall, which is the transparency failure FW-TRA2 forbids.
//! So it blocks a small fixed set of shedding/escalation surfaces and lets everything else through;
//! Landlock, not seccomp, carries the filesystem boundary.

use formwork_detect::HostProfile;
use formwork_spec::NetPosture;

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
    "kexec_file_load",
    "kexec_load",
    "keyctl",
    "mount",
    "mount_setattr",
    "move_mount",
    "open_by_handle_at",
    "perf_event_open",
    "pivot_root",
    "ptrace",
    "request_key",
    "setns",
];

/// `net_via_seccomp` is true when the host lacks Landlock net ABI and net default-deny must instead
/// be carried by denying inet `socket(2)` creation.
pub fn seccomp_plan(net_via_seccomp: bool) -> SeccompPlan {
    let deny_syscalls: Vec<String> = BASELINE_DENY.iter().map(|s| s.to_string()).collect();
    debug_assert!(
        deny_syscalls.windows(2).all(|w| w[0] < w[1]),
        "BASELINE_DENY must stay sorted"
    );

    // Block inet/inet6/packet + non-route netlink; AF_UNIX and socketpair stay allowed so the
    // injected fd seam is untouched (FW-XR7).
    let deny_socket_families = if net_via_seccomp {
        vec![
            SocketFamily::Inet,
            SocketFamily::Inet6,
            SocketFamily::Packet,
            SocketFamily::NetlinkNonRoute,
        ]
    } else {
        Vec::new()
    };

    SeccompPlan {
        deny_syscalls,
        deny_socket_families,
        restrict_userns: true,
        set_no_new_privs: true,
    }
}

/// Returns `(plan, net_via_seccomp, port_tier)`.
pub fn net_plan(host: &HostProfile, net: &NetPosture) -> (LinuxNetPlan, bool, PortTier) {
    let abi = host.landlock_abi.unwrap_or(0);
    match net {
        NetPosture::Deny => {
            if abi >= LANDLOCK_NET_ABI {
                (
                    LinuxNetPlan::LandlockTcp { ports: vec![] },
                    false,
                    PortTier::NotRequested,
                )
            } else {
                (LinuxNetPlan::SeccompDenyInet, true, PortTier::NotRequested)
            }
        }
        NetPosture::Ports(ports) => {
            if abi >= LANDLOCK_NET_ABI {
                (
                    LinuxNetPlan::LandlockTcp {
                        ports: ports.clone(),
                    },
                    false,
                    PortTier::Enforced,
                )
            } else {
                // Cannot honor the port tier; fall back to full seccomp deny (fail-closed) and
                // report the tier unenforceable -- no silent open (FW-INV6).
                (
                    LinuxNetPlan::SeccompDenyInet,
                    true,
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
        let plan = seccomp_plan(false);
        assert!(plan.deny_syscalls.windows(2).all(|w| w[0] < w[1]));
        assert!(plan.deny_syscalls.iter().any(|s| s == "bpf"));
        assert!(plan.deny_syscalls.iter().any(|s| s == "setns"));
        assert!(plan.restrict_userns);
        assert!(plan.set_no_new_privs);
        assert!(plan.deny_socket_families.is_empty());
    }

    #[test]
    fn net_deny_uses_seccomp_below_abi4_landlock_above() {
        let old = HostProfile::synthetic_linux(Some(1));
        let (plan, via_seccomp, tier) = net_plan(&old, &NetPosture::Deny);
        assert!(matches!(plan, LinuxNetPlan::SeccompDenyInet));
        assert!(via_seccomp);
        assert_eq!(tier, PortTier::NotRequested);

        let new = HostProfile::synthetic_linux(Some(4));
        let (plan, via_seccomp, _) = net_plan(&new, &NetPosture::Deny);
        assert!(matches!(plan, LinuxNetPlan::LandlockTcp { ports } if ports.is_empty()));
        assert!(!via_seccomp);
    }

    #[test]
    fn port_tier_unenforceable_below_abi4_falls_back_to_deny() {
        let old = HostProfile::synthetic_linux(Some(1));
        let (plan, via_seccomp, tier) = net_plan(&old, &NetPosture::Ports(vec![8080]));
        assert!(matches!(plan, LinuxNetPlan::SeccompDenyInet));
        assert!(via_seccomp);
        assert_eq!(tier, PortTier::UnenforceableBelowAbi4);

        let new = HostProfile::synthetic_linux(Some(4));
        let (plan, _, tier) = net_plan(&new, &NetPosture::Ports(vec![8080]));
        assert!(matches!(plan, LinuxNetPlan::LandlockTcp { ports } if ports == vec![8080]));
        assert_eq!(tier, PortTier::Enforced);
    }
}
