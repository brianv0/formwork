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
            // Deny ALL inet egress via seccomp (blocks TCP, UDP, and raw at the socket-family level),
            // matching macOS `(deny network*)`. Landlock net governs *only* TCP, so carrying deny with
            // it would leave UDP/raw open -- an exfil channel. AF_UNIX (the injected-fd seam) stays
            // allowed. Landlock net is reserved for the port tier, where per-port TCP allow is needed.
            (LinuxNetPlan::SeccompDenyInet, true, PortTier::NotRequested)
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
        assert!(plan.deny_socket_families.is_empty());
    }

    #[test]
    fn net_deny_always_uses_seccomp_inet_deny() {
        // Deny is carried by seccomp at every ABI so UDP/raw are covered, not just TCP.
        for abi in [1, 4, 6] {
            let host = HostProfile::synthetic_linux(Some(abi));
            let (plan, via_seccomp, tier) = net_plan(&host, &NetPosture::Deny);
            assert!(
                matches!(plan, LinuxNetPlan::SeccompDenyInet),
                "abi {abi}: net-deny must be the complete seccomp inet deny"
            );
            assert!(via_seccomp);
            assert_eq!(tier, PortTier::NotRequested);
        }
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
