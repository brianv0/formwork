//! The compiler's output: symbolic policy objects the confiners and gateway later execute. The
//! Linux policy carries path *patterns* and a seccomp *plan*, not expanded Landlock rules --
//! expansion happens at enforce time, which keeps `compile()` pure and byte-deterministic (FW-FID4).

use serde::{Deserialize, Serialize};

use formwork_blueprint::{McpPolicy, PathPattern, ReadMode};

use crate::report::FidelityReport;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledPolicy {
    pub confiner: ConfinerPolicy,
    pub gateway: GatewayPolicy,
    pub report: FidelityReport,
}

/// Chosen by the *host's* OS, so a synthetic Linux profile on a Mac yields `Linux(..)` -- the basis
/// of cross-platform dry-run (FW-E2E-026).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "kebab-case")]
pub enum ConfinerPolicy {
    Linux(LinuxPolicy),
    Macos(MacosPolicy),
    /// No usable confiner here. Net still fails closed (the gateway is the only egress), but the
    /// caller is told plainly that OS-level fs confinement is unavailable.
    Unavailable {
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LinuxPolicy {
    pub landlock_abi_target: Option<u32>,
    pub read_mode: ReadMode,
    /// Write grants already folded in.
    pub reads: Vec<PathPattern>,
    pub writes: Vec<PathPattern>,
    pub subtract: Vec<PathPattern>,
    pub exec: ExecPlan,
    pub net: LinuxNetPlan,
    pub seccomp: SeccompPlan,
    /// Always true: `NO_NEW_PRIVS` is the anti-shedding floor (FW-ISO8).
    pub no_new_privs: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum LinuxNetPlan {
    /// Below Landlock net ABI (v4): deny inet `socket(2)` creation via seccomp. Inherited connected
    /// fds still work -- that is the seam (FW-XR7).
    SeccompDenyInet,
    /// `ports` may be empty (pure deny) or an allow-list.
    LandlockTcp { ports: Vec<u16> },
}

/// Off unless the blueprint asks (FW-ISO4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ExecPlan {
    Unrestricted,
    Allowlist { paths: Vec<PathPattern> },
}

/// The seccomp baseline plan (FW-ISO8): deny-list shaped for transparency -- it blocks
/// confinement-shedding and escalation surfaces while letting normal toolchains through (FW-TRA2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SeccompPlan {
    /// Sorted, for deterministic output.
    pub deny_syscalls: Vec<String>,
    /// Empty when net-deny is via Landlock.
    pub deny_socket_families: Vec<SocketFamily>,
    /// Deny new user namespaces (`CLONE_NEWUSER`, `setns`), which would hand back capabilities the
    /// baseline is removing. A flag because it is an argument-conditioned rule, not a whole deny.
    pub restrict_userns: bool,
    /// Required for an unprivileged filter.
    pub set_no_new_privs: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SocketFamily {
    Inet,
    Inet6,
    Packet,
    /// Netlink except the route family toolchains need; the confiner encodes the exact predicate.
    NetlinkNonRoute,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosPolicy {
    pub sbpl: String,
}

/// What the gateway enforces: per-server MCP shading (FW-GW2/GW3) plus an informational mirror of
/// the direct-TCP port tier, so a caller can see the full egress surface (FW-GW7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GatewayPolicy {
    pub servers: std::collections::BTreeMap<String, McpPolicy>,
    pub direct_tcp_ports: Vec<u16>,
}
