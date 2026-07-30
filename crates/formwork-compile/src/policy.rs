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
    // Boxed: `LinuxPolicy` is far larger than the other variants, and `Box` keeps the enum small
    // without changing the serialized shape (serde treats `Box<T>` as `T`).
    Linux(Box<LinuxPolicy>),
    Macos(MacosPolicy),
    /// No usable confiner on this host (no Landlock, no seccomp): fs scope and net default-deny are
    /// both reported `Unenforceable`, never silently assumed (FW-INV6). Egress containment then rests
    /// on the seam alone -- the agent reaches the network only through the injected gateway fd
    /// (FW-XR7) -- which this policy does not itself enforce.
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
    /// Read + modify-existing, no create (FW-CAP9): the write bits minus create, rendered per backend.
    pub writes_no_create: Vec<PathPattern>,
    pub subtract: Vec<PathPattern>,
    /// Write-denied but readable tamper vectors (FW-TRA7).
    pub write_subtract: Vec<PathPattern>,
    pub exec: ExecPlan,
    pub net: LinuxNetPlan,
    pub seccomp: SeccompPlan,
    /// Always true: `NO_NEW_PRIVS` is the anti-shedding floor (FW-ISO8).
    pub no_new_privs: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum LinuxNetPlan {
    /// Full inet default-deny: block inet `socket(2)` creation via seccomp -- TCP, UDP, and raw. Used
    /// for any outright net-deny (Landlock net governs only TCP), not just a sub-ABI-v4 fallback.
    /// Inherited connected fds still work -- that is the seam (FW-XR7).
    SeccompDenyInet,
    /// The per-port TCP allow-list -- the port tier (ABI v4+). Landlock net governs *only* TCP, so a
    /// bare Landlock port tier would leave inet UDP/raw `socket(2)` wide open -- an arbitrary-egress
    /// hole (DNS tunneling). This plan therefore pairs the Landlock per-port TCP allow with a seccomp
    /// filter that denies inet DGRAM/RAW `socket(2)` while allowing STREAM, so Landlock still governs
    /// which TCP ports connect and direct UDP/raw egress fails closed (FW-ISO3/FW-INV3). Direct DNS is
    /// unavailable under the port tier; resolution goes through the gateway (FW-E2E-007).
    LandlockTcpSeccompDgramRawDeny { ports: Vec<u16> },
}

impl LinuxNetPlan {
    /// The TCP ports the Landlock net ruleset should allow-connect, when this plan carries a port
    /// tier. `None` for the pure seccomp inet deny (no Landlock net rules).
    pub fn landlock_tcp_ports(&self) -> Option<&[u16]> {
        match self {
            LinuxNetPlan::LandlockTcpSeccompDgramRawDeny { ports } => Some(ports),
            LinuxNetPlan::SeccompDenyInet => None,
        }
    }
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
    /// Socket domains (arg0 of `socket(2)`) denied outright. Carries the full inet deny
    /// (Inet/Inet6/Packet/non-route Netlink); under the port tier it carries only Packet + non-route
    /// Netlink, and the inet DGRAM/RAW deny rides `deny_inet_dgram_raw` instead.
    pub deny_socket_families: Vec<SocketFamily>,
    /// The port tier: deny inet/inet6 DGRAM and RAW `socket(2)` (type masked to `SOCK_TYPE_MASK`, so
    /// `SOCK_NONBLOCK`/`SOCK_CLOEXEC` cannot evade it) while allowing STREAM, so the Landlock per-port
    /// TCP rules govern TCP and direct UDP/raw egress fails closed (FW-ISO3/FW-INV3). False when the
    /// inet deny is carried at the family level (`deny_socket_families`) or net is Landlock-open.
    pub deny_inet_dgram_raw: bool,
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
