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
    /// both reported `Unenforceable`, never silently assumed (FW-INV6). Enforcing it fails
    /// (`ConfineError::Unavailable`), so no workload runs unconfined (FW-XR3).
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
    /// Device-node name prefixes withheld from every read/write grant: the device half of the
    /// denied `camera`/`microphone` channels (FW-ISO13). Prefix-shaped because device nodes are
    /// numbered (`/dev/video0`); matched against directory entries during expansion only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withhold_device_prefixes: Vec<String>,
    /// Pathname UNIX sockets the supervisor admits besides those bound inside the session
    /// (FW-ISO12): literal write grants and the sockets of lifted channels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unix_socket_grants: Vec<PathPattern>,
    /// The isolation tier (FW-ISO10), applied before Landlock and seccomp.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub isolate: Vec<formwork_blueprint::IsolateMember>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum LinuxNetPlan {
    /// Full inet default-deny: block inet `socket(2)` creation via seccomp -- TCP, UDP, and raw. Used
    /// for any outright net-deny (Landlock net governs only TCP), not just a sub-ABI-v4 fallback.
    /// Inherited connected fds still work, so descriptors Formwork installs keep working (FW-XR7).
    SeccompDenyInet,
    /// The per-port TCP allow-list -- the port tier (ABI v4+). Landlock net governs *only* TCP, so
    /// this plan pairs it with a seccomp deny of inet DGRAM/RAW `socket(2)` (FW-ISO11, D4): Landlock
    /// governs which TCP ports connect, and direct UDP/raw egress fails closed. Nothing inside the
    /// sandbox resolves names under this plan; host rules restore resolution through the Gateway.
    LandlockTcpSeccompDgramRawDeny { ports: Vec<u16> },
    /// The host-allowlist posture (FW-EGR7): inet STREAM sockets may be created, but every
    /// `connect()` (and every addressed `sendto`) is delivered to the supervisor in the spawning
    /// process, which performs the allowed ones itself -- only the session's Gateway listener and
    /// admitted pathname sockets. UDP and raw stay seccomp-denied (FW-ISO11).
    SupervisedConnect,
}

impl LinuxNetPlan {
    /// The TCP ports the Landlock net ruleset allow-connects, when this plan carries a port tier.
    pub fn landlock_tcp_ports(&self) -> Option<&[u16]> {
        match self {
            LinuxNetPlan::LandlockTcpSeccompDgramRawDeny { ports } => Some(ports),
            _ => None,
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

/// The seccomp plan (FW-ISO8): the syscall refusals are deny-list shaped for transparency -- they
/// block confinement-shedding and escalation surfaces while letting normal toolchains through
/// (FW-TRA2) -- and socket creation is allow-list shaped (FW-ISO28).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SeccompPlan {
    /// Sorted, for deterministic output.
    pub deny_syscalls: Vec<String>,
    /// The only sockets `socket(2)` and `socketpair(2)` create (FW-ISO28). An allow-list, so a
    /// family a later kernel adds is refused with no change here.
    pub allow_socket_families: Vec<SocketFamily>,
    /// Refuse `sendto`/`sendmsg`/`sendmmsg` carrying `MSG_FASTOPEN` (FW-ISO29): that flag opens a
    /// TCP connection without `connect()`, the one call the port tier and the supervisor mediate.
    pub deny_send_fastopen: bool,
    /// Refuse `execveat` with `AT_EMPTY_PATH` (FW-ISO31): a descriptor has no path for the exec
    /// allow-list to judge. Set only under an exec allow-list.
    pub deny_exec_by_descriptor: bool,
    /// Deliver `connect()` and addressed `sendto()` to the supervisor via seccomp user
    /// notification (FW-EGR7). The confiner refuses to spawn without a supervisor when set.
    #[serde(default)]
    pub supervise_connect: bool,
    /// Deny new user namespaces (`CLONE_NEWUSER`, `setns`), which would hand back capabilities the
    /// baseline is removing. A flag because it is an argument-conditioned rule, not a whole deny.
    pub restrict_userns: bool,
    /// Required for an unprivileged filter.
    pub set_no_new_privs: bool,
}

/// One admitted kind of socket; the confiner encodes the exact predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SocketFamily {
    /// `AF_UNIX`, any type: local IPC is not egress (FW-XR7).
    Unix,
    /// `AF_NETLINK` with protocol `NETLINK_ROUTE`, which resolvers and `getifaddrs` read (FW-TRA2).
    NetlinkRoute,
    /// `AF_INET`, `SOCK_STREAM`, protocol `0` or `IPPROTO_TCP` (FW-ISO11, FW-ISO35).
    InetTcpStream,
    /// `AF_INET6`, `SOCK_STREAM`, protocol `0` or `IPPROTO_TCP` (FW-ISO11, FW-ISO35).
    Inet6TcpStream,
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
    /// The host table the Gateway's egress listener enforces (FW-EGR1); `None` when the net
    /// posture is not host-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<formwork_blueprint::HostTable>,
}
