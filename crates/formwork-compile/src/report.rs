//! The `FidelityReport` -- Formwork's honesty ledger (FW-XR1, FW-INV5). For every capability it
//! evaluates it records `Enforced`, `Partial`, or `Unenforceable`; `enforce()` may only confirm
//! or degrade-loudly it, never upgrade a claim (FW-INV6).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use formwork_blueprint::Channel;

/// Sorted by `Ord` for deterministic serialization. Serialized by its stable JSON key
/// ([`Capability::as_key`]), the machine-door contract (FW-FID8); variants are appended, never
/// reordered, so the key order of earlier rows stays stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    FsRead,
    FsWrite,
    NetDefaultDeny,
    NetPortTier,
    Exec,
    McpShading,
    CrossDomainSocket,
    /// Whether ungranted paths vanish (ENOENT) or merely deny (EACCES). Formwork never provides
    /// filesystem invisibility; this row documents that as an explicit fact.
    FsInvisibility,
    /// The environment posture (FW-ENV1/2). Applied at spawn by the CLI shell, like MCP shading is
    /// applied by the Gateway -- reported here so the honesty ledger is complete.
    EnvScrub,
    /// The write-denied-but-readable tamper-vector set (FW-TRA7): `Partial` where a backend
    /// withholds rows it cannot install (Landlock cannot root `**/` rows, D1).
    TamperVectors,
    /// Host-scoped egress through the Gateway (FW-EGR1).
    NetHostScope,
    /// Request-level inspection of an inspected host (FW-EGR10).
    NetInspection,
    /// Direct UDP and raw sockets closed (FW-ISO11).
    NetUdp,
    /// Pathname UNIX sockets mediated (FW-ISO12) or path-gated.
    NetUnixSocket,
    /// Local name resolution (FW-EGR12). Reported under every posture so the resolver is never
    /// an unlisted channel (D8).
    NetResolver,
    /// The Gateway presents a credential the agent never holds (FW-CRED11/CRED15).
    CredentialBroker,
    IsolateProcesses,
    IsolateIpc,
    /// The per-session temporary directory (FW-TRA10).
    PrivateTmp,
    /// One row per host-service channel in the baseline (FW-ISO13).
    Channel(Channel),
    /// Privileged kernel interfaces (FW-ISO14).
    PrivilegedInterfaces,
    /// Other processes' environments unreadable (FW-ISO16).
    ProcessEnvironment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    Landlock,
    Seccomp,
    Seatbelt,
    Gateway,
    /// The launcher -- the third enforcement arm (FEP-2 §6): the spawn-time construction of the
    /// confined child, environment rebuild and credential strip included (FW-ENV1, FW-CRED2).
    /// Not a kernel confiner; its guarantee is contingent on Formwork being the launching
    /// process, which the report must disclose (FW-CRED8). Renamed from `Process` by FEP-2
    /// (pre-release; no version bump -- canary consumers only).
    Launcher,
    /// The `connect()` supervisor (FW-EGR7): seccomp user notification serviced outside the
    /// sandbox by the spawning `formwork` process.
    Supervisor,
    /// Linux namespaces (FW-ISO10).
    Namespaces,
    None,
}

/// How a denial manifests to the confined process (FW-CAP4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DenialSemantics {
    /// The item is absent, not present-and-flagged (MCP shading).
    Hide,
    /// The operation fails with a natural errno (EACCES/EPERM) -- the filesystem case.
    Deny,
    NotApplicable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Fidelity {
    /// Backed by a real mechanism; a paired allow/deny probe must confirm it (FW-E2E-024).
    Enforced {
        backend: Backend,
    },
    Partial {
        backend: Backend,
        reason: String,
    },
    /// This host cannot carry it; the reason is surfaced, never swallowed (FW-INV6).
    Unenforceable {
        reason: String,
    },
}

impl Fidelity {
    pub fn is_enforced(&self) -> bool {
        matches!(self, Fidelity::Enforced { .. })
    }
}

/// Whether the host facility behind a channel exists on this host (FW-FID10), from `detect`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HostPresence {
    pub present: bool,
    /// The socket, device or session that makes the channel reachable, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

/// One channel's lift state and host reachability, beside its `channel-<name>` verdict row
/// (FW-FID8). A lifted channel carries no verdict row: nothing is enforced for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ChannelReport {
    pub lifted: bool,
    pub host: HostPresence,
}

/// The full per-capability report plus the host it was compiled against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FidelityReport {
    pub host: formwork_detect::HostProfile,
    pub per_capability: BTreeMap<Capability, Fidelity>,
    pub semantics: BTreeMap<Capability, DenialSemantics>,
    pub credentials: CredentialReport,
    /// Rules the backend could not install (FW-FID8), as `<kind> <pattern>`. Never silent: each
    /// entry also degrades the capability it belongs to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withheld: Vec<String>,
    /// Per-channel lift and host presence (FW-ISO13/FW-FID10), keyed by channel name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub channels: BTreeMap<String, ChannelReport>,
}

/// Per-credential-type honesty (FW-CRED8): which arm carries each location kind of every catalog
/// type still enforced, plus the visible list of deliberate exclusions (FW-CRED5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CredentialReport {
    pub catalog_version: u32,
    /// Types deliberately let through (FW-CRED5), itemized so the lift is auditable.
    pub allowed: Vec<String>,
    /// Types the Gateway brokers (FW-CRED11): the floor holds and the agent sees a placeholder.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub brokered: Vec<String>,
    pub per_type: BTreeMap<String, CredentialFidelity>,
    /// The generic backstop's path fidelity (FW-CRED6); `None` when lifted by name.
    pub backstop: Option<Fidelity>,
    /// FW-CRED8: stated plainly with every report -- the env arm's guarantee exists only while
    /// Formwork is the launching process. Never implied to hold independent of the launcher.
    pub launcher_contingency: String,
}

/// One catalog type's two arms (FW-CRED2). An absent kind is absent -- nothing is claimed for a
/// location kind the type does not have or an arm that is not applied (FW-INV5).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CredentialFidelity {
    /// Path locations -> the OS sandbox (EACCES).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Fidelity>,
    /// Env-var locations -> the launcher strip (variable absent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Fidelity>,
}

impl Capability {
    /// How a denial of this capability looks to the confined process: the launcher's env scrub
    /// and the Gateway's MCP shading hide what they deny; everything else refuses it.
    pub fn semantics(self) -> DenialSemantics {
        match self {
            Capability::EnvScrub | Capability::McpShading => DenialSemantics::Hide,
            _ => DenialSemantics::Deny,
        }
    }

    /// Every non-channel capability, for key lookup.
    const FIXED: [Capability; 21] = [
        Capability::FsRead,
        Capability::FsWrite,
        Capability::NetDefaultDeny,
        Capability::NetPortTier,
        Capability::Exec,
        Capability::McpShading,
        Capability::CrossDomainSocket,
        Capability::FsInvisibility,
        Capability::EnvScrub,
        Capability::TamperVectors,
        Capability::NetHostScope,
        Capability::NetInspection,
        Capability::NetUdp,
        Capability::NetUnixSocket,
        Capability::NetResolver,
        Capability::CredentialBroker,
        Capability::IsolateProcesses,
        Capability::IsolateIpc,
        Capability::PrivateTmp,
        Capability::PrivilegedInterfaces,
        Capability::ProcessEnvironment,
    ];

    pub fn as_key(&self) -> String {
        let fixed = match self {
            Capability::FsRead => "fs-read",
            Capability::FsWrite => "fs-write",
            Capability::NetDefaultDeny => "net-default-deny",
            Capability::NetPortTier => "net-port-tier",
            Capability::Exec => "exec",
            Capability::McpShading => "mcp-shading",
            Capability::CrossDomainSocket => "cross-domain-socket",
            Capability::FsInvisibility => "fs-invisibility",
            Capability::EnvScrub => "env-scrub",
            Capability::TamperVectors => "tamper-vectors",
            Capability::NetHostScope => "net-host-scope",
            Capability::NetInspection => "net-inspection",
            Capability::NetUdp => "net-udp",
            Capability::NetUnixSocket => "net-unix-socket",
            Capability::NetResolver => "net-resolver",
            Capability::CredentialBroker => "credential-broker",
            Capability::IsolateProcesses => "isolate-processes",
            Capability::IsolateIpc => "isolate-ipc",
            Capability::PrivateTmp => "private-tmp",
            Capability::PrivilegedInterfaces => "privileged-interfaces",
            Capability::ProcessEnvironment => "process-environment",
            Capability::Channel(c) => return format!("channel-{}", c.name()),
        };
        fixed.to_string()
    }

    /// The inverse of [`Capability::as_key`].
    pub fn from_key(key: &str) -> Option<Capability> {
        if let Some(name) = key.strip_prefix("channel-") {
            return Channel::from_name(name).map(Capability::Channel);
        }
        Capability::FIXED.into_iter().find(|c| c.as_key() == key)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_key())
    }
}

impl Serialize for Capability {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_key())
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let key = String::deserialize(deserializer)?;
        Capability::from_key(&key)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown capability key {key:?}")))
    }
}

impl FidelityReport {
    /// True if net is never left silently open: enforced or partial, never bare-`Unenforceable`.
    /// The compiler upholds this by construction; the check lets `enforce()` assert it (FW-INV6).
    pub fn net_is_fail_closed(&self) -> bool {
        match self.per_capability.get(&Capability::NetDefaultDeny) {
            Some(f) => f.is_enforced() || matches!(f, Fidelity::Partial { .. }),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_keys_round_trip_and_channels_are_keyed_by_name() {
        for c in Capability::FIXED
            .into_iter()
            .chain(Channel::ALL.into_iter().map(Capability::Channel))
        {
            assert_eq!(Capability::from_key(&c.as_key()), Some(c));
            let json = serde_json::to_string(&c).unwrap();
            let back: Capability = serde_json::from_str(&json).unwrap();
            assert_eq!(back, c);
        }
        assert_eq!(
            Capability::Channel(Channel::OpenUrl).as_key(),
            "channel-open-url"
        );
        assert_eq!(Capability::from_key("channel-bogus"), None);
    }
}
