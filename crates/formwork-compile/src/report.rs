//! The `FidelityReport` -- Formwork's honesty ledger (FW-XR1, FW-INV5). For every capability it
//! evaluates it records `Enforced`, `Partial`, or `Unenforceable`; `enforce()` may only confirm
//! or degrade-loudly it, never upgrade a claim (FW-INV6).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Sorted by `Ord` for deterministic serialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
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
    /// applied by the Gateway -- reported here so the honesty ledger is complete. Appended last to
    /// keep the `Ord`-derived serialization order of the earlier variants stable.
    EnvScrub,
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

/// The full per-capability report plus the host it was compiled against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FidelityReport {
    pub host: formwork_detect::HostProfile,
    pub per_capability: BTreeMap<Capability, Fidelity>,
    pub semantics: BTreeMap<Capability, DenialSemantics>,
    pub credentials: CredentialReport,
}

/// Per-credential-type honesty (FW-CRED8): which arm carries each location kind of every catalog
/// type still enforced, plus the visible list of deliberate exclusions (FW-CRED5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CredentialReport {
    pub catalog_version: u32,
    /// Types deliberately let through (FW-CRED5), itemized so the lift is auditable.
    pub allowed: Vec<String>,
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
    pub fn as_key(&self) -> &'static str {
        match self {
            Capability::FsRead => "fs-read",
            Capability::FsWrite => "fs-write",
            Capability::NetDefaultDeny => "net-default-deny",
            Capability::NetPortTier => "net-port-tier",
            Capability::Exec => "exec",
            Capability::McpShading => "mcp-shading",
            Capability::CrossDomainSocket => "cross-domain-socket",
            Capability::FsInvisibility => "fs-invisibility",
            Capability::EnvScrub => "env-scrub",
        }
    }
}

impl FidelityReport {
    /// The probe suite (FW-E2E-024) must confirm each.
    pub fn enforced_capabilities(&self) -> impl Iterator<Item = (Capability, Backend)> + '_ {
        self.per_capability.iter().filter_map(|(k, v)| match v {
            Fidelity::Enforced { backend } => Some((*k, *backend)),
            _ => None,
        })
    }

    /// True if net is never left silently open: enforced or partial, never bare-`Unenforceable`.
    /// The compiler upholds this by construction; the check lets `enforce()` assert it (FW-INV6).
    pub fn net_is_fail_closed(&self) -> bool {
        match self.per_capability.get(&Capability::NetDefaultDeny) {
            Some(f) => f.is_enforced() || matches!(f, Fidelity::Partial { .. }),
            None => false,
        }
    }
}
