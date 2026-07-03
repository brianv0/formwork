//! The `FidelityReport` -- Formwork's honesty ledger (FW-XR1, FW-INV5). For every capability the
//! spec asks for it records `Enforced`, `Partial`, or `Unenforceable`; `enforce()` may only confirm
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    Landlock,
    Seccomp,
    Seatbelt,
    Gateway,
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
    Enforced { backend: Backend },
    Partial { backend: Backend, reason: String },
    /// This host cannot carry it; the reason is surfaced, never swallowed (FW-INV6).
    Unenforceable { reason: String },
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
