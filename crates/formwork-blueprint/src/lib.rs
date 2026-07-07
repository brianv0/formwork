//! The capability blueprint: pure data describing what a confined process may touch. Narrowing
//! (`Blueprint::narrow`) can only shrink a grant, never widen it (FW-CAP2).

mod narrow;
mod path;

pub use path::{canonicalize_set, PathError, PathPattern};

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `BTreeMap` keeps server order canonical for deterministic compiles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blueprint {
    #[serde(default)]
    pub fs: FsBlueprint,
    #[serde(default)]
    pub net: NetPosture,
    #[serde(default)]
    pub exec: ExecPosture,
    #[serde(default)]
    pub mcp: BTreeMap<String, McpPolicy>,
}

/// `write` grants imply `read`; `subtract` holes win over grants (FW-TRA3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct FsBlueprint {
    #[serde(default)]
    pub read_mode: ReadMode,
    #[serde(default)]
    pub reads: Vec<PathPattern>,
    #[serde(default)]
    pub writes: Vec<PathPattern>,
    /// Sensitive paths denied even under a broad grant.
    #[serde(default)]
    pub subtract: Vec<PathPattern>,
}

/// `Closed` denies by default (only grants readable); `AmbientMinusSubtract` allows broad ambient
/// reads minus the `subtract` set (FW-CAP3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ReadMode {
    #[default]
    Closed,
    AmbientMinusSubtract,
}

/// `Deny` is the fail-closed default (FW-XR3); `Ports` allows direct TCP connect to a port set
/// only where the platform can enforce it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NetPosture {
    #[default]
    Deny,
    Ports(Vec<u16>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ExecPosture {
    #[default]
    Unrestricted,
    Allowlist(Vec<PathPattern>),
}

/// Per-MCP-server visibility policy the gateway enforces (FW-GW2/GW3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpPolicy {
    #[serde(default)]
    pub tools: Visibility,
    #[serde(default)]
    pub resources: Visibility,
    #[serde(default)]
    pub prompts: Visibility,
    #[serde(default)]
    pub sampling: Gate,
    #[serde(default)]
    pub elicitation: Gate,
}

impl Default for McpPolicy {
    /// Default-deny the whole surface: an unlisted server grants nothing.
    fn default() -> Self {
        McpPolicy {
            tools: Visibility::Deny,
            resources: Visibility::Deny,
            prompts: Visibility::Deny,
            sampling: Gate::Deny,
            elicitation: Gate::Deny,
        }
    }
}

/// `Allow` grants exactly the listed names; everything else is absent from listings and
/// non-invocable (FW-CAP4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Visibility {
    AllowAll,
    Allow(Vec<String>),
    #[default]
    Deny,
}

impl Visibility {
    pub fn permits(&self, name: &str) -> bool {
        match self {
            Visibility::AllowAll => true,
            Visibility::Allow(names) => names.iter().any(|n| n == name),
            Visibility::Deny => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Gate {
    Allow,
    #[default]
    Deny,
}

impl Blueprint {
    /// The fail-closed floor: nothing readable/writable, net denied, exec unrestricted, no MCP.
    pub fn empty() -> Self {
        Blueprint {
            fs: FsBlueprint::default(),
            net: NetPosture::Deny,
            exec: ExecPosture::Unrestricted,
            mcp: BTreeMap::new(),
        }
    }

    /// Equal capabilities canonicalize identically, which is what makes compilation
    /// byte-deterministic (FW-FID4).
    pub fn canonicalize(&self) -> Blueprint {
        let mut mcp = BTreeMap::new();
        for (k, v) in &self.mcp {
            mcp.insert(k.clone(), v.canonicalize());
        }
        Blueprint {
            fs: FsBlueprint {
                read_mode: self.fs.read_mode,
                reads: canonicalize_set(&self.fs.reads),
                writes: canonicalize_set(&self.fs.writes),
                subtract: canonicalize_set(&self.fs.subtract),
            },
            net: self.net.canonicalize(),
            exec: self.exec.canonicalize(),
            mcp,
        }
    }
}

impl McpPolicy {
    fn canonicalize(&self) -> McpPolicy {
        McpPolicy {
            tools: self.tools.canonicalize(),
            resources: self.resources.canonicalize(),
            prompts: self.prompts.canonicalize(),
            sampling: self.sampling,
            elicitation: self.elicitation,
        }
    }
}

impl Visibility {
    fn canonicalize(&self) -> Visibility {
        match self {
            Visibility::Allow(names) => {
                let mut n = names.clone();
                n.sort();
                n.dedup();
                Visibility::Allow(n)
            }
            other => other.clone(),
        }
    }
}

impl NetPosture {
    fn canonicalize(&self) -> NetPosture {
        match self {
            NetPosture::Ports(ports) => {
                let mut p = ports.clone();
                p.sort_unstable();
                p.dedup();
                if p.is_empty() {
                    NetPosture::Deny
                } else {
                    NetPosture::Ports(p)
                }
            }
            NetPosture::Deny => NetPosture::Deny,
        }
    }
}

impl ExecPosture {
    fn canonicalize(&self) -> ExecPosture {
        match self {
            ExecPosture::Allowlist(paths) => ExecPosture::Allowlist(canonicalize_set(paths)),
            ExecPosture::Unrestricted => ExecPosture::Unrestricted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mcp_policy_denies_everything() {
        let d = McpPolicy::default();
        assert!(!d.tools.permits("anything"));
        assert!(!d.resources.permits("anything"));
        assert_eq!(d.sampling, Gate::Deny);
    }

    #[test]
    fn canonicalize_sorts_and_dedupes_allow_lists() {
        let mut mcp = BTreeMap::new();
        mcp.insert(
            "srv".to_string(),
            McpPolicy {
                tools: Visibility::Allow(vec!["b".into(), "a".into(), "b".into()]),
                ..Default::default()
            },
        );
        let s = Blueprint {
            mcp,
            ..Blueprint::empty()
        }
        .canonicalize();
        assert_eq!(
            s.mcp["srv"].tools,
            Visibility::Allow(vec!["a".into(), "b".into()])
        );
    }

    #[test]
    fn empty_ports_canonicalizes_to_deny() {
        let s = Blueprint {
            net: NetPosture::Ports(vec![]),
            ..Blueprint::empty()
        }
        .canonicalize();
        assert_eq!(s.net, NetPosture::Deny);
    }

    #[test]
    fn toml_roundtrip() {
        let src = r#"
            [fs]
            read-mode = "closed"
            reads = ["/work/project/**"]
            writes = ["/work/project/**"]
            subtract = ["/work/project/.git/**"]

            [net]
            ports = [8080]

            [mcp.files]
            tools = { allow = ["read_file"] }
            resources = "allow-all"
            sampling = "deny"
        "#;
        let blueprint: Blueprint = toml::from_str(src).unwrap();
        assert_eq!(
            blueprint.fs.reads,
            vec![PathPattern::parse("/work/project/**").unwrap()]
        );
        assert_eq!(blueprint.net, NetPosture::Ports(vec![8080]));
        assert_eq!(
            blueprint.mcp["files"].tools,
            Visibility::Allow(vec!["read_file".into()])
        );
        assert_eq!(blueprint.mcp["files"].resources, Visibility::AllowAll);
    }
}
