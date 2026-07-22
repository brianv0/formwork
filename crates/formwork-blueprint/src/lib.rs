//! The capability blueprint: pure data describing what a confined process may touch. Narrowing
//! (`Blueprint::narrow`) can only shrink a grant, never widen it (FW-CAP2).

mod catalog;
mod discovery;
mod launcher;
mod layer;
mod narrow;
mod path;
mod provenance;

pub use catalog::{Catalog, CatalogEntry, ResolvedCatalog, ResolvedEntry, BACKSTOP};
pub use discovery::{
    reverse_compile, synthesize_blueprint, AccessRecord, Candidate, CandidateTag, DenialAccess,
    DenialRecord, ProposalOutcome, WithheldEntry,
};
pub use launcher::{construct_env, EnvConstruction};
pub use layer::{merge, BlueprintLayer, DiscoveryLayer, FsLayer, ProvenanceEntry};
pub use narrow::intersect_grants;
pub use path::{canonicalize_set, PathError, PathPattern};
pub use provenance::{merge_with_provenance, Explanation, Provenance, RuleSource, Verdict};

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `BTreeMap` keeps server order canonical for deterministic compiles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Blueprint {
    #[serde(default)]
    pub fs: FsBlueprint,
    #[serde(default)]
    pub net: NetPosture,
    #[serde(default)]
    pub exec: ExecPosture,
    #[serde(default)]
    pub env: EnvPosture,
    #[serde(default)]
    pub mcp: BTreeMap<String, McpPolicy>,
    /// Credential types deliberately let through the catalog floor (FW-CRED5). The catalog itself
    /// is compiled in; this is the only mechanism that lifts a typed entry -- path allows cannot.
    #[serde(default)]
    pub allow_credentials: Vec<String>,
    #[serde(default)]
    pub discovery: DiscoveryBlueprint,
}

impl Blueprint {
    /// The policy enforced *during* a permissive recording: everything is allowed, so the workload
    /// runs unconfined and its accesses can be observed -- except the credential floor, which the
    /// compiler still denies (`ResolvedCatalog::denied_paths`) for read *and* write. Open ambient
    /// reads plus an open `/**` write grant; the floor's deny wins by last-match over the broad
    /// write, so a recording can never read or write a credential (the recording-run half of the
    /// floor guarantee FW-INV8). The observed accesses are floored again at synthesis
    /// (`synthesize_blueprint`), so the floor holds whether or not enforcement is present.
    pub fn floor_only_permissive() -> Self {
        Blueprint {
            fs: FsBlueprint {
                read_mode: ReadMode::AmbientMinusSubtract,
                writes: vec![
                    PathPattern::parse("/**").expect("/** is a constant, valid open-write pattern")
                ],
                ..FsBlueprint::default()
            },
            ..Blueprint::empty()
        }
    }
}

/// The merged discovery posture (FW-DISC4): the operator-drawn zone inside which a learning run
/// may self-grant. Empty by default -- nothing self-grants out of the box.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct DiscoveryBlueprint {
    #[serde(default)]
    pub auto_widen: Vec<PathPattern>,
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
    /// Read + modify-existing, but not create (the create/write split, FW-CAP9): the `modify` verb.
    /// A weaker `writes` -- change files that exist, plant no new ones.
    #[serde(default)]
    pub writes_no_create: Vec<PathPattern>,
    /// Sensitive paths denied even under a broad grant (read *and* write).
    #[serde(default)]
    pub subtract: Vec<PathPattern>,
    /// Tamper vectors denied for *write* but left readable: git hooks/config, `.mcp.json`, IDE task
    /// files. Tooling still reads them (git reads `.git/config` constantly), but a confined agent
    /// cannot plant one that later runs unsandboxed (FW-TRA7).
    #[serde(default)]
    pub write_subtract: Vec<PathPattern>,
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

/// The reads posture, written in flat verb rules (FW-BP1): a friendlier alias of
/// [`ReadMode`]. `unveil` starts from an empty universe (only grants readable);
/// `subtractive` starts from ambient reads minus the catalog floor. A posture, not a rule -- the
/// loader maps it onto `fs.read_mode` before merge, so it carries no independent semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Unveil,
    Subtractive,
}

impl Mode {
    pub fn read_mode(self) -> ReadMode {
        match self {
            Mode::Unveil => ReadMode::Closed,
            Mode::Subtractive => ReadMode::AmbientMinusSubtract,
        }
    }
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

/// How the confined child's environment is built (FW-ENV1). The confined child otherwise inherits
/// the full parent environment, so `ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY`, etc. would pass
/// straight through -- with reads closed and egress host-scoped, env vars are the easiest remaining
/// exfiltration payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EnvPosture {
    /// Inherit the whole parent environment (today's behavior).
    #[default]
    Passthrough,
    /// Only these names survive; everything else is dropped.
    Allowlist(Vec<String>),
    /// Drop secret-shaped variables (FW-ENV2), with explicit `allow`/`deny` name overrides.
    Scrub(EnvScrub),
}

/// Overrides for [`EnvPosture::Scrub`]: `allow` names are always kept (e.g. the model API key the
/// agent legitimately needs), `deny` names are always dropped, and anything else is dropped only if
/// it looks like a secret by name or value shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EnvScrub {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl EnvPosture {
    /// Pure: given the ambient environment, return the pairs to keep. The caller (the impure CLI
    /// shell) collects `std::env::vars()` and applies the result to the child `Command`.
    pub fn apply(&self, vars: Vec<(String, String)>) -> Vec<(String, String)> {
        match self {
            EnvPosture::Passthrough => vars,
            EnvPosture::Allowlist(names) => vars
                .into_iter()
                .filter(|(k, _)| names.iter().any(|n| n == k))
                .collect(),
            EnvPosture::Scrub(s) => vars.into_iter().filter(|(k, v)| s.keeps(k, v)).collect(),
        }
    }

    /// Names dropped from `vars`, for telemetry. Never the values (secrets never hit logs).
    pub fn dropped_names(&self, vars: &[(String, String)]) -> Vec<String> {
        match self {
            EnvPosture::Passthrough => Vec::new(),
            EnvPosture::Allowlist(names) => vars
                .iter()
                .filter(|(k, _)| !names.iter().any(|n| n == k))
                .map(|(k, _)| k.clone())
                .collect(),
            EnvPosture::Scrub(s) => vars
                .iter()
                .filter(|(k, v)| !s.keeps(k, v))
                .map(|(k, _)| k.clone())
                .collect(),
        }
    }

    fn canonicalize(&self) -> EnvPosture {
        match self {
            EnvPosture::Passthrough => EnvPosture::Passthrough,
            EnvPosture::Allowlist(names) => {
                let mut n = names.clone();
                n.sort();
                n.dedup();
                EnvPosture::Allowlist(n)
            }
            EnvPosture::Scrub(s) => EnvPosture::Scrub(s.canonicalize()),
        }
    }
}

impl EnvScrub {
    fn keeps(&self, name: &str, value: &str) -> bool {
        if self.allow.iter().any(|n| n == name) {
            true
        } else if self.deny.iter().any(|n| n == name) {
            false
        } else {
            !env_is_secret_shaped(name, value)
        }
    }

    fn canonicalize(&self) -> EnvScrub {
        let dedup = |v: &[String]| {
            let mut x = v.to_vec();
            x.sort();
            x.dedup();
            x
        };
        EnvScrub {
            allow: dedup(&self.allow),
            deny: dedup(&self.deny),
        }
    }
}

/// A variable is secret-shaped if its NAME contains a secret marker or its VALUE matches a
/// high-confidence secret shape (FW-ENV2). Coarse by design -- the `allow` list handles false
/// positives; the fail-closed default is to drop.
fn env_is_secret_shaped(name: &str, value: &str) -> bool {
    const NAME_MARKERS: &[&str] = &[
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "APIKEY",
        "API_KEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "AUTH",
        "CREDENTIAL",
    ];
    let upper = name.to_ascii_uppercase();
    if NAME_MARKERS.iter().any(|m| upper.contains(m)) {
        return true;
    }
    env_value_is_secret(value)
}

fn env_value_is_secret(v: &str) -> bool {
    v.starts_with("-----BEGIN ")            // PEM private key / cert block
        || v.starts_with("ghp_")            // GitHub personal access token
        || v.starts_with("gho_")
        || v.starts_with("github_pat_")
        || v.starts_with("xoxb-")           // Slack bot token
        || v.starts_with("xoxp-")
        || v.starts_with("sk-")             // common API secret-key prefix
        || (v.starts_with("AKIA") && v.len() == 20)   // AWS access key id
        || (v.starts_with("AIza") && v.len() > 30)    // Google API key
        || is_jwt(v)
}

/// Three base64url segments; the header almost always begins `eyJ` (base64 of `{"`).
fn is_jwt(v: &str) -> bool {
    v.starts_with("eyJ") && v.bytes().filter(|&b| b == b'.').count() == 2
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
    /// The fail-closed floor: nothing readable/writable, net denied, exec unrestricted, env
    /// passthrough, no MCP.
    pub fn empty() -> Self {
        Blueprint {
            fs: FsBlueprint::default(),
            net: NetPosture::Deny,
            exec: ExecPosture::Unrestricted,
            env: EnvPosture::Passthrough,
            mcp: BTreeMap::new(),
            allow_credentials: Vec::new(),
            discovery: DiscoveryBlueprint::default(),
        }
    }

    /// Equal capabilities canonicalize identically, which is what makes compilation
    /// byte-deterministic (FW-FID4).
    pub fn canonicalize(&self) -> Blueprint {
        let mut mcp = BTreeMap::new();
        for (k, v) in &self.mcp {
            mcp.insert(k.clone(), v.canonicalize());
        }
        let mut allow_credentials = self.allow_credentials.clone();
        allow_credentials.sort();
        allow_credentials.dedup();
        Blueprint {
            fs: FsBlueprint {
                read_mode: self.fs.read_mode,
                reads: canonicalize_set(&self.fs.reads),
                writes: canonicalize_set(&self.fs.writes),
                writes_no_create: canonicalize_set(&self.fs.writes_no_create),
                subtract: canonicalize_set(&self.fs.subtract),
                write_subtract: canonicalize_set(&self.fs.write_subtract),
            },
            net: self.net.canonicalize(),
            exec: self.exec.canonicalize(),
            env: self.env.canonicalize(),
            mcp,
            allow_credentials,
            discovery: DiscoveryBlueprint {
                auto_widen: canonicalize_set(&self.discovery.auto_widen),
            },
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
    fn env_scrub_drops_secret_shaped_keeps_allowlisted() {
        let scrub = EnvPosture::Scrub(EnvScrub {
            allow: vec!["ANTHROPIC_API_KEY".into()],
            deny: vec!["EDITOR".into()],
        });
        let vars = vec![
            ("PATH".into(), "/usr/bin".into()),            // ordinary -> kept
            ("ANTHROPIC_API_KEY".into(), "sk-abc".into()), // allowlisted -> kept despite secret shape
            ("AWS_SECRET_ACCESS_KEY".into(), "x".into()),  // name marker -> dropped
            ("GITHUB_TOKEN".into(), "ghp_x".into()),       // name marker -> dropped
            ("DEPLOY".into(), "ghp_realtoken".into()),     // secret VALUE shape -> dropped
            ("EDITOR".into(), "vim".into()),               // explicit deny -> dropped
        ];
        let kept: Vec<String> = scrub
            .apply(vars.clone())
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(kept, vec!["PATH", "ANTHROPIC_API_KEY"]);
        let dropped = scrub.dropped_names(&vars);
        assert!(dropped.contains(&"AWS_SECRET_ACCESS_KEY".to_string()));
        assert!(dropped.contains(&"DEPLOY".to_string()));
        assert!(dropped.contains(&"EDITOR".to_string()));
    }

    #[test]
    fn env_allowlist_keeps_only_named() {
        let env = EnvPosture::Allowlist(vec!["PATH".into(), "HOME".into()]);
        let vars = vec![
            ("PATH".into(), "/usr/bin".into()),
            ("HOME".into(), "/home/x".into()),
            ("SECRET".into(), "y".into()),
        ];
        let kept: Vec<String> = env.apply(vars).into_iter().map(|(k, _)| k).collect();
        assert_eq!(kept, vec!["PATH", "HOME"]);
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
