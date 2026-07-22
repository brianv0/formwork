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
    reverse_compile, Candidate, CandidateTag, DenialAccess, DenialRecord, ProposalOutcome,
    WithheldEntry,
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
            tools: Visibility::default(),
            resources: Visibility::default(),
            prompts: Visibility::default(),
            sampling: Gate::Deny,
            elicitation: Gate::Deny,
        }
    }
}

/// Per-axis MCP visibility: an **allow scope** minus **terminal deny patterns**. `permits(name)`
/// holds iff the allow scope admits `name` *and* no deny pattern matches it -- a deny always wins
/// over any allow, the MCP-surface form of the deny-terminal fs model (FW-CAP8) applied to tool,
/// resource, and prompt identities (FW-GW9). An unlisted allow admits nothing (FW-CAP4).
///
/// Entries are exact identifiers or anchored regex written `/…/`, matched against the *whole* name
/// (FW-GW9). Authoring is identical on every axis (TOML):
/// - `"allow-all"` / `"deny"` — the whole surface, one keyword.
/// - `{ allow = ["read_file", "/^get_/"] }` — an allowlist of names and/or patterns.
/// - `{ allow = [...], deny = ["/^delete_/"] }` — an allowlist with a terminal deny carve-out.
/// - `{ deny = ["/^delete_/"] }` — everything *except* the deny patterns. Omitting `allow` means
///   "all"; an explicit empty `allow = []` means "none"; an empty table `{}` is a loud error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "VisibilityRepr", into = "VisibilityRepr")]
pub struct Visibility {
    allow: AllowScope,
    deny: Vec<Pattern>,
}

/// What the allow layer admits, before the terminal deny is applied.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
enum AllowScope {
    All,
    #[default]
    Nothing,
    Only(Vec<Pattern>),
}

/// One allow/deny entry: an exact MCP identifier, or an anchored regex *source* (without its `/…/`
/// slashes) that must match the entire name.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Pattern {
    Exact(String),
    Regex(String),
}

/// A blueprint carried an unusable MCP pattern (a `/…/` that will not compile) or an empty policy
/// table. Fail-loud at parse time (FW-INV6): neither ever reaches the gateway as a silent deny-all
/// or a silent allow-all.
#[derive(Debug, thiserror::Error)]
pub enum VisibilityError {
    #[error("invalid MCP pattern `/{pattern}/`: {reason}")]
    BadPattern { pattern: String, reason: String },
    #[error(
        "empty MCP policy table: write \"allow-all\", \"deny\", or a non-empty allow/deny list"
    )]
    EmptyTable,
}

impl Pattern {
    /// Parse one authoring entry. A value wrapped in single slashes (`/re/`, at least `//`) is a
    /// regex; anything else is an exact identifier -- including a name that itself contains slashes.
    fn parse(raw: &str) -> Result<Pattern, VisibilityError> {
        if raw.len() >= 2 && raw.starts_with('/') && raw.ends_with('/') {
            let inner = &raw[1..raw.len() - 1];
            // Validate now so an unusable pattern is a loud config error, never a silent deny-all.
            Pattern::compile(inner).map_err(|e| VisibilityError::BadPattern {
                pattern: inner.to_string(),
                reason: e.to_string(),
            })?;
            Ok(Pattern::Regex(inner.to_string()))
        } else {
            Ok(Pattern::Exact(raw.to_string()))
        }
    }

    /// Compile a regex source anchored to the whole name (`\A(?:…)\z`), so `/get_.*/` matches
    /// `get_issue` but not `forget_me` -- allow patterns stay tight and deny patterns don't
    /// over-reach onto unrelated names.
    fn compile(inner: &str) -> Result<regex::Regex, regex::Error> {
        regex::Regex::new(&format!(r"\A(?:{inner})\z"))
    }

    fn matches(&self, name: &str) -> bool {
        match self {
            Pattern::Exact(s) => s == name,
            // Validated at parse; on the impossible recompile failure, fail closed (no match).
            Pattern::Regex(inner) => Pattern::compile(inner)
                .map(|re| re.is_match(name))
                .unwrap_or(false),
        }
    }

    /// The authoring form, for canonical (re)serialization.
    fn source(&self) -> String {
        match self {
            Pattern::Exact(s) => s.clone(),
            Pattern::Regex(inner) => format!("/{inner}/"),
        }
    }
}

fn parse_patterns(raw: &[String]) -> Result<Vec<Pattern>, VisibilityError> {
    raw.iter().map(|s| Pattern::parse(s)).collect()
}

impl Default for Visibility {
    /// Fail-closed: an axis with no explicit policy admits nothing.
    fn default() -> Self {
        Visibility {
            allow: AllowScope::Nothing,
            deny: Vec::new(),
        }
    }
}

impl Visibility {
    pub fn all() -> Self {
        Visibility {
            allow: AllowScope::All,
            deny: Vec::new(),
        }
    }

    /// Literal identifiers only, no `/…/` parsing -- the shape every pre-pattern blueprint compiles to.
    pub fn allow_exact<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Visibility {
            allow: AllowScope::Only(
                names
                    .into_iter()
                    .map(|s| Pattern::Exact(s.into()))
                    .collect(),
            ),
            deny: Vec::new(),
        }
    }

    /// Parse an allow list and a deny list of authoring entries (exact names or `/re/`). Every
    /// `/…/` is validated (FW-GW9); an invalid one is a loud error, never a silent deny.
    pub fn parse(allow: &[String], deny: &[String]) -> Result<Self, VisibilityError> {
        Ok(Visibility {
            allow: AllowScope::Only(parse_patterns(allow)?),
            deny: parse_patterns(deny)?,
        })
    }

    pub fn with_deny(mut self, deny: &[String]) -> Result<Self, VisibilityError> {
        self.deny = parse_patterns(deny)?;
        Ok(self)
    }

    /// `true` iff `name` is admitted: no deny pattern matches it, and the allow scope covers it.
    /// Deny is terminal (FW-GW9/FW-CAP8).
    pub fn permits(&self, name: &str) -> bool {
        if self.deny.iter().any(|p| p.matches(name)) {
            return false;
        }
        match &self.allow {
            AllowScope::All => true,
            AllowScope::Nothing => false,
            AllowScope::Only(patterns) => patterns.iter().any(|p| p.matches(name)),
        }
    }
}

/// Serde surface for [`Visibility`]: a keyword string or a `{ allow?, deny? }` table. Kept separate
/// so the in-memory form stays a validated `Visibility` while TOML/JSON round-trips through strings.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum VisibilityRepr {
    Keyword(VisibilityKeyword),
    Table(VisibilityTable),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum VisibilityKeyword {
    AllowAll,
    Deny,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VisibilityTable {
    // `deny_unknown_fields` so a misspelled key errors rather than parsing as a deny-only
    // (allow-all) table -- a typo must never silently widen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deny: Vec<String>,
}

impl TryFrom<VisibilityRepr> for Visibility {
    type Error = VisibilityError;
    fn try_from(repr: VisibilityRepr) -> Result<Self, Self::Error> {
        match repr {
            VisibilityRepr::Keyword(VisibilityKeyword::AllowAll) => Ok(Visibility::all()),
            VisibilityRepr::Keyword(VisibilityKeyword::Deny) => Ok(Visibility::default()),
            VisibilityRepr::Table(VisibilityTable { allow: None, deny }) if deny.is_empty() => {
                Err(VisibilityError::EmptyTable)
            }
            VisibilityRepr::Table(VisibilityTable { allow, deny }) => {
                let deny = parse_patterns(&deny)?;
                let allow = match allow {
                    None => AllowScope::All,
                    Some(list) => AllowScope::Only(parse_patterns(&list)?),
                };
                Ok(Visibility { allow, deny })
            }
        }
    }
}

impl From<Visibility> for VisibilityRepr {
    fn from(v: Visibility) -> Self {
        let deny: Vec<String> = v.deny.iter().map(Pattern::source).collect();
        match v.allow {
            // Nothing is allowed: any deny is moot, so collapse to the bare keyword.
            AllowScope::Nothing => VisibilityRepr::Keyword(VisibilityKeyword::Deny),
            AllowScope::All if deny.is_empty() => {
                VisibilityRepr::Keyword(VisibilityKeyword::AllowAll)
            }
            AllowScope::All => VisibilityRepr::Table(VisibilityTable { allow: None, deny }),
            AllowScope::Only(patterns) => VisibilityRepr::Table(VisibilityTable {
                allow: Some(patterns.iter().map(Pattern::source).collect()),
                deny,
            }),
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
        let allow = match &self.allow {
            AllowScope::Only(patterns) => {
                let sorted = sort_dedup(patterns);
                // An empty allowlist admits nothing -- same capability as `Nothing`, so it
                // canonicalizes there (FW-FID4: equal grants canonicalize identically).
                if sorted.is_empty() {
                    AllowScope::Nothing
                } else {
                    AllowScope::Only(sorted)
                }
            }
            other => other.clone(),
        };
        // Nothing is allowed => deny is moot; drop it so equal capabilities canonicalize identically.
        let deny = if matches!(allow, AllowScope::Nothing) {
            Vec::new()
        } else {
            sort_dedup(&self.deny)
        };
        Visibility { allow, deny }
    }
}

/// Sort by authoring form and drop duplicates, so equal pattern sets canonicalize byte-identically
/// (FW-FID4).
fn sort_dedup(patterns: &[Pattern]) -> Vec<Pattern> {
    let mut v = patterns.to_vec();
    v.sort_by_key(|p| p.source());
    v.dedup();
    v
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

    // ---- FW-GW9: regex allow/deny patterns for the MCP surface -------------------------------

    /// Parse a `[mcp.s] tools = …` fragment into just the tools visibility.
    fn tools_vis(fragment: &str) -> Visibility {
        let src = format!("[mcp.s]\ntools = {fragment}\n");
        let bp: Blueprint = toml::from_str(&src).unwrap();
        bp.mcp["s"].tools.clone()
    }

    #[test]
    fn regex_allow_matches_whole_name_only() {
        let v = tools_vis(r#"{ allow = ["/get_.*/"] }"#);
        assert!(v.permits("get_issue"));
        assert!(v.permits("get_"));
        assert!(!v.permits("forget_me"));
        assert!(!v.permits("get")); // no trailing text to satisfy `_.*`
    }

    #[test]
    fn exact_and_regex_entries_coexist() {
        let v = tools_vis(r#"{ allow = ["echo", "/list_.*/"] }"#);
        assert!(v.permits("echo"));
        assert!(v.permits("list_dir"));
        assert!(!v.permits("echoes")); // exact, not a prefix
        assert!(!v.permits("http_fetch"));
    }

    #[test]
    fn deny_is_terminal_over_allow() {
        let v = tools_vis(r#"{ allow = ["/.*/"], deny = ["/delete_.*/", "http_fetch"] }"#);
        assert!(v.permits("read_file"));
        assert!(!v.permits("delete_repo"), "deny pattern beats allow-all");
        assert!(!v.permits("http_fetch"), "exact deny beats allow-all");
    }

    #[test]
    fn deny_only_table_means_all_except() {
        let v = tools_vis(r#"{ deny = ["/admin_.*/"] }"#);
        assert!(v.permits("echo"));
        assert!(!v.permits("admin_reset"));
    }

    #[test]
    fn empty_allowlist_admits_nothing_but_is_not_all() {
        // Explicit empty allow = "none" (distinct from an absent allow, which is "all").
        let v = tools_vis(r#"{ allow = [] }"#);
        assert!(!v.permits("echo"));
        // An empty allowlist is the same capability as `deny`; canonicalize collapses it there.
        assert_eq!(v.canonicalize(), Visibility::default());
    }

    #[test]
    fn keyword_forms_round_trip() {
        assert_eq!(tools_vis(r#""allow-all""#), Visibility::all());
        assert_eq!(tools_vis(r#""deny""#), Visibility::default());
    }

    #[test]
    fn empty_table_is_a_loud_error() {
        // `{}` is ambiguous between allow-all and deny-none; refuse it rather than pick silently.
        let err = toml::from_str::<Blueprint>("[mcp.s]\ntools = {}\n").unwrap_err();
        assert!(err.to_string().contains("empty MCP policy table"), "{err}");
    }

    #[test]
    fn invalid_regex_fails_loud_at_parse() {
        let err = toml::from_str::<Blueprint>("[mcp.s]\ntools = { allow = [\"/get_(/\"] }\n")
            .unwrap_err();
        assert!(err.to_string().contains("invalid MCP pattern"), "{err}");
    }

    #[test]
    fn unknown_table_key_is_rejected_not_silently_widened() {
        // A typo like `alow` must not deserialize to a deny-only (allow-all) table.
        let parsed = toml::from_str::<Blueprint>("[mcp.s]\ntools = { alow = [\"x\"] }\n");
        assert!(
            parsed.is_err(),
            "a misspelled key must not parse: {parsed:?}"
        );
    }

    #[test]
    fn visibility_json_round_trips_through_serde() {
        // The compiled policy embeds Visibility as JSON (compile --json), so it must round-trip.
        for fragment in [
            r#""allow-all""#,
            r#""deny""#,
            r#"{ allow = ["a", "/b.*/"] }"#,
            r#"{ allow = ["/x/"], deny = ["/y.*/", "z"] }"#,
            r#"{ deny = ["/admin_.*/"] }"#,
        ] {
            let v = tools_vis(fragment);
            let json = serde_json::to_string(&v).unwrap();
            let back: Visibility = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back, "round trip changed {fragment}");
        }
    }

    #[test]
    fn canonicalize_is_deterministic_for_patterns() {
        let a = tools_vis(r#"{ allow = ["/b.*/", "a", "a"], deny = ["z", "z"] }"#);
        let b = tools_vis(r#"{ allow = ["a", "/b.*/"], deny = ["z"] }"#);
        let canon = |v: &Visibility| serde_json::to_string(&v.canonicalize()).unwrap();
        assert_eq!(canon(&a), canon(&b));
    }

    #[test]
    fn canonicalize_sorts_and_dedupes_allow_lists() {
        let mut mcp = BTreeMap::new();
        mcp.insert(
            "srv".to_string(),
            McpPolicy {
                tools: Visibility::allow_exact(["b", "a", "b"]),
                ..Default::default()
            },
        );
        let s = Blueprint {
            mcp,
            ..Blueprint::empty()
        }
        .canonicalize();
        assert_eq!(s.mcp["srv"].tools, Visibility::allow_exact(["a", "b"]));
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
            Visibility::allow_exact(["read_file"])
        );
        assert_eq!(blueprint.mcp["files"].resources, Visibility::all());
    }
}
