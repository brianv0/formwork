//! The credential-location catalog (FW-CRED1): typed, versioned data embedded at build time so
//! the pure compiler needs no I/O. Raw entries carry `~`-relative paths; [`Catalog::resolve`]
//! expands them against a caller-supplied home into [`ResolvedCatalog`], the form the compiler
//! takes. Resolution is pure in `(catalog, home)`, keeping compilation deterministic (FW-FID4).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{PathError, PathPattern};

/// The Catalog type for the OS keyring, which Linux reaches over the session bus (Secret
/// Service): exposing it admits the bus address and socket.
pub const OS_KEYRING: &str = "os-keyring";

/// The name under which the generic backstop (FW-CRED6) can be lifted via `allow-credentials`.
/// Deliberately coarse: it lifts every backstop row at once, so narrowing a real type is always
/// preferable; it exists so a backstop false positive has a visible, explicit escape hatch.
pub const BACKSTOP: &str = "backstop";

const BUILTIN: &str = include_str!("../../../profiles/credential-catalog.toml");

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Catalog {
    pub version: u32,
    pub types: BTreeMap<String, CatalogEntry>,
    pub backstop: BackstopEntry,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct CatalogEntry {
    /// `~`-relative or absolute path patterns (FW-CAP6 grammar) -> confiner deny (FW-CRED2).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Environment variable names -> launcher strip (FW-CRED2).
    #[serde(default)]
    pub envs: Vec<String>,
    /// Env vars whose *value* names a file: excluding the type strips the var and denies the
    /// referenced file (FW-CRED3). Must be a subset of `envs`.
    #[serde(default)]
    pub env_file_refs: Vec<EnvFileRef>,
    /// Env vars whose *value* is a directory a tool uses in place of one of this type's
    /// `~`-relative roots (FW-CRED32). Not stripped: the variable is where the tool looks, and
    /// the floor follows it there.
    #[serde(default)]
    pub env_dir_refs: Vec<EnvDirRef>,
    /// Service locations (FW-CRED13): `mach:<name>` on macOS, `bus:<name>` or
    /// `runtime:<socket under $XDG_RUNTIME_DIR>` on Linux. Denied like paths, by the channel
    /// mechanism of each backend.
    #[serde(default)]
    pub services: Vec<String>,
    /// How the Gateway presents this type when it is brokered (FW-CRED11): one scheme per set of
    /// hosts, since one credential can need different schemes on different hosts.
    #[serde(default)]
    pub broker: Vec<BrokerBlock>,
}

/// One `env-file-refs` entry: the bare variable name for a variable whose value is one file
/// (FW-CRED3), or `{ var = "<name>", list = true }` for one whose value is a `:`-separated list of
/// files (FW-CRED33). The list form is opt-in per variable because `:` is an ordinary byte in a
/// single path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvFileRef {
    pub var: String,
    pub list: bool,
}

impl<'de> Deserialize<'de> for EnvFileRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Table {
            var: String,
            #[serde(default)]
            list: bool,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Name(String),
            Table(Table),
        }
        Ok(match Repr::deserialize(deserializer)? {
            Repr::Name(var) => EnvFileRef { var, list: false },
            Repr::Table(t) => EnvFileRef {
                var: t.var,
                list: t.list,
            },
        })
    }
}

impl Serialize for EnvFileRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !self.list {
            return serializer.serialize_str(&self.var);
        }
        let mut table = serializer.serialize_struct("EnvFileRef", 2)?;
        table.serialize_field("var", &self.var)?;
        table.serialize_field("list", &self.list)?;
        table.end()
    }
}

/// One `env-dir-refs` entry (FW-CRED32): `replaces` is the `~`-relative root the variable's value
/// stands in for, so each of the type's patterns below that root is denied below the value too.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvDirRef {
    pub var: String,
    pub replaces: String,
}

/// One `env-dir-refs` variable in the compiler-facing form: the type's patterns below the
/// replaced root, each as the remainder after that root (`/**`, `/credentials.toml`). Taken from
/// the Catalog's own rows, so rebasing one variable never feeds another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StoreRelocation {
    pub var: String,
    pub below: Vec<String>,
}

/// One reference variable that was set in the launching environment (FW-CRED35): its name and the
/// number of deny rows it added. The value locates a credential store and is never carried.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedReference {
    pub var: String,
    pub rows: usize,
}

/// One `{ hosts, scheme }` pair of a Catalog `broker` block (FEP-5 §3.2).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct BrokerBlock {
    pub hosts: Vec<String>,
    pub scheme: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct BackstopEntry {
    pub paths: Vec<String>,
}

impl Catalog {
    /// The catalog shipped in this binary. Parsed once; the data is validated by unit tests, and
    /// a parse failure here is a corrupt build, not an input error.
    pub fn builtin() -> &'static Catalog {
        static PARSED: OnceLock<Catalog> = OnceLock::new();
        PARSED.get_or_init(|| {
            toml::from_str(BUILTIN).expect("embedded credential-catalog.toml must parse")
        })
    }

    pub fn type_names(&self) -> impl Iterator<Item = &str> {
        self.types.keys().map(String::as_str)
    }

    pub fn is_known_type(&self, name: &str) -> bool {
        name == BACKSTOP || self.types.contains_key(name)
    }

    /// Expand `~` against `home` and parse every pattern. Fails loud on an unparsable pattern
    /// (a hole that silently failed to match would be a fail-open of the floor, FW-INV6).
    pub fn resolve(&self, home: &str) -> Result<ResolvedCatalog, PathError> {
        let expand = |s: &str| -> Result<PathPattern, PathError> {
            let expanded = if s == "~" {
                home.to_string()
            } else if let Some(rest) = s.strip_prefix("~/") {
                format!("{}/{}", home.trim_end_matches('/'), rest)
            } else {
                s.to_string()
            };
            PathPattern::parse(&expanded)
        };
        let mut types = BTreeMap::new();
        for (name, entry) in &self.types {
            types.insert(
                name.clone(),
                ResolvedEntry {
                    paths: entry
                        .paths
                        .iter()
                        .map(|p| expand(p))
                        .collect::<Result<_, _>>()?,
                    envs: entry.envs.clone(),
                    env_file_refs: entry.env_file_refs.clone(),
                    env_dir_refs: entry
                        .env_dir_refs
                        .iter()
                        .map(|reference| StoreRelocation {
                            var: reference.var.clone(),
                            below: entry
                                .paths
                                .iter()
                                .filter_map(|p| p.strip_prefix(reference.replaces.as_str()))
                                .filter(|rest| rest.starts_with('/'))
                                .map(str::to_string)
                                .collect(),
                        })
                        .collect(),
                    references: Vec::new(),
                    services: entry.services.clone(),
                    broker: entry.broker.clone(),
                },
            );
        }
        Ok(ResolvedCatalog {
            version: self.version,
            types,
            backstop: self
                .backstop
                .paths
                .iter()
                .map(|p| expand(p))
                .collect::<Result<_, _>>()?,
        })
    }
}

/// The compiler-facing form: patterns parsed, `~` gone. Constructed at the CLI edge (the only
/// place that knows `$HOME`) and passed into `compile` -- the floor is an explicit input, not
/// ambient state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ResolvedCatalog {
    pub version: u32,
    pub types: BTreeMap<String, ResolvedEntry>,
    pub backstop: Vec<PathPattern>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ResolvedEntry {
    pub paths: Vec<PathPattern>,
    pub envs: Vec<String>,
    pub env_file_refs: Vec<EnvFileRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env_dir_refs: Vec<StoreRelocation>,
    /// What the launching environment's reference variables added for this type (FW-CRED35),
    /// recorded by whoever resolved them -- the CLI edge, since the compiler reads no environment.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<ResolvedReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub broker: Vec<BrokerBlock>,
}

impl ResolvedEntry {
    /// FW-CRED32: deny this type's store where `var` relocates it -- each pattern below the
    /// replaced root, rebased onto `root`. The `~` rows stay, so a tool that ignores the variable
    /// still finds nothing, and the rebased rows are the type's own: `allow-credentials` lifts
    /// them with it (FW-CRED5). Records the variable and the rows it added (FW-CRED35); a row the
    /// type already holds is not added twice.
    pub fn relocate(&mut self, var: &str, root: &PathPattern) -> Result<(), PathError> {
        let root = root.canonical();
        let root = root.trim_end_matches('/');
        let below: Vec<String> = self
            .env_dir_refs
            .iter()
            .filter(|relocation| relocation.var == var)
            .flat_map(|relocation| relocation.below.iter().cloned())
            .collect();
        let mut rows = 0;
        for rest in below {
            let rebased = PathPattern::parse(&format!("{root}{rest}"))?;
            if !self.paths.contains(&rebased) {
                self.paths.push(rebased);
                rows += 1;
            }
        }
        self.references.push(ResolvedReference {
            var: var.to_string(),
            rows,
        });
        Ok(())
    }
}

impl ResolvedCatalog {
    /// The builtin catalog resolved for one home -- the standard constructor everywhere.
    pub fn builtin_for_home(home: &str) -> Result<ResolvedCatalog, PathError> {
        Catalog::builtin().resolve(home)
    }

    /// A catalog with no entries, i.e. NO credential floor. Exists so unit tests can isolate
    /// non-catalog behavior; production callers use [`ResolvedCatalog::builtin_for_home`].
    pub fn empty_no_floor() -> ResolvedCatalog {
        ResolvedCatalog {
            version: 0,
            types: BTreeMap::new(),
            backstop: Vec::new(),
        }
    }

    /// Confiner-deny patterns for every type NOT excluded (FW-CRED4/5), plus the backstop unless
    /// `allow` names [`BACKSTOP`]. The only un-deny that exists is this typed exclusion.
    pub fn denied_paths(&self, allow: &[String]) -> Vec<PathPattern> {
        let mut out = Vec::new();
        for (name, entry) in &self.types {
            if !allow.iter().any(|a| a == name) {
                out.extend(entry.paths.iter().cloned());
            }
        }
        if !allow.iter().any(|a| a == BACKSTOP) {
            out.extend(self.backstop.iter().cloned());
        }
        out
    }

    /// Types (name -> entry) still enforced after exclusions -- what the report itemizes.
    pub fn enforced_types<'a>(
        &'a self,
        allow: &'a [String],
    ) -> impl Iterator<Item = (&'a str, &'a ResolvedEntry)> + 'a {
        self.types
            .iter()
            .filter(move |(name, _)| !allow.iter().any(|a| a == name.as_str()))
            .map(|(name, entry)| (name.as_str(), entry))
    }

    /// Which type floors this candidate (or [`BACKSTOP`]), for the operator-channel "why"
    /// (FW-CRED7). A candidate subtree that would swallow a type's directory is floored too; a
    /// subtree that merely *could* contain future backstop matches is not -- the backstop keeps
    /// denying those at enforcement no matter what is granted (deny beats allow, FW-BP4).
    ///
    /// The backstop is location-independent (`**/<name>`, matched by shape), so a credential shape
    /// is withheld wherever a denial was observed -- not only under `~`. That matters because
    /// discovery collection is tolerant of over-capture (a denial from another process, possibly
    /// outside this run's `$HOME`, can land in the log window), so the confused-deputy wall
    /// (FW-INV8) must classify by shape everywhere. Enforcement denies the same shapes everywhere
    /// too (`denied_paths`), keeping the two floors symmetric (FW-CRED6).
    pub fn floor_type_of(&self, allow: &[String], candidate: &PathPattern) -> Option<String> {
        fn hit(floor: &PathPattern, candidate: &PathPattern) -> bool {
            floor == candidate
                || floor.covers(candidate)
                || candidate.covers(floor)
                || (!candidate.is_any_depth() && floor.matches_path(candidate.base()))
        }
        for (name, entry) in self.enforced_types(allow) {
            if entry.paths.iter().any(|p| hit(p, candidate)) {
                return Some(name.to_string());
            }
        }
        // Mirror enforcement's typed exemption (FW-CRED5): inside an excluded type's own scope
        // the backstop is lifted, so it does not floor there either.
        let in_excluded_scope = self
            .types
            .iter()
            .filter(|(name, _)| allow.iter().any(|a| a == name.as_str()))
            .flat_map(|(_, entry)| entry.paths.iter())
            .any(|p| hit(p, candidate));
        if !in_excluded_scope
            && !allow.iter().any(|a| a == BACKSTOP)
            && self.backstop.iter().any(|p| hit(p, candidate))
        {
            return Some(BACKSTOP.to_string());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_catalog_parses_and_resolves() {
        let catalog = Catalog::builtin();
        assert_eq!(catalog.version, 4);
        // The FEP-named curated types are present.
        for t in [
            "aws",
            "gcp",
            "ssh",
            "anthropic",
            "slack",
            "github",
            "docker",
            "npm",
            "kube",
        ] {
            assert!(catalog.types.contains_key(t), "missing curated type {t}");
        }
        let resolved = catalog.resolve("/home/x").unwrap();
        assert!(resolved.types["aws"]
            .paths
            .contains(&PathPattern::parse("/home/x/.aws/**").unwrap()));
        // The .env family is one typed decision (dotenv); the backstop's shape rules match at any
        // depth anywhere (a location-independent catch-all), not just under the home tree.
        assert!(resolved.types["dotenv"]
            .paths
            .contains(&PathPattern::parse("**/.env.production").unwrap()));
        assert!(resolved
            .backstop
            .contains(&PathPattern::parse("**/credentials").unwrap()));
        assert!(resolved.types["secrets-mount"]
            .paths
            .contains(&PathPattern::parse("/run/secrets/**").unwrap()));
    }

    #[test]
    fn env_file_refs_are_a_subset_of_envs() {
        for (name, entry) in &Catalog::builtin().types {
            for reference in &entry.env_file_refs {
                let var = &reference.var;
                assert!(
                    entry.envs.contains(var),
                    "{name}: env-file-ref {var} must also be listed in envs"
                );
            }
        }
    }

    #[test]
    fn fw_cred33_env_file_refs_take_a_name_or_a_list_marked_table() {
        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct Refs {
            env_file_refs: Vec<EnvFileRef>,
        }
        let parse = |src: &str| toml::from_str::<Refs>(src).map(|r| r.env_file_refs);
        let refs = parse(
            r#"env-file-refs = ["ONE_FILE", { var = "FILE_LIST", list = true }, { var = "PLAIN" }]"#,
        )
        .unwrap();
        let shape: Vec<(&str, bool)> = refs.iter().map(|r| (r.var.as_str(), r.list)).collect();
        assert_eq!(
            shape,
            [("ONE_FILE", false), ("FILE_LIST", true), ("PLAIN", false)]
        );
        assert!(parse(r#"env-file-refs = [{ var = "X", lst = true }]"#).is_err());
        assert!(parse(r#"env-file-refs = [{ list = true }]"#).is_err());
        // The written form round-trips: a plain reference stays the bare name.
        assert_eq!(
            serde_json::to_string(&refs).unwrap(),
            r#"["ONE_FILE",{"var":"FILE_LIST","list":true},"PLAIN"]"#
        );

        // The shipped catalog marks the one list-valued reference it carries.
        let lists: Vec<&str> = Catalog::builtin()
            .types
            .values()
            .flat_map(|entry| entry.env_file_refs.iter())
            .filter(|r| r.list)
            .map(|r| r.var.as_str())
            .collect();
        assert_eq!(lists, ["KUBECONFIG"]);
    }

    /// Each shipped `env-dir-refs` entry replaces a root the type has rows below, so a set
    /// variable always has something to rebase; and no variable is both a directory and a file.
    #[test]
    fn fw_cred32_every_env_dir_ref_replaces_a_root_of_its_type() {
        assert!(toml::from_str::<EnvDirRef>(r#"var = "X""#).is_err());
        assert!(
            toml::from_str::<EnvDirRef>("var = \"X\"\nreplaces = \"~/.x\"\nlist = true").is_err()
        );
        let resolved = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        let mut seen = 0;
        for (name, entry) in &Catalog::builtin().types {
            let mut vars: Vec<&str> = entry.env_dir_refs.iter().map(|r| r.var.as_str()).collect();
            vars.sort_unstable();
            vars.dedup();
            assert_eq!(
                vars.len(),
                entry.env_dir_refs.len(),
                "{name}: a variable is listed twice"
            );
            for reference in &entry.env_dir_refs {
                seen += 1;
                let (var, root) = (&reference.var, &reference.replaces);
                assert!(
                    root.starts_with("~/") && !root.ends_with('/') && !root.contains("**"),
                    "{name}: {var} replaces {root:?}, which is not a plain `~` directory"
                );
                assert!(
                    !entry.env_file_refs.iter().any(|f| &f.var == var),
                    "{name}: {var} is both an env-file-ref and an env-dir-ref"
                );
                let relocation = resolved.types[name]
                    .env_dir_refs
                    .iter()
                    .find(|r| &r.var == var)
                    .unwrap();
                assert!(
                    !relocation.below.is_empty(),
                    "{name}: no path of the type lies below {root}, so {var} would rebase nothing"
                );
            }
        }
        assert!(seen > 0, "the shipped catalog carries env-dir-refs");
    }

    #[test]
    fn fw_cred32_a_relocated_store_is_denied_beside_the_home_rows() {
        let mut resolved = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        let home_rows = resolved.denied_paths(&[]);
        let at = |p: &str| PathPattern::parse(p).unwrap();

        // A whole-directory type moves whole; a type of two files moves those two files only.
        let entry = |c: &mut ResolvedCatalog, name: &str, var: &str, root: &str| {
            c.types
                .get_mut(name)
                .unwrap()
                .relocate(var, &at(root))
                .unwrap();
        };
        entry(&mut resolved, "gpg", "GNUPGHOME", "/secure/gnupg");
        entry(&mut resolved, "cargo", "CARGO_HOME", "/opt/cargo");
        // Two variables of one type each rebase the Catalog's own rows, never each other's.
        entry(
            &mut resolved,
            "github",
            "GH_CONFIG_DIR",
            "/home/x/.config/gh-work",
        );
        entry(&mut resolved, "github", "XDG_CONFIG_HOME", "/xdg");
        // The directory moves; the file beside it in `~` is not below the replaced root.
        entry(&mut resolved, "claude", "CLAUDE_CONFIG_DIR", "/claude");

        let denied = resolved.denied_paths(&[]);
        for row in &home_rows {
            assert!(denied.contains(row), "{row} left the floor");
        }
        let added: Vec<String> = denied
            .iter()
            .filter(|row| !home_rows.contains(row))
            .map(PathPattern::canonical)
            .collect();
        assert_eq!(
            added,
            [
                "/opt/cargo/credentials.toml",
                "/opt/cargo/credentials",
                "/claude/**",
                "/home/x/.config/gh-work/**",
                "/xdg/gh/**",
                "/secure/gnupg/**",
            ]
        );
        let floor = |c: &ResolvedCatalog, allow: &[String], p: &str| c.floor_type_of(allow, &at(p));
        assert_eq!(
            floor(&resolved, &[], "/secure/gnupg/private-keys-v1.d/k.key").as_deref(),
            Some("gpg")
        );
        assert_eq!(floor(&resolved, &[], "/opt/cargo/registry/index"), None);

        // The typed exclude lifts the rebased rows with the type, and nothing adjacent (FW-CRED5).
        let lifted = resolved.denied_paths(&["gpg".to_string()]);
        assert!(!lifted.contains(&at("/secure/gnupg/**")));
        assert!(lifted.contains(&at("/xdg/gh/**")));
        assert_eq!(
            floor(&resolved, &["gpg".to_string()], "/secure/gnupg/pubring.kbx"),
            None
        );
    }

    #[test]
    fn fw_cred35_a_relocation_records_its_variable_and_the_rows_it_added() {
        let mut resolved = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        let at = |p: &str| PathPattern::parse(p).unwrap();
        let cargo = resolved.types.get_mut("cargo").unwrap();
        cargo.relocate("CARGO_HOME", &at("/opt/cargo")).unwrap();
        let github = resolved.types.get_mut("github").unwrap();
        // The default spelled out adds no row, and is still named: the variable was honoured.
        github
            .relocate("XDG_CONFIG_HOME", &at("/home/x/.config"))
            .unwrap();
        github.relocate("GH_CONFIG_DIR", &at("/work/gh")).unwrap();
        let recorded = |name: &str| -> Vec<(String, usize)> {
            resolved.types[name]
                .references
                .iter()
                .map(|r| (r.var.clone(), r.rows))
                .collect()
        };
        assert_eq!(recorded("cargo"), [("CARGO_HOME".to_string(), 2)]);
        assert_eq!(
            recorded("github"),
            [
                ("XDG_CONFIG_HOME".to_string(), 0),
                ("GH_CONFIG_DIR".to_string(), 1)
            ]
        );
        assert!(recorded("gpg").is_empty());
        // The record holds the name and a count; the directory is in the deny rows and nowhere
        // else.
        let json = serde_json::to_string(&resolved.types["cargo"].references).unwrap();
        assert_eq!(json, r#"[{"var":"CARGO_HOME","rows":2}]"#);
    }

    #[test]
    fn every_type_contributes_at_least_one_location() {
        for (name, entry) in &Catalog::builtin().types {
            assert!(
                !entry.paths.is_empty() || !entry.envs.is_empty() || !entry.services.is_empty(),
                "{name} has no location"
            );
            for block in &entry.broker {
                crate::BrokerScheme::parse(&block.scheme).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert!(
                    !block.hosts.is_empty(),
                    "{name}: a broker block binds no host"
                );
                assert!(
                    !entry.envs.is_empty(),
                    "{name}: a brokered type needs an env source"
                );
            }
        }
    }

    #[test]
    fn exclusion_lifts_exactly_the_named_type() {
        let resolved = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        let aws_path = PathPattern::parse("/home/x/.aws/**").unwrap();
        let ssh_path = PathPattern::parse("/home/x/.ssh/**").unwrap();

        let denied_default = resolved.denied_paths(&[]);
        assert!(denied_default.contains(&aws_path));
        assert!(denied_default.contains(&ssh_path));

        let denied_allow_aws = resolved.denied_paths(&["aws".to_string()]);
        assert!(!denied_allow_aws.contains(&aws_path), "aws must be lifted");
        assert!(denied_allow_aws.contains(&ssh_path), "ssh must stay denied");
    }

    #[test]
    fn backstop_lifts_only_by_its_own_name() {
        let resolved = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        let novel = PathPattern::parse("**/credentials").unwrap();
        assert!(resolved.denied_paths(&["aws".into()]).contains(&novel));
        assert!(!resolved
            .denied_paths(&[BACKSTOP.to_string()])
            .contains(&novel));
    }

    #[test]
    fn floor_type_of_matches_paths_under_catalog_patterns() {
        let resolved = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        let probe = PathPattern::parse("/home/x/.ssh/id_ed25519").unwrap();
        assert_eq!(resolved.floor_type_of(&[], &probe).as_deref(), Some("ssh"));
        assert_eq!(
            resolved.floor_type_of(&["ssh".to_string()], &probe),
            None,
            "excluding ssh lifts its floor (backstop included, mirroring enforcement)"
        );
        let ordinary = PathPattern::parse("/home/x/project/main.rs").unwrap();
        assert_eq!(resolved.floor_type_of(&[], &ordinary), None);
    }

    #[test]
    fn backstop_covers_credential_shapes_everywhere() {
        // FW-CRED6: a catch-all is location-independent. A credential-shaped file outside $HOME is
        // caught by the backstop at BOTH surfaces -- the discovery floor (so an over-captured
        // denial never leaks into a proposal, FW-INV8) and enforcement (so it stays denied even
        // under a broad grant). The two floors are symmetric.
        let resolved = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        let foreign = PathPattern::parse("/some/other/home/.ssh/id_ed25519").unwrap();
        assert_eq!(
            resolved.floor_type_of(&[], &foreign).as_deref(),
            Some("backstop"),
            "discovery floor must withhold a credential shape wherever observed"
        );
        let denied = resolved.denied_paths(&[]);
        assert!(
            denied
                .iter()
                .any(|p| p.matches_path(std::path::Path::new("/some/other/home/.ssh/id_ed25519"))),
            "enforcement must deny a credential shape even outside $HOME"
        );

        // The named lift turns the whole backstop off at both surfaces (FW-CRED6).
        assert_eq!(
            resolved.floor_type_of(&[BACKSTOP.to_string()], &foreign),
            None
        );
    }
}
