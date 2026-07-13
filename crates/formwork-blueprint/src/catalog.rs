//! The credential-location catalog (FW-CRED1): typed, versioned data embedded at build time so
//! the pure compiler needs no I/O. Raw entries carry `~`-relative paths; [`Catalog::resolve`]
//! expands them against a caller-supplied home into [`ResolvedCatalog`], the form the compiler
//! takes. Resolution is pure in `(catalog, home)`, keeping compilation deterministic (FW-FID4).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::{PathError, PathPattern};

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
    pub env_file_refs: Vec<String>,
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
    pub env_file_refs: Vec<String>,
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
        assert_eq!(catalog.version, 1);
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
            for var in &entry.env_file_refs {
                assert!(
                    entry.envs.contains(var),
                    "{name}: env-file-ref {var} must also be listed in envs"
                );
            }
        }
    }

    #[test]
    fn every_type_contributes_at_least_one_location() {
        for (name, entry) in &Catalog::builtin().types {
            assert!(
                !entry.paths.is_empty() || !entry.envs.is_empty(),
                "{name} has neither paths nor envs"
            );
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
