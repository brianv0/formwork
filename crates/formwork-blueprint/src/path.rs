//! Path patterns: normalized absolute paths with an optional `/**` subtree marker, plus a `**/`
//! recursive-basename form that matches a suffix at any depth (FW-CAP6). Normalization (lexical
//! `.`/`..`, collapsed slashes, no trailing slash) makes equal scopes compare equal, which keeps
//! compilation deterministic and narrowing exact. `~` is expanded by the CLI, not here.

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathPattern {
    /// Absolute when `any_depth` is false; a relative suffix when it is true.
    base: PathBuf,
    subtree: bool,
    /// A leading `**/`: match `base` as a trailing/containing component sequence at any depth.
    any_depth: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    #[error("path pattern must be absolute (start with '/'): {0:?}")]
    NotAbsolute(String),
    #[error("path pattern is empty")]
    Empty,
    #[error("path pattern escapes root with '..': {0:?}")]
    EscapesRoot(String),
}

impl PathPattern {
    pub fn parse(input: &str) -> Result<Self, PathError> {
        if input.is_empty() {
            return Err(PathError::Empty);
        }

        // Recursive-basename form (FW-CAP6): a leading `**/` matches the suffix at any depth. Used
        // for sensitive files that appear anywhere in a tree, e.g. `**/.env`, `**/.git/hooks/**`.
        if let Some(rest) = input.strip_prefix("**/") {
            let (suffix, subtree) = match rest.strip_suffix("/**") {
                Some(s) => (s, true),
                None => (rest, false),
            };
            if suffix.is_empty() || suffix == "**" {
                return Err(PathError::Empty);
            }
            let base = normalize_relative(suffix)
                .ok_or_else(|| PathError::EscapesRoot(input.to_string()))?;
            return Ok(PathPattern {
                base,
                subtree,
                any_depth: true,
            });
        }

        let (path_part, subtree) = if input == "/**" {
            ("/", true)
        } else if let Some(stripped) = input.strip_suffix("/**") {
            (stripped, true)
        } else {
            (input, false)
        };

        if !path_part.starts_with('/') {
            return Err(PathError::NotAbsolute(input.to_string()));
        }

        let base = normalize_absolute(path_part)
            .ok_or_else(|| PathError::EscapesRoot(input.to_string()))?;
        Ok(PathPattern {
            base,
            subtree,
            any_depth: false,
        })
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    pub fn is_subtree(&self) -> bool {
        self.subtree
    }

    /// True for the `**/`-anchored recursive-basename form (FW-CAP6). The `base` is then a relative
    /// suffix, and enforcement matches it at any depth (a regex on Seatbelt).
    pub fn is_any_depth(&self) -> bool {
        self.any_depth
    }

    /// Round-trips through `parse`.
    pub fn canonical(&self) -> String {
        if self.any_depth {
            if self.subtree {
                format!("**/{}/**", self.base.display())
            } else {
                format!("**/{}", self.base.display())
            }
        } else if self.subtree {
            if self.base == Path::new("/") {
                "/**".to_string()
            } else {
                format!("{}/**", self.base.display())
            }
        } else {
            self.base.display().to_string()
        }
    }

    /// The primitive behind narrowing: a subtree covers any path at or below its base; a literal
    /// covers only the identical literal. `**/` patterns compare among themselves the same way;
    /// across the two forms only the everything-grant `/**` covers an any-depth pattern, and an
    /// any-depth pattern is conservatively taken not to cover a fixed absolute path (a redundant
    /// deny is harmless, a missed one is not -- FW-INV6).
    pub fn covers(&self, other: &PathPattern) -> bool {
        match (self.any_depth, other.any_depth) {
            (false, false) | (true, true) => {
                if self.subtree {
                    other.base.starts_with(&self.base)
                } else {
                    !other.subtree && self.base == other.base
                }
            }
            (false, true) => self.subtree && self.base == Path::new("/"),
            (true, false) => false,
        }
    }
}

/// Purely lexical (no filesystem access); real-path canonicalization is deferred to enforce time.
fn normalize_absolute(path: &str) -> Option<PathBuf> {
    let mut out: Vec<&std::ffi::OsStr> = Vec::new();
    for comp in Path::new(path).components() {
        match comp {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop()?; // `..` above root -> escape
            }
            Component::Normal(c) => out.push(c),
            Component::Prefix(_) => return None,
        }
    }
    let mut buf = PathBuf::from("/");
    for c in out {
        buf.push(c);
    }
    Some(buf)
}

/// The relative suffix of a `**/`-anchored pattern: normal components only -- no root, no `..`, no
/// interior `**`. Returns a relative `PathBuf` with at least one component, else `None`.
fn normalize_relative(path: &str) -> Option<PathBuf> {
    let mut out: Vec<&std::ffi::OsStr> = Vec::new();
    for comp in Path::new(path).components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(c) => {
                if c == "**" {
                    return None; // interior `**` is unsupported; only a single leading `**/`
                }
                out.push(c);
            }
            // Root, `..`, and Windows prefixes are all invalid inside a suffix.
            _ => return None,
        }
    }
    if out.is_empty() {
        return None;
    }
    let mut buf = PathBuf::new();
    for c in out {
        buf.push(c);
    }
    Some(buf)
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

impl fmt::Debug for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PathPattern({:?})", self.canonical())
    }
}

impl FromStr for PathPattern {
    type Err = PathError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PathPattern::parse(s)
    }
}

impl Serialize for PathPattern {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.canonical())
    }
}

impl<'de> Deserialize<'de> for PathPattern {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        PathPattern::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Idempotent and order-independent. O(n^2); scope sets are small.
pub fn canonicalize_set(patterns: &[PathPattern]) -> Vec<PathPattern> {
    let mut sorted = patterns.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut out: Vec<PathPattern> = Vec::with_capacity(sorted.len());
    for (i, p) in sorted.iter().enumerate() {
        let redundant = sorted
            .iter()
            .enumerate()
            .any(|(j, q)| i != j && q.covers(p) && !(p.covers(q) && j > i));
        if !redundant {
            out.push(p.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathPattern {
        PathPattern::parse(s).unwrap()
    }

    #[test]
    fn normalization_collapses_and_resolves() {
        assert_eq!(p("/work//project/./x").canonical(), "/work/project/x");
        assert_eq!(p("/work/project/../other").canonical(), "/work/other");
        assert_eq!(p("/work/project/").canonical(), "/work/project");
    }

    #[test]
    fn subtree_marker_parsed_and_rendered() {
        assert!(p("/work/**").is_subtree());
        assert_eq!(p("/work/**").canonical(), "/work/**");
        assert_eq!(p("/**").canonical(), "/**");
        assert!(p("/**").is_subtree());
        assert!(!p("/work/file").is_subtree());
    }

    #[test]
    fn rejects_relative_and_escaping() {
        assert!(matches!(
            PathPattern::parse("work/x"),
            Err(PathError::NotAbsolute(_))
        ));
        assert!(matches!(
            PathPattern::parse("/../x"),
            Err(PathError::EscapesRoot(_))
        ));
        assert!(matches!(PathPattern::parse(""), Err(PathError::Empty)));
    }

    #[test]
    fn any_depth_parses_literal_and_subtree() {
        let env = p("**/.env");
        assert!(env.is_any_depth());
        assert!(!env.is_subtree());
        assert_eq!(env.canonical(), "**/.env");

        let hooks = p("**/.git/hooks/**");
        assert!(hooks.is_any_depth());
        assert!(hooks.is_subtree());
        assert_eq!(hooks.canonical(), "**/.git/hooks/**");

        assert_eq!(p("**/.git/config").canonical(), "**/.git/config");
    }

    #[test]
    fn any_depth_rejects_degenerate_and_interior_globs() {
        assert!(matches!(PathPattern::parse("**/"), Err(PathError::Empty)));
        assert!(matches!(PathPattern::parse("**/**"), Err(PathError::Empty)));
        assert!(matches!(
            PathPattern::parse("**/a/**/b"),
            Err(PathError::EscapesRoot(_))
        ));
        assert!(matches!(
            PathPattern::parse("**/../etc"),
            Err(PathError::EscapesRoot(_))
        ));
    }

    #[test]
    fn subtree_covers_descendants_literal_covers_only_self() {
        assert!(p("/work/**").covers(&p("/work/project/x")));
        assert!(p("/work/**").covers(&p("/work/**")));
        assert!(p("/work/**").covers(&p("/work/project/**")));
        assert!(!p("/work/project/**").covers(&p("/work/other")));
        assert!(p("/work/f").covers(&p("/work/f")));
        assert!(!p("/work/f").covers(&p("/work/**")));
        assert!(!p("/work/f").covers(&p("/work/f/child")));
    }

    #[test]
    fn covers_is_component_aware_not_string_prefix() {
        assert!(!p("/work/proj/**").covers(&p("/work/project/x")));
    }

    #[test]
    fn any_depth_covers_only_within_form_except_root_grant() {
        // among any-depth patterns, subtree covers a deeper suffix
        assert!(p("**/.git/**").covers(&p("**/.git/hooks/**")));
        assert!(p("**/.env").covers(&p("**/.env")));
        assert!(!p("**/.env").covers(&p("**/.envrc")));
        // the everything-grant covers any-depth patterns; a specific path does not
        assert!(p("/**").covers(&p("**/.env")));
        assert!(!p("/work/**").covers(&p("**/.env")));
        // an any-depth pattern is conservatively not taken to cover a fixed path
        assert!(!p("**/.env").covers(&p("/work/.env")));
    }

    #[test]
    fn canonicalize_drops_redundant() {
        let set = vec![
            p("/work/**"),
            p("/work/project/x"),
            p("/etc/hosts"),
            p("/work/project/**"),
        ];
        let c = canonicalize_set(&set);
        assert_eq!(c, vec![p("/etc/hosts"), p("/work/**")]);
    }

    #[test]
    fn serde_roundtrip_is_canonical_string() {
        let j = serde_json::to_string(&p("/a//b/../c/**")).unwrap();
        assert_eq!(j, "\"/a/c/**\"");
        let back: PathPattern = serde_json::from_str(&j).unwrap();
        assert_eq!(back, p("/a/c/**"));

        let j2 = serde_json::to_string(&p("**/.env")).unwrap();
        assert_eq!(j2, "\"**/.env\"");
        let back2: PathPattern = serde_json::from_str(&j2).unwrap();
        assert_eq!(back2, p("**/.env"));
    }
}
