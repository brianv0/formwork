//! Loading a blueprint from disk. Impure on purpose -- this is where `~` is expanded against `$HOME` and
//! where enforcement paths are canonicalized against the real filesystem -- so the compiler stays
//! pure and takes only absolute, host-independent patterns.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use formwork_blueprint::{Blueprint, ExecPosture, PathPattern};

pub fn load(path: &Path, home: &str) -> Result<Blueprint> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading blueprint {}", path.display()))?;
    let mut value: toml::Value =
        toml::from_str(&text).with_context(|| format!("parsing blueprint {}", path.display()))?;
    expand_tilde(&mut value, home);
    let blueprint: Blueprint = value.try_into().context("interpreting blueprint")?;
    Ok(blueprint)
}

/// Only leading tildes, so a tool name is untouched unless it literally starts with `~/`.
fn expand_tilde(value: &mut toml::Value, home: &str) {
    match value {
        toml::Value::String(s) => {
            if s == "~" {
                *s = home.to_string();
            } else if let Some(rest) = s.strip_prefix("~/") {
                *s = format!("{}/{}", home.trim_end_matches('/'), rest);
            }
        }
        toml::Value::Array(a) => a.iter_mut().for_each(|v| expand_tilde(v, home)),
        toml::Value::Table(t) => t.iter_mut().for_each(|(_, v)| expand_tilde(v, home)),
        _ => {}
    }
}

/// Enforcement path only. Seatbelt (and Landlock) match on the kernel's resolved path, so a grant of
/// `/tmp/x` never matches the real `/private/tmp/x` (macOS firmlinks). This resolves the longest
/// existing ancestor of each pattern and re-appends the not-yet-existing tail. Impure, so it lives
/// here, not in the compiler, and is not applied to dry-run compiles. Fails loud on a non-UTF-8
/// resolved path: a lossy rule could silently fail to match, and for a `subtract` hole that is a
/// silent fail-open (FW-INV6).
pub fn canonicalize_for_enforcement(blueprint: &Blueprint) -> Result<Blueprint> {
    let map = |ps: &[PathPattern]| ps.iter().map(canon_pattern).collect::<Result<Vec<_>>>();
    let mut out = blueprint.clone();
    out.fs.reads = map(&blueprint.fs.reads)?;
    out.fs.writes = map(&blueprint.fs.writes)?;
    out.fs.subtract = map(&blueprint.fs.subtract)?;
    if let ExecPosture::Allowlist(paths) = &blueprint.exec {
        out.exec = ExecPosture::Allowlist(map(paths)?);
    }
    Ok(out)
}

fn canon_pattern(p: &PathPattern) -> Result<PathPattern> {
    let base = canonicalize_existing_prefix(p.base());
    // `to_str`, not `to_string_lossy`: refuse to enforce a path we cannot render faithfully (FW-INV6).
    let base = base.to_str().ok_or_else(|| {
        anyhow!(
            "refusing to enforce: resolved path for {} is not valid UTF-8 and cannot be rendered \
             into a policy rule without risking a silent mismatch (FW-INV6)",
            p.canonical()
        )
    })?;
    let mut s = base.to_string();
    if p.is_subtree() {
        s.push_str("/**");
    }
    // Re-parse; if canonicalization produced something unparsable, keep the original.
    Ok(PathPattern::parse(&s).unwrap_or_else(|_| p.clone()))
}

fn canonicalize_existing_prefix(path: &Path) -> PathBuf {
    let mut ancestor = path.to_path_buf();
    let mut tail: Vec<OsString> = Vec::new();
    loop {
        if let Ok(real) = std::fs::canonicalize(&ancestor) {
            let mut out = real;
            out.extend(tail.iter().rev());
            return out;
        }
        match (
            ancestor.file_name().map(|n| n.to_owned()),
            ancestor.parent().map(|p| p.to_path_buf()),
        ) {
            (Some(name), Some(parent)) => {
                tail.push(name);
                ancestor = parent;
            }
            _ => return path.to_path_buf(), // reached root with nothing resolvable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use formwork_blueprint::PathPattern;

    #[test]
    fn expands_leading_tilde_in_paths() {
        let mut v: toml::Value = toml::from_str(
            r#"
            [fs]
            reads = ["~/project/**", "~"]
            subtract = ["~/.ssh/**"]
            [mcp.s]
            tools = { allow = ["~weird_but_left_alone"] }
        "#,
        )
        .unwrap();
        expand_tilde(&mut v, "/Users/bvk");
        let blueprint: Blueprint = v.try_into().unwrap();
        assert_eq!(
            blueprint.fs.reads[0],
            PathPattern::parse("/Users/bvk/project/**").unwrap()
        );
        assert!(blueprint
            .fs
            .reads
            .contains(&PathPattern::parse("/Users/bvk").unwrap()));
        assert_eq!(
            blueprint.fs.subtract[0],
            PathPattern::parse("/Users/bvk/.ssh/**").unwrap()
        );
        // A tool name that isn't `~/`-prefixed is untouched.
        assert_eq!(
            blueprint.mcp["s"].tools,
            formwork_blueprint::Visibility::Allow(vec!["~weird_but_left_alone".into()])
        );
    }
}
