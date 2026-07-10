//! Loading a blueprint from disk. Impure on purpose -- this is where `~` is expanded against `$HOME`,
//! where the `extends` chain is resolved against real files (FW-BP3), and where enforcement paths
//! are canonicalized against the real filesystem -- so the compiler stays pure and takes only
//! absolute, host-independent patterns and an already-flattened layer stack.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use formwork_blueprint::{Blueprint, BlueprintLayer, ExecPosture, PathPattern};

/// Load the file's layer stack (extends chain flattened, bases first) and merge, with no CLI
/// overrides. The single-file case degenerates to exactly the pre-layering behavior (FW-E2E-041).
/// Production callers always pass overrides, so this exists for the tests only.
#[cfg(test)]
pub fn load(path: &Path, home: &str) -> Result<Blueprint> {
    load_stack(path, &[], BlueprintLayer::default(), home)
}

/// The full FW-BP2 stack: baseline (fail-closed floor) → extends chain → file → each `--set`
/// fragment in order → sugar flags. The credential-catalog floor is the compiler's, not a layer.
pub fn load_stack(
    path: &Path,
    sets: &[String],
    sugar: BlueprintLayer,
    home: &str,
) -> Result<Blueprint> {
    let mut layers = Vec::new();
    let mut visiting = Vec::new();
    resolve_file(path, home, &mut visiting, &mut layers)?;
    let cwd = std::env::current_dir().context("resolving current dir for CLI overrides")?;
    for fragment in sets {
        let mut value: toml::Value = toml::from_str(fragment)
            .with_context(|| format!("parsing --set fragment {fragment:?}"))?;
        expand_tilde(&mut value, home);
        let layer: BlueprintLayer = value
            .try_into()
            .with_context(|| format!("interpreting --set fragment {fragment:?}"))?;
        resolve_layer(layer, &cwd, home, &mut visiting, &mut layers)?;
    }
    // A discovered layer sits beside its blueprint and applies from the next run on
    // (FW-DISC4/6). It loads above the file (learned refinements) and below CLI overrides, and
    // only with valid provenance -- a grant nobody can attribute is refused loud.
    let discovered = crate::learn::discovered_path(path);
    if discovered.exists() {
        let layer = parse_discovered_layer(&discovered, home)?;
        tracing::info!(
            file = %discovered.display(),
            reads = layer.fs.reads.len(),
            writes = layer.fs.writes.len(),
            "discovered layer loaded (grants carry discovery provenance)"
        );
        layers.push(layer);
    }
    resolve_layer(sugar, &cwd, home, &mut visiting, &mut layers)?;
    let blueprint = formwork_blueprint::merge(&layers);

    // A typo'd credential type would silently stay blocked -- fail-closed but intent-hiding, the
    // same trap as a typo'd gateway server name. Validate at the edge (parse, don't validate).
    let catalog = formwork_blueprint::Catalog::builtin();
    for t in &blueprint.allow_credentials {
        if !catalog.is_known_type(t) {
            let known: Vec<&str> = catalog
                .type_names()
                .chain(std::iter::once(formwork_blueprint::BACKSTOP))
                .collect();
            bail!("unknown credential type {t:?} in allow-credentials (known: {known:?})");
        }
    }
    Ok(blueprint)
}

/// Depth-first post-order: every base lands before the layer that extends it, so the extending
/// layer's contributions sit higher in the stack (FW-BP2 as amended).
fn resolve_file(
    path: &Path,
    home: &str,
    visiting: &mut Vec<PathBuf>,
    out: &mut Vec<BlueprintLayer>,
) -> Result<()> {
    let canon = std::fs::canonicalize(path)
        .with_context(|| format!("resolving blueprint {}", path.display()))?;
    if let Some(start) = visiting.iter().position(|p| p == &canon) {
        let cycle: Vec<String> = visiting[start..]
            .iter()
            .chain(std::iter::once(&canon))
            .map(|p| p.display().to_string())
            .collect();
        bail!("blueprint `extends` cycle: {}", cycle.join(" -> "));
    }
    let text = std::fs::read_to_string(&canon)
        .with_context(|| format!("reading blueprint {}", canon.display()))?;
    let mut value: toml::Value =
        toml::from_str(&text).with_context(|| format!("parsing blueprint {}", canon.display()))?;
    expand_tilde(&mut value, home);
    let layer: BlueprintLayer = value
        .try_into()
        .with_context(|| format!("interpreting blueprint {}", canon.display()))?;
    let base_dir = canon.parent().map(Path::to_path_buf).unwrap_or_default();

    visiting.push(canon);
    resolve_layer(layer, &base_dir, home, visiting, out)?;
    visiting.pop();
    Ok(())
}

/// Resolve one layer's `extends` (relative to `base_dir`), pushing bases then the layer itself.
fn resolve_layer(
    mut layer: BlueprintLayer,
    base_dir: &Path,
    home: &str,
    visiting: &mut Vec<PathBuf>,
    out: &mut Vec<BlueprintLayer>,
) -> Result<()> {
    for base in std::mem::take(&mut layer.extends) {
        let base_path = if Path::new(&base).is_absolute() {
            PathBuf::from(&base)
        } else {
            base_dir.join(&base)
        };
        resolve_file(&base_path, home, visiting, out)
            .with_context(|| format!("resolving extends {base:?}"))?;
    }
    out.push(layer);
    Ok(())
}

/// Only leading tildes, so a tool name is untouched unless it literally starts with `~/`.
fn expand_tilde(value: &mut toml::Value, home: &str) {
    match value {
        toml::Value::String(s) => *s = expand_tilde_str(s, home),
        toml::Value::Array(a) => a.iter_mut().for_each(|v| expand_tilde(v, home)),
        toml::Value::Table(t) => t.iter_mut().for_each(|(_, v)| expand_tilde(v, home)),
        _ => {}
    }
}

/// The same expansion for CLI flag values, so both surfaces resolve `~` identically (FW-BP1).
pub fn expand_tilde_str(s: &str, home: &str) -> String {
    if s == "~" {
        home.to_string()
    } else if let Some(rest) = s.strip_prefix("~/") {
        format!("{}/{}", home.trim_end_matches('/'), rest)
    } else {
        s.to_string()
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
    // The auto-widen zone is matched against kernel-resolved denial paths at learn time, so it
    // needs the same firmlink/symlink resolution as the grants it may become (FW-DISC4).
    out.discovery.auto_widen = map(&blueprint.discovery.auto_widen)?;
    Ok(out)
}

/// The discovered layer is machine-written and narrowly shaped: no `extends`, and every grant
/// must carry provenance (FW-DISC6) so audit can always distinguish learned from authored.
fn parse_discovered_layer(path: &Path, home: &str) -> Result<BlueprintLayer> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading discovered layer {}", path.display()))?;
    let mut value: toml::Value = toml::from_str(&text)
        .with_context(|| format!("parsing discovered layer {}", path.display()))?;
    expand_tilde(&mut value, home);
    let layer: BlueprintLayer = value
        .try_into()
        .with_context(|| format!("interpreting discovered layer {}", path.display()))?;
    if !layer.extends.is_empty() {
        bail!(
            "discovered layer {} must not use extends; learned grants only",
            path.display()
        );
    }
    for grant in layer.fs.reads.iter().chain(layer.fs.writes.iter()) {
        if !layer.discovery.provenance.contains_key(&grant.canonical()) {
            bail!(
                "discovered layer {} grants {} without provenance; refusing an unattributable grant (FW-DISC6)",
                path.display(),
                grant.canonical()
            );
        }
    }
    Ok(layer)
}

/// Write-deny the session's own policy inputs -- the blueprint, its discovered layer, and its
/// proposal -- inside the confined tree. A confined agent must not shape its own NEXT run by
/// editing the files this run was built from (FW-XR8 / FW-INV8). Readable stays fine (FW-TRA7
/// semantics); only writes are denied.
pub fn protect_policy_inputs(blueprint: &mut Blueprint, blueprint_path: &Path) -> Result<()> {
    let cwd = std::env::current_dir().context("resolving cwd to protect policy inputs")?;
    let absolute = |p: &Path| -> PathBuf {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            cwd.join(p)
        }
    };
    let mut inputs = vec![absolute(blueprint_path)];
    inputs.push(absolute(&crate::learn::discovered_path(blueprint_path)));
    inputs.push(absolute(&crate::learn::proposal_path(blueprint_path)));
    for input in inputs {
        let rendered = input.to_str().ok_or_else(|| {
            anyhow!("policy input path is not valid UTF-8; cannot write-protect it (FW-INV6)")
        })?;
        blueprint
            .fs
            .write_subtract
            .push(PathPattern::parse(rendered).with_context(|| format!("protecting {rendered}"))?);
    }
    Ok(())
}

/// FW-CRED3: an enforced env-points-to-file credential (`GOOGLE_APPLICATION_CREDENTIALS`,
/// `KUBECONFIG`) is stripped as a variable AND the file its value names is denied. The value
/// lives in the launcher's own environment -- impure -- so this is loader-edge code; the result
/// joins the blueprint's subtract set before enforcement-time canonicalization. A set value we
/// cannot faithfully render into a deny fails loud: leaving the referenced file readable while
/// claiming the type enforced would be a silent fail-open (FW-INV6).
pub fn env_file_ref_denies(
    catalog: &formwork_blueprint::ResolvedCatalog,
    allow: &[String],
) -> Result<Vec<PathPattern>> {
    let cwd = std::env::current_dir().context("resolving cwd for env-file-ref denies")?;
    let mut out = Vec::new();
    for (type_name, entry) in catalog.enforced_types(allow) {
        for var in &entry.env_file_refs {
            let Some(raw) = std::env::var_os(var) else {
                continue;
            };
            let value = raw.to_str().ok_or_else(|| {
                anyhow!(
                    "{var} (credential type {type_name}) holds a non-UTF-8 path; refusing to \
                     enforce a deny that might silently not match (FW-INV6)"
                )
            })?;
            if value.is_empty() {
                continue;
            }
            let absolute = if Path::new(value).is_absolute() {
                PathBuf::from(value)
            } else {
                cwd.join(value)
            };
            let pattern = absolute
                .to_str()
                .ok_or_else(|| anyhow!("{var} resolves to a non-UTF-8 path; refusing (FW-INV6)"))?;
            out.push(PathPattern::parse(pattern).with_context(|| {
                format!("{var} (credential type {type_name}) does not name a deniable path")
            })?);
        }
    }
    Ok(out)
}

/// The catalog's floor patterns get the same enforcement-time resolution as grants: a hole that
/// silently failed to match the kernel's resolved path would be a fail-open of the sensitive set
/// (FW-INV6).
pub fn canonicalize_catalog_for_enforcement(
    catalog: &formwork_blueprint::ResolvedCatalog,
) -> Result<formwork_blueprint::ResolvedCatalog> {
    let map = |ps: &[PathPattern]| ps.iter().map(canon_pattern).collect::<Result<Vec<_>>>();
    let mut out = catalog.clone();
    for entry in out.types.values_mut() {
        entry.paths = map(&entry.paths)?;
    }
    out.backstop = map(&catalog.backstop)?;
    Ok(out)
}

fn canon_pattern(p: &PathPattern) -> Result<PathPattern> {
    // Any-depth (`**/`) patterns are relative match suffixes, not resolvable filesystem paths, so
    // symlink/firmlink canonicalization does not apply to the suffix -- but an ANCHORED form's
    // absolute prefix must resolve like any grant (a `/tmp`-anchored rule would otherwise never
    // match the kernel's `/private/tmp` paths -- the same FW-INV6 hazard as any subtract hole).
    if p.is_any_depth() {
        let Some(anchor) = p.anchor() else {
            return Ok(p.clone());
        };
        let resolved = canonicalize_existing_prefix(anchor);
        let resolved = resolved.to_str().ok_or_else(|| {
            anyhow!(
                "refusing to enforce: resolved anchor for {} is not valid UTF-8 (FW-INV6)",
                p.canonical()
            )
        })?;
        let rendered = format!(
            "{}/**/{}{}",
            resolved.trim_end_matches('/'),
            p.base().display(),
            if p.is_subtree() { "/**" } else { "" }
        );
        return Ok(PathPattern::parse(&rendered).unwrap_or_else(|_| p.clone()));
    }
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

    /// Repo test convention (see formwork-confine tests): a pid-tagged dir under temp_dir, no
    /// tempfile dependency.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let root =
                std::env::temp_dir().join(format!("formwork-load-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Scratch(root)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn extends_chain_merges_bases_under_the_extending_file() {
        let dir = Scratch::new("chain");
        std::fs::write(
            dir.path().join("base.toml"),
            r#"
            net = { ports = [443] }
            [fs]
            read-mode = "ambient-minus-subtract"
            subtract = ["/etc/shadow"]
        "#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("child.toml"),
            r#"
            extends = ["base.toml"]
            net = "deny"
            [fs]
            writes = ["/work/project/**"]
        "#,
        )
        .unwrap();
        let bp = load(&dir.path().join("child.toml"), "/home/x").unwrap();
        // Child's posture beats the base's; the base's contributions still union in.
        assert_eq!(bp.net, formwork_blueprint::NetPosture::Deny);
        assert_eq!(
            bp.fs.read_mode,
            formwork_blueprint::ReadMode::AmbientMinusSubtract
        );
        assert_eq!(
            bp.fs.subtract,
            vec![PathPattern::parse("/etc/shadow").unwrap()]
        );
        assert_eq!(
            bp.fs.writes,
            vec![PathPattern::parse("/work/project/**").unwrap()]
        );
    }

    #[test]
    fn extends_cycle_fails_loud_naming_the_cycle() {
        let dir = Scratch::new("cycle");
        std::fs::write(dir.path().join("a.toml"), "extends = [\"b.toml\"]\n").unwrap();
        std::fs::write(dir.path().join("b.toml"), "extends = [\"a.toml\"]\n").unwrap();
        let err = load(&dir.path().join("a.toml"), "/home/x").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cycle"), "error should name the cycle: {msg}");
        assert!(msg.contains("a.toml") && msg.contains("b.toml"), "{msg}");
    }

    #[test]
    fn diamond_extends_is_not_a_cycle() {
        let dir = Scratch::new("diamond");
        std::fs::write(
            dir.path().join("d.toml"),
            "[fs]\nsubtract = [\"/etc/shadow\"]\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("b.toml"), "extends = [\"d.toml\"]\n").unwrap();
        std::fs::write(dir.path().join("c.toml"), "extends = [\"d.toml\"]\n").unwrap();
        std::fs::write(
            dir.path().join("a.toml"),
            "extends = [\"b.toml\", \"c.toml\"]\n",
        )
        .unwrap();
        let bp = load(&dir.path().join("a.toml"), "/home/x").unwrap();
        assert_eq!(
            bp.fs.subtract,
            vec![PathPattern::parse("/etc/shadow").unwrap()]
        );
    }

    #[test]
    fn set_fragments_and_sugar_layer_over_the_file() {
        let dir = Scratch::new("sets");
        let file = dir.path().join("bp.toml");
        std::fs::write(
            &file,
            r#"
            net = { ports = [443] }
            [fs]
            reads = ["/work/**"]
        "#,
        )
        .unwrap();
        let sugar = BlueprintLayer {
            fs: formwork_blueprint::FsLayer {
                subtract: vec![PathPattern::parse("/work/secret.txt").unwrap()],
                ..Default::default()
            },
            ..Default::default()
        };
        let bp = load_stack(&file, &["net = \"deny\"".to_string()], sugar, "/home/x").unwrap();
        assert_eq!(bp.net, formwork_blueprint::NetPosture::Deny);
        assert_eq!(bp.fs.reads, vec![PathPattern::parse("/work/**").unwrap()]);
        assert_eq!(
            bp.fs.subtract,
            vec![PathPattern::parse("/work/secret.txt").unwrap()]
        );
    }

    #[test]
    fn any_depth_patterns_pass_canonicalization_unchanged() {
        // A `**/` suffix is a match pattern, not a real path: it must survive enforcement-time
        // canonicalization verbatim, never get re-rooted against cwd.
        let blueprint = Blueprint {
            fs: formwork_blueprint::FsBlueprint {
                subtract: vec![
                    PathPattern::parse("**/.env").unwrap(),
                    PathPattern::parse("**/.git/hooks/**").unwrap(),
                ],
                ..Default::default()
            },
            ..Blueprint::empty()
        };
        let out = canonicalize_for_enforcement(&blueprint).unwrap();
        assert_eq!(out.fs.subtract, blueprint.fs.subtract);
    }
}
