//! Loading a blueprint from disk. Impure on purpose -- this is where the CLI-edge path sigils are
//! expanded (`~` against `$HOME`, `$CWD` against the launch directory, see [`Sigils`]), where the
//! `extends` chain is resolved against real files (FW-BP3), and where enforcement paths are
//! canonicalized against the real filesystem -- so the compiler stays pure and takes only
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
    load_stack(
        path,
        &[],
        BlueprintLayer::default(),
        &Sigils::new(home, "/work"),
    )
}

/// The full FW-BP2 stack: baseline (fail-closed floor) → extends chain → file → each `--set`
/// fragment in order → sugar flags. The credential-catalog floor is the compiler's, not a layer.
pub fn load_stack(
    path: &Path,
    sets: &[String],
    sugar: BlueprintLayer,
    sigils: &Sigils,
) -> Result<Blueprint> {
    let mut layers = Vec::new();
    let mut visiting = Vec::new();
    resolve_file(path, sigils, &mut visiting, &mut layers)?;
    // Relative `extends` in a CLI override (no file to sit beside) resolve against the launch
    // directory -- the same path `$CWD` expands to.
    let cwd = Path::new(sigils.cwd);
    for fragment in sets {
        let mut value: toml::Value = toml::from_str(fragment)
            .with_context(|| format!("parsing --set fragment {fragment:?}"))?;
        sigils.expand_value(&mut value);
        let layer: BlueprintLayer = value
            .try_into()
            .with_context(|| format!("interpreting --set fragment {fragment:?}"))?;
        resolve_layer(layer, cwd, sigils, &mut visiting, &mut layers)?;
    }
    // A discovered layer sits beside its blueprint and applies from the next run on
    // (FW-DISC4/6). It loads above the file (learned refinements) and below CLI overrides, and
    // only with valid provenance -- a grant nobody can attribute is refused loud.
    let discovered = crate::learn::discovered_path(path);
    if discovered.exists() {
        let layer = parse_discovered_layer(&discovered, sigils)?;
        tracing::info!(
            file = %discovered.display(),
            reads = layer.fs.reads.len(),
            writes = layer.fs.writes.len(),
            "discovered layer loaded (grants carry discovery provenance)"
        );
        layers.push(layer);
    }
    resolve_layer(sugar, cwd, sigils, &mut visiting, &mut layers)?;
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
    sigils: &Sigils,
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
    sigils.expand_value(&mut value);
    let layer: BlueprintLayer = value
        .try_into()
        .with_context(|| format!("interpreting blueprint {}", canon.display()))?;
    let base_dir = canon.parent().map(Path::to_path_buf).unwrap_or_default();

    visiting.push(canon);
    resolve_layer(layer, &base_dir, sigils, visiting, out)?;
    visiting.pop();
    Ok(())
}

/// Resolve one layer's `extends` (relative to `base_dir`), pushing bases then the layer itself.
fn resolve_layer(
    mut layer: BlueprintLayer,
    base_dir: &Path,
    sigils: &Sigils,
    visiting: &mut Vec<PathBuf>,
    out: &mut Vec<BlueprintLayer>,
) -> Result<()> {
    for base in std::mem::take(&mut layer.extends) {
        let base_path = if Path::new(&base).is_absolute() {
            PathBuf::from(&base)
        } else {
            base_dir.join(&base)
        };
        resolve_file(&base_path, sigils, visiting, out)
            .with_context(|| format!("resolving extends {base:?}"))?;
    }
    desugar_rules(&mut layer, sigils)?;
    out.push(layer);
    Ok(())
}

/// Desugar the flat rule surface (FW-BP1) into `fs`/`exec`, then empty `rules`/`mode` -- the same
/// edge that resolves `extends`, so verbs never reach the pure merge or compiler. One `"<verb>:<path>"`
/// string is one rule; the path takes the same sigils as any grant (FW-BP5). Deny still beats allow
/// at match time (FW-BP4), so a verb only ever appends to a set; order does not matter.
fn desugar_rules(layer: &mut BlueprintLayer, sigils: &Sigils) -> Result<()> {
    if let Some(mode) = layer.mode.take() {
        if layer.fs.read_mode.is_some() {
            bail!("set either `mode` or `[fs] read-mode` in a layer, not both");
        }
        layer.fs.read_mode = Some(mode.read_mode());
    }
    if layer.rules.is_empty() {
        return Ok(());
    }
    // Exec verbs fold into one allow-list for this layer (last-set-wins across layers, FW-ISO4);
    // an allow-list already present on the layer is extended, never dropped.
    let mut exec_paths: Vec<PathPattern> = match layer.exec.take() {
        Some(ExecPosture::Allowlist(p)) => p,
        Some(ExecPosture::Unrestricted) => {
            bail!("exec verbs (`exec`/`readexec`/`allow`) conflict with an explicit `exec = unrestricted` in the same layer");
        }
        None => Vec::new(),
    };
    for raw in std::mem::take(&mut layer.rules) {
        let (verb, path) = raw
            .split_once(':')
            .ok_or_else(|| anyhow!("rule {raw:?} is not \"<verb>:<path>\""))?;
        let pat = PathPattern::parse(&sigils.expand(path.trim()))
            .with_context(|| format!("rule {raw:?}"))?;
        match verb.trim() {
            "read" | "readonly" => layer.fs.reads.push(pat),
            "readwrite" => layer.fs.writes.push(pat),
            // The create/write split (FW-CAP9): modify existing, no create.
            "write" => layer.fs.writes_no_create.push(pat),
            "allow" => {
                layer.fs.writes.push(pat.clone());
                exec_paths.push(pat);
            }
            "readexec" => {
                layer.fs.reads.push(pat.clone());
                exec_paths.push(pat);
            }
            "exec" => exec_paths.push(pat),
            "deny" => layer.fs.subtract.push(pat),
            other => bail!(
                "unknown rule verb {other:?} in {raw:?} (known: read, readonly, write, readwrite, allow, readexec, exec, deny)"
            ),
        }
    }
    if !exec_paths.is_empty() {
        layer.exec = Some(ExecPosture::Allowlist(exec_paths));
    }
    Ok(())
}

/// The CLI-edge path sigils, expanded before patterns reach the pure, absolute-only compiler:
/// `~` -> `$HOME`, `$CWD` -> the directory `formwork` was launched from. A fixed, closed set of
/// tokens -- deliberately NOT general `$VAR` interpolation, since the environment is exactly what
/// the launcher scrubs (FW-CRED2), so letting arbitrary vars name paths would reopen that surface.
/// Both tokens yield absolute paths; enforcement-time canonicalization ([`canon_pattern`]) then
/// reconciles them with the kernel's resolved view, so an expanded sigil behaves like any absolute
/// grant. One `Sigils` is built per invocation and shared across every surface (file, `--set`,
/// sugar flags), so `~` and `$CWD` resolve identically everywhere (FW-BP1).
pub struct Sigils<'a> {
    home: &'a str,
    cwd: &'a str,
    warned_cwd: std::cell::Cell<bool>,
}

impl<'a> Sigils<'a> {
    pub fn new(home: &'a str, cwd: &'a str) -> Sigils<'a> {
        Sigils {
            home,
            cwd,
            warned_cwd: std::cell::Cell::new(false),
        }
    }

    /// Expand a leading sigil in one string. A value that starts with neither sigil is returned
    /// untouched, so a tool name is only rewritten if it literally begins with `~`/`~/`/`$CWD`/`$CWD/`.
    pub fn expand(&self, s: &str) -> String {
        if s == "~" {
            self.home.to_string()
        } else if let Some(rest) = s.strip_prefix("~/") {
            format!("{}/{}", self.home.trim_end_matches('/'), rest)
        } else if s == "$CWD" {
            self.warn_if_broad_cwd();
            self.cwd.to_string()
        } else if let Some(rest) = s.strip_prefix("$CWD/") {
            self.warn_if_broad_cwd();
            format!("{}/{}", self.cwd.trim_end_matches('/'), rest)
        } else {
            s.to_string()
        }
    }

    /// `$CWD` is contextual where `~` is stable: launched from `$HOME` or `/`, a `$CWD/**` grant
    /// covers the whole home or the entire filesystem rather than a project. It is operator-chosen
    /// (an agent cannot move the launch directory) and the expanded path is visible in the
    /// dry-run, so this warns once rather than refusing -- a nudge to launch from the project dir.
    fn warn_if_broad_cwd(&self) {
        if (self.cwd == self.home || self.cwd == "/") && !self.warned_cwd.replace(true) {
            tracing::warn!(
                cwd = %self.cwd,
                "$CWD resolves to {} -- a grant written relative to $CWD covers your whole home or \
                 the filesystem root; launch formwork from the project directory to scope it",
                self.cwd
            );
        }
    }

    /// Walk a parsed TOML value, expanding every string leaf. Only leading sigils are touched.
    fn expand_value(&self, value: &mut toml::Value) {
        match value {
            toml::Value::String(s) => *s = self.expand(s),
            toml::Value::Array(a) => a.iter_mut().for_each(|v| self.expand_value(v)),
            toml::Value::Table(t) => t.iter_mut().for_each(|(_, v)| self.expand_value(v)),
            _ => {}
        }
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
fn parse_discovered_layer(path: &Path, sigils: &Sigils) -> Result<BlueprintLayer> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading discovered layer {}", path.display()))?;
    let mut value: toml::Value = toml::from_str(&text)
        .with_context(|| format!("parsing discovered layer {}", path.display()))?;
    sigils.expand_value(&mut value);
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
    use formwork_blueprint::{ExecPosture, Mode, PathPattern, ReadMode};

    fn pp(s: &str) -> PathPattern {
        PathPattern::parse(s).unwrap()
    }

    #[test]
    fn desugar_maps_verbs_and_mode_to_fields() {
        let sigils = Sigils::new("/home/x", "/work");
        let mut layer = BlueprintLayer {
            mode: Some(Mode::StrictUnveil),
            rules: vec![
                "readonly:/usr/**".into(),
                "readwrite:~/project/**".into(),
                "write:~/project/build".into(),
                "readexec:/bin/ls".into(),
                "exec:/bin/cat".into(),
                "deny:~/.ssh".into(),
            ],
            ..Default::default()
        };
        desugar_rules(&mut layer, &sigils).unwrap();
        // Emptied like `extends`, so merge never sees verbs.
        assert!(layer.rules.is_empty() && layer.mode.is_none());
        assert_eq!(layer.fs.read_mode, Some(ReadMode::Closed));
        assert_eq!(layer.fs.reads, vec![pp("/usr/**"), pp("/bin/ls")]);
        assert_eq!(layer.fs.writes, vec![pp("/home/x/project/**")]);
        assert_eq!(layer.fs.writes_no_create, vec![pp("/home/x/project/build")]);
        assert_eq!(layer.fs.subtract, vec![pp("/home/x/.ssh")]);
        assert_eq!(
            layer.exec,
            Some(ExecPosture::Allowlist(vec![pp("/bin/ls"), pp("/bin/cat")]))
        );
    }

    #[test]
    fn flat_rules_equal_nested_fs_after_load() {
        // FW-BP1: the flat rule surface and the nested `[fs]` table are one model.
        let flat = "net = \"deny\"\nmode = \"strict-unveil\"\n\
                    rules = [\"readonly:/usr/**\", \"readwrite:/work/p/**\", \"deny:/work/p/secret\"]\n";
        let nested = "net = \"deny\"\n[fs]\nread-mode = \"closed\"\n\
                      reads = [\"/usr/**\"]\nwrites = [\"/work/p/**\"]\nsubtract = [\"/work/p/secret\"]\n";
        let sigils = Sigils::new("/home/x", "/work");
        let load = |src: &str| {
            let layer: BlueprintLayer = toml::from_str(src).unwrap();
            let mut out = Vec::new();
            resolve_layer(
                layer,
                Path::new("/work"),
                &sigils,
                &mut Vec::new(),
                &mut out,
            )
            .unwrap();
            formwork_blueprint::merge(&out)
        };
        assert_eq!(load(flat), load(nested));
    }

    #[test]
    fn desugar_rejects_bad_input() {
        let sigils = Sigils::new("/home/x", "/work");
        let layer = |rules: &[&str], mode, read_mode| BlueprintLayer {
            rules: rules.iter().map(|s| s.to_string()).collect(),
            mode,
            fs: formwork_blueprint::FsLayer {
                read_mode,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(desugar_rules(&mut layer(&["bogus:/x"], None, None), &sigils).is_err());
        assert!(desugar_rules(&mut layer(&["deny"], None, None), &sigils).is_err());
        // `mode` and `[fs] read-mode` in one layer is a loud conflict.
        assert!(desugar_rules(
            &mut layer(&[], Some(Mode::Subtractive), Some(ReadMode::Closed)),
            &sigils
        )
        .is_err());
    }

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
        Sigils::new("/home/testuser", "/work").expand_value(&mut v);
        let blueprint: Blueprint = v.try_into().unwrap();
        assert_eq!(
            blueprint.fs.reads[0],
            PathPattern::parse("/home/testuser/project/**").unwrap()
        );
        assert!(blueprint
            .fs
            .reads
            .contains(&PathPattern::parse("/home/testuser").unwrap()));
        assert_eq!(
            blueprint.fs.subtract[0],
            PathPattern::parse("/home/testuser/.ssh/**").unwrap()
        );
        // A tool name that isn't `~/`-prefixed is untouched.
        assert_eq!(
            blueprint.mcp["s"].tools,
            formwork_blueprint::Visibility::Allow(vec!["~weird_but_left_alone".into()])
        );
    }

    #[test]
    fn expands_cwd_sigil_and_composes_with_anchored_form() {
        let sigils = Sigils::new("/home/testuser", "/work/proj");
        // `$CWD` alone and as a prefix, resolved against the launch directory.
        assert_eq!(sigils.expand("$CWD"), "/work/proj");
        assert_eq!(sigils.expand("$CWD/src/**"), "/work/proj/src/**");
        // It composes with the anchored any-depth form: the project becomes the prefix.
        assert_eq!(
            sigils.expand("$CWD/**/credentials"),
            "/work/proj/**/credentials"
        );
        // `~` still resolves against $HOME in the same context, and a bare word is untouched.
        assert_eq!(sigils.expand("~/.ssh/**"), "/home/testuser/.ssh/**");
        assert_eq!(sigils.expand("/etc/hosts"), "/etc/hosts");
        assert_eq!(sigils.expand("$CWDISH"), "$CWDISH"); // only the exact sigil, not a prefix match

        // A blueprint value goes through the same walker and parses to an absolute pattern.
        let mut v: toml::Value = toml::from_str("[fs]\nwrites = [\"$CWD/**\"]\n").unwrap();
        sigils.expand_value(&mut v);
        let blueprint: Blueprint = v.try_into().unwrap();
        assert_eq!(
            blueprint.fs.writes,
            vec![PathPattern::parse("/work/proj/**").unwrap()]
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
        let bp = load_stack(
            &file,
            &["net = \"deny\"".to_string()],
            sugar,
            &Sigils::new("/home/x", "/work"),
        )
        .unwrap();
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
