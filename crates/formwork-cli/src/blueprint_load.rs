//! Loading a blueprint from disk. Impure on purpose -- this is where the CLI-edge path sigils are
//! expanded (`~` against `$HOME`, `$CWD` against the launch directory, see [`Sigils`]), where the
//! `extends` chain is resolved against real files (FW-BP3), and where enforcement paths are
//! canonicalized against the real filesystem -- so the compiler stays pure and takes only
//! absolute, host-independent patterns and an already-flattened layer stack.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use formwork_blueprint::{
    merge_with_provenance, Blueprint, BlueprintLayer, ExecPosture, PathPattern, Provenance,
    ResolvedCatalog, ResolvedReference, RuleSource,
};

/// The blueprint file every subcommand looks for when `--blueprint` is not given.
pub const DEFAULT_BLUEPRINT_NAME: &str = "FORMWORK.toml";

/// The second discovery location (FEP-5 D3): a blueprint inside `.formwork/`, so the file and its
/// derived proposal/discovered layers sit in one directory. Write-protecting them then protects
/// one directory instead of splitting the project root, where Landlock would lose the right to
/// create files directly in the root.
pub const DOTDIR_BLUEPRINT: &str = ".formwork/blueprint.toml";

/// Profiles compiled into the binary, addressable as `extends = ["builtin:<name>"]` -- so a
/// blueprint can layer on the shipped default without a repo checkout (the release-binary user
/// has no `profiles/` directory to point at).
const BUILTIN_PROFILES: &[(&str, &str)] =
    &[("default", include_str!("../../../profiles/default.toml"))];

/// How the blueprint path was chosen. Auto-discovery must never be silent (a policy the user
/// never named still governs the session), so the source travels with the path into logs and
/// `compile`/`explain` output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlueprintSource {
    Flag,
    Discovered,
}

impl BlueprintSource {
    pub fn as_str(self) -> &'static str {
        match self {
            BlueprintSource::Flag => "flag",
            BlueprintSource::Discovered => "auto-discovered",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedBlueprint {
    pub path: PathBuf,
    pub source: BlueprintSource,
}

/// Resolve which blueprint file governs this invocation: the explicit flag always wins; otherwise
/// a `FORMWORK.toml` discovered from the launch directory upward. `Ok(None)` means neither -- the
/// caller decides whether that is an error (enforcing commands) or a degraded mode (`explain`
/// with no blueprint still summarizes the host).
pub fn resolve_blueprint(
    flag: Option<&Path>,
    cwd: &Path,
    home: &str,
) -> Result<Option<ResolvedBlueprint>> {
    if let Some(path) = flag {
        tracing::info!(blueprint = %path.display(), source = "flag", "blueprint resolved");
        return Ok(Some(ResolvedBlueprint {
            path: path.to_path_buf(),
            source: BlueprintSource::Flag,
        }));
    }
    let Some(found) = find_default_blueprint(cwd, home)? else {
        return Ok(None);
    };
    tracing::info!(
        blueprint = %found.display(),
        source = "auto-discovered",
        "blueprint resolved (no --blueprint given; found {})",
        found.display()
    );
    Ok(Some(ResolvedBlueprint {
        path: found,
        source: BlueprintSource::Discovered,
    }))
}

/// Walk from `cwd` upward looking for a `FORMWORK.toml`, stopping at `$HOME` (inclusive) so a
/// project never silently inherits a file from above the user's own tree, and never consulting
/// the filesystem root for a nested cwd (a root-owned policy file governing every launch would
/// be a surprise, not a convenience).
///
/// The walk stays inside the invoking user's trust boundary (FW-BP8):
/// an ancestor directory the user does not own ends the walk before it is consulted (so a
/// world-writable `/tmp` or a root-owned `/srv` can never plant an implicit policy), and a
/// candidate file the user does not own is refused with a warning, fail-closed -- `--blueprint`
/// remains the explicit door for a file discovery will not trust. The `$HOME` boundary compares
/// symlink-resolved paths, so a symlinked home (macOS `/var` vs `/private/var`) cannot let the
/// walk escape above the real home directory.
pub fn find_default_blueprint(cwd: &Path, home: &str) -> Result<Option<PathBuf>> {
    find_default_blueprint_trusting(cwd, home, &user_controls)
}

/// The walk with the ownership check injected -- the same pure-function substitution the
/// constitution allows for the compiler's HostProfile, so the trust-boundary control flow is
/// testable without chown/root. Production goes through [`find_default_blueprint`].
fn find_default_blueprint_trusting(
    cwd: &Path,
    home: &str,
    trusted: &dyn Fn(&Path) -> bool,
) -> Result<Option<PathBuf>> {
    // Boundary comparisons happen in symlink-resolved coordinates; the returned candidate keeps
    // the caller's (as-given) coordinates, which the loader canonicalizes itself.
    let resolve = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let home = resolve(Path::new(home));
    for dir in cwd.ancestors() {
        if dir.parent().is_none() && cwd.parent().is_some() {
            break;
        }
        if !trusted(dir) {
            break;
        }
        let root_file = dir.join(DEFAULT_BLUEPRINT_NAME);
        let dotdir_file = dir.join(DOTDIR_BLUEPRINT);
        // `.formwork/` is one more directory level: it must be the user's too (FW-BP8).
        let dotdir_ok = || dotdir_file.parent().map(trusted).unwrap_or(false);
        let candidate = match (root_file.is_file(), dotdir_file.is_file()) {
            (true, true) => bail!(
                "both {} and {} exist; one project has one blueprint -- remove one, or pass \
                 --blueprint to choose",
                root_file.display(),
                dotdir_file.display()
            ),
            (true, false) => Some(root_file),
            (false, true) if dotdir_ok() => Some(dotdir_file),
            (false, true) => {
                tracing::warn!(
                    candidate = %dotdir_file.display(),
                    "ignoring a .formwork/ directory not owned by the invoking user (FW-BP8); \
                     pass --blueprint to use its blueprint explicitly"
                );
                return Ok(None);
            }
            (false, false) => None,
        };
        if let Some(candidate) = candidate {
            if trusted(&candidate) {
                return Ok(Some(candidate));
            }
            // Fail-closed, not fail-open-through-a-foreign-file: the nearer suspicious file also
            // shadows anything above it -- silently skipping to a farther match would leave the
            // planted file looking effective.
            tracing::warn!(
                candidate = %candidate.display(),
                "ignoring a blueprint not owned by the invoking user (FW-BP8); pass --blueprint \
                 to use it explicitly"
            );
            return Ok(None);
        }
        if resolve(dir) == home {
            break;
        }
    }
    Ok(None)
}

/// Implicit policy may come only from territory the invoking user controls (FW-BP8): the path is
/// owned by the effective uid. An unreadable path is untrusted (fail-closed).
fn user_controls(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        // SAFETY: geteuid is a trivial always-successful syscall with no memory effects.
        .map(|m| m.uid() == unsafe { libc::geteuid() })
        .unwrap_or(false)
}

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
    load_stack_with_provenance(path, sets, sugar, sigils).map(|(blueprint, _)| blueprint)
}

/// FEP-5 D10: the ambient universe is a property of the read mode, never a row. Under `closed`
/// (`mode = "unveil"`) a `/**` read row silently reopens everything the mode closed, so it is
/// refused, naming the layer it came from.
fn refuse_universe_row(layers: &[(RuleSource, BlueprintLayer)], merged: &Blueprint) -> Result<()> {
    if merged.fs.read_mode != formwork_blueprint::ReadMode::Closed {
        return Ok(());
    }
    let universe = PathPattern::parse("/**").expect("constant pattern");
    for (source, layer) in layers {
        let rows = layer
            .fs
            .reads
            .iter()
            .chain(layer.fs.writes.iter())
            .chain(layer.fs.writes_no_create.iter());
        if rows.clone().any(|p| *p == universe) {
            let origin = describe_source(source);
            bail!(
                "a `/**` grant from {origin} reopens the whole filesystem under the closed read \
                 mode (`mode = \"unveil\"`); the ambient universe is a read mode, not a rule -- \
                 use `mode = \"subtractive\"`, or grant the directories the session needs"
            );
        }
    }
    Ok(())
}

/// Same stack as [`load_stack`], but each layer keeps the [`RuleSource`] it came from so `explain`
/// (FW-FID6) can name which layer decides a path. The merged Blueprint is identical to
/// `load_stack`'s (FW-FID4); the [`Provenance`] is a side table.
pub fn load_stack_with_provenance(
    path: &Path,
    sets: &[String],
    sugar: BlueprintLayer,
    sigils: &Sigils,
) -> Result<(Blueprint, Provenance)> {
    let layers = load_layers(path, sets, sugar, sigils)?;
    let (blueprint, provenance) = merge_with_provenance(&layers);
    refuse_universe_row(&layers, &blueprint)?;
    note_host_rules_dropped_by_deny(&layers);
    validate_net(&layers, &blueprint)?;
    Ok((validate(blueprint, sigils.home)?, provenance))
}

/// A typo'd credential type would silently stay blocked -- fail-closed but intent-hiding, the same
/// trap as a typo'd gateway server name. Validate at the edge (parse, don't validate).
fn validate(blueprint: Blueprint, home: &str) -> Result<Blueprint> {
    let catalog = formwork_blueprint::Catalog::builtin();
    for entry in &blueprint.allow_credentials {
        // Inline bindings name credentials the Catalog does not know; `resolve_brokers` checks them.
        let t = match entry {
            formwork_blueprint::CredentialEntry::Inline(_) => continue,
            other => other.name(),
        };
        if !catalog.is_known_type(t) {
            let known: Vec<&str> = catalog
                .type_names()
                .chain(std::iter::once(formwork_blueprint::BACKSTOP))
                .collect();
            bail!("unknown credential type {t:?} in allow-credentials (known: {known:?})");
        }
    }
    // FW-CRED12: every brokered credential resolves to hosts an inspected rule covers.
    let resolved = catalog
        .resolve(home)
        .context("resolving the credential catalog")?;
    if let Err(errors) = formwork_blueprint::resolve_brokers(
        &blueprint.allow_credentials,
        &resolved,
        blueprint.net.host_table(),
    ) {
        bail!("allow-credentials:\n  {}", errors.join("\n  "));
    }
    for t in formwork_blueprint::doubly_named(&blueprint.allow_credentials) {
        tracing::info!(
            credential = %t,
            "named both bare and `broker:`; brokered wins, so the credential stays out of the session (FW-BP12)"
        );
    }
    Ok(blueprint)
}

/// Resolve the whole layer stack, each tagged with its origin (FW-FID6): the named file, its
/// `extends` bases (profiles), the discovered layer, and every `--set`/sugar CLI override.
fn load_layers(
    path: &Path,
    sets: &[String],
    sugar: BlueprintLayer,
    sigils: &Sigils,
) -> Result<Vec<(RuleSource, BlueprintLayer)>> {
    let mut layers = Vec::new();
    let mut walk = ExtendsWalk::default();
    resolve_file(
        path,
        RuleSource::File(path.display().to_string()),
        sigils,
        &mut walk,
        &mut layers,
    )?;
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
        resolve_layer(layer, RuleSource::Cli, cwd, sigils, &mut walk, &mut layers)?;
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
        layers.push((
            RuleSource::Discovered(discovered.display().to_string()),
            layer,
        ));
    }
    resolve_layer(sugar, RuleSource::Cli, cwd, sigils, &mut walk, &mut layers)?;
    Ok(layers)
}

/// What one stack load carries across its `extends` walk.
#[derive(Default)]
struct ExtendsWalk {
    /// The chain of files being resolved, for cycle detection (FW-BP3).
    visiting: Vec<PathBuf>,
    /// Bases the ownership notice has looked at, so one reached twice is named once (FW-BP32).
    noted: Vec<PathBuf>,
}

/// FW-BP32: a base the operator's blueprint names is loaded as written -- a file outside the
/// sandbox is the operator's to protect -- and one that another account can rewrite is named, so
/// a policy someone else can change is not in force unannounced.
fn note_base_others_can_change(base: &Path) {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(base) else {
        return;
    };
    // SAFETY: geteuid is a trivial always-successful syscall with no memory effects.
    let invoking = unsafe { libc::geteuid() };
    if let Some(why) = base_others_can_change(meta.uid(), meta.mode(), invoking) {
        tracing::warn!(
            base = %base.display(),
            "this `extends` base {why}; it is loaded as written, and whoever can write it can \
             change this session's policy (FW-BP32)"
        );
    }
}

/// Why a base owned by `owner` with permission bits `mode` is not the invoking user's alone to
/// change, if it is not. Root can change any file, so a root-owned base is not named for its
/// owner.
fn base_others_can_change(owner: u32, mode: u32, invoking: u32) -> Option<String> {
    let mut why = Vec::new();
    if owner != invoking && owner != 0 {
        why.push(format!(
            "is owned by uid {owner}, neither the invoking user nor root"
        ));
    }
    if mode & 0o022 != 0 {
        why.push(format!(
            "is group- or world-writable (mode {:04o})",
            mode & 0o7777
        ));
    }
    (!why.is_empty()).then(|| why.join(" and "))
}

/// Depth-first post-order: every base lands before the layer that extends it, so the extending
/// layer's contributions sit higher in the stack (FW-BP2 as amended).
fn resolve_file(
    path: &Path,
    source: RuleSource,
    sigils: &Sigils,
    walk: &mut ExtendsWalk,
    out: &mut Vec<(RuleSource, BlueprintLayer)>,
) -> Result<()> {
    let canon = std::fs::canonicalize(path)
        .with_context(|| format!("resolving blueprint {}", path.display()))?;
    if let Some(start) = walk.visiting.iter().position(|p| p == &canon) {
        let cycle: Vec<String> = walk.visiting[start..]
            .iter()
            .chain(std::iter::once(&canon))
            .map(|p| p.display().to_string())
            .collect();
        bail!("blueprint `extends` cycle: {}", cycle.join(" -> "));
    }
    if matches!(source, RuleSource::Profile(_)) && !walk.noted.contains(&canon) {
        note_base_others_can_change(&canon);
        walk.noted.push(canon.clone());
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

    walk.visiting.push(canon);
    resolve_layer(layer, source, &base_dir, sigils, walk, out)?;
    walk.visiting.pop();
    Ok(())
}

/// Resolve one layer's `extends` (relative to `base_dir`), pushing bases then the layer itself.
/// The layer carries `source`; its `extends` bases are profiles named by their path.
fn resolve_layer(
    mut layer: BlueprintLayer,
    source: RuleSource,
    base_dir: &Path,
    sigils: &Sigils,
    walk: &mut ExtendsWalk,
    out: &mut Vec<(RuleSource, BlueprintLayer)>,
) -> Result<()> {
    for base in std::mem::take(&mut layer.extends) {
        // `builtin:<name>` resolves against the compiled-in profiles, not the filesystem, so a
        // release binary can extend the shipped default with no repo checkout present.
        if let Some(name) = base.strip_prefix("builtin:") {
            let Some((_, text)) = BUILTIN_PROFILES.iter().find(|(n, _)| *n == name) else {
                let known: Vec<String> = BUILTIN_PROFILES
                    .iter()
                    .map(|(n, _)| format!("builtin:{n}"))
                    .collect();
                bail!("unknown builtin profile {base:?} (known: {known:?})");
            };
            let mut value: toml::Value = toml::from_str(text)
                .with_context(|| format!("parsing builtin profile {base:?}"))?;
            sigils.expand_value(&mut value);
            let builtin: BlueprintLayer = value
                .try_into()
                .with_context(|| format!("interpreting builtin profile {base:?}"))?;
            resolve_layer(
                builtin,
                RuleSource::Profile(base.clone()),
                base_dir,
                sigils,
                walk,
                out,
            )?;
            continue;
        }
        let base_path = if Path::new(&base).is_absolute() {
            PathBuf::from(&base)
        } else {
            base_dir.join(&base)
        };
        resolve_file(
            &base_path,
            RuleSource::Profile(base.clone()),
            sigils,
            walk,
            out,
        )
        .with_context(|| format!("resolving extends {base:?}"))?;
    }
    desugar_rules(&mut layer, sigils)?;
    out.push((source, layer));
    Ok(())
}

/// Desugar flat verb rules (FW-BP1) into `fs`/`exec`, then empty `rules`/`mode` -- the same edge
/// that resolves `extends`, so verbs never reach the pure merge or compiler. One `"<verb>:<path>"`
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
            bail!("exec verbs (`exec`/`readexec`) conflict with an explicit `exec = unrestricted` in the same layer");
        }
        None => Vec::new(),
    };
    for raw in std::mem::take(&mut layer.rules) {
        let (verb, target) = raw
            .split_once(':')
            .ok_or_else(|| anyhow!("rule {raw:?} is not \"<verb>:<target>\""))?;
        let target = target.trim();
        let atoms: Vec<&str> = verb.split(',').map(str::trim).collect();
        // The verb decides the axis (FW-BP15); `allow` and `deny` belong to both, and the
        // target's shape -- a path or a host -- decides it there (FW-BP13, FW-BP16).
        let egress_only = atoms
            .iter()
            .all(|a| formwork_blueprint::HTTP_ATOMS.contains(a));
        let both_axes = atoms == ["allow"] || atoms == ["deny"];
        let host_target = formwork_blueprint::target_is_host(target);
        if egress_only && !host_target {
            bail!("rule {raw:?}: `{verb}` is an egress verb and takes a host target, not a path");
        }
        if host_target && !egress_only && !both_axes {
            bail!(
                "rule {raw:?}: `{verb}` is not an egress verb (egress atoms: {}; on both axes: \
                 allow, deny); a path target starts with /, ~ or $CWD",
                formwork_blueprint::HTTP_ATOMS.join(", ")
            );
        }
        if egress_only || (both_axes && host_target) {
            let rule = formwork_blueprint::HostRule::parse(verb, target)
                .map_err(|e| anyhow!("rule {raw:?}: {e}"))?;
            layer.hosts.push(rule);
            continue;
        }
        let pat =
            PathPattern::parse(&sigils.expand(target)).with_context(|| format!("rule {raw:?}"))?;
        let fs = fs_atoms(&atoms).map_err(|e| anyhow!("rule {raw:?}: {e}"))?;
        if fs.deny {
            layer.fs.subtract.push(pat);
            continue;
        }
        // `write` implies read and includes create; `modify` is write without create (FW-CAP9),
        // subsumed when both are named.
        if fs.write {
            layer.fs.writes.push(pat.clone());
        } else if fs.modify {
            layer.fs.writes_no_create.push(pat.clone());
        } else if fs.read {
            layer.fs.reads.push(pat.clone());
        }
        if fs.exec {
            exec_paths.push(pat);
        }
    }
    if !exec_paths.is_empty() {
        layer.exec = Some(ExecPosture::Allowlist(exec_paths));
    }
    // FW-BP13: within one layer neither reading is safe to pick -- the host rule winning drops an
    // explicit deny, and the deny winning drops a rule the same author wrote beside it.
    if let (Some(rule), Some(formwork_blueprint::NetPosture::Deny)) =
        (layer.hosts.first(), &layer.net)
    {
        bail!(
            "the host rule `{rule}` and `net = \"deny\"` are set together (in one file, one \
             `--set` fragment, or the command-line flags) and contradict: a host rule sends \
             egress through the Gateway to the hosts listed, and `net = \"deny\"` allows none. \
             Remove one; a `net = \"deny\"` in a later layer drops the host rules below it"
        );
    }
    Ok(())
}

/// The filesystem verb atoms of one rule (FW-BP15), with the landed compound verbs as aliases.
#[derive(Default)]
struct FsAtoms {
    read: bool,
    write: bool,
    modify: bool,
    exec: bool,
    deny: bool,
}

fn fs_atoms(atoms: &[&str]) -> std::result::Result<FsAtoms, String> {
    let mut out = FsAtoms::default();
    for atom in atoms {
        match *atom {
            "read" | "readonly" => out.read = true,
            "write" | "readwrite" => out.write = true,
            "modify" => out.modify = true,
            "exec" => out.exec = true,
            "readexec" => {
                out.read = true;
                out.exec = true;
            }
            // `allow` is the ordinary full grant on each axis: read, write and create here, with
            // execute spelled `exec` (FW-ISO9, FEP-6 §9 j).
            "allow" => out.write = true,
            "deny" => out.deny = true,
            other => {
                return Err(format!(
                    "unknown rule verb {other:?} (filesystem atoms: read, write, modify, exec, \
                     and the compounds readonly, readwrite, readexec; on both axes: allow, deny; \
                     egress atoms: {})",
                    formwork_blueprint::HTTP_ATOMS.join(", ")
                ))
            }
        }
    }
    if out.deny && atoms.len() > 1 {
        return Err("`deny` cannot be combined with other atoms".to_string());
    }
    Ok(out)
}

/// FW-BP13/FW-EGR1: a port tier and host rules reach the network by different doors, so both in
/// one blueprint is refused; FW-BP14: one host, one grade. Every conflict is named.
fn validate_net(layers: &[(RuleSource, BlueprintLayer)], merged: &Blueprint) -> Result<()> {
    let Some(table) = merged.net.host_table() else {
        return Ok(());
    };
    if let Some((source, _)) = layers
        .iter()
        .rev()
        .find(|(_, l)| matches!(l.net, Some(formwork_blueprint::NetPosture::Ports(_))))
    {
        let first = table
            .rules
            .first()
            .map(|r| r.to_string())
            .unwrap_or_default();
        bail!(
            "host rules (e.g. `{first}`) and a direct port tier (`net = {{ ports = [...] }}` in \
             {}) cannot both apply: host rules route all egress through the Gateway, and the port \
             tier would bypass it. Remove the port tier",
            describe_source(source)
        );
    }
    if let Err(errors) = formwork_blueprint::validate_host_rules(&table.rules) {
        bail!("host rules conflict:\n  {}", errors.join("\n  "));
    }
    Ok(())
}

/// FW-BP2: a later layer's `net = "deny"` replaces the host-allowlist posture the layers below it
/// set, so their host rules stop applying. The operator asked for the deny; the rules it removes
/// are named here so that neither side of the override is silent.
fn note_host_rules_dropped_by_deny(layers: &[(RuleSource, BlueprintLayer)]) {
    let mut below: Vec<String> = Vec::new();
    for (source, layer) in layers {
        if matches!(layer.net, Some(formwork_blueprint::NetPosture::Deny)) && !below.is_empty() {
            tracing::info!(
                dropped = ?below,
                "net = \"deny\" from {} drops the host rules of the layers below it (FW-BP2)",
                describe_source(source)
            );
            below.clear();
        }
        below.extend(layer.hosts.iter().map(|rule| rule.to_string()));
    }
}

fn describe_source(source: &RuleSource) -> String {
    match source {
        RuleSource::BuiltIn => "the built-in baseline".to_string(),
        RuleSource::Profile(p) => format!("profile {p}"),
        RuleSource::File(p) => format!("blueprint {p}"),
        RuleSource::Cli => "a CLI override".to_string(),
        RuleSource::Discovered(p) => format!("discovered layer {p}"),
    }
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
    let mut layer: BlueprintLayer = value
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
    // FW-DISC12: learned host rules and channel lifts, each attributable. Only host rules may
    // sit in `rules` here -- a path rule would dodge the fs provenance check above.
    for rule in &layer.rules {
        let is_host = rule
            .split_once(':')
            .map(|(_, target)| formwork_blueprint::target_is_host(target))
            .unwrap_or(false);
        if !is_host {
            bail!(
                "discovered layer {} carries the rule {rule:?}, which is not a host rule; learned \
                 paths belong in [fs] with provenance (FW-DISC6)",
                path.display()
            );
        }
        if !layer
            .discovery
            .provenance
            .contains_key(&crate::learn::rule_key(rule))
        {
            bail!(
                "discovered layer {} adds the host rule {rule:?} without provenance; refusing an \
                 unattributable grant (FW-DISC6)",
                path.display()
            );
        }
    }
    if let Some(channels) = &layer.channels {
        if !channels.denied().is_empty() {
            bail!(
                "discovered layer {} denies channels; a learned layer only lifts",
                path.display()
            );
        }
        for channel in channels.allowed() {
            if !layer
                .discovery
                .provenance
                .contains_key(&crate::learn::channel_key(channel.name()))
            {
                bail!(
                    "discovered layer {} lifts the channel {:?} without provenance; refusing an \
                     unattributable lift (FW-DISC6)",
                    path.display(),
                    channel.name()
                );
            }
        }
    }
    desugar_rules(&mut layer, sigils)?;
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

/// The Catalog as this launching environment locates it: `~` against `home` (FW-CRED1), and each
/// set `env-dir-refs` variable's store denied where the variable puts it (FW-CRED32). The values
/// are read here, at the edge that reads `$HOME`, and the compiler takes the result. Every door
/// builds its floor through this, so `compile` and `explain` state the floor a `run` from the
/// same environment enforces.
pub fn resolve_catalog(home: &str) -> Result<ResolvedCatalog> {
    let mut catalog =
        ResolvedCatalog::builtin_for_home(home).context("resolving credential catalog")?;
    let cwd = std::env::current_dir().context("resolving cwd for relocated credential stores")?;
    relocate_stores(&mut catalog, &cwd, |var| std::env::var_os(var))?;
    Ok(catalog)
}

/// [`resolve_catalog`]'s relocation with the launching environment and directory passed in.
/// Excluded types are rebased too: the exclusion then lifts the relocated store with the type
/// (FW-CRED5), the way it lifts the `~` rows.
fn relocate_stores(
    catalog: &mut ResolvedCatalog,
    cwd: &Path,
    value_of: impl Fn(&str) -> Option<OsString>,
) -> Result<()> {
    for (type_name, entry) in catalog.types.iter_mut() {
        let vars: Vec<String> = entry.env_dir_refs.iter().map(|r| r.var.clone()).collect();
        for var in vars {
            let Some(raw) = value_of(&var) else {
                continue;
            };
            let value = reference_value(&var, type_name, &raw)?;
            // Empty is how a tool spells unset, so its store is where the `~` rows already are.
            if value.is_empty() {
                continue;
            }
            let root = render_reference(&var, type_name, value, cwd)?;
            entry.relocate(&var, &root).with_context(|| {
                format!(
                    "{var} (credential type {type_name}) does not name a deniable directory; \
                     refusing to start with that store undenied (FW-INV6)"
                )
            })?;
        }
    }
    Ok(())
}

/// FW-CRED3: an enforced env-points-to-file credential (`GOOGLE_APPLICATION_CREDENTIALS`,
/// `KUBECONFIG`) is stripped as a variable AND the file its value names is denied. The value
/// lives in the launcher's own environment -- impure -- so this is loader-edge code; the result
/// joins the blueprint's subtract set before enforcement-time canonicalization. A set value we
/// cannot faithfully render into a deny fails loud: leaving the referenced file readable while
/// claiming the type enforced would be a silent fail-open (FW-INV6). Each variable and the rows it
/// added are recorded on its type for the report (FW-CRED35).
pub fn env_file_ref_denies(
    catalog: &mut ResolvedCatalog,
    allow: &[String],
) -> Result<Vec<PathPattern>> {
    let cwd = std::env::current_dir().context("resolving cwd for env-file-ref denies")?;
    env_file_ref_patterns(catalog, allow, &cwd, |var| std::env::var_os(var))
}

/// [`env_file_ref_denies`] with the launching environment and directory passed in.
fn env_file_ref_patterns(
    catalog: &mut ResolvedCatalog,
    allow: &[String],
    cwd: &Path,
    value_of: impl Fn(&str) -> Option<OsString>,
) -> Result<Vec<PathPattern>> {
    let mut out = Vec::new();
    let enforced = catalog
        .types
        .iter_mut()
        .filter(|(name, _)| !allow.iter().any(|a| a == *name));
    for (type_name, entry) in enforced {
        for reference in entry.env_file_refs.clone() {
            let var = &reference.var;
            let Some(raw) = value_of(var) else {
                continue;
            };
            let value = reference_value(var, type_name, &raw)?;
            if value.is_empty() {
                continue;
            }
            // FW-CRED33: read whole, a list names one file that does not exist.
            let files: Vec<&str> = if reference.list {
                value.split(':').collect()
            } else {
                vec![value]
            };
            let mut rows = 0;
            for file in files.into_iter().filter(|f| !f.is_empty()) {
                let pattern = render_reference(var, type_name, file, cwd)?;
                if !out.contains(&pattern) {
                    out.push(pattern);
                    rows += 1;
                }
            }
            entry.references.push(ResolvedReference {
                var: var.clone(),
                rows,
            });
        }
    }
    Ok(out)
}

/// A set reference variable's value as text. FW-CRED34: a value that is not UTF-8 cannot be
/// written into a rule that matches it.
fn reference_value<'a>(var: &str, type_name: &str, raw: &'a std::ffi::OsStr) -> Result<&'a str> {
    raw.to_str().ok_or_else(|| {
        anyhow!(
            "{var} (credential type {type_name}) holds a non-UTF-8 path; refusing to enforce a \
             deny that might silently not match (FW-INV6)"
        )
    })
}

/// The one file or directory a reference variable names, as the pattern that names it: resolved
/// against the launch directory when relative, `..` folded as the kernel will fold it.
fn render_reference(var: &str, type_name: &str, location: &str, cwd: &Path) -> Result<PathPattern> {
    let absolute = if Path::new(location).is_absolute() {
        PathBuf::from(location)
    } else {
        cwd.join(location)
    };
    let absolute = fold_parent_components(&absolute).with_context(|| {
        format!(
            "{var} (credential type {type_name}) names a path whose `..` cannot be resolved; \
             refusing to start with that location undenied (FW-INV6)"
        )
    })?;
    let rendered = absolute
        .to_str()
        .ok_or_else(|| anyhow!("{var} resolves to a non-UTF-8 path; refusing (FW-INV6)"))?;
    let pattern = PathPattern::parse(rendered).with_context(|| {
        format!(
            "{var} (credential type {type_name}) does not name a deniable path; refusing to \
             start with that location undenied (FW-INV6)"
        )
    })?;
    // FW-CRED34: the pattern grammar reads a `**` component as a wildcard, so the deny would not
    // be the location named -- and an any-depth row is one Landlock withholds.
    if pattern.is_subtree() || pattern.is_any_depth() {
        bail!(
            "{var} (credential type {type_name}) names a path with a `**` component, which a \
             path pattern cannot name as one file or directory; refusing to start with that \
             location undenied (FW-INV6)"
        );
    }
    Ok(pattern)
}

/// Fold each `..` the way the kernel will when the workload opens the path: against the directory
/// the path has reached by then, symlinks resolved. Folded lexically, as [`PathPattern::parse`]
/// does, `a/link/../f` would deny `a/f` while the file opened is the one beside the link's target.
fn fold_parent_components(path: &Path) -> std::io::Result<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        if component != std::path::Component::ParentDir {
            out.push(component);
            continue;
        }
        match std::fs::canonicalize(&out) {
            Ok(real) => out = real,
            // Nothing is there to be a symlink, so the lexical parent is the parent.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        out.pop();
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
            mode: Some(Mode::Unveil),
            rules: vec![
                "readonly:/usr/**".into(),
                "readwrite:~/project/**".into(),
                "modify:~/project/build".into(),
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
    fn verb_atoms_compose_and_host_rules_desugar_by_target_shape() {
        let sigils = Sigils::new("/home/x", "/work");
        let mut layer = BlueprintLayer {
            rules: vec![
                "read,write:/a/**".into(),
                "read,exec:/b/**".into(),
                "write,modify:/c".into(),
                "tunnel:api.anthropic.com".into(),
                "get,post:api.github.com/repos/acme/**".into(),
                "allow:registry.npmjs.org".into(),
                "deny:telemetry.example.com".into(),
                "deny:~/.ssh".into(),
                "allow:$CWD/out/**".into(),
            ],
            ..Default::default()
        };
        desugar_rules(&mut layer, &sigils).unwrap();
        // `allow` is the full grant on each axis, decided by the target's shape (FW-BP16): read,
        // write and create on a path, with execute spelled `exec`.
        assert_eq!(
            layer.fs.writes,
            vec![pp("/a/**"), pp("/c"), pp("/work/out/**")]
        );
        assert_eq!(layer.fs.reads, vec![pp("/b/**")]);
        assert_eq!(layer.fs.subtract, vec![pp("/home/x/.ssh")]);
        assert_eq!(layer.exec, Some(ExecPosture::Allowlist(vec![pp("/b/**")])));
        let hosts: Vec<String> = layer.hosts.iter().map(|h| h.to_string()).collect();
        assert_eq!(
            hosts,
            vec![
                "tunnel:api.anthropic.com",
                "get,post:api.github.com/repos/acme/**",
                "allow:registry.npmjs.org",
                "deny:telemetry.example.com"
            ]
        );
        for bad in [
            "read,deny:/x",
            // FEP-6 §9 (j): the FEP-5 verbs are not aliases.
            "https:api.anthropic.com",
            "any:api.github.com",
            // FW-BP16: a relative path typed by mistake is not a host named `build`.
            "allow:build/**",
            "get:/etc/passwd",
        ] {
            let mut layer = BlueprintLayer {
                rules: vec![bad.into()],
                ..Default::default()
            };
            assert!(desugar_rules(&mut layer, &sigils).is_err(), "{bad}");
        }
    }

    #[test]
    fn host_rules_refuse_a_port_tier_and_a_second_grade() {
        let dir = Scratch::new("host-rules");
        std::fs::write(
            dir.path().join("bp.toml"),
            "net = { ports = [443] }\nrules = [\"allow:api.anthropic.com\"]\n",
        )
        .unwrap();
        let msg = format!(
            "{:#}",
            load(&dir.path().join("bp.toml"), "/home/x").unwrap_err()
        );
        assert!(msg.contains("port tier"), "{msg}");
        std::fs::write(
            dir.path().join("two.toml"),
            "rules = [\"tunnel:*.github.com\", \"post:api.github.com/x\"]\n",
        )
        .unwrap();
        let msg = format!(
            "{:#}",
            load(&dir.path().join("two.toml"), "/home/x").unwrap_err()
        );
        assert!(msg.contains("two grades"), "{msg}");
        std::fs::write(
            dir.path().join("ok.toml"),
            "rules = [\"tunnel:api.anthropic.com\", \"get:api.github.com\"]\n",
        )
        .unwrap();
        let bp = load(&dir.path().join("ok.toml"), "/home/x").unwrap();
        assert_eq!(bp.net.host_table().unwrap().rules.len(), 2);
    }

    #[test]
    fn flat_rules_equal_nested_fs_after_load() {
        // FW-BP1: flat verb rules and the nested `[fs]` table are one model.
        let flat = "net = \"deny\"\nmode = \"unveil\"\n\
                    rules = [\"readonly:/usr/**\", \"readwrite:/work/p/**\", \"deny:/work/p/secret\"]\n";
        let nested = "net = \"deny\"\n[fs]\nread-mode = \"closed\"\n\
                      reads = [\"/usr/**\"]\nwrites = [\"/work/p/**\"]\nsubtract = [\"/work/p/secret\"]\n";
        let sigils = Sigils::new("/home/x", "/work");
        let load = |src: &str| {
            let layer: BlueprintLayer = toml::from_str(src).unwrap();
            let mut out = Vec::new();
            resolve_layer(
                layer,
                RuleSource::Cli,
                Path::new("/work"),
                &sigils,
                &mut ExtendsWalk::default(),
                &mut out,
            )
            .unwrap();
            let plain: Vec<BlueprintLayer> = out.into_iter().map(|(_, l)| l).collect();
            formwork_blueprint::merge(&plain)
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
            formwork_blueprint::Visibility::allow_exact(["~weird_but_left_alone"])
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

    /// FW-BP2 on the net axis: host rules are how a layer sets the host-allowlist posture, so a
    /// `net = "deny"` in any later layer -- a leaf file, a `--set` fragment, the `--net` flag --
    /// replaces them, and host rules in a layer later still apply alone.
    #[test]
    fn fw_bp2_a_later_net_deny_drops_the_host_rules_below_it() {
        let dir = Scratch::new("net-deny");
        let base = dir.path().join("base.toml");
        std::fs::write(
            &base,
            "extends = [\"builtin:default\"]\n\
             rules = [\"readwrite:/work/**\", \"allow:example.com\"]\n",
        )
        .unwrap();
        let leaf = dir.path().join("leaf.toml");
        std::fs::write(&leaf, "extends = [\"base.toml\"]\nnet = \"deny\"\n").unwrap();
        let sigils = Sigils::new("/home/x", "/work");
        let deny_flag = || BlueprintLayer {
            net: Some(formwork_blueprint::NetPosture::Deny),
            ..Default::default()
        };
        let set = ["net = \"deny\"".to_string()];
        let stack = |file: &Path, sets: &[String], sugar: BlueprintLayer| {
            load_stack(file, sets, sugar, &sigils).unwrap().net
        };

        let control = stack(&base, &[], BlueprintLayer::default());
        assert_eq!(control.host_table().unwrap().rules.len(), 1);
        for denied in [
            stack(&leaf, &[], BlueprintLayer::default()),
            stack(&base, &set, BlueprintLayer::default()),
            stack(&base, &[], deny_flag()),
        ] {
            assert_eq!(denied, formwork_blueprint::NetPosture::Deny);
        }

        let later_rule = BlueprintLayer {
            rules: vec!["allow:other.example".into()],
            ..Default::default()
        };
        let rules: Vec<String> = stack(&base, &set, later_rule)
            .host_table()
            .unwrap()
            .rules
            .iter()
            .map(|r| r.to_string())
            .collect();
        assert_eq!(rules, ["allow:other.example"]);
    }

    /// FW-BP13: a host rule and `net = "deny"` in one layer is refused, not resolved either way.
    #[test]
    fn fw_bp13_a_host_rule_beside_net_deny_in_one_layer_is_refused() {
        let dir = Scratch::new("net-deny-same-layer");
        let file = dir.path().join("bp.toml");
        std::fs::write(&file, "net = \"deny\"\nrules = [\"allow:example.com\"]\n").unwrap();
        let msg = format!("{:#}", load(&file, "/home/x").unwrap_err());
        assert!(
            msg.contains("allow:example.com") && msg.contains("net = \"deny\""),
            "{msg}"
        );

        std::fs::write(&file, "rules = [\"readwrite:/work/**\"]\n").unwrap();
        let flags = BlueprintLayer {
            net: Some(formwork_blueprint::NetPosture::Deny),
            rules: vec!["allow:example.com".into()],
            ..Default::default()
        };
        assert!(load_stack(&file, &[], flags, &Sigils::new("/home/x", "/work")).is_err());
    }

    /// The env-file-ref denies for one set variable, launched from `/work`.
    fn file_ref_denies(var: &str, value: &[u8], allow: &[String]) -> Result<Vec<String>> {
        use std::os::unix::ffi::OsStringExt;
        let mut catalog = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        let value = OsString::from_vec(value.to_vec());
        env_file_ref_patterns(&mut catalog, allow, Path::new("/work"), |name| {
            (name == var).then(|| value.clone())
        })
        .map(|patterns| patterns.iter().map(PathPattern::canonical).collect())
    }

    #[test]
    fn fw_cred33_each_file_of_a_list_valued_reference_is_denied() {
        let kube = |value: &str| file_ref_denies("KUBECONFIG", value.as_bytes(), &[]).unwrap();
        assert_eq!(kube("/k/a.yaml"), ["/k/a.yaml"]);
        assert_eq!(kube("/k/a.yaml:/k/b.yaml"), ["/k/a.yaml", "/k/b.yaml"]);
        // Empty elements name nothing; a relative one resolves against the launch directory.
        assert_eq!(
            kube(":/k/a.yaml::rel/c.yaml:/k/b.yaml:"),
            ["/k/a.yaml", "/work/rel/c.yaml", "/k/b.yaml"]
        );
        assert!(kube("").is_empty() && kube(":").is_empty());
        // A reference the Catalog does not mark as a list keeps its colon: it is one path.
        assert_eq!(
            file_ref_denies("GOOGLE_APPLICATION_CREDENTIALS", b"/k/a:b.json", &[]).unwrap(),
            ["/k/a:b.json"]
        );
        // An excluded type's reference is the session's to read (FW-CRED5).
        assert!(
            file_ref_denies("KUBECONFIG", b"/k/a.yaml:/k/b.yaml", &["kube".to_string()])
                .unwrap()
                .is_empty()
        );
    }

    /// The deny names the file the kernel will open: a `..` is folded against the directory the
    /// path has reached, so one that follows a symlink leaves through the link's target.
    #[test]
    fn fw_cred3_a_parent_component_is_folded_as_the_kernel_resolves_it() {
        let dir = Scratch::new("ref-dotdot");
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("elsewhere/sub")).unwrap();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::os::unix::fs::symlink(root.join("elsewhere/sub"), root.join("keys/link")).unwrap();
        let shown = |p: &str| format!("{}/{p}", root.display());
        let denies = |value: String| {
            file_ref_denies("GOOGLE_APPLICATION_CREDENTIALS", value.as_bytes(), &[]).unwrap()
        };
        assert_eq!(
            denies(shown("keys/link/../sa.json")),
            [shown("elsewhere/sa.json")]
        );
        // Without a symlink, and where nothing exists yet, the lexical parent is the parent;
        // above the root there is only the root.
        assert_eq!(denies(shown("keys/../sa.json")), [shown("sa.json")]);
        assert_eq!(
            denies(shown("absent/dir/../sa.json")),
            [shown("absent/sa.json")]
        );
        assert_eq!(denies("/../../sa.json".to_string()), ["/sa.json"]);
    }

    #[test]
    fn fw_cred34_an_unrenderable_reference_is_refused_naming_the_variable() {
        let cases: &[(&str, &[u8])] = &[
            ("GOOGLE_APPLICATION_CREDENTIALS", b"/k/\xff/sa.json"),
            ("KUBECONFIG", b"/k/a.yaml:/k/\xff.yaml"),
            // A `**` component is a wildcard to the pattern grammar, not a file name.
            ("KUBECONFIG", b"/k/a.yaml:/k/**"),
            ("KUBECONFIG", b"/k/**/b.yaml"),
            ("GOOGLE_APPLICATION_CREDENTIALS", b"/**"),
        ];
        for (var, value) in cases {
            let refusal = file_ref_denies(var, value, &[]).unwrap_err();
            let msg = format!("{refusal:#}");
            assert!(
                msg.contains(var),
                "{var}={:?}: {msg}",
                String::from_utf8_lossy(value)
            );
        }
    }

    /// The Catalog for `/home/x`, launched from `/work`, with the given variables set.
    fn relocated(env: &[(&str, &[u8])]) -> Result<ResolvedCatalog> {
        use std::os::unix::ffi::OsStringExt;
        let mut catalog = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        relocate_stores(&mut catalog, Path::new("/work"), |name| {
            env.iter()
                .find(|(var, _)| *var == name)
                .map(|(_, value)| OsString::from_vec(value.to_vec()))
        })?;
        Ok(catalog)
    }

    fn rows_beyond_home(catalog: &ResolvedCatalog, allow: &[String]) -> Vec<String> {
        let home = ResolvedCatalog::builtin_for_home("/home/x")
            .unwrap()
            .denied_paths(&[]);
        catalog
            .denied_paths(allow)
            .iter()
            .filter(|row| !home.contains(row))
            .map(PathPattern::canonical)
            .collect()
    }

    #[test]
    fn fw_cred32_a_set_store_variable_rebases_its_types_rows() {
        assert!(rows_beyond_home(&relocated(&[]).unwrap(), &[]).is_empty());
        let catalog = relocated(&[
            ("GNUPGHOME", b"/secure/gnupg/"),
            // A relative value is the launch directory's, as a relative file reference is.
            ("DOCKER_CONFIG", b"ci/docker"),
            ("CARGO_HOME", b"/opt/rust/../cargo"),
            // Empty is unset to the tools that read these.
            ("CODEX_HOME", b""),
            ("XDG_CONFIG_HOME", b"/xdg"),
        ])
        .unwrap();
        assert_eq!(
            rows_beyond_home(&catalog, &[]),
            [
                "/xdg/google-chrome/**",
                "/opt/cargo/credentials.toml",
                "/opt/cargo/credentials",
                "/work/ci/docker/**",
                "/xdg/gh/**",
                "/secure/gnupg/**",
            ]
        );
        // An excluded type's relocated store is lifted with it, and only it (FW-CRED5).
        assert_eq!(
            rows_beyond_home(&catalog, &["gpg".to_string(), "docker".to_string()]),
            [
                "/xdg/google-chrome/**",
                "/opt/cargo/credentials.toml",
                "/opt/cargo/credentials",
                "/xdg/gh/**",
            ]
        );
        assert!(catalog.types["codex"].references.is_empty());
    }

    /// A relocated store sits wherever the operator put it, so its `..` is folded as a file
    /// reference's is: against the directory reached, symlinks resolved.
    #[test]
    fn fw_cred32_a_store_variable_is_folded_as_the_kernel_resolves_it() {
        let dir = Scratch::new("store-dotdot");
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("elsewhere/sub")).unwrap();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::os::unix::fs::symlink(root.join("elsewhere/sub"), root.join("keys/link")).unwrap();
        let value = format!("{}/keys/link/../gnupg", root.display());
        let catalog = relocated(&[("GNUPGHOME", value.as_bytes())]).unwrap();
        assert_eq!(
            rows_beyond_home(&catalog, &[]),
            [format!("{}/elsewhere/gnupg/**", root.display())]
        );
    }

    #[test]
    fn fw_cred34_an_unrenderable_store_variable_is_refused_naming_the_variable() {
        let cases: &[(&str, &[u8])] = &[
            ("GNUPGHOME", b"/secure/\xff/gnupg"),
            ("XDG_CONFIG_HOME", b"\xff"),
            // A `**` component would make the rebased rows a different set of paths.
            ("DOCKER_CONFIG", b"/srv/**"),
            ("CARGO_HOME", b"/srv/**/cargo"),
            ("GH_CONFIG_DIR", b"**/gh"),
        ];
        for (var, value) in cases {
            let refusal = relocated(&[(*var, *value)]).unwrap_err();
            let msg = format!("{refusal:#}");
            assert!(
                msg.contains(var) && msg.contains("refusing"),
                "{var}={:?}: {msg}",
                String::from_utf8_lossy(value)
            );
        }
    }

    #[test]
    fn fw_cred35_each_set_reference_is_recorded_with_the_rows_it_added() {
        use std::os::unix::ffi::OsStringExt;
        let env: &[(&str, &[u8])] = &[
            ("KUBECONFIG", b"/k/a.yaml::/k/b.yaml:/k/a.yaml"),
            ("AWS_CONFIG_FILE", b"/srv/aws/config"),
            ("AWS_SHARED_CREDENTIALS_FILE", b"/srv/aws/config"),
            ("NETRC", b""),
            ("GOOGLE_APPLICATION_CREDENTIALS", b"/k/sa.json"),
            ("CLOUDSDK_CONFIG", b"/srv/gcloud"),
        ];
        let value_of = |name: &str| {
            env.iter()
                .find(|(var, _)| *var == name)
                .map(|(_, value)| OsString::from_vec(value.to_vec()))
        };
        let mut catalog = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        relocate_stores(&mut catalog, Path::new("/work"), value_of).unwrap();
        let allow = ["kube".to_string()];
        let denies =
            env_file_ref_patterns(&mut catalog, &allow, Path::new("/work"), value_of).unwrap();
        let recorded = |name: &str| -> Vec<(&str, usize)> {
            catalog.types[name]
                .references
                .iter()
                .map(|r| (r.var.as_str(), r.rows))
                .collect()
        };
        // Both kinds land on the type, in the order they were resolved; a file two variables
        // name is one row.
        assert_eq!(
            recorded("gcp"),
            [
                ("CLOUDSDK_CONFIG", 1),
                ("GOOGLE_APPLICATION_CREDENTIALS", 1)
            ]
        );
        assert_eq!(
            recorded("aws"),
            [("AWS_SHARED_CREDENTIALS_FILE", 1), ("AWS_CONFIG_FILE", 0)]
        );
        // An empty value names nothing, and an excluded type's reference adds no deny.
        assert!(recorded("netrc").is_empty() && recorded("kube").is_empty());
        assert_eq!(denies.len(), 2);

        let mut catalog = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        env_file_ref_patterns(&mut catalog, &[], Path::new("/work"), value_of).unwrap();
        assert_eq!(
            catalog.types["kube"].references,
            [ResolvedReference {
                var: "KUBECONFIG".to_string(),
                rows: 2
            }]
        );
    }

    /// FW-BP32's test of a base: owned by the invoking user or root, and writable by its owner
    /// alone. Either failing names the base; both failing is still one reason line.
    #[test]
    fn fw_bp32_a_base_others_can_change_is_named_and_one_that_is_private_is_not() {
        const INVOKING: u32 = 1000;
        for (owner, mode) in [(INVOKING, 0o100644), (0, 0o100644), (INVOKING, 0o100600)] {
            assert_eq!(base_others_can_change(owner, mode, INVOKING), None);
        }
        // Root invoking: its own files are both the invoking user's and root's.
        assert_eq!(base_others_can_change(0, 0o100644, 0), None);

        let other = base_others_can_change(1001, 0o100644, INVOKING).unwrap();
        assert!(other.contains("uid 1001"), "{other}");
        for mode in [0o100664, 0o100646, 0o100666] {
            let writable = base_others_can_change(INVOKING, mode, INVOKING).unwrap();
            assert!(writable.contains("group- or world-writable"), "{writable}");
            assert!(
                base_others_can_change(0, mode, INVOKING).is_some(),
                "a root-owned base others can write is still named"
            );
        }
        let both = base_others_can_change(1001, 0o100666, INVOKING).unwrap();
        assert!(
            both.contains("uid 1001") && both.contains("mode 0666"),
            "{both}"
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

    #[test]
    fn builtin_default_profile_resolves_without_a_checkout() {
        let dir = Scratch::new("builtin");
        std::fs::write(
            dir.path().join("bp.toml"),
            "extends = [\"builtin:default\"]\nrules = [\"readwrite:/work/proj/**\"]\n",
        )
        .unwrap();
        let bp = load(&dir.path().join("bp.toml"), "/home/x").unwrap();
        // The embedded default's posture and tamper-vector holes come through...
        assert_eq!(bp.net, formwork_blueprint::NetPosture::Deny);
        assert_eq!(
            bp.fs.read_mode,
            formwork_blueprint::ReadMode::AmbientMinusSubtract
        );
        assert!(bp
            .fs
            .write_subtract
            .contains(&PathPattern::parse("**/.git/hooks/**").unwrap()));
        // FW-TRA7 also names shell rc files and the agent-config settings that carry hooks as tamper vectors.
        assert!(bp
            .fs
            .write_subtract
            .contains(&PathPattern::parse("**/.bashrc").unwrap()));
        assert!(bp
            .fs
            .write_subtract
            .contains(&PathPattern::parse("**/.claude/settings.json").unwrap()));
        // ...and the extending file's grant layers on top.
        assert!(bp
            .fs
            .writes
            .contains(&PathPattern::parse("/work/proj/**").unwrap()));
    }

    #[test]
    fn unknown_builtin_profile_fails_loud_naming_the_known_set() {
        let dir = Scratch::new("builtin-bad");
        std::fs::write(
            dir.path().join("bp.toml"),
            "extends = [\"builtin:bogus\"]\n",
        )
        .unwrap();
        let err = load(&dir.path().join("bp.toml"), "/home/x").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("builtin:bogus") && msg.contains("builtin:default"),
            "{msg}"
        );
    }

    #[test]
    fn default_blueprint_discovery_walks_up_and_stops_at_home() {
        let dir = Scratch::new("discover");
        let home = dir.path().join("home");
        let project = home.join("work").join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let home_str = home.to_str().unwrap();

        // Nothing anywhere: no discovery.
        assert_eq!(find_default_blueprint(&project, home_str).unwrap(), None);

        // A file in a parent (still under $HOME) is found from a nested cwd.
        std::fs::write(home.join("work").join(DEFAULT_BLUEPRINT_NAME), "").unwrap();
        assert_eq!(
            find_default_blueprint(&project, home_str).unwrap(),
            Some(home.join("work").join(DEFAULT_BLUEPRINT_NAME))
        );

        // The cwd's own file wins over a parent's.
        std::fs::write(project.join(DEFAULT_BLUEPRINT_NAME), "").unwrap();
        assert_eq!(
            find_default_blueprint(&project, home_str).unwrap(),
            Some(project.join(DEFAULT_BLUEPRINT_NAME))
        );

        // The walk never escapes above $HOME: a file beside (not under) home is not picked up
        // from a cwd inside home.
        std::fs::write(dir.path().join(DEFAULT_BLUEPRINT_NAME), "").unwrap();
        std::fs::remove_file(project.join(DEFAULT_BLUEPRINT_NAME)).unwrap();
        std::fs::remove_file(home.join("work").join(DEFAULT_BLUEPRINT_NAME)).unwrap();
        assert_eq!(find_default_blueprint(&project, home_str).unwrap(), None);

        // A cwd outside $HOME still walks its own ancestors (a project need not live under
        // home), just never as far as the filesystem root.
        let outside = dir.path().join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        assert_eq!(
            find_default_blueprint(&outside, home_str).unwrap(),
            Some(dir.path().join(DEFAULT_BLUEPRINT_NAME))
        );
    }

    /// FEP-5 D3: `.formwork/blueprint.toml` is discovered like FORMWORK.toml, and a directory
    /// holding both is a loud error rather than a silent pick.
    #[test]
    fn dotdir_blueprint_is_discovered_and_ambiguity_fails_loud() {
        let dir = Scratch::new("discover-dotdir");
        let home = dir.path().join("home");
        let project = home.join("proj");
        std::fs::create_dir_all(project.join(".formwork")).unwrap();
        let home_str = home.to_str().unwrap();
        let dotdir = project.join(DOTDIR_BLUEPRINT);
        std::fs::write(&dotdir, "").unwrap();
        assert_eq!(
            find_default_blueprint(&project, home_str).unwrap(),
            Some(dotdir.clone())
        );
        std::fs::write(project.join(DEFAULT_BLUEPRINT_NAME), "").unwrap();
        let err = find_default_blueprint(&project, home_str).unwrap_err();
        assert!(format!("{err}").contains("both"), "{err}");
    }

    /// FEP-5 D10: `/**` under the closed read mode is refused, naming the layer; the same row is
    /// harmless under the ambient mode.
    #[test]
    fn universe_row_under_closed_mode_is_refused_naming_the_layer() {
        let dir = Scratch::new("universe-row");
        std::fs::write(
            dir.path().join("base.toml"),
            "[fs]\nread-mode = \"ambient-minus-subtract\"\nreads = [\"/**\"]\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("bp.toml"),
            "extends = [\"base.toml\"]\nmode = \"unveil\"\n",
        )
        .unwrap();
        let err = load(&dir.path().join("bp.toml"), "/home/x").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("base.toml") && msg.contains("/**"), "{msg}");
        assert!(load(&dir.path().join("base.toml"), "/home/x").is_ok());
        // The builtin default no longer carries the row, so extending it in unveil mode is fine.
        std::fs::write(
            dir.path().join("strict.toml"),
            "extends = [\"builtin:default\"]\nmode = \"unveil\"\n",
        )
        .unwrap();
        let bp = load(&dir.path().join("strict.toml"), "/home/x").unwrap();
        assert!(bp.fs.reads.is_empty(), "{:?}", bp.fs.reads);
    }

    /// FW-BP8: the walk ends at the first ancestor the invoking user does not control, BEFORE
    /// consulting it -- a policy file planted in a world-writable or foreign-owned ancestor
    /// (`/tmp`, a root-owned `/srv`) never governs a session implicitly. Ownership is injected
    /// (chown needs root); the real check is `user_controls`.
    #[test]
    fn discovery_stops_at_the_first_untrusted_ancestor() {
        let dir = Scratch::new("discover-trust");
        let home = dir.path().join("home");
        let shared = dir.path().join("shared"); // plays the foreign-owned ancestor
        let project = shared.join("proj");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(shared.join(DEFAULT_BLUEPRINT_NAME), "").unwrap();
        let home_str = home.to_str().unwrap();
        let foreign = shared.clone();
        let trusted = move |p: &Path| p != foreign;

        // The planted file sits in the untrusted ancestor: never consulted.
        assert_eq!(
            find_default_blueprint_trusting(&project, home_str, &trusted).unwrap(),
            None
        );

        // The user's own launch directory still works below the same untrusted ancestor.
        std::fs::write(project.join(DEFAULT_BLUEPRINT_NAME), "").unwrap();
        assert_eq!(
            find_default_blueprint_trusting(&project, home_str, &trusted).unwrap(),
            Some(project.join(DEFAULT_BLUEPRINT_NAME))
        );
    }

    /// FW-BP8: a candidate file the user does not own -- inside territory they DO own -- is
    /// refused fail-closed rather than governing the session, and does not fall through to a
    /// farther (owned) match it shadows.
    #[test]
    fn discovery_refuses_a_foreign_owned_candidate_file() {
        let dir = Scratch::new("discover-foreign-file");
        let home = dir.path().join("home");
        let project = home.join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let planted = project.join(DEFAULT_BLUEPRINT_NAME);
        std::fs::write(&planted, "").unwrap();
        std::fs::write(home.join(DEFAULT_BLUEPRINT_NAME), "").unwrap();
        let home_str = home.to_str().unwrap();
        let foreign = planted.clone();
        let trusted = move |p: &Path| p != foreign;

        assert_eq!(
            find_default_blueprint_trusting(&project, home_str, &trusted).unwrap(),
            None,
            "a refused candidate must not fall through to the file it shadows"
        );
    }

    /// FW-BP8: the $HOME stop compares symlink-resolved paths. With `$HOME` set to a symlink
    /// (macOS `/var/root` -> `/private/var/root`), a textual comparison never matches the
    /// resolved cwd ancestors, and the walk would escape above the real home -- where a planted
    /// file waits.
    #[test]
    fn discovery_home_stop_holds_through_a_symlinked_home() {
        let dir = Scratch::new("discover-symhome");
        let real_home = dir.path().join("real-home");
        let project = real_home.join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let link_home = dir.path().join("link-home");
        std::os::unix::fs::symlink(&real_home, &link_home).unwrap();
        // The escape target: a file ABOVE home, inside territory the user owns.
        std::fs::write(dir.path().join(DEFAULT_BLUEPRINT_NAME), "").unwrap();

        assert_eq!(
            find_default_blueprint(&project, link_home.to_str().unwrap()).unwrap(),
            None,
            "the walk escaped above a symlinked $HOME"
        );
    }
}
