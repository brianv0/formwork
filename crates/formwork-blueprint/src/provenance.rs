//! Per-rule provenance and `explain` (FW-FID6): for a path, which rule decides read/write/exec
//! access under the deny-terminal model (FW-CAP8), and which layer that rule came from. The
//! provenance is a side table alongside the merged Blueprint, so the compiler and its determinism
//! are untouched.

use std::path::Path;

use serde::Serialize;

use crate::layer::{merge, BlueprintLayer};
use crate::{Blueprint, ExecPosture, PathPattern, ReadMode};

/// Where an effective rule came from (FW-FID6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "origin", content = "name", rename_all = "kebab-case")]
pub enum RuleSource {
    /// The fail-closed baseline and the compiled-in credential-catalog floor.
    BuiltIn,
    /// An `extends` base (its file path).
    Profile(String),
    /// The named blueprint file.
    File(String),
    /// A `--rule` / `--set` / sugar override.
    Cli,
    /// The discovered layer.
    Discovered(String),
}

/// Effective fs/exec patterns tagged with the layer they came from. Kept raw (not canonicalized) so
/// `explain` can name the exact rule and origin that decides a path.
#[derive(Clone, Debug, Default)]
pub struct Provenance {
    reads: Vec<(PathPattern, RuleSource)>,
    writes: Vec<(PathPattern, RuleSource)>,
    writes_no_create: Vec<(PathPattern, RuleSource)>,
    subtract: Vec<(PathPattern, RuleSource)>,
    write_subtract: Vec<(PathPattern, RuleSource)>,
    /// The winning exec allow-list (empty when exec is unrestricted). Exec is a last-set-wins
    /// posture, not a union of path sets, so a later layer's allow-list replaces an earlier one.
    exec: Vec<(PathPattern, RuleSource)>,
}

/// Like [`merge`], but also records, per fs/exec pattern, the layer it came from. The returned
/// Blueprint is identical to `merge(...)` (FW-FID4); provenance is a side table for `explain` only.
pub fn merge_with_provenance(layers: &[(RuleSource, BlueprintLayer)]) -> (Blueprint, Provenance) {
    let plain: Vec<BlueprintLayer> = layers.iter().map(|(_, l)| l.clone()).collect();
    let blueprint = merge(&plain);
    let mut p = Provenance::default();
    for (src, layer) in layers {
        let tag = |v: &[PathPattern]| -> Vec<(PathPattern, RuleSource)> {
            v.iter().map(|pat| (pat.clone(), src.clone())).collect()
        };
        p.reads.extend(tag(&layer.fs.reads));
        p.writes.extend(tag(&layer.fs.writes));
        p.writes_no_create.extend(tag(&layer.fs.writes_no_create));
        p.subtract.extend(tag(&layer.fs.subtract));
        p.write_subtract.extend(tag(&layer.fs.write_subtract));
        // Exec is last-set-wins (mirrors `merge`): a layer's allow-list replaces the running one;
        // an explicit `unrestricted` clears it, matching the merged posture the Blueprint carries.
        match &layer.exec {
            Some(ExecPosture::Allowlist(paths)) => p.exec = tag(paths),
            Some(ExecPosture::Unrestricted) => p.exec.clear(),
            None => {}
        }
    }
    (blueprint, p)
}

/// A read, write, or exec verdict for a path (FW-FID6), naming the winning rule and its origin.
#[derive(Debug, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "kebab-case")]
pub enum Verdict {
    /// A grant applies, from `source`.
    Granted { rule: String, source: RuleSource },
    /// A deny applies -- deny is terminal (FW-CAP8), so it wins over any grant.
    Denied { rule: String, source: RuleSource },
    /// Default-allow with no rule naming it: subtractive-mode reads, or unrestricted exec
    /// (ungoverned/transparent, FW-ISO9). Access is on, but no grant is responsible.
    Ambient,
    /// No grant reaches this in a closed universe -- unlisted under `unveil` reads, an unlisted
    /// write (writes have no ambient), or a path outside an exec allow-list. Not accessible.
    Hidden,
}

/// The read, write, and exec verdicts for a path.
#[derive(Debug, Serialize)]
pub struct Explanation {
    pub path: String,
    pub read: Verdict,
    pub write: Verdict,
    pub exec: Verdict,
}

impl Provenance {
    /// Evaluate `path` under the deny-terminal model (FW-CAP8): a matching deny wins; otherwise a
    /// matching grant; otherwise the mode's default. `floor_type` is the credential-floor match the
    /// caller computes from the catalog -- a built-in, un-liftable deny of both read and write. Exec
    /// is a separate axis (FW-ISO9): the read/write floor never governs it, matching enforcement
    /// where an exec grant confers execute only ([FW-XR6](#fw-xr6) parity).
    pub fn explain(
        &self,
        blueprint: &Blueprint,
        path: &Path,
        floor_type: Option<String>,
    ) -> Explanation {
        let first = |v: &[(PathPattern, RuleSource)]| -> Option<(String, RuleSource)> {
            v.iter()
                .find(|(p, _)| p.matches_path(path))
                .map(|(p, s)| (p.to_string(), s.clone()))
        };

        // The floor and any operator subtract deny read AND write, terminally.
        let hard_deny = match floor_type {
            Some(t) => Some((format!("credential floor ({t})"), RuleSource::BuiltIn)),
            None => first(&self.subtract),
        };

        let read = if let Some((rule, source)) = &hard_deny {
            Verdict::Denied {
                rule: rule.clone(),
                source: source.clone(),
            }
        } else if let Some((rule, source)) = first(&self.reads)
            .or_else(|| first(&self.writes))
            .or_else(|| first(&self.writes_no_create))
        {
            // A write grant implies read of the same path.
            Verdict::Granted { rule, source }
        } else if blueprint.fs.read_mode == ReadMode::AmbientMinusSubtract {
            Verdict::Ambient
        } else {
            Verdict::Hidden
        };

        let write = if let Some((rule, source)) = &hard_deny {
            Verdict::Denied {
                rule: rule.clone(),
                source: source.clone(),
            }
        } else if let Some((rule, source)) = first(&self.write_subtract) {
            Verdict::Denied {
                rule: format!("{rule} (write-subtract)"),
                source,
            }
        } else if let Some((rule, source)) = first(&self.writes) {
            Verdict::Granted { rule, source }
        } else if let Some((rule, source)) = first(&self.writes_no_create) {
            Verdict::Granted {
                rule: format!("{rule} (no create)"),
                source,
            }
        } else {
            Verdict::Hidden
        };

        // Exec is governed only by the exec posture (FW-ISO9). Unrestricted means execute is
        // ungoverned (ambient); an allow-list grants only listed paths, everything else is closed.
        let exec = match blueprint.exec {
            ExecPosture::Unrestricted => Verdict::Ambient,
            ExecPosture::Allowlist(_) => match first(&self.exec) {
                Some((rule, source)) => Verdict::Granted { rule, source },
                None => Verdict::Hidden,
            },
        };

        Explanation {
            path: path.display().to_string(),
            read,
            write,
            exec,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FsLayer;

    fn pp(s: &str) -> PathPattern {
        PathPattern::parse(s).unwrap()
    }

    fn layer(fs: FsLayer) -> BlueprintLayer {
        BlueprintLayer {
            fs,
            ..Default::default()
        }
    }

    #[test]
    fn explain_names_the_winning_rule_and_origin() {
        // A file grants a broad read/write; a CLI deny carves a hole. Deny is terminal.
        let file = layer(FsLayer {
            read_mode: Some(ReadMode::Closed),
            reads: vec![pp("/work/**")],
            writes: vec![pp("/work/**")],
            ..Default::default()
        });
        let cli = layer(FsLayer {
            subtract: vec![pp("/work/secret")],
            ..Default::default()
        });
        let (bp, prov) = merge_with_provenance(&[
            (RuleSource::File("session.toml".into()), file),
            (RuleSource::Cli, cli),
        ]);

        let ok = prov.explain(&bp, Path::new("/work/main.rs"), None);
        assert_eq!(
            ok.read,
            Verdict::Granted {
                rule: "/work/**".into(),
                source: RuleSource::File("session.toml".into())
            }
        );
        assert!(matches!(ok.write, Verdict::Granted { .. }));

        let denied = prov.explain(&bp, Path::new("/work/secret"), None);
        assert_eq!(
            denied.read,
            Verdict::Denied {
                rule: "/work/secret".into(),
                source: RuleSource::Cli
            }
        );
        assert!(matches!(denied.write, Verdict::Denied { .. }));

        // Unlisted under closed mode is hidden, not ambient.
        assert_eq!(
            prov.explain(&bp, Path::new("/etc/hosts"), None).read,
            Verdict::Hidden
        );
    }

    #[test]
    fn floor_denies_terminally_as_built_in() {
        let (bp, prov) = merge_with_provenance(&[(
            RuleSource::File("s.toml".into()),
            layer(FsLayer {
                read_mode: Some(ReadMode::AmbientMinusSubtract),
                ..Default::default()
            }),
        )]);
        let e = prov.explain(&bp, Path::new("/home/x/.aws/creds"), Some("aws".into()));
        assert_eq!(
            e.read,
            Verdict::Denied {
                rule: "credential floor (aws)".into(),
                source: RuleSource::BuiltIn
            }
        );
        // A non-floored path in subtractive mode is ambient-readable.
        assert_eq!(
            prov.explain(&bp, Path::new("/usr/bin/x"), None).read,
            Verdict::Ambient
        );
    }

    #[test]
    fn write_no_create_and_write_subtract_are_distinguished() {
        let (bp, prov) = merge_with_provenance(&[(
            RuleSource::File("s.toml".into()),
            layer(FsLayer {
                read_mode: Some(ReadMode::Closed),
                writes_no_create: vec![pp("/data/**")],
                write_subtract: vec![pp("/data/.git/config")],
                ..Default::default()
            }),
        )]);
        // A write-no-create path: readable + writable-but-no-create.
        let w = prov.explain(&bp, Path::new("/data/app.log"), None);
        assert!(matches!(w.read, Verdict::Granted { .. }));
        match w.write {
            Verdict::Granted { rule, .. } => assert!(rule.contains("no create")),
            other => panic!("expected granted-no-create, got {other:?}"),
        }
        // A write-subtract path: readable, write denied.
        let t = prov.explain(&bp, Path::new("/data/.git/config"), None);
        assert!(matches!(t.read, Verdict::Granted { .. }));
        assert!(matches!(t.write, Verdict::Denied { .. }));
    }

    #[test]
    fn explain_reports_exec_as_a_separate_axis() {
        // An exec allow-list from the `exec`/`readexec` verbs (last-set-wins across layers).
        let with_allowlist = BlueprintLayer {
            exec: Some(ExecPosture::Allowlist(vec![pp("/usr/bin/git")])),
            fs: FsLayer {
                read_mode: Some(ReadMode::Closed),
                ..Default::default()
            },
            ..Default::default()
        };
        let (bp, prov) =
            merge_with_provenance(&[(RuleSource::File("s.toml".into()), with_allowlist)]);
        // A listed binary: exec granted and attributed, even though read is closed (FW-XR6 parity).
        let git = prov.explain(&bp, Path::new("/usr/bin/git"), None);
        assert_eq!(
            git.exec,
            Verdict::Granted {
                rule: "/usr/bin/git".into(),
                source: RuleSource::File("s.toml".into())
            }
        );
        assert_eq!(
            git.read,
            Verdict::Hidden,
            "exec confers execute only, not read"
        );
        // An unlisted binary under an allow-list: exec closed.
        assert_eq!(
            prov.explain(&bp, Path::new("/bin/sh"), None).exec,
            Verdict::Hidden
        );

        // Default (no exec verb) leaves exec unrestricted -- ungoverned/transparent (FW-ISO9).
        let (bp2, prov2) = merge_with_provenance(&[(
            RuleSource::File("s.toml".into()),
            layer(FsLayer::default()),
        )]);
        assert_eq!(
            prov2.explain(&bp2, Path::new("/usr/bin/git"), None).exec,
            Verdict::Ambient
        );
    }
}
