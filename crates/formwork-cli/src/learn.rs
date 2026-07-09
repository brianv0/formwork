//! `formwork learn` and `formwork accept` -- observe-then-widen discovery (FEP-2 Part D).
//!
//! A learning run is an ENFORCED run plus observation: the policy is compiled and installed
//! exactly as `run` would (FW-INV10 -- observation never weakens the live session), and the
//! denials the kernel logged during the run window are collected afterwards and reverse-compiled
//! into a proposal (FW-DISC2). On macOS the denial feed is the unified log's Sandbox records,
//! collected post-hoc with `log show` so there is no stream-startup race. Attribution is the run
//! window plus dedup -- deliberately tolerant of over-capture, because a candidate has no effect
//! until accepted (FW-INV10), credentials are floored regardless (FW-DISC3), and everything else
//! waits for review. On hosts without a denial feed, learning says so loudly and proposes
//! nothing -- never a silent pretend (FW-INV5/6).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use formwork_blueprint::{
    reverse_compile, Blueprint, BlueprintLayer, Candidate, CandidateTag, DenialAccess,
    DenialRecord, ProvenanceEntry, ResolvedCatalog,
};

/// The reviewable proposal artifact (FW-DISC5). Candidates only: withheld credential matches are
/// operator-channel material and never written here -- the file may sit inside the confined
/// grant, and itemizing catalog matches in it would hand the agent an oracle (FW-INV9).
/// Unreviewed entries ACCUMULATE across learning runs (each stamped with the run that observed
/// it, so acceptance provenance stays truthful); a re-observed entry is refreshed in place.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ProposalFile {
    /// The blueprint the proposal was learned against, for `accept` to find the discovered layer.
    pub blueprint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<ProposalEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ProposalEntry {
    #[serde(flatten)]
    pub candidate: Candidate,
    /// The learning run that (last) observed this need.
    pub run_id: String,
}

pub fn proposal_path(blueprint: &Path) -> PathBuf {
    PathBuf::from(format!("{}.proposal.toml", blueprint.display()))
}

pub fn discovered_path(blueprint: &Path) -> PathBuf {
    PathBuf::from(format!("{}.discovered.toml", blueprint.display()))
}

/// One unified-log Sandbox record: `Sandbox: cat(29810) deny(1) file-read-data /private/tmp/x`.
/// Returns the denial with the kernel-resolved path, or None for lines that are not fs denials.
fn parse_sandbox_denial(event_message: &str) -> Option<DenialRecord> {
    let message = event_message
        .strip_prefix("Sandbox: ")
        .unwrap_or(event_message);
    let deny_at = message.find(" deny(")?;
    let rest = &message[deny_at + 1..];
    let close = rest.find(") ")?;
    let (operation, path) = rest[close + 2..].split_once(' ')?;
    if !path.starts_with('/') {
        return None;
    }
    let access = if operation.starts_with("file-write") {
        DenialAccess::Write
    } else if operation.starts_with("file-read") || operation == "process-exec" {
        // An exec denial is a read-grant gap in the unrestricted-exec default.
        DenialAccess::Read
    } else {
        return None; // mach-lookup, network*, etc. -- not filesystem discovery material
    };
    Some(DenialRecord {
        path: path.to_string(),
        access,
    })
}

/// Post-hoc collection over the run window (plus slack for log-persistence latency).
fn collect_denials(window_secs: u64) -> Result<Vec<DenialRecord>> {
    let output = Command::new("/usr/bin/log")
        .args([
            "show",
            "--style",
            "ndjson",
            "--last",
            &format!("{window_secs}s"),
            "--predicate",
            r#"sender == "Sandbox""#,
        ])
        .output()
        .context("running `log show` to collect sandbox denials")?;
    if !output.status.success() {
        bail!(
            "`log show` failed (status {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let mut records = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(message) = value.get("eventMessage").and_then(|m| m.as_str()) {
            if let Some(record) = parse_sandbox_denial(message) {
                records.push(record);
            }
        }
    }
    Ok(records)
}

/// The learn phase after the confined child has exited: collect, reverse-compile, merge into
/// the proposal, self-accept in-zone candidates into the discovered layer, and itemize on the
/// operator channel.
pub fn conclude_learning_run(
    blueprint: &Blueprint,
    blueprint_path: &Path,
    catalog: &ResolvedCatalog,
    run_id: &str,
    window_secs: u64,
    workload_status: &std::process::ExitStatus,
) -> Result<()> {
    let records = collect_denials(window_secs)?;
    let outcome = reverse_compile(
        &records,
        catalog,
        &blueprint.allow_credentials,
        &blueprint.discovery.auto_widen,
    );

    // FW-CRED7: the withheld itemization -- names and types -- goes to the operator channel only.
    for withheld in &outcome.withheld {
        tracing::info!(
            path = %withheld.path,
            credential_type = %withheld.credential_type,
            "learning: denial withheld by the credential floor (FW-DISC3); lift only via --allow-cred"
        );
    }

    let auto: Vec<ProposalEntry> = outcome
        .candidates
        .iter()
        .filter(|c| c.tag == CandidateTag::AutoAccepted)
        .map(|c| ProposalEntry {
            candidate: c.clone(),
            run_id: run_id.to_string(),
        })
        .collect();
    if !auto.is_empty() {
        let discovered = discovered_path(blueprint_path);
        let auto_refs: Vec<&ProposalEntry> = auto.iter().collect();
        let count = merge_into_discovered(&discovered, &auto_refs, "discovery-auto")?;
        tracing::info!(
            file = %discovered.display(),
            grants = count,
            "learning: in-zone candidates self-granted for the NEXT run (FW-DISC4)"
        );
    }

    let path = proposal_path(blueprint_path);
    let previous: Vec<ProposalEntry> = match std::fs::read_to_string(&path) {
        Ok(text) => {
            toml::from_str::<ProposalFile>(&text)
                .with_context(|| format!("parsing existing proposal {}", path.display()))?
                .candidates
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e).context(format!("reading {}", path.display())),
    };
    let observed: Vec<ProposalEntry> = outcome
        .candidates
        .iter()
        .map(|c| ProposalEntry {
            candidate: c.clone(),
            run_id: run_id.to_string(),
        })
        .collect();
    let (candidates, carried) = merge_proposal_entries(previous, observed);
    if carried > 0 {
        tracing::info!(
            carried,
            "unreviewed candidates from earlier learning runs kept in the proposal"
        );
    }

    let proposal = ProposalFile {
        blueprint: blueprint_path
            .canonicalize()
            .unwrap_or_else(|_| blueprint_path.to_path_buf())
            .display()
            .to_string(),
        candidates,
    };
    let body = format!(
        "# formwork learn proposal -- review with `formwork accept --proposal {p}` (no selection\n\
         # lists entries by number), then accept per entry (--entry <N> or --entry <pattern>).\n\
         # Paths are kernel-resolved (macOS: /tmp appears as /private/tmp). Nothing here has any\n\
         # effect until accepted (FW-INV10).\n{body}",
        p = path.display(),
        body = toml::to_string_pretty(&proposal).context("serializing proposal")?
    );
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    tracing::info!(
        workload_exit = workload_status.code().unwrap_or(-1),
        proposal = %path.display(),
        candidates = proposal.candidates.len(),
        needs_review = proposal
            .candidates
            .iter()
            .filter(|c| c.candidate.tag == CandidateTag::NeedsReview)
            .count(),
        withheld = outcome.withheld.len(),
        "learning run complete (proposal written regardless of workload exit)"
    );
    Ok(())
}

/// Pure merge: unreviewed entries from earlier runs are kept (sticky learning), a re-observed
/// (pattern, access) is refreshed with the newest run's tag and run id. Prior auto-accepted
/// entries are NOT carried -- they already live in the discovered layer with provenance, which
/// is the durable audit trail; re-listing them here forever would only accrete noise. Returns
/// the merged, deterministic list and how many prior entries were carried forward un-refreshed.
fn merge_proposal_entries(
    previous: Vec<ProposalEntry>,
    observed: Vec<ProposalEntry>,
) -> (Vec<ProposalEntry>, usize) {
    let key = |e: &ProposalEntry| (e.candidate.pattern.canonical(), e.candidate.access);
    let mut merged: std::collections::BTreeMap<_, ProposalEntry> = previous
        .into_iter()
        .filter(|e| e.candidate.tag == CandidateTag::NeedsReview)
        .map(|e| (key(&e), e))
        .collect();
    let before = merged.len();
    let mut refreshed = 0;
    for entry in observed {
        if merged.insert(key(&entry), entry).is_some() {
            refreshed += 1;
        }
    }
    let carried = before - refreshed;
    (merged.into_values().collect(), carried)
}

/// Append accepted entries to the discovered layer with provenance (FW-DISC6), deduped and
/// canonical. The file is itself a BlueprintLayer, so the next run stacks it like any base.
fn merge_into_discovered(
    path: &Path,
    accepted: &[&ProposalEntry],
    added_via: &str,
) -> Result<usize> {
    let mut layer: BlueprintLayer = match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text)
            .with_context(|| format!("parsing existing discovered layer {}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BlueprintLayer::default(),
        Err(e) => return Err(e).context(format!("reading {}", path.display())),
    };
    for entry in accepted {
        match entry.candidate.access {
            DenialAccess::Read => layer.fs.reads.push(entry.candidate.pattern.clone()),
            DenialAccess::Write => layer.fs.writes.push(entry.candidate.pattern.clone()),
        }
        layer.discovery.provenance.insert(
            entry.candidate.pattern.canonical(),
            ProvenanceEntry {
                added_via: added_via.to_string(),
                run_id: entry.run_id.clone(),
            },
        );
    }
    layer.fs.reads = formwork_blueprint::canonicalize_set(&layer.fs.reads);
    layer.fs.writes = formwork_blueprint::canonicalize_set(&layer.fs.writes);
    let body = format!(
        "# Discovered grants (formwork learn/accept). Every grant carries provenance (FW-DISC6);\n\
         # authored grants belong in the blueprint, not here.\n{}",
        toml::to_string_pretty(&layer).context("serializing discovered layer")?
    );
    std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))?;
    Ok(accepted.len())
}

/// `formwork accept`: per-entry, human-in-the-loop acceptance (FW-DISC5). With no selection it
/// lists the candidates by number instead of erroring, so the review loop is self-describing.
/// A selection names an entry by its 1-based number or by its exact pattern. The credential
/// floor is re-checked here with NO exclusions -- even a forged proposal cannot move a catalog
/// location into the discovered layer through this door (FW-INV8).
pub fn accept(proposal_file: &Path, entries: &[String], all: bool, home: &str) -> Result<()> {
    let text = std::fs::read_to_string(proposal_file)
        .with_context(|| format!("reading proposal {}", proposal_file.display()))?;
    let proposal: ProposalFile = toml::from_str(&text)
        .with_context(|| format!("parsing proposal {}", proposal_file.display()))?;

    if !all && entries.is_empty() {
        if proposal.candidates.is_empty() {
            tracing::info!("proposal has no candidates; nothing to review");
            return Ok(());
        }
        for (index, entry) in proposal.candidates.iter().enumerate() {
            tracing::info!(
                entry = index + 1,
                pattern = %entry.candidate.pattern.canonical(),
                access = ?entry.candidate.access,
                tag = ?entry.candidate.tag,
                observed_by = %entry.run_id,
                "candidate"
            );
        }
        tracing::info!(
            "select with --entry <number|pattern> (repeatable) or --all; auto-accepted entries \
             are already in the discovered layer and are listed for audit only"
        );
        return Ok(());
    }

    let matches_selection = |index: usize, entry: &ProposalEntry| -> bool {
        all || entries.iter().any(|sel| {
            sel.parse::<usize>()
                .map(|n| n == index + 1)
                .unwrap_or(false)
                || *sel == entry.candidate.pattern.canonical()
        })
    };
    let selected: Vec<&ProposalEntry> = proposal
        .candidates
        .iter()
        .enumerate()
        .filter(|(_, e)| e.candidate.tag == CandidateTag::NeedsReview)
        .filter(|(i, e)| matches_selection(*i, e))
        .map(|(_, e)| e)
        .collect();
    if selected.is_empty() {
        bail!("no needs-review candidate matched the selection (run with no selection to list)");
    }

    let catalog = ResolvedCatalog::builtin_for_home(home)
        .context("resolving credential catalog for the acceptance floor check")?;
    for entry in &selected {
        if let Some(credential_type) = catalog.floor_type_of(&[], &entry.candidate.pattern) {
            bail!(
                "refusing to accept {}: it matches the credential floor (type: {credential_type}); \
                 the only lift is the explicit typed exclude, --allow-cred (FW-INV8)",
                entry.candidate.pattern.canonical()
            );
        }
    }

    let blueprint_path = PathBuf::from(&proposal.blueprint);
    let discovered = discovered_path(&blueprint_path);
    let count = merge_into_discovered(&discovered, &selected, "discovery")?;

    // Rewrite the proposal without the accepted entries so acceptance is visibly consumed.
    let accepted: Vec<String> = selected
        .iter()
        .map(|e| e.candidate.pattern.canonical())
        .collect();
    let remaining = ProposalFile {
        blueprint: proposal.blueprint.clone(),
        candidates: proposal
            .candidates
            .iter()
            .filter(|e| !accepted.contains(&e.candidate.pattern.canonical()))
            .cloned()
            .collect(),
    };
    let body = toml::to_string_pretty(&remaining).context("serializing remaining proposal")?;
    std::fs::write(proposal_file, body)
        .with_context(|| format!("rewriting {}", proposal_file.display()))?;

    tracing::info!(
        accepted = count,
        into = %discovered.display(),
        "accepted discovered grants; they apply from the next run"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use formwork_blueprint::PathPattern;

    #[test]
    fn proposal_merge_is_sticky_and_refreshes_reobserved() {
        let entry = |path: &str, run: &str| ProposalEntry {
            candidate: Candidate {
                pattern: PathPattern::parse(path).unwrap(),
                access: DenialAccess::Read,
                tag: CandidateTag::NeedsReview,
            },
            run_id: run.to_string(),
        };
        let previous = vec![
            entry("/opt/toolchain/**", "learn-1"),
            entry("/srv/data", "learn-1"),
        ];
        let observed = vec![
            entry("/srv/data", "learn-2"),
            entry("/var/cache/x", "learn-2"),
        ];
        let (merged, carried) = merge_proposal_entries(previous, observed);
        assert_eq!(
            carried, 1,
            "the un-reobserved toolchain entry is carried, not dropped"
        );
        let by_path: std::collections::BTreeMap<String, String> = merged
            .iter()
            .map(|e| (e.candidate.pattern.canonical(), e.run_id.clone()))
            .collect();
        assert_eq!(by_path["/opt/toolchain/**"], "learn-1");
        assert_eq!(
            by_path["/srv/data"], "learn-2",
            "re-observed entry refreshed"
        );
        assert_eq!(by_path["/var/cache/x"], "learn-2");
        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn parses_real_sandbox_messages() {
        // Shape captured live from `log show` on macOS 15 (see docs/fep2-plan.md §4).
        let record = parse_sandbox_denial(
            "Sandbox: cat(29810) deny(1) file-read-data /private/tmp/fw-spike/home/.aws/credentials",
        )
        .unwrap();
        assert_eq!(record.path, "/private/tmp/fw-spike/home/.aws/credentials");
        assert_eq!(record.access, DenialAccess::Read);

        let write =
            parse_sandbox_denial("Sandbox: sh(123) deny(1) file-write-create /work/out.txt")
                .unwrap();
        assert_eq!(write.access, DenialAccess::Write);

        // Non-fs denials and unparsable lines yield nothing.
        assert!(parse_sandbox_denial("Sandbox: x(1) deny(1) mach-lookup com.apple.foo").is_none());
        assert!(parse_sandbox_denial("unrelated log line").is_none());
    }
}
