//! Reverse compilation (FW-DISC2): observed denials -> a tagged proposal. Pure -- the unified-log
//! tap and all file IO live in the CLI -- so the load-bearing safety property is testable in
//! isolation: a denial matching the credential catalog is *never* a candidate, no matter the
//! zone, the attempt count, or who asks (FW-DISC3 / FW-INV8). Everything else is either inside
//! the operator-drawn auto-widen zone (FW-DISC4) or needs review (FW-DISC5). Observation never
//! changes the running session (FW-INV10): this function proposes, the operator disposes.

use serde::{Deserialize, Serialize};

use crate::{PathPattern, ResolvedCatalog};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DenialAccess {
    Read,
    Write,
}

/// One observed denial: a kernel-resolved absolute path and the access that failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DenialRecord {
    pub path: String,
    pub access: DenialAccess,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateTag {
    /// Inside the auto-widen zone: the learn run may move it into the discovered layer itself.
    AutoAccepted,
    /// Outside the zone: surfaces in the proposal and waits for per-entry acceptance.
    NeedsReview,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Candidate {
    pub pattern: PathPattern,
    pub access: DenialAccess,
    pub tag: CandidateTag,
}

/// A denial the floor withheld -- operator-channel material (FW-CRED7), never a candidate and
/// never written into the proposal file (the file may sit inside the confined grant; itemizing
/// catalog matches there would hand the agent an oracle).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithheldEntry {
    pub path: String,
    pub credential_type: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposalOutcome {
    pub candidates: Vec<Candidate>,
    pub withheld: Vec<WithheldEntry>,
}

/// Denials -> tagged candidates. Deterministic: inputs are deduped and sorted; sibling paths
/// (>= 2 sharing a parent, same access) fold into one `parent/**` candidate unless the folded
/// pattern would cross the credential floor, in which case the individual paths stand.
pub fn reverse_compile(
    records: &[DenialRecord],
    catalog: &ResolvedCatalog,
    allow: &[String],
    auto_widen: &[PathPattern],
) -> ProposalOutcome {
    let mut seen = std::collections::BTreeSet::new();
    let mut withheld = Vec::new();
    let mut granular: Vec<(PathPattern, DenialAccess)> = Vec::new();

    for record in records {
        let Ok(pattern) = PathPattern::parse(&record.path) else {
            // Not an absolute kernel path (malformed log line); nothing enforceable to propose.
            continue;
        };
        if !seen.insert((pattern.canonical(), record.access)) {
            continue;
        }
        // The floor (FW-DISC3/FW-INV8): catalog-matched denials are withheld, never proposed.
        if let Some(credential_type) = catalog.floor_type_of(allow, &pattern) {
            withheld.push(WithheldEntry {
                path: record.path.clone(),
                credential_type,
            });
            continue;
        }
        granular.push((pattern, record.access));
    }

    // Fold >= 2 same-access siblings into their parent subtree -- unless the fold would cover a
    // floor path (a subtree swallowing a credential dir), where granularity is kept.
    let mut by_parent: std::collections::BTreeMap<(String, DenialAccess), Vec<PathPattern>> =
        std::collections::BTreeMap::new();
    for (pattern, access) in &granular {
        let parent = pattern
            .base()
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "/".to_string());
        by_parent
            .entry((parent, *access))
            .or_default()
            .push(pattern.clone());
    }

    let mut candidates = Vec::new();
    for ((parent, access), members) in by_parent {
        let folded = PathPattern::parse(&format!("{}/**", parent.trim_end_matches('/')));
        let fold = match folded {
            Ok(f) if members.len() >= 2 && catalog.floor_type_of(allow, &f).is_none() => Some(f),
            _ => None,
        };
        match fold {
            Some(f) => candidates.push(tag_candidate(f, access, auto_widen)),
            None => {
                for member in members {
                    candidates.push(tag_candidate(member, access, auto_widen));
                }
            }
        }
    }
    candidates.sort_by_key(|c| (c.pattern.canonical(), c.access));
    withheld.sort_by(|a, b| a.path.cmp(&b.path));

    ProposalOutcome {
        candidates,
        withheld,
    }
}

fn tag_candidate(
    pattern: PathPattern,
    access: DenialAccess,
    auto_widen: &[PathPattern],
) -> Candidate {
    let in_zone = auto_widen.iter().any(|z| z.covers(&pattern));
    Candidate {
        pattern,
        access,
        tag: if in_zone {
            CandidateTag::AutoAccepted
        } else {
            CandidateTag::NeedsReview
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(path: &str) -> DenialRecord {
        DenialRecord {
            path: path.to_string(),
            access: DenialAccess::Read,
        }
    }

    fn catalog() -> ResolvedCatalog {
        ResolvedCatalog::builtin_for_home("/home/x").unwrap()
    }

    fn pp(s: &str) -> PathPattern {
        PathPattern::parse(s).unwrap()
    }

    #[test]
    fn catalog_denials_are_withheld_never_candidates() {
        // The FW-ADV-013 property at the unit level: however many times the credential is
        // attempted, and even with an adversarially broad zone, it never becomes a candidate.
        let records: Vec<DenialRecord> = std::iter::repeat_with(|| read("/home/x/.ssh/id_ed25519"))
            .take(50)
            .collect();
        let zone = vec![pp("/home/x/**")]; // adversarially broad
        let out = reverse_compile(&records, &catalog(), &[], &zone);
        assert!(out.candidates.is_empty(), "{:?}", out.candidates);
        assert_eq!(out.withheld.len(), 1, "deduped, then withheld");
        assert_eq!(out.withheld[0].credential_type, "ssh");
    }

    #[test]
    fn zone_splits_auto_accept_from_needs_review() {
        let records = vec![
            read("/work/project/.cache/a.bin"),
            read("/opt/toolchain/lib.py"),
        ];
        let zone = vec![pp("/work/project/**")];
        let out = reverse_compile(&records, &catalog(), &[], &zone);
        let by_tag = |t: CandidateTag| -> Vec<String> {
            out.candidates
                .iter()
                .filter(|c| c.tag == t)
                .map(|c| c.pattern.canonical())
                .collect()
        };
        assert_eq!(
            by_tag(CandidateTag::AutoAccepted),
            vec!["/work/project/.cache/a.bin"]
        );
        assert_eq!(
            by_tag(CandidateTag::NeedsReview),
            vec!["/opt/toolchain/lib.py"]
        );
    }

    #[test]
    fn siblings_fold_to_parent_subtree() {
        let records = vec![read("/opt/toolchain/one.py"), read("/opt/toolchain/two.py")];
        let out = reverse_compile(&records, &catalog(), &[], &[]);
        assert_eq!(out.candidates.len(), 1);
        assert_eq!(out.candidates[0].pattern, pp("/opt/toolchain/**"));
    }

    #[test]
    fn fold_that_would_swallow_a_floor_path_stays_granular() {
        // Two denials directly in the fake home: folding to /home/x/** would cover ~/.ssh.
        let records = vec![read("/home/x/one.txt"), read("/home/x/two.txt")];
        let out = reverse_compile(&records, &catalog(), &[], &[]);
        let patterns: Vec<String> = out
            .candidates
            .iter()
            .map(|c| c.pattern.canonical())
            .collect();
        assert_eq!(patterns, vec!["/home/x/one.txt", "/home/x/two.txt"]);
    }

    #[test]
    fn output_is_deterministic_and_deduped() {
        let records = vec![read("/b/file"), read("/a/file"), read("/b/file")];
        let a = reverse_compile(&records, &catalog(), &[], &[]);
        let b = reverse_compile(&records, &catalog(), &[], &[]);
        assert_eq!(a, b);
        assert_eq!(a.candidates.len(), 2);
        assert!(a.candidates[0].pattern.canonical() < a.candidates[1].pattern.canonical());
    }

    #[test]
    fn excluded_type_is_no_longer_floored_for_discovery() {
        // FW-CRED5 is the one lift: with aws excluded, an aws-path denial may be proposed
        // (it is an ordinary path for this session), while ssh stays floored.
        let records = vec![read("/home/x/.aws/config"), read("/home/x/.ssh/config")];
        let out = reverse_compile(&records, &catalog(), &["aws".to_string()], &[]);
        let patterns: Vec<String> = out
            .candidates
            .iter()
            .map(|c| c.pattern.canonical())
            .collect();
        assert_eq!(patterns, vec!["/home/x/.aws/config"]);
        assert_eq!(out.withheld.len(), 1);
    }
}
