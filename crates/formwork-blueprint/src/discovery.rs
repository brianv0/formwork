//! Reverse compilation (FW-DISC2): observed denials -> a tagged proposal. Pure -- the unified-log
//! tap and all file IO live in the CLI -- so the essential safety property is testable in
//! isolation: a denial matching the credential catalog is *never* a candidate, no matter the
//! zone, the attempt count, or who asks (FW-DISC3 / FW-INV8). Everything else is either inside
//! the operator-drawn auto-widen zone (FW-DISC4) or needs review (FW-DISC5). Observation never
//! changes the running session (FW-INV10): this function proposes, the operator disposes.

use serde::{Deserialize, Serialize};

use crate::{
    canonicalize_set, Blueprint, CredentialEntry, FsBlueprint, PathPattern, ReadMode,
    ResolvedCatalog,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DenialAccess {
    Read,
    Write,
}

/// A kernel-resolved absolute path and its access grade. The source is deliberately not encoded: an
/// enforced-`learn` denial and a permissive recording's open are one shape, so both feed one reverse
/// compiler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessRecord {
    pub path: String,
    pub access: DenialAccess,
}

/// Kept so the enforced-`learn` call sites, which observe denials, read in their own terms.
pub type DenialRecord = AccessRecord;

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
            // FW-INV8 defense-in-depth: never fold into a subtree that would cover a path the floor
            // just withheld. Enforcement (deny beats allow) is the primary wall -- it denies the
            // credential shape regardless of any grant -- but keeping the fold granular means a
            // proposal never even *lists* a grant that would re-cover a withheld credential, so the
            // proposal itself stays honest and the wall survives a future narrowing of enforcement.
            Ok(f)
                if members.len() >= 2
                    && catalog.floor_type_of(allow, &f).is_none()
                    && !fold_would_cover_withheld(&f, &withheld) =>
            {
                Some(f)
            }
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

/// Observed accesses -> a standalone, enforceable Blueprint, where `reverse_compile` yields a
/// discovered-layer *diff*. Shares that reverse compiler, so the credential floor still withholds
/// catalog matches (FW-DISC3 / FW-INV8): a recorded credential access never becomes a grant, however
/// permissive the run that observed it.
pub fn synthesize_blueprint(
    records: &[AccessRecord],
    catalog: &ResolvedCatalog,
    allow: &[String],
) -> Blueprint {
    // No auto-widen zone: synthesis is a full grant set, not a proposal to tag/review.
    let outcome = reverse_compile(records, catalog, allow, &[]);
    let mut reads = Vec::new();
    let mut writes = Vec::new();
    for candidate in &outcome.candidates {
        match candidate.access {
            // Write grants imply read at compile time, so a write need not also list a read.
            DenialAccess::Read => reads.push(candidate.pattern.clone()),
            DenialAccess::Write => writes.push(candidate.pattern.clone()),
        }
    }
    Blueprint {
        fs: FsBlueprint {
            read_mode: ReadMode::Closed,
            reads: canonicalize_set(&reads),
            writes: canonicalize_set(&writes),
            ..FsBlueprint::default()
        },
        allow_credentials: allow
            .iter()
            .map(|a| CredentialEntry::Expose(a.clone()))
            .collect(),
        ..Blueprint::empty()
    }
}

/// FW-INV8: would this folded subtree grant cover a path the floor withheld? A `true` keeps the
/// members granular so a withheld credential is never re-granted through a covering subtree.
fn fold_would_cover_withheld(folded: &PathPattern, withheld: &[WithheldEntry]) -> bool {
    withheld
        .iter()
        .any(|w| PathPattern::parse(&w.path).is_ok_and(|p| folded.covers(&p)))
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

/// A destination the Gateway refused as a policy decision (FW-DISC12): the host and port, and for
/// a request refused on an inspected host, its method and canonical path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct EgressObservation {
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Host rules `learn` proposes, and the destinations it withholds with the reason
/// (operator-channel material, like the credential floor's withheld list).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EgressProposal {
    pub rules: Vec<crate::HostRule>,
    pub withheld: Vec<(String, String)>,
}

/// FW-DISC12: refused destinations -> host rules at the grade the host already has. A host no rule
/// names is proposed at the tunnel grade (`https:host`); a request refused on an inspected host is
/// proposed as that method on that exact path. Metadata names and restricted addresses are never
/// proposed (FW-EGR4), and neither is a host a `deny:` rule names -- lifting an authored deny is
/// an authoring decision. Deterministic: deduplicated and sorted.
pub fn propose_host_rules(
    observed: &[EgressObservation],
    table: Option<&crate::HostTable>,
) -> EgressProposal {
    use crate::{
        canonicalize_host, is_restricted_ip, CanonicalHost, EgressDecision, HostRule, HostTable,
        HttpMethod, DEFAULT_HTTPS_PORT, METADATA_HOSTNAMES,
    };
    let empty = HostTable::default();
    let table = table.unwrap_or(&empty);
    let mut out = EgressProposal::default();
    for obs in observed {
        let Ok(host) = canonicalize_host(&obs.host) else {
            continue;
        };
        let target = format!("{host}:{}", obs.port);
        let restricted = match &host {
            CanonicalHost::Ip(ip) => is_restricted_ip(*ip),
            CanonicalHost::Name(n) => METADATA_HOSTNAMES.contains(&n.as_str()),
        };
        if restricted {
            out.withheld.push((
                target,
                "a metadata, private, loopback or link-local destination is never proposed \
                 (FW-EGR4); name it in a rule by hand if the session truly needs it"
                    .to_string(),
            ));
            continue;
        }
        let port = if obs.port == DEFAULT_HTTPS_PORT {
            String::new()
        } else {
            format!(":{}", obs.port)
        };
        let rule = match table.decide_connect(&host, obs.port) {
            EgressDecision::Deny {
                rule: Some(rule), ..
            } => {
                out.withheld
                    .push((target, format!("denied by the rule `{rule}`")));
                continue;
            }
            EgressDecision::Deny { rule: None, .. } => {
                HostRule::parse("https", &format!("{host}{port}"))
            }
            EgressDecision::Inspect => {
                let (Some(method), Some(path)) = (&obs.method, &obs.path) else {
                    continue;
                };
                let Some(method) = HttpMethod::from_token(method) else {
                    out.withheld
                        .push((target, format!("the method {method:?} has no rule atom")));
                    continue;
                };
                if !path.starts_with('/') {
                    continue;
                }
                // A requested path is a literal; `*` in it would become a glob in the rule and
                // widen the proposal past what the session asked for.
                if path.contains('*') {
                    out.withheld.push((
                        target,
                        format!("the path {path:?} carries `*`, which a rule would read as a glob"),
                    ));
                    continue;
                }
                HostRule::parse(method.atom(), &format!("{host}{port}{path}"))
            }
            // Admitted already: the refusal was not a missing rule (e.g. the name resolved to a
            // restricted address).
            EgressDecision::Tunnel { .. } | EgressDecision::Allow { .. } => continue,
        };
        match rule {
            Ok(rule) => out.rules.push(rule),
            Err(e) => out.withheld.push((target, e)),
        }
    }
    out.rules.sort();
    out.rules.dedup();
    out.withheld.sort();
    out.withheld.dedup();
    out
}

/// FW-DISC12: channels a run was refused -> the ones not already lifted, deduplicated and sorted.
pub fn propose_channels(
    observed: &[crate::Channel],
    policy: &crate::ChannelPolicy,
) -> Vec<crate::Channel> {
    let mut out: Vec<crate::Channel> = observed
        .iter()
        .copied()
        .filter(|c| !policy.lifted(*c))
        .collect();
    out.sort_by_key(|c| c.name());
    out.dedup();
    out
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

    fn write(path: &str) -> AccessRecord {
        AccessRecord {
            path: path.to_string(),
            access: DenialAccess::Write,
        }
    }

    #[test]
    fn synthesize_yields_a_closed_blueprint_with_credentials_withheld() {
        // The permissive-recording property at the unit level: a credential the run observed never
        // enters the synthesized grant, and the result is a tight closed blueprint (FW-DISC3/FW-INV8).
        let records = vec![
            read("/home/x/.ssh/id_ed25519"),
            read("/opt/toolchain/lib.py"),
        ];
        let bp = synthesize_blueprint(&records, &catalog(), &[]);
        assert_eq!(bp.fs.read_mode, ReadMode::Closed);
        let reads: Vec<String> = bp.fs.reads.iter().map(|p| p.canonical()).collect();
        assert_eq!(reads, vec!["/opt/toolchain/lib.py"]);
        assert!(bp.fs.writes.is_empty());
        assert!(!reads.iter().any(|r| r.contains(".ssh")));
    }

    #[test]
    fn synthesize_splits_read_and_write_grades() {
        let records = vec![read("/work/in.txt"), write("/work/out.txt")];
        let bp = synthesize_blueprint(&records, &catalog(), &[]);
        let reads: Vec<String> = bp.fs.reads.iter().map(|p| p.canonical()).collect();
        let writes: Vec<String> = bp.fs.writes.iter().map(|p| p.canonical()).collect();
        assert_eq!(reads, vec!["/work/in.txt"]);
        assert_eq!(writes, vec!["/work/out.txt"]);
    }

    #[test]
    fn synthesize_folds_observed_siblings_into_a_subtree() {
        let records = vec![read("/opt/tc/a.py"), read("/opt/tc/b.py")];
        let bp = synthesize_blueprint(&records, &catalog(), &[]);
        let reads: Vec<String> = bp.fs.reads.iter().map(|p| p.canonical()).collect();
        assert_eq!(reads, vec!["/opt/tc/**"]);
    }

    #[test]
    fn synthesize_carries_the_credential_exclusions() {
        // With aws excluded, the aws path is an ordinary grant AND the blueprint records the lift,
        // so the frozen artifact is self-consistent: the grant it carries is one it justifies.
        let bp = synthesize_blueprint(
            &[read("/home/x/.aws/config")],
            &catalog(),
            &["aws".to_string()],
        );
        assert_eq!(bp.exposed_credentials(), vec!["aws".to_string()]);
        let reads: Vec<String> = bp.fs.reads.iter().map(|p| p.canonical()).collect();
        assert_eq!(reads, vec!["/home/x/.aws/config"]);
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
    fn fold_never_re_grants_a_withheld_credential_outside_home() {
        // FW-INV8 defense-in-depth: a credential-shaped file OUTSIDE $HOME is withheld by the shape
        // floor, and its ordinary siblings must not fold into a subtree that would *list* a grant
        // covering it -- even though enforcement (deny beats allow) would still deny the key. Unlike
        // the home case above, floor_type_of on the folded subtree does not flag it (a subtree base
        // is not itself credential-shaped), so the fold guard is what keeps the proposal honest.
        let records = vec![
            read("/srv/app/id_rsa"), // credential shape, outside $HOME -> withheld (backstop)
            read("/srv/app/a.txt"),
            read("/srv/app/b.txt"),
        ];
        let zone = vec![pp("/srv/app/**")]; // drawn over the dir: a fold here would auto-accept
        let out = reverse_compile(&records, &catalog(), &[], &zone);

        assert_eq!(out.withheld.len(), 1);
        assert_eq!(out.withheld[0].path, "/srv/app/id_rsa");
        assert_eq!(out.withheld[0].credential_type, "backstop");

        let patterns: Vec<String> = out
            .candidates
            .iter()
            .map(|c| c.pattern.canonical())
            .collect();
        assert_eq!(
            patterns,
            vec!["/srv/app/a.txt", "/srv/app/b.txt"],
            "must stay granular"
        );
        assert!(
            !out.candidates
                .iter()
                .any(|c| c.pattern.covers(&pp("/srv/app/id_rsa"))),
            "no candidate may cover the withheld credential"
        );
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

    fn obs(host: &str, port: u16, req: Option<(&str, &str)>) -> EgressObservation {
        EgressObservation {
            host: host.into(),
            port,
            method: req.map(|(m, _)| m.into()),
            path: req.map(|(_, p)| p.into()),
        }
    }

    #[test]
    fn fw_disc12_hosts_are_proposed_at_their_grade_and_metadata_is_withheld() {
        let table = crate::HostTable::new(vec![
            crate::HostRule::parse("get", "api.github.com/repos/**").unwrap(),
            crate::HostRule::parse("deny", "evil.test").unwrap(),
        ]);
        let out = propose_host_rules(
            &[
                obs("blocked.test", 443, None),
                obs("Blocked.test.", 443, None),
                obs("registry.test", 8443, None),
                obs(
                    "api.github.com",
                    443,
                    Some(("POST", "/repos/acme/x/issues")),
                ),
                obs("169.254.169.254", 80, None),
                obs("metadata.google.internal", 80, None),
                obs("evil.test", 443, None),
                obs("api.github.com", 443, Some(("GET", "/repos/**"))),
            ],
            Some(&table),
        );
        let rules: Vec<String> = out.rules.iter().map(|r| r.to_string()).collect();
        assert!(
            rules.contains(&"https:blocked.test".to_string()),
            "{rules:?}"
        );
        assert!(
            rules.contains(&"https:registry.test:8443".to_string()),
            "{rules:?}"
        );
        assert!(
            rules.contains(&"post:api.github.com/repos/acme/x/issues".to_string()),
            "{rules:?}"
        );
        assert_eq!(rules.len(), 3, "{rules:?}");
        let withheld: Vec<&str> = out.withheld.iter().map(|(t, _)| t.as_str()).collect();
        assert!(withheld.contains(&"169.254.169.254:80"), "{withheld:?}");
        assert!(
            withheld.contains(&"metadata.google.internal:80"),
            "{withheld:?}"
        );
        assert!(withheld.contains(&"evil.test:443"), "{withheld:?}");
        assert!(
            out.withheld.iter().any(|(_, why)| why.contains("glob")),
            "a literal `*` in a requested path is never proposed as a glob: {:?}",
            out.withheld
        );
    }

    #[test]
    fn fw_disc12_channels_already_lifted_are_not_proposed() {
        use crate::{Channel, ChannelPolicy};
        let lifted = ChannelPolicy::allow([Channel::Clipboard]);
        assert_eq!(
            propose_channels(
                &[Channel::OpenUrl, Channel::Clipboard, Channel::OpenUrl],
                &lifted
            ),
            vec![Channel::OpenUrl]
        );
    }
}
