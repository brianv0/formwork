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

/// A deny the Launcher added to one session for a credential type: the file a Catalog
/// `env-file-refs` variable names (FW-CRED3). The path has no Catalog shape, so discovery floors
/// on these beside the Catalog (FW-DISC15).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LauncherDeny {
    pub pattern: PathPattern,
    pub credential_type: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposalOutcome {
    pub candidates: Vec<Candidate>,
    pub withheld: Vec<WithheldEntry>,
    /// Denied paths with a `**` component. A grant spells that component as a pattern, so no
    /// grant covers the literal path alone; itemized to the operator, never proposed.
    pub unproposable: Vec<String>,
}

/// Denials -> tagged candidates. Deterministic: inputs are deduped and sorted; sibling paths
/// (>= 2 sharing a parent, same access) fold into one `parent/**` candidate unless the folded
/// pattern would cross the credential floor, in which case the individual paths stand.
pub fn reverse_compile(
    records: &[DenialRecord],
    catalog: &ResolvedCatalog,
    launcher_denies: &[LauncherDeny],
    allow: &[String],
    auto_widen: &[PathPattern],
) -> ProposalOutcome {
    let mut seen = std::collections::BTreeSet::new();
    let mut withheld = Vec::new();
    let mut unproposable = Vec::new();
    let mut granular: Vec<(PathPattern, DenialAccess)> = Vec::new();

    for record in records {
        // The confined process chooses its own file names: parsed as a pattern, a denied
        // `/srv/**/config` would become an any-depth grant that no kernel record asked for.
        if record.path.split('/').any(|component| component == "**") {
            unproposable.push(record.path.clone());
            continue;
        }
        let Ok(pattern) = PathPattern::parse(&record.path) else {
            // Not an absolute kernel path (malformed log line); nothing enforceable to propose.
            continue;
        };
        if !seen.insert((pattern.canonical(), record.access)) {
            continue;
        }
        // FW-DISC15: the Launcher's own denies come first, so the entry names the type whose
        // variable pointed at the file.
        if let Some(deny) = launcher_denies
            .iter()
            .find(|deny| crate::catalog::floor_hit(&deny.pattern, &pattern))
        {
            withheld.push(WithheldEntry {
                path: record.path.clone(),
                credential_type: deny.credential_type.clone(),
            });
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
    unproposable.sort();
    unproposable.dedup();

    ProposalOutcome {
        candidates,
        withheld,
        unproposable,
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
    // No auto-widen zone: synthesis is a full grant set, not a proposal to tag/review. No
    // Launcher denies either: a recording is not a launched session.
    let outcome = reverse_compile(records, catalog, &[], allow, &[]);
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

/// A destination the Gateway refused as a policy decision (FW-DISC12): the host and port, the
/// refusal reason (FW-FID12), and for a request refused on an inspected host, its method and
/// canonical path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct EgressObservation {
    pub host: String,
    pub port: u16,
    pub reason: crate::RefusalReason,
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
/// names is proposed inspected (`allow:host`, FEP-6 §9 j); a request refused on an inspected host
/// is proposed as that method on that exact path. Metadata names, restricted addresses and names
/// refused for the class of address they resolved to are never proposed (FW-EGR19), and neither
/// is a host a `deny:` rule names -- lifting an authored deny is an authoring decision.
/// Deterministic: deduplicated and sorted.
pub fn propose_host_rules(
    observed: &[EgressObservation],
    table: Option<&crate::HostTable>,
) -> EgressProposal {
    use crate::{
        canonicalize_host, CanonicalPath, ConnectDecision, Denial, HostRule, HostTable, HttpMethod,
        RefusalReason, DEFAULT_HTTPS_PORT,
    };
    let empty = HostTable::default();
    let table = table.unwrap_or(&empty);
    let mut out = EgressProposal::default();
    for obs in observed {
        let Ok(host) = canonicalize_host(&obs.host) else {
            continue;
        };
        let target = format!("{host}:{}", obs.port);
        if host.is_restricted() || obs.reason == RefusalReason::AddressClass {
            out.withheld.push((
                target,
                "a metadata, private, loopback or special-purpose destination is never proposed \
                 (FW-EGR19); name it in a rule by hand if the session truly needs it"
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
            ConnectDecision::Deny(Denial {
                rule: Some(rule), ..
            }) => {
                out.withheld
                    .push((target, format!("denied by the rule `{rule}`")));
                continue;
            }
            ConnectDecision::Deny(Denial { rule: None, .. }) => {
                HostRule::parse("allow", &format!("{host}{port}"))
            }
            ConnectDecision::Inspect => {
                let (Some(method), Some(path)) = (&obs.method, &obs.path) else {
                    continue;
                };
                let Some(method) = HttpMethod::from_token(method) else {
                    out.withheld
                        .push((target, format!("the method {method:?} has no rule atom")));
                    continue;
                };
                let Ok(path) = CanonicalPath::parse(path) else {
                    continue;
                };
                // A requested path is a literal; `*` in it would become a glob in the rule and
                // widen the proposal past what the session asked for.
                if path.as_str().contains('*') {
                    out.withheld.push((
                        target,
                        format!("the path {path:?} carries `*`, which a rule would read as a glob"),
                    ));
                    continue;
                }
                HostRule::parse(method.atom(), &format!("{host}{port}{path}"))
            }
            // Admitted already: the refusal was not a missing rule.
            ConnectDecision::Tunnel(_) => continue,
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

/// Is this a host rule [`propose_host_rules`] can produce? `accept` reads the proposal as
/// untrusted input (FW-DISC3), so a rule of any other kind -- a `tunnel:` or `deny:` grade, a
/// wildcard host, a restricted destination, a path glob -- is an authoring decision that does not
/// pass through the review door (FW-DISC12). The error says which.
pub fn proposable_host_rule(rule: &crate::HostRule) -> Result<(), String> {
    use crate::{canonicalize_host, is_restricted_ip, HostAccess, HostPattern, PathGlob};
    let restricted = match &rule.host {
        HostPattern::Exact(name) => canonicalize_host(name)
            .map(|host| host.is_restricted())
            .unwrap_or(true),
        HostPattern::Ip(ip) => is_restricted_ip(*ip),
        HostPattern::Wildcard(_) => {
            return Err("discovery proposes exact hosts, never a wildcard".to_string())
        }
    };
    if restricted {
        return Err(
            "a metadata, private, loopback or special-purpose destination is never proposed \
             (FW-EGR19)"
                .to_string(),
        );
    }
    let proposed = match &rule.access {
        HostAccess::Tunnel => return Err("discovery never proposes a `tunnel:` grade".to_string()),
        HostAccess::Deny { .. } => {
            return Err("discovery never proposes a `deny:` rule".to_string())
        }
        HostAccess::Inspected { methods, path } if methods.is_empty() => *path == PathGlob::any(),
        HostAccess::Inspected { methods, path } => {
            methods.len() == 1 && !path.as_str().contains('*')
        }
    };
    if proposed {
        Ok(())
    } else {
        Err(
            "discovery proposes `allow:` for a whole host or one method on one literal path, \
             never a path glob"
                .to_string(),
        )
    }
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
        let out = reverse_compile(&records, &catalog(), &[], &[], &zone);
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
        let out = reverse_compile(&records, &catalog(), &[], &[], &zone);
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
        let out = reverse_compile(&records, &catalog(), &[], &[], &[]);
        assert_eq!(out.candidates.len(), 1);
        assert_eq!(out.candidates[0].pattern, pp("/opt/toolchain/**"));
    }

    #[test]
    fn fold_that_would_swallow_a_floor_path_stays_granular() {
        // Two denials directly in the fake home: folding to /home/x/** would cover ~/.ssh.
        let records = vec![read("/home/x/one.txt"), read("/home/x/two.txt")];
        let out = reverse_compile(&records, &catalog(), &[], &[], &[]);
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
        let out = reverse_compile(&records, &catalog(), &[], &[], &zone);

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
        let a = reverse_compile(&records, &catalog(), &[], &[], &[]);
        let b = reverse_compile(&records, &catalog(), &[], &[], &[]);
        assert_eq!(a, b);
        assert_eq!(a.candidates.len(), 2);
        assert!(a.candidates[0].pattern.canonical() < a.candidates[1].pattern.canonical());
    }

    #[test]
    fn excluded_type_is_no_longer_floored_for_discovery() {
        // FW-CRED5 is the one lift: with aws excluded, an aws-path denial may be proposed
        // (it is an ordinary path for this session), while ssh stays floored.
        let records = vec![read("/home/x/.aws/config"), read("/home/x/.ssh/config")];
        let out = reverse_compile(&records, &catalog(), &[], &["aws".to_string()], &[]);
        let patterns: Vec<String> = out
            .candidates
            .iter()
            .map(|c| c.pattern.canonical())
            .collect();
        assert_eq!(patterns, vec!["/home/x/.aws/config"]);
        assert_eq!(out.withheld.len(), 1);
    }

    /// The file a credential variable named has no Catalog shape, so only the Launcher's deny
    /// for it marks its denial as a credential's: withheld with the type, even inside the zone,
    /// and never folded back in through a sibling subtree.
    #[test]
    fn fw_disc15_a_launcher_deny_is_withheld_with_its_type() {
        let records = vec![
            read("/work/keys/sa.json"),
            read("/work/keys/a.txt"),
            read("/work/keys/b.txt"),
        ];
        let zone = vec![pp("/work/**")];
        let denies = vec![LauncherDeny {
            pattern: pp("/work/keys/sa.json"),
            credential_type: "gcp".to_string(),
        }];

        let out = reverse_compile(&records, &catalog(), &denies, &[], &zone);
        assert_eq!(
            out.withheld,
            vec![WithheldEntry {
                path: "/work/keys/sa.json".to_string(),
                credential_type: "gcp".to_string(),
            }]
        );
        let patterns: Vec<String> = out
            .candidates
            .iter()
            .map(|c| c.pattern.canonical())
            .collect();
        assert_eq!(patterns, vec!["/work/keys/a.txt", "/work/keys/b.txt"]);

        // Without the Launcher's deny the same denial is an ordinary in-zone candidate: the
        // path alone does not say the file is a credential.
        let unfloored = reverse_compile(&records, &catalog(), &[], &[], &zone);
        assert!(unfloored.withheld.is_empty());
        assert!(unfloored
            .candidates
            .iter()
            .any(|c| c.tag == CandidateTag::AutoAccepted && c.pattern.covers(&denies[0].pattern)));
    }

    /// A denied path is a literal. With a `**` component it would read back from the proposal as
    /// an any-depth or subtree pattern, a grant wider than anything the kernel refused.
    #[test]
    fn fw_disc2_an_observed_path_is_a_literal_never_a_pattern() {
        let records = vec![
            write("/srv/**/config"),
            write("/srv/data/**"),
            read("/srv/ok**/x"),
        ];
        let zone = vec![pp("/srv/**")];
        let out = reverse_compile(&records, &catalog(), &[], &[], &zone);
        assert_eq!(out.unproposable, vec!["/srv/**/config", "/srv/data/**"]);
        let patterns: Vec<String> = out
            .candidates
            .iter()
            .map(|c| c.pattern.canonical())
            .collect();
        assert_eq!(
            patterns,
            vec!["/srv/ok**/x"],
            "`**` inside a name is a name"
        );
        assert!(out
            .candidates
            .iter()
            .all(|c| !c.pattern.is_any_depth() && !c.pattern.is_subtree()));
    }

    /// `accept` holds a proposal's host rules to what [`propose_host_rules`] can produce.
    #[test]
    fn fw_disc12_only_the_rule_kinds_discovery_proposes_are_proposable() {
        let rule = |raw: &str| raw.parse::<crate::HostRule>().unwrap();
        for proposed in [
            "allow:blocked.test",
            "allow:registry.test:8443",
            "post:api.github.com/repos/acme/x/issues",
            "allow:93.184.216.34",
        ] {
            assert_eq!(proposable_host_rule(&rule(proposed)), Ok(()), "{proposed}");
        }
        for (forged, why) in [
            ("tunnel:git.corp.example", "tunnel"),
            ("deny:wiki.corp.example", "deny"),
            ("deny:wiki.corp.example/admin/**", "deny"),
            ("allow:*.corp.example", "wildcard"),
            ("allow:169.254.169.254", "FW-EGR19"),
            ("allow:metadata.google.internal", "FW-EGR19"),
            ("allow:10.0.0.7", "FW-EGR19"),
            ("allow:api.github.com/repos/**", "path glob"),
            ("get:api.github.com/repos/*/x", "path glob"),
            ("get,post:api.github.com/repos/acme/x", "path glob"),
        ] {
            let refusal = proposable_host_rule(&rule(forged)).unwrap_err();
            assert!(refusal.contains(why), "{forged}: {refusal}");
        }
    }

    fn obs(host: &str, port: u16, req: Option<(&str, &str)>) -> EgressObservation {
        EgressObservation {
            host: host.into(),
            port,
            reason: if req.is_some() {
                crate::RefusalReason::Path
            } else {
                crate::RefusalReason::HostNotListed
            },
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
                EgressObservation {
                    reason: crate::RefusalReason::AddressClass,
                    ..obs("rebound.test", 443, None)
                },
            ],
            Some(&table),
        );
        let rules: Vec<String> = out.rules.iter().map(|r| r.to_string()).collect();
        assert!(
            rules.contains(&"allow:blocked.test".to_string()),
            "{rules:?}"
        );
        assert!(
            rules.contains(&"allow:registry.test:8443".to_string()),
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
        assert!(withheld.contains(&"rebound.test:443"), "{withheld:?}");
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
