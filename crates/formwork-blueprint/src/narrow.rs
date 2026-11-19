//! Monotonic narrowing (FW-CAP2): `parent.narrow(&requested)` intersects two capability sets into a
//! subset of both. The deny-holes -- `subtract` (secrets) and `write_subtract` (tamper vectors) --
//! grow under narrowing, so they union. The grant intersection is conservative -- it may
//! under-approximate but never over-approximate, so the result is always a genuine subset.

use crate::credential::exposed_types;
use crate::path::{canonicalize_set, canonicalize_write_set, PathPattern};
use crate::{
    AllowScope, Blueprint, CredentialEntry, DiscoveryBlueprint, EnvPosture, EnvScrub, ExecPosture,
    FsBlueprint, Gate, McpPolicy, NetPosture, Pattern, ReadMode, Visibility,
};

fn clamp_to(subject: &[PathPattern], bound: &[PathPattern]) -> Vec<PathPattern> {
    subject
        .iter()
        .filter(|p| bound.iter().any(|b| b.covers(p)))
        .cloned()
        .collect()
}

/// Subset of both inputs. Public because the compiler clamps the credential-floor exemption to
/// the blueprint's own grant surface with it (FW-CRED5) -- an exemption must lift a floor hole,
/// never widen a grant.
pub fn intersect_grants(a: &[PathPattern], b: &[PathPattern]) -> Vec<PathPattern> {
    let mut out = clamp_to(a, b);
    out.extend(clamp_to(b, a));
    canonicalize_set(&out)
}

fn union_grants(a: &[PathPattern], b: &[PathPattern]) -> Vec<PathPattern> {
    let mut out = a.to_vec();
    out.extend_from_slice(b);
    canonicalize_set(&out)
}

impl Blueprint {
    /// The result is a subset of both `self` (parent) and `requested` (FW-CAP2).
    pub fn narrow(&self, requested: &Blueprint) -> Blueprint {
        Blueprint {
            fs: narrow_fs(&self.fs, &requested.fs),
            net: narrow_net(&self.net, &requested.net),
            exec: narrow_exec(&self.exec, &requested.exec),
            env: narrow_env(&self.env, &requested.env),
            mcp: narrow_mcp(&self.mcp, &requested.mcp),
            // Letting a credential type through (FW-CRED5) is authority, so it intersects: a child
            // cannot un-block a type its parent kept blocked.
            allow_credentials: narrow_credentials(
                &self.allow_credentials,
                &requested.allow_credentials,
            ),
            // The auto-widen zone (FW-DISC4) is authority to self-grant, so it intersects too.
            discovery: DiscoveryBlueprint {
                auto_widen: intersect_grants(
                    &self.discovery.auto_widen,
                    &requested.discovery.auto_widen,
                ),
            },
            // A channel lift is authority: a child keeps only the lifts both hold, and a deny
            // from either side stays terminal (FW-BP10).
            channels: crate::ChannelPolicy::allow(
                crate::Channel::ALL
                    .into_iter()
                    .filter(|c| self.channels.lifted(*c) && requested.channels.lifted(*c)),
            )
            .with_deny(
                self.channels
                    .denied()
                    .iter()
                    .chain(requested.channels.denied().iter())
                    .copied(),
            ),
            // Isolation only ever grows under narrowing: a member either side requests is kept.
            isolate: self
                .isolate
                .iter()
                .chain(requested.isolate.iter())
                .copied()
                .collect(),
        }
        .canonicalize()
    }
}

/// Exposing a type and brokering it are different authorities over it, and a type named both ways
/// is brokered, not exposed (FW-BP12). Intersecting the entries as written would keep the bare
/// name where one side holds it only beside its `broker:` form, and so expose a credential that
/// side never let into a session. Each authority survives where both sides hold it once that
/// rule is applied.
fn narrow_credentials(parent: &[CredentialEntry], req: &[CredentialEntry]) -> Vec<CredentialEntry> {
    let exposed_by_req = exposed_types(req);
    let mut out: Vec<CredentialEntry> = exposed_types(parent)
        .into_iter()
        .filter(|t| exposed_by_req.contains(t))
        .map(CredentialEntry::Expose)
        .collect();
    out.extend(
        parent
            .iter()
            .filter(|e| !matches!(e, CredentialEntry::Expose(_)) && req.contains(e))
            .cloned(),
    );
    out
}

/// A literal write grant is also a pathname-socket grant (FW-ISO12); a subtree that covers the
/// same path is not. A literal one side holds and the other covers only by subtree would hand
/// the result a socket that side never granted, so a literal survives only where both sides
/// write it as a literal. The file grant is lost with it: an under-approximation.
fn narrow_writes(parent: &[PathPattern], req: &[PathPattern]) -> Vec<PathPattern> {
    let names_one_file = |p: &PathPattern| !p.is_subtree() && !p.is_any_depth();
    let mut out: Vec<PathPattern> = intersect_grants(parent, req)
        .into_iter()
        .filter(|p| !names_one_file(p))
        .collect();
    out.extend(
        parent
            .iter()
            .filter(|p| names_one_file(p) && req.contains(p))
            .cloned(),
    );
    canonicalize_write_set(&out)
}

fn narrow_fs(parent: &FsBlueprint, req: &FsBlueprint) -> FsBlueprint {
    let subtract = union_grants(&parent.subtract, &req.subtract);
    // Write-deny holes, like read+write holes, only ever grow under narrowing.
    let write_subtract = union_grants(&parent.write_subtract, &req.write_subtract);
    let writes = narrow_writes(&parent.writes, &req.writes);
    // A weaker write grant narrows like any grant: a child keeps only what both allow.
    let writes_no_create = intersect_grants(&parent.writes_no_create, &req.writes_no_create);

    // The narrower read mode wins (Closed < AmbientMinusSubtract).
    let (read_mode, reads) = match (parent.read_mode, req.read_mode) {
        (ReadMode::AmbientMinusSubtract, ReadMode::AmbientMinusSubtract) => (
            ReadMode::AmbientMinusSubtract,
            union_grants(&parent.reads, &req.reads),
        ),
        (ReadMode::Closed, ReadMode::Closed) => (
            ReadMode::Closed,
            intersect_grants(&parent.reads, &req.reads),
        ),
        // Closed bounds Ambient: the Closed side's grants bound the result; the Ambient side
        // contributes only its subtract holes (already unioned above).
        (ReadMode::Closed, ReadMode::AmbientMinusSubtract) => {
            (ReadMode::Closed, parent.reads.clone())
        }
        (ReadMode::AmbientMinusSubtract, ReadMode::Closed) => (ReadMode::Closed, req.reads.clone()),
    };

    FsBlueprint {
        read_mode,
        reads: canonicalize_set(&reads),
        writes,
        writes_no_create,
        subtract,
        write_subtract,
    }
}

fn narrow_net(parent: &NetPosture, req: &NetPosture) -> NetPosture {
    match (parent, req) {
        (NetPosture::Deny, _) | (_, NetPosture::Deny) => NetPosture::Deny,
        (NetPosture::Ports(a), NetPosture::Ports(b)) => {
            let ports: Vec<u16> = a.iter().copied().filter(|p| b.contains(p)).collect();
            if ports.is_empty() {
                NetPosture::Deny
            } else {
                NetPosture::Ports(ports)
            }
        }
        // A child keeps only host rules its parent also holds, and every deny either side wrote
        // (FW-CAP2). Mixing a port tier with a host table narrows to deny: the two reach the network
        // by different doors, and neither is a subset of the other.
        (NetPosture::AllowHosts(a), NetPosture::AllowHosts(b)) => {
            let rules: Vec<crate::HostRule> = b
                .rules
                .iter()
                .filter(|r| {
                    matches!(r.access, crate::HostAccess::Deny { .. }) || a.rules.contains(r)
                })
                .chain(
                    a.rules
                        .iter()
                        .filter(|r| matches!(r.access, crate::HostAccess::Deny { .. })),
                )
                .cloned()
                .collect();
            NetPosture::AllowHosts(crate::HostTable::new(rules))
        }
        (NetPosture::AllowHosts(_), NetPosture::Ports(_))
        | (NetPosture::Ports(_), NetPosture::AllowHosts(_)) => NetPosture::Deny,
    }
}

fn narrow_exec(parent: &ExecPosture, req: &ExecPosture) -> ExecPosture {
    match (parent, req) {
        (ExecPosture::Unrestricted, ExecPosture::Unrestricted) => ExecPosture::Unrestricted,
        (ExecPosture::Unrestricted, ExecPosture::Allowlist(a))
        | (ExecPosture::Allowlist(a), ExecPosture::Unrestricted) => {
            ExecPosture::Allowlist(canonicalize_set(a))
        }
        (ExecPosture::Allowlist(a), ExecPosture::Allowlist(b)) => {
            ExecPosture::Allowlist(intersect_grants(a, b))
        }
    }
}

fn narrow_mcp(
    parent: &std::collections::BTreeMap<String, McpPolicy>,
    req: &std::collections::BTreeMap<String, McpPolicy>,
) -> std::collections::BTreeMap<String, McpPolicy> {
    // Only servers present in both survive: requested can't introduce a server the parent lacked.
    let mut out = std::collections::BTreeMap::new();
    for (name, rp) in req {
        if let Some(pp) = parent.get(name) {
            out.insert(name.clone(), narrow_mcp_policy(pp, rp));
        }
    }
    out
}

fn narrow_mcp_policy(parent: &McpPolicy, req: &McpPolicy) -> McpPolicy {
    McpPolicy {
        tools: narrow_visibility(&parent.tools, &req.tools),
        resources: narrow_visibility(&parent.resources, &req.resources),
        prompts: narrow_visibility(&parent.prompts, &req.prompts),
        sampling: narrow_gate(parent.sampling, req.sampling),
        elicitation: narrow_gate(parent.elicitation, req.elicitation),
    }
}

fn narrow_visibility(parent: &Visibility, req: &Visibility) -> Visibility {
    let allow = narrow_allow(&parent.allow, &req.allow);
    // A deny from *either* layer applies: deny holes only grow under narrowing, like the fs
    // `subtract`/`write_subtract` sets, so the deny lists union (deny is terminal, FW-GW9/FW-CAP8).
    let mut deny = parent.deny.clone();
    for p in &req.deny {
        if !deny.contains(p) {
            deny.push(p.clone());
        }
    }
    Visibility { allow, deny }.canonicalize()
}

fn narrow_allow(parent: &AllowScope, req: &AllowScope) -> AllowScope {
    match (parent, req) {
        (AllowScope::Nothing, _) | (_, AllowScope::Nothing) => AllowScope::Nothing,
        (AllowScope::All, other) | (other, AllowScope::All) => other.clone(),
        (AllowScope::Only(a), AllowScope::Only(b)) => {
            // Sound subset: keep the entries present in *both* lists (by authoring form). For exact
            // names this is set intersection; for regexes it is conservative -- only identical
            // sources survive -- which under-approximates but never widens (FW-CAP2 forbids only
            // widening).
            let both: Vec<Pattern> = a.iter().filter(|p| b.contains(p)).cloned().collect();
            if both.is_empty() {
                AllowScope::Nothing
            } else {
                AllowScope::Only(both)
            }
        }
    }
}

/// The result admits a subset of what either side admits (FW-CAP2). `Passthrough` admits everything,
/// so it yields to the other side; otherwise restrictions combine (allowlists intersect, scrub denies
/// union). For a mixed Allowlist/Scrub the only names Scrub is *guaranteed* to keep are its `allow`
/// set less its `deny` set, which wins (FW-ENV2), and less git's numbered config variables, which
/// Scrub keeps or drops as whole entries. Any other name may be dropped by value shape, which
/// narrowing cannot evaluate, so the sound subset is the allowlist intersected with those names --
/// an under-approximation, never wider than either side.
fn narrow_env(parent: &EnvPosture, req: &EnvPosture) -> EnvPosture {
    match (parent, req) {
        (EnvPosture::Passthrough, other) | (other, EnvPosture::Passthrough) => other.clone(),
        (EnvPosture::Allowlist(a), EnvPosture::Allowlist(b)) => {
            EnvPosture::Allowlist(a.iter().filter(|n| b.contains(n)).cloned().collect())
        }
        (EnvPosture::Scrub(a), EnvPosture::Scrub(b)) => EnvPosture::Scrub(EnvScrub {
            allow: a
                .allow
                .iter()
                .filter(|n| b.allow.contains(n))
                .cloned()
                .collect(),
            deny: {
                let mut d = a.deny.clone();
                d.extend(b.deny.iter().cloned());
                d
            },
        }),
        (EnvPosture::Allowlist(a), EnvPosture::Scrub(s))
        | (EnvPosture::Scrub(s), EnvPosture::Allowlist(a)) => EnvPosture::Allowlist(
            a.iter()
                .filter(|n| s.allow.contains(n) && !s.deny.contains(n))
                .filter(|n| !crate::is_git_config_env(n))
                .cloned()
                .collect(),
        ),
    }
}

fn narrow_gate(parent: Gate, req: Gate) -> Gate {
    if parent == Gate::Allow && req == Gate::Allow {
        Gate::Allow
    } else {
        Gate::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PathPattern;
    use std::collections::BTreeMap;

    fn pp(s: &str) -> PathPattern {
        PathPattern::parse(s).unwrap()
    }

    #[test]
    fn read_intersection_clamps_to_narrower() {
        let parent = Blueprint {
            fs: FsBlueprint {
                reads: vec![pp("/work/**")],
                ..Default::default()
            },
            ..Blueprint::empty()
        };
        let req = Blueprint {
            fs: FsBlueprint {
                reads: vec![pp("/work/project/**"), pp("/etc/**")],
                ..Default::default()
            },
            ..Blueprint::empty()
        };
        let n = parent.narrow(&req);
        // /work/project survives (covered by parent /work); /etc is dropped.
        assert_eq!(n.fs.reads, vec![pp("/work/project/**")]);
    }

    #[test]
    fn subtract_unions_under_narrowing() {
        let parent = Blueprint {
            fs: FsBlueprint {
                subtract: vec![pp("/a/**")],
                ..Default::default()
            },
            ..Blueprint::empty()
        };
        let req = Blueprint {
            fs: FsBlueprint {
                subtract: vec![pp("/b/**")],
                ..Default::default()
            },
            ..Blueprint::empty()
        };
        let n = parent.narrow(&req);
        assert_eq!(n.fs.subtract, vec![pp("/a/**"), pp("/b/**")]);
    }

    #[test]
    fn net_narrows_to_deny_or_intersection() {
        let ports = |v: Vec<u16>| Blueprint {
            net: NetPosture::Ports(v),
            ..Blueprint::empty()
        };
        assert_eq!(
            ports(vec![80, 443]).narrow(&ports(vec![443, 8080])).net,
            NetPosture::Ports(vec![443])
        );
        assert_eq!(
            ports(vec![80]).narrow(&ports(vec![443])).net,
            NetPosture::Deny
        );
        assert_eq!(
            ports(vec![80]).narrow(&Blueprint::empty()).net,
            NetPosture::Deny
        );
    }

    #[test]
    fn mcp_server_absent_in_parent_cannot_appear() {
        let mut req_mcp = BTreeMap::new();
        req_mcp.insert(
            "secret".to_string(),
            McpPolicy {
                tools: Visibility::all(),
                ..Default::default()
            },
        );
        let req = Blueprint {
            mcp: req_mcp,
            ..Blueprint::empty()
        };
        let n = Blueprint::empty().narrow(&req);
        assert!(n.mcp.is_empty());
    }

    #[test]
    fn mcp_visibility_intersects() {
        let mk = |v: Visibility| {
            let mut m = BTreeMap::new();
            m.insert(
                "s".to_string(),
                McpPolicy {
                    tools: v,
                    ..Default::default()
                },
            );
            Blueprint {
                mcp: m,
                ..Blueprint::empty()
            }
        };
        let n = mk(Visibility::allow_exact(["a", "b"]))
            .narrow(&mk(Visibility::allow_exact(["b", "c"])));
        assert_eq!(n.mcp["s"].tools, Visibility::allow_exact(["b"]));

        let n2 = mk(Visibility::all()).narrow(&mk(Visibility::allow_exact(["x"])));
        assert_eq!(n2.mcp["s"].tools, Visibility::allow_exact(["x"]));
    }

    #[test]
    fn mcp_deny_unions_and_wins_under_narrowing() {
        // A deny from *either* side survives (deny is terminal, FW-GW9): the child cannot un-deny a
        // tool its parent denied, and the parent inherits the child's deny too.
        let mk = |v: Visibility| {
            let mut m = BTreeMap::new();
            m.insert(
                "s".to_string(),
                McpPolicy {
                    tools: v,
                    ..Default::default()
                },
            );
            Blueprint {
                mcp: m,
                ..Blueprint::empty()
            }
        };
        let parent = mk(Visibility::all()
            .with_deny(&["/delete_.*/".into()])
            .unwrap());
        let child = mk(Visibility::parse(&["/(get|delete)_.*/".into()], &[]).unwrap());
        let n = parent.narrow(&child);
        let tools = &n.mcp["s"].tools;
        assert!(
            tools.permits("get_item"),
            "child's allow, not denied by either"
        );
        assert!(
            !tools.permits("delete_item"),
            "parent's deny is terminal even under the child's allow"
        );
    }

    #[test]
    fn env_narrow_never_admits_more_than_either_side() {
        // A name the *request* scrubs must not survive narrowing (FW-CAP2). Regression for the mixed
        // Allowlist/Scrub case that previously returned the parent allowlist verbatim.
        let parent = Blueprint {
            env: EnvPosture::Allowlist(vec!["PATH".into(), "GH_TOKEN".into()]),
            ..Blueprint::empty()
        };
        let req = Blueprint {
            env: EnvPosture::Scrub(EnvScrub {
                allow: vec!["PATH".into()],
                deny: vec!["GH_TOKEN".into()],
            }),
            ..Blueprint::empty()
        };
        let admits = |bp: &Blueprint, name: &str| {
            !bp.env
                .apply(vec![(name.to_string(), "x".to_string())])
                .is_empty()
        };
        let n = parent.narrow(&req);
        // req keeps PATH (in its allow) and drops GH_TOKEN (in its deny); the result must not exceed that.
        assert!(
            !admits(&n, "GH_TOKEN"),
            "narrow must not admit a var the request scrubbed"
        );
        assert!(admits(&req, "PATH") && admits(&parent, "PATH"));
        assert_eq!(n.env, EnvPosture::Allowlist(vec!["PATH".into()]));
    }

    #[test]
    fn fw_cap2_a_literal_write_under_a_subtree_gains_no_socket() {
        let writes = |patterns: &[&str]| Blueprint {
            fs: FsBlueprint {
                writes: patterns.iter().map(|p| pp(p)).collect(),
                ..Default::default()
            },
            ..Blueprint::empty()
        };
        let subtree = writes(&["/run/user/1000/**"]);
        let literal = writes(&["/run/user/1000/bus"]);
        // Neither order may yield the literal: the subtree's holder granted no socket.
        assert!(subtree.narrow(&literal).fs.writes.is_empty());
        assert!(literal.narrow(&subtree).fs.writes.is_empty());
        // Held as a literal by both, it survives beside the subtree both also hold.
        let both = writes(&["/run/user/1000/**", "/run/user/1000/bus"]);
        assert_eq!(both.narrow(&both).fs.writes, both.canonicalize().fs.writes);
        assert_eq!(both.narrow(&literal).fs.writes, literal.fs.writes);
    }

    #[test]
    fn fw_cap2_a_brokered_type_is_not_exposed_by_narrowing() {
        let credentials = |entries: &[&str]| Blueprint {
            allow_credentials: entries.iter().map(|e| (*e).into()).collect(),
            ..Blueprint::empty()
        };
        let brokered = credentials(&["github", "broker:github", "aws"]);
        let bare = credentials(&["github", "aws"]);
        for n in [brokered.narrow(&bare), bare.narrow(&brokered)] {
            assert_eq!(n.exposed_credentials(), ["aws"]);
            assert_eq!(n.brokered_credentials().count(), 0);
        }
        let n = brokered.narrow(&credentials(&["broker:github", "broker:aws"]));
        assert!(n.exposed_credentials().is_empty());
        assert_eq!(n.allow_credentials, vec!["broker:github".into()]);
    }

    /// Every probe a blueprint answers yes to: one string per held authority, over a fixed set of
    /// paths, variables, endpoints and names. Isolation is held as the authority to share.
    fn held(bp: &Blueprint) -> std::collections::BTreeSet<String> {
        use std::path::Path;
        let mut out = std::collections::BTreeSet::new();
        let any = |rows: &[PathPattern], p: &Path| rows.iter().any(|row| row.matches_path(p));
        for raw in [
            "/run/user/1000/bus",
            "/run/user/1000/other",
            "/work/a",
            "/work/project/x",
            "/work/project/sock",
            "/etc/hosts",
        ] {
            let p = Path::new(raw);
            let denied = any(&bp.fs.subtract, p);
            let write_denied = denied || any(&bp.fs.write_subtract, p);
            let wrote = any(&bp.fs.writes, p);
            let modified = wrote || any(&bp.fs.writes_no_create, p);
            let facts = [
                (
                    "read",
                    !denied
                        && (bp.fs.read_mode == ReadMode::AmbientMinusSubtract
                            || modified
                            || any(&bp.fs.reads, p)),
                ),
                ("write", !write_denied && wrote),
                ("modify", !write_denied && modified),
                (
                    "socket",
                    !write_denied && bp.fs.writes.iter().any(|w| *w == pp(raw)),
                ),
                (
                    "exec",
                    match &bp.exec {
                        ExecPosture::Unrestricted => true,
                        ExecPosture::Allowlist(paths) => any(paths, p),
                    },
                ),
                ("auto-widen", any(&bp.discovery.auto_widen, p)),
            ];
            out.extend(
                facts
                    .iter()
                    .filter(|(_, yes)| *yes)
                    .map(|(f, _)| format!("{f} {raw}")),
            );
        }
        for (name, value) in [
            ("PATH", "/usr/bin"),
            ("EDITOR", "vim"),
            ("GH_TOKEN", "t"),
            ("DEPLOY", "ghp_x"),
            ("GIT_CONFIG_KEY_0", "user.name"),
        ] {
            if !bp.env.apply(vec![(name.into(), value.into())]).is_empty() {
                out.insert(format!("env {name}"));
            }
        }
        match &bp.net {
            NetPosture::Deny => {}
            NetPosture::Ports(ports) => out.extend(ports.iter().map(|p| format!("port {p}"))),
            NetPosture::AllowHosts(table) => {
                for (host, port, path) in [
                    ("api.example.com", 443, "/v1/x"),
                    ("api.example.com", 443, "/admin/x"),
                    ("git.example.com", 443, "/x"),
                    ("other.example.com", 443, "/x"),
                    ("other.example.com", 8443, "/x"),
                ] {
                    let name = crate::canonicalize_host(host).unwrap();
                    let path = crate::CanonicalPath::parse(path).unwrap();
                    for method in [crate::HttpMethod::Get, crate::HttpMethod::Post] {
                        if table.decide(&name, port, Some(method), &path).is_ok() {
                            out.insert(format!("{} {host}:{port}{path}", method.atom()));
                        }
                    }
                }
            }
        }
        out.extend(
            bp.exposed_credentials()
                .iter()
                .map(|t| format!("expose {t}")),
        );
        out.extend(
            bp.brokered_credentials()
                .map(|e| format!("broker {}", e.name())),
        );
        for channel in crate::Channel::ALL {
            if bp.channels.lifted(channel) {
                out.insert(format!("channel {}", channel.name()));
            }
        }
        for member in [crate::IsolateMember::Processes, crate::IsolateMember::Ipc] {
            if !bp.isolate.contains(&member) {
                out.insert(format!("shares {member:?}"));
            }
        }
        for (server, policy) in &bp.mcp {
            for name in ["get_item", "delete_item", "other"] {
                if policy.tools.permits(name) {
                    out.insert(format!("mcp {server} tool {name}"));
                }
                if policy.resources.permits(name) {
                    out.insert(format!("mcp {server} resource {name}"));
                }
            }
            if policy.sampling == Gate::Allow {
                out.insert(format!("mcp {server} sampling"));
            }
        }
        out
    }

    /// FW-CAP2 over every ordered pair of a fixed sample: what the narrowed blueprint holds, each
    /// side holds. The sample puts a literal beside a covering subtree, a bare type beside its
    /// brokered form, an allowlist beside a scrub that denies one of its names, and every posture
    /// of each axis, on each side.
    #[test]
    fn fw_cap2_narrowing_holds_nothing_either_side_lacks() {
        let sample: Vec<Blueprint> = [
            r#"
            "#,
            r#"
            exec = "unrestricted"
            env = "passthrough"
            net = { ports = [80, 443] }
            allow-credentials = ["github", "aws"]
            channels = ["desktop", "media"]
            [fs]
            read-mode = "ambient-minus-subtract"
            writes = ["/**"]
            [discovery]
            auto-widen = ["/**"]
            [mcp.s]
            tools = "allow-all"
            resources = "allow-all"
            sampling = "allow"
            "#,
            r#"
            allow-credentials = ["github", "broker:github", "aws"]
            env = { scrub = { allow = ["GH_TOKEN", "PATH", "DEPLOY"], deny = ["GH_TOKEN"] } }
            channels = { allow = ["clipboard", "screen"], deny = ["screen"] }
            isolate = ["processes"]
            [fs]
            reads = ["/etc/**"]
            writes = ["/run/user/1000/**", "/work/**"]
            subtract = ["/work/a"]
            [discovery]
            auto-widen = ["/work/**"]
            [mcp.s]
            tools = { deny = ["/delete_.*/"] }
            resources = { allow = ["get_item"] }
            sampling = "allow"
            "#,
            r#"
            allow-credentials = ["github"]
            env = { allowlist = ["GH_TOKEN", "PATH", "DEPLOY", "GIT_CONFIG_KEY_0"] }
            channels = ["clipboard", "screen", "run-outside"]
            exec = { allowlist = ["/work/**"] }
            [fs]
            reads = ["/etc/hosts", "/work/**"]
            writes = ["/run/user/1000/bus", "/work/project/sock"]
            writes-no-create = ["/etc/hosts"]
            [discovery]
            auto-widen = ["/work/project/**"]
            [mcp.s]
            tools = { allow = ["get_item", "delete_item"] }
            resources = "allow-all"
            "#,
            r#"
            allow-credentials = ["broker:github", "aws"]
            env = { scrub = { allow = ["GH_TOKEN", "GIT_CONFIG_KEY_0", "DEPLOY"] } }
            net = { ports = [443, 8080] }
            exec = { allowlist = ["/work/project/x"] }
            isolate = ["ipc"]
            [fs]
            read-mode = "ambient-minus-subtract"
            writes = ["/work/**", "/work/project/sock", "/run/user/1000/bus"]
            writes-no-create = ["/etc/**"]
            write-subtract = ["/work/project/x"]
            [mcp.s]
            tools = { allow = ["get_item"] }
            [mcp.t]
            tools = "allow-all"
            "#,
        ]
        .iter()
        .map(|src| toml::from_str(src).unwrap())
        .chain(
            [
                &[
                    "allow:api.example.com",
                    "deny:api.example.com/admin/**",
                    "tunnel:git.example.com",
                ][..],
                &[
                    "get:api.example.com",
                    "tunnel:git.example.com",
                    "allow:other.example.com",
                ][..],
                &["allow:api.example.com", "deny:other.example.com"][..],
            ]
            .iter()
            .map(|rules| Blueprint {
                net: NetPosture::AllowHosts(crate::HostTable::new(
                    rules.iter().map(|r| r.parse().unwrap()).collect(),
                )),
                ..Blueprint::empty()
            }),
        )
        .collect();

        for (i, parent) in sample.iter().enumerate() {
            for (j, requested) in sample.iter().enumerate() {
                let narrowed = held(&parent.narrow(requested));
                for (side, name) in [(parent, "parent"), (requested, "requested")] {
                    let side = held(side);
                    let gained: Vec<&String> = narrowed.difference(&side).collect();
                    assert!(
                        gained.is_empty(),
                        "sample[{i}].narrow(sample[{j}]) holds what its {name} lacks: {gained:?}"
                    );
                }
            }
        }
        // The probes can tell the sample apart: no two members hold the same set.
        let distinct: std::collections::BTreeSet<_> = sample.iter().map(held).collect();
        assert_eq!(distinct.len(), sample.len());
    }

    #[test]
    fn narrowing_is_idempotent() {
        let s = Blueprint {
            fs: FsBlueprint {
                reads: vec![pp("/work/**")],
                writes: vec![pp("/work/project/**")],
                writes_no_create: vec![],
                subtract: vec![pp("/work/.ssh/**")],
                ..Default::default()
            },
            net: NetPosture::Ports(vec![8080, 80]),
            ..Blueprint::empty()
        };
        assert_eq!(s.narrow(&s), s.canonicalize());
    }

    #[test]
    fn writes_no_create_intersects_like_a_grant() {
        // A weaker write grant (FW-CAP9) narrows per-field like any other grant (FW-CAP2).
        let parent = Blueprint {
            fs: FsBlueprint {
                writes_no_create: vec![pp("/work/**")],
                ..Default::default()
            },
            ..Blueprint::empty()
        };
        let req = Blueprint {
            fs: FsBlueprint {
                writes_no_create: vec![pp("/work/logs/**"), pp("/etc/**")],
                ..Default::default()
            },
            ..Blueprint::empty()
        };
        // /work/logs survives (covered by parent /work); /etc is dropped.
        assert_eq!(
            parent.narrow(&req).fs.writes_no_create,
            vec![pp("/work/logs/**")]
        );
    }

    #[test]
    fn narrowing_across_write_grades_is_conservative() {
        // Grades don't merge across fields: per-field intersection drops both rather than widen the
        // no-create child into a full grant -- fail-closed, the direction narrowing must take.
        let full_parent = Blueprint {
            fs: FsBlueprint {
                writes: vec![pp("/work/**")],
                ..Default::default()
            },
            ..Blueprint::empty()
        };
        let no_create_child = Blueprint {
            fs: FsBlueprint {
                writes_no_create: vec![pp("/work/build")],
                ..Default::default()
            },
            ..Blueprint::empty()
        };
        let n = full_parent.narrow(&no_create_child);
        assert!(n.fs.writes.is_empty());
        assert!(n.fs.writes_no_create.is_empty());
    }
}
