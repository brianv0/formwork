//! Monotonic narrowing (FW-CAP2): `parent.narrow(&requested)` intersects two capability sets into a
//! subset of both. The deny-holes -- `subtract` (secrets) and `write_subtract` (tamper vectors) --
//! grow under narrowing, so they union. The grant intersection is conservative -- it may
//! under-approximate but never over-approximate, so the result is always a genuine subset.

use crate::path::{canonicalize_set, PathPattern};
use crate::{
    Blueprint, DiscoveryBlueprint, EnvPosture, EnvScrub, ExecPosture, FsBlueprint, Gate, McpPolicy,
    NetPosture, ReadMode, Visibility,
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
            allow_credentials: self
                .allow_credentials
                .iter()
                .filter(|t| requested.allow_credentials.contains(t))
                .cloned()
                .collect(),
            // The auto-widen zone (FW-DISC4) is authority to self-grant, so it intersects too.
            discovery: DiscoveryBlueprint {
                auto_widen: intersect_grants(
                    &self.discovery.auto_widen,
                    &requested.discovery.auto_widen,
                ),
            },
        }
        .canonicalize()
    }
}

fn narrow_fs(parent: &FsBlueprint, req: &FsBlueprint) -> FsBlueprint {
    let subtract = union_grants(&parent.subtract, &req.subtract);
    // Write-deny holes, like read+write holes, only ever grow under narrowing.
    let write_subtract = union_grants(&parent.write_subtract, &req.write_subtract);
    let writes = intersect_grants(&parent.writes, &req.writes);

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
    match (parent, req) {
        (Visibility::Deny, _) | (_, Visibility::Deny) => Visibility::Deny,
        (Visibility::AllowAll, other) | (other, Visibility::AllowAll) => other.clone(),
        (Visibility::Allow(a), Visibility::Allow(b)) => {
            let names: Vec<String> = a.iter().filter(|n| b.contains(n)).cloned().collect();
            if names.is_empty() {
                Visibility::Deny
            } else {
                Visibility::Allow(names)
            }
        }
    }
}

/// The result admits a subset of what either side admits (FW-CAP2). `Passthrough` admits everything,
/// so it yields to the other side; otherwise restrictions combine (allowlists intersect, scrub denies
/// union). For a mixed Allowlist/Scrub the only names Scrub is *guaranteed* to keep are its `allow`
/// set (any other name may be dropped by value shape, which narrowing cannot evaluate), so the sound
/// subset is the allowlist intersected with Scrub's `allow` -- an under-approximation, never wider
/// than either side.
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
        | (EnvPosture::Scrub(s), EnvPosture::Allowlist(a)) => {
            EnvPosture::Allowlist(a.iter().filter(|n| s.allow.contains(n)).cloned().collect())
        }
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
                tools: Visibility::AllowAll,
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
        let n = mk(Visibility::Allow(vec!["a".into(), "b".into()]))
            .narrow(&mk(Visibility::Allow(vec!["b".into(), "c".into()])));
        assert_eq!(n.mcp["s"].tools, Visibility::Allow(vec!["b".into()]));

        let n2 = mk(Visibility::AllowAll).narrow(&mk(Visibility::Allow(vec!["x".into()])));
        assert_eq!(n2.mcp["s"].tools, Visibility::Allow(vec!["x".into()]));
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
    fn narrowing_is_idempotent() {
        let s = Blueprint {
            fs: FsBlueprint {
                reads: vec![pp("/work/**")],
                writes: vec![pp("/work/project/**")],
                subtract: vec![pp("/work/.ssh/**")],
                ..Default::default()
            },
            net: NetPosture::Ports(vec![8080, 80]),
            ..Blueprint::empty()
        };
        assert_eq!(s.narrow(&s), s.canonicalize());
    }
}
