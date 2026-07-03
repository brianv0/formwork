//! Monotonic narrowing (FW-CAP2): `parent.narrow(&requested)` intersects two capability sets into a
//! subset of both. `subtract` (sensitive holes) is the one set that grows under narrowing, so it
//! unions. The grant intersection is conservative -- it may under-approximate but never over-
//! approximate, so the result is always a genuine subset.

use crate::path::{canonicalize_set, PathPattern};
use crate::{ExecPosture, FsSpec, Gate, McpPolicy, NetPosture, ReadMode, Spec, Visibility};

fn clamp_to(subject: &[PathPattern], bound: &[PathPattern]) -> Vec<PathPattern> {
    subject
        .iter()
        .filter(|p| bound.iter().any(|b| b.covers(p)))
        .cloned()
        .collect()
}

/// Subset of both inputs.
fn intersect_grants(a: &[PathPattern], b: &[PathPattern]) -> Vec<PathPattern> {
    let mut out = clamp_to(a, b);
    out.extend(clamp_to(b, a));
    canonicalize_set(&out)
}

fn union_grants(a: &[PathPattern], b: &[PathPattern]) -> Vec<PathPattern> {
    let mut out = a.to_vec();
    out.extend_from_slice(b);
    canonicalize_set(&out)
}

impl Spec {
    /// The result is a subset of both `self` (parent) and `requested` (FW-CAP2).
    pub fn narrow(&self, requested: &Spec) -> Spec {
        Spec {
            fs: narrow_fs(&self.fs, &requested.fs),
            net: narrow_net(&self.net, &requested.net),
            exec: narrow_exec(&self.exec, &requested.exec),
            mcp: narrow_mcp(&self.mcp, &requested.mcp),
        }
        .canonicalize()
    }
}

fn narrow_fs(parent: &FsSpec, req: &FsSpec) -> FsSpec {
    let subtract = union_grants(&parent.subtract, &req.subtract);
    let writes = intersect_grants(&parent.writes, &req.writes);

    // The narrower read mode wins (Closed < AmbientMinusSubtract).
    let (read_mode, reads) = match (parent.read_mode, req.read_mode) {
        (ReadMode::AmbientMinusSubtract, ReadMode::AmbientMinusSubtract) => (
            ReadMode::AmbientMinusSubtract,
            union_grants(&parent.reads, &req.reads),
        ),
        (ReadMode::Closed, ReadMode::Closed) => {
            (ReadMode::Closed, intersect_grants(&parent.reads, &req.reads))
        }
        // Closed bounds Ambient: the Closed side's grants bound the result; the Ambient side
        // contributes only its subtract holes (already unioned above).
        (ReadMode::Closed, ReadMode::AmbientMinusSubtract) => {
            (ReadMode::Closed, parent.reads.clone())
        }
        (ReadMode::AmbientMinusSubtract, ReadMode::Closed) => (ReadMode::Closed, req.reads.clone()),
    };

    FsSpec {
        read_mode,
        reads: canonicalize_set(&reads),
        writes,
        subtract,
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
        let parent = Spec {
            fs: FsSpec {
                reads: vec![pp("/work/**")],
                ..Default::default()
            },
            ..Spec::empty()
        };
        let req = Spec {
            fs: FsSpec {
                reads: vec![pp("/work/project/**"), pp("/etc/**")],
                ..Default::default()
            },
            ..Spec::empty()
        };
        let n = parent.narrow(&req);
        // /work/project survives (covered by parent /work); /etc is dropped.
        assert_eq!(n.fs.reads, vec![pp("/work/project/**")]);
    }

    #[test]
    fn subtract_unions_under_narrowing() {
        let parent = Spec {
            fs: FsSpec {
                subtract: vec![pp("/a/**")],
                ..Default::default()
            },
            ..Spec::empty()
        };
        let req = Spec {
            fs: FsSpec {
                subtract: vec![pp("/b/**")],
                ..Default::default()
            },
            ..Spec::empty()
        };
        let n = parent.narrow(&req);
        assert_eq!(n.fs.subtract, vec![pp("/a/**"), pp("/b/**")]);
    }

    #[test]
    fn net_narrows_to_deny_or_intersection() {
        let ports = |v: Vec<u16>| Spec {
            net: NetPosture::Ports(v),
            ..Spec::empty()
        };
        assert_eq!(
            ports(vec![80, 443]).narrow(&ports(vec![443, 8080])).net,
            NetPosture::Ports(vec![443])
        );
        assert_eq!(
            ports(vec![80]).narrow(&ports(vec![443])).net,
            NetPosture::Deny
        );
        assert_eq!(ports(vec![80]).narrow(&Spec::empty()).net, NetPosture::Deny);
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
        let req = Spec {
            mcp: req_mcp,
            ..Spec::empty()
        };
        let n = Spec::empty().narrow(&req);
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
            Spec {
                mcp: m,
                ..Spec::empty()
            }
        };
        let n = mk(Visibility::Allow(vec!["a".into(), "b".into()]))
            .narrow(&mk(Visibility::Allow(vec!["b".into(), "c".into()])));
        assert_eq!(n.mcp["s"].tools, Visibility::Allow(vec!["b".into()]));

        let n2 = mk(Visibility::AllowAll).narrow(&mk(Visibility::Allow(vec!["x".into()])));
        assert_eq!(n2.mcp["s"].tools, Visibility::Allow(vec!["x".into()]));
    }

    #[test]
    fn narrowing_is_idempotent() {
        let s = Spec {
            fs: FsSpec {
                reads: vec![pp("/work/**")],
                writes: vec![pp("/work/project/**")],
                subtract: vec![pp("/work/.ssh/**")],
                ..Default::default()
            },
            net: NetPosture::Ports(vec![8080, 80]),
            ..Spec::empty()
        };
        assert_eq!(s.narrow(&s), s.canonicalize());
    }
}
