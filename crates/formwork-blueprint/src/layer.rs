//! Blueprint layering (FW-BP1/2/3): a [`BlueprintLayer`] is one surface's partial contribution --
//! a preset, the named file, or the CLI override set -- and [`merge`] folds a fixed stack of them
//! into the effective [`Blueprint`]. Path sets merge additively and deny still beats allow at
//! match time (FW-BP4), so no layer can shadow another's deny; postures are last-set-wins. The
//! fold is deterministic (FW-FID4). `extends` resolution reads files, so it lives in the CLI
//! loader; the pure merge sees an already-flattened stack.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Blueprint, EnvPosture, ExecPosture, McpPolicy, NetPosture, PathPattern, ReadMode};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct BlueprintLayer {
    /// Base Blueprints this layer sits on (FW-BP3), lowest first. Paths resolve relative to the
    /// file that names them; the loader flattens the chain and empties this field before merge.
    #[serde(default)]
    pub extends: Vec<String>,
    #[serde(default)]
    pub fs: FsLayer,
    pub net: Option<NetPosture>,
    pub exec: Option<ExecPosture>,
    pub env: Option<EnvPosture>,
    #[serde(default)]
    pub mcp: BTreeMap<String, McpPolicy>,
    /// Credential types deliberately let through (FW-CRED5); unions across layers.
    #[serde(default)]
    pub allow_credentials: Vec<String>,
    #[serde(default)]
    pub discovery: DiscoveryLayer,
}

/// [`crate::FsBlueprint`] with set-vs-unset distinguishable: in a layer, an absent `read-mode`
/// inherits rather than meaning `closed`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct FsLayer {
    pub read_mode: Option<ReadMode>,
    #[serde(default)]
    pub reads: Vec<PathPattern>,
    #[serde(default)]
    pub writes: Vec<PathPattern>,
    #[serde(default)]
    pub subtract: Vec<PathPattern>,
    #[serde(default)]
    pub write_subtract: Vec<PathPattern>,
}

/// Discovery inputs a layer may carry. `auto-widen` is capability-bearing (it bounds what a
/// learning run may self-grant, FW-DISC4) and survives the merge; `provenance` is audit metadata
/// recorded in discovered-layer files (FW-DISC6) -- it distinguishes learned grants from authored
/// ones and is deliberately *not* merged into the grant.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct DiscoveryLayer {
    #[serde(default)]
    pub auto_widen: Vec<PathPattern>,
    #[serde(default)]
    pub provenance: BTreeMap<String, ProvenanceEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ProvenanceEntry {
    /// `discovery` (operator-accepted) or `discovery-auto` (inside the auto-widen zone).
    pub added_via: String,
    pub run_id: String,
}

/// Fold a stack of layers, lowest first, into the effective Blueprint (FW-BP2). The baseline is
/// the fail-closed empty Blueprint; the credential-catalog floor is applied by the compiler, not
/// here, so no layer stack can carry it away.
pub fn merge(layers: &[BlueprintLayer]) -> Blueprint {
    let mut out = Blueprint::empty();
    for layer in layers {
        if let Some(mode) = layer.fs.read_mode {
            out.fs.read_mode = mode;
        }
        out.fs.reads.extend(layer.fs.reads.iter().cloned());
        out.fs.writes.extend(layer.fs.writes.iter().cloned());
        out.fs.subtract.extend(layer.fs.subtract.iter().cloned());
        out.fs
            .write_subtract
            .extend(layer.fs.write_subtract.iter().cloned());
        if let Some(net) = &layer.net {
            out.net = net.clone();
        }
        if let Some(exec) = &layer.exec {
            out.exec = exec.clone();
        }
        if let Some(env) = &layer.env {
            out.env = env.clone();
        }
        for (server, policy) in &layer.mcp {
            out.mcp.insert(server.clone(), policy.clone());
        }
        out.allow_credentials
            .extend(layer.allow_credentials.iter().cloned());
        out.discovery
            .auto_widen
            .extend(layer.discovery.auto_widen.iter().cloned());
    }
    out.canonicalize()
}

impl BlueprintLayer {
    /// A full Blueprint viewed as one layer: what a pre-layering single-file blueprint contributes.
    /// `merge(&[layer_from(bp)])` equals `bp.canonicalize()` -- the FW-E2E-041 refactor guard.
    pub fn from_blueprint(bp: &Blueprint) -> BlueprintLayer {
        BlueprintLayer {
            extends: Vec::new(),
            fs: FsLayer {
                read_mode: Some(bp.fs.read_mode),
                reads: bp.fs.reads.clone(),
                writes: bp.fs.writes.clone(),
                subtract: bp.fs.subtract.clone(),
                write_subtract: bp.fs.write_subtract.clone(),
            },
            net: Some(bp.net.clone()),
            exec: Some(bp.exec.clone()),
            env: Some(bp.env.clone()),
            mcp: bp.mcp.clone(),
            allow_credentials: bp.allow_credentials.clone(),
            discovery: DiscoveryLayer {
                auto_widen: bp.discovery.auto_widen.clone(),
                provenance: BTreeMap::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EnvScrub, FsBlueprint, Visibility};

    fn pp(s: &str) -> PathPattern {
        PathPattern::parse(s).unwrap()
    }

    fn layer_toml(src: &str) -> BlueprintLayer {
        toml::from_str(src).unwrap()
    }

    #[test]
    fn empty_stack_is_the_fail_closed_floor() {
        assert_eq!(merge(&[]), Blueprint::empty().canonicalize());
    }

    #[test]
    fn path_sets_union_across_layers() {
        let base = layer_toml(r#"[fs]"#);
        let a = layer_toml(
            r#"
            [fs]
            reads = ["/work/**"]
            subtract = ["/work/.ssh/**"]
        "#,
        );
        let b = layer_toml(
            r#"
            [fs]
            reads = ["/data/**"]
            subtract = ["/work/other/**"]
        "#,
        );
        let merged = merge(&[base, a, b]);
        assert_eq!(merged.fs.reads, vec![pp("/data/**"), pp("/work/**")]);
        assert_eq!(
            merged.fs.subtract,
            vec![pp("/work/.ssh/**"), pp("/work/other/**")]
        );
    }

    #[test]
    fn postures_are_last_set_wins_and_unset_inherits() {
        let a = layer_toml(r#"net = { ports = [443] }"#);
        let b = layer_toml(r#"[fs]"#); // sets nothing
        let c = layer_toml(r#"net = "deny""#);
        assert_eq!(
            merge(&[a.clone(), b.clone()]).net,
            NetPosture::Ports(vec![443])
        );
        assert_eq!(merge(&[a, b, c]).net, NetPosture::Deny);
    }

    #[test]
    fn read_mode_unset_inherits_rather_than_meaning_closed() {
        let base = layer_toml(
            r#"[fs]
            read-mode = "ambient-minus-subtract""#,
        );
        let over = layer_toml(
            r#"[fs]
            writes = ["/work/project/**"]"#,
        );
        let merged = merge(&[base, over]);
        assert_eq!(merged.fs.read_mode, ReadMode::AmbientMinusSubtract);
    }

    #[test]
    fn env_posture_layering_replaces_wholesale() {
        let base = layer_toml(r#"env = { scrub = { allow = ["ANTHROPIC_API_KEY"] } }"#);
        let over = layer_toml(r#"env = { allowlist = ["PATH", "HOME"] }"#);
        let merged = merge(&[base, over]);
        assert_eq!(
            merged.env,
            EnvPosture::Allowlist(vec!["HOME".into(), "PATH".into()])
        );
        let scrub_only = merge(&[layer_toml(
            r#"env = { scrub = { allow = ["ANTHROPIC_API_KEY"] } }"#,
        )]);
        assert_eq!(
            scrub_only.env,
            EnvPosture::Scrub(EnvScrub {
                allow: vec!["ANTHROPIC_API_KEY".into()],
                deny: vec![]
            })
        );
    }

    #[test]
    fn mcp_merges_per_server_last_set_wins() {
        let a = layer_toml(
            r#"
            [mcp.files]
            tools = { allow = ["read_file", "write_file"] }
            [mcp.web]
            tools = "allow-all"
        "#,
        );
        let b = layer_toml(
            r#"
            [mcp.files]
            tools = { allow = ["read_file"] }
        "#,
        );
        let merged = merge(&[a, b]);
        assert_eq!(
            merged.mcp["files"].tools,
            Visibility::Allow(vec!["read_file".into()])
        );
        assert_eq!(merged.mcp["web"].tools, Visibility::AllowAll);
    }

    #[test]
    fn allow_credentials_and_zone_union_and_dedupe() {
        let a = layer_toml(
            r#"
            allow-credentials = ["aws"]
            [discovery]
            auto-widen = ["/work/project/**"]
        "#,
        );
        let b = layer_toml(r#"allow-credentials = ["aws", "gcp"]"#);
        let merged = merge(&[a, b]);
        assert_eq!(merged.allow_credentials, vec!["aws", "gcp"]);
        assert_eq!(merged.discovery.auto_widen, vec![pp("/work/project/**")]);
    }

    #[test]
    fn merge_is_deterministic_across_repeats() {
        let layers = vec![
            layer_toml(
                r#"[fs]
                reads = ["/b/**", "/a/**"]"#,
            ),
            layer_toml(r#"net = { ports = [8080, 443] }"#),
        ];
        assert_eq!(merge(&layers), merge(&layers));
        let json = serde_json::to_string(&merge(&layers)).unwrap();
        assert_eq!(json, serde_json::to_string(&merge(&layers)).unwrap());
    }

    #[test]
    fn single_full_layer_equals_direct_blueprint_parse() {
        // The FW-E2E-041 guard at the unit level: layering a complete pre-FEP-2 blueprint over
        // the baseline changes nothing.
        let src = r#"
            net = { ports = [8080] }
            exec = "unrestricted"
            [fs]
            read-mode = "closed"
            reads = ["/work/project/**"]
            writes = ["/work/project/**"]
            subtract = ["/work/project/.git/**"]
            [mcp.files]
            tools = { allow = ["read_file"] }
        "#;
        let direct: Blueprint = toml::from_str(src).unwrap();
        let layered = merge(&[toml::from_str::<BlueprintLayer>(src).unwrap()]);
        assert_eq!(layered, direct.canonicalize());
    }

    #[test]
    fn provenance_is_metadata_not_grant() {
        let discovered = layer_toml(
            r#"
            [fs]
            reads = ["/opt/toolchain/**"]
            [discovery.provenance."/opt/toolchain/**"]
            added-via = "discovery"
            run-id = "learn-1234"
        "#,
        );
        let merged = merge(std::slice::from_ref(&discovered));
        assert_eq!(merged.fs.reads, vec![pp("/opt/toolchain/**")]);
        // The grant landed; the provenance table stays with the layer file.
        assert_eq!(
            discovered.discovery.provenance["/opt/toolchain/**"].run_id,
            "learn-1234"
        );
    }

    #[test]
    fn from_blueprint_round_trips_through_merge() {
        let bp = Blueprint {
            fs: FsBlueprint {
                read_mode: ReadMode::AmbientMinusSubtract,
                reads: vec![pp("/**")],
                writes: vec![pp("/tmp/**")],
                subtract: vec![pp("**/.env")],
                write_subtract: vec![pp("**/.git/config")],
            },
            net: NetPosture::Ports(vec![443]),
            ..Blueprint::empty()
        };
        assert_eq!(
            merge(&[BlueprintLayer::from_blueprint(&bp)]),
            bp.canonicalize()
        );
    }
}
