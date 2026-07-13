//! Phase 1 exit tests, named for the design-doc test IDs they discharge (design §7.6). They
//! exercise the compiler as a black box the way the CLI and Python harness do.

use formwork_blueprint::{
    Blueprint, FsBlueprint, NetPosture, PathPattern, ReadMode, ResolvedCatalog,
};
use formwork_compile::{to_canonical_json, Capability, CompiledPolicy, ConfinerPolicy, Fidelity};
use formwork_detect::{HostProfile, Os};

/// Dry-run compiles carry the credential floor like the product does; a fixed home keeps them
/// deterministic on any machine.
fn compile(blueprint: &Blueprint, host: &HostProfile) -> CompiledPolicy {
    formwork_compile::compile(
        blueprint,
        host,
        &ResolvedCatalog::builtin_for_home("/home/x").unwrap(),
    )
}

fn pp(s: &str) -> PathPattern {
    PathPattern::parse(s).unwrap()
}

fn rich_blueprint() -> Blueprint {
    Blueprint {
        fs: FsBlueprint {
            read_mode: ReadMode::Closed,
            reads: vec![pp("/work/**")],
            writes: vec![pp("/work/project/**")],
            subtract: vec![pp("/work/project/.git/**"), pp("/work/.ssh/**")],
            write_subtract: vec![pp("**/.mcp.json")],
        },
        net: NetPosture::Ports(vec![8080]),
        exec: formwork_blueprint::ExecPosture::Unrestricted,
        mcp: Default::default(),
        ..Blueprint::empty()
    }
}

/// FW-E2E-026: dry-run compile without enforcement, including a Linux policy on any host (compile is pure).
#[test]
fn fw_e2e_026_dry_run_cross_platform_compile() {
    let linux = compile(&rich_blueprint(), &HostProfile::synthetic_linux(Some(6)));
    assert!(matches!(linux.confiner, ConfinerPolicy::Linux(_)));
    assert!(linux
        .report
        .per_capability
        .contains_key(&Capability::FsRead));

    let mac = compile(&rich_blueprint(), &HostProfile::synthetic_macos());
    assert!(matches!(mac.confiner, ConfinerPolicy::Macos(_)));

    // A host with no confiner still compiles (and says so) rather than crashing.
    let bare = HostProfile {
        os: Os::Linux,
        landlock_abi: None,
        seccomp: false,
        seatbelt: false,
        os_version: "bare".into(),
    };
    let bare_policy = compile(&rich_blueprint(), &bare);
    assert!(matches!(
        bare_policy.confiner,
        ConfinerPolicy::Unavailable { .. }
    ));
}

/// FW-E2E-027: deterministic compile -- byte-identical output, insensitive to input ordering.
#[test]
fn fw_e2e_027_deterministic_compile() {
    let host = HostProfile::synthetic_linux(Some(4));
    let a = to_canonical_json(&compile(&rich_blueprint(), &host));
    let b = to_canonical_json(&compile(&rich_blueprint(), &host));
    assert_eq!(a, b, "identical inputs must produce byte-identical output");

    let mut shuffled = rich_blueprint();
    shuffled.fs.reads = vec![pp("/work/**"), pp("/work/**")];
    shuffled.fs.subtract = vec![pp("/work/.ssh/**"), pp("/work/project/.git/**")];
    let c = to_canonical_json(&compile(&shuffled, &host));
    assert_eq!(
        a, c,
        "reordered/duplicated but equivalent blueprint must compile identically"
    );
}

/// FW-INV5 (report soundness, compile half): every `Enforced` capability names a real backend.
#[test]
fn fw_inv5_every_enforced_capability_names_a_backend() {
    for host in [
        HostProfile::synthetic_macos(),
        HostProfile::synthetic_linux(Some(6)),
    ] {
        let policy = compile(&rich_blueprint(), &host);
        for (cap, fidelity) in &policy.report.per_capability {
            if let Fidelity::Enforced { backend } = fidelity {
                assert!(
                    !matches!(backend, formwork_compile::Backend::None),
                    "{cap:?} claims Enforced but names no backend on {:?}",
                    host.os
                );
            }
        }
    }
}

/// FW-XR3 / FW-INV6 (compile half): net never silently opens -- fail-closed or explicitly Unenforceable, never absent.
#[test]
fn fw_inv6_net_never_silently_open() {
    let hosts = [
        HostProfile::synthetic_macos(),
        HostProfile::synthetic_linux(Some(6)),
        HostProfile::synthetic_linux(Some(1)),
        HostProfile {
            os: Os::Linux,
            landlock_abi: None,
            seccomp: true,
            seatbelt: false,
            os_version: "seccomp-only".into(),
        },
        HostProfile {
            os: Os::Linux,
            landlock_abi: None,
            seccomp: false,
            seatbelt: false,
            os_version: "bare".into(),
        },
    ];
    for host in hosts {
        let policy = compile(&Blueprint::empty(), &host);
        let net = policy
            .report
            .per_capability
            .get(&Capability::NetDefaultDeny)
            .expect("net posture must always be reported");
        match net {
            Fidelity::Enforced { .. } | Fidelity::Partial { .. } => {}
            Fidelity::Unenforceable { reason } => {
                assert!(
                    !reason.is_empty(),
                    "an unenforceable net must carry a surfaced reason"
                );
            }
        }
    }
}
