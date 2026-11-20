//! One meaning for a path pattern on both backends (FW-BP27..FW-BP29), at the compiler: what the
//! Seatbelt profile renders for a literal row, and which blueprints a Linux target refuses. The
//! macOS half of each paired test lives here because the compiler renders SBPL on any host.

use formwork_blueprint::{
    Blueprint, ExecPosture, FsBlueprint, PathPattern, ReadMode, ResolvedCatalog,
};
use formwork_compile::{refusal, Capability, CompiledPolicy, ConfinerPolicy, Fidelity};
use formwork_detect::HostProfile;

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

fn sbpl(blueprint: &Blueprint) -> String {
    match compile(blueprint, &HostProfile::synthetic_macos()).confiner {
        ConfinerPolicy::Macos(m) => m.sbpl,
        other => panic!("expected a macOS policy, got {other:?}"),
    }
}

fn closed(fs: FsBlueprint) -> Blueprint {
    Blueprint {
        fs: FsBlueprint {
            read_mode: ReadMode::Closed,
            ..fs
        },
        ..Blueprint::empty()
    }
}

/// FW-E2E-178 (macOS arm): a literal grant is rendered as a `literal` filter, which matches the
/// named object and no entry beneath it, on every grant axis.
#[test]
fn fw_e2e_178_a_literal_grant_renders_as_a_seatbelt_literal() {
    let mut blueprint = closed(FsBlueprint {
        reads: vec![pp("/a/data")],
        writes: vec![pp("/a/out")],
        writes_no_create: vec![pp("/a/log")],
        ..FsBlueprint::default()
    });
    blueprint.exec = ExecPosture::Allowlist(vec![pp("/a/bin")]);
    let profile = sbpl(&blueprint);
    for rule in [
        "(allow file-read* (literal \"/a/data\"))",
        "(allow file-write* (literal \"/a/out\"))",
        "(allow file-write-data (literal \"/a/log\"))",
        "(allow process-exec* (literal \"/a/bin\"))",
    ] {
        assert!(profile.contains(rule), "missing {rule}\n{profile}");
    }
    for subtree in ["/a/data", "/a/out", "/a/log", "/a/bin"] {
        assert!(
            !profile.contains(&format!("(subpath \"{subtree}\")")),
            "a literal row must not render as a subtree of {subtree}\n{profile}"
        );
    }
}

/// FW-E2E-179 (macOS arm): a literal deny covers the entry it names; the `/**` spelling is the
/// one that covers a directory's contents, and the two render differently.
#[test]
fn fw_e2e_179_a_literal_deny_renders_as_a_seatbelt_literal() {
    let literal = sbpl(&closed(FsBlueprint {
        reads: vec![pp("/a/**")],
        writes: vec![pp("/a/**")],
        subtract: vec![pp("/a/secrets")],
        ..FsBlueprint::default()
    }));
    for op in ["file-read*", "file-read-metadata", "file-write*"] {
        let rule = format!("(deny {op} (literal \"/a/secrets\"))");
        assert!(literal.contains(&rule), "missing {rule}\n{literal}");
    }
    assert!(!literal.contains("(subpath \"/a/secrets\")"), "{literal}");

    let subtree = sbpl(&closed(FsBlueprint {
        reads: vec![pp("/a/**")],
        subtract: vec![pp("/a/secrets/**")],
        ..FsBlueprint::default()
    }));
    assert!(
        subtree.contains("(deny file-read* (subpath \"/a/secrets\"))"),
        "{subtree}"
    );
}

/// The rows FW-BP28 refuses for Linux, one per field an operator can write an any-depth pattern
/// into.
fn any_depth_rows() -> Vec<(&'static str, Blueprint)> {
    let fs = |fs: FsBlueprint| closed(fs);
    let mut exec = fs(FsBlueprint::default());
    exec.exec = ExecPosture::Allowlist(vec![pp("**/tool")]);
    vec![
        (
            "`read:**/data/**`",
            fs(FsBlueprint {
                reads: vec![pp("**/data/**")],
                ..FsBlueprint::default()
            }),
        ),
        (
            "`write:/srv/elsewhere/**/data/**`",
            fs(FsBlueprint {
                writes: vec![pp("/srv/elsewhere/**/data/**")],
                ..FsBlueprint::default()
            }),
        ),
        (
            "`modify:/srv/**/app.log`",
            fs(FsBlueprint {
                writes_no_create: vec![pp("/srv/**/app.log")],
                ..FsBlueprint::default()
            }),
        ),
        ("`exec:**/tool`", exec),
        (
            "`deny:**/secrets.yaml`",
            fs(FsBlueprint {
                reads: vec![pp("/work/**")],
                subtract: vec![pp("**/secrets.yaml")],
                ..FsBlueprint::default()
            }),
        ),
    ]
}

/// FW-E2E-180: an any-depth grant or operator deny is refused for every Linux target, naming the
/// row, and a compile that was not asked first yields no policy to enforce and claims no
/// filesystem scope.
#[test]
fn fw_e2e_180_an_any_depth_operator_row_is_refused_for_linux() {
    let hosts = [
        HostProfile::synthetic_linux(Some(1)),
        HostProfile::synthetic_linux(Some(6)),
        HostProfile::synthetic_linux(None),
    ];
    for (row, blueprint) in any_depth_rows() {
        for host in &hosts {
            let reason = refusal(&blueprint, host).unwrap_or_else(|| panic!("{row} not refused"));
            assert!(reason.contains(row), "{row} is not named: {reason}");
            assert!(reason.contains("Landlock"), "{reason}");

            let policy = compile(&blueprint, host);
            match &policy.confiner {
                ConfinerPolicy::Unavailable {
                    reason: unavailable,
                } => {
                    assert!(unavailable.contains(row), "{unavailable}")
                }
                other => panic!("{row}: a refused blueprint compiled to {other:?}"),
            }
            for cap in [Capability::FsRead, Capability::FsWrite] {
                assert!(
                    matches!(
                        policy.report.per_capability.get(&cap),
                        Some(Fidelity::Unenforceable { .. })
                    ),
                    "{row}: {cap:?} must not be claimed"
                );
            }
        }
    }
}

/// FW-E2E-180: the same blueprints compile for macOS, where Seatbelt matches the row by regex.
#[test]
fn fw_e2e_180_an_any_depth_operator_row_compiles_for_macos() {
    let host = HostProfile::synthetic_macos();
    for (row, blueprint) in any_depth_rows() {
        assert_eq!(refusal(&blueprint, &host), None, "{row}");
        assert!(sbpl(&blueprint).contains("(regex #\""), "{row}");
    }
    let profile = sbpl(&any_depth_rows().pop().unwrap().1);
    assert!(
        profile.contains(r#"(deny file-read* (regex #"/secrets\.yaml$"))"#),
        "{profile}"
    );
}

/// FW-BP28 refuses what the policy would carry. A row that a covering subtree, or the ambient read
/// mode, already makes redundant on both backends is not in the policy and is not refused.
#[test]
fn fw_bp28_a_row_the_policy_would_not_carry_is_not_refused() {
    let host = HostProfile::synthetic_linux(Some(6));
    let fs = |fs: FsBlueprint| Blueprint {
        fs,
        ..Blueprint::empty()
    };
    let redundant = [
        fs(FsBlueprint {
            read_mode: ReadMode::AmbientMinusSubtract,
            reads: vec![pp("**/notes")],
            ..FsBlueprint::default()
        }),
        fs(FsBlueprint {
            read_mode: ReadMode::Closed,
            reads: vec![pp("/work/**/notes")],
            writes: vec![pp("/work/**")],
            ..FsBlueprint::default()
        }),
        fs(FsBlueprint {
            read_mode: ReadMode::Closed,
            writes: vec![pp("/work/**"), pp("/work/**/out/**")],
            subtract: vec![pp("/work/secret/**"), pp("/work/secret/**/key")],
            ..FsBlueprint::default()
        }),
    ];
    for blueprint in &redundant {
        assert_eq!(refusal(blueprint, &host), None, "{:?}", blueprint.fs);
        let ConfinerPolicy::Linux(linux) = compile(blueprint, &host).confiner else {
            panic!("expected a Linux policy for {:?}", blueprint.fs);
        };
        let rows = [&linux.reads, &linux.writes, &linux.subtract];
        assert!(rows.iter().all(|set| set.iter().all(|p| !p.is_any_depth())));
    }
    // The ambient mode covers reads only: a write grant is still a row of its own.
    let write = fs(FsBlueprint {
        read_mode: ReadMode::AmbientMinusSubtract,
        writes: vec![pp("**/out/**")],
        ..FsBlueprint::default()
    });
    assert!(refusal(&write, &host)
        .unwrap()
        .contains("`write:**/out/**`"));
}

/// FW-BP28 leaves the rows the operator did not write as they were: the credential floor's and
/// the tamper vectors' any-depth rows are withheld and reported, never a reason to refuse
/// (FW-CRED9), or the default profile could not start on Linux.
#[test]
fn fw_bp28_floor_and_tamper_vector_rows_are_withheld_not_refused() {
    let blueprint = Blueprint {
        fs: FsBlueprint {
            read_mode: ReadMode::AmbientMinusSubtract,
            writes: vec![pp("/work/**")],
            write_subtract: vec![pp("**/.git/hooks/**")],
            ..FsBlueprint::default()
        },
        ..Blueprint::empty()
    };
    let host = HostProfile::synthetic_linux(Some(6));
    assert_eq!(refusal(&blueprint, &host), None);
    let policy = compile(&blueprint, &host);
    assert!(matches!(policy.confiner, ConfinerPolicy::Linux(_)));
    assert!(
        policy
            .report
            .withheld
            .iter()
            .any(|w| w == "write-subtract **/.git/hooks/**"),
        "{:?}",
        policy.report.withheld
    );
    assert!(policy
        .report
        .withheld
        .iter()
        .any(|w| w.starts_with("credential-floor **/")));
}

/// FW-E2E-181 (macOS arm): an escaped glob character is part of the file name the rule carries
/// into the profile.
#[test]
fn fw_e2e_181_an_escaped_name_reaches_the_profile_unescaped() {
    let profile = sbpl(&closed(FsBlueprint {
        reads: vec![pp("/srv/**")],
        subtract: vec![pp(r"/srv/keys/\*.pem"), pp(r"**/\[id]/secret")],
        ..FsBlueprint::default()
    }));
    assert!(
        profile.contains("(deny file-read* (literal \"/srv/keys/*.pem\"))"),
        "{profile}"
    );
    assert!(
        profile.contains(r#"(deny file-read* (regex #"/\[id\]/secret$"))"#),
        "{profile}"
    );
}

/// FW-BP29: a socket path `detect` found is one concrete path. A name with a glob character is
/// admitted as itself when its channel is lifted, never refused as a pattern and dropped.
#[test]
fn fw_bp29_a_detected_socket_path_is_never_read_as_grammar() {
    let mut host = HostProfile::synthetic_linux(Some(6));
    host.facilities.session_bus = Some("/run/user/1000/bus[1]*".to_string());
    let blueprint = Blueprint {
        channels: formwork_blueprint::ChannelPolicy::allow([
            formwork_blueprint::Channel::RunOutside,
        ]),
        ..closed(FsBlueprint::default())
    };
    let ConfinerPolicy::Linux(linux) = compile(&blueprint, &host).confiner else {
        panic!("expected a Linux policy");
    };
    assert_eq!(
        linux.unix_socket_grants,
        vec![PathPattern::literal(std::path::Path::new("/run/user/1000/bus[1]*")).unwrap()]
    );
}
