//! The capability compiler: the single authority mapping a [`Blueprint`] to concrete mechanisms. Pure --
//! it never touches the kernel -- so it runs anywhere, is inspectable without enforcing (FW-FID2),
//! and is deterministic in `(blueprint, host)` (FW-FID4). Impurity is confined to the [`HostProfile`]
//! the caller passes in; a synthetic profile compiles a policy for a platform you are not on.

mod linux;
mod policy;
mod report;
mod sbpl;

pub use policy::{
    CompiledPolicy, ConfinerPolicy, ExecPlan, GatewayPolicy, LinuxNetPlan, LinuxPolicy,
    MacosPolicy, SeccompPlan, SocketFamily,
};
pub use report::{
    Backend, Capability, CredentialFidelity, CredentialReport, DenialSemantics, Fidelity,
    FidelityReport,
};

use std::collections::BTreeMap;

use formwork_blueprint::{
    canonicalize_set, Blueprint, EnvPosture, ExecPosture, NetPosture, PathPattern, ReadMode,
    ResolvedCatalog,
};
use formwork_detect::{HostProfile, Os};

use linux::PortTier;

/// The normalized intermediate both backends consume: canonicalized, with write grants folded into
/// the read surface (writes imply reads). Operator denies (`subtract`) and the credential floor
/// (`floor`) stay separate: the floor's typed exemption (FW-CRED5) may lift a floor hole, but an
/// operator deny is never lifted by anything.
pub struct CompileInput {
    pub read_mode: ReadMode,
    pub effective_reads: Vec<PathPattern>,
    pub writes: Vec<PathPattern>,
    pub subtract: Vec<PathPattern>,
    pub write_subtract: Vec<PathPattern>,
    /// The credential floor (FW-CRED2 path arm, FW-CRED4): every non-excluded catalog type's paths
    /// plus the backstop. Read+write denied, like `subtract`.
    pub floor: Vec<PathPattern>,
    /// Excluded types' scopes (FW-CRED5): where a *floor* deny (the any-depth backstop crossing
    /// into a type's own directory, e.g. `**/credentials` inside an excluded `~/.aws/**`) is
    /// re-lifted. Applied clamped to the grant surface, and never against `subtract`.
    pub floor_exempt: Vec<PathPattern>,
    pub net: NetPosture,
    pub exec: ExecPosture,
}

impl CompileInput {
    fn from_blueprint(blueprint: &Blueprint, catalog: &ResolvedCatalog) -> Self {
        let mut reads = blueprint.fs.reads.clone();
        reads.extend(blueprint.fs.writes.iter().cloned());
        let floor_exempt: Vec<PathPattern> = catalog
            .types
            .iter()
            .filter(|(name, _)| {
                blueprint
                    .allow_credentials
                    .iter()
                    .any(|a| a == name.as_str())
            })
            .flat_map(|(_, entry)| entry.paths.iter().cloned())
            .collect();
        CompileInput {
            read_mode: blueprint.fs.read_mode,
            effective_reads: canonicalize_set(&reads),
            writes: canonicalize_set(&blueprint.fs.writes),
            subtract: canonicalize_set(&blueprint.fs.subtract),
            write_subtract: canonicalize_set(&blueprint.fs.write_subtract),
            floor: canonicalize_set(&catalog.denied_paths(&blueprint.allow_credentials)),
            floor_exempt: canonicalize_set(&floor_exempt),
            net: blueprint.net.clone(),
            exec: blueprint.exec.clone(),
        }
    }
}

/// Pure and deterministic in `(blueprint, host, catalog)`. The catalog is a mandatory input by
/// design: the credential floor (FW-CRED4) cannot be forgotten, only explicitly resolved (or,
/// in tests, explicitly emptied) at the edge that knows `$HOME`.
pub fn compile(
    blueprint: &Blueprint,
    host: &HostProfile,
    catalog: &ResolvedCatalog,
) -> CompiledPolicy {
    let blueprint = blueprint.canonicalize();
    let input = CompileInput::from_blueprint(&blueprint, catalog);

    let mut per_capability: BTreeMap<Capability, Fidelity> = BTreeMap::new();
    let mut semantics: BTreeMap<Capability, DenialSemantics> = BTreeMap::new();

    let (confiner, direct_tcp_ports) = match host.os {
        Os::MacOs => compile_macos(
            &input,
            host,
            &blueprint,
            &mut per_capability,
            &mut semantics,
        ),
        Os::Linux => compile_linux(
            &input,
            host,
            &blueprint,
            &mut per_capability,
            &mut semantics,
        ),
    };

    // Filesystem invisibility is never provided; document it as an explicit, reported fact.
    per_capability.insert(
        Capability::FsInvisibility,
        Fidelity::Unenforceable {
            reason: "Formwork denies with EACCES/EPERM; it does not emulate ENOENT (design §3, §4)"
                .to_string(),
        },
    );
    semantics.insert(Capability::FsInvisibility, DenialSemantics::Deny);

    // Environment posture is applied at spawn by the CLI shell, independent of the OS confiner (like
    // MCP shading below). Passthrough asks for nothing, so it earns no row. Allowlist is exact
    // (only named vars survive); Scrub is heuristic and must SAY so -- reporting it Enforced would be
    // the silent over-claim FW-XR1 forbids.
    match &blueprint.env {
        EnvPosture::Passthrough => {}
        EnvPosture::Allowlist(_) => {
            per_capability.insert(
                Capability::EnvScrub,
                Fidelity::Enforced {
                    backend: Backend::Launcher,
                },
            );
            semantics.insert(Capability::EnvScrub, DenialSemantics::Hide);
        }
        EnvPosture::Scrub(_) => {
            per_capability.insert(
                Capability::EnvScrub,
                Fidelity::Partial {
                    backend: Backend::Launcher,
                    reason: "heuristic: drops secret-shaped names and values; a secret with neither a known marker name nor a recognized value shape (e.g. an inline credential in DATABASE_URL) is not caught -- pin it with an explicit deny or use an allowlist".to_string(),
                },
            );
            semantics.insert(Capability::EnvScrub, DenialSemantics::Hide);
        }
    }

    // MCP shading is a gateway property, independent of the OS confiner.
    if !blueprint.mcp.is_empty() {
        per_capability.insert(
            Capability::McpShading,
            Fidelity::Enforced {
                backend: Backend::Gateway,
            },
        );
        semantics.insert(Capability::McpShading, DenialSemantics::Hide);
    }

    let credentials = credential_report(catalog, &blueprint, host, &per_capability);
    let report = FidelityReport {
        host: host.clone(),
        per_capability,
        semantics,
        credentials,
    };
    let gateway = GatewayPolicy {
        servers: blueprint.mcp.clone(),
        direct_tcp_ports,
    };

    CompiledPolicy {
        confiner,
        gateway,
        report,
    }
}

/// The FW-CRED8 section: every still-enforced type labeled with the arm that carries each of its
/// location kinds. The path arm rides whatever mechanism carries fs reads on this host, so its
/// fidelity is FsRead's -- including honest degradation: no Landlock -> Unenforceable, and on
/// Linux a type whose rows include any-depth (`**/`) patterns is Partial, because those rows
/// cannot be rooted Landlock rules and are withheld from the policy. The env arm is the
/// launcher's strip, absolute-but-launcher-contingent, disclosed as such.
fn credential_report(
    catalog: &ResolvedCatalog,
    blueprint: &Blueprint,
    host: &HostProfile,
    per_capability: &BTreeMap<Capability, Fidelity>,
) -> CredentialReport {
    let base_fidelity =
        per_capability
            .get(&Capability::FsRead)
            .cloned()
            .unwrap_or(Fidelity::Unenforceable {
                reason: "no filesystem confinement on this host".to_string(),
            });
    let linux_any_depth_gap = matches!(host.os, Os::Linux) && base_fidelity.is_enforced();
    let path_fidelity_for = |paths: &[PathPattern]| -> Fidelity {
        if linux_any_depth_gap && paths.iter().any(|p| p.is_any_depth()) {
            Fidelity::Partial {
                backend: Backend::Landlock,
                reason: "any-depth (`**/`) rows cannot be rooted Landlock rules and are withheld \
                         on Linux; absolute rows are enforced (see docs/linux-backend.md)"
                    .to_string(),
            }
        } else {
            base_fidelity.clone()
        }
    };
    let env_fidelity = Fidelity::Enforced {
        backend: Backend::Launcher,
    };
    let mut per_type = BTreeMap::new();
    for (name, entry) in catalog.enforced_types(&blueprint.allow_credentials) {
        per_type.insert(
            name.to_string(),
            CredentialFidelity {
                path: (!entry.paths.is_empty()).then(|| path_fidelity_for(&entry.paths)),
                env: (!entry.envs.is_empty()).then(|| env_fidelity.clone()),
            },
        );
    }
    let backstop_lifted = blueprint
        .allow_credentials
        .iter()
        .any(|a| a == formwork_blueprint::BACKSTOP);
    CredentialReport {
        catalog_version: catalog.version,
        allowed: blueprint.allow_credentials.clone(),
        per_type,
        backstop: (!backstop_lifted).then(|| path_fidelity_for(&catalog.backstop)),
        launcher_contingency: "env-var shading is applied by the launcher at spawn; it holds only \
                               while Formwork is the launching process and is not a kernel \
                               guarantee (FW-CRED8)"
            .to_string(),
    }
}

fn compile_macos(
    input: &CompileInput,
    _host: &HostProfile,
    blueprint: &Blueprint,
    caps: &mut BTreeMap<Capability, Fidelity>,
    sem: &mut BTreeMap<Capability, DenialSemantics>,
) -> (ConfinerPolicy, Vec<u16>) {
    let sbpl = sbpl::render(input);

    let seatbelt = || Fidelity::Enforced {
        backend: Backend::Seatbelt,
    };
    caps.insert(Capability::FsRead, seatbelt());
    caps.insert(Capability::FsWrite, seatbelt());
    caps.insert(Capability::NetDefaultDeny, seatbelt());
    sem.insert(Capability::FsRead, DenialSemantics::Deny);
    sem.insert(Capability::FsWrite, DenialSemantics::Deny);
    sem.insert(Capability::NetDefaultDeny, DenialSemantics::Deny);

    // Seatbelt path-gates UNIX sockets, so cross-domain socket control is clean here.
    caps.insert(Capability::CrossDomainSocket, seatbelt());
    sem.insert(Capability::CrossDomainSocket, DenialSemantics::Deny);

    let mut direct_ports = Vec::new();
    if let NetPosture::Ports(ports) = &input.net {
        caps.insert(Capability::NetPortTier, seatbelt());
        sem.insert(Capability::NetPortTier, DenialSemantics::Deny);
        direct_ports = ports.clone();
    }
    if let ExecPosture::Allowlist(_) = &input.exec {
        caps.insert(Capability::Exec, seatbelt());
        sem.insert(Capability::Exec, DenialSemantics::Deny);
    }
    let _ = blueprint;

    (ConfinerPolicy::Macos(MacosPolicy { sbpl }), direct_ports)
}

fn compile_linux(
    input: &CompileInput,
    host: &HostProfile,
    _blueprint: &Blueprint,
    caps: &mut BTreeMap<Capability, Fidelity>,
    sem: &mut BTreeMap<Capability, DenialSemantics>,
) -> (ConfinerPolicy, Vec<u16>) {
    let abi = host.landlock_abi.unwrap_or(0);
    let has_landlock = abi >= 1;

    // Filesystem read/write require Landlock. Report honestly if it is absent.
    if has_landlock {
        caps.insert(
            Capability::FsRead,
            Fidelity::Enforced {
                backend: Backend::Landlock,
            },
        );
        caps.insert(
            Capability::FsWrite,
            Fidelity::Enforced {
                backend: Backend::Landlock,
            },
        );
    } else {
        let reason =
            "Landlock unavailable on this host; filesystem scope cannot be enforced".to_string();
        caps.insert(
            Capability::FsRead,
            Fidelity::Unenforceable {
                reason: reason.clone(),
            },
        );
        caps.insert(Capability::FsWrite, Fidelity::Unenforceable { reason });
    }
    sem.insert(Capability::FsRead, DenialSemantics::Deny);
    sem.insert(Capability::FsWrite, DenialSemantics::Deny);

    let (net_plan, net_via_seccomp, tier) = linux::net_plan(host, &input.net);
    let net_fidelity = if net_via_seccomp {
        if host.seccomp {
            Fidelity::Enforced {
                backend: Backend::Seccomp,
            }
        } else {
            Fidelity::Unenforceable {
                reason: "neither Landlock net rules nor seccomp available; direct egress cannot be denied".to_string(),
            }
        }
    } else {
        Fidelity::Enforced {
            backend: Backend::Landlock,
        }
    };
    caps.insert(Capability::NetDefaultDeny, net_fidelity);
    sem.insert(Capability::NetDefaultDeny, DenialSemantics::Deny);

    let mut direct_ports = Vec::new();
    match tier {
        PortTier::NotRequested => {}
        PortTier::Enforced => {
            caps.insert(
                Capability::NetPortTier,
                Fidelity::Enforced {
                    backend: Backend::Landlock,
                },
            );
            sem.insert(Capability::NetPortTier, DenialSemantics::Deny);
            if let NetPosture::Ports(ports) = &input.net {
                direct_ports = ports.clone();
            }
        }
        PortTier::UnenforceableBelowAbi4 => {
            caps.insert(
                Capability::NetPortTier,
                Fidelity::Unenforceable {
                    reason: format!(
                        "direct TCP port tier needs Landlock ABI v{} (host has v{}); egress fails closed instead",
                        linux::LANDLOCK_NET_ABI, abi
                    ),
                },
            );
            sem.insert(Capability::NetPortTier, DenialSemantics::Deny);
        }
    }

    // Optional exec allow-list (Landlock FS_EXECUTE); seccomp cannot filter execve by path.
    let exec_plan = match &input.exec {
        ExecPosture::Unrestricted => ExecPlan::Unrestricted,
        ExecPosture::Allowlist(paths) => {
            if has_landlock {
                caps.insert(
                    Capability::Exec,
                    Fidelity::Enforced {
                        backend: Backend::Landlock,
                    },
                );
            } else {
                caps.insert(
                    Capability::Exec,
                    Fidelity::Unenforceable {
                        reason: "exec allow-list needs Landlock FS_EXECUTE; unavailable here"
                            .to_string(),
                    },
                );
            }
            sem.insert(Capability::Exec, DenialSemantics::Deny);
            ExecPlan::Allowlist {
                paths: paths.clone(),
            }
        }
    };

    // Cross-domain UNIX-socket scoping: coarse and recent (ABI v6). Partial where present, else a
    // reported gap -- the fail-closed net posture still prevents remote egress (FW-ADV-006).
    if abi >= 6 {
        caps.insert(
            Capability::CrossDomainSocket,
            Fidelity::Partial {
                backend: Backend::Landlock,
                reason: "Landlock UNIX-socket scope is coarse: it blocks sockets created outside the domain, not per-path".to_string(),
            },
        );
    } else {
        caps.insert(
            Capability::CrossDomainSocket,
            Fidelity::Unenforceable {
                reason: "UNIX-socket scoping needs Landlock ABI v6; remote egress still denied by net posture".to_string(),
            },
        );
    }
    sem.insert(Capability::CrossDomainSocket, DenialSemantics::Deny);

    if !has_landlock && !host.seccomp {
        let confiner = ConfinerPolicy::Unavailable {
            reason: "no Landlock and no seccomp on this host; OS-level confinement unavailable"
                .to_string(),
        };
        return (confiner, Vec::new());
    }

    let seccomp = linux::seccomp_plan(net_via_seccomp);
    // The floor's absolute rows ride the subtract holes. Any-depth (`**/`) floor rows cannot be
    // rooted Landlock rules (formwork-confine rejects them loud); they are withheld here and the
    // credentials report marks the affected types Partial -- reported, never silently pretended
    // (FW-INV5/6). No exemption plumbing exists on Linux because only any-depth rows can cross
    // into an excluded type's scope.
    let mut subtract = input.subtract.clone();
    subtract.extend(input.floor.iter().filter(|p| !p.is_any_depth()).cloned());
    let policy = LinuxPolicy {
        landlock_abi_target: host.landlock_abi,
        read_mode: input.read_mode,
        reads: input.effective_reads.clone(),
        writes: input.writes.clone(),
        subtract: canonicalize_set(&subtract),
        write_subtract: input.write_subtract.clone(),
        exec: exec_plan,
        net: net_plan,
        seccomp,
        no_new_privs: true,
    };
    (ConfinerPolicy::Linux(policy), direct_ports)
}

/// Serialize a compiled policy to canonical, compact JSON. Byte-identical for equal inputs
/// (FW-FID4): `BTreeMap`s and canonicalized vectors fix key and element order.
pub fn to_canonical_json(policy: &CompiledPolicy) -> Vec<u8> {
    serde_json::to_vec(policy).expect("CompiledPolicy is always serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use formwork_blueprint::{FsBlueprint, Visibility};

    fn pp(s: &str) -> PathPattern {
        PathPattern::parse(s).unwrap()
    }

    fn sample_blueprint() -> Blueprint {
        let mut mcp = BTreeMap::new();
        mcp.insert(
            "files".to_string(),
            formwork_blueprint::McpPolicy {
                tools: Visibility::Allow(vec!["read_file".into()]),
                ..Default::default()
            },
        );
        Blueprint {
            fs: FsBlueprint {
                read_mode: ReadMode::Closed,
                reads: vec![pp("/work/**")],
                writes: vec![pp("/work/project/**")],
                subtract: vec![pp("/work/.ssh/**")],
                write_subtract: vec![pp("**/.git/hooks/**")],
            },
            net: NetPosture::Deny,
            exec: ExecPosture::Unrestricted,
            mcp,
            ..Blueprint::empty()
        }
    }

    /// These unit tests isolate non-catalog behavior, so they compile with NO credential floor;
    /// catalog behavior has its own tests below and in the blueprint crate.
    fn compile(blueprint: &Blueprint, host: &HostProfile) -> CompiledPolicy {
        super::compile(blueprint, host, &ResolvedCatalog::empty_no_floor())
    }

    #[test]
    fn writes_fold_into_effective_reads() {
        let input = CompileInput::from_blueprint(
            &sample_blueprint().canonicalize(),
            &ResolvedCatalog::empty_no_floor(),
        );
        // /work/project (write) is under /work (read) so it's canonicalized away.
        assert_eq!(input.effective_reads, vec![pp("/work/**")]);
    }

    #[test]
    fn macos_compile_is_seatbelt_enforced() {
        let policy = compile(&sample_blueprint(), &HostProfile::synthetic_macos());
        assert!(matches!(policy.confiner, ConfinerPolicy::Macos(_)));
        assert!(policy.report.per_capability[&Capability::FsRead].is_enforced());
        assert!(policy.report.per_capability[&Capability::NetDefaultDeny].is_enforced());
        assert!(policy.report.per_capability[&Capability::McpShading].is_enforced());
    }

    #[test]
    fn linux_modern_uses_landlock_fs_and_seccomp_netdeny() {
        let policy = compile(&sample_blueprint(), &HostProfile::synthetic_linux(Some(6)));
        assert!(policy.report.per_capability[&Capability::FsRead].is_enforced());
        match &policy.confiner {
            ConfinerPolicy::Linux(l) => {
                // net-deny is the complete seccomp inet deny (covers UDP), not Landlock's TCP-only.
                assert!(matches!(l.net, LinuxNetPlan::SeccompDenyInet));
                assert!(l.no_new_privs);
            }
            other => panic!("expected Linux confiner, got {other:?}"),
        }
        assert!(matches!(
            policy.report.per_capability[&Capability::CrossDomainSocket],
            Fidelity::Partial { .. }
        ));
    }

    #[test]
    fn linux_port_tier_uses_landlock_tcp() {
        let blueprint = Blueprint {
            net: NetPosture::Ports(vec![443]),
            ..Blueprint::empty()
        };
        let policy = compile(&blueprint, &HostProfile::synthetic_linux(Some(6)));
        match &policy.confiner {
            ConfinerPolicy::Linux(l) => assert!(
                matches!(&l.net, LinuxNetPlan::LandlockTcp { ports } if ports == &vec![443]),
                "the TCP port tier is carried by Landlock net"
            ),
            other => panic!("expected Linux confiner, got {other:?}"),
        }
    }

    #[test]
    fn linux_old_kernel_denies_net_via_seccomp() {
        let policy = compile(&sample_blueprint(), &HostProfile::synthetic_linux(Some(1)));
        match &policy.confiner {
            ConfinerPolicy::Linux(l) => assert!(matches!(l.net, LinuxNetPlan::SeccompDenyInet)),
            other => panic!("expected Linux confiner, got {other:?}"),
        }
        assert!(policy.report.per_capability[&Capability::NetDefaultDeny].is_enforced());
    }

    #[test]
    fn linux_without_landlock_reports_fs_unenforceable() {
        let mut host = HostProfile::synthetic_linux(None);
        host.seccomp = true;
        let policy = compile(&sample_blueprint(), &host);
        assert!(matches!(
            policy.report.per_capability[&Capability::FsRead],
            Fidelity::Unenforceable { .. }
        ));
        assert!(policy.report.net_is_fail_closed());
    }

    #[test]
    fn no_confiner_at_all_is_unavailable_but_reported() {
        let host = HostProfile {
            os: Os::Linux,
            landlock_abi: None,
            seccomp: false,
            seatbelt: false,
            os_version: "ancient".to_string(),
        };
        let policy = compile(&sample_blueprint(), &host);
        assert!(matches!(
            policy.confiner,
            ConfinerPolicy::Unavailable { .. }
        ));
        assert!(
            !policy.report.net_is_fail_closed(),
            "net is genuinely unenforceable here and says so"
        );
    }

    #[test]
    fn env_posture_reported_honestly() {
        use formwork_blueprint::{EnvPosture, EnvScrub};
        // Passthrough asks for nothing -> no row.
        let pass = compile(&Blueprint::empty(), &HostProfile::synthetic_macos());
        assert!(!pass
            .report
            .per_capability
            .contains_key(&Capability::EnvScrub));

        // Allowlist is exact -> Enforced.
        let allow = compile(
            &Blueprint {
                env: EnvPosture::Allowlist(vec!["PATH".into()]),
                ..Blueprint::empty()
            },
            &HostProfile::synthetic_macos(),
        );
        assert!(allow.report.per_capability[&Capability::EnvScrub].is_enforced());

        // Scrub is heuristic -> Partial, never a silent Enforced over-claim (FW-XR1).
        let scrub = compile(
            &Blueprint {
                env: EnvPosture::Scrub(EnvScrub::default()),
                ..Blueprint::empty()
            },
            &HostProfile::synthetic_macos(),
        );
        assert!(matches!(
            scrub.report.per_capability[&Capability::EnvScrub],
            Fidelity::Partial {
                backend: Backend::Launcher,
                ..
            }
        ));
    }

    #[test]
    fn catalog_floor_rides_linux_subtract_absolute_rows_only() {
        let catalog = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        let policy = super::compile(
            &Blueprint::empty(),
            &HostProfile::synthetic_linux(Some(6)),
            &catalog,
        );
        let linux = match &policy.confiner {
            ConfinerPolicy::Linux(p) => p,
            other => panic!("expected linux policy, got {other:?}"),
        };
        assert!(linux.subtract.contains(&pp("/home/x/.ssh/**")));
        assert!(
            !linux.subtract.iter().any(|p| p.is_any_depth()),
            "any-depth floor rows cannot be rooted Landlock rules and must be withheld"
        );
        // ...and the withholding is REPORTED, never silent (FW-INV5): the all-any-depth backstop
        // and the dotenv type are Partial on Linux, absolute types ride Landlock.
        let creds = &policy.report.credentials;
        assert!(matches!(creds.backstop, Some(Fidelity::Partial { .. })));
        assert!(matches!(
            creds.per_type["dotenv"].path,
            Some(Fidelity::Partial { .. })
        ));
        assert!(matches!(
            creds.per_type["ssh"].path,
            Some(Fidelity::Enforced {
                backend: Backend::Landlock
            })
        ));
    }

    #[test]
    fn excluded_type_leaves_report_per_type_and_lists_allowed() {
        let catalog = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        let bp = Blueprint {
            allow_credentials: vec!["aws".to_string()],
            ..Blueprint::empty()
        };
        let policy = super::compile(&bp, &HostProfile::synthetic_macos(), &catalog);
        let creds = &policy.report.credentials;
        assert!(
            !creds.per_type.contains_key("aws"),
            "excluded type must not be claimed"
        );
        assert_eq!(creds.allowed, vec!["aws"]);
        assert!(
            creds.per_type.contains_key("ssh"),
            "adjacent types stay enforced"
        );
        assert!(creds.launcher_contingency.contains("launching process"));
    }

    #[test]
    fn deterministic_compile_is_byte_identical() {
        let blueprint = sample_blueprint();
        let host = HostProfile::synthetic_linux(Some(4));
        let a = to_canonical_json(&compile(&blueprint, &host));
        let b = to_canonical_json(&compile(&blueprint, &host));
        assert_eq!(a, b);
        let mut blueprint2 = blueprint.clone();
        blueprint2.fs.reads.insert(0, pp("/work/**")); // duplicate; canonicalization removes it
        let c = to_canonical_json(&compile(&blueprint2, &host));
        assert_eq!(a, c);
    }

    #[test]
    fn port_tier_unenforceable_on_old_linux_but_fail_closed() {
        let blueprint = Blueprint {
            net: NetPosture::Ports(vec![8080]),
            ..Blueprint::empty()
        };
        let policy = compile(&blueprint, &HostProfile::synthetic_linux(Some(1)));
        assert!(matches!(
            policy.report.per_capability[&Capability::NetPortTier],
            Fidelity::Unenforceable { .. }
        ));
        assert!(policy.report.net_is_fail_closed());
        assert!(policy.gateway.direct_tcp_ports.is_empty());
    }
}
