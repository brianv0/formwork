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
pub use report::{Backend, Capability, DenialSemantics, Fidelity, FidelityReport};

use std::collections::BTreeMap;

use formwork_blueprint::{
    canonicalize_set, Blueprint, ExecPosture, NetPosture, PathPattern, ReadMode,
};
use formwork_detect::{HostProfile, Os};

use linux::PortTier;

/// The normalized intermediate both backends consume: canonicalized, with write grants folded into
/// the read surface (writes imply reads).
pub struct CompileInput {
    pub read_mode: ReadMode,
    pub effective_reads: Vec<PathPattern>,
    pub writes: Vec<PathPattern>,
    pub subtract: Vec<PathPattern>,
    pub net: NetPosture,
    pub exec: ExecPosture,
}

impl CompileInput {
    fn from_blueprint(blueprint: &Blueprint) -> Self {
        let mut reads = blueprint.fs.reads.clone();
        reads.extend(blueprint.fs.writes.iter().cloned());
        CompileInput {
            read_mode: blueprint.fs.read_mode,
            effective_reads: canonicalize_set(&reads),
            writes: canonicalize_set(&blueprint.fs.writes),
            subtract: canonicalize_set(&blueprint.fs.subtract),
            net: blueprint.net.clone(),
            exec: blueprint.exec.clone(),
        }
    }
}

/// Pure and deterministic in `(blueprint, host)`.
pub fn compile(blueprint: &Blueprint, host: &HostProfile) -> CompiledPolicy {
    let blueprint = blueprint.canonicalize();
    let input = CompileInput::from_blueprint(&blueprint);

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

    let report = FidelityReport {
        host: host.clone(),
        per_capability,
        semantics,
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
    let policy = LinuxPolicy {
        landlock_abi_target: host.landlock_abi,
        read_mode: input.read_mode,
        reads: input.effective_reads.clone(),
        writes: input.writes.clone(),
        subtract: input.subtract.clone(),
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
            },
            net: NetPosture::Deny,
            exec: ExecPosture::Unrestricted,
            mcp,
        }
    }

    #[test]
    fn writes_fold_into_effective_reads() {
        let input = CompileInput::from_blueprint(&sample_blueprint().canonicalize());
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
    fn linux_modern_uses_landlock_and_reports_socket_partial() {
        let policy = compile(&sample_blueprint(), &HostProfile::synthetic_linux(Some(6)));
        match &policy.confiner {
            ConfinerPolicy::Linux(l) => {
                assert!(matches!(l.net, LinuxNetPlan::LandlockTcp { .. }));
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
