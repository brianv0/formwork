//! The capability compiler: the single authority mapping a [`Blueprint`] to concrete mechanisms. Pure --
//! it never touches the kernel -- so it runs anywhere, is inspectable without enforcing (FW-FID2),
//! and is deterministic in `(blueprint, host)` (FW-FID4). Impurity is confined to the [`HostProfile`]
//! the caller passes in; a synthetic profile compiles a policy for a platform you are not on.

mod linux;
mod policy;
mod report;
mod sbpl;

pub use sbpl::MACOS_RESOLVER_SOCKET;

pub use policy::{
    CompiledPolicy, ConfinerPolicy, ExecPlan, GatewayPolicy, LinuxNetPlan, LinuxPolicy,
    MacosPolicy, SeccompPlan, SocketFamily,
};
pub use report::{
    Backend, Capability, ChannelReport, CredentialFidelity, CredentialReport, DenialSemantics,
    Fidelity, FidelityReport, HostPresence,
};

use std::collections::BTreeMap;

use formwork_blueprint::{
    canonicalize_set, Blueprint, Channel, ChannelPolicy, EnvPosture, ExecPosture, IsolateMember,
    NetPosture, PathPattern, ReadMode, ResolvedCatalog,
};
use formwork_detect::{HostProfile, Os};

use linux::{InetSeccompDeny, PortTier};

/// The normalized intermediate both backends consume: canonicalized, with write grants folded into
/// the read surface (writes imply reads). Operator denies (`subtract`) and the credential floor
/// (`floor`) stay separate: the floor's typed exemption (FW-CRED5) may lift a floor hole, but an
/// operator deny is never lifted by anything.
pub struct CompileInput {
    pub read_mode: ReadMode,
    pub effective_reads: Vec<PathPattern>,
    pub writes: Vec<PathPattern>,
    /// Read + modify-existing, no create (FW-CAP9); read access folds into `effective_reads`.
    pub writes_no_create: Vec<PathPattern>,
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
    /// Host-service channels the blueprint lifts from the baseline (FW-ISO13).
    pub channels: ChannelPolicy,
    pub isolate: Vec<IsolateMember>,
    /// The session Gateway's loopback port, known only when compiling for a spawn (FW-EGR8).
    pub gateway_port: Option<u16>,
    /// Pathname sockets granted by a literal write grant (FW-ISO12, FEP-5 §3.1.1).
    pub unix_socket_grants: Vec<PathPattern>,
    /// Whether any credential is brokered (FW-CRED11).
    pub brokered: bool,
    /// Whether the `os-keyring` type is lifted (FW-CRED13).
    pub keyring_lifted: bool,
}

impl CompileInput {
    fn from_blueprint(blueprint: &Blueprint, catalog: &ResolvedCatalog) -> Self {
        let mut reads = blueprint.fs.reads.clone();
        reads.extend(blueprint.fs.writes.iter().cloned());
        // Write grants imply read; the no-create grant is a write grant too.
        reads.extend(blueprint.fs.writes_no_create.iter().cloned());
        let exposed = blueprint.exposed_credentials();
        let floor_exempt: Vec<PathPattern> = catalog
            .types
            .iter()
            .filter(|(name, _)| exposed.iter().any(|a| a == name.as_str()))
            .flat_map(|(_, entry)| entry.paths.iter().cloned())
            .collect();
        CompileInput {
            read_mode: blueprint.fs.read_mode,
            effective_reads: canonicalize_set(&reads),
            writes: formwork_blueprint::canonicalize_write_set(&blueprint.fs.writes),
            writes_no_create: canonicalize_set(&blueprint.fs.writes_no_create),
            subtract: canonicalize_set(&blueprint.fs.subtract),
            write_subtract: canonicalize_set(&blueprint.fs.write_subtract),
            floor: canonicalize_set(&catalog.denied_paths(&exposed)),
            floor_exempt: canonicalize_set(&floor_exempt),
            net: blueprint.net.clone(),
            exec: blueprint.exec.clone(),
            channels: blueprint.channels.clone(),
            isolate: blueprint.isolate.clone(),
            gateway_port: None,
            brokered: blueprint
                .allow_credentials
                .iter()
                .any(|e| !matches!(e, formwork_blueprint::CredentialEntry::Expose(_))),
            keyring_lifted: exposed.iter().any(|t| t == "os-keyring"),
            // A literal (non-subtree) write grant names one file; that is how a session grants a
            // socket (`readwrite:$SSH_AUTH_SOCK`). Subtree grants never admit sockets, or a
            // writable `/tmp/**` would admit the X11 socket beneath it.
            unix_socket_grants: canonicalize_set(
                &blueprint
                    .fs
                    .writes
                    .iter()
                    .filter(|p| !p.is_subtree() && !p.is_any_depth())
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

/// Per-spawn facts that are not blueprint content: the Gateway listener port the session's egress
/// goes to (FW-EGR8/FW-EGR14). A dry-run compiles with none, and the macOS profile then allows no
/// outbound endpoint at all (fail-closed).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionEndpoints {
    pub gateway_port: Option<u16>,
}

/// Pure and deterministic in `(blueprint, host, catalog)`. The catalog is a mandatory input by
/// design: the credential floor (FW-CRED4) cannot be forgotten, only explicitly resolved (or,
/// in tests, explicitly emptied) at the edge that knows `$HOME`.
pub fn compile(
    blueprint: &Blueprint,
    host: &HostProfile,
    catalog: &ResolvedCatalog,
) -> CompiledPolicy {
    compile_for_session(blueprint, host, catalog, &SessionEndpoints::default())
}

/// [`compile`] with the per-spawn endpoints a session adds. Still pure and deterministic in its
/// inputs (FW-FID4).
pub fn compile_for_session(
    blueprint: &Blueprint,
    host: &HostProfile,
    catalog: &ResolvedCatalog,
    session: &SessionEndpoints,
) -> CompiledPolicy {
    let blueprint = blueprint.canonicalize();
    let mut input = CompileInput::from_blueprint(&blueprint, catalog);
    input.gateway_port = session.gateway_port;

    let mut per_capability: BTreeMap<Capability, Fidelity> = BTreeMap::new();
    let mut semantics: BTreeMap<Capability, DenialSemantics> = BTreeMap::new();
    let mut withheld: Vec<String> = Vec::new();

    let (confiner, direct_tcp_ports) = match host.os {
        Os::MacOs => compile_macos(&input, host, &mut per_capability, &mut semantics),
        Os::Linux => compile_linux(
            &input,
            host,
            &mut per_capability,
            &mut semantics,
            &mut withheld,
        ),
    };
    let supervised = supervised(&input, host);
    egress_rows(
        &input,
        host,
        supervised,
        &mut per_capability,
        &mut semantics,
    );
    let channels = baseline_rows(
        &input,
        host,
        supervised,
        &mut per_capability,
        &mut semantics,
    );

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
    withheld.sort();
    withheld.dedup();
    let report = FidelityReport {
        host: host.clone(),
        per_capability,
        semantics,
        credentials,
        withheld,
        channels,
    };
    let gateway = GatewayPolicy {
        servers: blueprint.mcp.clone(),
        direct_tcp_ports,
        egress: blueprint.net.host_table().cloned(),
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
    let exposed = blueprint.exposed_credentials();
    let mut per_type = BTreeMap::new();
    for (name, entry) in catalog.enforced_types(&exposed) {
        per_type.insert(
            name.to_string(),
            CredentialFidelity {
                path: (!entry.paths.is_empty()).then(|| path_fidelity_for(&entry.paths)),
                env: (!entry.envs.is_empty()).then(|| env_fidelity.clone()),
            },
        );
    }
    let backstop_lifted = exposed.iter().any(|a| a == formwork_blueprint::BACKSTOP);
    let mut brokered: Vec<String> = blueprint
        .allow_credentials
        .iter()
        .filter(|e| !matches!(e, formwork_blueprint::CredentialEntry::Expose(_)))
        .map(|e| e.name().to_string())
        .collect();
    brokered.sort();
    brokered.dedup();
    CredentialReport {
        catalog_version: catalog.version,
        allowed: exposed,
        brokered,
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
    host: &HostProfile,
    caps: &mut BTreeMap<Capability, Fidelity>,
    sem: &mut BTreeMap<Capability, DenialSemantics>,
) -> (ConfinerPolicy, Vec<u16>) {
    let sbpl = sbpl::render(input);

    // Every macOS enforcement rides Seatbelt; a macOS host without it is reported, never claimed
    // (FW-INV5/FW-XR1).
    let seatbelt = |what: &str| -> Fidelity {
        if host.seatbelt {
            Fidelity::Enforced {
                backend: Backend::Seatbelt,
            }
        } else {
            Fidelity::Unenforceable {
                reason: format!("Seatbelt unavailable on this host; {what} cannot be enforced"),
            }
        }
    };
    let mut put = |cap: Capability, f: Fidelity| {
        caps.insert(cap, f);
        sem.insert(cap, DenialSemantics::Deny);
    };
    put(Capability::FsRead, seatbelt("filesystem read scope"));
    put(Capability::FsWrite, seatbelt("filesystem write scope"));
    put(Capability::NetDefaultDeny, seatbelt("network default-deny"));
    // Seatbelt path-gates UNIX sockets under `(deny network*)`, so cross-domain socket control and
    // pathname sockets are closed apart from granted literals.
    put(
        Capability::CrossDomainSocket,
        seatbelt("UNIX-socket control"),
    );
    put(
        Capability::NetUnixSocket,
        seatbelt("pathname-socket control"),
    );
    put(Capability::NetUdp, seatbelt("UDP/raw closure"));
    if !input.write_subtract.is_empty() {
        put(Capability::TamperVectors, seatbelt("the tamper-vector set"));
    }

    let mut direct_ports = Vec::new();
    match &input.net {
        NetPosture::Ports(ports) => {
            put(Capability::NetPortTier, seatbelt("the direct port tier"));
            direct_ports = ports.clone();
            // D8: the port tier re-allows the mDNSResponder literal, a name-resolution channel the
            // report must list.
            put(
                Capability::NetResolver,
                Fidelity::Partial {
                    backend: Backend::Seatbelt,
                    reason: format!(
                        "the port tier allows the system resolver socket {} so names resolve; \
                         every looked-up name reaches mDNSResponder outside the sandbox",
                        sbpl::MACOS_RESOLVER_SOCKET
                    ),
                },
            );
        }
        // FW-EGR12: under host rules the resolver literal is dropped and every lookup happens in
        // the Gateway, which pins it (FW-ADV-008).
        NetPosture::Deny | NetPosture::AllowHosts(_) => {
            put(Capability::NetResolver, seatbelt("resolver closure"))
        }
    }
    if let ExecPosture::Allowlist(_) = &input.exec {
        put(Capability::Exec, seatbelt("the exec allow-list"));
    }

    (ConfinerPolicy::Macos(MacosPolicy { sbpl }), direct_ports)
}

/// Device-node prefixes behind the `camera` and `microphone` channels on Linux (FW-ISO13).
const LINUX_CAMERA_DEVICES: &[&str] = &["/dev/media", "/dev/v4l", "/dev/video"];
const LINUX_MICROPHONE_DEVICES: &[&str] = &["/dev/snd"];

fn compile_linux(
    input: &CompileInput,
    host: &HostProfile,
    caps: &mut BTreeMap<Capability, Fidelity>,
    sem: &mut BTreeMap<Capability, DenialSemantics>,
    withheld: &mut Vec<String>,
) -> (ConfinerPolicy, Vec<u16>) {
    let abi = host.landlock_abi.unwrap_or(0);
    let has_landlock = abi >= 1;
    let landlock = || Fidelity::Enforced {
        backend: Backend::Landlock,
    };

    // Filesystem read/write require Landlock. Report honestly if it is absent.
    if has_landlock {
        caps.insert(Capability::FsRead, landlock());
        caps.insert(Capability::FsWrite, landlock());
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

    let (net_plan, inet_deny, tier) = linux::net_plan(host, &input.net);
    // Net default-deny is seccomp-carried on every Linux path: an outright deny blocks the inet
    // family, and the port tier needs seccomp for the inet DGRAM/RAW deny (Landlock net governs TCP
    // only). Without a working seccomp filter it is not claimed (FW-ISO11, FW-INV5).
    let seccomp_or = |what: &str| -> Fidelity {
        if host.seccomp {
            Fidelity::Enforced {
                backend: Backend::Seccomp,
            }
        } else {
            Fidelity::Unenforceable {
                reason: format!("seccomp unavailable on this host; {what} cannot be enforced"),
            }
        }
    };
    caps.insert(
        Capability::NetDefaultDeny,
        seccomp_or("direct egress denial"),
    );
    sem.insert(Capability::NetDefaultDeny, DenialSemantics::Deny);
    caps.insert(Capability::NetUdp, seccomp_or("UDP/raw closure"));
    sem.insert(Capability::NetUdp, DenialSemantics::Deny);
    // D8/FW-EGR12: UDP resolution is closed with the inet deny, but the pathname resolver sockets
    // stay connect()-reachable without the supervisor, so resolution is not closed.
    caps.insert(
        Capability::NetResolver,
        Fidelity::Partial {
            backend: Backend::Seccomp,
            reason: "UDP resolution is closed, but pathname resolver sockets (nscd, \
                     systemd-resolved) are connect()-reachable; host rules route resolution \
                     through the Gateway and close them"
                .to_string(),
        },
    );
    sem.insert(Capability::NetResolver, DenialSemantics::Deny);

    let mut direct_ports = Vec::new();
    match tier {
        PortTier::NotRequested => {}
        PortTier::Enforced => {
            caps.insert(Capability::NetPortTier, landlock());
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
                caps.insert(Capability::Exec, landlock());
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

    // D5: Landlock scoping (ABI 6) covers abstract sockets and signals, never pathname sockets.
    let pathname_gap = "pathname UNIX-socket connect() is unmediated without host rules, which \
                        reaches the session bus and systemd --user where a user session runs (a \
                        path to run code outside the sandbox); the default scrub hides their \
                        locator variables but does not close the sockets";
    if abi >= 6 {
        caps.insert(
            Capability::CrossDomainSocket,
            Fidelity::Partial {
                backend: Backend::Landlock,
                reason: format!(
                    "Landlock scope blocks abstract UNIX sockets and signals outside the domain; \
                     {pathname_gap}"
                ),
            },
        );
    } else {
        caps.insert(
            Capability::CrossDomainSocket,
            Fidelity::Unenforceable {
                reason: format!(
                    "abstract-socket and signal scoping needs Landlock ABI v6; {pathname_gap}"
                ),
            },
        );
    }
    sem.insert(Capability::CrossDomainSocket, DenialSemantics::Deny);
    caps.insert(
        Capability::NetUnixSocket,
        Fidelity::Partial {
            backend: Backend::Launcher,
            reason: pathname_gap.to_string(),
        },
    );
    sem.insert(Capability::NetUnixSocket, DenialSemantics::Deny);

    // D1: any-depth write-subtract rows cannot be rooted Landlock rules; they are withheld as the
    // floor's are and reported, never silently pretended (FW-INV5/6).
    let (write_subtract, any_depth_ws): (Vec<PathPattern>, Vec<PathPattern>) = input
        .write_subtract
        .iter()
        .cloned()
        .partition(|p| !p.is_any_depth());
    if !input.write_subtract.is_empty() {
        let fidelity = if !has_landlock {
            Fidelity::Unenforceable {
                reason: "Landlock unavailable on this host".to_string(),
            }
        } else if any_depth_ws.is_empty() {
            landlock()
        } else {
            Fidelity::Partial {
                backend: Backend::Landlock,
                reason: "any-depth (`**/`) rows cannot be rooted Landlock rules and are withheld \
                         on Linux (see `withheld`); absolute rows are enforced"
                    .to_string(),
            }
        };
        caps.insert(Capability::TamperVectors, fidelity);
        sem.insert(Capability::TamperVectors, DenialSemantics::Deny);
    }
    if has_landlock {
        withheld.extend(any_depth_ws.iter().map(|p| format!("write-subtract {p}")));
        withheld.extend(
            input
                .floor
                .iter()
                .filter(|p| p.is_any_depth())
                .map(|p| format!("credential-floor {p}")),
        );
    }

    if !has_landlock && !host.seccomp {
        let confiner = ConfinerPolicy::Unavailable {
            reason: "no Landlock and no seccomp on this host; OS-level confinement unavailable"
                .to_string(),
        };
        return (confiner, Vec::new());
    }

    let supervise = matches!(net_plan, LinuxNetPlan::SupervisedConnect);
    let seccomp = linux::seccomp_plan(inet_deny, supervise);
    debug_assert!(
        !matches!(inet_deny, InetSeccompDeny::DgramRawOnly) || seccomp.deny_inet_dgram_raw
    );
    // The floor's absolute rows ride the subtract holes. Any-depth (`**/`) floor rows cannot be
    // rooted Landlock rules (formwork-confine rejects them loud); they are withheld above and the
    // credentials report marks the affected types Partial (FW-INV5/6).
    let mut subtract = input.subtract.clone();
    subtract.extend(input.floor.iter().filter(|p| !p.is_any_depth()).cloned());
    // D10: the ambient universe is a property of the read mode, not an authored row. Landlock is
    // allow-list only, so the ambient mode is rendered as a `/` read root expanded around the holes.
    let mut reads = input.effective_reads.clone();
    if input.read_mode == ReadMode::AmbientMinusSubtract {
        reads.push(PathPattern::parse("/**").expect("constant pattern"));
    }
    let mut withhold_device_prefixes: Vec<String> = Vec::new();
    if !input.channels.lifted(Channel::Camera) {
        withhold_device_prefixes.extend(LINUX_CAMERA_DEVICES.iter().map(|s| s.to_string()));
    }
    if !input.channels.lifted(Channel::Microphone) {
        withhold_device_prefixes.extend(LINUX_MICROPHONE_DEVICES.iter().map(|s| s.to_string()));
    }
    withhold_device_prefixes.sort();
    let policy = LinuxPolicy {
        landlock_abi_target: host.landlock_abi,
        read_mode: input.read_mode,
        reads: canonicalize_set(&reads),
        writes: input.writes.clone(),
        writes_no_create: input.writes_no_create.clone(),
        subtract: canonicalize_set(&subtract),
        write_subtract: canonicalize_set(&write_subtract),
        exec: exec_plan,
        net: net_plan,
        seccomp,
        no_new_privs: true,
        withhold_device_prefixes,
        unix_socket_grants: canonicalize_set(&unix_socket_grants(input, host)),
        isolate: input.isolate.clone(),
    };
    (ConfinerPolicy::Linux(Box::new(policy)), direct_ports)
}

/// The FEP-5 baseline rows shared by both backends: host-service channels (FW-ISO13), privileged
/// interfaces (FW-ISO14), process-environment disclosure (FW-ISO16), the private temporary
/// directory (FW-TRA10) and the isolation tier (FW-ISO10). Returns the per-channel detail.
fn baseline_rows(
    input: &CompileInput,
    host: &HostProfile,
    supervised: bool,
    caps: &mut BTreeMap<Capability, Fidelity>,
    sem: &mut BTreeMap<Capability, DenialSemantics>,
) -> BTreeMap<String, ChannelReport> {
    let mut channels = BTreeMap::new();
    let fs_enforced = caps
        .get(&Capability::FsRead)
        .map(Fidelity::is_enforced)
        .unwrap_or(false);
    let facilities = &host.facilities;
    for channel in Channel::ALL {
        let presence = channel_presence(host, channel);
        let lifted = input.channels.lifted(channel);
        channels.insert(
            channel.name().to_string(),
            ChannelReport {
                lifted,
                host: presence,
            },
        );
        if lifted {
            continue;
        }
        let fidelity = match host.os {
            Os::MacOs => {
                if host.seatbelt {
                    Fidelity::Partial {
                        backend: Backend::Seatbelt,
                        reason: format!(
                            "SBPL deny installed ({}); the service-name coverage is pending the \
                             macOS characterization suite (FEP-5 §6.3)",
                            sbpl::channel_mechanism(channel)
                        ),
                    }
                } else {
                    Fidelity::Unenforceable {
                        reason: "Seatbelt unavailable on this host".to_string(),
                    }
                }
            }
            Os::Linux => linux_channel_fidelity(channel, fs_enforced, supervised, host),
        };
        let cap = Capability::Channel(channel);
        caps.insert(cap, fidelity);
        sem.insert(cap, DenialSemantics::Deny);
    }

    let privileged = match host.os {
        Os::MacOs => Fidelity::Partial {
            backend: Backend::Seatbelt,
            reason: "mach-priv-host-port and mach-priv-task-port are denied; iokit-open is not \
                     yet narrowed to an allowlist (pending characterization C8)"
                .to_string(),
        },
        Os::Linux if host.seccomp => Fidelity::Enforced {
            backend: Backend::Seccomp,
        },
        Os::Linux => Fidelity::Unenforceable {
            reason: "seccomp unavailable on this host; the anti-shedding baseline cannot install"
                .to_string(),
        },
    };
    caps.insert(Capability::PrivilegedInterfaces, privileged);
    sem.insert(Capability::PrivilegedInterfaces, DenialSemantics::Deny);

    let environment = match host.os {
        Os::MacOs => Fidelity::Partial {
            backend: Backend::Seatbelt,
            reason: "the kern.procargs2 sysctl is denied, which hides other processes' \
                     environments; pending characterization C5"
                .to_string(),
        },
        Os::Linux if host.user_namespaces && input.isolate.contains(&IsolateMember::Processes) => {
            // FW-ISO16: the fresh procfs lists only session processes.
            Fidelity::Enforced {
                backend: Backend::Namespaces,
            }
        }
        Os::Linux => Fidelity::Partial {
            backend: Backend::Landlock,
            reason: if facilities.pid_ns_nested {
                "same-uid processes' /proc/<pid>/environ and cmdline are readable \
                 (ptrace_may_access is outside Landlock); an outer PID namespace limits this to \
                 processes inside it; isolate = [\"processes\"] closes it"
                    .to_string()
            } else {
                "same-uid processes' /proc/<pid>/environ and cmdline are readable \
                 (ptrace_may_access is outside Landlock); isolate = [\"processes\"] closes it"
                    .to_string()
            },
        },
    };
    caps.insert(Capability::ProcessEnvironment, environment);
    sem.insert(Capability::ProcessEnvironment, DenialSemantics::Deny);

    // FW-TRA10: the Launcher's per-session directory is private; `/tmp` stays shared when the
    // blueprint grants it (the default profile does, so tools that hardcode `/tmp` keep working).
    let tmp = std::path::Path::new("/tmp/x");
    let private_tmp_tmp = std::path::Path::new("/private/tmp/x");
    let shares_tmp = input
        .writes
        .iter()
        .any(|p| p.matches_path(tmp) || p.matches_path(private_tmp_tmp));
    let tmpfs = host.os == Os::Linux
        && host.user_namespaces
        && input.isolate.contains(&IsolateMember::Processes);
    let private_tmp = if shares_tmp {
        Fidelity::Partial {
            backend: Backend::Launcher,
            reason: if tmpfs {
                "tmpfs form: TMPDIR/TMP/TEMP point at a tmpfs in the session's mount namespace, \
                 but /tmp is shared by a blueprint write grant"
            } else {
                "directory form: TMPDIR/TMP/TEMP point at a per-session directory, but /tmp is \
                 shared by a blueprint write grant"
            }
            .to_string(),
        }
    } else {
        Fidelity::Enforced {
            backend: Backend::Launcher,
        }
    };
    caps.insert(Capability::PrivateTmp, private_tmp);
    sem.insert(Capability::PrivateTmp, DenialSemantics::Deny);

    for member in &input.isolate {
        let cap = match member {
            IsolateMember::Processes => Capability::IsolateProcesses,
            IsolateMember::Ipc => Capability::IsolateIpc,
        };
        let fidelity = match host.os {
            Os::Linux if host.user_namespaces => Fidelity::Enforced {
                backend: Backend::Namespaces,
            },
            Os::Linux => Fidelity::Unenforceable {
                reason: "unprivileged user namespaces are unavailable on this host; `run` \
                         refuses the member before spawn"
                    .to_string(),
            },
            Os::MacOs => Fidelity::Partial {
                backend: Backend::Seatbelt,
                reason: match member {
                    IsolateMember::Processes => {
                        "process-info and signal are denied for processes outside the session's \
                         children and process group; pending characterization C6"
                    }
                    IsolateMember::Ipc => "SysV IPC is denied; POSIX IPC names are global on macOS",
                }
                .to_string(),
            },
        };
        caps.insert(cap, fidelity);
        sem.insert(cap, DenialSemantics::Deny);
    }
    channels
}

/// Linux channel verdicts. The socket-shaped channels close only under supervised connect
/// (FW-ISO12), which host rules turn on; the device-shaped ones close with the filesystem grant.
fn linux_channel_fidelity(
    channel: Channel,
    fs_enforced: bool,
    supervised: bool,
    host: &HostProfile,
) -> Fidelity {
    // Under supervised connect every pathname and abstract connect() is decided outside the
    // sandbox (FW-ISO12), so the socket-shaped channels are closed.
    if supervised {
        return match channel {
            Channel::Camera | Channel::Microphone if !fs_enforced => Fidelity::Unenforceable {
                reason: "Landlock unavailable on this host; device nodes cannot be withheld"
                    .to_string(),
            },
            Channel::Camera => Fidelity::Enforced {
                backend: Backend::Landlock,
            },
            _ => Fidelity::Enforced {
                backend: Backend::Supervisor,
            },
        };
    }
    let unmediated = |what: &str| Fidelity::Partial {
        backend: Backend::Launcher,
        reason: format!(
            "pathname connect() reaches {what} without host rules; the locator variables are \
             stripped (FW-BP11), which hides the socket from well-behaved clients but does not \
             close it"
        ),
    };
    match channel {
        Channel::RunOutside => unmediated("the session bus and the systemd --user socket"),
        Channel::OpenUrl => unmediated("the session bus (the desktop portal)"),
        Channel::Clipboard | Channel::Screen => {
            if host.landlock_abi.unwrap_or(0) >= 6 {
                unmediated("the X11/Wayland pathname socket")
            } else {
                unmediated("the X11/Wayland socket, abstract X11 included (Landlock ABI < 6)")
            }
        }
        Channel::Camera if fs_enforced => Fidelity::Enforced {
            backend: Backend::Landlock,
        },
        Channel::Microphone if fs_enforced => Fidelity::Partial {
            backend: Backend::Landlock,
            reason: "/dev/snd is withheld from every grant, but the audio server socket \
                     (PulseAudio/PipeWire) is reachable by pathname connect() without host rules"
                .to_string(),
        },
        Channel::Camera | Channel::Microphone => Fidelity::Unenforceable {
            reason: "Landlock unavailable on this host; device nodes cannot be withheld"
                .to_string(),
        },
    }
}

/// Whether the Linux `connect()` supervisor carries this session (FW-EGR7).
fn supervised(input: &CompileInput, host: &HostProfile) -> bool {
    host.os == Os::Linux
        && matches!(input.net, NetPosture::AllowHosts(_))
        && host.seccomp
        && host.connect_supervision
}

/// The sockets the Linux supervisor admits besides in-session ones (FW-ISO12): literal write
/// grants, and the sockets behind lifted channels as `detect` found them (FW-FID10). `open-url`
/// never lifts a host service (FW-ISO18).
fn unix_socket_grants(input: &CompileInput, host: &HostProfile) -> Vec<PathPattern> {
    let f = &host.facilities;
    let mut paths: Vec<String> = Vec::new();
    for channel in input.channels.lifted_channels() {
        match channel {
            Channel::RunOutside => {
                paths.extend(f.session_bus.iter().cloned());
                paths.extend(f.user_manager.iter().cloned());
            }
            Channel::Clipboard | Channel::Screen => paths.extend(f.display.iter().cloned()),
            Channel::Microphone => paths.extend(f.audio.iter().cloned()),
            Channel::OpenUrl | Channel::Camera => {}
        }
    }
    // FW-CRED13: lifting `os-keyring` admits the keyring sockets and -- because the Secret Service
    // lives on it -- the session bus (the coupling the report states).
    if input.keyring_lifted {
        paths.extend(f.keyring.iter().cloned());
        paths.extend(f.session_bus.iter().cloned());
    }
    let mut grants = input.unix_socket_grants.clone();
    grants.extend(paths.iter().filter_map(|p| PathPattern::parse(p).ok()));
    grants
}

/// The host-scoped egress rows (FW-EGR1, FW-FID8): host scope, inspection, and -- under the
/// supervisor -- the net rows the supervisor now carries.
fn egress_rows(
    input: &CompileInput,
    host: &HostProfile,
    supervised: bool,
    caps: &mut BTreeMap<Capability, Fidelity>,
    sem: &mut BTreeMap<Capability, DenialSemantics>,
) {
    let NetPosture::AllowHosts(table) = &input.net else {
        return;
    };
    let mut put = |cap: Capability, f: Fidelity| {
        caps.insert(cap, f);
        sem.insert(cap, DenialSemantics::Deny);
    };
    let has_tunnel = table
        .rules
        .iter()
        .any(|r| matches!(r.access, formwork_blueprint::HostAccess::Tunnel));
    let has_inspected = table.rules.iter().any(|r| r.is_inspected());
    let tunnel_gap = "tunnel-grade hosts (`https:`) are admitted by the CONNECT target and trust the client's SNI and Host; domain fronting is not caught (FW-EGR5)";
    let unavailable = "connect supervision is unavailable on this host: it needs seccomp user \
                        notification, pidfd_getfd (Linux 5.6+), and Yama ptrace_scope 0 or 1; \
                        egress fails closed and `run` refuses the host rules";
    match host.os {
        Os::Linux if !supervised => {
            put(
                Capability::NetHostScope,
                Fidelity::Unenforceable {
                    reason: unavailable.to_string(),
                },
            );
            return;
        }
        Os::Linux => {
            put(
                Capability::NetHostScope,
                if has_tunnel {
                    Fidelity::Partial {
                        backend: Backend::Gateway,
                        reason: tunnel_gap.to_string(),
                    }
                } else {
                    Fidelity::Enforced {
                        backend: Backend::Gateway,
                    }
                },
            );
            let supervisor = || Fidelity::Enforced {
                backend: Backend::Supervisor,
            };
            put(Capability::NetDefaultDeny, supervisor());
            put(Capability::NetResolver, supervisor());
            let sendmsg_gap = "addressed sendmsg()/sendmmsg() on an AF_UNIX datagram socket is not mediated (its destination sits in memory seccomp cannot read); connect() and addressed sendto() are";
            put(
                Capability::NetUnixSocket,
                Fidelity::Partial {
                    backend: Backend::Supervisor,
                    reason: sendmsg_gap.to_string(),
                },
            );
            put(
                Capability::CrossDomainSocket,
                Fidelity::Partial {
                    backend: Backend::Supervisor,
                    reason: if host.landlock_abi.unwrap_or(0) >= 6 {
                        format!("pathname and abstract connect() are supervised; {sendmsg_gap}")
                    } else {
                        format!(
                            "pathname and abstract connect() are supervised; signals outside the \
                              domain need Landlock ABI 6; {sendmsg_gap}"
                        )
                    },
                },
            );
        }
        Os::MacOs => {
            let mut reason = "the egress listener admits the per-session proxy credential; the \
                               peer-process check is pending characterization (C2), so a same-uid \
                               process that reads the agent's environment could reach it"
                .to_string();
            if has_tunnel {
                reason = format!("{reason}; {tunnel_gap}");
            }
            put(
                Capability::NetHostScope,
                if host.seatbelt {
                    Fidelity::Partial {
                        backend: Backend::Gateway,
                        reason,
                    }
                } else {
                    Fidelity::Unenforceable {
                        reason: "Seatbelt unavailable on this host".to_string(),
                    }
                },
            );
        }
    }
    if has_inspected {
        // Every request to an inspected host is decided per method and path; a client that does
        // not trust the session CA fails its handshake and is refused -- fail-closed, not a bypass.
        // The macOS limit (Security.framework clients ignore SSL_CERT_FILE) is a compatibility
        // note the operator channel carries (FW-FID9), not a gap in what is enforced.
        put(
            Capability::NetInspection,
            Fidelity::Enforced {
                backend: Backend::Gateway,
            },
        );
    }
    if input.brokered {
        put(
            Capability::CredentialBroker,
            Fidelity::Enforced {
                backend: Backend::Gateway,
            },
        );
    }
}

/// Whether this host runs the facility a channel reaches (FW-FID10).
fn channel_presence(host: &HostProfile, channel: Channel) -> HostPresence {
    let f = &host.facilities;
    let via = match host.os {
        Os::MacOs => {
            if f.gui_session {
                Some("GUI login session".to_string())
            } else if channel == Channel::RunOutside {
                Some("launchd".to_string())
            } else {
                None
            }
        }
        Os::Linux => match channel {
            Channel::RunOutside => f.session_bus.clone().or_else(|| f.user_manager.clone()),
            Channel::OpenUrl => f.session_bus.clone(),
            Channel::Clipboard | Channel::Screen => f.display.first().cloned(),
            Channel::Camera => f.video_device.clone(),
            Channel::Microphone => f.audio.clone(),
        },
    };
    HostPresence {
        present: via.is_some(),
        via,
    }
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
                tools: Visibility::allow_exact(["read_file"]),
                ..Default::default()
            },
        );
        Blueprint {
            fs: FsBlueprint {
                read_mode: ReadMode::Closed,
                reads: vec![pp("/work/**")],
                writes: vec![pp("/work/project/**")],
                writes_no_create: vec![],
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
            ConfinerPolicy::Linux(l) => {
                assert_eq!(l.net.landlock_tcp_ports(), Some(&[443][..]));
                assert!(
                    l.seccomp.deny_inet_dgram_raw,
                    "the port tier must seccomp-deny inet UDP/raw (FW-ISO11)"
                );
            }
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
            user_namespaces: false,
            connect_supervision: false,
            facilities: Default::default(),
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
    fn floor_only_permissive_allows_everything_but_the_credential_floor() {
        // The recording-time floor guarantee: the open base still denies a credential on both axes
        // (the structural floor, FW-INV11).
        let catalog = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        let policy = super::compile(
            &Blueprint::floor_only_permissive(),
            &HostProfile::synthetic_macos(),
            &catalog,
        );
        let sbpl = match &policy.confiner {
            ConfinerPolicy::Macos(m) => &m.sbpl,
            other => panic!("expected a Seatbelt policy, got {other:?}"),
        };
        assert!(sbpl.contains("(allow default)"), "permissive base");
        assert!(
            sbpl.contains("(allow file-write* (subpath \"/\"))"),
            "open writes so the workload's writes are observable"
        );
        let denies = |verb: &str| {
            sbpl.lines()
                .any(|l| l.starts_with(verb) && l.contains("/home/x/.ssh"))
        };
        assert!(
            denies("(deny file-read*"),
            "a credential read stays floored under the permissive base"
        );
        assert!(
            denies("(deny file-write*"),
            "a credential write stays floored under the open /** grant"
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
            allow_credentials: vec!["aws".into()],
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
