//! The capability compiler: the single authority mapping a [`Blueprint`] to concrete mechanisms. Pure --
//! it never touches the kernel -- so it runs anywhere, is inspectable without enforcing (FW-FID2),
//! and is deterministic in `(blueprint, host)` (FW-FID4). Impurity is confined to the [`HostProfile`]
//! the caller passes in; a synthetic profile compiles a policy for a platform you are not on.

mod linux;
mod policy;
mod report;
mod sbpl;

pub use sbpl::{channel_services, Service, CHANNEL_SERVICES, MACOS_RESOLVER_SOCKET};

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
    /// The marker the Gateway's peer check recognizes the session's processes by (FW-EGR9 on
    /// macOS); known only when compiling for a spawn with host rules.
    pub session_marker: Option<SessionMarker>,
    /// The tag every macOS deny carries into its Sandbox record (FW-DISC2); known only when
    /// compiling for a spawn.
    pub deny_tag: Option<String>,
    /// Pathname sockets granted by a literal write grant (FW-ISO12, FEP-5 §3.1.1).
    pub unix_socket_grants: Vec<PathPattern>,
    /// Whether any credential is brokered (FW-CRED11).
    pub brokered: bool,
    /// Whether the `os-keyring` type is lifted (FW-CRED13).
    pub keyring_lifted: bool,
    /// The keychain's Mach services (the catalog's `mach:` services of `os-keyring`), denied on
    /// macOS until a type that reaches them is lifted (FW-CRED13).
    pub keyring_services: Vec<String>,
    /// Whether an exposed type reaches the keychain on macOS: `os-keyring` itself, or a type whose
    /// macOS location is the keychain (`claude`, FEP-5 §3.4).
    pub keychain_lifted: bool,
}

impl CompileInput {
    fn from_blueprint(blueprint: &Blueprint, catalog: &ResolvedCatalog) -> Self {
        let mut reads = blueprint.fs.reads.clone();
        reads.extend(blueprint.fs.writes.iter().cloned());
        // Write grants imply read; the no-create grant is a write grant too.
        reads.extend(blueprint.fs.writes_no_create.iter().cloned());
        let exposed = blueprint.exposed_credentials();
        let keyring_services: Vec<String> = catalog
            .types
            .iter()
            .filter(|(name, _)| name.as_str() == formwork_blueprint::OS_KEYRING)
            .flat_map(|(_, entry)| entry.services.iter())
            .filter_map(|s| s.strip_prefix("mach:"))
            .map(str::to_string)
            .collect();
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
            session_marker: None,
            deny_tag: None,
            brokered: blueprint.brokered_credentials().next().is_some(),
            keyring_lifted: exposed.iter().any(|t| t == formwork_blueprint::OS_KEYRING),
            keyring_services: keyring_services.clone(),
            keychain_lifted: catalog
                .types
                .iter()
                .filter(|(name, _)| exposed.iter().any(|e| e == name.as_str()))
                .flat_map(|(_, entry)| entry.services.iter())
                .filter_map(|s| s.strip_prefix("mach:"))
                .any(|s| keyring_services.iter().any(|k| k == s)),
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

/// Pure and deterministic in `(blueprint, host, catalog)`. The catalog is a mandatory input by
/// design: the credential floor (FW-CRED4) cannot be forgotten, only explicitly resolved (or,
/// in tests, explicitly emptied) at the edge that knows `$HOME`.
pub fn compile(
    blueprint: &Blueprint,
    host: &HostProfile,
    catalog: &ResolvedCatalog,
) -> CompiledPolicy {
    compile_for_session(blueprint, host, catalog, &SessionSpec::default())
}

/// A per-session secret the macOS profile carries so the Gateway can tell the session's processes
/// from every other process (FW-EGR9; FEP-5 §3.1, characterization C2): the profile denies one
/// Mach service name derived from it and allows another. An unconfined process may look up both;
/// another sandbox denies both, or allows both; only a process confined by this session's profile
/// is denied the first and allowed the second, and `sandbox_check` asks without a violation record.
/// The names are never written where the session can read them, so a process outside the session
/// cannot adopt a profile that carries them.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionMarker(String);

impl SessionMarker {
    /// `nonce` is a per-session random value of hex digits.
    pub fn new(nonce: &str) -> SessionMarker {
        SessionMarker(nonce.to_string())
    }

    pub fn denied_service(&self) -> String {
        format!("dev.formwork.session.{}.d", self.0)
    }

    pub fn allowed_service(&self) -> String {
        format!("dev.formwork.session.{}.a", self.0)
    }
}

impl std::fmt::Debug for SessionMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionMarker(..)")
    }
}

/// What a spawned session's profile names beyond the blueprint (FW-EGR8, FW-EGR9): the Gateway
/// listener's loopback port and the marker its peer check recognizes the session by.
#[derive(Clone, Debug)]
pub struct SessionGateway {
    pub port: u16,
    pub marker: SessionMarker,
}

/// What a spawned session's profile names beyond the blueprint.
#[derive(Clone, Debug, Default)]
pub struct SessionSpec {
    /// The Gateway listener the session's egress goes to and the marker its peer check asks for
    /// (FW-EGR8, FW-EGR9, FW-EGR14).
    pub gateway: Option<SessionGateway>,
    /// A per-session tag every macOS deny carries into its Sandbox record, so the unified log's
    /// records name the session that produced them (FW-DISC2). Distinct from the marker: a session
    /// that reads its own records learns this tag, never the marker.
    pub deny_tag: Option<String>,
}

/// [`compile`] for a session: the per-spawn Gateway listener and deny tag are not blueprint
/// content. A dry run compiles with neither, and the macOS profile then allows no outbound
/// endpoint at all (fail-closed). Still pure and deterministic in its inputs (FW-FID4).
pub fn compile_for_session(
    blueprint: &Blueprint,
    host: &HostProfile,
    catalog: &ResolvedCatalog,
    session: &SessionSpec,
) -> CompiledPolicy {
    let blueprint = blueprint.canonicalize();
    let mut input = CompileInput::from_blueprint(&blueprint, catalog);
    input.gateway_port = session.gateway.as_ref().map(|g| g.port);
    input.session_marker = session.gateway.as_ref().map(|g| g.marker.clone());
    input.deny_tag = session.deny_tag.clone();

    let mut per_capability: BTreeMap<Capability, Fidelity> = BTreeMap::new();
    let mut withheld: Vec<String> = Vec::new();

    let (confiner, direct_tcp_ports) = match host.os {
        Os::MacOs => compile_macos(&input, host, &mut per_capability),
        Os::Linux => compile_linux(&input, host, &mut per_capability, &mut withheld),
    };
    let supervised = supervised(&input, host);
    egress_rows(&input, host, supervised, &mut per_capability);
    let channels = baseline_rows(&input, host, supervised, &mut per_capability);

    // Filesystem invisibility is never provided; document it as an explicit, reported fact.
    per_capability.insert(
        Capability::FsInvisibility,
        Fidelity::Unenforceable {
            reason: "Formwork denies with EACCES/EPERM; it does not emulate ENOENT (design §3, §4)"
                .to_string(),
        },
    );

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
        }
        EnvPosture::Scrub(_) => {
            per_capability.insert(
                Capability::EnvScrub,
                Fidelity::Partial {
                    backend: Backend::Launcher,
                    reason: "heuristic: drops secret-shaped names and values; a secret with neither a known marker name nor a recognized value shape (e.g. an inline credential in DATABASE_URL) is not caught -- pin it with an explicit deny or use an allowlist".to_string(),
                },
            );
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
    }

    let credentials = credential_report(catalog, &blueprint, host, &per_capability);
    let semantics = per_capability
        .keys()
        .map(|&cap| (cap, cap.semantics()))
        .collect();
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

/// The Partial reason for a row set Landlock can only partly root: its any-depth rows are withheld,
/// and its absolute rows are named as enforced only when it has some -- the backstop and the
/// default tamper vectors are any-depth throughout, and the clause would read as an enforcement
/// claim for them (FW-INV5).
fn any_depth_withheld(has_absolute: bool, cite: &str) -> String {
    format!(
        "any-depth (`**/`) rows cannot be rooted Landlock rules and are withheld on Linux{} ({cite})",
        if has_absolute {
            "; absolute rows are enforced"
        } else {
            ""
        }
    )
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
                reason: any_depth_withheld(
                    paths.iter().any(|p| !p.is_any_depth()),
                    "formwork.md §9, FW-CRED9",
                ),
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
        .brokered_credentials()
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
    caps.insert(Capability::FsRead, seatbelt("filesystem read scope"));
    caps.insert(Capability::FsWrite, seatbelt("filesystem write scope"));
    // FW-EGR15 lets a confined login flow accept its loopback callback, but Seatbelt's local
    // filter names only `*` or `localhost`, and `localhost` matches every local address: the same
    // listener accepts connections on the host's other interfaces (characterization C1).
    caps.insert(
        Capability::NetDefaultDeny,
        match seatbelt("network default-deny") {
            Fidelity::Enforced { backend } => Fidelity::Partial {
                backend,
                reason: "outbound connections are denied apart from the granted endpoints; a \
                         listener the session opens for a loopback callback (FW-EGR15) also \
                         accepts connections on the host's other addresses, because Seatbelt's \
                         `localhost` local filter matches every local address"
                    .to_string(),
            },
            other => other,
        },
    );
    // Seatbelt path-gates UNIX sockets under `(deny network*)`, so cross-domain socket control and
    // pathname sockets are closed apart from granted literals.
    caps.insert(
        Capability::CrossDomainSocket,
        seatbelt("UNIX-socket control"),
    );
    caps.insert(
        Capability::NetUnixSocket,
        seatbelt("pathname-socket control"),
    );
    caps.insert(Capability::NetUdp, seatbelt("UDP/raw closure"));
    if !input.write_subtract.is_empty() {
        caps.insert(Capability::TamperVectors, seatbelt("the tamper-vector set"));
    }

    let mut direct_ports = Vec::new();
    match &input.net {
        NetPosture::Ports(ports) => {
            caps.insert(Capability::NetPortTier, seatbelt("the direct port tier"));
            direct_ports = ports.clone();
            // D8: the port tier re-allows the mDNSResponder literal, a name-resolution channel the
            // report must list.
            caps.insert(
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
            caps.insert(Capability::NetResolver, seatbelt("resolver closure"));
        }
    }
    if let ExecPosture::Allowlist(_) = &input.exec {
        caps.insert(Capability::Exec, seatbelt("the exec allow-list"));
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
    caps.insert(Capability::NetUdp, seccomp_or("UDP/raw closure"));
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

    let mut direct_ports = Vec::new();
    match tier {
        PortTier::NotRequested => {}
        PortTier::Enforced => {
            caps.insert(Capability::NetPortTier, landlock());
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
        }
    }

    // Optional exec allow-list (Landlock FS_EXECUTE); seccomp cannot filter execve by path.
    let exec_plan = match &input.exec {
        ExecPosture::Unrestricted => ExecPlan::Unrestricted,
        ExecPosture::Allowlist(paths) => {
            if has_landlock {
                // Landlock checks execute on the ELF interpreter an `execve` opens, so the confiner
                // grants it too, or no dynamically linked binary starts. A loader invoked directly
                // maps its argument without an exec check, and Landlock cannot tell the two opens
                // apart (FW-INV5).
                caps.insert(
                    Capability::Exec,
                    Fidelity::Partial {
                        backend: Backend::Landlock,
                        reason: "the standard dynamic loader the allow-listed binaries need is \
                                 granted execute too (the one a listed file names; every one for \
                                 a listed directory), and a loader runs any ELF the session can \
                                 read when invoked as `ld.so <file>`, so the allow-list limits \
                                 which files are exec'd, not which readable binaries run; execve \
                                 also reads the file it runs, so an `exec:` grant runs a file only \
                                 where a read grant covers it"
                            .to_string(),
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
    caps.insert(
        Capability::NetUnixSocket,
        Fidelity::Partial {
            backend: Backend::Launcher,
            reason: pathname_gap.to_string(),
        },
    );

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
                reason: any_depth_withheld(!write_subtract.is_empty(), "see `withheld`"),
            }
        };
        caps.insert(Capability::TamperVectors, fidelity);
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
                if !host.seatbelt {
                    Fidelity::Unenforceable {
                        reason: "Seatbelt unavailable on this host".to_string(),
                    }
                } else if matches!(channel, Channel::Camera | Channel::Microphone) {
                    // A hosted runner has no camera or microphone, so these service names are the
                    // documented ones, not observed ones.
                    Fidelity::Partial {
                        backend: Backend::Seatbelt,
                        reason: format!(
                            "SBPL deny installed ({}); not characterized: the CI hosts have no \
                             capture device",
                            sbpl::channel_mechanism(channel)
                        ),
                    }
                } else {
                    // Characterized on macOS 14 and 15 (FEP-5 §6.3 C3, C4): each probe is denied
                    // under these rules, and no probe reaches a service the map does not name.
                    Fidelity::Enforced {
                        backend: Backend::Seatbelt,
                    }
                }
            }
            Os::Linux => linux_channel_fidelity(channel, fs_enforced, supervised, host),
        };
        let cap = Capability::Channel(channel);
        caps.insert(cap, fidelity);
    }

    let privileged = match host.os {
        // Characterization C8: the toolchain suite (git, Python, Node, cc, cargo, swift build,
        // gh, Homebrew, curl) opens no IOKit user client, but Metal opens the GPU's and IOSurface's,
        // whose class names differ by GPU; an allowlist from the paravirtual GPU of a hosted runner
        // would break GPU work on real hardware.
        Os::MacOs => Fidelity::Partial {
            backend: Backend::Seatbelt,
            reason: "mach-priv-host-port and mach-priv-task-port are denied; IOKit user clients \
                     stay open, because GPU compute needs the GPU's own user-client classes, \
                     which differ by hardware"
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

    let environment = match host.os {
        // Characterization C5: the kern.procargs2 sysctl returns a same-uid process's exec-time
        // environment, and no Seatbelt operation mediates it -- not sysctl-read, by name or
        // whole, nor process-info.
        Os::MacOs => Fidelity::Unenforceable {
            reason: "other same-uid processes' exec-time environments are readable through the \
                     kern.procargs2 sysctl, which Seatbelt does not mediate; formwork zeroes its \
                     own, so the Gateway's credentials are not among them"
                .to_string(),
        },
        Os::Linux if host.user_namespaces && input.isolate.contains(&IsolateMember::Processes) => {
            // FW-ISO16: the fresh procfs lists only session processes.
            Fidelity::Enforced {
                backend: Backend::Namespaces,
            }
        }
        // Landlock refuses a confined process ptrace-class access to any process outside its
        // domain, which is the check `/proc/<pid>/environ` goes through (FW-ISO16).
        Os::Linux if host.landlock_abi.is_some() && !facilities.ptrace_privileged => {
            Fidelity::Enforced {
                backend: Backend::Landlock,
            }
        }
        Os::Linux if host.landlock_abi.is_some() => Fidelity::Partial {
            backend: Backend::Landlock,
            reason: format!(
                "Landlock refuses ptrace-class access, /proc/<pid>/environ included, to processes \
                 outside the session, but formwork runs with CAP_SYS_ADMIN, CAP_PERFMON or \
                 CAP_SYS_PTRACE, which the confined process keeps and which can lift that \
                 refusal{}; run formwork unprivileged, or isolate = [\"processes\"] closes it",
                if facilities.pid_ns_nested {
                    " (an outer PID namespace limits it to processes inside that namespace)"
                } else {
                    ""
                }
            ),
        },
        Os::Linux => Fidelity::Unenforceable {
            reason: "Landlock unavailable on this host; same-uid processes' /proc/<pid>/environ \
                     is readable; isolate = [\"processes\"] closes it"
                .to_string(),
        },
    };
    caps.insert(Capability::ProcessEnvironment, environment);

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
                    // Characterization C6 and C5.
                    IsolateMember::Processes => {
                        "signals and process inspection are refused for every process outside \
                         the session; their pids, names and arguments stay visible through \
                         sysctl, and their exec-time environments through kern.procargs2"
                    }
                    // Characterization C7: Python's multiprocessing names its semaphores and
                    // shared memory itself, so a session prefix would break it.
                    IsolateMember::Ipc => {
                        "SysV IPC is denied; POSIX IPC names are global on macOS, and libraries \
                         choose them, so they cannot be confined to a session prefix"
                    }
                }
                .to_string(),
            },
        };
        caps.insert(cap, fidelity);
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
    matches!(input.net, NetPosture::AllowHosts(_)) && host.can_supervise_connect()
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
) {
    let NetPosture::AllowHosts(table) = &input.net else {
        return;
    };
    let has_tunnel = table
        .rules
        .iter()
        .any(|r| matches!(r.access, formwork_blueprint::HostAccess::Tunnel));
    let has_inspected = table.rules.iter().any(|r| r.is_inspected());
    let tunnel_gap = "`tunnel:` hosts are forwarded once the ClientHello's server name matches the CONNECT host (FW-EGR16), but the request inside is opaque: a CDN serving many names from one address can be fronted (FW-EGR5)";
    let unavailable = format!(
        "connect supervision is unavailable on this host: it needs {}; egress fails closed and \
         `run` refuses the host rules",
        formwork_detect::CONNECT_SUPERVISION_NEEDS
    );
    match host.os {
        Os::Linux if !supervised => {
            caps.insert(
                Capability::NetHostScope,
                Fidelity::Unenforceable {
                    reason: unavailable.to_string(),
                },
            );
            return;
        }
        Os::Linux => {
            caps.insert(
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
            caps.insert(Capability::NetDefaultDeny, supervisor());
            caps.insert(Capability::NetResolver, supervisor());
            let sendmsg_gap = "addressed sendmsg()/sendmmsg() on an AF_UNIX datagram socket is not mediated (its destination sits in memory seccomp cannot read); connect() and addressed sendto() are";
            caps.insert(
                Capability::NetUnixSocket,
                Fidelity::Partial {
                    backend: Backend::Supervisor,
                    reason: sendmsg_gap.to_string(),
                },
            );
            caps.insert(
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
            // FW-EGR9: the listener admits a connection only when it carries the per-session
            // credential and a process of the session holds its client end (characterization C2).
            caps.insert(
                Capability::NetHostScope,
                if host.seatbelt {
                    if has_tunnel {
                        Fidelity::Partial {
                            backend: Backend::Gateway,
                            reason: tunnel_gap.to_string(),
                        }
                    } else {
                        Fidelity::Enforced {
                            backend: Backend::Gateway,
                        }
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
        caps.insert(
            Capability::NetInspection,
            Fidelity::Enforced {
                backend: Backend::Gateway,
            },
        );
    }
    if input.brokered {
        // FW-CRED17: the reflection guard scans for the credential's wire encodings in responses
        // it can read, which is why it refuses any content coding but identity; an upstream that
        // echoes the credential transformed (escaped, re-encoded, split across WebSocket frames)
        // is not recognized.
        let reason = "responses to brokered requests must be identity-coded (any other content \
                      coding is refused), and one that carries the credential or its scheme value \
                      is ended; an echo transformed some other way (escaped, re-encoded, split \
                      across WebSocket frames) is not recognized"
            .to_string();
        caps.insert(
            Capability::CredentialBroker,
            Fidelity::Partial {
                backend: Backend::Gateway,
                reason,
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
        // Outbound is denied, but the loopback-callback listener is not loopback-only (C1).
        assert!(matches!(
            &policy.report.per_capability[&Capability::NetDefaultDeny],
            Fidelity::Partial { backend: Backend::Seatbelt, reason } if reason.contains("FW-EGR15")
        ));
        assert!(policy.report.per_capability[&Capability::McpShading].is_enforced());
    }

    /// A blueprint exercising every Seatbelt-carried macOS capability at once: fs reads + writes
    /// (FsRead/FsWrite), a default-deny net posture with a direct port tier (NetDefaultDeny/
    /// CrossDomainSocket/NetPortTier), and an exec allowlist (Exec). Used to prove all six caps
    /// track `host.seatbelt` together -- both the deny arm (unavailable -> Unenforceable) and the
    /// allow arm (available -> Enforced{Seatbelt}), a paired report-soundness check (FW-INV5).
    fn macos_all_caps_blueprint() -> Blueprint {
        Blueprint {
            fs: FsBlueprint {
                read_mode: ReadMode::Closed,
                reads: vec![pp("/work/**")],
                writes: vec![pp("/work/project/**")],
                writes_no_create: vec![],
                subtract: vec![],
                write_subtract: vec![],
            },
            net: NetPosture::Ports(vec![443]),
            exec: ExecPosture::Allowlist(vec![pp("/usr/bin/git")]),
            ..Blueprint::empty()
        }
    }

    /// The six macOS capabilities that ride Seatbelt; all must appear in a report compiled from
    /// `macos_all_caps_blueprint`.
    const MACOS_SEATBELT_CAPS: [Capability; 6] = [
        Capability::FsRead,
        Capability::FsWrite,
        Capability::NetDefaultDeny,
        Capability::CrossDomainSocket,
        Capability::NetPortTier,
        Capability::Exec,
    ];

    #[test]
    fn macos_without_seatbelt_reports_unenforceable_not_enforced() {
        // A macOS host lacking Seatbelt must not silently over-claim (FW-INV5/FW-XR1); ALL six
        // Seatbelt-carried caps -- including the direct port tier and the exec allowlist -- degrade
        // to Unenforceable, mirroring the Linux no-Landlock branch. Never a silent Enforced.
        let mut host = HostProfile::synthetic_macos();
        host.seatbelt = false;
        let policy = compile(&macos_all_caps_blueprint(), &host);
        for cap in MACOS_SEATBELT_CAPS {
            assert!(
                matches!(
                    policy.report.per_capability[&cap],
                    Fidelity::Unenforceable { .. }
                ),
                "{cap:?} should be Unenforceable without Seatbelt, got {:?}",
                policy.report.per_capability[&cap]
            );
        }
    }

    #[test]
    fn macos_with_seatbelt_reports_all_caps_enforced() {
        // The paired allow arm (FW-INV5 report soundness): the SAME six caps that degrade above are
        // reported by Seatbelt when the host carries it -- Enforced, the default deny Partial --
        // not self-agreement, a real allow/deny split against the identical blueprint.
        let host = HostProfile::synthetic_macos();
        assert!(host.seatbelt, "synthetic macOS host has Seatbelt");
        let policy = compile(&macos_all_caps_blueprint(), &host);
        for cap in MACOS_SEATBELT_CAPS {
            // Seatbelt carries the default deny, partially: the loopback-callback listener also
            // accepts on the host's other addresses (characterization C1).
            if cap == Capability::NetDefaultDeny {
                assert!(matches!(
                    policy.report.per_capability[&cap],
                    Fidelity::Partial {
                        backend: Backend::Seatbelt,
                        ..
                    }
                ));
                continue;
            }
            assert!(
                matches!(
                    policy.report.per_capability[&cap],
                    Fidelity::Enforced {
                        backend: Backend::Seatbelt
                    }
                ),
                "{cap:?} should be Enforced{{Seatbelt}} with Seatbelt, got {:?}",
                policy.report.per_capability[&cap]
            );
        }
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
    fn linux_port_tier_uses_landlock_tcp_plus_seccomp_dgram_raw_deny() {
        let blueprint = Blueprint {
            net: NetPosture::Ports(vec![443]),
            ..Blueprint::empty()
        };
        let policy = compile(&blueprint, &HostProfile::synthetic_linux(Some(6)));
        match &policy.confiner {
            ConfinerPolicy::Linux(l) => {
                // The TCP port tier is carried by Landlock net...
                assert!(
                    matches!(&l.net, LinuxNetPlan::LandlockTcpSeccompDgramRawDeny { ports } if ports == &vec![443]),
                    "the TCP port tier is carried by Landlock net"
                );
                // ...and the inet DGRAM/RAW deny is carried by seccomp, so direct UDP/raw egress
                // (DNS tunneling) is closed while STREAM survives for Landlock to govern (FW-INV3).
                assert!(
                    l.seccomp.deny_inet_dgram_raw,
                    "the port tier must seccomp-deny inet UDP/raw, not leave them open"
                );
                assert!(
                    !l.seccomp.deny_socket_families.contains(&SocketFamily::Inet)
                        && !l
                            .seccomp
                            .deny_socket_families
                            .contains(&SocketFamily::Inet6),
                    "the inet families must not be denied wholesale, or TCP dies too"
                );
            }
            other => panic!("expected Linux confiner, got {other:?}"),
        }
    }

    /// The report must NOT over-claim (FW-INV5): under the Landlock TCP port tier, net default-deny is
    /// genuinely Enforced -- because the port tier now seccomp-denies inet UDP/raw (not TCP-only
    /// Landlock, which would leave UDP open). And it degrades honestly to Unenforceable if the host
    /// carries no seccomp to install that deny.
    #[test]
    fn linux_port_tier_net_default_deny_is_honestly_enforced() {
        let blueprint = Blueprint {
            net: NetPosture::Ports(vec![443]),
            ..Blueprint::empty()
        };
        // ABI 6 host with seccomp: UDP/raw are actually denied, so Enforced (via seccomp) is honest.
        let policy = compile(&blueprint, &HostProfile::synthetic_linux(Some(6)));
        assert_eq!(
            policy.report.per_capability[&Capability::NetDefaultDeny],
            Fidelity::Enforced {
                backend: Backend::Seccomp
            },
            "net-deny under the port tier is carried by seccomp (UDP/raw) + Landlock (TCP)"
        );
        assert!(policy.report.per_capability[&Capability::NetPortTier].is_enforced());
        assert!(policy.report.net_is_fail_closed());

        // Same ABI but no seccomp: the DGRAM/RAW deny cannot install, so net-deny must NOT be claimed
        // Enforced -- the report degrades rather than silently leaving UDP/raw open.
        let mut no_seccomp = HostProfile::synthetic_linux(Some(6));
        no_seccomp.seccomp = false;
        let policy = compile(&blueprint, &no_seccomp);
        assert!(
            matches!(
                policy.report.per_capability[&Capability::NetDefaultDeny],
                Fidelity::Unenforceable { .. }
            ),
            "without seccomp the UDP/raw deny cannot hold; net-deny must not over-claim Enforced"
        );
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

    /// FW-ISO4/FW-INV5: a Linux exec allow-list is Landlock-carried but `Partial` -- the loader its
    /// binaries need is granted too, and a loader runs what it is handed -- and `Unenforceable`
    /// without Landlock. macOS stays `Enforced` (`macos_with_seatbelt_reports_all_caps_enforced`).
    #[test]
    fn linux_exec_allowlist_is_partial_for_the_loader() {
        let blueprint = Blueprint {
            exec: ExecPosture::Allowlist(vec![pp("/usr/bin/git")]),
            ..sample_blueprint()
        };
        let policy = compile(&blueprint, &HostProfile::synthetic_linux(Some(6)));
        assert!(
            matches!(
                &policy.report.per_capability[&Capability::Exec],
                Fidelity::Partial { backend: Backend::Landlock, reason }
                    if reason.contains("loader") && reason.contains("ld.so <file>")
            ),
            "{:?}",
            policy.report.per_capability[&Capability::Exec]
        );
        let mut host = HostProfile::synthetic_linux(None);
        host.seccomp = true;
        let policy = compile(&blueprint, &host);
        assert!(matches!(
            policy.report.per_capability[&Capability::Exec],
            Fidelity::Unenforceable { .. }
        ));
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

    /// The Partial reason is what `explain` prints for the backstop, so it claims enforcement only
    /// for absolute rows that exist and cites where the withholding is specified (FW-CRED9,
    /// FW-E2E-050).
    #[test]
    fn any_depth_partial_reason_names_absolute_rows_only_when_present() {
        let mut catalog = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        let linux = HostProfile::synthetic_linux(Some(6));
        let reason = |f: &Option<Fidelity>| match f {
            Some(Fidelity::Partial { reason, .. }) => reason.clone(),
            other => panic!("expected Partial, got {other:?}"),
        };
        let creds = super::compile(&Blueprint::empty(), &linux, &catalog)
            .report
            .credentials;
        let backstop = reason(&creds.backstop);
        assert!(backstop.contains("withheld on Linux"), "{backstop}");
        assert!(backstop.contains("FW-CRED9"), "{backstop}");
        assert!(!backstop.contains("absolute rows"), "{backstop}");
        assert!(!backstop.contains("linux-backend.md"), "{backstop}");

        // A type mixing an absolute row with its any-depth ones keeps the absolute clause.
        catalog
            .types
            .get_mut("dotenv")
            .unwrap()
            .paths
            .push(pp("/home/x/.config/dotenv/**"));
        let creds = super::compile(&Blueprint::empty(), &linux, &catalog)
            .report
            .credentials;
        let mixed = reason(&creds.per_type["dotenv"].path);
        assert!(mixed.contains("absolute rows are enforced"), "{mixed}");
    }

    /// The tamper-vector Partial reason follows the same rule as the floor's: absolute
    /// write-subtract rows are named as enforced only when the set has some (FW-INV5).
    #[test]
    fn tamper_vector_reason_names_absolute_rows_only_when_present() {
        let catalog = ResolvedCatalog::empty_no_floor();
        let linux = HostProfile::synthetic_linux(Some(6));
        let reason = |rows: &[&str]| {
            let mut blueprint = Blueprint::empty();
            blueprint.fs.write_subtract = rows.iter().map(|r| pp(r)).collect();
            match super::compile(&blueprint, &linux, &catalog)
                .report
                .per_capability
                .remove(&Capability::TamperVectors)
            {
                Some(Fidelity::Partial { reason, .. }) => reason,
                other => panic!("expected Partial, got {other:?}"),
            }
        };
        let any_depth = reason(&["**/.git/config"]);
        assert!(any_depth.contains("withheld on Linux"), "{any_depth}");
        assert!(!any_depth.contains("absolute rows"), "{any_depth}");
        let mixed = reason(&["**/.git/config", "/work/.envrc"]);
        assert!(mixed.contains("absolute rows are enforced"), "{mixed}");
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
