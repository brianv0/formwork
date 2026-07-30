//! Phase 2 Linux backend tests -- native, Linux only, against a real kernel (Docker/Lima with
//! Docker's own seccomp/AppArmor disabled, so only Formwork's sandbox is under test). Paired
//! allow/deny probes at the real boundary (FW-INV5): a grant works *and* the matching deny bites.
//! Filesystem tests need Landlock (skip cleanly on a pre-5.13 kernel); the seccomp baseline and net
//! default-deny run everywhere.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use formwork_blueprint::{
    Blueprint, FsBlueprint, NetPosture, PathPattern, ReadMode, ResolvedCatalog,
};
use formwork_compile::{CompiledPolicy, ConfinerPolicy};
use formwork_detect::detect;

/// Integration tests enforce what the product enforces: the builtin catalog resolved for the
/// real home. The probes below touch only scratch paths, so the floor never interferes.
fn compile(blueprint: &Blueprint, host: &formwork_detect::HostProfile) -> CompiledPolicy {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    formwork_compile::compile(
        blueprint,
        host,
        &ResolvedCatalog::builtin_for_home(&home).unwrap(),
    )
}

fn have_landlock() -> bool {
    detect().landlock_abi.is_some()
}

/// A `{path}/**` subtree pattern.
fn pp(path: &Path) -> PathPattern {
    PathPattern::parse(&format!("{}/**", path.display())).unwrap()
}

/// A Closed-mode policy (grants + essentials only) compiled against the real host. Net stays the
/// `Blueprint::empty` default (Deny).
fn closed_policy(
    reads: Vec<PathPattern>,
    writes: Vec<PathPattern>,
    subtract: Vec<PathPattern>,
) -> CompiledPolicy {
    let blueprint = Blueprint {
        fs: FsBlueprint {
            read_mode: ReadMode::Closed,
            reads,
            writes,
            writes_no_create: Vec::new(),
            subtract,
            write_subtract: Vec::new(),
        },
        ..Blueprint::empty()
    };
    compile(&blueprint, &detect())
}

fn run(policy: &CompiledPolicy, mut cmd: Command) -> i32 {
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    formwork_confine::spawn_confined(&mut cmd, policy).expect("confinement applies");
    cmd.status().expect("child runs").code().unwrap_or(-1)
}

fn cat(path: &Path) -> Command {
    let mut c = Command::new("/bin/cat");
    c.arg(path);
    c
}

fn sh(script: &str) -> Command {
    let mut c = Command::new("/bin/sh");
    c.arg("-c").arg(script);
    c
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("fw-linux-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("granted")).unwrap();
        fs::create_dir_all(root.join("secret")).unwrap();
        let root = fs::canonicalize(&root).unwrap();
        fs::write(root.join("granted/ok.txt"), b"in-scope\n").unwrap();
        fs::write(root.join("secret/secret.txt"), b"TOP SECRET\n").unwrap();
        Fixture { root }
    }
    fn granted(&self) -> PathBuf {
        self.root.join("granted")
    }
    fn granted_file(&self) -> PathBuf {
        self.root.join("granted/ok.txt")
    }
    fn secret_file(&self) -> PathBuf {
        self.root.join("secret/secret.txt")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

// --- filesystem (Landlock) ---

/// FW-E2E-001 (Linux/Landlock): an in-scope read succeeds, an out-of-scope read is denied.
#[test]
fn landlock_granted_read_ok_ungranted_denied() {
    if !have_landlock() {
        eprintln!("skipping: no Landlock on this host");
        return;
    }
    let fx = Fixture::new("fs001");
    let policy = closed_policy(vec![pp(&fx.granted())], vec![], vec![]);
    assert_eq!(
        run(&policy, cat(&fx.granted_file())),
        0,
        "granted read must succeed (also proves essentials load /bin/cat under Closed mode)"
    );
    assert_ne!(
        run(&policy, cat(&fx.secret_file())),
        0,
        "out-of-scope read must be denied by Landlock"
    );
}

/// FW-E2E-003 (Linux/Landlock): subtractive expansion -- a broad grant with a hole reads everything
/// but the hole. Exercises the readdir walk that turns `subtract` into the shape of the grants.
#[test]
fn landlock_subtract_denies_within_grant() {
    if !have_landlock() {
        eprintln!("skipping: no Landlock on this host");
        return;
    }
    let fx = Fixture::new("fs003");
    let policy = closed_policy(
        vec![pp(&fx.root)],
        vec![],
        vec![pp(&fx.root.join("secret"))],
    );
    assert_eq!(
        run(&policy, cat(&fx.granted_file())),
        0,
        "a sibling of the hole stays readable"
    );
    assert_ne!(
        run(&policy, cat(&fx.secret_file())),
        0,
        "the subtracted subtree must be denied"
    );
}

/// FW-ISO2 (Linux/Landlock): writes are confined to the write grant; a readable-but-ungranted path is
/// not writable.
#[test]
fn landlock_write_confined_to_grant() {
    if !have_landlock() {
        eprintln!("skipping: no Landlock on this host");
        return;
    }
    let fx = Fixture::new("fsw");
    let policy = closed_policy(vec![pp(&fx.root)], vec![pp(&fx.granted())], vec![]);
    let in_grant = fx.granted().join("new.txt");
    let outside = fx.root.join("secret/new.txt");
    assert_eq!(
        run(&policy, sh(&format!("echo x > '{}'", in_grant.display()))),
        0,
        "write inside the write grant must succeed"
    );
    assert_ne!(
        run(&policy, sh(&format!("echo x > '{}'", outside.display()))),
        0,
        "write to a readable-but-ungranted path must be denied"
    );
}

/// HARDENING (fail-open escape): a symlink among the entries of a *split* grant (one with a hole)
/// must not grant its target. Landlock's `PathFd` follows symlinks (`O_PATH`), so the expansion must
/// skip symlink entries or reading through them escapes the wall.
#[test]
fn landlock_symlink_in_grant_does_not_escape() {
    if !have_landlock() {
        eprintln!("skipping: no Landlock on this host");
        return;
    }
    let fx = Fixture::new("symlink");
    // A hole forces `root` to be split into its entries; a symlink to /etc rides among them.
    std::os::unix::fs::symlink("/etc", fx.root.join("etclink")).unwrap();
    let policy = closed_policy(
        vec![pp(&fx.root)],
        vec![],
        vec![pp(&fx.root.join("secret"))],
    );
    assert_ne!(
        run(&policy, cat(&fx.root.join("etclink/hostname"))),
        0,
        "reading /etc through an in-grant symlink must be denied (no escape)"
    );
    assert_eq!(
        run(&policy, cat(&fx.granted_file())),
        0,
        "a real sibling of the hole stays readable"
    );
}

/// HARDENING (transparency): a confined process must read its OWN `/proc/self` -- runtimes (Python,
/// Go, glibc) depend on it. The essential must resolve to the child, not the launcher.
#[test]
fn proc_self_readable_by_child() {
    if !have_landlock() {
        eprintln!("skipping: no Landlock on this host");
        return;
    }
    let fx = Fixture::new("procself");
    let policy = closed_policy(vec![pp(&fx.granted())], vec![], vec![]);
    assert_eq!(
        run(&policy, cat(Path::new("/proc/self/status"))),
        0,
        "a confined process must be able to read its own /proc/self/status"
    );
}

/// HARDENING (transparency): safe device nodes must stay fully usable, including their ioctls --
/// interactive agents (the primary use case) ioctl their terminal for winsize/raw-mode. Landlock's
/// IOCTL_DEV right (ABI v5+) would otherwise deny every device ioctl. The probe exits 0 when the
/// ioctl reaches the device (ENOTTY on /dev/null), 7 when the sandbox denies it.
#[test]
fn device_ioctls_are_permitted() {
    if !have_landlock() {
        eprintln!("skipping: no Landlock on this host");
        return;
    }
    let probe = PathBuf::from(env!("CARGO_BIN_EXE_fw-ioctl-probe"));
    let probe_dir = probe.parent().expect("probe has a parent directory");
    let policy = closed_policy(vec![pp(probe_dir)], vec![], vec![]);
    let code = run(&policy, Command::new(&probe));
    assert_eq!(
        code, 0,
        "an ioctl on a granted device must be permitted (got {code}; 7 = Landlock denied it)"
    );
}

// --- net + seccomp baseline (run on any kernel) ---

/// FW-E2E-002 (Linux): a confined process cannot reach the network. Net-deny is carried by the seccomp
/// inet-family filter, which rejects `socket(2)` creation; the probe surfaces the EPERM as exit 7.
#[test]
fn net_default_deny_blocks_egress() {
    // Grant the probe's own directory (read = loadable/executable) rather than copying it into a
    // fresh dir and racing exec against the write (ETXTBSY on overlayfs).
    let probe = PathBuf::from(env!("CARGO_BIN_EXE_fw-connect-probe"));
    let probe_dir = probe.parent().expect("probe has a parent directory");
    let policy = closed_policy(vec![pp(probe_dir)], vec![], vec![]);
    let code = run(&policy, Command::new(&probe));
    assert_eq!(
        code, 7,
        "egress must be denied with EPERM (exit 7); got {code}"
    );
}

/// HARDENING (Linux): net-deny covers UDP, not just TCP. Landlock net governs only TCP, so deny is
/// carried by the seccomp inet-family filter, which rejects datagram `socket(2)` at creation. The
/// probe surfaces the EPERM as exit 7 -- proving the old TCP-only gap is closed.
#[test]
fn net_default_deny_blocks_udp() {
    let probe = PathBuf::from(env!("CARGO_BIN_EXE_fw-udp-probe"));
    let probe_dir = probe.parent().expect("probe has a parent directory");
    let policy = closed_policy(vec![pp(probe_dir)], vec![], vec![]);
    let code = run(&policy, Command::new(&probe));
    assert_eq!(
        code, 7,
        "UDP egress must be denied with EPERM (exit 7); got {code}"
    );
}

/// FW-ISO5 (DNS, Linux): the mirror of the macOS resolver test -- the two kernels sever DNS at
/// different layers, so the shared claim (a granted port tier can resolve a name) needs a
/// per-backend probe. Which half runs depends on the kernel, so the report drives the assertion
/// rather than a second copy of the ABI rule (FW-E2E-024, report soundness):
///
///   * tier Enforced (Landlock net, ABI 4+): net-deny's seccomp inet filter is not installed and
///     Landlock net governs TCP only, so nothing blocks the resolver's UDP:53 -- DNS works with no
///     macOS-style re-allow. Asserts not-EPERM, not success: a sandboxed runner may have no route.
///   * tier Unenforceable (below ABI 4, e.g. CI's 5.15): the tier falls back to a full seccomp inet
///     deny, so DNS is deliberately dead. That is FW-INV6 honesty, not the macOS bug -- formwork
///     reports the gap instead of silently opening egress, and the fix must not weaken it.
#[test]
fn port_tier_resolver_matches_reported_fidelity() {
    use formwork_compile::{Capability, Fidelity};
    let probe = PathBuf::from(env!("CARGO_BIN_EXE_fw-udp-probe"));
    let probe_dir = probe.parent().expect("probe has a parent directory");
    let mut blueprint = Blueprint::empty();
    blueprint.fs.read_mode = ReadMode::Closed;
    blueprint.fs.reads = vec![pp(probe_dir)];
    blueprint.net = NetPosture::Ports(vec![443]);
    let policy = compile(&blueprint, &detect());
    let tier = policy
        .report
        .per_capability
        .get(&Capability::NetPortTier)
        .expect("a requested port tier is always reported");
    let enforced = matches!(tier, Fidelity::Enforced { .. });

    let code = run(&policy, Command::new(&probe));
    if enforced {
        assert_ne!(
            code, 7,
            "an enforced port tier must leave the resolver reachable, else it reaches only IPs"
        );
    } else {
        assert_eq!(
            code, 7,
            "an unenforceable port tier must fail closed to the inet deny, not open egress; got {code}"
        );
    }
}

/// FW-TRA2 (Linux): the sandbox is transparent -- a shell that forks and execs a child runs clean
/// with only Closed-mode essentials, exercising clone/clone3 + execve under both mechanisms.
#[test]
fn baseline_is_transparent_to_fork_and_exec() {
    let policy = compile(&Blueprint::empty(), &detect());
    assert_eq!(
        run(&policy, sh("/bin/echo hi | /bin/cat >/dev/null")),
        0,
        "an ordinary fork+exec pipeline must run under essentials alone"
    );
}

/// FW-ADV (Linux): a confinement-shedding syscall from the seccomp baseline is denied. `unshare -U`
/// requests a new user namespace (CLONE_NEWUSER); the rule must reject it.
#[test]
fn baseline_denies_new_user_namespace() {
    if !Path::new("/usr/bin/unshare").exists() {
        eprintln!("skipping: /usr/bin/unshare not present");
        return;
    }
    // Grant the unshare binary's tree so it loads, then confirm the syscall itself is blocked.
    let policy = closed_policy(vec![pp(Path::new("/usr"))], vec![], vec![]);
    let mut cmd = Command::new("/usr/bin/unshare");
    cmd.arg("--user").arg("/bin/true");
    assert_ne!(
        run(&policy, cmd),
        0,
        "unshare(CLONE_NEWUSER) must be denied by the seccomp baseline"
    );
}

/// FW-ADV-001 (Linux): the full sandbox-shedding sequence. A confined process attempts, in order,
/// the setuid-exec vector (neutralized by NO_NEW_PRIVS), clearing NO_NEW_PRIVS (a one-way latch),
/// and re-exec to drop the seccomp filter (inherited across execve). The probe exits 0 only when
/// every attempt fails and confinement persists across the re-exec; any nonzero names the specific
/// break. Complements `baseline_denies_new_user_namespace`, which covers only the userns vector.
/// Runs on any seccomp host (no Landlock required); the shedding defenses are seccomp/prctl-carried.
#[test]
fn fw_adv_001_full_sandbox_shedding_sequence() {
    let probe = PathBuf::from(env!("CARGO_BIN_EXE_fw-shed-probe"));
    let probe_dir = probe.parent().expect("probe has a parent directory");
    // The probe re-execs /proc/self/exe, so grant its own tree (read = loadable/executable).
    let policy = closed_policy(vec![pp(probe_dir)], vec![], vec![]);
    let code = run(&policy, Command::new(&probe));
    assert_eq!(
        code, 0,
        "every shedding vector must fail and confinement persist across the re-exec \
         (20=not confined, 21=NNP cleared, 22=shed syscall allowed, 24=filter dropped on re-exec, \
         25=NNP lost); got {code}"
    );
}

/// FW-INV2 (Linux): descendant containment. Confinement is inherited by descendants and cannot be
/// relaxed anywhere in a spawn tree (FW-XR4). A shell forks a nested child down to the shed-probe
/// leaf; the probe (itself re-execing once) proves NO_NEW_PRIVS and the seccomp filter still hold at
/// depth -- no descendant escaped or relaxed the confiner. FW-INV2: this is a targeted case standing
/// in for the spec's fuzzing over random spawn trees, tracked as an exception in docs/STATUS.md.
#[test]
fn fw_inv2_descendant_containment_over_spawn_tree() {
    let probe = PathBuf::from(env!("CARGO_BIN_EXE_fw-shed-probe"));
    let probe_dir = probe.parent().expect("probe has a parent directory");
    // Only the probe tree is granted explicitly; Closed-mode essentials load /bin/sh and the runtime.
    let policy = closed_policy(vec![pp(probe_dir)], vec![], vec![]);
    // Two forked shells deep, then exec the probe: a small spawn tree, not a single re-exec.
    let script = format!("/bin/sh -c '{}'", probe.display());
    let code = run(&policy, sh(&script));
    assert_eq!(
        code, 0,
        "a nested forked descendant must stay confined (the shed-probe passes at depth); got {code}"
    );
}

/// FW-INV3 (Linux): egress only via the gateway fd. A confined process has no network path except
/// the injected fd, so every *direct* egress primitive fails closed under default deny: a TCP
/// `connect()` (EPERM -> exit 7), a raw socket (denied at creation -> exit 0), and direct DNS (a
/// UDP:53 datagram, EPERM -> exit 7). Net-deny is seccomp-carried, so this runs on any seccomp host.
#[test]
fn fw_inv3_egress_only_via_gateway_fd() {
    let connect = PathBuf::from(env!("CARGO_BIN_EXE_fw-connect-probe"));
    let udp = PathBuf::from(env!("CARGO_BIN_EXE_fw-udp-probe"));
    let raw = PathBuf::from(env!("CARGO_BIN_EXE_fw-rawsock-probe"));
    // Grant each probe's directory so it loads; grants never open network (net stays default-deny).
    let dirs = [
        connect.parent().unwrap(),
        udp.parent().unwrap(),
        raw.parent().unwrap(),
    ];
    let policy = closed_policy(dirs.iter().map(|d| pp(d)).collect(), vec![], vec![]);

    assert_eq!(
        run(&policy, Command::new(&connect)),
        7,
        "a direct TCP connect() must fail closed (EPERM -> exit 7)"
    );
    assert_eq!(
        run(&policy, Command::new(&udp)),
        7,
        "direct DNS (UDP:53) must fail closed (EPERM -> exit 7)"
    );
    // FW-INV3: this arm is only load-bearing under CAP_NET_RAW (the root-in-container Docker/Lima
    // matrix Testing mandates). An unprivileged process is denied SOCK_RAW by ordinary Linux
    // capability checks regardless of the seccomp filter, so off that matrix this is a vacuous pass
    // and the connect()/UDP arms above carry the verdict. The probe stays: raw sockets are a distinct
    // egress vector.
    assert_eq!(
        run(&policy, Command::new(&raw)),
        0,
        "a raw socket must be denied at creation (exit 0 = denied; 4 = a raw egress path opened)"
    );
}

/// FW-ADV-005 (Linux): fd smuggling. A confined stdio backend cannot manufacture a new egress socket
/// (the raw material of a smuggled fd) -- only the seam mints egress fds. The probe proves inet
/// `socket()` is denied while the seam's own AF_UNIX socketpair transport still works, so the deny is
/// scoped to egress, never the seam (FW-XR7). Net-deny is seccomp-carried, so this runs on any
/// seccomp host. It asserts the socket-manufacture arm; the SCM_RIGHTS hand-off arm is exercised by
/// the macOS `seam_confined` suite (FW-E2E-011) and the recursion test (FW-E2E-019).
#[test]
fn fw_adv_005_confined_backend_cannot_manufacture_egress_fd() {
    let probe = PathBuf::from(env!("CARGO_BIN_EXE_fw-fdsmuggle-probe"));
    let probe_dir = probe.parent().expect("probe has a parent directory");
    let policy = closed_policy(vec![pp(probe_dir)], vec![], vec![]);
    let code = run(&policy, Command::new(&probe));
    assert_eq!(
        code, 0,
        "a confined backend must not manufacture an inet egress fd, yet keep its AF_UNIX seam \
         transport (0 = both hold; 4 = egress fd manufactured; 5 = seam socketpair broken); got {code}"
    );
}

/// FW-ADV-006 (Linux): cross-domain UNIX-socket reach-around. On an ABI>=6 kernel the confined
/// process cannot connect to a pathname (or abstract) UNIX socket owned by an out-of-domain process;
/// below v6 the capability is reported Unenforceable/Partial and the fail-closed net posture still
/// holds. This host lacks ABI v6, so the capable-kernel arm skips cleanly and the reported-gap arm
/// (a pure property of the compiled report) runs.
#[test]
fn fw_adv_006_cross_domain_unix_socket_reach_around() {
    use formwork_compile::{Capability, Fidelity};

    let host = detect();
    let policy = compile(&Blueprint::empty(), &host);
    let cross = policy
        .report
        .per_capability
        .get(&Capability::CrossDomainSocket)
        .expect("the cross-domain-socket capability is always reported");

    if host.landlock_abi.unwrap_or(0) >= 6 {
        // Capable kernel: a listener owned by this (out-of-domain, unconfined) test process, which the
        // confined child must not be able to reach once UNIX-socket scoping is in force.
        let sock = std::env::temp_dir().join(format!("fw-adv006-{}.sock", std::process::id()));
        let _ = fs::remove_file(&sock);
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let probe = PathBuf::from(env!("CARGO_BIN_EXE_fw-unix-connect-probe"));
        // Grant BOTH the probe's tree (so it loads) and the socket's directory for read, so a *path*
        // denial cannot be confused with the scope denial: reaching connect() and being blocked at
        // the socket scope is the point.
        let sock_dir = fs::canonicalize(sock.parent().unwrap()).unwrap();
        let policy = closed_policy(
            vec![pp(probe.parent().unwrap()), pp(&sock_dir)],
            vec![],
            vec![],
        );
        let mut cmd = Command::new(&probe);
        cmd.arg(&sock);
        let code = run(&policy, cmd);
        drop(listener);
        let _ = fs::remove_file(&sock);
        assert!(
            matches!(cross, Fidelity::Partial { .. } | Fidelity::Enforced { .. }),
            "an ABI>=6 host must report cross-domain scoping as Partial/Enforced, not a gap"
        );
        assert_ne!(
            code, 4,
            "a confined process must not connect to an out-of-domain UNIX socket on a capable kernel"
        );
    } else {
        // Below v6: the gap is reported (never silently pretended), and net still fails closed.
        assert!(
            matches!(cross, Fidelity::Unenforceable { .. } | Fidelity::Partial { .. }),
            "below ABI v6 the cross-domain-socket capability must be reported Unenforceable/Partial, \
             got {cross:?}"
        );
        assert!(
            policy.report.net_is_fail_closed(),
            "the fail-closed net posture must still prevent remote egress when scoping is unavailable"
        );
        eprintln!("skipping capable-kernel arm: no Landlock ABI v6 on this host");
    }
}

/// FW-E2E-045 (Linux/Landlock credential floor): the §9 matrix claims absolute credential rows are
/// Enforced via Landlock deny, but the enforcement probes for it were all macOS-only. Under a broad
/// `read` grant with the default catalog, a catalog credential path (`~/.aws/credentials`) is denied
/// (EACCES) while an ordinary in-grant file stays readable -- the floor is a hole, not a wall. Gated
/// on Landlock (the floor's path arm rides the Landlock subtract); skips cleanly without it.
#[test]
fn fw_e2e_045_credential_floor_denies_catalog_path_linux() {
    if !have_landlock() {
        eprintln!("skipping: no Landlock on this host (the credential floor's path arm needs it)");
        return;
    }
    // A realpath'd fake home with a planted fake credential and an ordinary file, so the developer's
    // real secrets are never in play and the catalog resolves against a controlled tree.
    let home = std::env::temp_dir().join(format!("fw-credfloor-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".aws")).unwrap();
    let home = fs::canonicalize(&home).unwrap();
    fs::write(
        home.join(".aws/credentials"),
        b"[default]\naws_secret_access_key = FAKE\n",
    )
    .unwrap();
    fs::write(home.join("notes.txt"), b"ordinary home file\n").unwrap();

    // Compile a broad read grant over the fake home with the builtin catalog resolved for it: the
    // floor subtracts the credential path even though the grant covers it (FW-CRED4).
    let blueprint = Blueprint {
        fs: FsBlueprint {
            read_mode: ReadMode::Closed,
            reads: vec![pp(&home)],
            writes: Vec::new(),
            writes_no_create: Vec::new(),
            subtract: Vec::new(),
            write_subtract: Vec::new(),
        },
        ..Blueprint::empty()
    };
    let catalog = ResolvedCatalog::builtin_for_home(&home.to_string_lossy()).unwrap();
    let policy = formwork_compile::compile(&blueprint, &detect(), &catalog);

    assert_eq!(
        run(&policy, cat(&home.join("notes.txt"))),
        0,
        "an ordinary file under the broad grant stays readable (the floor is a hole, not a wall)"
    );
    assert_ne!(
        run(&policy, cat(&home.join(".aws/credentials"))),
        0,
        "a catalog credential path must be denied (EACCES) despite the broad read grant"
    );
    let _ = fs::remove_dir_all(&home);
}

/// Sanity: the confiner really is the Linux one and targets the host's ABI, so the tests above are
/// exercising the mechanism we think they are.
#[test]
fn confiner_matches_host() {
    match compile(&Blueprint::empty(), &detect()).confiner {
        ConfinerPolicy::Linux(l) => assert_eq!(l.landlock_abi_target, detect().landlock_abi),
        other => panic!("expected a Linux confiner, got {other:?}"),
    }
}
