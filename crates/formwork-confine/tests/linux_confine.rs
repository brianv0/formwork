//! Phase 2 Linux backend tests -- native, Linux only, against a real kernel (Docker/Lima with
//! Docker's own seccomp/AppArmor disabled, so only Formwork's sandbox is under test). Paired
//! allow/deny probes at the real boundary (FW-INV5): a grant works *and* the matching deny bites.
//! Filesystem tests need Landlock (skip cleanly on a pre-5.13 kernel); the seccomp baseline and net
//! default-deny run everywhere.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use formwork_blueprint::{Blueprint, FsBlueprint, PathPattern, ReadMode};
use formwork_compile::{compile, CompiledPolicy, ConfinerPolicy};
use formwork_detect::detect;

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

/// FW-E2E-002 (Linux): a confined process cannot reach the network. Landlock (TCP) or seccomp (inet
/// socket) denies it; the staged probe surfaces the EPERM as exit 7.
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
/// staged probe surfaces the EPERM as exit 7 -- proving the old TCP-only gap is closed.
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

/// Sanity: the confiner really is the Linux one and targets the host's ABI, so the tests above are
/// exercising the mechanism we think they are.
#[test]
fn confiner_matches_host() {
    match compile(&Blueprint::empty(), &detect()).confiner {
        ConfinerPolicy::Linux(l) => assert_eq!(l.landlock_abi_target, detect().landlock_abi),
        other => panic!("expected a Linux confiner, got {other:?}"),
    }
}
