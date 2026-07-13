//! Phase 3 macOS Seatbelt confiner tests (design §7.1). Native -- macOS only. The real-enforcement
//! half of the filesystem invariants; the compile half lives in formwork-compile. Also serves as the
//! Phase-0 spike: `sandbox_init(profile, 0, ..)` compiles/applies an SBPL string, confinement
//! survives `execve`, and it is inherited by descendants.

#![cfg(target_os = "macos")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use formwork_blueprint::{Blueprint, FsBlueprint, PathPattern, ReadMode, ResolvedCatalog};
use formwork_detect::detect;

/// Integration tests enforce what the product enforces: the builtin catalog resolved for the
/// real home. The probes below touch only scratch paths, so the floor never interferes.
fn compile(
    blueprint: &Blueprint,
    host: &formwork_detect::HostProfile,
) -> formwork_compile::CompiledPolicy {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    formwork_compile::compile(
        blueprint,
        host,
        &ResolvedCatalog::builtin_for_home(&home).unwrap(),
    )
}

fn pp(p: &Path) -> PathPattern {
    PathPattern::parse(&format!("{}/**", p.display())).unwrap()
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let pid = std::process::id();
        let root = std::env::temp_dir().join(format!("formwork-test-{tag}-{pid}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("granted")).unwrap();
        fs::create_dir_all(root.join("secret")).unwrap();
        // Resolve symlinks (macOS /var -> /private/var) so grant paths match the real enforced paths.
        let root = fs::canonicalize(&root).unwrap();
        fs::write(root.join("granted/ok.txt"), b"in-scope contents\n").unwrap();
        fs::write(root.join("secret/secret.env"), b"TOP SECRET\n").unwrap();
        Fixture { root }
    }
    fn granted(&self) -> PathBuf {
        self.root.join("granted")
    }
    fn secret_file(&self) -> PathBuf {
        self.root.join("secret/secret.env")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn confined_read_only(granted_dir: &Path) -> formwork_compile::CompiledPolicy {
    confined(vec![pp(granted_dir)], vec![], vec![])
}

fn confined(
    reads: Vec<PathPattern>,
    writes: Vec<PathPattern>,
    subtract: Vec<PathPattern>,
) -> formwork_compile::CompiledPolicy {
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

/// Outcome of a direct-connect probe. Distinguishing these matters: a probe that failed to *start*,
/// never reaching `connect()`, must not read as denial -- that would be a false confirmation.
#[derive(Debug, PartialEq)]
enum ConnectProbe {
    Connected,         // egress LEAKED (exit 0)
    DeniedAtConnect,   // connect() returned EPERM/EACCES (exit 7)
    OtherFailure(i32), // reached connect() but failed otherwise, or the probe could not run
}

/// Runs the self-contained `fw-connect-probe` binary *inside* the sandbox and reads its exit code.
/// It is staged into `cwd` -- which the policy grants read -- because the build-output path is
/// outside the read scope; being std-only it links just libSystem and so starts under the read-only
/// policy wherever `/bin/cat` does. (An earlier version shelled out to `/usr/bin/python3`, but that
/// CLT stub cannot load its interpreter when `xcode-select` points into `/Applications/Xcode.app`,
/// as on GitHub's macOS runners -- it dies before reaching `connect()`.)
fn tcp_connect_probe(policy: &formwork_compile::CompiledPolicy, cwd: &Path) -> ConnectProbe {
    let staged = cwd.join("fw-connect-probe");
    fs::copy(env!("CARGO_BIN_EXE_fw-connect-probe"), &staged).expect("stage probe binary");
    let mut cmd = Command::new(&staged);
    cmd.current_dir(cwd);
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    formwork_confine::spawn_confined(&mut cmd, policy).expect("confinement applies");
    match cmd.status().expect("probe runs").code() {
        Some(0) => ConnectProbe::Connected,
        Some(7) => ConnectProbe::DeniedAtConnect,
        other => ConnectProbe::OtherFailure(other.unwrap_or(-1)),
    }
}

fn sh_succeeds(policy: &formwork_compile::CompiledPolicy, script: &str) -> bool {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(script);
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    formwork_confine::spawn_confined(&mut cmd, policy).expect("confinement applies");
    cmd.status().expect("sh runs").success()
}

fn cat_succeeds(policy: &formwork_compile::CompiledPolicy, path: &Path) -> bool {
    let mut cmd = Command::new("/bin/cat");
    cmd.arg(path);
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    formwork_confine::spawn_confined(&mut cmd, policy).expect("confinement applies");
    cmd.status().expect("cat runs").success()
}

/// FW-E2E-001 (spawn-confined): granted read succeeds, ungranted read denied.
#[test]
fn fw_e2e_001_granted_read_succeeds_ungranted_denied() {
    let fx = Fixture::new("e2e001");
    let policy = confined_read_only(&fx.granted());

    assert!(
        cat_succeeds(&policy, &fx.granted().join("ok.txt")),
        "in-scope read must succeed (also proves the ambient toolchain loads under confinement)"
    );
    assert!(
        !cat_succeeds(&policy, &fx.secret_file()),
        "out-of-scope read must be denied by Seatbelt"
    );
}

/// FW-E2E-037 (FW-CAP7): a subtracted path leaks neither contents nor metadata. `stat` is denied,
/// so a confined process cannot learn a credential file's existence, size, or mtime. The broad
/// `(allow file-read-metadata)` re-admits metadata only for non-sensitive ungranted paths (FW-TRA4);
/// the `subtract` deny of `file-read*` (which covers metadata) is emitted last and wins.
#[test]
fn fw_e2e_037_subtract_denies_metadata_not_only_contents() {
    let fx = Fixture::new("e2e037");
    let policy = confined(
        vec![pp(&fx.root)],
        vec![],
        vec![pp(&fx.root.join("secret"))],
    );
    let secret = fx.secret_file();
    let granted = fx.root.join("granted/ok.txt");

    assert!(
        !cat_succeeds(&policy, &secret),
        "subtracted contents must be denied"
    );
    assert!(
        !sh_succeeds(
            &policy,
            &format!("/usr/bin/stat -f %z '{}'", secret.display())
        ),
        "stat of a subtracted path must be denied -- no size/mtime oracle (FW-CAP7)"
    );
    assert!(
        sh_succeeds(
            &policy,
            &format!("/usr/bin/stat -f %z '{}'", granted.display())
        ),
        "stat of a granted path must still succeed (the metadata deny is scoped to subtract)"
    );
}

/// FW-E2E-038 (FW-CAP6): a `**/` any-depth subtract denies a matching file at real depth while a
/// sibling stays readable. This exercises the compiled Seatbelt *regex* at the kernel boundary, not
/// just its string form -- a wrong regex is a missed subtract hole, a fail-open (FW-INV6).
#[test]
fn fw_e2e_038_any_depth_subtract_denies_at_real_depth() {
    let fx = Fixture::new("e2e038");
    let proj = fx.root.join("proj");
    fs::create_dir_all(&proj).unwrap();
    fs::write(proj.join(".env"), b"SECRET=1\n").unwrap();
    fs::write(proj.join("ok.txt"), b"public\n").unwrap();
    let policy = confined(
        vec![pp(&fx.root)],
        vec![],
        vec![PathPattern::parse("**/.env").unwrap()],
    );
    assert!(
        !cat_succeeds(&policy, &proj.join(".env")),
        "**/.env must deny a nested .env (FW-CAP6 regex, real Seatbelt)"
    );
    assert!(
        cat_succeeds(&policy, &proj.join("ok.txt")),
        "a sibling that does not match the regex stays readable"
    );
}

/// FW-E2E-039 (FW-TRA7): a write-subtract tamper vector is readable but not writable, even under a
/// write grant that covers it. A confined agent cannot plant a `.git/config` that later runs
/// unsandboxed, yet git and tooling still read it.
#[test]
fn fw_e2e_039_write_subtract_reads_but_denies_writes() {
    let fx = Fixture::new("e2e039");
    let git = fx.root.join("proj/.git");
    fs::create_dir_all(&git).unwrap();
    let cfg = git.join("config");
    fs::write(&cfg, b"[core]\n").unwrap();
    let normal = fx.root.join("proj/normal.txt");
    fs::write(&normal, b"x\n").unwrap();

    let blueprint = Blueprint {
        fs: FsBlueprint {
            read_mode: ReadMode::Closed,
            reads: vec![pp(&fx.root)],
            writes: vec![pp(&fx.root)],
            subtract: Vec::new(),
            write_subtract: vec![PathPattern::parse("**/.git/config").unwrap()],
        },
        ..Blueprint::empty()
    };
    let policy = compile(&blueprint, &detect());

    assert!(
        cat_succeeds(&policy, &cfg),
        ".git/config must stay READABLE under write-subtract (FW-TRA7)"
    );
    assert!(
        !sh_succeeds(&policy, &format!("echo pwned >> '{}'", cfg.display())),
        "write-subtract must DENY writing the tamper vector despite the write grant"
    );
    assert!(
        sh_succeeds(&policy, &format!("echo ok >> '{}'", normal.display())),
        "a normal file under the same write grant stays writable (deny is scoped)"
    );
}

/// FW-E2E-005: a shell child, and its child, stay confined.
#[test]
fn fw_e2e_005_descendant_inheritance() {
    let fx = Fixture::new("e2e005");
    let policy = confined_read_only(&fx.granted());

    // A grandchild (sh -> cat) attempting an out-of-scope read is denied -- confinement inherited.
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(format!("/bin/cat {}", fx.secret_file().display()));
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    formwork_confine::spawn_confined(&mut cmd, &policy).unwrap();
    assert!(
        !cmd.status().unwrap().success(),
        "descendant must not escape the sandbox"
    );

    // The same pipeline reading an in-scope file still works.
    let mut ok = Command::new("/bin/sh");
    ok.arg("-c").arg(format!(
        "/bin/cat {}",
        fx.granted().join("ok.txt").display()
    ));
    ok.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    formwork_confine::spawn_confined(&mut ok, &policy).unwrap();
    assert!(
        ok.status().unwrap().success(),
        "in-scope descendant read should still work"
    );
}

/// FW-E2E-002: writes inside the write grant succeed; a read-only-granted path and /etc are denied.
#[test]
fn fw_e2e_002_write_scope_and_readonly() {
    let fx = Fixture::new("e2e002");
    let policy = confined(vec![pp(&fx.root)], vec![pp(&fx.granted())], vec![]);

    assert!(
        sh_succeeds(
            &policy,
            &format!("echo x > {}/new.txt", fx.granted().display())
        ),
        "write inside the write grant must succeed"
    );
    assert!(
        !sh_succeeds(
            &policy,
            &format!("echo x > {}/secret/injected.txt", fx.root.display())
        ),
        "write to a read-only-granted path must be denied"
    );
    assert!(
        !sh_succeeds(&policy, "echo x > /etc/formwork-should-not-exist"),
        "write to /etc must be denied"
    );
}

/// FW-E2E-003: sensitive-set subtraction wins over a broad grant.
#[test]
fn fw_e2e_003_sensitive_subtraction_under_broad_grant() {
    let fx = Fixture::new("e2e003");
    let policy = confined(
        vec![pp(&fx.root)],
        vec![],
        vec![pp(&fx.root.join("secret"))],
    );

    assert!(
        cat_succeeds(&policy, &fx.granted().join("ok.txt")),
        "ordinary read under the broad grant must succeed"
    );
    assert!(
        !cat_succeeds(&policy, &fx.secret_file()),
        "subtracted path must be denied even though the parent is broadly granted"
    );
}

/// FW-E2E-004: a symlink inside a granted dir pointing at an ungranted target confers no access --
/// the target's scope governs, not the link's location.
#[test]
fn fw_e2e_004_symlink_escape_blocked() {
    let fx = Fixture::new("e2e004");
    let policy = confined_read_only(&fx.granted());

    let link = fx.granted().join("escape");
    std::os::unix::fs::symlink(fx.secret_file(), &link).unwrap();

    assert!(
        cat_succeeds(&policy, &fx.granted().join("ok.txt")),
        "sanity: a real in-scope file still reads"
    );
    assert!(
        !cat_succeeds(&policy, &link),
        "reading through a symlink to an ungranted target must be denied"
    );
}

/// FW-E2E-024 (report soundness, fs+net half): every `Enforced` capability is backed by a probe that
/// confirms allow succeeds and deny fails.
#[test]
fn fw_e2e_024_report_soundness_probes() {
    use formwork_compile::{Capability, Fidelity};
    let fx = Fixture::new("e2e024");
    let policy = confined_read_only(&fx.granted());

    for (cap, fidelity) in &policy.report.per_capability {
        if !matches!(fidelity, Fidelity::Enforced { .. }) {
            continue;
        }
        match cap {
            Capability::FsRead => {
                assert!(
                    cat_succeeds(&policy, &fx.granted().join("ok.txt")),
                    "fs-read allow probe"
                );
                assert!(
                    !cat_succeeds(&policy, &fx.secret_file()),
                    "fs-read deny probe"
                );
            }
            Capability::NetDefaultDeny => {
                assert_eq!(
                    tcp_connect_probe(&policy, &fx.granted()),
                    ConnectProbe::DeniedAtConnect,
                    "net-default-deny deny probe: direct connect must be denied at connect()"
                );
            }
            _ => {}
        }
    }
}

/// FW-E2E-001 (confine-self): a process that confines itself in place is then denied an out-of-scope
/// read but keeps its in-scope read. Uses fork so the irreversible confinement is isolated.
#[test]
fn fw_e2e_001_confine_self_posture() {
    let fx = Fixture::new("e2e001self");
    let policy = confined_read_only(&fx.granted());
    let ok = fx.granted().join("ok.txt");
    let secret = fx.secret_file();

    // SAFETY: fork in a test; the child only reads files and _exits, never returning to the harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let confined_ok = formwork_confine::enforce_self(&policy).is_ok();
        let in_scope = std::fs::read(&ok).is_ok();
        let out_scope_denied = std::fs::read(&secret).is_err();
        let code = if confined_ok && in_scope && out_scope_denied {
            0
        } else {
            1
        };
        unsafe { libc::_exit(code) };
    }
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let exit = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    assert_eq!(
        exit, 0,
        "confine-self child: in-scope read ok AND out-of-scope denied"
    );
}

/// FW-E2E-006: under net=deny, an outbound connection fails closed at connect() (not masked by a
/// startup failure). The staged std-only `fw-connect-probe` reports the outcome by exit code, so a
/// policy denial is distinguishable from any other failure.
#[test]
fn fw_e2e_006_direct_egress_denied() {
    let fx = Fixture::new("e2e006");
    let policy = confined_read_only(&fx.granted());

    assert_eq!(
        tcp_connect_probe(&policy, &fx.granted()),
        ConnectProbe::DeniedAtConnect,
        "direct network egress must be denied at connect() under net=deny"
    );
}
