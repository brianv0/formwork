//! FEP-15 black-box tests of the Launcher's session state against the real kernel: where the
//! session root lives and who may touch it (FW-TRA18, FW-TRA19, FW-INV23), what a signal to the
//! Launcher does (FW-XR12, FW-XR13), and when the root goes away (FW-TRA20, FW-TRA21).
//!
//! Every cross-session test puts the session roots inside a tree the blueprint grants for
//! writing, so placement protects nothing and only the compiled deny stands between two sessions.

#![cfg(unix)]

use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod support;
use support::*;

/// The variable that names the invoking user's runtime directory.
const RUNTIME_VAR: &str = if cfg!(target_os = "macos") {
    "TMPDIR"
} else {
    "XDG_RUNTIME_DIR"
};

const WRITABLE_PROJECT: &str = "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\"]\n";
const INSPECTED: &str = "extends = [\"builtin:default\"]\n\
                         rules = [\"readwrite:$CWD/**\", \"allow:example.test\"]\n";

fn confiner_host(dir: &Path) -> bool {
    let host = host_profile(dir);
    if host["landlock-abi"].as_u64().is_some() || host["seatbelt"].as_bool() == Some(true) {
        return true;
    }
    not_exercised("no filesystem confiner on this host");
    false
}

/// A scratch project with `blueprint`, an `out/` the session can create files in, and a private
/// runtime directory inside the project -- inside the `$CWD/**` write grant.
fn project(tag: &str, blueprint: &str) -> (Scratch, PathBuf) {
    let dir = Scratch::new(tag);
    std::fs::write(dir.path().join("FORMWORK.toml"), blueprint).unwrap();
    std::fs::create_dir(dir.path().join("out")).unwrap();
    let runtime = dir.path().join("run");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&runtime)
        .unwrap();
    (dir, runtime)
}

/// The session roots under `runtime` (FW-TRA18); none when the Launcher never created the parent.
fn session_roots(runtime: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(runtime.join("formwork"))
        .map(|entries| entries.flatten().map(|e| e.path()).collect())
        .unwrap_or_default()
}

/// Longer than any wait these tests expect of a Launcher, **term-grace** included.
const LAUNCHER_LIMIT: Duration = Duration::from_secs(60);

fn appears(path: &Path, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if std::fs::metadata(path)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// A workload's process, killed when the test ends: a test that fails because a workload
/// outlived its Launcher must not leave it running.
struct Workload(libc::pid_t);

impl Workload {
    /// The workload wrote its pid to `out/pid` once it was ready.
    fn started(dir: &Path) -> Workload {
        assert!(
            appears(&dir.join("out/pid"), 30),
            "the workload never started"
        );
        let pid = std::fs::read_to_string(dir.join("out/pid")).unwrap();
        Workload(pid.trim().parse().unwrap())
    }

    fn alive(&self) -> bool {
        // SAFETY: signal 0 only checks that the process exists.
        unsafe { libc::kill(self.0, 0) == 0 }
    }

    fn gone(&self, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if !self.alive() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }
}

impl Drop for Workload {
    fn drop(&mut self) {
        // SAFETY: kill with a scalar pid and signal.
        unsafe { libc::kill(self.0, libc::SIGKILL) };
    }
}

fn signal(pid: u32, signo: libc::c_int) {
    // SAFETY: kill with a scalar pid and signal.
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, signo) }, 0);
}

/// `formwork` in `dir` with the runtime directory at `runtime`, running in the background, in a
/// state that does not depend on how the test runner was started. The forwarded signals are at
/// their default dispositions: a runner started as a shell's background job ignores SIGINT, and
/// the Launcher keeps an inherited ignore. The Launcher leads a session of its own, with no
/// controlling terminal: where only the terminal tells the keyboard's interrupt from `kill(2)`,
/// a runner in a terminal's foreground would have the test's interrupt taken for the keyboard's.
fn background(dir: &Path, runtime: &Path, args: &[&str]) -> Command {
    let runtime = runtime.to_str().unwrap();
    let mut cmd = formwork_command(dir, args, &[(RUNTIME_VAR, runtime)], &[]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: signal(2) and setsid(2) are async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            for signo in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
                libc::signal(signo, libc::SIG_DFL);
            }
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd
}

/// Wait for the Launcher to exit, not for its output to end: a workload that outlives its
/// Launcher -- what several of these tests exist to catch -- holds the pipes open. A signal
/// death is reported as the negated signal. A Launcher still running after [`LAUNCHER_LIMIT`] is
/// killed and fails the test, which would otherwise hang on a Launcher that never ends its wait.
fn finish(mut child: Child) -> Output {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    let nonblocking = |fd: std::os::fd::OwnedFd| {
        // SAFETY: fcntl on a descriptor owned here.
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        File::from(fd)
    };
    let mut pipes = [
        (child.stdout.take().map(|p| nonblocking(p.into()))),
        (child.stderr.take().map(|p| nonblocking(p.into()))),
    ];
    let mut read = [Vec::new(), Vec::new()];
    let mut drain = |pipes: &mut [Option<File>; 2]| {
        for (pipe, bytes) in pipes.iter_mut().zip(read.iter_mut()) {
            if let Some(pipe) = pipe {
                let _ = pipe.read_to_end(bytes);
            }
        }
    };
    let deadline = Instant::now() + LAUNCHER_LIMIT;
    let status = loop {
        drain(&mut pipes);
        if let Some(status) = child.try_wait().unwrap() {
            drain(&mut pipes);
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            drain(&mut pipes);
            panic!(
                "the Launcher was still running after {LAUNCHER_LIMIT:?}: {}",
                String::from_utf8_lossy(&read[1])
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let [stdout, stderr] = read;
    Output {
        code: status
            .code()
            .unwrap_or_else(|| -status.signal().unwrap_or(0)),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }
}

/// A session that records where its Launcher-owned paths are, waits for `out/go`, then runs its
/// opener shim.
struct Victim {
    child: Child,
    shim_dir: PathBuf,
    bundle: PathBuf,
    tmp: PathBuf,
    root: PathBuf,
}

const VICTIM: &str = r#"printf '%s\n%s\n%s\n' "${PATH%%:*}" "$SSL_CERT_FILE" "$TMPDIR" > out/paths
while [ ! -e out/go ]; do sleep 0.1; done
xdg-open http://example.test/
echo "shim-exit=$?"
"#;

impl Victim {
    fn start(dir: &Path, command: &mut Command) -> Victim {
        let child = command.spawn().unwrap();
        assert!(
            appears(&dir.join("out/paths"), 30),
            "the first session never started"
        );
        let paths = std::fs::read_to_string(dir.join("out/paths")).unwrap();
        let mut lines = paths.lines().map(PathBuf::from);
        let shim_dir = lines.next().unwrap();
        let bundle = lines.next().unwrap();
        let tmp = lines.next().unwrap();
        let root = tmp.parent().unwrap().to_path_buf();
        Victim {
            child,
            shim_dir,
            bundle,
            tmp,
            root,
        }
    }

    /// The bytes a second session must not change: the shim directory's entries and the bundle.
    fn launcher_owned(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&self.shim_dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        files.push(self.bundle.clone());
        files
            .into_iter()
            .map(|f| {
                let bytes = std::fs::read(&f).unwrap();
                (f, bytes)
            })
            .collect()
    }

    /// Let the session run its shim; what it printed and its exit status.
    fn run_the_shim(self, dir: &Path) -> Output {
        std::fs::write(dir.join("out/go"), "go").unwrap();
        finish(self.child)
    }
}

const WRITE_ATTEMPTS: &str = r#"shim="$1/xdg-open"; bundle="$2"; tmp="$3"
echo own > "$TMPDIR/own" && echo own-tmp-writable
rm -f "$shim" 2>/dev/null
printf '#!/bin/sh\necho PLANTED\n' > "$shim" && echo replaced-shim
echo x >> "$bundle" && echo wrote-bundle
echo x > "$tmp/planted" && echo wrote-tmp
cat "$bundle" > /dev/null 2>&1 && echo read-bundle
ls "$tmp" > /dev/null 2>&1 && echo listed-tmp
echo attempts-done
"#;

const REFUSED: &[&str] = &[
    "replaced-shim",
    "wrote-bundle",
    "wrote-tmp",
    "read-bundle",
    "listed-tmp",
];

/// Run `attempts` in a second session against a first one's Launcher-owned paths: each attempt is
/// refused, the first session's files are unchanged, and its shim is still the Launcher's.
/// Returns the first session's stderr.
fn second_session_is_refused(
    dir: &Path,
    first: &mut Command,
    mut second: Command,
    attempts: &str,
    refused: &[&str],
) -> String {
    let victim = Victim::start(dir, first);
    let before = victim.launcher_owned();
    assert!(
        victim.shim_dir.starts_with(&victim.root) && victim.bundle.starts_with(&victim.root),
        "every per-session path sits in one session root (FW-TRA18): {:?} {:?} {:?}",
        victim.shim_dir,
        victim.bundle,
        victim.tmp
    );
    let out = second
        .args(["run", "--", "/bin/sh", "-c", attempts, "sh"])
        .args([&victim.shim_dir, &victim.bundle, &victim.tmp, &victim.root])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("attempts-done") && stdout.contains("own-tmp-writable"),
        "the second session did not run its attempts: {stdout} {stderr}"
    );
    for marker in refused {
        assert!(
            !stdout.contains(marker),
            "a second session reached the first's files ({marker}): {stdout} {stderr}"
        );
    }
    assert!(
        !victim.tmp.join("planted").exists(),
        "a file appeared in the first session's temp directory"
    );
    assert_eq!(
        before,
        victim.launcher_owned(),
        "the first session's shim directory or trust bundle changed"
    );
    let first = victim.run_the_shim(dir);
    assert!(
        first.stdout.contains("shim-exit=1") && !first.stdout.contains("PLANTED"),
        "the first session did not run the Launcher's shim: {} {}",
        first.stdout,
        first.stderr
    );
    assert!(
        first.stderr.contains("open-url"),
        "the Launcher's shim reaches the Launcher's opener: {}",
        first.stderr
    );
    first.stderr
}

/// FW-E2E-191 (both; FW-TRA19, FW-INV23): two concurrent sessions under `builtin:default`, their
/// roots inside a tree both may write. The second cannot replace the first's `opener/xdg-open`,
/// overwrite or read its `trust/ca-bundle.pem`, or create or list a file in its `tmp/`; the first
/// then runs its shim and gets the Launcher's.
#[test]
fn fw_e2e_191_a_second_session_cannot_rewrite_the_firsts_launcher_owned_files() {
    let (dir, runtime) = project("roots", INSPECTED);
    if !confiner_host(dir.path()) {
        return;
    }
    if !egress_host(dir.path()) {
        not_exercised("no host-scoped egress on this host, so no session has a trust bundle");
        return;
    }
    let mut first = background(
        dir.path(),
        &runtime,
        &["run", "--", "/bin/sh", "-c", VICTIM],
    );
    let second = background(dir.path(), &runtime, &[]);
    second_session_is_refused(dir.path(), &mut first, second, WRITE_ATTEMPTS, REFUSED);
    assert!(
        session_roots(&runtime).is_empty(),
        "both roots are removed when their sessions end (FW-TRA20)"
    );
}

/// FW-E2E-192 (both; FW-TRA19): with `readwrite:~/**` and no private runtime directory, the roots
/// fall back to `~/.local/state/formwork`, inside the granted tree. The same attempts are refused
/// and the operator channel names the Launcher deny.
#[test]
fn fw_e2e_192_a_grant_over_the_fallback_location_does_not_lift_the_deny() {
    let home_grant = "extends = [\"builtin:default\"]\n\
                      rules = [\"readwrite:~/**\", \"allow:example.test\"]\n";
    let (dir, _) = project("fallback", home_grant);
    if !confiner_host(dir.path()) {
        return;
    }
    if !egress_host(dir.path()) {
        not_exercised("no host-scoped egress on this host, so no session has a trust bundle");
        return;
    }
    // A runtime variable that names no private directory: `/` is not mode 0700.
    let mut first = background(
        dir.path(),
        Path::new("/"),
        &["run", "--", "/bin/sh", "-c", VICTIM],
    );
    let second = background(dir.path(), Path::new("/"), &[]);
    let fallback = dir.path().join(".local/state/formwork");
    let stderr = second_session_is_refused(dir.path(), &mut first, second, WRITE_ATTEMPTS, REFUSED);
    assert!(
        stderr.contains("Launcher deny")
            && stderr.contains("FW-TRA19")
            && stderr.contains(fallback.to_str().unwrap()),
        "the operator channel names the Launcher deny and the directory it covers: {stderr}"
    );
    assert_eq!(
        std::fs::read_dir(&fallback).unwrap().count(),
        0,
        "the roots were created in the fallback location and removed"
    );
}

const LINK_ATTEMPTS: &str = r##"root="$4"; parent="${root%/*}"; runtime="${parent%/*}"
echo mine > "$TMPDIR/own" && echo own-tmp-writable
mv "$root" "$parent/00000000000000000000000000000000" 2>/dev/null && echo renamed-root
mv "$root" "$TMPDIR/stolen" 2>/dev/null && echo moved-root
mv "$parent" "$runtime/moved" 2>/dev/null && echo renamed-parent
mv "$runtime" "$runtime.moved" 2>/dev/null && echo renamed-runtime
ln "$TMPDIR/own" "$3/linked" 2>/dev/null && echo linked-into-tmp
ln "$TMPDIR/own" "$1/linked" 2>/dev/null && echo linked-into-shim
ln -s "$TMPDIR" "$parent/ffffffffffffffffffffffffffffffff" 2>/dev/null && echo planted-next-root
mkdir "$parent/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" 2>/dev/null && echo created-root
if [ -n "$FW_TMPFILE_PROBE" ]; then
python3 - "$3/tmpfile-linked" "$1/tmpfile-linked" <<'PY' || exit 9
import os, sys
for target in sys.argv[1:]:
    fd = os.open(os.environ["TMPDIR"], os.O_TMPFILE | os.O_RDWR, 0o755)
    os.write(fd, b"#!/bin/sh\necho PLANTED\n")
    try:
        os.link(f"/proc/self/fd/{fd}", target, follow_symlinks=True)
        print("tmpfile-linked")
    except OSError:
        pass
print("tmpfile-probed")
PY
fi
echo attempts-done
"##;

/// FW-ADV-053 (both; FW-INV23 by rename and link): a second session tries to rename the first's
/// root, its parent and the runtime directory, to hard-link into the root, to plant a symlink or
/// a directory where a later session's root would go, and (Linux) to link an `O_TMPFILE` into it.
/// Every attempt fails, and the first session's `PATH` head and bundle are byte-identical.
#[test]
fn fw_adv_053_a_session_root_is_closed_to_rename_and_link() {
    let (dir, runtime) = project("links", INSPECTED);
    if !confiner_host(dir.path()) {
        return;
    }
    if !egress_host(dir.path()) {
        not_exercised("no host-scoped egress on this host, so no session has a trust bundle");
        return;
    }
    let tmpfile_probe = cfg!(target_os = "linux") && on_path("python3");
    if cfg!(target_os = "linux") && !tmpfile_probe {
        not_exercised("python3 unavailable for the O_TMPFILE probe");
    }
    let mut first = background(
        dir.path(),
        &runtime,
        &["run", "--", "/bin/sh", "-c", VICTIM],
    );
    let mut second = background(dir.path(), &runtime, &[]);
    if tmpfile_probe {
        second.env("FW_TMPFILE_PROBE", "1");
    }
    let refused = [
        "renamed-root",
        "moved-root",
        "renamed-parent",
        "renamed-runtime",
        "linked-into-tmp",
        "linked-into-shim",
        "planted-next-root",
        "created-root",
        "tmpfile-linked",
    ];
    second_session_is_refused(dir.path(), &mut first, second, LINK_ATTEMPTS, &refused);
    assert!(
        session_roots(&runtime).is_empty() && runtime.is_dir(),
        "nothing was planted beside the roots, and the runtime directory is where it was"
    );
}

/// FW-TRA18: the session root is a 0700 directory of the invoking uid under the runtime
/// directory, named by 128 random bits; where the directory that would hold it is not the
/// invoking user's alone, `run` refuses to start and names it.
#[test]
fn fw_tra18_the_session_root_is_private_or_the_run_is_refused() {
    let (dir, runtime) = project("private-root", WRITABLE_PROJECT);
    if !confiner_host(dir.path()) {
        return;
    }
    let mut session = background(
        dir.path(),
        &runtime,
        &[
            "run",
            "--",
            "/bin/sh",
            "-c",
            "echo \"$TMPDIR\" > out/tmp; while [ ! -e out/go ]; do sleep 0.1; done",
        ],
    )
    .spawn()
    .unwrap();
    assert!(appears(&dir.path().join("out/tmp"), 30));
    let tmp = PathBuf::from(
        std::fs::read_to_string(dir.path().join("out/tmp"))
            .unwrap()
            .trim(),
    );
    let root = tmp.parent().unwrap();
    assert_eq!(root.parent().unwrap(), runtime.join("formwork"));
    let id = root.file_name().unwrap().to_str().unwrap();
    assert!(
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "{id}"
    );
    let meta = std::fs::metadata(root).unwrap();
    // SAFETY: geteuid has no failure modes.
    assert_eq!(meta.uid(), unsafe { libc::geteuid() });
    assert_eq!(meta.mode() & 0o777, 0o700);
    std::fs::write(dir.path().join("out/go"), "go").unwrap();
    assert_eq!(session.wait().unwrap().code(), Some(0));

    let parent = runtime.join("formwork");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let refused = finish(
        background(
            dir.path(),
            &runtime,
            &["run", "--", "/bin/sh", "-c", ": > out/started"],
        )
        .spawn()
        .unwrap(),
    );
    assert_ne!(refused.code, 0);
    assert!(
        refused.stderr.contains(parent.to_str().unwrap()) && refused.stderr.contains("FW-TRA18"),
        "{}",
        refused.stderr
    );
    assert!(
        !dir.path().join("out/started").exists(),
        "the workload started"
    );
}

const HANDLES_TERM: &str = r#"trap 'echo term >> out/log; exit 7' TERM
echo $$ > out/pid
while :; do sleep 0.1; done
"#;

const HANDLES_INT: &str = r#"trap 'echo int >> out/log' INT
echo $$ > out/pid
while [ ! -e out/stop ]; do sleep 0.1; done
exit 5
"#;

/// FW-E2E-193 (both; FW-XR12, FW-XR10, FW-TRA20): `SIGTERM` to the Launcher reaches the workload,
/// the Launcher exits with the workload's status, no process of the session remains and no
/// session root is left. `SIGINT` against a workload that handles it and continues: the Launcher
/// keeps waiting, and reports the status the workload exits with later.
#[test]
fn fw_e2e_193_a_signal_to_the_launcher_reaches_the_workload() {
    let (dir, runtime) = project("sigterm", WRITABLE_PROJECT);
    if !confiner_host(dir.path()) {
        return;
    }
    let run = ["run", "--", "/bin/sh", "-c"];
    let launcher = background(dir.path(), &runtime, &[&run[..], &[HANDLES_TERM]].concat())
        .spawn()
        .unwrap();
    let workload = Workload::started(dir.path());
    assert_eq!(session_roots(&runtime).len(), 1);
    signal(launcher.id(), libc::SIGTERM);
    let out = finish(launcher);
    assert_eq!(
        out.code, 7,
        "the Launcher exits with the workload's status: {}",
        out.stderr
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("out/log")).unwrap(),
        "term\n"
    );
    assert!(workload.gone(5), "the workload outlived its Launcher");
    assert!(session_roots(&runtime).is_empty(), "the root was left");

    std::fs::remove_file(dir.path().join("out/pid")).unwrap();
    std::fs::remove_file(dir.path().join("out/log")).unwrap();
    let mut launcher = background(dir.path(), &runtime, &[&run[..], &[HANDLES_INT]].concat())
        .spawn()
        .unwrap();
    let workload = Workload::started(dir.path());
    signal(launcher.id(), libc::SIGINT);
    assert!(
        appears(&dir.path().join("out/log"), 10),
        "the workload never received the interrupt"
    );
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        launcher.try_wait().unwrap().is_none() && workload.alive(),
        "the Launcher keeps waiting while the workload runs"
    );
    std::fs::write(dir.path().join("out/stop"), "stop").unwrap();
    let out = finish(launcher);
    assert_eq!(out.code, 5, "{}", out.stderr);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("out/log")).unwrap(),
        "int\n"
    );
    assert!(session_roots(&runtime).is_empty(), "the root was left");
}

const IGNORES_TERM: &str = r#"trap '' TERM INT
echo $$ > out/pid
while :; do sleep 0.1; done
"#;

/// FW-E2E-194 (both; FW-XR13): a workload that ignores `SIGTERM` is killed **term-grace** (10 s)
/// after the forward, within 2 s, and the Launcher exits 137 with no root left.
#[test]
fn fw_e2e_194_a_workload_that_ignores_sigterm_is_killed_after_the_grace_period() {
    let (dir, runtime) = project("grace", WRITABLE_PROJECT);
    if !confiner_host(dir.path()) {
        return;
    }
    let launcher = background(
        dir.path(),
        &runtime,
        &["run", "--", "/bin/sh", "-c", IGNORES_TERM],
    )
    .spawn()
    .unwrap();
    let workload = Workload::started(dir.path());
    let sent = Instant::now();
    signal(launcher.id(), libc::SIGTERM);
    let out = finish(launcher);
    let waited = sent.elapsed();
    assert_eq!(out.code, 137, "{}", out.stderr);
    assert!(
        waited >= Duration::from_secs(8) && waited <= Duration::from_secs(12),
        "killed {waited:?} after the forward, not 10 s"
    );
    assert!(workload.gone(5), "the workload survived the kill");
    assert!(session_roots(&runtime).is_empty(), "the root was left");
}

/// FW-E2E-195 (FW-TRA20): the invocations that left a session directory behind -- a refused
/// `--confine-self`, a refused `gateway`, a refused broker, a `learn` run -- leave none, and
/// neither does a refusal after the root exists (an unsupported upstream proxy). A successful `--confine-self` has no Launcher left to remove its root: it says so, and the next
/// Launcher removes it (FW-TRA21).
#[test]
fn fw_e2e_195_no_session_root_is_left_behind() {
    let (dir, runtime) = project("leftovers", WRITABLE_PROJECT);
    if !confiner_host(dir.path()) {
        return;
    }
    // Where the host temp root is not the runtime directory it is a scratch directory too:
    // nothing of a session may land there.
    let tmp_root = dir.path().join("tmp-root");
    std::fs::create_dir(&tmp_root).unwrap();
    let mut env = vec![(RUNTIME_VAR, runtime.to_str().unwrap())];
    if RUNTIME_VAR != "TMPDIR" {
        env.push(("TMPDIR", tmp_root.to_str().unwrap()));
    }
    let left = || -> Vec<PathBuf> {
        let stray = std::fs::read_dir(&tmp_root).unwrap().flatten();
        session_roots(&runtime)
            .into_iter()
            .chain(stray.map(|e| e.path()))
            .collect()
    };
    let host_rule = ["--rule", "allow:example.com"];

    let out = formwork(
        dir.path(),
        &[&["run", "--confine-self"][..], &host_rule, &["--", "true"]].concat(),
        &env,
    );
    assert_ne!(out.code, 0, "host rules need the spawn posture");
    assert!(out.stderr.contains("--confine-self"), "{}", out.stderr);
    assert_eq!(left(), Vec::<PathBuf>::new(), "{}", out.stderr);

    let out = formwork(
        dir.path(),
        &[
            &["gateway"][..],
            &host_rule,
            &["--server", "files", "--", "true"],
        ]
        .concat(),
        &env,
    );
    assert_ne!(out.code, 0, "host rules do not apply behind `gateway`");
    assert!(out.stderr.contains("formwork gateway"), "{}", out.stderr);
    assert_eq!(left(), Vec::<PathBuf>::new(), "{}", out.stderr);

    if egress_host(dir.path()) {
        let out = formwork_env(
            dir.path(),
            &[
                "run",
                "--rule",
                "get,post:api.anthropic.com",
                "--allow-cred",
                "broker:anthropic",
                "--",
                "true",
            ],
            &env,
            &["ANTHROPIC_API_KEY"],
        );
        assert_ne!(out.code, 0, "a brokered credential needs its value");
        assert!(out.stderr.contains("ANTHROPIC_API_KEY"), "{}", out.stderr);
        assert_eq!(left(), Vec::<PathBuf>::new(), "{}", out.stderr);

        // Refused only once the Gateway starts, after the root exists: the root goes with the
        // error, not with a check that runs before it.
        let proxied = [&env[..], &[("HTTPS_PROXY", "socks5://127.0.0.1:1")]].concat();
        let out = formwork(
            dir.path(),
            &[&["run"][..], &host_rule, &["--", "true"]].concat(),
            &proxied,
        );
        assert_ne!(out.code, 0, "the Gateway carries no socks5 upstream");
        assert!(out.stderr.contains("socks5://"), "{}", out.stderr);
        assert_eq!(left(), Vec::<PathBuf>::new(), "{}", out.stderr);
    } else {
        not_exercised("no host-scoped egress on this host for the broker row");
    }

    if cfg!(target_os = "macos") || on_path("strace") {
        let out = formwork(
            dir.path(),
            &["learn", "--", "/bin/sh", "-c", "exit 0"],
            &env,
        );
        assert_eq!(out.code, 0, "{}", out.stderr);
        assert_eq!(left(), Vec::<PathBuf>::new(), "{}", out.stderr);
    } else {
        not_exercised("strace unavailable for the learn row");
    }

    let out = formwork(
        dir.path(),
        &["run", "--confine-self", "--", "/bin/sh", "-c", "exit 0"],
        &env,
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    let kept = left();
    assert_eq!(
        kept.len(),
        1,
        "confine-self leaves its root: {}",
        out.stderr
    );
    assert!(
        out.stderr.contains(kept[0].to_str().unwrap()) && out.stderr.contains("FW-TRA21"),
        "and says so on the operator channel: {}",
        out.stderr
    );
    let out = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", "exit 0"], &env);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(left(), Vec::<PathBuf>::new(), "{}", out.stderr);
}

/// FW-E2E-196 (FW-TRA21): a live session's root survives a concurrent `run`; once its Launcher is
/// killed, the next `run` removes the root and runs.
#[test]
fn fw_e2e_196_the_next_launcher_removes_a_dead_sessions_root() {
    let (dir, runtime) = project("stale", WRITABLE_PROJECT);
    if !confiner_host(dir.path()) {
        return;
    }
    let env = [(RUNTIME_VAR, runtime.to_str().unwrap())];
    let script = "echo $$ > out/pid; while :; do sleep 0.1; done";
    let mut launcher = background(
        dir.path(),
        &runtime,
        &["run", "--", "/bin/sh", "-c", script],
    )
    .spawn()
    .unwrap();
    let workload = Workload::started(dir.path());
    let live = session_roots(&runtime);
    assert_eq!(live.len(), 1);

    let other = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", "exit 0"], &env);
    assert_eq!(other.code, 0, "{}", other.stderr);
    assert_eq!(
        session_roots(&runtime),
        live,
        "a concurrent run removed a live session's root"
    );

    signal(launcher.id(), libc::SIGKILL);
    launcher.wait().unwrap();
    assert_eq!(
        session_roots(&runtime),
        live,
        "a killed Launcher removes nothing"
    );
    let next = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", "exit 0"], &env);
    assert!(
        workload.alive(),
        "the killed Launcher's workload was reparented and runs on: the root went with its \
         Launcher, not with its last process"
    );
    assert_eq!(next.code, 0, "the next run starts: {}", next.stderr);
    assert!(
        next.stderr.contains("FW-TRA21"),
        "the removal is on the operator channel: {}",
        next.stderr
    );
    assert_eq!(
        session_roots(&runtime),
        Vec::<PathBuf>::new(),
        "the dead session's root is still there"
    );
}

/// A [`background`] command as the foreground job of a new pseudo-terminal, which becomes its
/// session's controlling terminal and its stdin. Returns the terminal's other end: a byte written
/// there is typed at the session.
fn on_a_terminal(mut command: Command) -> (Child, File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: openpty writes two descriptors, owned below.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: fresh descriptors from openpty, owned from here on.
    let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
    // SAFETY: fcntl on a descriptor owned above; the session must not hold the master.
    unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    command
        .stdin(Stdio::from(slave))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: ioctl(2) on the child's own stdin, between fork and exec, after `background` made
    // it a session leader.
    unsafe {
        command.pre_exec(|| {
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    (command.spawn().unwrap(), master)
}

const COUNTS_INT: &str = r#"trap 'echo int >> out/log' INT
echo $$ > out/pid
while [ ! -e out/stop ]; do :; done
"#;

/// FW-XR12, the terminal half: ^C at the terminal signals the whole foreground group, the
/// workload included, so the Launcher does not deliver it a second time -- a second interrupt is
/// how an operator ends a tool that asks for confirmation on the first.
#[test]
fn fw_xr12_a_terminal_interrupt_reaches_the_workload_once() {
    let (dir, runtime) = project("tty-int", WRITABLE_PROJECT);
    if !confiner_host(dir.path()) {
        return;
    }
    let (launcher, mut terminal) = on_a_terminal(background(
        dir.path(),
        &runtime,
        &["run", "--", "/bin/sh", "-c", COUNTS_INT],
    ));
    let workload = Workload::started(dir.path());
    terminal.write_all(b"\x03").unwrap();
    assert!(
        appears(&dir.path().join("out/log"), 10),
        "the interrupt never reached the workload"
    );
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("out/log")).unwrap(),
        "int\n",
        "the Launcher forwarded an interrupt the terminal had already delivered"
    );
    assert!(workload.alive());
    signal(launcher.id(), libc::SIGTERM);
    let out = finish(launcher);
    assert_eq!(out.code, 143, "the workload dies of the forwarded SIGTERM");
    assert!(session_roots(&runtime).is_empty(), "the root was left");
}

/// FW-XR13, the terminal half: during the grace period an interrupt from the terminal ends the
/// wait at once.
#[test]
fn fw_xr13_a_terminal_interrupt_during_the_grace_period_kills_at_once() {
    let (dir, runtime) = project("tty-grace", WRITABLE_PROJECT);
    if !confiner_host(dir.path()) {
        return;
    }
    let (launcher, mut terminal) = on_a_terminal(background(
        dir.path(),
        &runtime,
        &["run", "--", "/bin/sh", "-c", IGNORES_TERM],
    ));
    let workload = Workload::started(dir.path());
    signal(launcher.id(), libc::SIGTERM);
    std::thread::sleep(Duration::from_millis(500));
    assert!(workload.alive(), "the workload ignores SIGTERM");
    let typed = Instant::now();
    terminal.write_all(b"\x03").unwrap();
    let out = finish(launcher);
    assert_eq!(out.code, 137);
    assert!(
        typed.elapsed() < Duration::from_secs(5),
        "the Launcher waited out the grace period: {:?}",
        typed.elapsed()
    );
    assert!(workload.gone(5));
    assert!(session_roots(&runtime).is_empty(), "the root was left");
}
