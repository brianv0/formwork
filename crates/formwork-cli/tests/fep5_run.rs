//! FEP-5 black-box tests of `formwork run` against the real kernel: the Phase 0 defects that kept
//! the README quickstart and the closed read mode from starting, the Launcher-owned temporary
//! directory, channel locator variables, and the environment-disclosure report line. Each drives
//! the built binary with `$HOME` and the launch directory pinned inside a scratch directory.

use std::path::{Path, PathBuf};
use std::process::Command;

struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Scratch {
        let root = std::env::temp_dir().join(format!("formwork-fep5-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Scratch(std::fs::canonicalize(&root).unwrap())
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

fn formwork(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_formwork"));
    cmd.args(args).current_dir(dir).env("HOME", dir);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("running formwork");
    Output {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn landlock_host(dir: &Path) -> bool {
    let out = formwork(dir, &["explain", "--json"], &[]);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    v["host"]["landlock-abi"].as_u64().is_some()
}

const QUICKSTART: &str = "extends = [\"builtin:default\"]\nnet = { ports = [443] }\n\
                          rules = [\"readwrite:$CWD/**\"]\n";

/// FEP-5 D1: the README quickstart starts. `builtin:default`'s any-depth write-subtract rows used
/// to reach the Landlock builder and abort the spawn on Linux; they are withheld and reported now.
#[test]
fn readme_quickstart_starts_and_reports_what_it_withholds() {
    let dir = Scratch::new("quickstart");
    std::fs::write(dir.path().join("FORMWORK.toml"), QUICKSTART).unwrap();
    let run = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", "exit 0"], &[]);
    assert_eq!(run.code, 0, "the quickstart must start:\n{}", run.stderr);

    let report = formwork(dir.path(), &["compile", "--report-only"], &[]);
    assert_eq!(report.code, 0, "{}", report.stderr);
    let v: serde_json::Value = serde_json::from_str(&report.stdout).unwrap();
    if cfg!(target_os = "linux") && v["host"]["landlock-abi"].as_u64().is_some() {
        assert_eq!(
            v["per-capability"]["tamper-vectors"]["status"], "partial",
            "withheld rows degrade the capability: {}",
            v["per-capability"]["tamper-vectors"]
        );
        let withheld: Vec<&str> = v["withheld"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap())
            .collect();
        assert!(
            withheld.contains(&"write-subtract **/.git/hooks/**"),
            "{withheld:?}"
        );
    }
}

/// FW-E2E-089 (Linux half; D10/D11/FW-TRA9/FW-TRA10): under `mode = "unveil"` with only the
/// project granted, `$TMPDIR` is set and writable, a grandchild reads `/proc/self/status` and
/// `/etc/hosts`, and the per-session directory is removed when the run ends.
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_089_launcher_owned_paths_under_closed_mode() {
    let dir = Scratch::new("closed");
    if !landlock_host(dir.path()) {
        eprintln!("skipping: no Landlock on this host");
        return;
    }
    std::fs::write(
        dir.path().join("FORMWORK.toml"),
        "mode = \"unveil\"\nrules = [\"readwrite:$CWD/**\"]\n",
    )
    .unwrap();
    let script = r#"set -e
test -n "$TMPDIR" && test "$TMPDIR" = "$TMP" && test "$TMPDIR" = "$TEMP"
echo scratch > "$TMPDIR/f"
/bin/sh -c 'cat /proc/self/status > /dev/null && cat /etc/hosts > /dev/null'
printf '%s' "$TMPDIR"
"#;
    let run = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", script], &[]);
    assert_eq!(run.code, 0, "stdout={} stderr={}", run.stdout, run.stderr);
    let tmp = run.stdout.trim();
    assert!(tmp.contains("formwork-session-"), "{tmp}");
    assert!(
        !Path::new(tmp).exists(),
        "the session temp directory must be removed after the run"
    );
    assert!(
        run.stderr.contains("session temp directory"),
        "the directory is disclosed on the operator channel (FW-FID7): {}",
        run.stderr
    );
}

/// FW-E2E-088 (locator half, FW-BP11): a denied channel's locator variables are stripped; lifting
/// `desktop` re-admits `DISPLAY`/`WAYLAND_DISPLAY` and keeps `DBUS_SESSION_BUS_ADDRESS` out, since
/// `run-outside` is in no group.
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_088_channel_locator_variables_follow_the_lift() {
    let dir = Scratch::new("locators");
    if !landlock_host(dir.path()) {
        eprintln!("skipping: no Landlock on this host");
        return;
    }
    let locators = [
        ("DISPLAY", ":99"),
        ("WAYLAND_DISPLAY", "wayland-9"),
        ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/bus"),
    ];
    let probe =
        "env | grep -E '^(DISPLAY|WAYLAND_DISPLAY|DBUS_SESSION_BUS_ADDRESS)=' | sort; exit 0";
    std::fs::write(dir.path().join("FORMWORK.toml"), QUICKSTART).unwrap();
    let denied = formwork(
        dir.path(),
        &["run", "--", "/bin/sh", "-c", probe],
        &locators,
    );
    assert_eq!(denied.code, 0, "{}", denied.stderr);
    assert_eq!(
        denied.stdout.trim(),
        "",
        "denied channels strip their locators"
    );

    let lifted = formwork(
        dir.path(),
        &[
            "run",
            "--set",
            "channels = [\"desktop\"]",
            "--",
            "/bin/sh",
            "-c",
            probe,
        ],
        &locators,
    );
    assert_eq!(lifted.code, 0, "{}", lifted.stderr);
    assert_eq!(
        lifted.stdout.trim(),
        "DISPLAY=:99\nWAYLAND_DISPLAY=wayland-9",
        "desktop re-admits the display locators only"
    );
}

/// FW-E2E-083 (Linux default-profile half, D9): a same-uid sibling's environment is readable under
/// the default profile, and the report says `partial` with that residual -- the report and the
/// observation agree.
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_083_environment_disclosure_matches_the_report() {
    let dir = Scratch::new("environ");
    if !landlock_host(dir.path()) {
        eprintln!("skipping: no Landlock on this host");
        return;
    }
    std::fs::write(dir.path().join("FORMWORK.toml"), QUICKSTART).unwrap();
    let nonce = format!("canary-{}", std::process::id());
    let mut sibling = Command::new("/bin/sleep")
        .arg("30")
        .env("FW_CANARY", &nonce)
        .spawn()
        .unwrap();
    let environ = format!("/proc/{}/environ", sibling.id());
    // Until the sibling's exec lands, its environ is the forked parent's; poll for the canary.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let live = loop {
        let control = std::fs::read(&environ).unwrap_or_default();
        if String::from_utf8_lossy(&control).contains(&nonce) {
            break true;
        }
        if std::time::Instant::now() > deadline {
            break false;
        }
        std::thread::yield_now();
    };
    assert!(live, "control: the canary is live");
    let confined = formwork(dir.path(), &["run", "--", "/bin/cat", &environ], &[]);
    let _ = sibling.kill();
    let _ = sibling.wait();
    let observed = confined.code == 0 && confined.stdout.contains(&nonce);

    let report = formwork(dir.path(), &["compile", "--report-only"], &[]);
    let v: serde_json::Value = serde_json::from_str(&report.stdout).unwrap();
    let line = &v["per-capability"]["process-environment"];
    assert_eq!(line["status"], "partial", "{line}");
    assert!(
        observed,
        "the default profile reports this residual, so the observation must show it: {}",
        confined.stderr
    );
}

/// FEP-5 D3: a blueprint at `.formwork/blueprint.toml` is discovered, its derived proposal path
/// sits beside it inside `.formwork/`, and `compile` stamps where it came from.
#[test]
fn dotdir_blueprint_is_discovered() {
    let dir = Scratch::new("dotdir");
    std::fs::create_dir_all(dir.path().join(".formwork")).unwrap();
    std::fs::write(dir.path().join(".formwork/blueprint.toml"), QUICKSTART).unwrap();
    let out = formwork(
        dir.path(),
        &["compile", "--target", "linux-v6", "--report-only"],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["blueprint"]["source"], "auto-discovered");
    assert!(v["blueprint"]["path"]
        .as_str()
        .unwrap()
        .ends_with(".formwork/blueprint.toml"));
}

/// FW-FID11 (channel half): `explain <channel>` and `explain <group>` print each member's verdict,
/// its deciding layer, and host reachability.
#[test]
fn explain_names_the_channel_verdict_and_deciding_layer() {
    let dir = Scratch::new("explain-channel");
    std::fs::write(
        dir.path().join("FORMWORK.toml"),
        format!("{QUICKSTART}channels = {{ allow = [\"desktop\"], deny = [\"open-url\"] }}\n"),
    )
    .unwrap();
    let out = formwork(dir.path(), &["explain", "desktop", "run-outside"], &[]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout
            .contains("clipboard\n  verdict: lifted by channels allow clipboard"),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout
            .contains("open-url\n  verdict: denied by channels deny open-url"),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout
            .contains("run-outside\n  verdict: denied by channel baseline (built-in)"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("host: "), "{}", out.stdout);
    let bad = formwork(
        dir.path(),
        &["compile", "--set", "channels = [\"desk\"]", "--report-only"],
        &[],
    );
    assert_ne!(bad.code, 0);
    assert!(
        bad.stderr.contains("desk") && bad.stderr.contains("clipboard"),
        "an unknown channel fails at parse listing the valid names: {}",
        bad.stderr
    );
}
