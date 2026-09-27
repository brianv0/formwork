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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
/// Skip with a reason locally; in CI (`FW_REQUIRE_EXERCISED=1`) a test that could not exercise its
/// mechanism fails instead (FEP-5 §6.1).
fn not_exercised(reason: &str) {
    if std::env::var("FW_REQUIRE_EXERCISED").as_deref() == Ok("1") {
        panic!("not exercised on a CI runner: {reason}");
    }
    eprintln!("skipping: {reason}");
}

#[cfg(target_os = "linux")]
fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(tool).is_file()))
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn supervision_host(dir: &Path) -> bool {
    let out = formwork(dir, &["explain", "--json"], &[]);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    v["host"]["connect-supervision"].as_bool() == Some(true)
}

#[cfg(target_os = "linux")]
/// A loopback HTTP upstream that answers every request with `upstream-ok` and counts connections.
fn http_fixture() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = count.clone();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(500)));
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nupstream-ok\n",
            );
        }
    });
    (port, count)
}

/// FW-E2E-075 (Linux, through `run`): with a host rule, a request through the Gateway reaches the
/// upstream; the same request with the proxy bypassed is refused by the supervisor; a host no rule
/// names is refused by the Gateway with a generic 403, and the operator channel names the refusal.
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_075_run_routes_egress_through_the_gateway() {
    let dir = Scratch::new("egress");
    if !supervision_host(dir.path()) || !on_path("curl") {
        not_exercised("connect supervision or curl unavailable");
        return;
    }
    let (port, hits) = http_fixture();
    std::fs::write(
        dir.path().join("FORMWORK.toml"),
        format!(
            "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\", \"https:127.0.0.1:{port}\"]\n"
        ),
    )
    .unwrap();
    let url = format!("http://127.0.0.1:{port}/");
    let via = formwork(
        dir.path(),
        &["run", "--", "curl", "-sS", "-m", "5", &url],
        &[],
    );
    assert_eq!(via.code, 0, "{}", via.stderr);
    assert_eq!(
        via.stdout, "upstream-ok\n",
        "stdout is the workload's alone (FW-XR10)"
    );

    let before = hits.load(std::sync::atomic::Ordering::SeqCst);
    let bypass = formwork(
        dir.path(),
        &[
            "run",
            "--",
            "curl",
            "-sS",
            "-m",
            "5",
            "--noproxy",
            "*",
            &url,
        ],
        &[],
    );
    assert_ne!(bypass.code, 0, "a direct connect must fail");
    assert!(
        bypass.stderr.contains("refused connect"),
        "the supervisor names the refusal: {}",
        bypass.stderr
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        before,
        "the bypass never reached the upstream"
    );

    let other = formwork(
        dir.path(),
        &["run", "--", "curl", "-sS", "-m", "5", "http://127.0.0.2:9/"],
        &[],
    );
    assert!(
        other.stdout.contains("denied by formwork policy"),
        "{}",
        other.stdout
    );
    assert!(
        other
            .stderr
            .contains("formwork explain http://127.0.0.2:9/"),
        "the refusal names its reproduction (FW-FID9): {}",
        other.stderr
    );
}

/// FW-E2E-086 (first half, FW-XR10): `run` exits with the workload's status and writes nothing of
/// its own to stdout.
#[test]
fn fw_e2e_086_run_exits_with_the_workload_status() {
    let dir = Scratch::new("exit");
    std::fs::write(dir.path().join("FORMWORK.toml"), QUICKSTART).unwrap();
    let out = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", "exit 3"], &[]);
    assert_eq!(out.code, 3, "{}", out.stderr);
    assert_eq!(out.stdout, "");
}

/// FW-E2E-082 (Linux, run-outside): against a session bus started for the test, a confined
/// `gdbus call` is refused under host rules (supervised connect) and succeeds once `run-outside` is
/// lifted, which also re-admits DBUS_SESSION_BUS_ADDRESS. The control call runs unconfined first.
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_082_session_bus_is_closed_until_run_outside_is_lifted() {
    let dir = Scratch::new("dbus");
    if !supervision_host(dir.path()) || !on_path("dbus-daemon") || !on_path("gdbus") {
        not_exercised("connect supervision, dbus-daemon or gdbus unavailable");
        return;
    }
    let bus = dir.path().join("bus");
    let address = format!("unix:path={}", bus.display());
    let mut daemon = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--address", &address])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !bus.exists() && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    let call = [
        "gdbus",
        "call",
        "--session",
        "--dest",
        "org.freedesktop.DBus",
        "--object-path",
        "/org/freedesktop/DBus",
        "--method",
        "org.freedesktop.DBus.ListNames",
    ];
    let control = Command::new(call[0])
        .args(&call[1..])
        .env("DBUS_SESSION_BUS_ADDRESS", &address)
        .output()
        .unwrap();
    assert!(control.status.success(), "control: the bus is live");

    let base =
        "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\", \"https:127.0.0.1:9\"]\n";
    std::fs::write(dir.path().join("FORMWORK.toml"), base).unwrap();
    let env = [("DBUS_SESSION_BUS_ADDRESS", address.as_str())];
    let mut args = vec!["run", "--"];
    args.extend(call);
    let denied = formwork(dir.path(), &args, &env);
    let mut lifted_args = vec!["run", "--set", "channels = [\"run-outside\"]", "--"];
    lifted_args.extend(call);
    let lifted = formwork(dir.path(), &lifted_args, &env);
    let _ = daemon.kill();
    let _ = daemon.wait();
    assert_ne!(
        denied.code, 0,
        "the bus must be unreachable: {}",
        denied.stdout
    );
    assert_eq!(
        lifted.code, 0,
        "run-outside lifts the bus: {}",
        lifted.stderr
    );
    assert!(lifted.stdout.contains("org.freedesktop.DBus"));
}

#[cfg(target_os = "linux")]
const BROKERED: &str = "extends = [\"builtin:default\"]\n\
                        rules = [\"readwrite:$CWD/**\", \"get,post:api.anthropic.com\"]\n\
                        allow-credentials = [\"broker:anthropic\"]\n";

/// FW-E2E-078 (Linux, the `run` half; the Gateway half is `formwork-gateway`'s inspect test): a
/// brokered credential reaches the session only as its placeholder, the secret bytes appear
/// nowhere in the confined environment, and the inspection trust bundle is readable but not
/// writable (FW-EGR13, FW-CRED14, FW-INV13).
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_078_session_holds_the_placeholder_and_a_read_only_trust_bundle() {
    let dir = Scratch::new("broker");
    if !supervision_host(dir.path()) {
        not_exercised("connect supervision unavailable");
        return;
    }
    std::fs::write(dir.path().join("FORMWORK.toml"), BROKERED).unwrap();
    std::fs::create_dir_all(dir.path().join(".anthropic")).unwrap();
    std::fs::write(dir.path().join(".anthropic/key"), "catalog-file-bytes").unwrap();
    let secret = "sk-fixture-5c1e7a9b";
    let script = r#"printf 'key=%s\n' "$ANTHROPIC_API_KEY"
cat "$HOME/.anthropic/key" 2>/dev/null
head -1 "$SSL_CERT_FILE"
[ "$NODE_EXTRA_CA_CERTS" = "$SSL_CERT_FILE" ] && echo same-bundle
( echo x >> "$SSL_CERT_FILE" ) 2>/dev/null && echo bundle-writable
env"#;
    let out = formwork(
        dir.path(),
        &["run", "--", "/bin/sh", "-c", script],
        &[("ANTHROPIC_API_KEY", secret)],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.contains("key=fwcred-anthropic-"),
        "the placeholder, not the secret: {}",
        out.stdout
    );
    assert!(out.stdout.contains("-----BEGIN CERTIFICATE-----"));
    assert!(out.stdout.contains("same-bundle"));
    assert!(!out.stdout.contains("bundle-writable"), "{}", out.stdout);
    assert!(
        !out.stdout.contains(secret),
        "secret disclosed: {}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("catalog-file-bytes"),
        "a brokered type keeps its floor: {}",
        out.stdout
    );
    assert!(
        !out.stderr.contains(secret),
        "secret logged: {}",
        out.stderr
    );
}

/// FW-XR9 for brokering: a brokered credential with no value on the launching host is refused
/// before the workload starts, naming the variable to set.
#[cfg(target_os = "linux")]
#[test]
fn a_brokered_credential_without_a_value_is_refused_before_spawn() {
    let dir = Scratch::new("broker-unset");
    if !supervision_host(dir.path()) {
        not_exercised("connect supervision unavailable");
        return;
    }
    std::fs::write(dir.path().join("FORMWORK.toml"), BROKERED).unwrap();
    let marker = dir.path().join("started");
    let out = Command::new(env!("CARGO_BIN_EXE_formwork"))
        .args(["run", "--", "/bin/sh", "-c", "touch started"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env_remove("ANTHROPIC_API_KEY")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("ANTHROPIC_API_KEY"), "{stderr}");
    assert!(!marker.exists(), "the workload started");
}

/// FW-CRED12: a credential brokered to a host no inspected rule covers is refused at load, with
/// the rule to write.
#[test]
fn brokering_to_a_tunneled_host_is_refused_at_load() {
    let dir = Scratch::new("broker-tunnel");
    let bp = "extends = [\"builtin:default\"]\n\
              rules = [\"readwrite:$CWD/**\", \"https:api.anthropic.com\"]\n\
              allow-credentials = [\"broker:anthropic\"]\n";
    std::fs::write(dir.path().join("FORMWORK.toml"), bp).unwrap();
    let out = formwork(dir.path(), &["explain", "--json"], &[]);
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("api.anthropic.com"), "{}", out.stderr);
}
