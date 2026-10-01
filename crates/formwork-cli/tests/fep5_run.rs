//! FEP-5 black-box tests of `formwork run` against the real kernel: the Phase 0 defects that kept
//! the README quickstart and the closed read mode from starting, the Launcher-owned temporary
//! directory, channel locator variables, and the environment-disclosure report line. Each drives
//! the built binary with `$HOME` and the launch directory pinned inside a scratch directory.

use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::Command;

mod support;
use support::*;

#[cfg(target_os = "linux")]
fn landlock_host(dir: &Path) -> bool {
    let out = formwork(dir, &["explain", "--json"], &[]);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    v["host"]["landlock-abi"].as_u64().is_some()
}

const QUICKSTART: &str = "extends = [\"builtin:default\"]\nnet = { ports = [443] }\n\
                          rules = [\"readwrite:$CWD/**\"]\n";

/// The README's `toml` blocks, verbatim, in order; the first is the quickstart.
fn readme_blueprints() -> Vec<String> {
    let readme =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md"))
            .expect("README.md");
    readme
        .split("```toml\n")
        .skip(1)
        .map(|rest| rest[..rest.find("```").expect("the toml block closes")].to_string())
        .collect()
}

fn readme_quickstart() -> String {
    readme_blueprints()
        .into_iter()
        .next()
        .expect("the README has a toml block")
}

/// Every blueprint the README shows loads and compiles, the brokered one included (FW-CRED12:
/// brokering needs an inspected rule).
#[test]
fn every_readme_blueprint_loads() {
    for (i, blueprint) in readme_blueprints().into_iter().enumerate() {
        let dir = Scratch::new(&format!("readme-{i}"));
        std::fs::write(dir.path().join("FORMWORK.toml"), &blueprint).unwrap();
        let out = formwork(dir.path(), &["compile", "--report-only"], &[]);
        assert_eq!(out.code, 0, "{blueprint}\n{}", out.stderr);
    }
}

/// FEP-5 D1: the README quickstart starts, verbatim. `builtin:default`'s any-depth write-subtract
/// rows used to reach the Landlock builder and abort the spawn on Linux; they are withheld and
/// reported now. The quickstart stays at most five lines (FEP-5 §4).
#[test]
fn readme_quickstart_starts_and_reports_what_it_withholds() {
    let dir = Scratch::new("quickstart");
    let quickstart = readme_quickstart();
    assert!(quickstart.lines().count() <= 5, "{quickstart}");
    assert_eq!(
        quickstart
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .map(|l| l.split('#').next().unwrap().trim_end())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
        QUICKSTART,
        "the fixture the other tests use is the README's quickstart"
    );
    std::fs::write(dir.path().join("FORMWORK.toml"), &quickstart).unwrap();
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

/// FW-E2E-083 (Linux default-profile half, D9): whether a same-uid sibling's environment is
/// readable under the default profile agrees with the report. Landlock refuses ptrace-class access
/// outside the domain, so an unprivileged run (every CI runner) sees `enforced` and a refused read;
/// a run holding `CAP_SYS_ADMIN`, `CAP_PERFMON` or `CAP_SYS_PTRACE` (a root container) sees
/// `partial`, and never `enforced` with the canary readable.
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
    let privileged = v["host"]["facilities"]["ptrace-privileged"] == true;
    // Never an over-claim: a readable canary is never reported enforced.
    assert!(
        !(observed && line["status"] == "enforced"),
        "reported enforced, yet the sibling's environment was read: {line}"
    );
    if privileged {
        assert_eq!(line["status"], "partial", "{line}");
    } else {
        // Nor an under-claim: without the capabilities, Landlock's refusal holds.
        assert_eq!(line["status"], "enforced", "{line}");
        assert!(
            !observed,
            "an unprivileged run read the sibling's environment"
        );
    }
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
            "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\", \"allow:127.0.0.1:{port}\"]\n"
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
    assert!(
        other.stderr.contains("reason=\"host-not-listed\""),
        "the refusal carries its reason (FW-FID12): {}",
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

/// FW-E2E-082 (Linux, run-outside; FW-INV14): against a session bus started for the test, a
/// confined `gdbus call` is refused under host rules (supervised connect) and succeeds once `run-outside` is
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
        "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\", \"allow:127.0.0.1:9\"]\n";
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

const BROKERED: &str = "extends = [\"builtin:default\"]\n\
                        rules = [\"readwrite:$CWD/**\", \"get,post:api.anthropic.com\"]\n\
                        allow-credentials = [\"broker:anthropic\"]\n";

/// FW-E2E-078 (both; the `run` half -- the Gateway half is `formwork-gateway`'s inspect test): a
/// brokered credential reaches the session only as its placeholder, the secret bytes appear
/// nowhere in the confined environment, and the inspection trust bundle is readable but not
/// writable (FW-EGR13, FW-CRED14, FW-INV13).
#[test]
fn fw_e2e_078_session_holds_the_placeholder_and_a_read_only_trust_bundle() {
    let dir = Scratch::new("broker");
    if !egress_host(dir.path()) {
        not_exercised("no host-scoped egress on this host");
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
    // FEP-6 §4.11: both spellings of the proxy variables, an empty no_proxy, and Node's opt-in.
    for line in [
        "http_proxy=http://fw:",
        "https_proxy=http://fw:",
        "HTTP_PROXY=http://fw:",
        "HTTPS_PROXY=http://fw:",
        "NODE_USE_ENV_PROXY=1",
    ] {
        assert!(
            out.stdout.lines().any(|l| l.starts_with(line)),
            "{line}: {}",
            out.stdout
        );
    }
    for line in ["no_proxy=", "NO_PROXY="] {
        assert!(
            out.stdout.lines().any(|l| l == line),
            "{line}: {}",
            out.stdout
        );
    }
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
#[test]
fn a_brokered_credential_without_a_value_is_refused_before_spawn() {
    let dir = Scratch::new("broker-unset");
    if !egress_host(dir.path()) {
        not_exercised("no host-scoped egress on this host");
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
              rules = [\"readwrite:$CWD/**\", \"tunnel:api.anthropic.com\"]\n\
              allow-credentials = [\"broker:anthropic\"]\n";
    std::fs::write(dir.path().join("FORMWORK.toml"), bp).unwrap();
    let out = formwork(dir.path(), &["explain", "--json"], &[]);
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("api.anthropic.com"), "{}", out.stderr);
}

#[cfg(target_os = "linux")]
fn isolation_host(dir: &Path) -> bool {
    let out = formwork(dir, &["explain", "--json"], &[]);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    v["host"]["user-namespaces"].as_bool() == Some(true)
}

/// FW-E2E-079 (Linux): under `isolate = ["processes"]`, `/proc` lists only session processes, a
/// host process can be neither signaled nor read, `$TMPDIR` is a tmpfs, the workload's exit code
/// passes through the stage and init (FW-XR10), and the report says `Enforced` for the member and
/// for environment disclosure (FW-ISO16). On a host without user namespaces (Ubuntu 24.04's
/// AppArmor restriction) the run is refused before spawn, naming the alternatives (FW-XR9).
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_079_isolation_tier() {
    let dir = Scratch::new("isolate");
    std::fs::write(
        dir.path().join("FORMWORK.toml"),
        "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\"]\n\
         isolate = [\"processes\", \"ipc\"]\n",
    )
    .unwrap();
    let marker = dir.path().join("started");
    if !isolation_host(dir.path()) {
        let out = formwork(
            dir.path(),
            &["run", "--", "/bin/sh", "-c", "touch started"],
            &[],
        );
        assert_ne!(out.code, 0);
        for alternative in ["AppArmor", "sysctl", "bwrap", "drop the member"] {
            assert!(
                out.stderr.contains(alternative),
                "{alternative}: {}",
                out.stderr
            );
        }
        assert!(!marker.exists(), "refused before spawn");
        return;
    }
    let mut host = Command::new("sleep")
        .arg("30")
        .env("FW_HOST_CANARY", "host-environment")
        .spawn()
        .unwrap();
    let hp = host.id();
    let script = format!(
        "ls /proc | grep -c '^[0-9]'\n\
         stat -f -c %T \"$TMPDIR\"\n\
         kill -0 {hp} 2>/dev/null && echo host-signalable\n\
         cat /proc/{hp}/environ 2>/dev/null\n\
         exit 7"
    );
    let out = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", &script], &[]);
    let _ = host.kill();
    let _ = host.wait();
    assert_eq!(out.code, 7, "the workload's status: {}", out.stderr);
    let mut lines = out.stdout.lines();
    let pids: usize = lines
        .next()
        .unwrap_or("")
        .trim()
        .parse()
        .unwrap_or(usize::MAX);
    assert!(
        pids <= 5,
        "/proc lists only the init, sh, ls and grep: {}",
        out.stdout
    );
    assert_eq!(lines.next(), Some("tmpfs"), "{}", out.stdout);
    assert!(!out.stdout.contains("host-signalable"), "{}", out.stdout);
    assert!(!out.stdout.contains("host-environment"), "{}", out.stdout);

    let report = formwork(dir.path(), &["compile", "--report-only"], &[]);
    let v: serde_json::Value = serde_json::from_str(&report.stdout).unwrap();
    let caps = &v["per-capability"];
    for key in ["isolate-processes", "isolate-ipc", "process-environment"] {
        assert_eq!(caps[key]["status"], "enforced", "{key}: {}", caps[key]);
    }
}

/// The isolation tier under host rules: the supervisor still decides every connect from inside
/// the namespaces, and a pathname socket bound in the session's tmpfs is admitted (FW-ISO12).
#[cfg(target_os = "linux")]
#[test]
fn isolation_tier_keeps_supervised_egress() {
    let dir = Scratch::new("isolate-egress");
    if !isolation_host(dir.path()) {
        // Ubuntu 24.04's AppArmor restriction: the tier is refused there, which FW-E2E-079
        // exercises; nothing to compose it with.
        eprintln!("skipping: user namespaces unavailable; FW-E2E-079 covers the refusal");
        return;
    }
    if !supervision_host(dir.path()) || !on_path("curl") {
        not_exercised("connect supervision or curl unavailable");
        return;
    }
    let (port, hits) = http_fixture();
    std::fs::write(
        dir.path().join("FORMWORK.toml"),
        format!(
            "extends = [\"builtin:default\"]\n\
             rules = [\"readwrite:$CWD/**\", \"allow:127.0.0.1:{port}\"]\n\
             isolate = [\"processes\"]\n"
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
    assert_eq!(via.stdout, "upstream-ok\n");
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
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), before);

    if on_path("python3") {
        let script = "import os, socket\n\
                      p = os.path.join(os.environ['TMPDIR'], 's.sock')\n\
                      srv = socket.socket(socket.AF_UNIX); srv.bind(p); srv.listen(1)\n\
                      c = socket.socket(socket.AF_UNIX); c.connect(p); print('admitted')\n";
        let out = formwork(dir.path(), &["run", "--", "python3", "-c", script], &[]);
        assert_eq!(out.stdout, "admitted\n", "{}", out.stderr);
    }
}

/// A host opener fixture that appends each URL it is asked to open to `<dir>/opened`.
#[cfg(target_os = "linux")]
fn opener_fixture(dir: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let log = dir.join("opened");
    let fixture = dir.join("fixture-opener");
    std::fs::write(
        &fixture,
        format!("#!/bin/sh\nprintf '%s\\n' \"$1\" >> {}\n", log.display()),
    )
    .unwrap();
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o700)).unwrap();
    (fixture, log)
}

#[cfg(target_os = "linux")]
fn read_after_exit(log: &Path) -> String {
    // The host opener is spawned asynchronously; give it a moment to write.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while !log.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    std::fs::read_to_string(log).unwrap_or_default()
}

/// FW-E2E-090 (Linux): under `channels = ["open-url"]` the confined `xdg-open` of an `https://`
/// URL reaches the host opener and the operator channel records it; a `file:` URL is refused with
/// an operator line naming its reproduction (FW-FID9); `$BROWSER` names the shim (FW-ISO17).
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_090_brokered_open_url() {
    let dir = Scratch::new("open-url");
    let (fixture, log) = opener_fixture(dir.path());
    std::fs::write(
        dir.path().join("FORMWORK.toml"),
        "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\"]\n\
         channels = [\"open-url\"]\n",
    )
    .unwrap();
    let out = formwork(
        dir.path(),
        &[
            "run",
            "--",
            "/bin/sh",
            "-c",
            "xdg-open https://example.test/login; echo \"https=$?\"; \
             xdg-open file:///etc/passwd; echo \"file=$?\"; basename \"$BROWSER\"",
        ],
        &[("FORMWORK_HOST_OPENER", fixture.to_str().unwrap())],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    // The shim mirrors the Gateway's verdict to its caller (a generic refusal, exit 1).
    assert_eq!(out.stdout, "https=0\nfile=1\nxdg-open\n");
    assert!(
        out.stderr.contains("formwork: open-url: refused"),
        "{}",
        out.stderr
    );
    assert_eq!(read_after_exit(&log), "https://example.test/login\n");
    assert!(out.stderr.contains("opened a URL"), "{}", out.stderr);
    assert!(
        out.stderr.contains("refused open-url") && out.stderr.contains("formwork explain open-url"),
        "{}",
        out.stderr
    );
}

/// FW-ADV-020, the opener route (Linux): with `open-url` not lifted, a URL carrying a nonce toward
/// a host no rule names never reaches the host opener, so no browser outside the session fetches
/// it -- no process outside the session opens a URL for it (FW-INV14). (The session-bus route is `FW-E2E-082`'s refusal; the direct route is `FW-E2E-075`'s.)
#[cfg(target_os = "linux")]
#[test]
fn fw_adv_020_the_opener_does_not_exfiltrate_when_not_lifted() {
    let dir = Scratch::new("adv-020");
    let (fixture, log) = opener_fixture(dir.path());
    std::fs::write(
        dir.path().join("FORMWORK.toml"),
        "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\"]\n",
    )
    .unwrap();
    let nonce = format!("nonce-{}", std::process::id());
    let script = format!(
        "xdg-open https://blocked.test/?q={nonce}; echo \"xdg-open=$?\"; \
         open https://blocked.test/?q={nonce}; sensible-browser https://blocked.test/?q={nonce}; \
         \"$BROWSER\" https://blocked.test/?q={nonce}; true"
    );
    let out = formwork(
        dir.path(),
        &["run", "--", "/bin/sh", "-c", &script],
        &[("FORMWORK_HOST_OPENER", fixture.to_str().unwrap())],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(
        !log.exists(),
        "the host opener ran: {}",
        read_after_exit(&log)
    );
    assert!(out.stderr.contains("not lifted"), "{}", out.stderr);
    assert_eq!(out.stdout, "xdg-open=1\n", "the caller hears a refusal");
}

/// FW-E2E-085 (Linux): a learning run under host rules proposes `allow:blocked.test` from the
/// Gateway's refusal and `open-url` from the opener's, withholds the metadata address with an
/// operator line, and the accepted entries apply from the next run (FW-DISC12).
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_085_discovery_of_hosts_and_channels() {
    let dir = Scratch::new("learn-hosts");
    if !supervision_host(dir.path()) || !on_path("curl") || !on_path("strace") {
        not_exercised("connect supervision, curl or strace unavailable");
        return;
    }
    std::fs::write(
        dir.path().join("FORMWORK.toml"),
        "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\", \"allow:127.0.0.1:9\"]\n",
    )
    .unwrap();
    let learned = formwork(
        dir.path(),
        &[
            "learn",
            "--",
            "/bin/sh",
            "-c",
            "curl -sS -m 3 http://blocked.test/ >/dev/null; \
             curl -sS -m 3 http://169.254.169.254/latest >/dev/null; \
             xdg-open https://example.test/login; true",
        ],
        &[],
    );
    assert_eq!(learned.code, 0, "{}", learned.stderr);
    assert!(
        learned
            .stderr
            .contains("withheld, not proposed (FW-DISC12)")
            && learned.stderr.contains("169.254.169.254"),
        "{}",
        learned.stderr
    );
    let list = formwork(dir.path(), &["learn", "--list"], &[]);
    assert!(
        list.stdout.contains("\"allow:blocked.test:80\""),
        "{}",
        list.stdout
    );
    assert!(list.stdout.contains("\"open-url\""), "{}", list.stdout);
    assert!(!list.stdout.contains("169.254"), "{}", list.stdout);

    let accepted = formwork(dir.path(), &["learn", "--accept-all"], &[]);
    assert_eq!(accepted.code, 0, "{}", accepted.stderr);
    let hosts = formwork(dir.path(), &["explain", "--hosts"], &[]);
    assert!(
        hosts.stdout.contains("allow:blocked.test:80") && hosts.stdout.contains("discovered layer"),
        "{}",
        hosts.stdout
    );
    let channel = formwork(dir.path(), &["explain", "open-url"], &[]);
    assert!(channel.stdout.contains("lifted"), "{}", channel.stdout);
}

/// FW-DISC6 for the new entry kinds: a forged discovered layer that carries a path in `rules` or a
/// lift without provenance is refused at load.
#[test]
fn a_discovered_layer_without_provenance_for_hosts_or_channels_is_refused() {
    let dir = Scratch::new("discovered-forged");
    std::fs::write(
        dir.path().join("FORMWORK.toml"),
        "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\"]\n",
    )
    .unwrap();
    let discovered = dir.path().join("FORMWORK.toml.discovered.toml");
    for forged in [
        "rules = [\"allow:evil.test\"]\n",
        "rules = [\"readwrite:/etc/**\"]\n",
        "channels = [\"run-outside\"]\n",
    ] {
        std::fs::write(&discovered, forged).unwrap();
        let out = formwork(dir.path(), &["explain", "--json"], &[]);
        assert_ne!(out.code, 0, "{forged}");
        assert!(out.stderr.contains("FW-DISC6"), "{forged}: {}", out.stderr);
    }
}

/// FW-E2E-084 (both): each shipped agent blueprint starts under the baseline, and where the
/// agent is installed, its non-interactive smoke command (`--version`) runs under `learn` with no
/// denial to propose -- the strace feed on Linux, the session's tagged Sandbox records on macOS.
/// The blueprints are copied out of the repo so the proposal files land in scratch. The
/// `agent-examples` CI job sets `FW_AGENTS_INSTALLED=1`, which makes a missing agent a failure.
#[test]
fn fw_e2e_084_agent_examples_under_the_baseline() {
    let dir = Scratch::new("examples");
    if !egress_host(dir.path()) {
        not_exercised("no host-scoped egress on this host (the agent examples use host rules)");
        return;
    }
    let agents_required = std::env::var("FW_AGENTS_INSTALLED").as_deref() == Ok("1");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = repo.join("examples/blueprints");
    let copy = dir.path().join("blueprints");
    std::fs::create_dir_all(&copy).unwrap();
    for entry in std::fs::read_dir(&source).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().and_then(|e| e.to_str()) == Some("toml") {
            std::fs::copy(entry.path(), copy.join(entry.file_name())).unwrap();
        }
    }
    // The state directories the examples tell the operator to create once, outside the sandbox.
    for state in [
        ".claude",
        ".codex",
        ".local/share/opencode",
        ".local/state/opencode",
        ".cache/opencode",
        ".config/opencode",
    ] {
        std::fs::create_dir_all(dir.path().join(state)).unwrap();
    }
    let keys = [
        ("ANTHROPIC_API_KEY", "sk-fixture-084"),
        ("OPENAI_API_KEY", "sk-fixture-084"),
    ];
    // Denials the host imposes whatever the sandbox does, which each example documents: the strace
    // feed sees them as the same EACCES a Landlock denial produces.
    let opencode_host: &[&str] = if cfg!(target_os = "linux") {
        &["/sys/kernel/debug/tracing/trace_marker"]
    } else {
        &[]
    };
    let examples: [(&str, &str, &[&str]); 5] = [
        ("claude-code.toml", "claude", &[]),
        ("claude-code-api-key.toml", "claude", &[]),
        ("codex.toml", "codex", &[]),
        ("codex-api-key.toml", "codex", &[]),
        ("opencode.toml", "opencode", opencode_host),
    ];
    for (file, agent, host_imposed) in examples {
        let blueprint = copy.join(file);
        let blueprint = blueprint.to_str().unwrap();
        let started = formwork(
            dir.path(),
            &[
                "run",
                "--blueprint",
                blueprint,
                "--",
                "/bin/sh",
                "-c",
                "echo started",
            ],
            &keys,
        );
        assert_eq!(started.code, 0, "{file}: {}", started.stderr);
        assert_eq!(started.stdout, "started\n", "{file}");
        let feed = cfg!(target_os = "macos") || on_path("strace");
        if !on_path(agent) || !feed {
            assert!(
                !agents_required,
                "{file}: {agent} or the denial feed is missing"
            );
            eprintln!("{file}: {agent} or strace not installed; the smoke command is skipped");
            continue;
        }
        let smoke = formwork(
            dir.path(),
            &["learn", "--blueprint", blueprint, "--", agent, "--version"],
            &keys,
        );
        assert_eq!(smoke.code, 0, "{file}: {}", smoke.stderr);
        // A listing of the launch directory or an ancestor is the documented Landlock residual
        // (docs/linux-backend.md: an ancestor of a denied path is traversable but not listable,
        // as under unveil's closed mode); any other candidate is a denial the example missed.
        let proposal = format!("{blueprint}.proposal.toml");
        let text = std::fs::read_to_string(&proposal).unwrap_or_default();
        let parsed: toml::Value =
            toml::from_str(&text).unwrap_or(toml::Value::Table(Default::default()));
        let launch = dir.path();
        let unexpected: Vec<String> = parsed
            .get("candidates")
            .and_then(|c| c.as_array())
            .into_iter()
            .flatten()
            .filter(|c| {
                let pattern = c.get("pattern").and_then(|p| p.as_str()).unwrap_or("");
                let read = c.get("access").and_then(|a| a.as_str()) == Some("read");
                // The launch directory is also `$HOME` here, itself an ancestor of the floor.
                !(host_imposed.contains(&pattern) || (read && launch.starts_with(pattern)))
            })
            .map(|c| c.to_string())
            .collect();
        let others = ["hosts", "channels"]
            .iter()
            .filter_map(|k| parsed.get(*k))
            .filter_map(|v| v.as_array())
            .map(|a| a.len())
            .sum::<usize>();
        assert!(
            unexpected.is_empty() && others == 0,
            "{file}: `{agent} --version` was denied something: {unexpected:?} (+{others} hosts/channels)\n{}",
            smoke.stderr
        );
    }
}

/// FW-E2E-087 (Linux): host-session detection. With an empty runtime directory and no bus address
/// the session-bus channel reports its facility absent; with a fixture `dbus-daemon` in the runtime
/// directory `detect` names its socket, the report says `Partial` without host rules and
/// `Enforced` under supervised connect. With `Xvfb` on the runner, the display socket is named too.
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_087_host_session_detection() {
    let dir = Scratch::new("detect");
    std::fs::write(
        dir.path().join("FORMWORK.toml"),
        "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\"]\n",
    )
    .unwrap();
    let runtime = dir.path().join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    let rt = runtime.to_str().unwrap().to_string();
    let explain = |extra: &[&str]| -> serde_json::Value {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_formwork"));
        cmd.args(["explain", "--json"])
            .args(extra)
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .env("XDG_RUNTIME_DIR", &rt)
            .env_remove("DBUS_SESSION_BUS_ADDRESS");
        let out = cmd.output().unwrap();
        serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|_| panic!("explain: {}", String::from_utf8_lossy(&out.stderr)))
    };
    let bare = explain(&[]);
    assert_eq!(
        bare["report"]["channels"]["run-outside"]["host"]["present"], false,
        "{}",
        bare["report"]["channels"]["run-outside"]
    );
    assert_eq!(
        bare["report"]["channels"]["microphone"]["host"]["present"],
        false
    );

    if !on_path("dbus-daemon") {
        not_exercised("dbus-daemon unavailable");
        return;
    }
    let bus = runtime.join("bus");
    let mut daemon = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--address"])
        .arg(format!("unix:path={}", bus.display()))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !bus.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let with_bus = explain(&[]);
    let supervised = supervision_host(dir.path());
    let under_rules = explain(&["--set", "rules = [\"allow:127.0.0.1:9\"]"]);
    let _ = daemon.kill();
    let _ = daemon.wait();
    let channel = &with_bus["report"]["channels"]["run-outside"]["host"];
    assert_eq!(channel["present"], true, "{channel}");
    assert_eq!(channel["via"], bus.display().to_string(), "{channel}");
    assert_eq!(
        with_bus["report"]["per-capability"]["channel-run-outside"]["status"],
        "partial"
    );
    if supervised {
        let line = &under_rules["report"]["per-capability"]["channel-run-outside"];
        assert_eq!(line["status"], "enforced", "{line}");
        assert_eq!(line["backend"], "supervisor", "{line}");
    }

    if on_path("Xvfb") {
        let display = 90 + (std::process::id() % 9) as usize;
        let socket = PathBuf::from(format!("/tmp/.X11-unix/X{display}"));
        let mut xvfb = Command::new("Xvfb")
            .arg(format!(":{display}"))
            .args(["-nolisten", "tcp"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !socket.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let with_display = explain(&[]);
        let _ = xvfb.kill();
        let _ = xvfb.wait();
        // A killed Xvfb leaves its socket and lock behind; later runs would see a phantom display.
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(format!("/tmp/.X{display}-lock"));
        let clipboard = &with_display["report"]["channels"]["clipboard"]["host"];
        assert_eq!(clipboard["present"], true, "{clipboard}");
    } else {
        not_exercised("Xvfb unavailable");
    }
}
