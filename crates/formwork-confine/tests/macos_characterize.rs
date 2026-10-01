//! The macOS characterization suite (FEP-5 §6.3). Each test records how Seatbelt behaves on the
//! runner -- what an SBPL rule admits, which service a channel's client reaches, what stays
//! unmediated -- as assertions the requirement tests and the compiler's verdicts rest on, so a
//! change across macOS releases fails CI instead of widening the sandbox unnoticed. Raw profiles
//! go through `sandbox-exec`; the compiler's own profiles through `spawn_confined`.

#![cfg(target_os = "macos")]

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use formwork_blueprint::{
    Blueprint, Channel, ChannelPolicy, CredentialEntry, FsBlueprint, HostRule, HostTable,
    IsolateMember, NetPosture, PathPattern, ReadMode, ResolvedCatalog,
};
use formwork_compile::{
    CompiledPolicy, ConfinerPolicy, SessionGateway, SessionMarker, SessionSpec,
};
use formwork_detect::detect;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let root = std::env::temp_dir().join(format!("fw-char-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Scratch(std::fs::canonicalize(&root).unwrap())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn not_exercised(reason: &str) {
    if std::env::var("FW_REQUIRE_EXERCISED").as_deref() == Ok("1") {
        panic!("not exercised on a CI runner: {reason}");
    }
    eprintln!("skipping: {reason}");
}

/// A Python that runs under a sandbox (the Xcode command-line stub at /usr/bin does not).
fn python() -> Option<PathBuf> {
    ["/opt/homebrew/bin/python3", "/usr/local/bin/python3"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

fn sandbox_exec(profile: &str, argv: &[&str]) -> Output {
    Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(profile)
        .args(argv)
        .output()
        .expect("sandbox-exec runs")
}

fn sh(script: &str) -> Output {
    Command::new("/bin/sh")
        .args(["-c", script])
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn compile(blueprint: &Blueprint, gateway: Option<&SessionGateway>) -> CompiledPolicy {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    formwork_compile::compile_for_session(
        blueprint,
        &detect(),
        &ResolvedCatalog::builtin_for_home(&home).unwrap(),
        &SessionSpec {
            gateway: gateway.cloned(),
            deny_tag: None,
        },
    )
}

fn sbpl(policy: &CompiledPolicy) -> String {
    match &policy.confiner {
        ConfinerPolicy::Macos(m) => m.sbpl.clone(),
        other => panic!("expected a Seatbelt policy, got {other:?}"),
    }
}

/// The default posture the shipped profile starts from: ambient reads, writes to `dir` only.
fn ambient(dir: &Path) -> Blueprint {
    Blueprint {
        fs: FsBlueprint {
            read_mode: ReadMode::AmbientMinusSubtract,
            reads: Vec::new(),
            writes: vec![PathPattern::parse(&format!("{}/**", dir.display())).unwrap()],
            writes_no_create: Vec::new(),
            subtract: Vec::new(),
            write_subtract: Vec::new(),
        },
        ..Blueprint::empty()
    }
}

/// Sandbox records the unified log persisted since `since` that satisfy `want`, polled until one
/// does or 30 seconds pass.
fn sandbox_records(since: Instant, want: impl Fn(&str) -> bool) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let out = Command::new("/usr/bin/log")
            .args([
                "show",
                "--style",
                "ndjson",
                "--last",
                &format!("{}s", since.elapsed().as_secs() + 5),
                "--predicate",
                r#"sender == "Sandbox""#,
            ])
            .output()
            .unwrap();
        let found: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v["eventMessage"].as_str().map(str::to_string))
            .filter(|m| want(m))
            .collect();
        if !found.is_empty() || Instant::now() > deadline {
            return found;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// C1: SBPL remote filters take only `*` or `localhost` as the host, so the profile cannot name the
/// Gateway's address, only its port; `localhost:<P>` admits 127.0.0.1 and ::1 on that port and
/// nothing else. In a local filter `localhost` matches every local address -- the wildcard and the
/// host's network addresses -- so the loopback-listen grant (FW-EGR15) is not loopback-only.
#[test]
fn c1_network_filters_name_only_star_or_localhost() {
    let Some(py) = python() else {
        return not_exercised("no sandboxable python3");
    };
    let py = py.to_str().unwrap();
    for literal in ["127.0.0.1:80", "::1:80"] {
        let out = sandbox_exec(
            &format!(
                "(version 1)(allow default)(deny network*)(allow network-outbound (remote tcp \"{literal}\"))"
            ),
            &["/usr/bin/true"],
        );
        assert!(!out.status.success(), "{literal} compiled");
        assert!(
            text(&out).contains("host must be * or localhost"),
            "{literal}: {}",
            text(&out)
        );
    }
    let v4 = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = v4.local_addr().unwrap().port();
    let _v6 = TcpListener::bind(("::1", port)).ok();
    let other = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let profile = format!(
        "(version 1)(allow default)(deny network*)(allow network-outbound (remote tcp \"localhost:{port}\"))"
    );
    let connect = |host: &str, port: u16| {
        let out = sandbox_exec(
            &profile,
            &[
                py,
                "-c",
                &format!(
                    "import socket; socket.create_connection(('{host}', {port}), timeout=3); print('ok')"
                ),
            ],
        );
        text(&out)
    };
    assert!(connect("127.0.0.1", port).contains("ok"));
    if _v6.is_some() {
        assert!(connect("::1", port).contains("ok"));
    }
    assert!(connect("127.0.0.1", other).contains("Operation not permitted"));

    let listen = "(version 1)(allow default)(deny network*)\
                  (allow network-bind (local ip \"localhost:*\"))\
                  (allow network-inbound (local ip \"localhost:*\"))";
    let wildcard = sandbox_exec(
        listen,
        &[
            py,
            "-c",
            "import socket; s = socket.socket(); s.bind(('0.0.0.0', 0)); s.listen(1); print('listening')",
        ],
    );
    assert!(
        text(&wildcard).contains("listening"),
        "the wildcard listen is admitted by `localhost`: {}",
        text(&wildcard)
    );
}

/// C2: the peer lookup is reliable. A confined process tree -- nine direct children holding 100
/// connections each and ten reparented grandchildren holding ten each -- makes 1,000 connections
/// to a listener while it is still forking; each accepted connection is attributed to the session
/// by its client end and the session marker, and a connection from an unconfined process is not.
/// Accepting runs on its own thread, as the Gateway's does: a lookup in the accept loop lets the
/// listen queue (128 on macOS) overflow, and macOS resets the connections past it.
#[test]
fn c2_peer_lookup_attributes_every_connection() {
    let Some(py) = python() else {
        return not_exercised("no sandboxable python3");
    };
    let dir = Scratch::new("c2");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local = listener.local_addr().unwrap();
    let nonce = format!(
        "{:016x}",
        (std::process::id() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
    );
    let marker = SessionMarker::new(&nonce);
    let mut blueprint = ambient(&dir.0);
    blueprint.net = NetPosture::AllowHosts(HostTable::new(vec!["allow:example.test"
        .parse::<HostRule>()
        .unwrap()]));
    let policy = compile(
        &blueprint,
        Some(&SessionGateway {
            port: local.port(),
            marker: marker.clone(),
        }),
    );
    let stop = dir.0.join("stop");
    let script = r#"
import os, socket, sys, time
port, stop = int(sys.argv[1]), sys.argv[2]
def connect():
    for _ in range(200):
        try:
            return socket.create_connection(("127.0.0.1", port))
        except OSError:
            time.sleep(0.05)
    os._exit(1)
def hold(n):
    held = [connect() for _ in range(n)]
    while not os.path.exists(stop):
        time.sleep(0.05)
    os._exit(0)
for _ in range(9):
    if os.fork() == 0:
        hold(100)
for _ in range(10):
    if os.fork() == 0:
        if os.fork() == 0:
            os.setsid()
            hold(10)
        os._exit(0)
while True:
    try:
        os.wait()
    except ChildProcessError:
        break
"#;
    let mut cmd = Command::new(&py);
    cmd.args([
        "-c",
        script,
        &local.port().to_string(),
        stop.to_str().unwrap(),
    ]);
    formwork_confine::spawn_confined(&mut cmd, &policy).unwrap();
    let (accepted, arrivals) = std::sync::mpsc::channel();
    let acceptor = listener.try_clone().unwrap();
    std::thread::spawn(move || loop {
        if let Ok(conn) = acceptor.accept() {
            if accepted.send(conn).is_err() {
                break;
            }
        }
    });
    let mut tree = cmd.spawn().unwrap();
    let started = Instant::now();
    let deadline = started + Duration::from_secs(120);
    let mut attributed = 0;
    let mut missed = Vec::new();
    while attributed + missed.len() < 1000 {
        let left = deadline.saturating_duration_since(Instant::now());
        let Ok((stream, peer)) = arrivals.recv_timeout(left) else {
            break;
        };
        if formwork_confine::session_holds_connection(&marker, peer, local) {
            attributed += 1;
        } else {
            missed.push(peer);
        }
        drop(stream);
    }
    let elapsed = started.elapsed();
    let outsider = TcpStream::connect(local).unwrap();
    let (_s, peer) = arrivals.recv_timeout(Duration::from_secs(10)).unwrap();
    let outsider_admitted = formwork_confine::session_holds_connection(&marker, peer, local);
    std::fs::write(&stop, "").unwrap();
    let _ = tree.wait();
    drop(outsider);
    eprintln!("C2: {attributed} connections attributed in {elapsed:?}");
    assert_eq!(
        attributed + missed.len(),
        1000,
        "the confined tree made only {} connections in {elapsed:?}",
        attributed + missed.len()
    );
    assert_eq!(attributed, 1000, "unattributed: {missed:?}");
    assert!(
        !outsider_admitted,
        "an unconfined process's connection was attributed"
    );
}

/// One channel probe: a shell script that exits 0 only when the channel worked.
struct Probe {
    channel: &'static str,
    script: String,
    /// The Sandbox record a denial leaves.
    record: &'static str,
}

/// C3 and C4: which services and operations each channel's client uses. Each probe works
/// unconfined and under a bare sandbox, and fails once exactly the compiler's rules for its
/// channel are added, leaving the record the map predicts. AppleEvents and launchd job creation
/// are refused to every sandboxed process by the services themselves -- System Events answers a
/// sandboxed sender with a privilege violation and launchd denies `job-creation` -- so those probes
/// are characterized as closed under any profile.
#[test]
fn c3_c4_channel_services_and_operations() {
    let dir = Scratch::new("c3");
    let d = dir.0.display();
    let keychain = dir.0.join("c3.keychain");
    let kc = keychain.to_str().unwrap();
    assert!(sh(&format!(
        "security create-keychain -p pw '{kc}' && security add-generic-password -s fw-c3 -a fw -w s3cret '{kc}'"
    ))
    .status
    .success());
    let app = dir.0.join("C3.app");
    std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    std::fs::write(
        app.join("Contents/Info.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict>\
         <key>CFBundleExecutable</key><string>c3</string><key>CFBundleIdentifier</key>\
         <string>dev.formwork.c3</string><key>CFBundlePackageType</key><string>APPL</string>\
         <key>LSUIElement</key><true/></dict></plist>",
    )
    .unwrap();
    std::fs::write(
        app.join("Contents/MacOS/c3"),
        format!("#!/bin/sh\necho launched >> '{d}/app-marker'\n"),
    )
    .unwrap();
    sh(&format!("chmod +x '{}/Contents/MacOS/c3'", app.display()));
    let probes = [
        Probe {
            channel: "clipboard",
            script: "printf c3 | pbcopy && [ \"$(pbpaste)\" = c3 ]".to_string(),
            record: "mach-lookup com.apple.pasteboard.1",
        },
        Probe {
            channel: "screen",
            script: format!("rm -f '{d}/s.png'; screencapture -x '{d}/s.png' && [ -s '{d}/s.png' ]"),
            record: "mach-lookup com.apple.windowserver.active",
        },
        Probe {
            channel: "os-keyring",
            script: format!("[ \"$(security find-generic-password -s fw-c3 -w '{kc}')\" = s3cret ]"),
            record: "mach-lookup com.apple.SecurityServer",
        },
        Probe {
            channel: "open-url",
            script: format!(
                "rm -f '{d}/app-marker'; /usr/bin/open -g -n '{}' && sleep 2 && [ -e '{d}/app-marker' ]",
                app.display()
            ),
            record: "lsopen",
        },
    ];
    let channel_rules = |channel: &str| -> String {
        // The compiler's own rules for the channel alone: a profile that lifts every other one.
        let mut blueprint = ambient(&dir.0);
        let keep: Vec<Channel> = Channel::ALL
            .into_iter()
            .filter(|c| c.name() != channel)
            .collect();
        blueprint.channels = ChannelPolicy::allow(keep);
        if channel != "os-keyring" {
            blueprint.allow_credentials = vec![CredentialEntry::parse("os-keyring")];
        }
        sbpl(&compile(&blueprint, None))
    };
    for probe in &probes {
        let control = sh(&probe.script);
        assert!(
            control.status.success(),
            "{}: control: {}",
            probe.channel,
            text(&control)
        );
        let bare = sandbox_exec(
            "(version 1)(allow default)",
            &["/bin/sh", "-c", &probe.script],
        );
        assert!(
            bare.status.success(),
            "{}: bare sandbox: {}",
            probe.channel,
            text(&bare)
        );
        let started = Instant::now();
        let closed = sandbox_exec(
            &channel_rules(probe.channel),
            &["/bin/sh", "-c", &probe.script],
        );
        assert!(
            !closed.status.success(),
            "{}: still works under its rules",
            probe.channel
        );
        let record = sandbox_records(started, |m| m.contains(&format!(") {}", probe.record)));
        assert!(
            !record.is_empty(),
            "{}: no `{}` record",
            probe.channel,
            probe.record
        );
    }
    let _ = sh(&format!("security delete-keychain '{kc}'"));
    let _ = sh("printf '' | pbcopy");

    // Closed to every sandbox, whatever the profile allows.
    let label = format!("dev.formwork.c4.{}", std::process::id());
    let job = sandbox_exec(
        "(version 1)(allow default)",
        &[
            "/bin/launchctl",
            "submit",
            "-l",
            &label,
            "--",
            "/usr/bin/true",
        ],
    );
    let _ = sh(&format!("launchctl remove {label} 2>/dev/null"));
    assert!(
        !job.status.success(),
        "a sandboxed process created a launchd job"
    );
    let ae = sandbox_exec(
        "(version 1)(allow default)",
        &[
            "/usr/bin/osascript",
            "-e",
            &format!(
                "tell application \"System Events\" to make new folder at end of folder \"{d}\" with properties {{name:\"ae\"}}"
            ),
        ],
    );
    assert!(
        !dir.0.join("ae").exists(),
        "System Events acted for a sandboxed sender"
    );
    assert!(text(&ae).contains("-10004"), "{}", text(&ae));
}

/// C5: `kern.procargs2` returns a same-uid process's exec-time environment, and no Seatbelt
/// operation mediates it -- neither `sysctl-read`, by name or whole, nor `process-info`. A process
/// that zeroes its own exec-time strings, as `formwork` does, is read as blank. And no sandboxed
/// process may exec a setuid binary (`ps` among them): Seatbelt's `forbidden-exec-sugid`.
#[test]
fn c5_procargs2_is_not_mediated() {
    let dir = Scratch::new("c5");
    // A C reader: under `(deny sysctl-read)` an interpreter cannot start (it reads sysctls).
    std::fs::write(
        dir.0.join("procargs.c"),
        "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <sys/sysctl.h>\n\
         int main(int c, char **v) { int mib[3] = {CTL_KERN, KERN_PROCARGS2, atoi(v[1])};\n\
         static char b[1 << 20]; size_t n = sizeof b;\n\
         if (sysctl(mib, 3, b, &n, NULL, 0)) { puts(\"unreadable\"); return 2; }\n\
         for (size_t i = 0; i + strlen(v[2]) <= n; i++) if (!memcmp(b + i, v[2], strlen(v[2]))) { puts(\"seen\"); return 0; }\n\
         puts(\"hidden\"); return 1; }\n",
    )
    .unwrap();
    let reader = dir.0.join("procargs");
    let built = Command::new("/usr/bin/cc")
        .arg("-o")
        .arg(&reader)
        .arg(dir.0.join("procargs.c"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !built {
        return not_exercised("no C compiler");
    }
    let nonce = format!("canary-{}", std::process::id());
    let mut sibling = Command::new("/bin/sleep")
        .arg("30")
        .env("FW_CANARY", &nonce)
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let pid = sibling.id().to_string();
    for profile in [
        "(version 1)(allow default)",
        "(version 1)(allow default)(deny sysctl-read (sysctl-name \"kern.procargs2\"))",
        "(version 1)(allow default)(deny sysctl-read)",
        "(version 1)(allow default)(deny process-info*)",
    ] {
        let out = sandbox_exec(profile, &[reader.to_str().unwrap(), &pid, &nonce]);
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "seen",
            "{profile}: {}",
            text(&out)
        );
    }
    let _ = sibling.kill();
    let _ = sibling.wait();

    // A process that zeroes its exec-time environment strings is read as blank.
    std::fs::write(
        dir.0.join("conceal.c"),
        "#include <crt_externs.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\
         #include <unistd.h>\nint main(void) { char ***e = _NSGetEnviron(); size_t n = 0;\n\
         while ((*e)[n]) n++; char **c = calloc(n + 1, sizeof *c);\n\
         for (size_t i = 0; i < n; i++) c[i] = strdup((*e)[i]); char **o = *e; *e = c;\n\
         for (size_t i = 0; i < n; i++) memset(o[i], 0, strlen(o[i]));\n\
         puts(\"ready\"); fflush(stdout); sleep(10); return 0; }\n",
    )
    .unwrap();
    let conceal = dir.0.join("conceal");
    assert!(Command::new("/usr/bin/cc")
        .arg("-o")
        .arg(&conceal)
        .arg(dir.0.join("conceal.c"))
        .status()
        .unwrap()
        .success());
    let mut concealed = Command::new(&conceal)
        .env("FW_CANARY", &nonce)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = [0u8; 6];
    std::io::Read::read_exact(concealed.stdout.as_mut().unwrap(), &mut ready).unwrap();
    let out = Command::new(&reader)
        .args([&concealed.id().to_string(), &nonce])
        .output()
        .unwrap();
    let _ = concealed.kill();
    let _ = concealed.wait();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hidden");

    let ps = sandbox_exec("(version 1)(allow default)", &["/bin/ps", "-p", "1"]);
    assert!(!ps.status.success(), "a sandboxed process exec'd setuid ps");
}

/// C6: the `(target …)` forms. `same-sandbox` keeps the session's process management -- job
/// control, a worker pool, `make -j`, Node's child processes, a reparented descendant -- while
/// `(deny signal)` and `(deny process-info*)` refuse a sibling in another process group and the
/// unconfined parent, which shares the session's process group (`(target others)` would leave it
/// out). Asserted on the compiler's own isolation profile.
#[test]
fn c6_same_sandbox_keeps_process_management() {
    let Some(py) = python() else {
        return not_exercised("no sandboxable python3");
    };
    let dir = Scratch::new("c6");
    let mut blueprint = ambient(&dir.0);
    blueprint.isolate = vec![IsolateMember::Processes];
    let policy = compile(&blueprint, None);
    use std::os::unix::process::CommandExt;
    let mut sibling = Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .unwrap();
    std::fs::write(
        dir.0.join("pool.py"),
        "import multiprocessing as mp\ndef f(x): return x * x\n\
         if __name__ == '__main__':\n    with mp.Pool(2) as p: print('pool', sum(p.map(f, range(10))))\n",
    )
    .unwrap();
    std::fs::write(
        dir.0.join("Makefile"),
        "all: a b\na:\n\tsleep 0.2\nb:\n\tsleep 0.2\n",
    )
    .unwrap();
    let node = if Path::new("/opt/homebrew/bin/node").exists() {
        "node -e 'const p=require(\"child_process\").spawn(\"sleep\",[\"5\"]);setTimeout(()=>p.kill(),200);p.on(\"exit\",(c,s)=>console.log(\"node\",s))'"
    } else {
        "echo node SIGTERM"
    };
    let script = format!(
        r#"cd '{dir}'
kill -0 {sib} 2>/dev/null && echo sibling=signalable || echo sibling=refused
kill -0 $PPID 2>/dev/null && echo parent=signalable || echo parent=refused
/bin/bash -c 'set -m; sleep 5 & kill -TERM %1; wait; echo jobs=ok' 2>/dev/null
{py} pool.py
{node}
make -s -j2 && echo make=ok
/bin/sh -c '/usr/bin/perl -e "setpgrp(0,0); sleep 30" & echo $! > gc'; sleep 0.3; kill "$(cat gc)" && echo reparented=ok
"#,
        dir = dir.0.display(),
        sib = sibling.id(),
        py = py.display(),
    );
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", &script]).stderr(Stdio::piped());
    formwork_confine::spawn_confined(&mut cmd, &policy).unwrap();
    let out = cmd.output().unwrap();
    let _ = sibling.kill();
    let _ = sibling.wait();
    let got = String::from_utf8_lossy(&out.stdout);
    for want in [
        "sibling=refused",
        "parent=refused",
        "jobs=ok",
        "pool 285",
        "node SIGTERM",
        "make=ok",
        "reparented=ok",
    ] {
        assert!(
            got.contains(want),
            "{want}:\n{got}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// C7: POSIX IPC names cannot be confined to a session prefix without breaking the tools that
/// choose their own: under a prefix rule Python's multiprocessing cannot create its semaphore or
/// shared memory, while a name inside the prefix works. So `isolate = ["ipc"]` leaves POSIX IPC
/// global and says so.
#[test]
fn c7_posix_ipc_prefixes_break_multiprocessing() {
    let Some(py) = python() else {
        return not_exercised("no sandboxable python3");
    };
    let py = py.to_str().unwrap();
    let profile = "(version 1)(allow default)(deny ipc-posix*)\
                   (allow ipc-posix* (ipc-posix-name-prefix \"/fw\"))";
    let lock = sandbox_exec(
        profile,
        &[
            py,
            "-c",
            "import multiprocessing as m; m.Lock(); print('ok')",
        ],
    );
    assert!(text(&lock).contains("PermissionError"), "{}", text(&lock));
    let shm = sandbox_exec(
        profile,
        &[
            py,
            "-c",
            "from multiprocessing import shared_memory as s; m = s.SharedMemory(name='fwc7', create=True, size=8); m.close(); m.unlink(); print('ok')",
        ],
    );
    assert!(text(&shm).contains("ok"), "{}", text(&shm));
    let sysv = sandbox_exec(
        "(version 1)(allow default)(deny ipc-sysv*)",
        &["/usr/bin/true"],
    );
    assert!(sysv.status.success());
}

/// C8: the toolchain opens no IOKit user client. With `iokit-open` denied outright, git, Python,
/// the C compiler, cargo, curl and xcrun all work -- so a narrowed allowlist costs the toolchain
/// nothing; what needs IOKit is the GPU and screen capture (Metal opens the GPU's user client,
/// whose class differs by hardware), which is why the baseline leaves it open. SwiftPM sandboxes
/// its manifest build with `sandbox-exec` itself, which no sandboxed process may do, so a
/// session runs `swift build --disable-sandbox`.
#[test]
fn c8_toolchain_needs_no_iokit_user_client() {
    let Some(py) = python() else {
        return not_exercised("no sandboxable python3");
    };
    let dir = Scratch::new("c8");
    std::fs::write(dir.0.join("t.c"), "int main(void) { return 0; }\n").unwrap();
    let profile = "(version 1)(allow default)(deny iokit-open)(deny iokit-open-user-client)\
                   (deny iokit-open-service)";
    let c = dir.0.join("t.c");
    let o = dir.0.join("t.o");
    let commands: Vec<Vec<&str>> = vec![
        vec!["/usr/bin/git", "--version"],
        vec![py.to_str().unwrap(), "-c", "print(1)"],
        vec![
            "/usr/bin/cc",
            "-c",
            c.to_str().unwrap(),
            "-o",
            o.to_str().unwrap(),
        ],
        vec!["/usr/bin/curl", "--version"],
        vec!["/usr/bin/xcrun", "--show-sdk-path"],
    ];
    for argv in &commands {
        let out = sandbox_exec(profile, argv);
        assert!(out.status.success(), "{argv:?}: {}", text(&out));
    }
    if let Some(cargo) = std::env::var_os("CARGO") {
        let out = sandbox_exec(profile, &[cargo.to_str().unwrap(), "--version"]);
        assert!(out.status.success(), "cargo: {}", text(&out));
    }
    let nested = sandbox_exec(
        "(version 1)(allow default)",
        &[
            "/usr/bin/sandbox-exec",
            "-p",
            "(version 1)(allow default)",
            "/usr/bin/true",
        ],
    );
    assert!(
        text(&nested).contains("Operation not permitted"),
        "a sandboxed process applied a second sandbox: {}",
        text(&nested)
    );
}

/// The session marker (FW-EGR9): `sandbox_check` reports a process confined by the compiler's
/// profile as denied the marker's first service and allowed its second, an unconfined process as
/// allowed both, and a deny-default sandbox as denied both -- asked from outside without a record.
#[test]
fn c2_the_session_marker_tells_the_session_apart() {
    let marker = SessionMarker::new("c2marker0123456789");
    let dir = Scratch::new("c2-marker");
    let mut blueprint = ambient(&dir.0);
    blueprint.net = NetPosture::AllowHosts(HostTable::new(vec!["allow:example.test"
        .parse::<HostRule>()
        .unwrap()]));
    let policy = compile(
        &blueprint,
        Some(&SessionGateway {
            port: 9,
            marker: marker.clone(),
        }),
    );
    let mut cmd = Command::new("/bin/sleep");
    cmd.arg("10");
    formwork_confine::spawn_confined(&mut cmd, &policy).unwrap();
    let mut confined = cmd.spawn().unwrap();
    let mut unconfined = Command::new("/bin/sleep").arg("10").spawn().unwrap();
    let mut deny_default = Command::new("/usr/bin/sandbox-exec")
        .args([
            "-p",
            "(version 1)(deny default)(allow process*)(allow file-read*)(allow sysctl-read)",
            "/bin/sleep",
            "10",
        ])
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let carries = |pid: u32| formwork_confine::carries_marker(pid as libc::pid_t, &marker);
    let results = (
        carries(confined.id()),
        carries(unconfined.id()),
        carries(deny_default.id()),
    );
    for c in [&mut confined, &mut unconfined, &mut deny_default] {
        let _ = c.kill();
        let _ = c.wait();
    }
    assert_eq!(results, (true, false, false));
}
