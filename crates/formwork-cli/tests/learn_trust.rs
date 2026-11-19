//! Black-box tests of what a learning run may trust: the denial feed (FW-DISC17), driven on Linux
//! through the real chain -- strace tracing a shim that enforces with Landlock -- and the closed
//! key set of the discovered layer (FW-DISC18), which is a dry load on any host.

mod support;
use support::*;

/// A whole trace line as `learn` reads one, naming a path no kernel refused.
#[cfg(target_os = "linux")]
const FORGED: &str = "7 openat(AT_FDCWD, \"/forged-by-the-workload/a\", O_RDONLY) = -1 EACCES \
                      (Permission denied)";

/// The workload's last act: the shell itself appends the forged line to a file in the temp root
/// -- one it found there, else a new one. A tracer that holds its own offset into a file writes
/// its next line over whatever was appended, so the append that would stand is the one nothing
/// is traced after: no later call, and no child whose exit is reported.
#[cfg(target_os = "linux")]
const APPEND_LAST: &str = r#"
        for found in "$1"/*; do [ -f "$found" ] && feed=$found; done
        printf '\n%s\n' "$2" >> "${feed:-$1/formwork-learn.strace}"
"#;

/// The shipped default profile with a writable launch directory.
#[cfg(target_os = "linux")]
const BLUEPRINT: &str = "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\"]\n";

/// A scratch home whose `proj` is the launch directory, and a temp root of its own, so a feed
/// file -- were there one -- would sit where this workload alone looks, apart from every other
/// test's.
#[cfg(target_os = "linux")]
fn learn_host(tag: &str) -> Option<(Scratch, Scratch)> {
    let dir = Scratch::new(tag);
    let temp_root = Scratch::new(&format!("{tag}-tmp"));
    if host_profile(dir.path())["landlock-abi"].as_u64().is_none() || !on_path("strace") {
        not_exercised("the Linux denial feed needs Landlock and strace");
        return None;
    }
    // The blueprint's own directory takes no new files on Linux (FW-XR8 write-protects the
    // policy inputs in it), so the workload's writable part of the launch directory is `out`.
    std::fs::create_dir_all(dir.path().join("proj/out")).unwrap();
    std::fs::write(dir.path().join("proj/FORMWORK.toml"), BLUEPRINT).unwrap();
    // A key the floor denies: the run's own kernel denial, which shows the feed is read.
    std::fs::create_dir(dir.path().join(".ssh")).unwrap();
    std::fs::write(dir.path().join(".ssh/id_ed25519"), "FAKE KEY\n").unwrap();
    Some((dir, temp_root))
}

/// The proposal a learning run of `workload` wrote, with `$1` the temp root and `$2` the forged
/// line. `None` where ptrace is refused to this process, which is said, not passed over.
#[cfg(target_os = "linux")]
fn learned(dir: &Scratch, temp_root: &Scratch, workload: &str) -> Option<String> {
    let root = temp_root.path().to_str().unwrap();
    let proj = dir.path().join("proj");
    let out = formwork_command(
        dir.path(),
        &["learn", "--", "/bin/sh", "-c", workload, "sh", root, FORGED],
        &[("TMPDIR", root)],
        &[],
    )
    .current_dir(&proj)
    .output()
    .expect("running formwork");
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    if stderr.contains("the denial feed is empty") {
        not_exercised("ptrace is refused in this environment");
        return None;
    }
    assert!(stdout.contains("proposal:"), "{stderr}");
    let proposal = std::fs::read_to_string(proj.join("FORMWORK.toml.proposal.toml"))
        .unwrap_or_else(|e| panic!("no proposal ({e}):\n{stderr}"));
    assert!(
        stderr
            .lines()
            .any(|l| l.contains("withheld by the credential floor") && l.contains("id_ed25519")),
        "the feed lost the run's own denial:\n{stderr}"
    );
    assert!(
        !proj.join("FORMWORK.toml.discovered.toml").exists(),
        "nothing is self-granted without a zone"
    );
    Some(proposal)
}

/// FW-E2E-209: under the default profile the temp root is writable, and the workload has this
/// user's uid. It finds no feed file there to write to, and a trace line it writes to the paths
/// it can reach is not a candidate.
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_209_the_feed_is_not_a_file_the_workload_can_find() {
    let Some((dir, temp_root)) = learn_host("feed-209") else {
        return;
    };
    let workload = r#"
        cat ../.ssh/id_ed25519
        ls -A "$1" > out/found.txt
        printf '%s\n' "$2" >> "$TMPDIR/formwork-learn.strace"
        printf '%s\n' "$2" >> out/formwork-learn.strace
    "#;
    let Some(proposal) = learned(&dir, &temp_root, &format!("{workload}{APPEND_LAST}")) else {
        return;
    };
    let found = std::fs::read_to_string(dir.path().join("proj/out/found.txt")).unwrap();
    assert!(
        found
            .lines()
            .all(|name| name.starts_with("formwork-session-")),
        "the temp root holds the session's own directories and no feed file:\n{found}"
    );
    assert!(
        !proposal.contains("forged-by-the-workload"),
        "a line the workload wrote became a candidate:\n{proposal}"
    );
}

/// FW-ADV-058: the workload tries every route it has to its own `learn` result -- files in the
/// temp root, the session temp directory and the launch directory, every descriptor it was born
/// with, and the descriptors of each ancestor, which include both ends of the feed. The proposal
/// holds nothing the workload wrote.
#[cfg(target_os = "linux")]
#[test]
fn fw_adv_058_a_workload_cannot_write_its_own_learn_result() {
    let Some((dir, temp_root)) = learn_host("feed-058") else {
        return;
    };
    let workload = r#"
        cat ../.ssh/id_ed25519
        for target in "$1"/* "$1"/.[!.]* "$TMPDIR"/* ./*.toml \
            "$TMPDIR/formwork-learn.strace" out/formwork-learn.strace /proc/self/fd/*; do
            printf '%s\n' "$2" >> "$target"
        done 2>/dev/null
        pid=$PPID
        for generation in 1 2 3 4 5 6; do
            [ "$pid" -gt 1 ] || break
            for fd in /proc/$pid/fd/* /proc/$pid/fd/0 /proc/$pid/fd/1 /proc/$pid/fd/2 \
                /proc/$pid/fd/3 /proc/$pid/fd/4 /proc/$pid/fd/5 /proc/$pid/fd/6 /proc/$pid/fd/7 \
                /proc/$pid/fd/8 /proc/$pid/fd/9 /proc/$pid/fd/10 /proc/$pid/fd/11; do
                printf '%s\n' "$2" >> "$fd"
            done 2>/dev/null
            pid=$(cut -d' ' -f4 "/proc/$pid/stat" 2>/dev/null) || break
        done
    "#;
    let Some(proposal) = learned(&dir, &temp_root, &format!("{workload}{APPEND_LAST}")) else {
        return;
    };
    assert!(
        !proposal.contains("forged-by-the-workload"),
        "the proposal holds a denial no kernel produced:\n{proposal}"
    );
}

/// The proposal one accepted entry of each learned kind comes from.
const PROPOSAL: &str = "blueprint = \"FORMWORK.toml\"\n\n\
    [[candidates]]\npattern = \"/opt/toolchain/**\"\naccess = \"read\"\ntag = \"needs-review\"\n\
    run-id = \"learn-1\"\n\n\
    [[candidates]]\npattern = \"/srv/out.log\"\naccess = \"write\"\ntag = \"needs-review\"\n\
    run-id = \"learn-1\"\n\n\
    [[hosts]]\nrule = \"allow:blocked.test\"\nrun-id = \"learn-1\"\n\n\
    [[channels]]\nchannel = \"clipboard\"\nrun-id = \"learn-1\"\n";

/// FW-E2E-210: the layer `accept` writes loads, and the same layer carrying any one key outside
/// the learned set -- `auto-widen` and each other -- is refused naming that key.
#[test]
fn fw_e2e_210_a_discovered_layer_refuses_every_key_outside_the_learned_set() {
    let dir = Scratch::new("discovered-keys");
    std::fs::write(
        dir.path().join("FORMWORK.toml"),
        "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\"]\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("FORMWORK.toml.proposal.toml"), PROPOSAL).unwrap();
    let accepted = formwork(dir.path(), &["learn", "--accept-all"], &[]);
    assert_eq!(accepted.code, 0, "{}", accepted.stderr);
    let discovered = dir.path().join("FORMWORK.toml.discovered.toml");
    let learned = std::fs::read_to_string(&discovered).unwrap();
    let loaded = formwork(dir.path(), &["explain", "--json"], &[]);
    assert_eq!(loaded.code, 0, "{learned}\n{}", loaded.stderr);

    // A top-level key goes before the layer's first table; a table key is appended.
    let top = |line: &str| format!("{line}\n{learned}");
    let table = |lines: &str| format!("{learned}\n{lines}\n");
    for (key, forged) in [
        ("extends", top("extends = [\"builtin:default\"]")),
        ("mode", top("mode = \"subtractive\"")),
        ("net", top("net = { ports = [443] }")),
        ("exec", top("exec = \"unrestricted\"")),
        ("env", top("env = \"passthrough\"")),
        ("allow-credentials", top("allow-credentials = [\"ssh\"]")),
        ("isolate", top("isolate = [\"pid\"]")),
        ("mcp", table("[mcp.files]\ntools = { allow = [\"*\"] }")),
        (
            "discovery.auto-widen",
            learned.replacen(
                "[discovery.provenance",
                "[discovery]\nauto-widen = [\"/**\"]\n\n[discovery.provenance",
                1,
            ),
        ),
        (
            "fs.read-mode",
            learned.replace("[fs]\n", "[fs]\nread-mode = \"ambient-minus-subtract\"\n"),
        ),
        (
            "fs.writes-no-create",
            learned.replace("[fs]\n", "[fs]\nwrites-no-create = [\"/etc/**\"]\n"),
        ),
        (
            "fs.subtract",
            learned.replace("[fs]\n", "[fs]\nsubtract = [\"/opt/toolchain/secret\"]\n"),
        ),
        (
            "fs.write-subtract",
            learned.replace("[fs]\n", "[fs]\nwrite-subtract = [\"/srv/**\"]\n"),
        ),
        (
            "channels.deny",
            learned.replace(
                "channels = [\"clipboard\"]",
                "channels = { allow = [\"clipboard\"], deny = [\"screen\"] }",
            ),
        ),
    ] {
        assert_ne!(
            forged, learned,
            "the {key} fixture did not change the layer"
        );
        std::fs::write(&discovered, &forged).unwrap();
        let out = formwork(dir.path(), &["explain", "--json"], &[]);
        assert_ne!(
            out.code, 0,
            "a discovered layer with `{key}` loaded:\n{forged}"
        );
        assert!(
            out.stderr.contains(&format!("`{key}`")) && out.stderr.contains("FW-DISC18"),
            "{key}: {}",
            out.stderr
        );
    }
}
