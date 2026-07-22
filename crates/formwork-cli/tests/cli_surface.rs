//! Black-box tests of the CLI surface itself: blueprint discovery and its transparency, the
//! human/machine explain doors, the help epilogue's host line, learn's fail-fast honesty, and the
//! hidden back-compat aliases. Everything here is dry-run (no confiner), so it runs on any host.

use std::path::{Path, PathBuf};
use std::process::Command;

struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Scratch {
        let root = std::env::temp_dir().join(format!("formwork-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Scratch(root)
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

/// Run the built `formwork` with cwd and $HOME pinned inside the scratch dir, so blueprint
/// discovery cannot escape into the real environment.
fn formwork(cwd: &Path, home: &Path, args: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_formwork"))
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .output()
        .expect("running formwork");
    Output {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

const MINIMAL_BLUEPRINT: &str =
    "net = \"deny\"\n[fs]\nread-mode = \"closed\"\nreads = [\"/opt/data/**\"]\n";

#[test]
fn help_epilogue_reports_this_host() {
    let dir = Scratch::new("help");
    let out = formwork(dir.path(), dir.path(), &["--help"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("This host: "), "{}", out.stdout);
    // The demoted plumbing/aliases stay callable but out of the listing.
    for hidden in ["detect", "enforce-self", "accept"] {
        assert!(
            !out.stdout.contains(&format!("\n  {hidden}")),
            "`{hidden}` should be hidden from help:\n{}",
            out.stdout
        );
    }
}

#[test]
fn formwork_toml_is_discovered_and_stamped_into_compile_output() {
    let dir = Scratch::new("discover");
    std::fs::write(dir.path().join("FORMWORK.toml"), MINIMAL_BLUEPRINT).unwrap();

    let out = formwork(
        dir.path(),
        dir.path(),
        &["compile", "--target", "linux-v6", "--report-only"],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    let report: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(report["blueprint"]["source"], "auto-discovered");
    assert!(
        report["blueprint"]["path"]
            .as_str()
            .unwrap()
            .ends_with("FORMWORK.toml"),
        "{}",
        report["blueprint"]
    );
    // Discovery is announced on the operator channel too, never silent.
    assert!(out.stderr.contains("auto-discovered"), "{}", out.stderr);

    // An explicit flag is stamped as such.
    let explicit = formwork(
        dir.path(),
        dir.path(),
        &[
            "compile",
            "--blueprint",
            "FORMWORK.toml",
            "--target",
            "linux-v6",
            "--report-only",
        ],
    );
    let report: serde_json::Value = serde_json::from_str(&explicit.stdout).unwrap();
    assert_eq!(report["blueprint"]["source"], "flag");
}

#[test]
fn missing_blueprint_error_teaches_the_two_options() {
    let dir = Scratch::new("nobp");
    let out = formwork(
        dir.path(),
        dir.path(),
        &["compile", "--target", "linux-v6", "--report-only"],
    );
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("--blueprint"), "{}", out.stderr);
    assert!(out.stderr.contains("FORMWORK.toml"), "{}", out.stderr);
    assert!(out.stderr.contains("builtin:default"), "{}", out.stderr);
}

#[test]
fn explain_json_wraps_explanations_and_names_the_blueprint() {
    let dir = Scratch::new("explain-json");
    std::fs::write(dir.path().join("bp.toml"), MINIMAL_BLUEPRINT).unwrap();
    let out = formwork(
        dir.path(),
        dir.path(),
        &[
            "explain",
            "--blueprint",
            "bp.toml",
            "--json",
            "/opt/data/x",
            "/etc/hosts",
        ],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(value["blueprint"]["source"], "flag");
    let explanations = value["explanations"].as_array().unwrap();
    assert_eq!(explanations.len(), 2);
    assert_eq!(explanations[0]["read"]["decision"], "granted");
    assert_eq!(explanations[1]["read"]["decision"], "hidden");
}

#[test]
fn explain_human_names_rule_and_origin() {
    let dir = Scratch::new("explain-human");
    std::fs::write(dir.path().join("bp.toml"), MINIMAL_BLUEPRINT).unwrap();
    let out = formwork(
        dir.path(),
        dir.path(),
        &["explain", "--blueprint", "bp.toml", "/opt/data/x"],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.contains("blueprint: bp.toml (flag)"),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("granted by /opt/data/**"),
        "{}",
        out.stdout
    );
}

#[test]
fn explain_with_no_path_summarizes_host_and_fidelity() {
    let dir = Scratch::new("explain-summary");
    std::fs::write(dir.path().join("FORMWORK.toml"), MINIMAL_BLUEPRINT).unwrap();
    let out = formwork(dir.path(), dir.path(), &["explain"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("host: "), "{}", out.stdout);
    assert!(out.stdout.contains("capabilities:"), "{}", out.stdout);
    assert!(out.stdout.contains("credential floor:"), "{}", out.stdout);
    // The active backstop earns its own line in the summary, with the lift (FW-CRED6/CRED7).
    assert!(out.stdout.contains("backstop:"), "{}", out.stdout);
    assert!(
        out.stdout.contains("allow-credentials = [\"backstop\"]"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("(auto-discovered)"), "{}", out.stdout);
}

/// A file named `credentials` in a granted working set is denied by the backstop (deny beats
/// allow, FW-CAP8): `explain PATH` must name the exact shape and the lift, so the cause of the
/// confined tool's bare EACCES (FW-CRED7) is one command away.
#[test]
fn explain_backstop_denial_names_shape_and_lift() {
    let dir = Scratch::new("explain-backstop");
    std::fs::write(
        dir.path().join("bp.toml"),
        "net = \"deny\"\n[fs]\nread-mode = \"closed\"\nreads = [\"/**\"]\nwrites = [\"/**\"]\n",
    )
    .unwrap();
    let out = formwork(
        dir.path(),
        dir.path(),
        &["explain", "--blueprint", "bp.toml", "/srv/app/credentials"],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.contains("denied by credential floor (backstop)"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("**/credentials"), "{}", out.stdout);
    assert!(
        out.stdout.contains("allow-credentials = [\"backstop\"]"),
        "{}",
        out.stdout
    );

    // The path a user actually types when diagnosing the failure is relative -- it must resolve
    // against cwd, not error on "must be absolute".
    let rel = formwork(
        dir.path(),
        dir.path(),
        &["explain", "--blueprint", "bp.toml", "./credentials"],
    );
    assert_eq!(rel.code, 0, "{}", rel.stderr);
    assert!(
        rel.stdout.contains("denied by credential floor (backstop)"),
        "{}",
        rel.stdout
    );
}

#[test]
fn explain_without_any_blueprint_degrades_to_host_only() {
    let dir = Scratch::new("explain-host-only");
    let out = formwork(dir.path(), dir.path(), &["explain"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("host: "), "{}", out.stdout);
    assert!(
        out.stdout.contains("host capabilities only"),
        "{}",
        out.stdout
    );

    let json = formwork(dir.path(), dir.path(), &["explain", "--json"]);
    let value: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    assert!(value["host"]["os"].is_string(), "{}", json.stdout);
}

#[test]
fn hidden_detect_still_prints_the_host_profile() {
    let dir = Scratch::new("detect");
    let out = formwork(dir.path(), dir.path(), &["detect"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let profile: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert!(matches!(profile["os"].as_str(), Some("macos" | "linux")));
}

/// The listing half of FW-E2E-063 at the Rust boundary; the full review loop (accept by number /
/// pattern / all, floor refusal) is discharged by the py harness, the outermost boundary.
#[test]
fn learn_review_lists_candidates_on_stdout() {
    let dir = Scratch::new("learn-list");
    std::fs::write(
        dir.path().join("bp.toml.proposal.toml"),
        "blueprint = \"bp.toml\"\n\n[[candidates]]\npattern = \"/opt/toolchain/**\"\n\
         access = \"read\"\ntag = \"needs-review\"\nrun-id = \"learn-1\"\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("bp.toml"), MINIMAL_BLUEPRINT).unwrap();
    let out = formwork(
        dir.path(),
        dir.path(),
        &["learn", "--blueprint", "bp.toml", "--list"],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    // The listing is the RESULT: stdout, present even though nothing raised it to warn level.
    assert!(
        out.stdout.contains("1. /opt/toolchain/**"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("needs-review"), "{}", out.stdout);
}

#[test]
fn learn_rejects_mixing_review_flags_with_a_command() {
    let dir = Scratch::new("learn-mix");
    std::fs::write(dir.path().join("bp.toml"), MINIMAL_BLUEPRINT).unwrap();
    let out = formwork(
        dir.path(),
        dir.path(),
        &[
            "learn",
            "--blueprint",
            "bp.toml",
            "--list",
            "--",
            "/bin/true",
        ],
    );
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("not both"), "{}", out.stderr);
}

/// FW-E2E-064 at the cargo-test boundary, so the stock macOS CI job (`cargo test --workspace`)
/// verifies learn is useful for the canonical discovery shape: a workload that dies on its first
/// denial in about a millisecond, while the unified log persists the record only seconds later.
/// Runs against the real Seatbelt kernel and the real `log show` feed -- if a runner cannot
/// carry either, this fails loudly rather than letting CI imply learn works there.
#[cfg(target_os = "macos")]
#[test]
fn learn_captures_a_millisecond_workloads_denial() {
    let dir = Scratch::new("learn-ms");
    // Kernel-resolved root (macOS /var -> /private/var), so the blueprint grant and the
    // proposal's kernel-reported paths line up.
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let ok = root.join("ok.txt");
    std::fs::write(&ok, "ok\n").unwrap();
    let denied = root.join("denied.txt");
    std::fs::write(&denied, "nope\n").unwrap();
    std::fs::write(
        root.join("bp.toml"),
        format!(
            "net = \"deny\"\n[fs]\nread-mode = \"closed\"\nreads = [\"{}\"]\n",
            ok.display()
        ),
    )
    .unwrap();

    let out = formwork(
        &root,
        &root,
        &[
            "learn",
            "--blueprint",
            "bp.toml",
            "--",
            "/bin/cat",
            denied.to_str().unwrap(),
        ],
    );
    assert_ne!(
        out.code, 0,
        "cat of the denied file failing IS the scenario: {}",
        out.stderr
    );

    let proposal = root.join("bp.toml.proposal.toml");
    assert!(proposal.exists(), "no proposal written:\n{}", out.stderr);
    let text = std::fs::read_to_string(&proposal).unwrap();
    assert!(
        text.contains(denied.to_str().unwrap()),
        "millisecond denial lost to feed-persistence latency:\n{text}\n{}",
        out.stderr
    );
    // The proposal pointer is a stdout result (survives quiet telemetry), not a log line.
    assert!(out.stdout.contains("proposal:"), "{}", out.stdout);
}

/// FW-E2E-062 / FW-INV5 at the CLI edge: on a host with no denial feed, `learn` refuses BEFORE
/// the workload runs instead of running it and admitting afterwards that nothing could be
/// observed.
#[cfg(target_os = "linux")]
#[test]
fn learn_fails_fast_without_a_denial_feed() {
    let dir = Scratch::new("learn-fast");
    let marker = dir.path().join("ran");
    std::fs::write(dir.path().join("bp.toml"), MINIMAL_BLUEPRINT).unwrap();
    let out = formwork(
        dir.path(),
        dir.path(),
        &[
            "learn",
            "--blueprint",
            "bp.toml",
            "--",
            "/bin/touch",
            marker.to_str().unwrap(),
        ],
    );
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("denial feed"), "{}", out.stderr);
    assert!(out.stderr.contains("--observe-anyway"), "{}", out.stderr);
    assert!(!marker.exists(), "the workload must not have run");
}
