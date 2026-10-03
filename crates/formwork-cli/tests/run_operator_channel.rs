//! Black-box tests that `formwork run` actually emits the credential floor's operator channel
//! (FW-CRED7). Unlike `cli_surface.rs` these drive the real `run` path, but they assert only the
//! itemization `run` logs in `prepare_session` *before* the confiner is applied -- so they need no
//! working backend and pass on any host (the workload need not even exist).

use std::path::Path;
use std::process::Command;

/// Run the built `formwork` with cwd and $HOME pinned to `dir`, returning combined stderr. The
/// exit status is deliberately ignored: the operator line under test is written before the
/// confiner/exec, so a host without a backend (or a missing workload) still carries it.
fn run_stderr(dir: &Path, formwork_toml: &str, args: &[&str]) -> String {
    run_stderr_at(dir, formwork_toml, args, "info")
}

fn run_stderr_at(dir: &Path, formwork_toml: &str, args: &[&str], level: &str) -> String {
    std::fs::write(dir.join("FORMWORK.toml"), formwork_toml).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_formwork"))
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("RUST_LOG", level)
        .output()
        .expect("running formwork");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("formwork-run-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

/// This host's credential report, from the same blueprint `run` would load.
fn credentials_report(dir: &Path) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_formwork"))
        .args(["explain", "--json"])
        .current_dir(dir)
        .env("HOME", dir)
        .output()
        .expect("running formwork");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    value["report"]["credentials"].clone()
}

/// This host's verdict on the backstop.
fn backstop_status(dir: &Path) -> Option<String> {
    credentials_report(dir)["backstop"]["status"]
        .as_str()
        .map(str::to_string)
}

#[test]
fn run_names_the_backstop_on_the_operator_channel() {
    let dir = scratch("backstop-channel");
    let stderr = run_stderr(
        &dir,
        "extends = [\"builtin:default\"]\nnet = \"deny\"\n",
        &["run", "--", "/bin/true"],
    );
    // The cause a confined tool's bare EACCES hides (FW-CRED7): named, with the `explain` pointer.
    // Where the host withholds the backstop (Landlock, FW-CRED9) there is no EACCES, and the line
    // says so instead of claiming the denial (FW-INV5).
    match backstop_status(&dir).as_deref() {
        Some("enforced") => assert!(
            stderr.contains("credential backstop active"),
            "operator channel must name the active backstop:\n{stderr}"
        ),
        Some(status) => {
            assert!(
                stderr.contains("credential backstop not enforced on this host"),
                "operator channel must say the backstop is not enforced:\n{stderr}"
            );
            assert!(stderr.contains(status), "{stderr}");
            assert!(!stderr.contains("credential backstop active"), "{stderr}");
        }
        None => panic!("the backstop is not lifted here"),
    }
    assert!(
        stderr.contains("formwork explain"),
        "the callout must point at `formwork explain`:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lifting_the_backstop_silences_the_callout_but_not_the_floor() {
    let dir = scratch("backstop-lifted");
    let stderr = run_stderr(
        &dir,
        "extends = [\"builtin:default\"]\nnet = \"deny\"\nallow-credentials = [\"backstop\"]\n",
        &["run", "--", "/bin/true"],
    );
    // Lifted by name -> no callout (telling a user how to lift what they already lifted is noise)...
    assert!(
        !stderr.contains("credential backstop"),
        "a lifted backstop must not be announced:\n{stderr}"
    );
    // ...while the rest of the credential floor is still itemized, now recording the exclusion.
    assert!(
        stderr.contains("credential floor active"),
        "the floor summary stays even with the backstop lifted:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The debug itemization's `denied_path_types` is what this host denies: a type the report marks
/// Partial (Landlock withholds its any-depth rows, FW-CRED9) or Unenforceable is itemized under
/// its own verdict, never as denied (FW-INV5).
#[test]
fn debug_itemization_lists_only_enforced_types_as_denied() {
    let dir = scratch("itemized");
    let stderr = run_stderr_at(
        &dir,
        "extends = [\"builtin:default\"]\nnet = \"deny\"\n",
        &["run", "--", "/bin/true"],
        "debug",
    );
    let field = |name: &str| -> Vec<String> {
        let line = stderr
            .lines()
            .find(|l| l.contains("credential catalog floor, itemized"))
            .unwrap_or_else(|| panic!("no itemization:\n{stderr}"));
        let start = line
            .find(&format!(" {name}=["))
            .unwrap_or_else(|| panic!("no {name}: {line}"))
            + name.len()
            + 3;
        let end = start + line[start..].find(']').unwrap();
        line[start..end]
            .split(", ")
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_matches('"').to_string())
            .collect()
    };
    let listed = [
        ("enforced", field("denied_path_types")),
        ("partial", field("partial_path_types")),
        ("unenforceable", field("unenforceable_path_types")),
    ];
    let report = credentials_report(&dir);
    for (name, t) in report["per-type"].as_object().unwrap() {
        let Some(status) = t["path"]["status"].as_str() else {
            continue;
        };
        for (verdict, names) in &listed {
            assert_eq!(
                names.contains(name),
                *verdict == status,
                "{name} is {status}: {listed:?}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
