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
    std::fs::write(dir.join("FORMWORK.toml"), formwork_toml).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_formwork"))
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
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

#[test]
fn run_names_the_backstop_on_the_operator_channel() {
    let dir = scratch("backstop-channel");
    let stderr = run_stderr(
        &dir,
        "extends = [\"builtin:default\"]\nnet = \"deny\"\n",
        &["run", "--", "/bin/true"],
    );
    // The cause a confined tool's bare EACCES hides (FW-CRED7): named, with the `explain` pointer.
    assert!(
        stderr.contains("credential backstop active"),
        "operator channel must name the active backstop:\n{stderr}"
    );
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
        !stderr.contains("credential backstop active"),
        "a lifted backstop must not be announced as active:\n{stderr}"
    );
    // ...while the rest of the credential floor is still itemized, now recording the exclusion.
    assert!(
        stderr.contains("credential floor active"),
        "the floor summary stays even with the backstop lifted:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
