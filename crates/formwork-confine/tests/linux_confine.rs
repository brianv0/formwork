//! Phase 2 Linux backend tests -- native, Linux only, run against a real kernel (Docker/Lima with
//! Docker's own seccomp/AppArmor disabled, so only Formwork's sandbox is under test). Paired
//! allow/deny probes at the real boundary (FW-INV5): egress is denied *and* an ordinary toolchain
//! still runs. The filesystem (Landlock) half is added in Cut 2; this covers the seccomp baseline and
//! net default-deny, which a pre-Landlock kernel (ABI absent) carries on its own.

#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};

use formwork_blueprint::Blueprint;
use formwork_compile::{compile, CompiledPolicy, ConfinerPolicy};
use formwork_detect::detect;

/// The default (net-deny) blueprint compiled against the *real* host.
fn confined_default() -> CompiledPolicy {
    compile(&Blueprint::empty(), &detect())
}

fn quiet(cmd: &mut Command) {
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
}

fn run(policy: &CompiledPolicy, mut cmd: Command) -> i32 {
    quiet(&mut cmd);
    formwork_confine::spawn_confined(&mut cmd, policy).expect("confinement applies");
    cmd.status().expect("child runs").code().unwrap_or(-1)
}

/// FW-E2E-002 (Linux): a confined process cannot reach the network. On a pre-Landlock kernel this is
/// carried by seccomp denying inet `socket(2)`; the probe surfaces the EPERM as exit 7.
#[test]
fn net_default_deny_blocks_egress() {
    let policy = confined_default();
    let cmd = Command::new(env!("CARGO_BIN_EXE_fw-connect-probe"));
    let code = run(&policy, cmd);
    assert_eq!(
        code, 7,
        "egress must be denied with EPERM (exit 7); got {code}"
    );
}

/// FW-TRA2 (Linux): the deny-list baseline is transparent. A shell that forks and execs a child runs
/// clean -- exercising clone/clone3 + execve under the filter, which the userns rule must not break.
#[test]
fn baseline_is_transparent_to_fork_and_exec() {
    let policy = confined_default();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg("/bin/echo hi | /bin/cat >/dev/null");
    assert_eq!(
        run(&policy, cmd),
        0,
        "an ordinary fork+exec pipeline must run"
    );
}

/// FW-ADV (Linux): a confinement-shedding syscall from the baseline is denied. `unshare -U` asks for
/// a new user namespace (CLONE_NEWUSER); the seccomp rule must reject it (nonzero exit).
#[test]
fn baseline_denies_new_user_namespace() {
    // Skip cleanly if util-linux `unshare` isn't installed, rather than fail for the wrong reason.
    if !std::path::Path::new("/usr/bin/unshare").exists() {
        eprintln!("skipping: /usr/bin/unshare not present");
        return;
    }
    let policy = confined_default();
    let mut cmd = Command::new("/usr/bin/unshare");
    cmd.arg("--user").arg("/bin/true");
    assert_ne!(
        run(&policy, cmd),
        0,
        "unshare(CLONE_NEWUSER) must be denied by the seccomp baseline"
    );
}

/// Sanity: on a host without Landlock the compiled net plan really is the seccomp path, so the
/// deny above is exercising seccomp (not accidentally a no-op). Fails loud if the assumption breaks.
#[test]
fn host_without_landlock_uses_seccomp_net_deny() {
    let host = detect();
    if host.landlock_abi.is_some() {
        eprintln!(
            "host has Landlock ABI {:?}; seccomp-net-deny assumption N/A",
            host.landlock_abi
        );
        return;
    }
    match confined_default().confiner {
        ConfinerPolicy::Linux(l) => assert!(
            matches!(l.net, formwork_compile::LinuxNetPlan::SeccompDenyInet),
            "pre-Landlock host must carry net-deny via seccomp"
        ),
        other => panic!("expected a Linux confiner, got {other:?}"),
    }
}
