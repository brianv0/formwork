//! FW-E2E-010/011/012, confined "zero net" halves (design §7.3): the injected-fd transport works
//! while the child is confined under `net: Deny` -- the agent reaches its gateway with no in-sandbox
//! network and no dependence on a socket path (FW-XR7, FW-GW4/GW6). macOS Seatbelt; native only.
//! Also Phase-0 Spike 1: under `(deny network*)` a confined process can still read/write an
//! already-connected inherited socketpair, the property the whole seam design leans on.
#![cfg(target_os = "macos")]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use formwork_blueprint::ResolvedCatalog;
use formwork_blueprint::{Blueprint, FsBlueprint, NetPosture, PathPattern, ReadMode};
use formwork_compile::{Capability, CompiledPolicy};

/// Integration tests enforce what the product enforces: the builtin catalog for the real home.
fn compile(
    blueprint: &formwork_blueprint::Blueprint,
    host: &formwork_detect::HostProfile,
) -> CompiledPolicy {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    formwork_compile::compile(
        blueprint,
        host,
        &ResolvedCatalog::builtin_for_home(&home).unwrap(),
    )
}
use formwork_detect::detect;
use formwork_seam::{inject, SeamPlan};

/// Serialize the fork/exec-bearing seam tests. Each forks a confined child; on macOS `socketpair(2)`
/// has no atomic close-on-exec, so std sets CLOEXEC in a separate `fcntl` after creating the pair. A
/// concurrent fork in another test can catch a seam socket inside that window and leak it past
/// `execve`, intermittently breaking the minted round-trip ("connection closed before a full
/// response arrived"). Production spawns one child per process and never races here -- this is a
/// test-harness artifact, serialized so the tests stay deterministic (no flaky tests).
static SEAM_SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn pp(dir: &Path) -> PathPattern {
    PathPattern::parse(&format!("{}/**", dir.display())).unwrap()
}

/// Granted for read so the confined child can load its code.
fn helper_dir() -> PathBuf {
    common::helper_path().parent().unwrap().to_path_buf()
}

/// The only route to the "gateway" is the injected fd.
fn net_deny_policy(read_dirs: &[&Path]) -> CompiledPolicy {
    let reads = read_dirs.iter().map(|d| pp(d)).collect();
    let blueprint = Blueprint {
        fs: FsBlueprint {
            read_mode: ReadMode::Closed,
            reads,
            writes: vec![],
            subtract: vec![],
            write_subtract: vec![],
        },
        net: NetPosture::Deny,
        ..Blueprint::empty()
    };
    let policy = compile(&blueprint, &detect());
    assert!(
        policy.report.per_capability[&Capability::NetDefaultDeny].is_enforced(),
        "test premise: net-default-deny must be enforced on this host"
    );
    policy
}

/// FW-E2E-010: MCP-over-injected-fd with zero net. The confined child completes a full round-trip
/// over a pre-opened inherited fd and, in the same run, proves a direct connect is denied.
#[test]
fn fw_e2e_010_mcp_over_injected_fd_zero_net() {
    let _serial = SEAM_SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = helper_dir();
    let policy = net_deny_policy(&[&dir]);

    let mut cmd = Command::new(common::helper_path());
    cmd.arg("preopen")
        .arg("gateway")
        .arg("initialize")
        .arg("--assert-net-denied");
    cmd.stdout(Stdio::null()).stderr(Stdio::inherit());

    // inject's dup2 hook runs first (places the fd), then Seatbelt, then execve.
    let seam = inject(&mut cmd, &SeamPlan::new().preopen("gateway")).unwrap();
    formwork_confine::spawn_confined(&mut cmd, &policy).unwrap();
    let (mut child, mut host) = seam.spawn(&mut cmd).unwrap();

    let mut gw = host.take_connection("gateway").unwrap();
    let served = common::serve_ok(&mut gw);

    let code = child.wait().unwrap().code();
    assert_eq!(
        code,
        Some(0),
        "exchange completed over the injected fd with zero in-sandbox network \
         (exit 4 = egress leak, exit 3 = seam failure)"
    );
    assert_eq!(served.unwrap(), "initialize");
}

/// FW-E2E-011: fd minting via SCM_RIGHTS under net=Deny. The confined child mints over CONTROL and
/// uses the passed fd; no in-sandbox `connect()`, and net-deny is never relaxed.
#[test]
fn fw_e2e_011_fd_minting_via_scm_rights() {
    let _serial = SEAM_SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = helper_dir();
    let policy = net_deny_policy(&[&dir]);

    let mut cmd = Command::new(common::helper_path());
    cmd.arg("mint")
        .arg("backend")
        .arg("call")
        .arg("--assert-net-denied");
    cmd.stdout(Stdio::null()).stderr(Stdio::inherit());

    let seam = inject(&mut cmd, &SeamPlan::new().with_control()).unwrap();
    formwork_confine::spawn_confined(&mut cmd, &policy).unwrap();
    let (mut child, mut host) = seam.spawn(&mut cmd).unwrap();

    let minted = host
        .accept_mint()
        .expect("read + fulfill the mint request")
        .expect("child issued a mint request over CONTROL");
    assert_eq!(minted.name, "backend");
    let mut backend = minted.parent_end;
    let served = common::serve_ok(&mut backend);

    let code = child.wait().unwrap().code();
    assert_eq!(
        code,
        Some(0),
        "child used the SCM_RIGHTS-passed fd; net-deny untouched"
    );
    assert_eq!(served.unwrap(), "call");
}

/// FW-E2E-012: no dependence on socket-path gating. The confined workload runs twice -- socket-path
/// dir granted, then denied -- and succeeds identically, because the transport is the injected fd.
#[test]
fn fw_e2e_012_no_dependence_on_socket_path_gating() {
    let _serial = SEAM_SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = helper_dir();

    // A real pathname UNIX socket exists on disk; the workload never references it. It is here only
    // so "grant vs deny its path" is a meaningful, observable variable.
    let sock_path =
        std::env::temp_dir().join(format!("formwork-seam-e2e012c-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    let sock_dir = std::fs::canonicalize(sock_path.parent().unwrap()).unwrap();

    let code_granted = run_confined_preopen(&net_deny_policy(&[&dir, &sock_dir]));
    let code_denied = run_confined_preopen(&net_deny_policy(&[&dir]));

    drop(listener);
    let _ = std::fs::remove_file(&sock_path);

    assert_eq!(code_granted, Some(0), "granted-path run succeeds");
    assert_eq!(code_denied, Some(0), "denied-path run succeeds identically");
    assert_eq!(
        code_granted, code_denied,
        "granting vs denying the socket PATH is irrelevant: the transport is the inherited fd"
    );
}

fn run_confined_preopen(policy: &CompiledPolicy) -> Option<i32> {
    let mut cmd = Command::new(common::helper_path());
    cmd.arg("preopen")
        .arg("gateway")
        .arg("workload")
        .arg("--assert-net-denied");
    cmd.stdout(Stdio::null()).stderr(Stdio::inherit());

    let seam = inject(&mut cmd, &SeamPlan::new().preopen("gateway")).unwrap();
    formwork_confine::spawn_confined(&mut cmd, policy).unwrap();
    let (mut child, mut host) = seam.spawn(&mut cmd).unwrap();

    let mut gw = host.take_connection("gateway").unwrap();
    let _ = common::serve_ok(&mut gw);
    child.wait().unwrap().code()
}
