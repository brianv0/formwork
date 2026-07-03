//! Cross-platform (any Unix) fd-seam transport tests: `inject` -> round-trip, and on-demand
//! `SCM_RIGHTS` minting -- without confinement, so they run on Linux and macOS alike. The confined
//! "zero net" halves live in `seam_confined.rs` (macOS-native).
#![cfg(unix)]

mod common;

use std::process::{Command, Stdio};

use formwork_seam::{inject, SeamPlan};

/// FW-E2E-010 (transport half): a full round-trip over a pre-opened inherited fd; no `connect()`.
#[test]
fn fw_e2e_010_roundtrip_over_preopened_fd() {
    let mut cmd = Command::new(common::helper_path());
    cmd.arg("preopen").arg("gateway").arg("hello");
    cmd.stdout(Stdio::null()).stderr(Stdio::inherit());

    let seam = inject(&mut cmd, &SeamPlan::new().preopen("gateway")).unwrap();
    let (mut child, mut host) = seam.spawn(&mut cmd).unwrap();

    let mut gw = host
        .take_connection("gateway")
        .expect("gateway connection was pre-opened");
    let served = common::serve_ok(&mut gw);

    let code = child.wait().unwrap().code();
    assert_eq!(code, Some(0), "child completed the exchange over the injected fd");
    assert_eq!(served.unwrap(), "hello");
}

/// FW-E2E-011 (transport half): child requests a connection over CONTROL; the launcher mints a fresh
/// connected fd and passes it via `SCM_RIGHTS`; the child uses it. No in-sandbox `connect()`.
#[test]
fn fw_e2e_011_mint_via_scm_rights() {
    let mut cmd = Command::new(common::helper_path());
    cmd.arg("mint").arg("backend").arg("ping");
    cmd.stdout(Stdio::null()).stderr(Stdio::inherit());

    let seam = inject(&mut cmd, &SeamPlan::new().with_control()).unwrap();
    let (mut child, mut host) = seam.spawn(&mut cmd).unwrap();

    let minted = host
        .accept_mint()
        .expect("read + fulfill mint request")
        .expect("child issued a mint request");
    assert_eq!(minted.name, "backend");
    let mut backend = minted.parent_end;
    let served = common::serve_ok(&mut backend);

    let code = child.wait().unwrap().code();
    assert_eq!(code, Some(0), "child used the SCM_RIGHTS-passed fd for a full round-trip");
    assert_eq!(served.unwrap(), "ping");
}

/// FW-E2E-012 (transport half): a pathname UNIX socket sits on disk but is never referenced; the
/// transport is the inherited socketpair, which has no filesystem name.
#[test]
fn fw_e2e_012_transport_uses_no_socket_path() {
    let sock_path =
        std::env::temp_dir().join(format!("formwork-seam-e2e012-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

    let mut cmd = Command::new(common::helper_path());
    cmd.arg("preopen").arg("gateway").arg("payload");
    cmd.stdout(Stdio::null()).stderr(Stdio::inherit());

    let seam = inject(&mut cmd, &SeamPlan::new().preopen("gateway")).unwrap();
    let (mut child, mut host) = seam.spawn(&mut cmd).unwrap();
    let mut gw = host.take_connection("gateway").unwrap();
    let served = common::serve_ok(&mut gw);
    let code = child.wait().unwrap().code();

    drop(listener);
    let _ = std::fs::remove_file(&sock_path);

    assert_eq!(code, Some(0), "workload succeeds regardless of the on-disk socket");
    assert_eq!(served.unwrap(), "payload");
}

/// Fail-closed: a child spawned without the seam finds no `FORMWORK_FD_*` and errors honestly.
#[test]
fn missing_seam_env_fails_honestly() {
    let mut cmd = Command::new(common::helper_path());
    cmd.arg("preopen").arg("gateway").arg("hello");
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let status = cmd.status().unwrap();
    assert_eq!(
        status.code(),
        Some(3),
        "child must fail (not hang, not succeed) when the seam fd is absent"
    );
}
