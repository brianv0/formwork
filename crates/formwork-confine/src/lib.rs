//! The confiner: turns a compiled [`ConfinerPolicy`] into kernel-enforced confinement of a process
//! and all its descendants (FW-XR4). Two postures (FW-ISO6): spawn-confined (a launcher confines a
//! child between fork and exec; preferred) and confine-self (a process restricts itself in place).
//! Backends are selected at compile time: Landlock+seccomp on Linux, Seatbelt on macOS. Honesty
//! (FW-INV6): if a promised mechanism fails to install, this aborts rather than running weakly.

use std::process::Command;

use formwork_compile::{CompiledPolicy, ConfinerPolicy};

/// The mechanism a compiled policy will enforce with, for telemetry. Not the fidelity -- that is the
/// compiler's returned report (`formwork compile --report-only`), not something this layer re-derives.
fn backend_label(policy: &CompiledPolicy) -> &'static str {
    match policy.confiner {
        ConfinerPolicy::Macos(_) => "seatbelt",
        ConfinerPolicy::Linux(_) => "landlock+seccomp",
        ConfinerPolicy::Unavailable { .. } => "none",
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfineError {
    #[error("no usable confiner on this host: {0}")]
    Unavailable(String),
    #[error("a mechanism promised by the fidelity report failed to install: {0}")]
    MechanismFailed(String),
    #[error("this platform backend is not yet implemented")]
    Unimplemented,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Configures `command` (does not spawn). Fails closed (FW-INV6): if a report-`Enforced` capability
/// can't install here, returns `Err` rather than yielding a running-but-unconfined child.
pub fn spawn_confined(command: &mut Command, policy: &CompiledPolicy) -> Result<(), ConfineError> {
    tracing::info!(
        posture = "spawn",
        backend = backend_label(policy),
        "configuring confinement"
    );
    backend::spawn_confined(command, policy)
}

/// Let `fd` survive into `command`'s exec: `FD_CLOEXEC` is cleared in the child after the fork.
/// The descriptor moves into the command, so an owned one stays open until the command is
/// dropped; the caller keeps a raw one open until the spawn.
#[cfg(unix)]
pub fn inherit_fd<F>(command: &mut Command, fd: F)
where
    F: std::os::fd::AsRawFd + Send + Sync + 'static,
{
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure runs post-fork and issues only fcntl(2) on a descriptor that is open in
    // the parent until the spawn.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// FW-CRED16: while this process holds brokered credentials, no same-uid process may read its
/// memory or environment. Linux: not dumpable, so `/proc/<pid>/mem`, `environ` and `ptrace` need
/// `CAP_SYS_PTRACE` whatever Yama and Landlock decide; `execve` resets the flag, so a spawned
/// workload is unaffected. macOS: debugger attachment denied. Call before the workload is spawned.
pub fn deny_inspection_of_self() -> Result<(), ConfineError> {
    #[cfg(target_os = "linux")]
    // SAFETY: prctl(PR_SET_DUMPABLE) takes integer arguments and touches no memory of ours.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    #[cfg(target_os = "macos")]
    // SAFETY: ptrace(PT_DENY_ATTACH) on the calling process takes no pointers it dereferences.
    let rc = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let rc = -1;
    if rc != 0 {
        return Err(ConfineError::MechanismFailed(format!(
            "denying inspection of the Gateway's memory (FW-CRED16): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// The egress listener's peer-process check (FW-EGR9 on macOS).
#[cfg(target_os = "macos")]
pub use backend::peer::{carries_marker, held_sockets, session_holds_connection, HeldSocket};

/// FW-CRED16 / FW-ISO16 on macOS: conceal `formwork`'s own exec-time environment.
#[cfg(target_os = "macos")]
pub use backend::conceal_environment;

/// The connect supervisor's configuration and handles (FW-EGR7); Linux only.
#[cfg(target_os = "linux")]
pub use backend::supervise::{Pending as PendingSupervisor, SupervisorConfig};

/// As [`spawn_confined`], and when the policy routes egress through the connect supervisor
/// (FW-EGR7), also prepares it: start the returned half after spawning, with the Gateway endpoint.
/// `None` means the policy needs no supervisor (every macOS policy, and Linux without host rules).
#[cfg(target_os = "linux")]
pub fn spawn_confined_supervised(
    command: &mut Command,
    policy: &CompiledPolicy,
) -> Result<Option<PendingSupervisor>, ConfineError> {
    tracing::info!(
        posture = "spawn",
        backend = backend_label(policy),
        "configuring confinement"
    );
    backend::spawn_confined_supervised(command, policy)
}

/// The isolation tier (FW-ISO10): `command` is `Command::new("/proc/self/exe")` with the
/// workload's environment applied; it becomes the single-threaded stage that creates the
/// namespaces, then confines and execs `argv`. Start the returned supervisor half after spawning.
#[cfg(target_os = "linux")]
pub fn spawn_isolated(
    command: &mut Command,
    argv: &[String],
    policy: &CompiledPolicy,
    private_tmp: Option<&std::path::Path>,
) -> Result<Option<PendingSupervisor>, ConfineError> {
    tracing::info!(
        posture = "spawn",
        backend = backend_label(policy),
        "configuring confinement with the isolation tier"
    );
    backend::spawn_isolated(command, argv, policy, private_tmp)
}

/// The isolation stage's entry point; see [`spawn_isolated`]. Call first thing in `main`.
#[cfg(target_os = "linux")]
pub use backend::isolate::stage_if_requested as isolation_stage;

/// Why a confined program failed to exec, when the Linux exec allow-list is the cause (FW-ISO4),
/// and the dynamic loaders the confiner grants beside an allow-list.
#[cfg(target_os = "linux")]
pub use backend::loader::{exec_denial_hint, granted_loaders};

/// Irreversible; confine-self posture (FW-ISO6).
pub fn enforce_self(policy: &CompiledPolicy) -> Result<(), ConfineError> {
    tracing::info!(
        posture = "self",
        backend = backend_label(policy),
        "configuring confinement"
    );
    backend::enforce_self(policy)
}

#[cfg(target_os = "macos")]
#[path = "macos/mod.rs"]
mod backend;

#[cfg(target_os = "linux")]
#[path = "linux/mod.rs"]
mod backend;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod backend {
    use super::*;
    pub fn spawn_confined(_c: &mut Command, _p: &CompiledPolicy) -> Result<(), ConfineError> {
        Err(ConfineError::Unimplemented)
    }
    pub fn enforce_self(_p: &CompiledPolicy) -> Result<(), ConfineError> {
        Err(ConfineError::Unimplemented)
    }
}
