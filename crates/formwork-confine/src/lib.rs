//! The confiner: turns a compiled [`ConfinerPolicy`] into kernel-enforced confinement of a process
//! and all its descendants (FW-XR4). Two postures (FW-ISO6): spawn-confined (a launcher confines a
//! child between fork and exec; preferred) and confine-self (a process restricts itself in place).
//! Backends are selected at compile time: Landlock+seccomp on Linux, Seatbelt on macOS. Honesty
//! (FW-INV6): if a promised mechanism fails to install, this aborts rather than running weakly.
//!
//! Requirement IDs (`FW-…`) cite `formwork.md`, the design + E2E spec at the repo root.

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
