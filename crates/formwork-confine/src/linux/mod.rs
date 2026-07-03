//! Linux Landlock + seccomp backend -- Phase 2, not yet implemented. An honest fail-closed stub: it
//! returns `Unimplemented` rather than running a process weakly-or-un-confined. Formwork must not
//! present kernel enforcement it has never verified against a kernel (FW-XR1, FW-INV5); the full
//! design (Landlock/seccomp APIs, subtractive expansion, clone3/netlink hazards) is in
//! docs/linux-backend.md.

use super::*;

pub fn spawn_confined(
    _command: &mut Command,
    _policy: &CompiledPolicy,
) -> Result<(), ConfineError> {
    Err(ConfineError::Unimplemented)
}

pub fn enforce_self(_policy: &CompiledPolicy) -> Result<(), ConfineError> {
    Err(ConfineError::Unimplemented)
}
