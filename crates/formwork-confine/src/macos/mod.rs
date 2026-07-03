//! macOS Seatbelt backend: confinement via `sandbox_init(3)` -- the deprecated-but-load-bearing API
//! still under `sandbox-exec`, Chromium, and Bazel. spawn-confined installs the profile in the
//! forked child via `pre_exec` before `execve` (Seatbelt is inherited by descendants, FW-XR4);
//! confine-self installs it in place. If `sandbox_init` fails the operation fails -- no unconfined
//! child, no partial-apply path (FW-INV6).

use std::ffi::{CStr, CString};
use std::io;
use std::os::raw::{c_char, c_int};
use std::os::unix::process::CommandExt;
use std::ptr;

use super::*;
use formwork_compile::ConfinerPolicy;

// From <sandbox.h>, via libSystem. flags = 0 treats `profile` as a literal SBPL string to compile
// and apply (the path `sandbox-exec -p` and older Chromium use).
extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

fn sbpl_of(policy: &CompiledPolicy) -> Result<CString, ConfineError> {
    let sbpl = match &policy.confiner {
        ConfinerPolicy::Macos(m) => &m.sbpl,
        ConfinerPolicy::Unavailable { reason } => {
            return Err(ConfineError::Unavailable(reason.clone()))
        }
        ConfinerPolicy::Linux(_) => {
            return Err(ConfineError::MechanismFailed(
                "compiled a Linux policy but running on macOS; recompile against this host".into(),
            ))
        }
    };
    CString::new(sbpl.as_str())
        .map_err(|_| ConfineError::MechanismFailed("SBPL profile contained an interior NUL".into()))
}

/// `sandbox_init` allocates, so this runs only before `exec` in a freshly-forked child (not an
/// async-signal-safe context by accident), or synchronously for confine-self. Irreversible.
fn apply(profile: &CStr) -> Result<(), String> {
    let mut errbuf: *mut c_char = ptr::null_mut();
    // SAFETY: `profile` is a valid NUL-terminated C string and `errbuf` a valid out-pointer. On
    // failure `errbuf` points to a libsandbox-owned string, which we free below.
    let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &mut errbuf) };
    if rc == 0 {
        return Ok(());
    }
    let msg = if errbuf.is_null() {
        format!("sandbox_init failed (rc={rc})")
    } else {
        // SAFETY: on failure `errbuf` points to a NUL-terminated string owned by libsandbox.
        let s = unsafe { CStr::from_ptr(errbuf) }
            .to_string_lossy()
            .into_owned();
        unsafe { sandbox_free_error(errbuf) };
        s
    };
    Err(msg)
}

pub fn spawn_confined(command: &mut Command, policy: &CompiledPolicy) -> Result<(), ConfineError> {
    let profile = sbpl_of(policy)?;
    // SAFETY: the closure runs in the forked child before `exec`, calling only libsandbox over a
    // CString built before the fork. On failure `Command::status`/`spawn` fails -- no unconfined child.
    unsafe {
        command.pre_exec(move || {
            apply(&profile).map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))
        });
    }
    Ok(())
}

pub fn enforce_self(policy: &CompiledPolicy) -> Result<(), ConfineError> {
    let profile = sbpl_of(policy)?;
    apply(&profile).map_err(ConfineError::MechanismFailed)
}
