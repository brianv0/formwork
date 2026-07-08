//! Linux Landlock + seccomp backend. Allocation-heavy work (rule expansion, opening `PathFd`s,
//! compiling the BPF program) happens in the *parent*; the forked child's `pre_exec` closure only
//! issues syscalls (`NO_NEW_PRIVS` -> Landlock `restrict_self` -> seccomp filter), which is the order
//! the kernel requires and the only async-signal-safe shape. Confinement is inherited across `execve`
//! and by descendants (FW-XR4). Fail closed (FW-INV6): a promised mechanism that cannot install
//! aborts the spawn -- there is no unconfined-child path.

use std::io;
use std::os::unix::process::CommandExt;

use super::*;
use formwork_compile::{ConfinerPolicy, LinuxPolicy};

mod seccomp;

fn linux_policy(policy: &CompiledPolicy) -> Result<&LinuxPolicy, ConfineError> {
    match &policy.confiner {
        ConfinerPolicy::Linux(l) => Ok(l),
        ConfinerPolicy::Unavailable { reason } => Err(ConfineError::Unavailable(reason.clone())),
        ConfinerPolicy::Macos(_) => Err(ConfineError::MechanismFailed(
            "compiled a macOS policy but running on Linux; recompile against this host".into(),
        )),
    }
}

/// Finished, ready-to-apply artifacts. Owns everything the child needs so `apply` allocates nothing.
struct Plan {
    seccomp: seccompiler::BpfProgram,
    no_new_privs: bool,
}

fn build(policy: &LinuxPolicy) -> Result<Plan, ConfineError> {
    // Landlock carries filesystem scope and the net port tier; the compiler marks it expected by
    // setting `landlock_abi_target` from the host's ABI. Until that half lands, refuse such a policy
    // rather than run with the filesystem unconfined behind the report's back (FW-INV6).
    if policy.landlock_abi_target.is_some() {
        return Err(ConfineError::MechanismFailed(
            "Landlock backend not yet implemented; refusing to under-enforce a Landlock policy"
                .into(),
        ));
    }
    Ok(Plan {
        seccomp: seccomp::build(&policy.seccomp)?,
        no_new_privs: policy.no_new_privs || policy.seccomp.set_no_new_privs,
    })
}

/// Runs in the child (or in place for confine-self). Syscalls only.
fn apply(plan: &Plan) -> Result<(), ConfineError> {
    if plan.no_new_privs {
        set_no_new_privs()?;
    }
    seccomp::apply(&plan.seccomp)
}

fn set_no_new_privs() -> Result<(), ConfineError> {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes fixed scalar args and only sets a per-thread flag.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(ConfineError::MechanismFailed(format!(
            "prctl(NO_NEW_PRIVS) failed: {}",
            io::Error::last_os_error()
        )))
    }
}

pub fn spawn_confined(command: &mut Command, policy: &CompiledPolicy) -> Result<(), ConfineError> {
    let plan = build(linux_policy(policy)?)?;
    // SAFETY: the closure runs in the forked child before `execve`, issuing only syscalls over
    // artifacts built before the fork. On failure `spawn`/`status` fails -- no unconfined child.
    unsafe {
        command.pre_exec(move || {
            apply(&plan).map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))
        });
    }
    Ok(())
}

pub fn enforce_self(policy: &CompiledPolicy) -> Result<(), ConfineError> {
    let plan = build(linux_policy(policy)?)?;
    apply(&plan)
}
