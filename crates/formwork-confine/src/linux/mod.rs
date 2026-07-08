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

mod landlock;
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
/// `landlock` is `None` when the host carries no ABI (the seccomp half then does what it can).
struct Plan {
    landlock: Option<landlock::Built>,
    seccomp: seccompiler::BpfProgram,
    no_new_privs: bool,
}

fn build(policy: &LinuxPolicy) -> Result<Plan, ConfineError> {
    Ok(Plan {
        landlock: landlock::build(policy)?,
        seccomp: seccomp::build(&policy.seccomp)?,
        no_new_privs: policy.no_new_privs || policy.seccomp.set_no_new_privs,
    })
}

/// Runs in the child (or in place for confine-self). Syscalls only, allocation-free on the success
/// path (the allocator may be poisoned post-`fork`), so it returns raw OS errors. Order is
/// kernel-required: `NO_NEW_PRIVS` first, then Landlock `restrict_self`, then the seccomp filter.
fn apply(plan: &mut Plan) -> io::Result<()> {
    if plan.no_new_privs {
        // SAFETY: PR_SET_NO_NEW_PRIVS takes fixed scalar args and only sets a per-thread flag.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if let Some(built) = plan.landlock.take() {
        landlock::apply(built)?;
    }
    seccomp::apply(&plan.seccomp)
}

pub fn spawn_confined(command: &mut Command, policy: &CompiledPolicy) -> Result<(), ConfineError> {
    let mut plan = build(linux_policy(policy)?)?;
    // SAFETY: the closure runs in the forked child before `execve`, issuing only syscalls over
    // artifacts built before the fork (allocation-free). On failure `spawn`/`status` fails -- there is
    // no unconfined child (FW-INV6).
    unsafe {
        command.pre_exec(move || apply(&mut plan));
    }
    Ok(())
}

pub fn enforce_self(policy: &CompiledPolicy) -> Result<(), ConfineError> {
    let mut plan = build(linux_policy(policy)?)?;
    // In-process (not forked): a formatted error is fine here.
    apply(&mut plan).map_err(|e| ConfineError::MechanismFailed(format!("confine-self failed: {e}")))
}
