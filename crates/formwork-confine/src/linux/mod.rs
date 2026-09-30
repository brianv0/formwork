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

pub mod isolate;
mod landlock;
mod seccomp;
pub mod supervise;

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
    /// The supervised-connect filter and listener handoff (FW-EGR7), when the policy needs it.
    supervise: Option<supervise::Plan>,
}

fn build(policy: &LinuxPolicy) -> Result<Plan, ConfineError> {
    Ok(Plan {
        landlock: landlock::build(policy)?,
        seccomp: seccomp::build(&policy.seccomp)?,
        no_new_privs: policy.no_new_privs || policy.seccomp.set_no_new_privs,
        supervise: None,
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
    seccomp::apply(&plan.seccomp)?;
    if let Some(sup) = &plan.supervise {
        supervise::install(sup)?;
    }
    Ok(())
}

pub fn spawn_confined(command: &mut Command, policy: &CompiledPolicy) -> Result<(), ConfineError> {
    let linux = linux_policy(policy)?;
    if linux.seccomp.supervise_connect {
        // FW-INV6: host-scoped egress without its supervisor would be a child whose every connect
        // hangs on a listener nobody reads; refuse rather than spawn it.
        return Err(ConfineError::MechanismFailed(
            "this policy routes egress through the connect supervisor; spawn it with \
             spawn_confined_supervised"
                .into(),
        ));
    }
    let mut plan = build(linux)?;
    // SAFETY: the closure runs in the forked child before `execve`, issuing only syscalls over
    // artifacts built before the fork (allocation-free). On failure `spawn`/`status` fails -- there is
    // no unconfined child (FW-INV6).
    unsafe {
        command.pre_exec(move || apply(&mut plan));
    }
    Ok(())
}

/// As [`spawn_confined`], plus the connect supervisor when the policy needs one (FW-EGR7). The
/// returned half is started, after the spawn, with [`supervise::Pending::start`].
pub fn spawn_confined_supervised(
    command: &mut Command,
    policy: &CompiledPolicy,
) -> Result<Option<supervise::Pending>, ConfineError> {
    let linux = linux_policy(policy)?;
    let mut plan = build(linux)?;
    let pending = if linux.seccomp.supervise_connect {
        let (sup, pending) = supervise::prepare()?;
        plan.supervise = Some(sup);
        Some(pending)
    } else {
        None
    };
    // SAFETY: as in `spawn_confined`; the supervisor half issues only seccomp(2), sendmsg(2) and
    // close(2) over descriptors and a filter built before the fork.
    unsafe {
        command.pre_exec(move || apply(&mut plan));
    }
    Ok(pending)
}

/// The isolation tier (FW-ISO10): configure `command` -- `Command::new("/proc/self/exe")` with
/// the workload's environment applied -- as the isolation stage for `argv`. The binary must call
/// [`isolate::stage_if_requested`] first thing in `main`.
pub fn spawn_isolated(
    command: &mut Command,
    argv: &[String],
    policy: &CompiledPolicy,
    private_tmp: Option<&std::path::Path>,
) -> Result<Option<supervise::Pending>, ConfineError> {
    let linux = linux_policy(policy)?;
    if linux.isolate.is_empty() {
        return Err(ConfineError::MechanismFailed(
            "spawn_isolated needs a policy with an isolate member".into(),
        ));
    }
    isolate::configure(command, argv, linux, private_tmp)
}

pub fn enforce_self(policy: &CompiledPolicy) -> Result<(), ConfineError> {
    let linux = linux_policy(policy)?;
    if linux.seccomp.supervise_connect {
        // FEP-5 §3.1: no process outside the sandbox remains to supervise a confine-self session.
        return Err(ConfineError::MechanismFailed(
            "host-scoped egress needs a supervisor outside the sandbox; confine-self has none -- \
             use the spawn posture"
                .into(),
        ));
    }
    let mut plan = build(linux)?;
    // In-process (not forked): a formatted error is fine here.
    apply(&mut plan).map_err(|e| ConfineError::MechanismFailed(format!("confine-self failed: {e}")))
}
