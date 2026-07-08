//! The seccomp baseline (FW-ISO8): a *deny-list* BPF filter. Default action is `Allow` so an ordinary
//! toolchain is never tripped by a forgotten syscall (FW-TRA2); a small fixed set of
//! escalation/confinement-shedding syscalls, and (below Landlock net ABI) inet `socket(2)` creation,
//! return `EPERM`. Built in the parent; `apply()` runs in the forked child after `NO_NEW_PRIVS`.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};

use formwork_compile::{SeccompPlan, SocketFamily};

use super::ConfineError;

fn fail(msg: impl Into<String>) -> ConfineError {
    ConfineError::MechanismFailed(msg.into())
}

/// Compile the plan into a BPF program (allocation happens here, in the parent).
pub fn build(plan: &SeccompPlan) -> Result<BpfProgram, ConfineError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Unconditional escalation/shedding denies. An unresolved syscall number would silently weaken
    // the baseline, so refuse to install rather than skip it (FW-INV6).
    for name in &plan.deny_syscalls {
        let nr = syscall_number(name)
            .ok_or_else(|| fail(format!("seccomp baseline syscall {name:?} has no number on this arch; refusing a silently-weakened filter")))?;
        rules.entry(nr).or_default(); // empty rule vec == unconditional match -> EPERM
    }

    // Net default-deny below the Landlock net ABI: block inet/inet6/packet/non-route-netlink
    // socket(2). AF_UNIX and socketpair are absent -> allowed, so the injected-fd seam is untouched
    // (FW-XR7). All are conditions on socket()'s domain (arg0), unioned as separate rules (OR).
    if !plan.deny_socket_families.is_empty() {
        let mut socket_rules = Vec::new();
        for fam in &plan.deny_socket_families {
            socket_rules.extend(socket_family_rules(*fam)?);
        }
        rules
            .entry(libc::SYS_socket)
            .or_default()
            .extend(socket_rules);
    }

    // User-namespace restriction: deny unshare()/clone() carrying CLONE_NEWUSER, which would let the
    // process regain capabilities inside a fresh userns. clone3()'s flags sit behind a pointer that
    // seccomp cannot read; that gap is covered by the mount/setns denies above (a userns without
    // mount or setns cannot be used to escape). See docs/linux-backend.md.
    if plan.restrict_userns {
        let newuser = libc::CLONE_NEWUSER as u64;
        rules
            .entry(libc::SYS_unshare)
            .or_default()
            .push(masked_flag_rule(0, newuser)?);
        // clone(2) takes flags in arg0 on x86_64 and aarch64 (the only arches built here).
        rules
            .entry(libc::SYS_clone)
            .or_default()
            .push(masked_flag_rule(0, newuser)?);
    }

    let arch = std::env::consts::ARCH.try_into().map_err(|_| {
        fail(format!(
            "seccomp: unsupported arch {}",
            std::env::consts::ARCH
        ))
    })?;
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow, // default: let everything else through
        SeccompAction::Errno(libc::EPERM as u32), // a listed syscall/condition -> EPERM
        arch,
    )
    .map_err(|e| fail(format!("seccomp filter build: {e}")))?;

    filter
        .try_into()
        .map_err(|e| fail(format!("seccomp bpf compile: {e}")))
}

/// Install the filter on the calling thread. Async-signal-safe (a single `seccomp(2)`), so it is
/// legal in the post-fork `pre_exec` child. Requires `NO_NEW_PRIVS` to already be set.
pub fn apply(prog: &BpfProgram) -> Result<(), ConfineError> {
    seccompiler::apply_filter(prog).map_err(|e| fail(format!("seccomp apply_filter: {e}")))
}

/// `(argN & mask) == mask`: true when every bit of `mask` is set in argument `N`.
fn masked_flag_rule(arg: u8, mask: u64) -> Result<SeccompRule, ConfineError> {
    let cond = SeccompCondition::new(
        arg,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(mask),
        mask,
    )
    .map_err(|e| fail(format!("seccomp condition: {e}")))?;
    SeccompRule::new(vec![cond]).map_err(|e| fail(format!("seccomp rule: {e}")))
}

fn eq_rule(arg: u8, value: u64) -> Result<SeccompRule, ConfineError> {
    let cond = SeccompCondition::new(arg, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value)
        .map_err(|e| fail(format!("seccomp condition: {e}")))?;
    SeccompRule::new(vec![cond]).map_err(|e| fail(format!("seccomp rule: {e}")))
}

fn socket_family_rules(fam: SocketFamily) -> Result<Vec<SeccompRule>, ConfineError> {
    Ok(match fam {
        SocketFamily::Inet => vec![eq_rule(0, libc::AF_INET as u64)?],
        SocketFamily::Inet6 => vec![eq_rule(0, libc::AF_INET6 as u64)?],
        SocketFamily::Packet => vec![eq_rule(0, libc::AF_PACKET as u64)?],
        // Deny AF_NETLINK only when the protocol (arg2) is not NETLINK_ROUTE(0): route netlink is what
        // getaddrinfo/getifaddrs/NSS reach for, and denying it breaks the reuse toolchains (FW-TRA2).
        SocketFamily::NetlinkNonRoute => {
            let domain = SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_NETLINK as u64,
            )
            .map_err(|e| fail(format!("seccomp condition: {e}")))?;
            let not_route = SeccompCondition::new(
                2,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Ne,
                libc::NETLINK_ROUTE as u64,
            )
            .map_err(|e| fail(format!("seccomp condition: {e}")))?;
            vec![SeccompRule::new(vec![domain, not_route])
                .map_err(|e| fail(format!("seccomp rule: {e}")))?]
        }
    })
}

/// Map a baseline syscall name to its number on the compiled arch. Explicit rather than a lookup so
/// a missing constant is a build error, never a silently dropped rule (docs/linux-backend.md).
fn syscall_number(name: &str) -> Option<i64> {
    Some(match name {
        "add_key" => libc::SYS_add_key,
        "bpf" => libc::SYS_bpf,
        "finit_module" => libc::SYS_finit_module,
        "init_module" => libc::SYS_init_module,
        "kexec_file_load" => libc::SYS_kexec_file_load,
        "kexec_load" => libc::SYS_kexec_load,
        "keyctl" => libc::SYS_keyctl,
        "mount" => libc::SYS_mount,
        "mount_setattr" => libc::SYS_mount_setattr,
        "move_mount" => libc::SYS_move_mount,
        "open_by_handle_at" => libc::SYS_open_by_handle_at,
        "perf_event_open" => libc::SYS_perf_event_open,
        "pivot_root" => libc::SYS_pivot_root,
        "ptrace" => libc::SYS_ptrace,
        "request_key" => libc::SYS_request_key,
        "setns" => libc::SYS_setns,
        _ => return None,
    })
}
