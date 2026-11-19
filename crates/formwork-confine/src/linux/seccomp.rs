//! The seccomp half of the Linux confiner: two stacked filters, built in the parent and installed
//! in the forked child after `NO_NEW_PRIVS`. The kernel runs every installed filter and takes the
//! most restrictive result.
//!
//! The baseline (FW-ISO8) is a *deny-list* compiled with `seccompiler`: the default action is
//! `Allow`, so an ordinary toolchain is never tripped by a forgotten syscall (FW-TRA2), and a small
//! fixed set of escalation/confinement-shedding syscalls returns `EPERM`. Socket creation is the one
//! *allow-list* in it (FW-ISO28): `socket(2)` and `socketpair(2)` return `EPERM` for everything
//! outside the plan's admitted set, which carries net default-deny (FW-ISO3/FW-INV3).
//!
//! The bound filter is written by hand, because `seccompiler` keys a rule by one syscall number and
//! gives a filter one errno: it refuses the x32 number range (FW-ISO33) and the flag-carried second
//! entry points to a mediated effect (FW-ISO29, FW-ISO31), each with its own errno.

use std::collections::BTreeMap;
use std::io;

use seccompiler::{
    sock_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule,
};

use formwork_compile::{SeccompPlan, SocketFamily};

use super::ConfineError;

fn fail(msg: impl Into<String>) -> ConfineError {
    ConfineError::MechanismFailed(msg.into())
}

/// Both programs, ready for the child.
pub struct Built {
    baseline: BpfProgram,
    bound: BpfProgram,
}

/// Compile the plan into its two BPF programs (allocation happens here, in the parent).
pub fn build(plan: &SeccompPlan) -> Result<Built, ConfineError> {
    Ok(Built {
        baseline: baseline(plan)?,
        bound: bound_filter(plan),
    })
}

fn baseline(plan: &SeccompPlan) -> Result<BpfProgram, ConfineError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Unconditional escalation/shedding denies. An unresolved syscall number would silently weaken
    // the baseline, so refuse to install rather than skip it (FW-INV6).
    for name in &plan.deny_syscalls {
        let nr = syscall_number(name)
            .ok_or_else(|| fail(format!("seccomp baseline syscall {name:?} has no number on this arch; refusing a silently-weakened filter")))?;
        rules.entry(nr).or_default(); // empty rule vec == unconditional match -> EPERM
    }

    // FW-ISO28. `socketpair` takes the same three leading arguments and creates both sockets
    // before it fails for a family that has no pairs, so it gets the same rules. An empty list
    // leaves an empty rule vec, which refuses every call: nothing admitted, nothing created.
    let socket_rules = socket_refusals(&plan.allow_socket_families)?;
    for nr in [libc::SYS_socket, libc::SYS_socketpair] {
        rules.entry(nr).or_default().extend(socket_rules.clone());
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

/// Install both filters on the calling thread. Async-signal-safe (one `seccomp(2)` each), so it is
/// legal in the post-fork `pre_exec` child. Requires `NO_NEW_PRIVS` to already be set. Returns the
/// raw OS error rather than a formatted `ConfineError` so the child path allocates nothing.
pub fn apply(built: &Built) -> io::Result<()> {
    for prog in [&built.baseline, &built.bound] {
        seccompiler::apply_filter(prog).map_err(|_| io::Error::last_os_error())?;
    }
    Ok(())
}

// <asm/unistd_x32.h>: `__X32_SYSCALL_BIT`.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The second filter. In order: refuse a syscall number in the x32 range (FW-ISO33, x86_64 only --
/// on a kernel built with that ABI every baseline rule is otherwise reachable under its x32
/// number); refuse a send that carries `MSG_FASTOPEN` (FW-ISO29); refuse `execveat` with
/// `AT_EMPTY_PATH` (FW-ISO31). A foreign architecture is left to the baseline, which kills it.
fn bound_filter(plan: &SeccompPlan) -> BpfProgram {
    use libc::{BPF_ABS, BPF_JEQ, BPF_JMP, BPF_JSET, BPF_K, BPF_LD, BPF_RET, BPF_W};
    let ins = |code: u32, jt: u8, jf: u8, k: u32| sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    let ld = |off: u32| ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, off);
    let jeq = |k: u32, jt: u8, jf: u8| ins(BPF_JMP | BPF_JEQ | BPF_K, jt, jf, k);
    let jset = |k: u32, jt: u8, jf: u8| ins(BPF_JMP | BPF_JSET | BPF_K, jt, jf, k);
    let allow = || ins(BPF_RET | BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW);
    let errno = |e: libc::c_int| ins(BPF_RET | BPF_K, 0, 0, libc::SECCOMP_RET_ERRNO | e as u32);

    // (syscall, index of its flags argument, flag, errno). Flags are `int` in each prototype, so
    // the kernel reads the low word only, and so does the filter.
    let mut refusals: Vec<(libc::c_long, u32, libc::c_int, libc::c_int)> = Vec::new();
    if plan.deny_send_fastopen {
        // EOPNOTSUPP is what a kernel without Fast Open answers; clients fall back to connect().
        let refuse = |nr, arg| (nr, arg, libc::MSG_FASTOPEN, libc::EOPNOTSUPP);
        refusals.extend([
            refuse(libc::SYS_sendto, 3),
            refuse(libc::SYS_sendmsg, 2),
            refuse(libc::SYS_sendmmsg, 3),
        ]);
    }
    if plan.deny_exec_by_descriptor {
        refusals.push((libc::SYS_execveat, 4, libc::AT_EMPTY_PATH, libc::EACCES));
    }

    // seccomp_data: nr @0, arch @4, args[i] @16 + 8*i (little-endian low word first). Every jump
    // is local to its block, so adding a block moves no other offset.
    let mut prog = vec![
        ld(4),
        jeq(super::supervise::AUDIT_ARCH, 1, 0),
        allow(),
        ld(0),
    ];
    #[cfg(target_arch = "x86_64")]
    prog.extend([jset(X32_SYSCALL_BIT, 0, 1), errno(libc::EPERM)]);
    for (nr, arg, flag, refusal) in refusals {
        prog.extend([
            jeq(nr as u32, 0, 4),
            ld(16 + 8 * arg),
            jset(flag as u32, 0, 1),
            errno(refusal),
            allow(),
        ]);
    }
    prog.push(allow());
    prog
}

/// `(argN & mask) == mask`: true when every bit of `mask` is set in argument `N`.
fn masked_flag_rule(arg: u8, mask: u64) -> Result<SeccompRule, ConfineError> {
    rule(vec![condition(arg, SeccompCmpOp::MaskedEq(mask), mask)?])
}

fn condition(arg: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompCondition, ConfineError> {
    SeccompCondition::new(arg, SeccompCmpArgLen::Dword, op, value)
        .map_err(|e| fail(format!("seccomp condition: {e}")))
}

fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule, ConfineError> {
    SeccompRule::new(conditions).map_err(|e| fail(format!("seccomp rule: {e}")))
}

fn domain(fam: SocketFamily) -> u64 {
    (match fam {
        SocketFamily::Unix => libc::AF_UNIX,
        SocketFamily::NetlinkRoute => libc::AF_NETLINK,
        SocketFamily::InetTcpStream => libc::AF_INET,
        SocketFamily::Inet6TcpStream => libc::AF_INET6,
    }) as u64
}

/// The rules that refuse `socket(domain, type, protocol)` outside `allowed` (FW-ISO28). Rules are
/// ORed and a rule's conditions ANDed, so the complement of the allow-list is one rule for "no
/// admitted domain" plus, per admitted domain, one rule for each way to miss its predicate.
fn socket_refusals(allowed: &[SocketFamily]) -> Result<Vec<SeccompRule>, ConfineError> {
    use SeccompCmpOp::{Eq, MaskedEq, Ne};
    // The bits of SOCK_TYPE_MASK (<linux/net.h>). SOCK_NONBLOCK and SOCK_CLOEXEC ride above it, so an
    // unmasked compare would refuse `SOCK_STREAM | SOCK_CLOEXEC`.
    const SOCK_TYPE_BITS: [u64; 4] = [1, 2, 4, 8];
    let mut rules = Vec::new();
    if allowed.is_empty() {
        return Ok(rules);
    }
    rules.push(rule(
        allowed
            .iter()
            .map(|fam| condition(0, Ne, domain(*fam)))
            .collect::<Result<_, _>>()?,
    )?);
    for fam in allowed {
        let this = || condition(0, Eq, domain(*fam));
        match fam {
            SocketFamily::Unix => {}
            // Route netlink is what getaddrinfo/getifaddrs/NSS reach for (FW-TRA2); the other
            // netlink protocols reach the audit, netfilter and sock_diag subsystems.
            SocketFamily::NetlinkRoute => rules.push(rule(vec![
                this()?,
                condition(2, Ne, libc::NETLINK_ROUTE as u64)?,
            ])?),
            SocketFamily::InetTcpStream | SocketFamily::Inet6TcpStream => {
                // seccompiler has no masked not-equal, so "the type is not SOCK_STREAM" is one
                // rule per type bit that differs from SOCK_STREAM's (FW-ISO11).
                let stream = libc::SOCK_STREAM as u64;
                for bit in SOCK_TYPE_BITS {
                    rules.push(rule(vec![
                        this()?,
                        condition(1, MaskedEq(bit), !stream & bit)?,
                    ])?);
                }
                // FW-ISO35: Landlock's port rules are TCP rules, and MPTCP and SCTP streams are
                // not known to be governed by them.
                rules.push(rule(vec![
                    this()?,
                    condition(2, Ne, 0)?,
                    condition(2, Ne, libc::IPPROTO_TCP as u64)?,
                ])?);
            }
        }
    }
    Ok(rules)
}

/// Map a baseline syscall name to its number on the compiled arch. Explicit rather than a lookup so
/// a missing constant is a build error, never a silently dropped rule (docs/linux-backend.md).
fn syscall_number(name: &str) -> Option<i64> {
    Some(match name {
        "add_key" => libc::SYS_add_key,
        "bpf" => libc::SYS_bpf,
        "finit_module" => libc::SYS_finit_module,
        "init_module" => libc::SYS_init_module,
        "io_uring_enter" => libc::SYS_io_uring_enter,
        "io_uring_register" => libc::SYS_io_uring_register,
        "io_uring_setup" => libc::SYS_io_uring_setup,
        "kexec_file_load" => libc::SYS_kexec_file_load,
        "kexec_load" => libc::SYS_kexec_load,
        "keyctl" => libc::SYS_keyctl,
        "mount" => libc::SYS_mount,
        "mount_setattr" => libc::SYS_mount_setattr,
        "move_mount" => libc::SYS_move_mount,
        "open_by_handle_at" => libc::SYS_open_by_handle_at,
        "perf_event_open" => libc::SYS_perf_event_open,
        "pidfd_getfd" => libc::SYS_pidfd_getfd,
        "pivot_root" => libc::SYS_pivot_root,
        "process_vm_readv" => libc::SYS_process_vm_readv,
        "process_vm_writev" => libc::SYS_process_vm_writev,
        "ptrace" => libc::SYS_ptrace,
        "request_key" => libc::SYS_request_key,
        "setns" => libc::SYS_setns,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::super::supervise::AUDIT_ARCH;
    use super::*;
    use formwork_blueprint::{Blueprint, ExecPosture, NetPosture, PathPattern, ResolvedCatalog};
    use formwork_compile::ConfinerPolicy;
    use formwork_detect::HostProfile;
    use libc::{
        AF_INET, AF_INET6, AF_NETLINK, AF_PACKET, AF_UNIX, AF_VSOCK, SOCK_CLOEXEC, SOCK_DGRAM,
        SOCK_NONBLOCK, SOCK_RAW, SOCK_SEQPACKET, SOCK_STREAM,
    };

    const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const LD: u32 = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    const AND: u32 = libc::BPF_ALU | libc::BPF_AND | libc::BPF_K;
    const JA: u32 = libc::BPF_JMP | libc::BPF_JA;
    const JEQ: u32 = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
    const JGT: u32 = libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K;
    const JGE: u32 = libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K;
    const JSET: u32 = libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K;
    const RET: u32 = libc::BPF_RET | libc::BPF_K;

    fn errno(e: libc::c_int) -> u32 {
        libc::SECCOMP_RET_ERRNO | e as u32
    }

    /// Both programs for a posture, from the plan the compiler emits for it.
    fn built(net: NetPosture, exec: ExecPosture) -> Built {
        let blueprint = Blueprint {
            net,
            exec,
            ..Blueprint::empty()
        };
        let policy = formwork_compile::compile(
            &blueprint,
            &HostProfile::synthetic_linux(Some(6)),
            &ResolvedCatalog::empty_no_floor(),
        );
        match policy.confiner {
            ConfinerPolicy::Linux(l) => build(&l.seccomp).expect("the plan builds"),
            other => panic!("expected a Linux confiner, got {other:?}"),
        }
    }

    fn net_deny() -> Built {
        built(NetPosture::Deny, ExecPosture::Unrestricted)
    }

    fn port_tier() -> Built {
        built(NetPosture::Ports(vec![443]), ExecPosture::Unrestricted)
    }

    /// A classic-BPF interpreter over the instructions the two programs use, fed a
    /// `seccomp_data`. CI kernels are not built with the x32 ABI, so no call there reaches what
    /// the number bound guards; the other rules are also probed on the kernel
    /// (tests/linux_confine.rs).
    fn eval(prog: &[sock_filter], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&nr.to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        for (i, arg) in args.iter().enumerate() {
            data[16 + 8 * i..24 + 8 * i].copy_from_slice(&arg.to_le_bytes());
        }
        let (mut acc, mut pc) = (0u32, 0usize);
        loop {
            let ins = &prog[pc];
            pc += 1;
            let k = ins.k;
            match u32::from(ins.code) {
                LD => {
                    let at = k as usize;
                    acc = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
                }
                AND => acc &= k,
                JA => pc += k as usize,
                RET => return k,
                code @ (JEQ | JGT | JGE | JSET) => {
                    let taken = match code {
                        JEQ => acc == k,
                        JGT => acc > k,
                        JGE => acc >= k,
                        _ => acc & k != 0,
                    };
                    pc += usize::from(if taken { ins.jt } else { ins.jf });
                }
                other => panic!("instruction {other:#x} is outside the interpreted subset"),
            }
        }
    }

    /// What the kernel answers with both filters installed: the most restrictive action.
    fn verdict(built: &Built, nr: libc::c_long, args: [u64; 6]) -> u32 {
        [&built.baseline, &built.bound]
            .into_iter()
            .map(|prog| eval(prog, AUDIT_ARCH, nr as u32, args))
            .min_by_key(|v| (v & libc::SECCOMP_RET_ACTION_FULL) as i32)
            .unwrap()
    }

    /// Whether `socket(domain, ty, protocol)` is admitted; `socketpair` must answer the same.
    fn admits(built: &Built, domain: i32, ty: i32, protocol: i32) -> bool {
        let args = [domain as u64, ty as u64, protocol as u64, 0, 0, 0];
        let socket = verdict(built, libc::SYS_socket, args);
        assert_eq!(socket, verdict(built, libc::SYS_socketpair, args));
        assert!(socket == ALLOW || socket == errno(libc::EPERM));
        socket == ALLOW
    }

    fn flags_at(index: usize, flags: i32) -> [u64; 6] {
        let mut args = [0u64; 6];
        args[index] = flags as u64;
        args
    }

    /// FW-E2E-205, filter half: every number in the x32 range is refused, whatever the baseline
    /// says about the native number beside it.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn fw_e2e_205_filter_refuses_the_x32_number_range() {
        const X32_PTRACE: libc::c_long = 521;
        const X32_PROCESS_VM_WRITEV: libc::c_long = 540;
        for built in [net_deny(), port_tier()] {
            for nr in [
                libc::SYS_socket,
                libc::SYS_io_uring_setup,
                libc::SYS_getpid,
                X32_PTRACE,
                X32_PROCESS_VM_WRITEV,
            ] {
                let x32 = nr | libc::c_long::from(X32_SYSCALL_BIT);
                assert_eq!(verdict(&built, x32, [0; 6]), errno(libc::EPERM), "x32 {nr}");
                assert_eq!(
                    eval(&built.bound, AUDIT_ARCH, x32 as u32, [0; 6]),
                    errno(libc::EPERM),
                    "the bound, not the baseline, refuses x32 {nr}"
                );
            }
            for nr in [libc::SYS_getpid, libc::SYS_read, libc::SYS_execve] {
                assert_eq!(verdict(&built, nr, [0; 6]), ALLOW, "native {nr}");
            }
        }
    }

    /// The hand-written filter leaves another architecture's numbers to the baseline, which
    /// kills: its own numbers mean other syscalls there.
    #[test]
    fn a_foreign_architecture_is_decided_by_the_baseline() {
        const AUDIT_ARCH_I386: u32 = 0x4000_0003;
        let built = net_deny();
        let args = flags_at(3, libc::MSG_FASTOPEN);
        let nr = libc::SYS_sendto as u32;
        assert_eq!(eval(&built.bound, AUDIT_ARCH_I386, nr, args), ALLOW);
        assert_eq!(
            eval(&built.baseline, AUDIT_ARCH_I386, nr, args),
            libc::SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn baseline_refuses_its_deny_list_and_nothing_ordinary() {
        let built = net_deny();
        for nr in [libc::SYS_ptrace, libc::SYS_bpf, libc::SYS_io_uring_setup] {
            assert_eq!(verdict(&built, nr, [0; 6]), errno(libc::EPERM), "{nr}");
        }
        assert_eq!(
            verdict(&built, libc::SYS_unshare, flags_at(0, libc::CLONE_NEWUSER)),
            errno(libc::EPERM)
        );
        for nr in [libc::SYS_read, libc::SYS_openat, libc::SYS_clone3] {
            assert_eq!(verdict(&built, nr, [0; 6]), ALLOW, "{nr}");
        }
    }

    /// FW-ISO28: under `net = "deny"` only AF_UNIX and route netlink are created.
    #[test]
    fn fw_iso28_net_deny_admits_no_family_outside_the_list() {
        const AF_ALG: i32 = 38;
        const AF_SMC: i32 = 43;
        // One above AF_MCTP, the highest family Linux 6.18 assigns.
        const UNASSIGNED: i32 = 46;
        let built = net_deny();
        for ty in [SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET | SOCK_CLOEXEC] {
            assert!(admits(&built, AF_UNIX, ty, 0), "AF_UNIX type {ty:#x}");
        }
        assert!(admits(&built, AF_NETLINK, SOCK_RAW, libc::NETLINK_ROUTE));
        for protocol in [
            libc::NETLINK_SOCK_DIAG,
            libc::NETLINK_AUDIT,
            libc::NETLINK_GENERIC,
        ] {
            assert!(
                !admits(&built, AF_NETLINK, SOCK_RAW, protocol),
                "netlink {protocol}"
            );
        }
        for domain in [
            AF_INET, AF_INET6, AF_PACKET, AF_VSOCK, AF_ALG, AF_SMC, UNASSIGNED, 0, 1000, -1,
        ] {
            for ty in [SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET] {
                assert!(!admits(&built, domain, ty, 0), "family {domain} type {ty}");
            }
        }
    }

    /// FW-ISO28 / FW-ISO35 / FW-ISO11: where stream sockets are admitted, an inet socket is
    /// created only as a TCP stream.
    #[test]
    fn fw_iso35_stream_postures_admit_inet_only_as_a_tcp_stream() {
        let built = port_tier();
        for domain in [AF_INET, AF_INET6] {
            for flags in [0, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_CLOEXEC | SOCK_NONBLOCK] {
                for protocol in [0, libc::IPPROTO_TCP] {
                    assert!(
                        admits(&built, domain, SOCK_STREAM | flags, protocol),
                        "family {domain} flags {flags:#x} protocol {protocol}"
                    );
                }
                for protocol in [libc::IPPROTO_MPTCP, libc::IPPROTO_SCTP, libc::IPPROTO_UDP] {
                    assert!(
                        !admits(&built, domain, SOCK_STREAM | flags, protocol),
                        "family {domain} flags {flags:#x} protocol {protocol}"
                    );
                }
                // Every type value but SOCK_STREAM, including the ones no kernel assigns.
                for ty in (0..16).filter(|ty| *ty != SOCK_STREAM) {
                    assert!(
                        !admits(&built, domain, ty | flags, 0),
                        "family {domain} type {ty} flags {flags:#x}"
                    );
                }
            }
        }
        assert!(admits(&built, AF_UNIX, SOCK_DGRAM, 0));
        assert!(admits(&built, AF_NETLINK, SOCK_RAW, libc::NETLINK_ROUTE));
        assert!(!admits(&built, AF_VSOCK, SOCK_STREAM, 0));
        assert!(!admits(&built, AF_PACKET, SOCK_RAW, 0));
    }

    /// FW-ISO29: the three sends are refused when, and only when, their flags argument carries
    /// `MSG_FASTOPEN`.
    #[test]
    fn fw_iso29_a_send_carrying_fastopen_is_refused() {
        let refused = errno(libc::EOPNOTSUPP);
        let fastopen = libc::MSG_FASTOPEN;
        for built in [net_deny(), port_tier()] {
            for (nr, index) in [
                (libc::SYS_sendto, 3),
                (libc::SYS_sendmsg, 2),
                (libc::SYS_sendmmsg, 3),
            ] {
                assert_eq!(verdict(&built, nr, flags_at(index, fastopen)), refused);
                assert_eq!(
                    verdict(&built, nr, flags_at(index, fastopen | libc::MSG_NOSIGNAL)),
                    refused
                );
                // The kernel reads flags as an int; the upper half of the register is not flags.
                let mut wide = flags_at(index, fastopen);
                wide[index] |= 0xdead_beef << 32;
                assert_eq!(verdict(&built, nr, wide), refused);
                let ordinary = libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT;
                assert_eq!(verdict(&built, nr, flags_at(index, ordinary)), ALLOW);
                assert_eq!(verdict(&built, nr, [0; 6]), ALLOW);
                // A neighbouring argument (a pointer) that happens to have the bit set.
                assert_eq!(verdict(&built, nr, flags_at(1, fastopen)), ALLOW);
            }
        }
    }

    /// FW-ISO31: `execveat` with `AT_EMPTY_PATH` is refused under an exec allow-list and nowhere
    /// else.
    #[test]
    fn fw_iso31_exec_by_descriptor_is_refused_under_an_allowlist() {
        let listed = ExecPosture::Allowlist(vec![PathPattern::parse("/usr/bin/true").unwrap()]);
        let allowlist = built(NetPosture::Deny, listed);
        let refused = errno(libc::EACCES);
        let empty_path = flags_at(4, libc::AT_EMPTY_PATH);
        let with_nofollow = flags_at(4, libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW);
        assert_eq!(verdict(&allowlist, libc::SYS_execveat, empty_path), refused);
        assert_eq!(
            verdict(&allowlist, libc::SYS_execveat, with_nofollow),
            refused
        );
        for args in [[0; 6], flags_at(4, libc::AT_SYMLINK_NOFOLLOW)] {
            assert_eq!(verdict(&allowlist, libc::SYS_execveat, args), ALLOW);
        }
        assert_eq!(verdict(&allowlist, libc::SYS_execve, empty_path), ALLOW);
        assert_eq!(
            verdict(&net_deny(), libc::SYS_execveat, empty_path),
            ALLOW,
            "unrestricted exec keeps fexecve"
        );
    }
}
