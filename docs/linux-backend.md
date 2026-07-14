# Linux confiner backend — design + hardening notes (Phase 2)

Status: **implemented and kernel-verified** (Landlock fs+net+scope, seccomp baseline, subtractive
expansion), verified against a real ABI-v6 kernel. This note keeps the researched design and crate
APIs, and now records the **hardening decisions** that closed real escape/transparency gaps found by
review on the kernel. Per [FW-XR1](../formwork.md#fw-xr1)/[FW-INV5](../formwork.md#fw-inv5), Formwork never claims containment it has not verified.

Verify against: the `formwork-linux-dev` Docker image on an ABI-v6 kernel, `--security-opt
seccomp=unconfined --security-opt apparmor=unconfined` so only Formwork's sandbox is under test.

## Hardening decisions (verified on the kernel)

- **Symlinks are skipped during subtractive expansion.** `PathFd` opens with `O_PATH` (no
  `O_NOFOLLOW`), so granting or recursing a symlink *entry* would bind the rule to its target — a
  fail-open escape out of a split grant. Access *through* a symlink still resolves to the real path,
  governed by whatever rule covers it (or denied), matching macOS's resolved-path checks.
- **`/proc/self` is granted in the child, not the parent.** It is a per-process symlink; a rule built
  in the parent binds the *launcher's* `/proc/<pid>`. The child's own `/proc/self` is added post-fork
  in `apply` (runtimes read `/proc/self/{maps,exe,status}` and would otherwise die under Closed mode).
- **Net-deny is carried by seccomp, not Landlock.** Landlock net governs only TCP; carrying deny with
  it left UDP/raw open (an exfil channel). Deny now denies inet `socket(2)` creation at the family
  level (TCP + UDP + raw), matching macOS `(deny network*)`. Landlock net is reserved for the port
  tier, where per-port TCP *allow* is required.
- **Abstract-UNIX-socket + signal scoping is enforced at ABI v6+** via the `Scope` handle — closing a
  pathless escape the fs rules cannot reach — matching the compiler's CrossDomainSocket = Partial.
- **Device ioctls are *not* governed** (`IOCTL_DEV` excluded from `handled_fs`). Governing it denies
  every ioctl on a device node — including the winsize/termios calls every interactive TUI makes on
  its inherited stdio, whose controlling pty is dynamic and cannot be pre-granted. macOS has no
  separate device-ioctl gate (parity). Residual surface is small: you can only ioctl a device you can
  already open, and the dangerous ones (e.g. TIOCSTI injection) are CAP_SYS_ADMIN-gated, which
  NO_NEW_PRIVS keeps unreachable.
- **Extra baseline denies:** `io_uring_{setup,enter,register}` (a historical seccomp/LSM bypass) and
  the cross-process reach-in surfaces `pidfd_getfd` / `process_vm_{readv,writev}` (fd theft or memory
  write into an *unconfined* same-uid sibling; `ptrace` denial does not cover these).
- **The child `apply` path is allocation-free on success** (only syscalls + raw-errno results), so a
  post-`fork` allocator poisoned by a multi-threaded parent cannot deadlock it.

## Posture: build in the parent, apply in the child

To avoid `malloc`-after-`fork` hazards, do all allocation-heavy work **before** the fork and apply
the finished artifacts in the `pre_exec` closure (which runs in the forked child, before `execve`):

1. **Parent, before `Command::pre_exec`:** expand the read/write sets against the filesystem
   (see below), open `PathFd`s, build the Landlock `RulesetCreated` (accumulates kernel state behind
   a ruleset fd — does *not* restrict the parent until `restrict_self`), and compile the seccomp
   `BpfProgram`. Move both into the closure.
2. **Child, inside `pre_exec`:** `prctl(PR_SET_NO_NEW_PRIVS, 1)` → `ruleset.restrict_self()` →
   `apply_filter(&bpf)`. These are syscalls only; no allocation. Then `execve` proceeds.

Order matters: `NO_NEW_PRIVS` must precede both the Landlock `restrict_self` (kernel requires it for
unprivileged restriction) and the seccomp `apply_filter` (required for an unprivileged filter).

## Landlock (filesystem + net)

Researched API (`landlock` 0.4, current crate supports up to ABI v7):

```rust
use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort,
    PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};

let abi = /* map policy.landlock_abi_target -> ABI::V1..=V7 */;
let created = Ruleset::default()
    .handle_access(handled_fs)?              // the access rights we govern (see note)
    .handle_access(AccessNet::from_all(abi))?  // only when net is Landlock-carried (ABI >= v4)
    .create()?
    .add_rules(path_beneath_rules(read_paths, read_access))?
    .add_rules(path_beneath_rules(write_paths, AccessFs::from_all(abi)))?;
// optional port tier:
let created = created.add_rule(NetPort::new(port, AccessNet::ConnectTcp)?)?;
created.restrict_self()?;   // apply to the calling thread (inherited across execve)
```

Key decisions:

- **Do not govern `Execute` when exec is unrestricted (the default).** Landlock denies any handled
  access that isn't granted, so if `AccessFs::Execute` is in `handled_fs`, only explicitly-granted
  paths are executable. For the transparent default, exclude `Execute` from `handled_fs` entirely so
  `execve` is never checked. (When the blueprint requests an exec allow-list ([FW-ISO4](../formwork.md#fw-iso4)), `Execute` is
  governed and granted only on the allow-list -- implemented here, though not yet exercised by a
  kernel test.)
- **Net default-deny via seccomp (all ABIs), *not* Landlock.** Landlock net governs only TCP, so a
  Landlock-carried deny leaves UDP/raw open. Deny denies inet `socket(2)` at the family level instead
  (TCP + UDP + raw); Landlock net (`handle_access(AccessNet::from_all(abi))` + `NetPort` allows) is
  reserved for the **port tier** (ABI ≥ v4), which needs per-port TCP *allow*.
- **UNIX-socket / signal scoping (ABI ≥ v6):** the `Scope` handle (`.scope(Scope::from_all(abi))`)
  blocks abstract-UNIX-socket and signal reach-out of the domain ([FW-ADV-006](../formwork.md#fw-adv-006)). Coarse (domain-
  relative, not per-path); reported Partial at v6+, Unenforceable below — matches the compiler.
- **ABI negotiation vs honesty:** the compiler already accounted fidelity from `host.landlock_abi`.
  Enforce at exactly `landlock_abi_target`. Prefer `CompatLevel::HardRequirement` so a missing
  access right is an error (fail-closed), *not* `BestEffort` (which would silently drop enforcement
  and contradict the report). The only softness allowed is skipping a grant path that doesn't exist.

### System-runtime essentials + subtractive expansion

Landlock is allow-list only, so two problems the macOS backend already solved recur here:

1. **Closed-read profiles need runtime essentials or nothing loads.** Granting only `/work/project`
   makes `ld.so`/libraries unreadable and every `execve` fails — the same class of failure the macOS
   spike hit (there it was a `dyld` SIGABRT). Linux essentials to add to the read set in Closed mode:
   `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc/ld.so.cache`, `/etc/ld.so.preload`, and the safe
   `/dev` nodes (`/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/random`, `/dev/tty`) — as literals,
   never a broad `/dev` (which would expose block devices, an out-of-band filesystem read). This
   mirrors `MACOS_READ_ESSENTIALS` / `MACOS_READ_DEVICES`. `/proc/self` is *not* a parent-side
   essential — it is per-process and must be granted in the child (see Hardening decisions above).
2. **`subtract` can't be a deny rule** — it must be compiled into the *shape* of the grants. The
   expansion (bounded by the number of holes, not filesystem size):

   ```text
   expand(root, subtract):
     if some pattern in subtract covers root:            return []           # whole root denied
     if no subtract pattern lies strictly under root:    return [root]       # grant whole subtree
     result = []
     for child in readdir(root):
         if child is a symlink:                          skip     # would bind the rule to its target
         if child is exactly subtracted:                 skip
         elif some subtract lies under child:            result += expand(child, subtract)
         else:                                           result.push(child)
     return result
   ```

   Applied to each read root and each write root. For the subtractive default profile the read root
   is `/` and the holes are the sensitive set; the walk grants everything except the sensitive
   subtrees. Consequence (state in the report): directories created under a broad root *after*
   enforcement are not covered — fail-closed, acceptable, and TOCTOU-safe because Landlock rules bind
   to the opened directory fds, not to path strings.

## seccomp baseline (`seccompiler`) — and its hazards

Researched API (`seccompiler` 0.4):

```rust
use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp,
                  SeccompCondition, SeccompFilter, SeccompRule};
use std::collections::BTreeMap;

let filter = SeccompFilter::new(
    rules,                                  // BTreeMap<i64, Vec<SeccompRule>>
    SeccompAction::Allow,                   // default (mismatch) action — deny-list shape
    SeccompAction::Errno(libc::EPERM as u32), // action when a listed syscall/condition matches
    std::env::consts::ARCH.try_into().unwrap(), // TargetArch of the running (compiled) arch
)?;
let prog: BpfProgram = filter.try_into()?;
apply_filter(&prog)?;
```

Deny-list shape: default `Allow`, listed syscalls → `Errno`. An empty rule vec is an unconditional
deny; conditional denies use `SeccompRule::new(vec![SeccompCondition::new(arg, len, op, val)?])`.
Syscall numbers come from `libc::SYS_*` (correct for the compiled arch). Socket-family deny:

```rust
// deny socket(AF_INET/AF_INET6/AF_PACKET, ...) — arg0 is the domain
rules.insert(libc::SYS_socket, vec![
    SeccompRule::new(vec![SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, AF_INET as u64)?])?,
    // ... INET6, PACKET ...
]);
// AF_UNIX / socketpair are absent from the list -> allowed (the injected-fd seam is untouched).
```

**Hazards (status after kernel validation):**

- **`clone3` — accepted gap, mitigated.** glibc uses `clone3` for thread/process creation and *falls
  back* to `clone` only on `ENOSYS`, not `EPERM` — so we do **not** filter `clone3` (returning `EPERM`
  would break `fork`/threads, the opposite of [FW-TRA2](../formwork.md#fw-tra2)). Its flags sit behind a `clone_args` pointer
  seccomp cannot read, so a `CLONE_NEWUSER` via `clone3` is not blocked at the flag level. This is
  well-mitigated: a fresh userns is inert here — `mount`, `setns`, `pivot_root` are denied and
  Landlock is namespace-independent, so the userns grants no reachable capability. The `unshare`/
  `clone` `CLONE_NEWUSER` flag filter still blocks the common paths. Verified transparent to
  fork+exec on the kernel.
- **netlink — resolved.** Only *non-route* `AF_NETLINK` is denied; `NETLINK_ROUTE` (what NSS /
  `getaddrinfo` / `getifaddrs` use) stays allowed. Fork+exec transparency verified; full reuse-
  workload confirmation is still owed for pytest/npm name resolution under the *port tier*.
- **`CLONE_NEWUSER` flag test** (`SeccompCmpOp::MaskedEq`, arg0) — verified on aarch64; the arch guard
  (`TargetArch::try_from`) rejects any arch where `clone`'s flags are not arg0.
- **Syscall coverage — fail-loud.** `syscall_number` is an explicit match; an unresolved baseline name
  aborts the build (`FW-INV6`) rather than silently dropping a rule. All baseline names resolve on
  x86_64/aarch64, including the hardening additions (`io_uring_*`, `pidfd_getfd`, `process_vm_*`).

Still owed: the Phase-4 reuse workloads (pytest/npm/cargo) under the baseline on a real kernel to
fully establish *transparency* ([FW-TRA2](../formwork.md#fw-tra2)) beyond the fork+exec + `/proc/self` cases already verified.
