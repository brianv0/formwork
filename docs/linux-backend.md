# Linux confiner backend — implementation plan (Phase 2)

Status: **not yet implemented.** The `formwork-confine` Linux backend is an honest fail-closed stub
(`ConfineError::Unimplemented`). This note captures the researched design and the concrete crate
APIs so implementation is fast once a Linux kernel is available to verify against — and records the
hazards that make blind implementation unwise (per FW-XR1/FW-INV5, Formwork must never claim
containment it has not verified).

Verify against: `just test-linux` (Docker, first-line) / `just test-linux-full` (Lima, ABI-v6 tier).
Exit criteria: FW-E2E-001..005, FW-ADV-001/002, FW-E2E-024 green on Linux, then FW-E2E-028 parity.

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
  `execve` is never checked. (Exec allow-list, FW-ISO4, is Phase 7: then govern `Execute` and grant
  it only on the allow-list.)
- **Net default-deny via Landlock (ABI ≥ v4):** `handle_access(AccessNet::from_all(abi))` with *no*
  `NetPort` rules denies all TCP connect/bind. Below v4, net-deny is carried by seccomp instead
  (see the socket-family rules) and this handle is omitted.
- **UNIX-socket / signal scoping (ABI ≥ v6):** the `Scope` handle blocks abstract-UNIX-socket and
  signal reach-out of the domain (FW-ADV-006). Coarse (domain-relative, not per-path); report
  Partial where present, Unenforceable below v6 — matches the compiler's report today.
- **ABI negotiation vs honesty:** the compiler already accounted fidelity from `host.landlock_abi`.
  Enforce at exactly `landlock_abi_target`. Prefer `CompatLevel::HardRequirement` so a missing
  access right is an error (fail-closed), *not* `BestEffort` (which would silently drop enforcement
  and contradict the report). The only softness allowed is skipping a grant path that doesn't exist.

### System-runtime essentials + subtractive expansion

Landlock is allow-list only, so two problems the macOS backend already solved recur here:

1. **Closed-read profiles need runtime essentials or nothing loads.** Granting only `/work/project`
   makes `ld.so`/libraries unreadable and every `execve` fails — the same class of failure the macOS
   spike hit (there it was a `dyld` SIGABRT). Linux essentials to add to the read set in Closed mode:
   `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc/ld.so.cache`, `/etc/ld.so.preload`, `/proc/self`,
   and the safe `/dev` nodes (`/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/random`, `/dev/tty`) —
   as literals, never a broad `/dev` (which would expose block devices, an out-of-band filesystem
   read). This mirrors `MACOS_READ_ESSENTIALS` / `MACOS_READ_DEVICES`.
2. **`subtract` can't be a deny rule** — it must be compiled into the *shape* of the grants. The
   expansion (bounded by the number of holes, not filesystem size):

   ```text
   expand(root, subtract):
     if some pattern in subtract covers root:            return []           # whole root denied
     if no subtract pattern lies strictly under root:    return [root]       # grant whole subtree
     result = []
     for child in readdir(root):
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

**Hazards that REQUIRE a real kernel + real toolchains to validate (do not ship blind):**

- **`clone3`.** glibc uses `clone3` for thread/process creation on recent versions and *falls back*
  to `clone` on `ENOSYS`. A seccomp filter returning `EPERM` (not `ENOSYS`) for `clone3` does **not**
  trigger the fallback and can break `fork`/threads across the whole toolchain — the opposite of
  FW-TRA2. The userns restriction also can't inspect `clone3`'s flags (they sit behind a `struct
  clone_args` pointer, unreadable by seccomp). Options to evaluate on a kernel: return `ENOSYS` for
  `clone3` to force the `clone` fallback (then filter `clone`'s flag arg), or rely on Landlock/no-new
  -privs + `unshare` filtering alone. Untestable here; decision deferred to Phase 2 on a kernel.
- **netlink.** Denying non-route `AF_NETLINK` may break NSS / `getaddrinfo` / `getifaddrs` paths that
  pytest and npm hit (Spike 3). Needs the real reuse workloads to confirm transparency.
- **`unshare`/`clone` `CLONE_NEWUSER` flag test** (`SeccompCmpOp::MaskedEq`) is arch-order sensitive
  and must be checked on both x86_64 and aarch64.
- **Syscall coverage.** Some baseline names (`mount_setattr`, `move_mount`, `clone3`) may lack
  `libc::SYS_*` constants; dropping one silently weakens the baseline — enumerate explicitly and log
  any that can't be resolved rather than skipping quietly.

The net effect: the Linux baseline's *transparency* (FW-TRA2) and *non-breakage* can only be
established by running the Phase-4 reuse workloads under it on a real kernel. That gate is why this
backend is deferred rather than written speculatively.
