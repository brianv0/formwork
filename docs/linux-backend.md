# Linux confiner backend — design + hardening notes

Status: **implemented and kernel-verified** (Landlock fs+net+scope, seccomp baseline, subtractive
expansion), verified against a real ABI-v6 kernel. This note keeps the researched design and crate
APIs, and now records the **hardening decisions** that closed real escape/transparency gaps found by
review on the kernel. Per [FW-XR1](../formwork.md#fw-xr1)/[FW-INV5](../formwork.md#fw-inv5), Formwork never claims containment it has not verified.

Verify against: the `formwork-linux-test` Docker image (`just test-linux`) on an ABI-v6 kernel,
`--security-opt seccomp=unconfined --security-opt apparmor=unconfined` so only Formwork's sandbox is
under test.

## Hardening decisions (verified on the kernel)

- **Symlinks are skipped during subtractive expansion.** `PathFd` opens with `O_PATH` (no
  `O_NOFOLLOW`), so granting or recursing a symlink *entry* would bind the rule to its target — a
  fail-open escape out of a split grant. Access *through* a symlink still resolves to the real path,
  governed by whatever rule covers it (or denied), matching macOS's resolved-path checks.
- **`/proc` and `/etc` are read essentials (FEP-5 D11).** A rule is bound to one inode at spawn, and
  each descendant's `/proc/self` resolves to a different directory, so granting `/proc/self` in the
  child left grandchildren (a shell's `node`, `cargo`, `go`) unable to read their own
  `/proc/self/{maps,exe,status}`. `/proc` is granted read in every mode instead. Other processes'
  `/proc/<pid>/environ` stays closed: `ptrace_may_access` decides it, and Landlock refuses a
  confined process ptrace-class access outside its domain. A process holding `CAP_SYS_ADMIN` or
  `CAP_PERFMON` (a root container) gets past that refusal; host detection records those capabilities and
  `CAP_SYS_PTRACE`, and the report says `Partial` then. `isolate = ["processes"]` closes it
  regardless, with a fresh procfs.
- **Net-deny is carried by seccomp, not Landlock.** Landlock net governs only TCP; carrying deny with
  it left UDP/raw open (an exfil channel). Deny now denies inet `socket(2)` creation at the family
  level (TCP + UDP + raw), matching macOS `(deny network*)`. Landlock net carries the port tier,
  where per-port TCP *allow* is required -- but even there seccomp still denies inet DGRAM/RAW
  `socket(2)` (type masked to `SOCK_TYPE_MASK`, STREAM allowed), so the TCP-only Landlock grant
  cannot be sidestepped with a UDP/raw socket ([FW-ISO3](../formwork.md#fw-iso3),
  [FW-INV3](../formwork.md#fw-inv3), [FW-ISO11](../formwork.md#fw-iso11)). Nothing inside the sandbox
  resolves names under the port tier; host rules restore resolution through the Gateway.
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
  reserved for the **port tier** (ABI ≥ v4), which needs per-port TCP *allow*. The port tier still
  seccomp-denies inet **DGRAM/RAW** `socket(2)` (type masked to `SOCK_TYPE_MASK` so
  `SOCK_NONBLOCK`/`SOCK_CLOEXEC` cannot evade it) while allowing STREAM, so UDP/raw egress fails
  closed and only the granted TCP ports connect ([FW-ISO3](../formwork.md#fw-iso3)/[FW-INV3](../formwork.md#fw-inv3)).
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
   `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc`, `/proc`, and the safe
   `/dev` nodes (`/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/random`, `/dev/tty`) — as literals,
   never a broad `/dev` (which would expose block devices, an out-of-band filesystem read). This
   mirrors `MACOS_READ_ESSENTIALS` / `MACOS_READ_DEVICES`.
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

   A second consequence: a split directory itself — every ancestor of a hole, typically `/`, `/home`
   and `$HOME` — is traversable but not listable, so `ls /` and a tool's walk up the tree for config
   files are refused, while every file beneath stays readable. The comparison is OpenBSD unveil:
   `unveil("/", "r")` plus `unveil("~/.ssh", "")` lists `/` and `~` but hides `~/.ssh` entirely,
   names included. Landlock cannot express both halves, because a listing right on `~` also applies
   inside `~/.ssh`. Formwork keeps the half that never allows more than unveil would: ancestors stay
   unlisted, and a denied directory's names stay hidden. (Under the closed read mode,
   `mode = "unveil"`, the behavior matches unveil exactly: ancestors of a grant are traversable, not
   listable.) Decided in FEP-5 review; `docs/fep-5-plan.md` §3.

   A third consequence: the policy inputs the Launcher write-protects
   ([FW-XR8](../formwork.md#fw-xr8): the blueprint, its discovered layer and its proposal, and the
   other discovery candidate beside the blueprint) are write holes like any other. A blueprint
   inside a write grant, whether `FORMWORK.toml` or `.formwork/blueprint.toml` under a `$CWD/**`
   project grant, splits every directory from the grant's root down to the blueprint's own, so
   nothing can be created, removed or renamed directly in the project root. No Landlock ruleset
   avoids this. A right on a directory reaches everything beneath it, and stacked layers only
   intersect, so a file created in the root during the session and the blueprint beside it (or
   `.formwork/` below it) always hold the same rights. `WriteFile` for one is `WriteFile` for the
   other, and `Make*`/`Remove*` on the root would let the session replace the blueprint, move
   `.formwork/` aside, or create the absent discovered layer. Only a blueprint outside the grant
   keeps the root whole, and the split is load-bearing: a launch directory the session can create in
   is one it can leave a blueprint in for the next run's discovery walk. `run` and `explain` name
   the split directories, and name `--blueprint` with a file outside the grant as the way to a whole
   root, with that residual (FEP-5 D3, amended in `docs/fep-5-plan.md` §3; the open shape is in its
   §5).

### Any-depth rows are withheld

The expansion needs a rooted hole. An any-depth row (`**/.env`, `**/credentials`, the anchored
`<prefix>/**/<suffix>`) names a file wherever it appears, and Landlock rules attach to opened
files and directories, so such a row has nothing to attach to. The compiler withholds these rows
from the Linux policy: the credential floor's any-depth rows (the generic backstop is all of them)
and any-depth `write-subtract` rows. It lists each one under `withheld` in the fidelity report and
marks the affected credential types, the backstop and `tamper-vectors` Partial
([FW-CRED9](../formwork.md#fw-cred9), [FW-INV5](../formwork.md#fw-inv5)). A confined process on
Linux can therefore read a `credentials` file inside a granted directory, where Seatbelt denies it
with a regex. `formwork explain` says so in its backstop line and names the affected types apart
from the denied count, and `formwork explain <path>` marks such a path "withheld on this host". `formwork-confine` rejects an any-depth hole, so a row the
compiler failed to withhold fails the run instead of going missing.

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
// AF_UNIX / socketpair are absent from the list -> allowed (local IPC is not egress).
```

### Connect supervision and the isolation tier (FEP-5)

- **Supervised connect ([FW-EGR7](../formwork.md#fw-egr7), [FW-ISO12](../formwork.md#fw-iso12)).**
  Under host rules a second seccomp filter returns `SECCOMP_RET_USER_NOTIF` for `connect` and for
  `sendto` with a non-null destination (x32 numbers are refused outright). The listener is handed to
  the `formwork` process over a socketpair; the supervisor copies the `sockaddr` once, re-checks the
  notification id, takes the socket with `pidfd_getfd` and performs the call itself, so a thread
  rewriting the address after the check changes nothing ([FW-ADV-018](../formwork.md#fw-adv-018)).
  Inet goes to the Gateway only, from a source port the supervisor registers first, so the Gateway
  listener admits exactly the connections the supervisor made ([FW-EGR9](../formwork.md#fw-egr9));
  this is the Linux counterpart of the macOS peer check. A pathname socket is admitted when a
  literal write grant names it, when a lifted channel's facility owns it (the session bus and user
  manager for `run-outside`, the display socket for `clipboard` and `screen`, the audio socket for
  `microphone`; the keyring sockets and the session bus when `os-keyring` is lifted), or when a
  session process bound it, which is decided from `sock_diag` or, on kernels without
  `CONFIG_UNIX_DIAG`, `/proc/net/unix`. An abstract socket is refused. Addressed
  `sendmsg`/`sendmmsg` on an AF_UNIX datagram socket is not mediated (its destination sits in memory
  seccomp cannot read), and the report says so. A loopback server the session itself starts is
  refused too, because the supervisor admits inet only to the Gateway (FEP-6 §11, "In-session
  loopback"; [FW-E2E-106](../formwork.md#fw-e2e-106) waits on it). Requires 5.6+ (`pidfd_getfd`) and
  Yama `ptrace_scope` 0 or 1; host detection probes all three.
- **Channels.** Without host rules nothing mediates a pathname `connect()`, so the socket-shaped
  channels (`run-outside`, `open-url` through the desktop portal, `clipboard`, `screen`) are
  `Partial`: the Launcher strips their locator variables ([FW-BP11](../formwork.md#fw-bp11)), which
  hides the sockets from well-behaved clients but does not close them. Under host rules the
  supervisor closes them ([FW-ISO13](../formwork.md#fw-iso13)). Camera device nodes are withheld by
  Landlock in either case.
- **Broker custody ([FW-CRED16](../formwork.md#fw-cred16)).** When a blueprint brokers a credential,
  the `formwork` process that hosts the Gateway sets `PR_SET_DUMPABLE` to 0 before it spawns the
  workload, so the session cannot read its memory or environment through `/proc`.
- **The isolation tier ([FW-ISO10](../formwork.md#fw-iso10)).** User, PID, mount and UTS namespaces
  (plus IPC for `ipc`) are created by the `formwork` binary re-executed as a single-threaded stage:
  the parent is multi-threaded and cannot `unshare(CLONE_NEWUSER)`, and Landlock rules must be built
  after the fresh `/proc` and the tmpfs over the session temp directory are mounted, which
  allocates. A minimal PID-1 init reaps orphans and relays user-sent signals. The seccomp baseline
  installed afterwards still denies `CLONE_NEWUSER` and the mount family. Host detection probes the
  whole tier, `/proc` mount included, so Ubuntu 24.04's AppArmor restriction is refused before
  spawn.

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
  aborts the build ([FW-INV6](../formwork.md#fw-inv6)) rather than silently dropping a rule. All baseline names resolve on
  x86_64/aarch64, including the hardening additions (`io_uring_*`, `pidfd_getfd`, `process_vm_*`).

Still owed: the Phase-4 reuse workloads (pytest/npm/cargo) under the baseline on a real kernel to
fully establish *transparency* ([FW-TRA2](../formwork.md#fw-tra2)) beyond the fork+exec + `/proc/self` cases already verified.
