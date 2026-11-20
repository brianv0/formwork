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
- **Net-deny is carried by seccomp, not Landlock, as an allow-list of socket families.** Landlock
  net governs only TCP; carrying deny with it left UDP/raw open (an exfil channel). A deny-list of
  four families (inet, inet6, packet, non-route netlink) replaced it and left every other family
  to the kernel: an `AF_VSOCK` socket was created under `net = "deny"`, and an `IPPROTO_MPTCP`
  stream under the port tier (verified on 6.18). `socket(2)` and
  `socketpair(2)` now create only what the posture admits and return `EPERM` for the rest
  ([FW-ISO28](../formwork.md#fw-iso28)), so a family a later kernel adds is refused with no change
  here, and `net = "deny"` matches macOS `(deny network*)`:

  | Posture | Admitted |
  |---|---|
  | `net = "deny"` | `AF_UNIX`; `AF_NETLINK` with protocol `NETLINK_ROUTE` |
  | port tier, host rules | the above; `AF_INET` and `AF_INET6` of type `SOCK_STREAM` with protocol `0` or `IPPROTO_TCP` |

  Landlock net carries the port tier, where per-port TCP *allow* is required. An inet socket there
  is a TCP stream or nothing: the type is compared under `SOCK_TYPE_MASK`, so the
  `SOCK_NONBLOCK`/`SOCK_CLOEXEC` bits neither admit a datagram socket nor refuse a stream, and a
  stream with `IPPROTO_MPTCP` or `IPPROTO_SCTP` is refused because Landlock's port rules are TCP
  rules ([FW-ISO3](../formwork.md#fw-iso3), [FW-INV3](../formwork.md#fw-inv3),
  [FW-ISO11](../formwork.md#fw-iso11), [FW-ISO35](../formwork.md#fw-iso35)). Nothing inside the
  sandbox resolves names under the port tier; host rules restore resolution through the Gateway.
- **A send cannot open a connection.** `sendto`, `sendmsg` and `sendmmsg` with `MSG_FASTOPEN`
  connect a TCP socket inside the send, and the kernel's connect hook -- where Landlock's port rule
  sits -- does not run for it: under the port tier such a send opened a connection to a port that
  `connect()` was refused (verified on 6.18, ABI 7). The second filter returns `EOPNOTSUPP` for the flag
  ([FW-ISO29](../formwork.md#fw-iso29)), which is what a kernel without Fast Open answers, so a
  client falls back to `connect()`. `setsockopt(TCP_FASTOPEN_CONNECT)` needs no rule: the client
  still calls `connect()`.
- **A descriptor cannot be executed under an exec allow-list.** Landlock judges the path being
  executed, and an anonymous memory file has none: `execveat(fd, "", .., AT_EMPTY_PATH)`, which is
  `fexecve`, ran an unlisted program from a memfd. Under an allow-list the second filter returns
  `EACCES` for that flag ([FW-ISO31](../formwork.md#fw-iso31)); with exec unrestricted `fexecve`
  is untouched. One descriptor route stays open: `execve("/proc/self/fd/N")` of a memfd still runs
  under the allow-list (verified on 6.18, ABI 7), because seccomp cannot read the path string and
  Landlock allows an object with no path. `memfd_create` is not refused: language runtimes use it.
  With a granted loader that maps an unlisted file, these routes leave `exec` `Partial`, and the
  reason names each ([FW-FID32](../formwork.md#fw-fid32), [FW-ADV-050](../formwork.md#fw-adv-050)).
- **x32 syscall numbers are refused on x86_64.** A kernel built with `CONFIG_X86_X32_ABI` offers
  every syscall a second time under a number with bit 30 set, and the baseline's rules are keyed
  by the native number. The second filter returns `EPERM` for any number with that bit
  ([FW-ISO33](../formwork.md#fw-iso33)), on every kernel: seccomp runs before dispatch, so where
  the ABI is absent the errno changes from `ENOSYS` to `EPERM` and nothing else does.
- **No inet socket listens under host rules.** The connect supervisor governed the outbound
  direction only. Under host rules a session called `listen` on an inet socket bound to the
  wildcard address, on one bound to loopback, and on one never bound, which `listen` binds to the
  wildcard address itself, and a process outside the session connected to all three (verified on
  6.18). seccomp cannot refuse `listen` alone: it sees a descriptor number, and a UNIX-socket
  listener makes the same call. `listen` now goes to the supervisor, which reads the socket's
  domain and answers `EACCES` for `AF_INET` and `AF_INET6`, loopback included
  ([FW-ISO34](../formwork.md#fw-iso34)). `bind` and `accept` need no rule, because a TCP socket
  takes no connection until it listens.
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

## Effects and entry points

For each effect the Linux backend reports `Enforced` or `Partial`, this table lists every system
call that produces it and the mechanism that mediates each call
([FW-ISO32](../formwork.md#fw-iso32)). A row whose status is `open` names an entry point nothing
mediates, and the quoted clause is part of the reason the compiler gives for each report row the
row names, which is `Partial` for it on Linux ([FW-FID32](../formwork.md#fw-fid32)); a
parenthesis limits the row to the postures named in it (`deny`, `ports`, `hosts`, `allow-list`
for an exec allow-list). A change to the seccomp baseline, the second filter or the notify filter
updates the table in the same change. `entry_points.rs` in `formwork-confine` parses it: each
call a `mediated` row puts under the notify filter, the baseline, the second filter or the socket
allow-list must get that verdict from the compiled filter, and each `open` clause must appear in
the reason ([FW-E2E-190](../formwork.md#fw-e2e-190)). Empty leading cells continue the row above.

<!-- entry-points: begin -->
| Effect | Report rows | System calls | Mechanism | Status |
|---|---|---|---|---|
| Open an outbound TCP connection | `net-default-deny`, `net-port-tier`, `net-host-scope` | `connect` | allow-list under `deny` (no inet socket exists); Landlock `CONNECT_TCP` under the port tier; notify filter under host rules | mediated |
| | | `sendto`, `sendmsg`, `sendmmsg` carrying `MSG_FASTOPEN` | second filter ([FW-ISO29](../formwork.md#fw-iso29)) | mediated |
| | | `sendto` naming a destination, `sendmsg`, `sendmmsg` | notify filter under host rules ([FW-ISO30](../formwork.md#fw-iso30)); elsewhere the kernel ignores a TCP destination without `MSG_FASTOPEN` | mediated |
| | | `io_uring_setup`, `io_uring_enter`, `io_uring_register` (`IORING_OP_CONNECT`) | baseline | mediated |
| Accept an inbound connection | `net-default-deny` | `listen` | allow-list under `deny`; notify filter under host rules ([FW-ISO34](../formwork.md#fw-iso34)) | mediated |
| | | `bind` | Landlock `BIND_TCP` under the port tier | mediated |
| | | `listen` on an unbound socket, then `accept`, `accept4` | nothing under the port tier: Landlock checks `bind`, not the bind `listen` makes | open (ports): "listen() on an unbound socket binds itself to the wildcard address" |
| Send a UDP or raw datagram | `net-udp` | `socket`, `socketpair` of an inet datagram or raw type | allow-list ([FW-ISO11](../formwork.md#fw-iso11)) | mediated |
| Create a socket that reaches off the host | `net-default-deny` | `socket`, `socketpair` | allow-list ([FW-ISO28](../formwork.md#fw-iso28)) | mediated |
| Use a socket from outside the session | `net-default-deny`, `net-udp`, `net-unix-socket`, `cross-domain-socket` | `accept`, `accept4`, `read`, `readv`, `write`, `writev`, `send`, `sendto`, `sendmsg`, `sendmmsg`, `recv`, `recvfrom`, `recvmsg`, `recvmmsg`, `sendfile`, `sendfile64`, `splice`, `vmsplice`, `tee` on a socket `formwork run` inherited or the session received with `SCM_RIGHTS` | nothing: the socket rules act on creation, `connect`, `listen` and addressed sends | open: "a socket the session did not create" |
| Reach a pathname or abstract UNIX socket | `net-unix-socket`, `cross-domain-socket` | `connect`, `sendto` naming a destination, `sendmsg`, `sendmmsg` | notify filter under host rules ([FW-ISO12](../formwork.md#fw-iso12), [FW-ISO30](../formwork.md#fw-iso30)) | mediated |
| | | the same calls under `deny` and the port tier | nothing for a pathname socket; Landlock's scope for an abstract one (ABI 6) | open (deny, ports): "pathname UNIX-socket connect() is unmediated without host rules" |
| Signal a process outside the session | `cross-domain-socket` | `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `pidfd_send_signal` | Landlock's signal scope (ABI 6) | mediated |
| Start a program outside the exec allow-list | `exec` | `execve`, `execveat` of a path | Landlock `EXECUTE` | mediated |
| | | `execveat` with `AT_EMPTY_PATH` | second filter ([FW-ISO31](../formwork.md#fw-iso31)) | mediated |
| | | `execve` of `/proc/self/fd/N` naming a memory file from `memfd_create` | nothing: Landlock allows an object with no path | open (allow-list): "execve of /proc/self/fd/N runs a memory file" |
| | | `mmap`, `mmap_pgoff`, `mprotect`, `pkey_mprotect`, `remap_file_pages` with `PROT_EXEC`, `personality` with `READ_IMPLIES_EXEC`, `uselib`, by a granted loader (`ld.so <file>`) | nothing: Landlock's execute right governs `execve`, not a mapping | open (allow-list): "a granted loader runs an unlisted file it can read" |
| Change a mount | `privileged-interfaces` | `mount`, `move_mount`, `mount_setattr`, `pivot_root` | baseline | mediated |
| | | `umount` (`umount2`), `oldumount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `open_tree`, `open_tree_attr` | the kernel's `CAP_SYS_ADMIN` check | open: "a session that holds CAP_SYS_ADMIN" |
| Change a namespace | `privileged-interfaces` | `unshare`, `clone` with `CLONE_NEWUSER` | baseline | mediated |
| | | `setns` | baseline | mediated |
| | | `clone3` with `CLONE_NEWUSER` | nothing: its flags sit behind a pointer | open: "clone3 with CLONE_NEWUSER creates a user namespace" |
| Reach into another process | `privileged-interfaces`, `process-environment` | `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd` | baseline | mediated |
| | | `openat` of `/proc/<pid>/mem` or `/proc/<pid>/environ`, `process_madvise`, `kcmp`, `migrate_pages`, `move_pages` | Landlock's ptrace scope; `process-environment` says `Partial` where the session holds `CAP_SYS_ADMIN` or `CAP_PERFMON` | mediated |
| Load kernel code, or change kernel state | `privileged-interfaces` | `bpf`, `perf_event_open`, `init_module`, `finit_module`, `kexec_load`, `kexec_file_load`, `keyctl`, `add_key`, `request_key`, `open_by_handle_at` | baseline | mediated |
| | | `delete_module`, `reboot`, `settimeofday`, `clock_settime`, `clock_settime32`, `adjtimex`, `adjtimex_time32`, `clock_adjtime`, `clock_adjtime32`, `stime`, `stime32`, `fanotify_init`, `fanotify_mark`, `iopl`, `ioperm`, `mknod`, `mknodat`, `swapon`, `swapoff`, `sethostname`, `setdomainname`, `acct`, `quotactl`, `quotactl_fd`, `syslog`, `vhangup` | the kernel's capability checks | open: "a session that holds CAP_SYS_ADMIN" |
| Any effect above, under an x32 number | every row | every system call with bit 30 set | second filter ([FW-ISO33](../formwork.md#fw-iso33), x86_64) | mediated |
| Any effect above, through the ia32 entry | every row | `socketcall`, `ipc` and every other call made through `int 0x80` | seccompiler's architecture check, which kills a foreign architecture | mediated |
<!-- entry-points: end -->

Under host rules the supervisor performs every call the notify filter delivers on its own copy of
the socket and of the call's memory, and never answers `CONTINUE` (see "Supervised sends" below).
The open rows are the ones known on 6.18 (x86_64, Landlock ABI 7): the port-tier `listen` and the
`/proc/self/fd/N` exec were observed there; the capability-holder rows follow from the baseline
not listing those calls, and no test issues them, because each acts on the host.

<details>
<summary>System calls with none of these effects (FW-ADV-051)</summary>

Every other entry the x86_64 6.18 kernel exports as `__x64_sys_<name>`, compatibility and
unimplemented entries included. [FW-ADV-051](../formwork.md#fw-adv-051) fails on a kernel that
exports a name in neither the table nor this list, until one of them names it.
Filesystem effects are outside this table.

<!-- inert: begin -->
```text
access alarm arch_prctl brk cachestat capget capset chdir chmod chown chown16 chroot
clock_getres clock_getres_time32 clock_gettime clock_gettime32 clock_nanosleep
clock_nanosleep_time32 close close_range copy_file_range creat dup dup2 dup3 epoll_create
epoll_create1 epoll_ctl epoll_pwait epoll_pwait2 epoll_wait eventfd eventfd2 exit exit_group
faccessat faccessat2 fadvise64 fadvise64_64 fallocate fchdir fchmod fchmodat fchmodat2 fchown
fchown16 fchownat fcntl fdatasync fgetxattr file_getattr file_setattr flistxattr flock fork
fremovexattr fsetxattr fstat fstatfs fstatfs64 fsync ftruncate futex futex_requeue futex_time32
futex_wait futex_waitv futex_wake futimesat futimesat_time32 get_mempolicy get_robust_list
get_thread_area getcpu getcwd getdents getdents64 getegid getegid16 geteuid geteuid16 getgid
getgid16 getgroups getgroups16 gethostname getitimer getpeername getpgid getpgrp getpid getppid
getpriority getrandom getresgid getresgid16 getresuid getresuid16 getrlimit getrusage getsid
getsockname getsockopt gettid gettimeofday getuid getuid16 getxattr getxattrat ia32_fadvise64
ia32_fadvise64_64 ia32_fallocate ia32_ftruncate64 ia32_pread64 ia32_pwrite64 ia32_readahead
ia32_sync_file_range ia32_truncate64 inotify_add_watch inotify_init inotify_init1
inotify_rm_watch io_cancel io_destroy io_getevents io_getevents_time32 io_pgetevents
io_pgetevents_time32 io_setup io_submit ioctl ioprio_get ioprio_set landlock_add_rule
landlock_create_ruleset landlock_restrict_self lchown lchown16 lgetxattr link linkat listmount
listxattr listxattrat llistxattr llseek lremovexattr lseek lsetxattr lsm_get_self_attr
lsm_list_modules lsm_set_self_attr lstat madvise map_shadow_stack mbind membarrier memfd_secret
mincore mkdir mkdirat mlock mlock2 mlockall modify_ldt mq_getsetattr mq_notify mq_open
mq_timedreceive mq_timedreceive_time32 mq_timedsend mq_timedsend_time32 mq_unlink mremap mseal
msgctl msgget msgrcv msgsnd msync munlock munlockall munmap name_to_handle_at nanosleep
nanosleep_time32 newfstat newfstatat newlstat newstat newuname ni_syscall nice old_getrlimit
old_msgctl old_readdir old_semctl old_shmctl olduname open openat2 pause pciconfig_iobase
pciconfig_read pciconfig_write pidfd_open pipe pipe2 pkey_alloc pkey_free poll ppoll
ppoll_time32 prctl pread64 preadv preadv2 prlimit64 process_mrelease pselect6 pselect6_time32
pwrite64 pwritev pwritev2 readahead readlink readlinkat recvmmsg_time32 removexattr
removexattrat rename renameat renameat2 restart_syscall rmdir rseq rt_sigaction rt_sigpending
rt_sigprocmask rt_sigreturn rt_sigsuspend rt_sigtimedwait rt_sigtimedwait_time32 rtas s390_ipc
s390_pci_mmio_read s390_pci_mmio_write sched_get_priority_max sched_get_priority_min
sched_getaffinity sched_getattr sched_getparam sched_getscheduler sched_rr_get_interval
sched_rr_get_interval_time32 sched_setaffinity sched_setattr sched_setparam sched_setscheduler
sched_yield seccomp select semctl semget semop semtimedop semtimedop_time32 set_mempolicy
set_mempolicy_home_node set_robust_list set_thread_area set_tid_address setfsgid setfsgid16
setfsuid setfsuid16 setgid setgid16 setgroups setgroups16 setitimer setpgid setpriority setregid
setregid16 setresgid setresgid16 setresuid setresuid16 setreuid setreuid16 setrlimit setsid
setsockopt setuid setuid16 setxattr setxattrat sgetmask shmat shmctl shmdt shmget shutdown
sigaltstack signal signalfd signalfd4 sigpending sigprocmask sigsuspend spu_create spu_run
ssetmask stat statfs statfs64 statmount statx subpage_prot symlink symlinkat sync
sync_file_range sync_file_range2 syncfs sysfs sysinfo time time32 timer_create timer_delete
timer_getoverrun timer_gettime timer_gettime32 timer_settime timer_settime32 timerfd_create
timerfd_gettime timerfd_gettime32 timerfd_settime timerfd_settime32 times truncate umask uname
unlink unlinkat uprobe uretprobe userfaultfd ustat utime utime32 utimensat utimensat_time32
utimes utimes_time32 vfork vm86 vm86old wait4 waitid waitpid
```
<!-- inert: end -->

</details>

## Posture: build in the parent, apply in the child

To avoid `malloc`-after-`fork` hazards, do all allocation-heavy work **before** the fork and apply
the finished artifacts in the `pre_exec` closure (which runs in the forked child, before `execve`):

1. **Parent, before `Command::pre_exec`:** expand the read/write sets against the filesystem
   (see below), open `PathFd`s, build the Landlock `RulesetCreated` (accumulates kernel state behind
   a ruleset fd — does *not* restrict the parent until `restrict_self`), and compile the two seccomp
   `BpfProgram`s. Move them into the closure.
2. **Child, inside `pre_exec`:** `prctl(PR_SET_NO_NEW_PRIVS, 1)` → `ruleset.restrict_self()` →
   `apply_filter` for the baseline, then for the second filter (and, under host rules, the notify
   filter last). These are syscalls only; no allocation. Then `execve` proceeds.

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
  governed and granted only on the allow-list; [FW-E2E-188](../formwork.md#fw-e2e-188) runs a listed
  program and is refused an unlisted one on the kernel. The ELF interpreter of a dynamically linked
  program needs the right too.)
- **Net default-deny via seccomp (all ABIs), *not* Landlock.** Landlock net governs only TCP, so a
  Landlock-carried deny leaves UDP/raw open. Deny admits no inet `socket(2)` instead
  (TCP + UDP + raw); Landlock net (`handle_access(AccessNet::from_all(abi))` + `NetPort` allows) is
  reserved for the **port tier** (ABI ≥ v4), which needs per-port TCP *allow*. The port tier still
  refuses inet **DGRAM/RAW** `socket(2)` (type masked to `SOCK_TYPE_MASK` so
  `SOCK_NONBLOCK`/`SOCK_CLOEXEC` cannot evade it) while admitting a TCP STREAM, so UDP/raw egress fails
  closed. Only the granted TCP ports connect, by `connect()` or by a send: the Landlock rule covers
  the first and the `MSG_FASTOPEN` refusal the second
  ([FW-ISO3](../formwork.md#fw-iso3)/[FW-INV3](../formwork.md#fw-inv3)/[FW-ISO29](../formwork.md#fw-iso29)).
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
Syscall numbers come from `libc::SYS_*` (correct for the compiled arch).

The socket allow-list ([FW-ISO28](../formwork.md#fw-iso28)) is written as its complement, because a
rule names what is refused: rules on one syscall are ORed and a rule's conditions ANDed. One rule
refuses a domain that equals none of the admitted ones; each admitted domain adds one rule per way
to miss its predicate. The same rules sit on `socket` and `socketpair`.

```rust
// net = "deny": admitted = AF_UNIX, AF_NETLINK/NETLINK_ROUTE
[domain != AF_UNIX, domain != AF_NETLINK]            // any other family, known or not
[domain == AF_NETLINK, protocol != NETLINK_ROUTE]
// port tier / host rules add, for AF_INET and again for AF_INET6:
[domain == AF_INET, (type & bit) == (!SOCK_STREAM & bit)]   // one per bit of SOCK_TYPE_MASK
[domain == AF_INET, protocol != 0, protocol != IPPROTO_TCP]
```

`seccompiler` has no masked not-equal, so "the type is not `SOCK_STREAM`" is one rule per type bit
that differs from `SOCK_STREAM`'s. Comparisons are 32-bit (`Dword`), as the kernel reads these
`int` arguments.

### The second filter

`seccompiler` keys a rule by one syscall number and gives a filter one errno, so the refusals that
need a number range or their own errno are a second, hand-written classic-BPF program installed
after the baseline (`seccomp.rs`, `bound_filter`). Stacked filters all run and the kernel takes
the most restrictive result. In order it: leaves a foreign architecture to the baseline, which
kills it; on x86_64 refuses a number with bit 30 set ([FW-ISO33](../formwork.md#fw-iso33)); refuses
`sendto`/`sendmsg`/`sendmmsg` whose flags carry `MSG_FASTOPEN` with `EOPNOTSUPP`
([FW-ISO29](../formwork.md#fw-iso29)); and, under an exec allow-list, refuses `execveat` whose
flags carry `AT_EMPTY_PATH` with `EACCES` ([FW-ISO31](../formwork.md#fw-iso31)). Each block's jumps
are local to it. A unit test interprets both programs for chosen `(number, arguments)` pairs
([FW-E2E-205](../formwork.md#fw-e2e-205)): CI kernels lack the x32 ABI, so no real call there
reaches what the bound guards.

### Connect supervision and the isolation tier (FEP-5)

- **Supervised connect ([FW-EGR7](../formwork.md#fw-egr7), [FW-ISO12](../formwork.md#fw-iso12)).**
  Under host rules a second seccomp filter returns `SECCOMP_RET_USER_NOTIF` for `connect`, for
  `sendto` with a non-null destination, for every `sendmsg` and `sendmmsg`, and for `listen` (x32
  numbers are refused outright). The `formwork` process takes the listener (see "Supervised
  sends"). For `connect` and `sendto` the
  supervisor copies the `sockaddr` once, re-checks the
  notification id, takes the socket with `pidfd_getfd` and performs the call itself, so a thread
  rewriting the address after the check changes nothing ([FW-ADV-018](../formwork.md#fw-adv-018)).
  Inet goes to the Gateway only, from a source port the supervisor registers first, so the Gateway
  listener admits exactly the connections the supervisor made ([FW-EGR9](../formwork.md#fw-egr9));
  this is the Linux counterpart of the macOS peer check. The port is registered before the
  connect, because the listener can accept before `connect` returns to the supervisor, and the
  listener removes it at that accept. A connect that makes no connection would leave it behind
  for another process to connect from, so the supervisor takes it back: at once when the call
  fails, and for a non-blocking socket, whose call returns `EINPROGRESS`, after a `poll` of up to
  2 s shows the handshake failed or unfinished ([FW-EGR37](../formwork.md#fw-egr37)). `poll`
  leaves the pending error for the session to read. A repeat `connect` on a socket whose first
  registration the listener has not taken yet leaves that registration alone. A pathname socket
  is admitted when a literal write grant names it, when a lifted channel's facility owns it (the session bus and user
  manager for `run-outside`, the display socket for `clipboard` and `screen`, the audio socket for
  `microphone`; the keyring sockets and the session bus when `os-keyring` is lifted), or when a
  session process bound it, which is decided from `sock_diag` or, on kernels without
  `CONFIG_UNIX_DIAG`, `/proc/net/unix`. An abstract socket is refused. Sends follow the same
  rule (see "Supervised sends" below). A loopback server the session itself starts is
  refused too: its `listen` is refused, and a `connect` to it would be, because the supervisor
  admits inet only to the Gateway (FEP-6 §11, "In-session loopback";
  [FW-E2E-106](../formwork.md#fw-e2e-106) waits on it). Requires 5.6+ (`pidfd_getfd`) and
  Yama `ptrace_scope` 0 or 1; host detection probes all three.
- **Supervised sends ([FW-ISO30](../formwork.md#fw-iso30)).** A `sendmsg` or `sendmmsg` can
  name a destination in its `msghdr`, which seccomp cannot read, and a UNIX datagram socket sends
  to any pathname or abstract socket it names: under host rules a session sent a datagram that
  way to a socket `connect()` was refused (verified on 6.18). The notify filter therefore delivers
  every `sendmsg` and `sendmmsg`, with or without a destination, alongside `connect`, `listen` and
  a `sendto` whose destination pointer is set. The supervisor copies the `msghdr`, the
  destination, the payload (up to 256 KiB a message; a stream send of more returns a short count,
  a datagram of more `EMSGSIZE`) and the control messages out of the caller once, decides each
  destination on that copy -- an inet one is refused, a pathname one is admitted as `connect()`
  admits it, a route netlink one as the kernel admits it for a caller without `CAP_NET_ADMIN` --
  and sends the copy itself on its duplicate of the socket. It never answers `CONTINUE`, for a
  call that names no destination either: the kernel would then read the `msghdr` again, and look
  the descriptor number up again, after the check. Probes rewriting the `msghdr` and swapping the
  descriptor from a second thread delivered datagrams to a foreign socket against a build that
  answered `CONTINUE` for those calls, and none against this one. A `sendmmsg` sends its entries
  in order and stops at the first refused one, returning the count sent, as the kernel does at a
  failing entry, and the supervisor writes each entry's `msg_len` back. Descriptors in an
  `SCM_RIGHTS` message are replaced by the supervisor's duplicates of the caller's; an
  `SCM_CREDENTIALS` message is dropped, because the kernel checks one against the sending
  process, so a receiver sees the `formwork` process's credentials, as `SO_PEERCRED` already
  names it for a connection the supervisor made. Each send is made non-blocking; a caller that
  asked to block waits in a worker thread, which retries when the socket is writable for as long
  as the notification is pending and honours `SO_SNDTIMEO`, so one blocked send does not hold up
  the session's other calls. The send runs with `MSG_NOSIGNAL`, and the caller gets `SIGPIPE`
  afterwards when it did not ask for that flag. `MSG_ZEROCOPY` is refused with `ENOBUFS`, on
  which a zero-copy sender copies instead. The same rule governs a route netlink `connect()` or
  send, which the supervisor once answered with `CONTINUE`: a probe flipping a descriptor number
  between a netlink and a TCP socket connected the TCP socket to a listener the supervisor
  refuses, in each of three runs on 6.18. The listener reaches the parent by a `write` of its
  descriptor number, with the writer's credentials attached (`SO_PASSCRED`), and the parent takes
  it with `pidfd_getfd` on a thread of its own while `Command::spawn` waits for the `execve`: the
  `sendmsg` with `SCM_RIGHTS` the handoff used before would now wait on the supervisor it is
  handing over. Cost: a `sendmsg` on a connected socket goes through the supervisor, about 35 to
  45 µs a call against about 1 µs unsupervised on a 4-vCPU VM (6.18), of which about 26 µs is
  the notification round trip itself. A send by `write`, `writev` or a `sendto` that names no
  destination is not delivered: curl, Python, Node and Go send that way on TCP.
- **Supervised listen ([FW-ISO34](../formwork.md#fw-iso34)).** The supervisor takes the caller's
  socket with `pidfd_getfd` after re-checking the notification id, as for `connect`, and reads
  `SO_DOMAIN` from its own copy. `AF_INET` and `AF_INET6` get `EACCES` and an operator line; a
  descriptor that is no socket gets the kernel's errno for it. For any other socket the supervisor
  calls `listen` itself, with the caller's backlog, on that copy, and returns the result. It does
  not answer `CONTINUE`: the kernel would then look the descriptor number up a second time, in the
  calling thread's table, and the socket there need not be the one that was checked. Two cases
  make them differ, and a probe runs both
  (`fw_iso34_listen_acts_on_the_socket_it_checked`): a second thread replaces the descriptor
  between the check and the call, which made an inet socket listen in each of five 300 ms runs
  against a build that answered `CONTINUE` (6.18); and a thread that has called
  `unshare(CLONE_FILES)` has a table of its own, while `pidfd_getfd` reads the thread group
  leader's. One effect is visible to a client: the kernel stamps a UNIX listener with the
  credentials of the process that called `listen`, so `SO_PEERCRED` on a connection to a
  session's UNIX listener names the `formwork` process
  ([FW-E2E-206](../formwork.md#fw-e2e-206) records it). A listening inet socket the session did
  not make listen is outside this rule: one already listening when `formwork run` inherited it,
  or one passed to the session over a granted UNIX socket. `io_uring`, whose `IORING_OP_LISTEN`
  would not reach the filter, is refused by the baseline.
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
- **netlink — resolved.** Of `AF_NETLINK` only `NETLINK_ROUTE` (what NSS /
  `getaddrinfo` / `getifaddrs` use) is admitted. Fork+exec transparency verified; full reuse-
  workload confirmation is still owed for pytest/npm name resolution under the *port tier*.
- **`CLONE_NEWUSER` flag test** (`SeccompCmpOp::MaskedEq`, arg0) — verified on aarch64; the arch guard
  (`TargetArch::try_from`) rejects any arch where `clone`'s flags are not arg0.
- **Syscall coverage — fail-loud.** `syscall_number` is an explicit match; an unresolved baseline name
  aborts the build ([FW-INV6](../formwork.md#fw-inv6)) rather than silently dropping a rule. All baseline names resolve on
  x86_64/aarch64, including the hardening additions (`io_uring_*`, `pidfd_getfd`, `process_vm_*`).

Still owed: the Phase-4 reuse workloads (pytest/npm/cargo) under the baseline on a real kernel to
fully establish *transparency* ([FW-TRA2](../formwork.md#fw-tra2)) beyond the fork+exec + `/proc/self` cases already verified.
