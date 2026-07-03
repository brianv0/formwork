# Phase 0 spike notes

Short programs answering the questions the whole design leans on, run before building on the
assumptions (plan §4, Phase 0). Each entry records the question, the finding, and any design
amendment. macOS spikes run natively here; Linux spikes are deferred until a Linux kernel is
available (Docker/Lima) and are marked as such.

## Spike 1 — Seatbelt vs. inherited connected fds (macOS) — **load-bearing for the fd seam**

**Question.** Under an SBPL profile with `(deny network*)`, does read/write on an *already
connected* inherited socket still work? The entire fd-seam design (FW-XR7) assumes yes: the gateway
connects outside the sandbox and hands the agent a connected fd, and the agent never calls
`connect()`. If Seatbelt re-checks data transfer (not just `connect`/`bind`) against `network*`,
the seam needs a scoped allowance and we must find that out now, not in Phase 5.

**Method.** Parent creates a `socketpair(AF_UNIX)`, and (separately) a connected `AF_INET` loopback
pair; forks; child applies a `(deny network*)` profile via `sandbox_init`; child then `read`/`write`
on the inherited fds. Also test whether a fresh `connect()` inside is denied (it must be).

**Status.** Pending native run as part of Phase 3 wiring. Recorded here so the result is captured
against the assumption it protects.

## Spike 2 — `sandbox_init` from Rust in a forked child (macOS)

**Question.** Is the deprecated `sandbox_init(3)` callable from Rust via direct FFI, does the
profile survive `execve`, is it inherited by descendants, and is the error path reportable on
macOS 26?

**Method.** Declare `sandbox_init`/`sandbox_free_error` FFI; fork; `sandbox_init` in the child;
`execve` a probe that attempts an out-of-scope read; assert denial. Deliberately pass a malformed
profile once to confirm the error string round-trips.

**Finding (resolved, macOS 26.5 / darwin 25.5).** `sandbox_init(profile, 0, &err)` compiles and
applies an SBPL *string* directly (flags = 0; the `sandbox-exec -p` / older-Chromium path). It is
callable from Rust with a three-symbol extern block against libSystem — no crate needed. The
profile survives `execve` and is inherited by descendants: `FW-E2E-005` (a `sh -> cat` grandchild)
is denied an out-of-scope read. The error path round-trips a readable string via the out-pointer.

**Discovery that amended the design — Closed-read profiles and dyld.** A naive
`(deny file-read* (subpath "/"))` makes every `execve`'d program `SIGABRT` (exit 134): the dynamic
loader can't read its own code. Two things are required for the ambient toolchain to load under a
closed read profile, and are now emitted by the SBPL generator:

1. `(allow file-read* (literal "/"))` — the root directory *inode* itself must be readable (the
   loader traverses it). This is the `/` entry only, not its subtree, so denied subdirs stay denied.
2. a fixed allowlist of system runtime dirs (`/System`, `/usr/lib`, `/usr/bin`, `/bin`, …).

`(allow file-read-metadata)` is also emitted so `stat` stays broadly available (consistent with
"deny, not ENOENT", FW-CAP4). With these, an in-scope read succeeds, an out-of-scope read returns
EPERM, and `/etc/passwd` is denied.

**Discovery — macOS firmlinks.** Grant paths under `/var`, `/tmp`, `/etc` must be canonicalized to
their `/private/...` real paths before enforcement, because Seatbelt matches the resolved path. This
canonicalization is an impure step done at spec load for the enforce path (like `~` expansion), not
in the pure compiler, and not for cross-platform dry-run compiles.

**Discovery — device nodes (feeds Phase 4).** Interpreters need `/dev/urandom` at startup (CPython
aborts in `_Py_HashRandomization_Init` without it), and `> /dev/null` needs `/dev` write. These are
emitted as a **curated literal allowlist** of safe nodes — never `(subpath "/dev")`, which would
expose `/dev/rdisk*` (the raw disk) and let a confined process read the whole filesystem out of
band. With the device nodes allowed, a confined `python3` starts fully and its `connect()` is denied
at the syscall (verified: exit 7 / `PermissionError`), proving egress denial is real and not a
startup artifact.

**Discovery — unreadable cwd breaks interpreters (feeds Phase 4).** Python puts the cwd on
`sys.path`; if the cwd is outside the read grant, the import machinery raises an uncaught
`PermissionError`. In the real reuse scenario the project dir is granted and is the cwd, so this is
benign — but the default-profile/reuse work (Phase 4) must ensure the working directory is always
within the read scope, and the CLI should default the child's cwd into the grant.

## Spike 3 — seccomp `socket(2)` domain filtering vs. toolchains (Linux) — deferred

**Question.** Does denying `AF_INET/AF_INET6/AF_PACKET` (and non-route `AF_NETLINK`) `socket(2)`
creation break resolver/toolchain paths that pytest / npm actually hit (e.g. `getifaddrs`,
NSS)? Net default-deny below Landlock ABI v4 depends on this being transparent enough.

**Status.** Deferred until a Linux env is wired. The compiler already encodes the plan
(`SeccompPlan.deny_socket_families`) so the spike only needs to validate transparency.

## Linux detection + degraded-host honesty — verified on real Linux (Docker, kernel 5.10)

Not one of the original four spikes, but a verification worth recording. The Docker Desktop VM
kernel is `5.10.104-linuxkit`, which predates Landlock (5.13). Running the `formwork` binary there
(built in-container) confirmed, on a genuine Linux kernel:

- **`formwork-detect` works** — the `landlock_create_ruleset(NULL,0,VERSION)` probe and
  `prctl(PR_GET_SECCOMP)` check (written on macOS, never before run on Linux) correctly report
  `landlock-abi: null, seccomp: true, os-version: 5.10.104-linuxkit`.
- **Degraded-host honesty holds (FW-E2E-025/026, FW-INV6)** — compiling a normal spec on this host
  reports `fs-read`/`fs-write` as `Unenforceable` (Landlock absent), while `net-default-deny` stays
  `Enforced` via seccomp. The report does not lie, and net fails closed rather than silently open.

This is the honesty invariant proven on a real degraded host, not just in synthetic-profile tests.
The Landlock *enforcement* still needs a 5.13+ kernel (Lima) to verify — see docs/linux-backend.md.

## Spike 4 — Landlock subtractive-expansion cost (Linux) — deferred

**Question.** Enumerate-and-grant over a realistic `$HOME` to convert "read all minus sensitive"
into Landlock allow rules — does it stay within the 50 ms spawn budget (design §8)?

**Status.** Deferred until a Linux env is wired.
