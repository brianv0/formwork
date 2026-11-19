# FEP-14 (proposal): the Linux kernel surface beyond `connect()` and `execve(path)`

**Formwork Enhancement Proposal 14 — proposal, not landed.** This draft describes escapes found in
a security review of `main` at `e6e4572`; none is fixed yet. Companion to `formwork.md`,
`constitution.md` and `docs/linux-backend.md`.

**Status.** Nothing here mutates the landed spec. New identifiers are draft numbering in inline
code. This FEP holds `FW-ISO28`..`FW-ISO32`, `FW-FID32`, `FW-E2E-185`..`FW-E2E-190` and
`FW-ADV-050`..`FW-ADV-052`, above FEP-8's `FW-ISO27` and FEP-13's test block.

---

## 1. Problem

The Linux backend closes network egress and program execution by mediating one entry point for
each: `connect(2)` (Landlock's TCP rule, or the seccomp notify filter) and `execve` of a path
(Landlock's execute right). The kernel has other entry points to the same effects.

| Effect | Mediated entry point | Unmediated entry point | Verified |
|---|---|---|---|
| Open a TCP connection | `connect` | `sendto` / `sendmsg` / `sendmmsg` with `MSG_FASTOPEN` | port tier: data delivered to a port that plain `connect` was refused |
| Reach something off the machine | `socket(AF_INET*)` | `socket(AF_VSOCK)`, and every family not on the deny-list | `net = "deny"`: vsock socket created, connect reached the host transport |
| Run a program | `execve(path)` | `fexecve` of a memfd (`execveat` with `AT_EMPTY_PATH`) | allow-list of one static binary ran a second, unlisted one |

The report says `enforced` for `net-port-tier`, `net-default-deny` and `exec` in all three cases.
Each is a deny-list or a single-hook design meeting a kernel that has more than one door:
`crates/formwork-compile/src/linux.rs:66-84` lists four socket families to deny;
`crates/formwork-confine/src/linux/supervise.rs:145-160` notifies on two syscalls;
`BASELINE_DENY` contains neither `memfd_create` nor `execveat`.

PR #38 already lowers Linux `exec` to `Partial` for the `ld.so <file>` route. This FEP treats the
three findings as one class and states the rule that keeps a fourth from appearing.

### 1.1 Constraints

- **Reuse.** The baseline cannot refuse syscalls ordinary toolchains need. `memfd_create` is used
  by language runtimes and JITs; `sendmsg` is every socket write.
- **seccomp reads scalars only.** A flags argument can be tested; a `sockaddr` or `msghdr` behind
  a pointer cannot, except through user notification.
- **No claim beyond the mechanism.** What stays open is a `Partial` reason and a test that
  asserts it stays open, in the manner of #38's `FW-E2E-107`.

## 2. Design

### 2.1 Socket families: an allow-list

`SeccompPlan` carries the families the posture admits, and every other family is refused at
`socket(2)` and `socketpair(2)` with `EPERM`.

| Posture | Admitted families |
|---|---|
| `net = "deny"` | `AF_UNIX`; `AF_NETLINK` with protocol `NETLINK_ROUTE` |
| port tier | the above, and `AF_INET`/`AF_INET6` of type `SOCK_STREAM` |
| host rules (supervised connect) | the same as the port tier |
| `net = "allow"` | no family filter |

A family a future kernel adds is refused without a code change. `AF_VSOCK` gets no blueprint
knob: a session that needs it is not a session this tool confines, and Growth says no until
someone shows the need.

### 2.2 Fast Open: refuse the flag

The baseline refuses `sendto`, `sendmsg` and `sendmmsg` when the flags argument has
`MSG_FASTOPEN` set (argument 3 for `sendto` and `sendmmsg`, argument 2 for `sendmsg`), with
`EOPNOTSUPP`, on every posture that admits stream sockets. Clients fall back to `connect`; the
flag is an optimization and the errno is the one a kernel without the feature returns.

`setsockopt(TCP_FASTOPEN_CONNECT)` needs nothing: with it the client still calls `connect`, and
the connect hook runs.

For the supervised posture the notify filter additionally notifies on `sendmsg` and `sendmmsg`
whose `msghdr` carries a destination, which it must read through the notification as it reads
`sendto`'s today. That closes an addressed send on an unconnected stream socket by any future
route, not only this flag. Cost: one notification per addressed `sendmsg`, which for a connected
TCP socket is none.

### 2.3 Exec: close what a flag can close, report the rest

Under an exec allow-list:

- `execveat` with `AT_EMPTY_PATH` set in its flags argument is refused with `EACCES`. This is
  `fexecve` on every libc that implements it with `execveat`.
- `execve` of `/proc/self/fd/N` (the fallback older libcs use) resolves through a magic link to an
  object with no path. Landlock does not apply a path rule to it. Characterize whether the
  Landlock execute check runs for a memfd reached this way; if it does not, this route stays open.
- `memfd_create` is not refused. A process can also map a readable file as code without any exec
  (the `ld.so` route of #38).

The Linux `exec` row stays `Partial`. Its reason names every route known to be open: a granted
loader started on an unlisted file; an executable mapping of a readable file; and, if the
characterization says so, `/proc/self/fd` exec of a memfd. `docs/linux-backend.md` removes the
sentence that an `AT_EXECVE_CHECK`-aware loader is the way back to `Enforced`, or qualifies it.

### 2.4 The rule that stops the fourth case

`docs/linux-backend.md` gains a table, **effects and entry points**: for each effect the backend
claims to close (TCP connect, UDP send, raw send, off-host socket, program start, mount,
namespace change, ptrace), every syscall that can produce it, and for each the mechanism that
mediates it or the word "open" with the report row that says so. A change to the seccomp
baseline or the notify filter updates the table in the same change. The table is the review
artifact; `FW-FID32` binds the report to it.

## 3. Surface changes (each measured against Growth)

| Change | Note |
|---|---|
| Compiled Linux policy: `allow-socket-families` replaces `deny-socket-families` | a CompiledPolicy shape change (Data model); no release has shipped it |
| Baseline: three flag-conditional refusals, one `execveat` flag refusal | no new syscall refused outright |
| Notify filter: `sendmsg`, `sendmmsg` | supervised posture only |
| Three new probe binaries in `formwork-confine/src/bin` | `fw-tfo-probe`, `fw-family-probe`, `fw-memfd-exec-probe` |

No blueprint field, flag, concept or dependency.

## 4. Proposed requirements (draft numbering)

| ID | Statement |
|---|---|
| `FW-ISO28` Socket-family allow-list | On Linux, for every net posture other than `allow`, the Confiner shall refuse creation of a socket of any address family not in the posture's admitted set (FEP-14 §2.1). |
| `FW-ISO29` No connection by send | On Linux, for every posture that admits stream sockets, the Confiner shall refuse a `sendto`, `sendmsg` or `sendmmsg` call carrying `MSG_FASTOPEN`. |
| `FW-ISO30` Supervised addressed sends | Under supervised connect, the Gateway shall receive every `sendto`, `sendmsg` and `sendmmsg` that names a destination, and shall refuse one whose destination is an inet address. |
| `FW-ISO31` No exec by descriptor | On Linux, under an exec allow-list, the Confiner shall refuse `execveat` with `AT_EMPTY_PATH`. |
| `FW-ISO32` Entry-point table | `docs/linux-backend.md` shall list, for each effect the Linux backend reports `Enforced` or `Partial`, every system call that produces the effect and the mechanism that mediates each. |
| `FW-FID32` Open entry points are reported | For each entry point the table of `FW-ISO32` marks open, the compiler shall report the affected capability `Partial` on Linux with a reason naming the entry point. |

## 5. Verification plan

Each test is a paired probe against the kernel: the mediated call is refused and the formerly
unmediated call is refused, or, for a route left open, the route is shown to work and the report
says `Partial`.

| ID | Test |
|---|---|
| `FW-E2E-185` | Port tier, ports `[443]`: `connect` to another port refused; `sendto`, `sendmsg` and `sendmmsg` with `MSG_FASTOPEN` to that port each refused; a listener on it receives nothing. Run with `tcp_fastopen` client-enabled, and fail (not skip) where it is not. |
| `FW-E2E-186` | The same three calls under supervised connect with a host rule: refused, and the Gateway records no connection. |
| `FW-E2E-187` | `net = "deny"`: `socket()` for `AF_VSOCK`, `AF_ALG`, `AF_XDP`, `AF_PACKET`, `AF_BLUETOOTH` and an unassigned family number each return `EPERM`; `AF_UNIX` succeeds. |
| `FW-E2E-188` | Exec allow-list of one static binary: `fexecve` of a memfd copy of an unlisted binary is refused. |
| `FW-E2E-189` | Reuse: `git`, `curl`, `python3 -c 'import socket'`, `node -e` and a `cargo build` each run under the default profile with the new baseline (no regression from the flag refusals). |
| `FW-E2E-190` | `compile` for a Linux host: the `exec` reason names each open route in the entry-point table; a harness canary parses the table and fails when a row marked open has no matching reason text. |
| `FW-ADV-050` | The stated limit for exec: the open routes (loader on an unlisted file; `/proc/self/fd` exec if characterized open) run the unlisted program, and the verdict is `Partial`. |
| `FW-ADV-051` | A sweep: for each syscall number in the running kernel's table not named in the entry-point table, the probe calls it with zeroed arguments under `net = "deny"` and records the result; a new syscall that returns something other than `ENOSYS`/`EPERM`/`EINVAL`/`EFAULT`/`EBADF` fails the test until the table has a row for it. Runs on the newest CI kernel. |
| `FW-ADV-052` | `io_uring`: `IORING_OP_CONNECT` and `IORING_OP_SENDMSG` under each posture. `BASELINE_DENY` refuses `io_uring_setup`, `io_uring_enter` and `io_uring_register` today, so no ring exists to submit to; the test pins that, because a ring would carry both operations past the connect hook's seccomp half. |

**Phasing.** A: `FW-ISO28`, `FW-ISO29`, `FW-ISO31` and their tests (seccomp only). B: `FW-ISO30`
(notify filter). C: `FW-ISO32`, `FW-FID32`, `FW-ADV-051`. Phase A closes the three reported
findings and can land as fixes ahead of this FEP's adoption.

## 6. Amendments (apply on landing)

- `formwork.md` §5: the rows of §4. [FW-ISO3](../formwork.md#fw-iso3) text: "seccomp
  socket-family allow-list" for "seccomp inet-socket deny". §9 matrix: Linux `exec` reason.
- `docs/linux-backend.md`: the entry-point table; correct `:29-34` ("matching macOS `(deny
  network*)`" becomes true with §2.1) and `:98-100`.
- `docs/STATUS.md`: Phase 7 row.

## 7. Decisions

- **Allow-list, not a longer deny-list.** A deny-list is wrong again at the next kernel release.
- **Refuse the Fast Open flag for every posture**, the supervised one included, where the notify
  filter would also catch it: two mechanisms, and the cheaper one needs no supervisor.
- **Do not refuse `memfd_create`.** It breaks runtimes, and the `ld.so` route means refusing it
  would not make the row `Enforced`.

## 8. Open questions

| Question | Owner | Closes at |
|---|---|---|
| Does Landlock's execute check run for `execve("/proc/self/fd/N")` on a memfd, on ABI 1 through 7? | implementer | spike before phase A |
| Do any of the clients in the `FW-E2E-094` matrix send with `MSG_FASTOPEN` and fail to fall back on `EOPNOTSUPP`? | implementer | phase A, measured in CI |
| Is `AF_NETLINK`/`NETLINK_ROUTE` needed under `net = "deny"`, or only where a resolver or `getifaddrs` runs? | reviewer | adoption |
| Should the supervisor become multi-threaded before `FW-ISO30` adds load to it? It serves notifications serially and calls blocking `connect()` inline today. | implementer | phase B |
