# FEP-5 execution record

Companion to `fep-5.md` (what and why). This records how FEP-5 was built, where the build departed
from the proposal and why, and what is still owed. Requirement and test IDs are defined in
`formwork.md`, where FEP-5's were folded after landing, anchored there, and cited bare in code.

## 1. What landed, by phase

Each phase landed as its own commit on the implementation branch, with the report honest at each
boundary (§6.5).

| Phase | Scope | Where |
|---|---|---|
| 0 | The eleven §2 defects, D1–D11 | `formwork-compile` (withheld rows, reasons), `formwork-confine` (Linux essentials, `/proc`), `formwork-gateway` (frame kinds), `formwork-cli` (`.formwork/` discovery, D10 refusal), `profiles/default.toml` |
| 1 | Channels and privileged interfaces, environment disclosure, private tmp, report lines, host-session detection | `formwork-blueprint/src/channel.rs`, `formwork-compile` (`baseline_rows`, SBPL channel denies), `formwork-detect` (`HostFacilities`) |
| 2 | Host rules, the Gateway egress listener, the Linux connect supervisor, the macOS endpoint | `formwork-blueprint/src/egress.rs`, `formwork-gateway/src/egress.rs`, `formwork-confine/src/linux/supervise.rs` |
| 3 | TLS inspection and credential brokering | `formwork-gateway/src/{ca,inspect}.rs`, `formwork-blueprint/src/credential.rs`, the session CA and placeholders in `formwork-cli` |
| 4 | The Linux isolation tier | `formwork-confine/src/linux/isolate.rs`, the stage entry in `formwork-cli` |
| — | The `open-url` opener shim and brokered open | `formwork-gateway/src/opener.rs`, the shim directory in `formwork-cli` |
| — | Host and channel discovery in `learn` | `propose_host_rules`/`propose_channels` in `formwork-blueprint/src/discovery.rs`, proposal entries in `formwork-cli/src/learn.rs` |
| — | §7 amendments, examples, CI | `formwork.md`, `fep-1.md`, `unstated-requirements.md`, `constitution.md`; `examples/blueprints/`; `.github/workflows/ci.yml` |

## 2. Mechanisms, as built

**Connect supervisor (Linux).** A second seccomp filter returns `USER_NOTIF` for `connect` and for
`sendto` with a destination; the listener crosses to the `formwork` process over a socketpair with
`SCM_RIGHTS`. The supervisor copies the `sockaddr` once with `process_vm_readv`, re-checks the
notification id, takes the target's socket with `pidfd_getfd`, and performs the operation itself.
Inet destinations go to the Gateway only, and the source port is registered so the Gateway admits
only supervisor-made connections (`FW-EGR9`). Pathname sockets are admitted when granted or bound
by a session process: UNIX socket diagnostics when the kernel has them, else `/proc/net/unix`
resolved from the binder's root. The supervisor resolves paths through `/proc/<pid>/root`, so it
works across the isolation tier's mount namespace.

**Gateway egress listener.** An HTTP proxy on `127.0.0.1:0` in its own thread and runtime, gated by
a per-session `Proxy-Authorization` credential. CONNECT tunnels and plain-HTTP absolute form are
served; the target is canonicalized (`FW-EGR3`), resolved once and pinned, and restricted addresses
are refused unless a rule names them (`FW-EGR4`). Every refusal is one operator line with the
`explain` invocation that reproduces it (`FW-FID9`), and carries what the session needed for
`learn`.

**Inspection and brokering.** A per-session CA made by `rcgen`, held in memory; leaves are minted per
host. TLS is `rustls` with the `ring` provider, HTTP/1.1 only. SNI and `Host` must match the CONNECT
target (`FW-EGR10`); paths are canonicalized and framing is strict (`FW-EGR11`). The upstream is
verified against the host trust store. The trust bundle (the CA plus the host roots) is written
0400 into a Launcher-owned directory beside the session temp directory, readable and
write-protected in every read mode, and exported through `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`,
`REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` and `PIP_CERT`. A brokered credential's
secret is read from the launching environment; the confined environment carries
`fwcred-<type>-<nonce>` in the same variable; the Gateway substitutes it or sets the scheme's header
on bound hosts, refuses it on any other host and over plain HTTP, and scrubs the secret from
responses (`FW-INV13`). A brokered credential with no value refuses the run before spawn.

**Isolation tier (Linux).** `formwork` cannot `unshare(CLONE_NEWUSER)` itself (it is
multi-threaded), and a `pre_exec` closure cannot fork a PID-1 init or build Landlock rules after
mounting. So the spawn runs the `formwork` binary again as a single-threaded stage, marked by an
environment variable that names a memfd holding the policy. The stage unshares the namespaces and
maps its own uid and gid. Under `processes` it forks a minimal init as PID 1, which mounts a fresh
`/proc` and a tmpfs over the session temp directory and forks the workload's process. That process
builds and applies the ordinary Landlock and seccomp plan against the new mounts and execs the
workload. The stage and the init relay user-sent signals and pass the workload's status through
(128 + signal for a signal death). `detect` probes the whole tier, the `/proc` mount included, so
a host that cannot carry it is refused before spawn.

**Opener shim.** In every spawned session the Launcher writes a POSIX shell script under the names
`xdg-open`, `open`, `sensible-browser`, `x-www-browser` and `www-browser` into a Launcher-owned
directory, first in `PATH` and in `BROWSER`. The script writes each URL to an inherited socket; the
`formwork` process opens `http(s)` URLs with the host opener when `open-url` is lifted and refuses
everything else, one operator line each. The script mirrors that verdict to its caller: exit 1 and
a generic refusal for a URL the Gateway will refuse.

## 3. Departures from the proposal

Each is a visible amendment in the sense of the constitution's Precedence & Conflicts, recorded
here rather than silently deviated.

- **`explain --hosts`, not `explain --net`.** `--net` is already the sugar flag that sets the net
  posture on every blueprint-taking subcommand; a second meaning on `explain` would collide in the
  shared argument struct. `explain --hosts` prints the host table. *Resolved: `--hosts` kept, and
  `fep-5.md` (§3.5, §4, `FW-FID11`) amended to match.*
- **The README's brokered example uses `any:`, not `https:`.** The proposal's README sketch pairs
  `https:api.anthropic.com` with `broker:anthropic`, which `FW-CRED12` itself refuses: the Gateway
  cannot present a credential on a tunnel it cannot see into. The README and the examples use the
  inspected grade. *Resolved: `any:` kept, and the §3.2 sketch in `fep-5.md` amended to match.
  Superseded by FEP-6 §9 (j): `allow:` and `tunnel:` replaced `any:` and `https:`.*
- **Sockets are granted by a literal write grant.** §3.1 says "granted by `allow`". `allow` also
  turns on the exec allowlist, so granting a socket through it would restrict exec as a side
  effect. A literal write grant on the socket path admits it (`FW-ISO12`); the compiler keeps
  literal write grants under a granted subtree for exactly this.
- **Loopback is restricted by name.** `localhost` and loopback literals are restricted destinations
  like private ranges, unless a rule names them explicitly. The tests' fixture resolver maps test
  names to loopback upstreams; the production resolver never does. *Superseded by FEP-6's
  `FW-EGR19`: an exact-name rule admits a loopback answer, and the fixture exception is gone.*
- **No `hyper`.** HTTP/1.1 framing is hand-written (content-length or chunked, never both, strict
  header parsing), now in `http.rs` (FEP-6). The dependency list is `rustls`, `tokio-rustls`, `rcgen` and
  `rustls-native-certs`, all confined to `formwork-gateway`.
- **The opener transport is one-way.** A shell script cannot hold a request-reply exchange on a
  socket shared by every process in the session without interleaving replies, so the shim cannot
  hear the Gateway's verdict. *Resolved: the shim mirrors it.* The Launcher writes the shim knowing
  whether `open-url` is lifted, and the shim repeats the Gateway's scheme, authority and length
  checks; a URL either side refuses makes the shim exit 1 with a generic `formwork: open-url:
  refused`, while the Gateway still decides, opens and records. A unit test holds the two to the
  same verdict. Only a host-opener launch failure stays invisible to the session.
  `FORMWORK_HOST_OPENER` in the operator's environment overrides the host opener, which the tests
  use for a fixture.
- **The shim is always placed.** §3.4 places it "when `open-url` is lifted". It is placed in every
  spawned session and refuses when the channel is not lifted, because `learn` proposes the channel
  from that refusal (§3.4, "`learn` proposes the channel from the shim's refusal record"), and
  `FW-ADV-020`'s opener route needs the refusal to be observable. *Resolved: always placed, and
  `FW-ISO17` amended to say so.*
- **Learning on Linux observes hosts and channels only through the spawn shim.** The Linux learning
  shim runs `run --confine-self` unless the blueprint has host rules or `isolate`, because the spawn
  posture puts `formwork`'s own file syscalls into the trace. Without host rules there is no Gateway,
  supervisor or outside process to observe, so host and channel proposals need host rules on Linux.
  The shim reports its observations to `learn` over an inherited pipe. *Resolved: kept as is. The
  only proposal lost is `open-url` on Linux without host rules or `isolate`; the README says so.*
- **macOS: the peer check identifies the session by its sandbox, not by ancestry** (built with the
  characterization). The listener maps an accepted connection's client end to the processes that
  hold it (`proc_pidfdinfo`), and admits it only when one of them carries the session marker: the
  profile denies one Mach service name derived from a per-session secret and allows another, and
  `sandbox_check` (without a violation record) tells a session process from an unconfined one and
  from any other sandbox. A parent-PID walk would miss reparented descendants, and the marker never
  appears where the session can read it. `net-host-scope` is `Enforced` on macOS.
- **macOS: the keychain is denied until lifted** (with the characterization). C3 showed TLS
  clients verify through `trustd`, not the keychain's services, so the `os-keyring` denies are
  emitted; the `claude` type reaches them too, since Claude Code keeps its macOS login there
  (§3.4).
- **macOS: other processes' environments stay readable** (C5): no Seatbelt operation mediates
  `kern.procargs2`, so the `sysctl-read` deny is not emitted and `process-environment` is
  `Unenforceable`. `formwork` zeroes its own exec-time environment at startup, which keeps the
  operator's credentials out of the session's reach.
- **macOS: the loopback-callback grant reaches the network** (C1): `localhost` in a local filter
  matches every local address, so `net-default-deny` is `Partial` on macOS with that reason, and
  `FW-E2E-028`'s intersection accepts it as a reported difference.
- **macOS: a session's denies carry a tag.** Every deny in a spawned session's profile has a
  `(with message …)` modifier naming the session, which the unified log appends to the record; the
  macOS `learn` feed keeps only its own records, and streams them live (`log stream`) beside the
  post-hoc `log show`.
- **`FW-E2E-086`'s second half** (killing the Gateway mid-session) is not reachable from a
  black-box test: the Gateway is a thread in the `formwork` process. The exit path is implemented
  (`run` checks the listener after the workload exits and fails with 125 and one `formwork:` line).

- **The port-scoped `agent-session.toml` is retired.** Each agent has a host-scoped blueprint on
  the shared `agent-base.toml`, which now carries the env scrub itself. Where host rules are refused,
  the examples document the port tier on the command line instead:
  `--blueprint agent-base.toml --net ports:443 --allow-cred claude`. `FW-E2E-024` (macOS port tier)
  and `FW-E2E-026` (dry-run compile) moved onto those blueprints.

- **codex and opencode broker their keys too.** Both were run for real under brokered blueprints
  and trust the session CA: codex's request reached OpenAI through the inspected rule over HTTPS
  and WebSocket carrying the substituted key, and opencode's reached Anthropic. `codex.toml` is the
  ChatGPT-login variant, `codex-api-key.toml` brokers `OPENAI_API_KEY`, and `opencode.toml` brokers
  `ANTHROPIC_API_KEY`. Each agent's state directory must exist before the first run; the examples
  say so.
- **Linux: ancestors of a denied path stay unlisted.** Landlock cannot grant listing on `$HOME`
  without granting it inside `~/.ssh`. Measured against OpenBSD unveil, keeping ancestors unlisted
  refuses some listings unveil would allow, while granting listing would expose names unveil hides;
  Formwork never allows more than unveil would, so ancestors stay unlisted (`ls /` is refused on
  Linux in the subtractive mode; the closed mode already matches unveil). This predates FEP-5.
  `FW-E2E-084` exempts listings of the launch directory and its ancestors, and
  `docs/linux-backend.md` states the residual.

- **Linux environment disclosure is `Enforced` for an unprivileged run.** D9 recorded
  `/proc/<pid>/environ` as readable from a root container. The first CI run, on ordinary
  runners, showed Landlock refusing it: ptrace-class access outside the domain is denied, and
  only `CAP_SYS_ADMIN` or `CAP_PERFMON` lifts the refusal (bisected capability by capability).
  `detect` now records those two and `CAP_SYS_PTRACE` in the effective set, and the report says
  `Enforced` without them and `Partial` with them. `FW-E2E-083` checks both directions; the whole
  suite was also run as an unprivileged user before the push.

- **D3: `.formwork/` does not keep the root whole on Linux.** The discovery test checked only that
  `.formwork/blueprint.toml` is found. A run under the quickstart could still create nothing in
  the project root. The protected files sit inside the `$CWD/**` grant either way, so the root
  and `.formwork/` are split, and `run` printed advice to move the blueprint into `.formwork/`
  (or nothing, once it was there). Landlock cannot express the intended carve-out. A right on a
  directory reaches everything beneath it, and stacked layers only intersect, so a file created in
  the root holds exactly the rights of the protected file beside it, or of `.formwork/` below it.
  `Make*` on the root, the §9 alternative, would let the session create the absent discovered
  layer, and without `WriteFile` a new file is not writable anyway. *Resolved:* `.formwork/` stays
  as the one-directory layout. `run` warns, and `explain` notes, which directories lose create,
  delete and rename, and they name the layout that keeps the root whole: a blueprint outside the
  write grant, in a directory above the project (discovery finds it) or via `--blueprint`. The
  README documents the limitation, and a run-level test checks all three layouts on both OSes.
  The same work found the policy inputs' write-subtract rows unresolved at enforcement, so a
  blueprint named through a symlinked directory stayed writable (fixed; `FW-XR8`).

## 4. Tests

| ID | Where | Runs on |
|---|---|---|
| `FW-E2E-075` | `formwork-confine/tests/linux_supervise.rs`, `formwork-cli/tests/fep5_run.rs` (Linux), `fep5_macos.rs` (macOS) | both |
| `FW-E2E-076` | `formwork-confine/tests/linux_supervise.rs` | Linux |
| `FW-E2E-077` | `formwork-gateway/tests/inspect.rs` | both |
| `FW-E2E-078` | `formwork-gateway/tests/inspect.rs` (Gateway half), `fep5_run.rs` (session half) | both |
| `FW-E2E-079` | `fep5_run.rs` (tier on 22.04, refusal on 24.04) | Linux |
| `FW-E2E-080` | `fep5_macos.rs` | macOS |
| `FW-E2E-081` | `fep5_macos.rs` against a fixture app, System Events, the pasteboard and a test keychain | macOS |
| `FW-E2E-082` | `fep5_run.rs` against a fixture `dbus-daemon` | Linux |
| `FW-E2E-083` | `fep5_run.rs` (Linux), `fep5_macos.rs` (macOS) | both |
| `FW-E2E-084` | `fep5_run.rs`; the `agent-examples` CI job installs Claude Code, codex and opencode on ubuntu-22.04 and macos-15 | both |
| `FW-E2E-085` | `fep5_run.rs` (Linux), `fep5_macos.rs` (macOS: the clipboard proposed from a Sandbox record) | both |
| `FW-E2E-086` | `fep5_run.rs` (first half) | both |
| `FW-E2E-087` | `fep5_run.rs` against a fixture `dbus-daemon` and `Xvfb` (Linux), `fep5_macos.rs` (macOS) | both |
| `FW-E2E-088` | `fep5_run.rs` (Linux), `fep5_macos.rs` (macOS) | both |
| `FW-E2E-089` | `fep5_run.rs` (Linux), `fep5_macos.rs` (macOS) | both |
| `FW-E2E-090` | `fep5_run.rs` (Linux), `fep5_macos.rs` (macOS) | both |
| `FW-E2E-091` | `fep5_macos.rs`, under `net = "deny"`, a port tier and a host rule, and from the host's network address | macOS |
| `FW-ADV-016` | `formwork-gateway/tests/gateway.rs` | both |
| `FW-ADV-017` | `formwork-gateway/tests/{egress,inspect}.rs` | both |
| `FW-ADV-018` | `formwork-confine/tests/linux_supervise.rs` | Linux |
| `FW-ADV-019` | `fep5_macos.rs` (an unconfined process with the session's credential), `formwork-gateway/tests/egress.rs` (the gate) | macOS |
| `FW-ADV-020` | `fep5_run.rs` (Linux, the opener route; the bus route is `FW-E2E-082`, the direct route `FW-E2E-075`), `fep5_macos.rs` (macOS: the opener, LaunchServices, an AppleEvent and the clipboard) | both |
| C1–C8 | `formwork-confine/tests/macos_characterize.rs` (§6.3; answers in `docs/macos-characterization.md`) | macOS |
| C9 | `fep5_macos.rs` (`c9_…`), in the macOS `agent-examples` job: Claude Code's `security` calls through a shim, reaching the keychain under `claude-code.toml` and denied without the lift | macOS |

CI sets `FW_REQUIRE_EXERCISED=1`, so a test that cannot exercise its mechanism on a runner fails
instead of skipping. The README quickstart is read verbatim from `README.md` and run.

## 5. Still owed

Nothing in FEP-5's scope. The macOS answers come from GitHub's virtual runners, which run with
System Integrity Protection off; `docs/macos-characterization.md` asks for a repeat on a
SIP-enabled Mac before a release that changes a verdict.
