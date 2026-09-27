# FEP-5 execution record

Companion to `fep-5.md` (what and why). This records how FEP-5 was built, where the build departed
from the proposal and why, and what is still owed. Requirement and test IDs are defined in
`fep-5.md`, anchored there, and cited bare in code.

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
everything else, one operator line each.

## 3. Departures from the proposal

Each is a visible amendment in the sense of the constitution's Precedence & Conflicts, recorded
here rather than silently deviated.

- **`explain --hosts`, not `explain --net`.** `--net` is already the sugar flag that sets the net
  posture on every blueprint-taking subcommand; a second meaning on `explain` would collide in the
  shared argument struct. `explain --hosts` prints the host table.
- **The README's brokered example uses `any:`, not `https:`.** The proposal's README sketch pairs
  `https:api.anthropic.com` with `broker:anthropic`, which `FW-CRED12` itself refuses: the Gateway
  cannot present a credential on a tunnel it cannot see into. The README and the examples use the
  inspected grade.
- **Sockets are granted by a literal write grant.** §3.1 says "granted by `allow`". `allow` also
  turns on the exec allowlist, so granting a socket through it would restrict exec as a side
  effect. A literal write grant on the socket path admits it (`FW-ISO12`); the compiler keeps
  literal write grants under a granted subtree for exactly this.
- **Loopback is restricted by name.** `localhost` and loopback literals are restricted destinations
  like private ranges, unless a rule names them explicitly. The tests' fixture resolver maps test
  names to loopback upstreams; the production resolver never does.
- **No `hyper`.** HTTP/1.1 framing is hand-written in `inspect.rs` (content-length or chunked,
  never both, strict header parsing). The dependency list is `rustls`, `tokio-rustls`, `rcgen` and
  `rustls-native-certs`, all confined to `formwork-gateway`.
- **The opener transport is one-way.** A shell script cannot hold a request-reply exchange on a
  socket shared by every process in the session without interleaving replies. The shim cannot learn
  the verdict: a refused URL simply does not open, and the operator line carries the reason.
  `FORMWORK_HOST_OPENER` in the operator's environment overrides the host opener, which the tests
  use for a fixture.
- **The shim is always placed.** §3.4 places it "when `open-url` is lifted". It is placed in every
  spawned session and refuses when the channel is not lifted, because `learn` proposes the channel
  from that refusal (§3.4, "`learn` proposes the channel from the shim's refusal record"), and
  `FW-ADV-020`'s opener route needs the refusal to be observable.
- **Learning on Linux observes hosts and channels only through the spawn shim.** The Linux learning
  shim runs `run --confine-self` unless the blueprint has host rules or `isolate`, because the spawn
  posture puts `formwork`'s own file syscalls into the trace. Without host rules there is no Gateway,
  supervisor or outside process to observe, so host and channel proposals need host rules on Linux.
  The shim reports its observations to `learn` over an inherited pipe.
- **macOS: the peer-PID check on the egress endpoint is not built.** The endpoint is gated by the
  per-session credential only, and `net-host-scope` says `Partial` with that reason.
- **macOS: the `os-keyring` and `securityd` denies are withheld** until the characterization suite
  confirms toolchains run without them (§1.1's gate); the report says so.
- **`FW-E2E-086`'s second half** (killing the Gateway mid-session) is not reachable from a
  black-box test: the Gateway is a thread in the `formwork` process. The exit path is implemented
  (`run` checks the listener after the workload exits and fails with 125 and one `formwork:` line).

## 4. Tests

| ID | Where | Runs on |
|---|---|---|
| `FW-E2E-075` | `formwork-confine/tests/linux_supervise.rs`, `formwork-cli/tests/fep5_run.rs` | Linux |
| `FW-E2E-076` | `formwork-confine/tests/linux_supervise.rs` | Linux |
| `FW-E2E-077` | `formwork-gateway/tests/inspect.rs` | both |
| `FW-E2E-078` | `formwork-gateway/tests/inspect.rs` (Gateway half), `fep5_run.rs` (session half) | both / Linux |
| `FW-E2E-079` | `fep5_run.rs` (tier on 22.04, refusal on 24.04) | Linux |
| `FW-E2E-082` | `fep5_run.rs` against a fixture `dbus-daemon` | Linux |
| `FW-E2E-083` | `fep5_run.rs` | Linux |
| `FW-E2E-084` | `fep5_run.rs`; the `agent-examples` CI job installs Claude Code | Linux |
| `FW-E2E-085` | `fep5_run.rs` | Linux |
| `FW-E2E-086` | `fep5_run.rs` (first half) | both |
| `FW-E2E-087` | `fep5_run.rs` against a fixture `dbus-daemon` and `Xvfb` | Linux |
| `FW-E2E-088` | `fep5_run.rs` | Linux |
| `FW-E2E-089` | `fep5_run.rs` | Linux |
| `FW-E2E-090` | `fep5_run.rs` | Linux |
| `FW-ADV-016` | `formwork-gateway/tests/gateway.rs` | both |
| `FW-ADV-017` | `formwork-gateway/tests/{egress,inspect}.rs` | both |
| `FW-ADV-018` | `formwork-confine/tests/linux_supervise.rs` | Linux |
| `FW-ADV-020` | `fep5_run.rs` (the opener route; the bus route is `FW-E2E-082`, the direct route `FW-E2E-075`) | Linux |

CI sets `FW_REQUIRE_EXERCISED=1`, so a test that cannot exercise its mechanism on a runner fails
instead of skipping. The README quickstart is read verbatim from `README.md` and run.

## 5. Still owed

- **The macOS characterization suite (§6.3)** and the macOS-only tests that depend on it:
  `FW-E2E-080` (isolation tier), `FW-E2E-081` (channels), `FW-E2E-091` (loopback callback),
  `FW-ADV-019` (endpoint theft). Until they run, every macOS channel, isolation and
  environment-disclosure verdict stays `Partial`, and the macOS cells marked `Enforced` in §3.6 are
  targets. Several `fep5_run.rs` tests are Linux-only for the same reason: they have not been
  observed on Seatbelt, and a test that has never run on its platform is a claim.
- **macOS channel proposals in `learn`.** The unified-log feed yields path denials; mapping Seatbelt
  service denials (pasteboard, AppleEvents) onto channels is not built. Opener and Gateway
  refusals are proposed on macOS, since the spawn is in-process there.
- **`FW-E2E-084` for codex and opencode.** The CI job installs Claude Code only; the other two
  agents' smoke commands have not been observed under their blueprints.
- **The `uv` recipe.** `uv` ignores `SSL_CERT_FILE` unless `UV_NATIVE_TLS=1`; the examples README
  carries the recipe, and the Launcher does not set it.
