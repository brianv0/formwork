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
only supervisor-made connections from `127.0.0.1` (`FW-EGR9`); a port whose connect definitely
failed is unregistered. The seccomp baseline denies any send carrying `MSG_FASTOPEN` under the
port tier and host rules, since a TCP Fast Open send connects without `connect()` and would pass
both Landlock's `ConnectTcp` hook and the supervisor. Pathname sockets are admitted when granted or bound
by a session process: UNIX socket diagnostics when the kernel has them, else `/proc/net/unix`
resolved from the binder's root. The supervisor resolves paths through `/proc/<pid>/root`, so it
works across the isolation tier's mount namespace.

**Gateway egress listener.** An HTTP proxy on `127.0.0.1:0` in its own thread and runtime, gated by
a per-session `Proxy-Authorization` credential. CONNECT tunnels and plain-HTTP absolute form are
served; the target is canonicalized (`FW-EGR3`), resolved once and pinned, and restricted addresses
are refused unless a rule names them by IP literal (`FW-EGR4`). Plain HTTP forwards the canonical
path it decided and exactly the framed body, then closes. Every refusal is one operator line with the
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
on bound hosts, refuses it on any other host and over plain HTTP, asks a bound host for an
uncompressed response, and scrubs the secret and each `basic` binding's encoded form from
responses (`FW-INV13`). A brokered credential with no value refuses the run before spawn. Because
the secret arrives in `formwork`'s own environment, `credential-broker` is `Partial` wherever
`process-environment` is not `Enforced`.

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
  inspected grade. *Resolved: `any:` kept, and the §3.2 sketch in `fep-5.md` amended to match.*
- **Sockets are granted by a literal write grant.** §3.1 said "granted by `allow`". `allow` also
  turns on the exec allowlist, so granting a socket through it would restrict exec as a side
  effect. A literal write grant on the socket path admits it (`FW-ISO12`); the compiler keeps
  literal write grants under a granted subtree for exactly this. *Resolved: §3.1.1, `FW-EGR8`,
  `FW-ISO12` and `FW-E2E-076` amended.*
- **The supervisor performs the call on the target's socket.** §3.1 described
  `SECCOMP_IOCTL_NOTIF_ADDFD` injection of a socket the supervisor opened. The build takes a
  duplicate of the target's own socket with `pidfd_getfd` and connects or sends on it, so the
  target's socket options survive; that needs Linux 5.6 and Yama `ptrace_scope` 0 or 1, which
  `detect` checks and `run` refuses host rules without. An addressed `sendmsg`/`sendmmsg` keeps its
  destination behind a pointer seccomp cannot read, so it is not mediated, and `net-unix-socket`
  says `Partial`. *Resolved: §3.1 and `FW-EGR7` amended.*
- **D3 keeps the root whole on macOS only.** Landlock cannot grant a directory whole while denying
  a path beneath it, so on Linux every directory above the protected blueprint is split, and the
  `.formwork/` layout splits the project root just as `FORMWORK.toml` does. `run` says so in both
  layouts and names what avoids it (new files in a subdirectory, or a blueprint outside the grant
  passed with `--blueprint`). *Resolved: the D3 row amended; §9's per-user state directory and
  `Make*` rights remain the alternatives.*
- **Brokered secrets are read once.** `FW-CRED15` stated a refresh interval from the Catalog. The
  only source built is the launching environment, which cannot change mid-session, so the Gateway
  reads it once at session start and the Catalog carries no interval. *Resolved: §3.2 and
  `FW-CRED15` amended; a file or service source would bring the interval back.*
- **The Catalog's `services` locations are descriptive.** The Linux keyring sockets the supervisor
  admits for `os-keyring` come from `detect` (`HostFacilities.keyring`), not from the Catalog entry,
  since only `detect` knows which exist on the host.
- **Run-time paths are disclosed by `run`.** §3.5 had `compile` and `explain` name the Gateway
  listener, the CA path and the temp directory; those exist only for a run, and `compile` stays
  pure, so `run` names them on the operator channel and `explain` names the blueprint source
  (`fd:N` for a descriptor). *Resolved: §3.5 and `FW-E2E-089` amended.*
- **The channel report is two maps.** §3.5 described one `{ verdict, reason, host }` object per
  channel. The verdict is the `per_capability` entry every capability uses, and presence is the
  report's `channels` map. *Resolved: §3.5 amended.*
- **`explain --hosts` prints one rule per line**, since a host may carry several rules (methods on
  different paths, a deny); each line names its broker binding and marks port 80 cleartext.
  *Resolved: §3.5 and `FW-FID11` amended.*
- **`FW-XR10` names `run`.** `learn` prints its proposal pointer on stdout, which FEP-4 landed as
  its result and its tests read. *Resolved: `FW-XR10` narrowed.*
- **The platform-verifier caveat is printed for every brokered run on macOS**, not per type: the
  Catalog does not know each type's typical client. `net-inspection` stays `Enforced`, since a
  client that refuses the session CA fails closed. *Resolved: §3.2 amended.*
- **The macOS default denies shipped before their gate.** §1.1 ships a new default deny only after
  the toolchain gate (`FW-E2E-020`..023) and the agent-example gate pass on macOS; neither has run
  there. The channel, `kern.procargs2` and `mach-priv*` denies are in the default profile, and each
  is reported `Partial` until the characterization suite runs. The `securityd` and `iokit-open`
  denies, the ones most likely to break a toolchain, are withheld.
- **Loopback is restricted by name.** `localhost` and loopback literals are restricted destinations
  like private ranges, unless a rule names them explicitly. The tests' fixture resolver maps test
  names to loopback upstreams; the production resolver never does.
- **No `hyper`.** HTTP/1.1 framing is hand-written in `inspect.rs` (content-length or chunked,
  never both, strict header parsing). The dependency list is `rustls`, `tokio-rustls`, `rcgen`,
  `rustls-native-certs` and `base64`, all confined to `formwork-gateway`. *Resolved: §4
  Dependencies amended.*
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
- **macOS: the peer-PID check on the egress endpoint is not built.** The endpoint is gated by the
  per-session credential only, and `net-host-scope` says `Partial` with that reason.
- **macOS: the `os-keyring` and `securityd` denies are withheld** until the characterization suite
  confirms toolchains run without them (§1.1's gate); the report says so.
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

## 4. Tests

| ID | Where | Runs on |
|---|---|---|
| `FW-E2E-075` | `formwork-confine/tests/linux_supervise.rs` (TCP Fast Open included), `formwork-cli/tests/fep5_run.rs` | Linux |
| `FW-E2E-076` | `formwork-confine/tests/linux_supervise.rs` | Linux |
| `FW-E2E-077` | `formwork-gateway/tests/inspect.rs` | both |
| `FW-E2E-078` | `formwork-gateway/tests/inspect.rs` (Gateway half), `fep5_run.rs` (session half) | both / Linux |
| `FW-E2E-079` | `fep5_run.rs` (tier on 22.04, refusal on 24.04) | Linux |
| `FW-E2E-082` | `fep5_run.rs` against a fixture `dbus-daemon` | Linux |
| `FW-E2E-083` | `fep5_run.rs` | Linux |
| `FW-E2E-084` | `fep5_run.rs`; the `agent-examples` CI job installs Claude Code, codex and opencode | Linux |
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
  targets. The macOS halves of `FW-E2E-075`, 076, 078 (session), 083, 084, 085, 087, 088, 089
  (`confstr`), 090 and `FW-ADV-020` are owed for the same reason: they have not been observed on
  Seatbelt, and a test that has never run on its platform is a claim. `FW-E2E-020`..023 (the
  toolchain gate) are owed on macOS too.
- **macOS mechanisms not built:** the egress peer-PID check (`FW-EGR9`), the `iokit-open`
  allowlist (`FW-ISO14`, C8), the `securityd` deny behind `os-keyring`, and the `claude` type's
  keychain location (`FW-CRED13`, C9).
- **Test branches not yet exercised.** `FW-E2E-082` covers the `gdbus` route; the fixture service
  standing in for `systemd --user`, the X11-shaped socket and the "a lift opens nothing else" check
  are owed. `FW-E2E-085` proposes `open-url` from the opener; the clipboard proposal from a
  supervisor-refused display socket is owed. `FW-E2E-088` checks the locator variables and the
  parse error; its runtime clipboard and URL probes and the downstream `deny` layer are owed.
  `FW-E2E-089` does not yet read the CA bundle from a grandchild, `FW-E2E-090` runs without host
  rules, `FW-ADV-020` covers the opener route only, `FW-E2E-084` runs each agent's `--version` (the
  Claude Code login flow with a fixture opener is owed), and `FW-E2E-079` chooses its branch from
  `detect` rather than pinning it per runner. The second half of `FW-E2E-086` is recorded above.
- **A requirement-to-test map** for the FEP-5 requirements (this record maps tests to files only).
- **macOS channel proposals in `learn`.** The unified-log feed yields path denials; mapping Seatbelt
  service denials (pasteboard, AppleEvents) onto channels is not built. Opener and Gateway
  refusals are proposed on macOS, since the spawn is in-process there.
- **The `uv` recipe.** `uv` ignores `SSL_CERT_FILE` unless `UV_NATIVE_TLS=1`; the examples README
  carries the recipe, and the Launcher does not set it.
