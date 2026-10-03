# Formwork

An OS-level sandbox for agent sessions: it takes a capability blueprint and turns the four
capabilities that touch the real operating system — read, write, exec, net — into boundaries the
kernel actually enforces, on Linux and macOS, for an agent process and every child it spawns. Plus
an MCP-aware gateway so every tool call and every byte of egress is forced through one auditable
door.

Formwork targets **good isolation, not perfect isolation**: a hard wall against accidental,
careless, and prompt-injected overreach and against untrusted code the agent runs — not against
kernel exploitation. Every enforcement claim is backed by a real mechanism on the current host or
reported as a gap; Formwork never silently claims containment it cannot deliver.

## Install

Prebuilt `formwork` binaries (macOS and Linux, arm64 and x86_64) are published on
[GitHub Releases](https://github.com/brianv0/formwork/releases): every merge to `main` updates the
rolling [`canary`](https://github.com/brianv0/formwork/releases/tag/canary) prerelease, and version
tags (`v*`) cut stable releases. Each release carries a `SHA256SUMS` file. For example:

```sh
curl -fsSLO https://github.com/brianv0/formwork/releases/download/canary/formwork-canary-aarch64-apple-darwin.tar.gz
tar -xzf formwork-canary-aarch64-apple-darwin.tar.gz
./formwork-canary-aarch64-apple-darwin/formwork explain
```

> **macOS Gatekeeper:** the binaries are not yet Developer-ID-signed or notarized. The terminal
> route above just works — `curl` and `tar` never set the quarantine flag. A **browser** download
> does get quarantined, and macOS will refuse to run the binary ("Apple could not verify 'formwork'
> is free of malware"). If you downloaded that way, clear the flag and re-extract:
>
> ```sh
> xattr -d com.apple.quarantine formwork-canary-*.tar.gz && tar -xzf formwork-canary-*.tar.gz
> ```

Or build from source (Rust 1.85+ and a C compiler): `cargo install --path crates/formwork-cli`.

## Quickstart

Drop a `FORMWORK.toml` in your project (or `.formwork/blueprint.toml`, which keeps Formwork's own
files in one directory) — every subcommand finds it automatically (current directory, then parents
up to `$HOME`) and announces which file it used:

```toml
# FORMWORK.toml — extend the built-in default profile (broad reads, credentials denied, other
# projects read-only, secret-shaped env vars scrubbed), then open what this project needs:
extends = ["builtin:default"]
net = { ports = [443] }              # TCP to port 443 on any host; omit for no network at all
rules = ["readwrite:$CWD/**"]        # the project directory is the writable working set
```

On Linux the port tier closes UDP too, so hostnames do not resolve inside the sandbox; host rules
(below) resolve them through the Gateway. See [`examples/`](examples/README.md).

```sh
# Run a command, and everything it spawns, behind the kernel wall:
formwork run -- npm test

# Run your agent the same way, with a blueprint that also grants its own state and model API
# (examples/ has them) — its in-app permission prompts stop being what protects you:
formwork run --blueprint claude-code.toml -- claude --dangerously-skip-permissions

# What does this host enforce, and what would this session's policy be?
formwork explain

# Why is a specific path granted or denied, and by which rule?
formwork explain ~/.ssh/id_ed25519 '$CWD/src/main.rs'
```

The sandbox holds for the whole process tree — a `git` or `python` the agent spawns hits the same
walls. Denials surface as ordinary `EACCES`/`EPERM`, credentials at their known locations stay
unreadable even under broad read grants, and a deny always beats an allow, from any layer. (On
Linux, credential-shaped *names* inside a granted tree, such as a project's `.env`, cannot be
denied by the kernel; `formwork explain` lists them as withheld.) Host services that could act for
the agent outside the sandbox — the clipboard, opening URLs, the session bus, AppleEvents — are
closed unless the blueprint lifts them with `channels` (on Linux without host rules they are hidden
from clients rather than closed).

To reach named hosts only, write host rules instead of the port tier. Every connection then goes
through a Gateway that Formwork runs outside the sandbox, and an API key can be *brokered*: the
agent holds a placeholder, and the Gateway presents the real key to that host alone.

```toml
extends = ["builtin:default"]
rules = ["readwrite:$CWD/**", "allow:api.anthropic.com"] # this host only, through the Gateway
allow-credentials = ["broker:anthropic"]                 # the agent sees a placeholder, never the key
```

Host rules come in two grades. `allow:host`, and method rules such as
`get,post:api.github.com/repos/acme/**`, are *inspected*: the Gateway terminates TLS with a
per-session CA, held in memory and limited to the hosts you named, and checks each request's host,
method and path; Formwork points common clients (curl, git, Python, Node, npm, pip, uv, cargo) at
that CA. `tunnel:host` forwards the client's own TLS unopened after checking the server name — for
clients that cannot trust an added CA, such as Go programs and rustup on macOS. Inspected hosts
speak HTTP/1.1. Private and loopback addresses are reached only through a rule naming the exact
host, and an `https_proxy` in Formwork's own environment carries the Gateway's upstream traffic.

`formwork learn` runs a workload enforced while recording what the kernel denied, then
proposes grants for review — nothing is widened until you accept it:

```sh
formwork learn -- npm test        # enforced run; denials become a reviewable proposal
formwork learn --list             # see the proposed grants, numbered
formwork learn --accept 1         # accept by number or pattern; applies from the next run
```

Beyond paths, `learn` proposes the hosts a run was refused and the channels it tried to use, such
as opening a login URL. It proposes hosts only when the blueprint already has a host rule (egress
then goes through the Gateway, which sees each refusal); on Linux it proposes channels only with
host rules or `isolate`.

See [`examples/`](examples/README.md) for complete blueprints, the rule vocabulary, CLI recipes,
and wiring for Claude Code, codex, and opencode.

## Platform support

| Capability | macOS | Linux |
|---|---|---|
| Filesystem read/write walls (`run`, `gateway`) | ✅ Seatbelt | ✅ Landlock + seccomp (kernel 5.13+) |
| Default-deny network | ✅ (a login flow's loopback listener also accepts on the host's other addresses) | ✅ |
| Port tier (direct TCP to listed ports) | ✅ | ✅ on kernel 6.7+ (elsewhere egress fails closed); names do not resolve |
| Host-scoped egress through the Gateway, TLS inspection, credential brokering | ✅ (clients that verify through the macOS keychain need `tunnel:`; on macOS 14 the sandbox can refuse a connection to the Gateway during a window of a few milliseconds every 15 seconds, observed on GitHub's macOS 14 runners, which the client sees as a failed connect) | ✅ (kernel 5.6+, Yama `ptrace_scope` 0 or 1) |
| Host-service channels closed by default (`channels`) | ✅ | ✅ (sockets closed under host rules; hidden otherwise) |
| Process isolation (`isolate = ["processes", "ipc"]`) | partial (sandbox filters) | ✅ where unprivileged user namespaces are allowed |
| Exec allow-lists | ✅ | ✅ (list the dynamic loader too, e.g. `/lib64/ld-linux-x86-64.so.2`) |
| MCP gateway shading | ✅ | ✅ |
| `learn` (denial observation) | ✅ unified-log feed | ✅ ptrace feed (needs `strace` and Landlock; fails fast with the reason otherwise) |
| `compile` / `explain` dry-run | ✅ any host | ✅ any host; `compile --target` builds a Linux policy on a Mac |

On a host that can't carry a capability (an older kernel, a missing mechanism), Formwork reports
the gap in its fidelity report and refuses to pretend — it fails closed, never silently open.
`formwork explain` (or the `--help` epilogue) tells you where the machine you're on stands.

## Commands

```text
formwork run      [--blueprint …] -- <cmd> …   confine a command and every child it spawns
formwork learn    [--blueprint …] -- <cmd> …   enforced run + denial observation → proposal
formwork learn    --list | --accept <n|pat>    review / accept proposed grants
formwork explain  [--blueprint …] [--hosts] [path | url | channel …]   host capabilities, policy summary, verdicts
formwork compile  [--blueprint …] [--target …] compiled policy + fidelity report as JSON (for CI)
formwork gateway  [--blueprint …] --server <name> -- <mcp server cmd>   MCP policy proxy
```

`explain` is the human door (prose; `--json` for machines), `compile` the machine door (stable
JSON). Both state which blueprint file they resolved and how. Blueprints compose: a file, its
`extends` chain (including the compiled-in `builtin:default`), a learned-grants layer, and CLI
overrides (`--rule`, `--set`, sugar flags) merge into one model where deny always wins.

## Development

`just test` (or `cargo test --workspace`) runs the pure + native-OS-backend tests on any host;
`cd py && uv run pytest` runs the black-box end-to-end harness. Linux enforcement is tested
first-line in Docker (`just test-linux`) with Docker's own seccomp/AppArmor disabled so only
Formwork's sandbox is under test; `just test-linux-full` runs the suite in a Lima VM you create
(an instance named `formwork` with a 6.12+ kernel). [`CONTRIBUTING.md`](CONTRIBUTING.md) has the
details.

- [`formwork.md`](formwork.md) — the design and end-to-end test spec (with the requirement
  identifiers cited throughout code and tests).
- [`docs/STATUS.md`](docs/STATUS.md) — implementation status by phase, and the work still owed.
- [`constitution.md`](constitution.md) — project doctrine, including the honesty rules.

## License

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([`LICENSE-MIT`](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
