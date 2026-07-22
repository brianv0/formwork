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
tags (`v*`) cut stable releases. Each asset ships with a `SHA256SUMS` file. For example:

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

Or build from source: `cargo install --path crates/formwork-cli`.

## Quickstart

Drop a `FORMWORK.toml` in your project — every subcommand finds it automatically (current
directory, then parents up to `$HOME`) and announces which file it used:

```toml
# FORMWORK.toml — extend the built-in default profile (broad reads, credentials and other
# projects denied, secret-shaped env vars scrubbed), then open what this project needs:
extends = ["builtin:default"]
net = { ports = [443] }              # HTTPS egress only; omit for no network at all
rules = ["readwrite:$CWD/**"]        # the project directory is the writable working set
```

```sh
# Run your agent behind the kernel wall — its in-app permission prompts stop being load-bearing:
formwork run -- claude --dangerously-skip-permissions

# What does this host enforce, and what would this session's policy be?
formwork explain

# Why is a specific path granted or denied, and by which rule?
formwork explain ~/.ssh/id_ed25519 '$CWD/src/main.rs'
```

The sandbox holds for the whole process tree — a `git` or `python` the agent spawns hits the same
walls. Denials surface as ordinary `EACCES`/`EPERM`, credentials stay unreadable even under broad
read grants, and a deny always beats an allow, from any layer.

`formwork learn` runs a workload enforced while recording what the kernel denied, then
proposes grants for review — nothing is widened until you accept it:

```sh
formwork learn -- npm test        # enforced run; denials become a reviewable proposal
formwork learn --list             # see the proposed grants, numbered
formwork learn --accept 1         # accept by number or pattern; applies from the next run
```

See [`examples/`](examples/README.md) for complete blueprints, the rule vocabulary, CLI recipes,
and wiring for Claude Code, codex, and opencode.

## Platform support

| Capability | macOS | Linux |
|---|---|---|
| Filesystem read/write walls (`run`, `gateway`) | ✅ Seatbelt | ✅ Landlock + seccomp (kernel 5.13+) |
| Default-deny network, port tier | ✅ | ✅ (best on kernel 6.7+) |
| Exec allow-lists | ✅ | ✅ |
| MCP gateway shading | ✅ | ✅ |
| `learn` (denial observation) | ✅ unified-log feed | ✅ ptrace feed (needs `strace` installed; fails fast with the reason otherwise) |
| `compile` / `explain` dry-run | ✅ any host | ✅ any host, cross-platform (compile a Linux policy on a Mac) |

On a host that can't carry a capability (an older kernel, a missing mechanism), Formwork reports
the gap in its fidelity report and refuses to pretend — it fails closed, never silently open.
`formwork explain` (or the `--help` epilogue) tells you where the machine you're on stands.

## Commands

```text
formwork run      [--blueprint …] -- <cmd> …   confine a command and every child it spawns
formwork learn    [--blueprint …] -- <cmd> …   enforced run + denial observation → proposal
formwork learn    --list | --accept <n|pat>    review / accept proposed grants
formwork explain  [--blueprint …] [path …]     host capabilities, policy summary, per-path verdicts
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
Formwork's sandbox is under test; `just test-linux-full` falls back to a Lima VM with a pinned
6.12+ kernel.

- [`formwork.md`](formwork.md) — the design and end-to-end test spec (with the requirement
  identifiers cited throughout code and tests).
- [`docs/STATUS.md`](docs/STATUS.md) — implementation status by phase.
- [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — how it is being built.
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
