# Formwork examples

Two independent ways to put Formwork around a coding agent, and how to wire each into Claude Code,
codex, and opencode. They compose — use either alone or both together.

| Axis | What it does | Command | Where it's enforced |
|---|---|---|---|
| **A — confine the agent** | Run the whole agent process (and every child it spawns) behind a kernel-enforced fs/net/exec wall. | `formwork run --blueprint … -- <agent> <flags>` | Seatbelt (macOS) / Landlock+seccomp (Linux) |
| **B — shade its MCP servers** | Put a policy gateway between the agent and each MCP server: only granted tools/resources/prompts are visible or callable, and the server itself runs confined. | `formwork gateway --blueprint … --server <name> -- <server cmd>` | The gateway is a stdio MCP server the host launches |

## Why this matters: turn off the permission prompts, safely

Every one of these agents ships a "stop asking me, just do it" mode — Claude Code's
`--dangerously-skip-permissions`, codex's `--dangerously-bypass-approvals-and-sandbox` (`--yolo`),
opencode's `permission: "allow"` / `--auto`. Those modes are dangerous precisely because the *only*
thing standing between the model and your filesystem/network is the agent's own in-app confirmation.

Axis A moves the wall down to the kernel. Once reads, writes, exec, and egress are boundaries the OS
enforces on the process, the in-app prompt is no longer load-bearing — so you can turn it off and let
the agent run uninterrupted, while credentials, other projects, and the network stay unreachable.
Each host's `sandbox-agent.sh` shows the exact invocation.

## What's actually enforced (be honest, check the host)

Formwork claims only what the current host can back. Check yours:

```sh
formwork detect                                   # capabilities of this machine
formwork compile --blueprint examples/blueprints/agent-session.toml --report-only   # per-capability fidelity
```

On macOS (Seatbelt) fs read/write, default-deny egress, and the direct-TCP port tier are all
enforced by the kernel. Egress is **port-scoped, not host-scoped**: `net = { ports = [443] }` allows
any HTTPS host, so the agent reaches its model API — the filesystem sandbox, not an egress
allowlist, is what stops secrets being read to exfiltrate in the first place. On a host that can't
enforce a capability, `formwork` reports the gap instead of pretending (it never fails open).

## Layout

```
examples/
  blueprints/agent-session.toml   # Axis A: confine an agent — scoped writes, secrets subtracted, HTTPS-only egress
  blueprints/mcp-gateway.toml      # Axis B: gateway policy — [mcp.files] shading + backend confinement
  blueprints/rules-demo.toml       # the flat verb surface (rules/mode) — same model, terser authoring
  gateway-demo.sh             # runnable Axis B demo against the built-in fixture (no external deps)
  claude-code/                # per-host: sandbox-agent.sh + the MCP-override config to stage
  codex/
  opencode/
```

## Two ways to author the same policy

The blueprints above use the nested `[fs]` table. The same filesystem grants can be written as a
flat list of **verb rules** — one `"<verb>:<path>"` string per rule — which is the *same vocabulary*
on a `--rule` flag and a file line, so a policy reads the same however you author it (`FW-BP1`). See
`blueprints/rules-demo.toml` and [`fep-3.md`](../fep-3.md) for the full grammar.

| Verb | Grants | Nested-`[fs]` equivalent |
|---|---|---|
| `read` / `readonly` | read | `reads` |
| `write` | read + modify, **no create** | `writes-no-create` |
| `readwrite` | read + write + create | `writes` |
| `allow` | read + write + create + exec | `writes` + `exec` allow-list |
| `readexec` | read + execute | `reads` + `exec` allow-list |
| `exec` | execute only | `exec` allow-list |
| `deny` | nothing (terminal) | `subtract` |

`--mode unveil` (empty universe) or `--mode subtractive` (ambient minus the credential floor)
is a friendlier spelling of `[fs] read-mode`. `deny` is terminal — no allow overrides it — and the
credential floor compiles into that same deny layer, so it can never be punched through. Example:

```sh
# The file form (verbs in a `rules` list):
formwork compile --blueprint examples/blueprints/rules-demo.toml --target macos --report-only

# The same vocabulary on the CLI, layered over any base blueprint — a deny narrows from anywhere:
formwork run --blueprint examples/blueprints/agent-session.toml \
  --rule "deny:$CWD/secrets" -- <agent> <flags>
```

### CLI recipes

`--rule` and `--mode` are the highest override layer — they apply on top of the file (and any
`extends` chain), so you shape a shipped blueprint per-run without editing it. `--blueprint` names
the base; everything else refines it.

```sh
# Add extra denies for one run — safe from any layer, since deny is terminal (FW-CAP8):
formwork run --blueprint examples/blueprints/agent-session.toml \
  --rule "deny:$CWD/secrets" --rule "deny:$CWD/.env.production" -- claude --dangerously-skip-permissions

# Let the agent EDIT an existing dir but not CREATE new files under it (create/write split, FW-CAP9):
formwork run --blueprint examples/blueprints/agent-session.toml \
  --rule "write:$CWD/var/log" -- <agent>

# Flip a blueprint to unveil (empty universe) and hand-pick what's readable/runnable:
formwork run --blueprint examples/blueprints/agent-session.toml --mode unveil \
  --rule "readonly:/usr/**" --rule "readexec:/bin/**" --rule "readwrite:$CWD/**" -- <agent>

# Tighten an otherwise-unrestricted agent's exec down to an allowlist (last-wins over `exec = "unrestricted"`):
formwork run --blueprint examples/blueprints/agent-session.toml \
  --rule "exec:/usr/bin/git" --rule "exec:/usr/bin/python3" -- <agent>

# Let one credential type through the floor AND grant its directory, in one invocation (FW-CRED5):
formwork run --blueprint examples/blueprints/agent-session.toml \
  --allow-cred aws --rule "readonly:$HOME/.aws/**" -- <agent>

# Mix the flat rule surface with a `--set` TOML fragment — both parse as the same model (FW-BP1):
formwork compile --blueprint examples/blueprints/rules-demo.toml \
  --set 'net = { ports = [443] }' --rule "deny:$HOME/.npmrc" --target linux-v6 --report-only

# Inspect the merged, canonical policy the confiner will enforce (not just the report):
formwork compile --blueprint examples/blueprints/rules-demo.toml --target macos | jq '.confiner'

# Compile a Linux policy on a Mac (or vice-versa) to review it before enforcing — pure, no kernel:
formwork compile --blueprint examples/blueprints/rules-demo.toml --target linux-v6 --report-only
```

Every `--rule` value is the exact string a file `rules = [...]` line would hold, so a recipe you
like copies straight into a blueprint. A bad verb, an unknown `--mode`, or a malformed rule is a
loud error, never a silent no-op.

## Install `formwork`

The examples call `formwork` on your PATH. Build and install it from the repo root:

```sh
cargo install --path crates/formwork-cli    # puts `formwork` on PATH
# or, without installing, use the built binary directly:
cargo build -p formwork-cli                 # ./target/debug/formwork
```

## Try it

```sh
./examples/gateway-demo.sh                  # Axis B, end to end, runs as-is
cat examples/claude-code/README.md          # Axis A + staging the MCP override, per host
```
