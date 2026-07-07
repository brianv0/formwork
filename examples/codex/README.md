# codex + Formwork

## Axis A — let Formwork be the sandbox, then bypass codex's own

codex has built-in `sandbox_mode` (`read-only` | `workspace-write` | `danger-full-access`) and
`approval_policy` (`untrusted` | `on-request` | `never`). Its "just run everything" escape hatch is
`--dangerously-bypass-approvals-and-sandbox` (alias `--yolo`), which turns **both** off. On its own
that leaves nothing scoping the process. Run codex under `formwork run` and Formwork's kernel wall
takes over that job:

```sh
formwork run --blueprint ./examples/blueprints/agent-session.toml -- \
    codex --dangerously-bypass-approvals-and-sandbox
```

`./sandbox-agent.sh` runs exactly this. For a one-shot, headless run use `codex exec`:

```sh
formwork run --blueprint ./examples/blueprints/agent-session.toml -- \
    codex exec --dangerously-bypass-approvals-and-sandbox "summarize the build"
```

The point isn't to disable safety — it's to move it down a layer. One Formwork blueprint then scopes
codex, Claude Code, and opencode identically, instead of each agent's bespoke sandbox settings.

## Axis B — route MCP servers through the gateway

codex declares MCP servers as `[mcp_servers.<name>]` tables in `config.toml`
([`config.toml`](./config.toml)). Point the server's `command` at `formwork gateway` and put the
real backend after `--`, so codex talks to the gateway and the gateway shades + confines the server:

```toml
[mcp_servers.files]
command = "formwork"
args = ["gateway", "--blueprint", "./examples/blueprints/mcp-gateway.toml", "--server", "files", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
```

**Staging the override.** Add it without hand-editing (note the `--` before the wrapped command):

```sh
codex mcp add files -- formwork gateway \
    --blueprint ./examples/blueprints/mcp-gateway.toml --server files -- \
    npx -y @modelcontextprotocol/server-filesystem .
```

codex reads `~/.codex/config.toml` (global) or a trusted project `./.codex/config.toml`, so dropping
this repo's `examples/codex/config.toml` contents into either overrides the `files` server with the
gateway-wrapped one. With `[mcp.files] tools = { allow = ["read_file"] }`, only `read_file` is
exposed; the write tools are absent and refused if called.

Run [`../gateway-demo.sh`](../gateway-demo.sh) to watch the gateway shade a backend end to end
(against the repo's built-in fixture, so no external server is needed).
