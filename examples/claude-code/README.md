# Claude Code + Formwork

## Axis A — confine Claude Code, then skip the prompts

Claude Code's `--dangerously-skip-permissions` (≡ `--permission-mode bypassPermissions`) executes
every tool call with no confirmation. On its own that's dangerous: the in-app prompt is the *only*
wall. Run Claude *under* `formwork run` and the wall moves to the kernel — reads, writes, exec, and
egress become OS-enforced boundaries on the `claude` process and everything it spawns — so skipping
the prompts is no longer what's protecting you.

```sh
formwork run --blueprint ./examples/blueprints/agent-session.toml -- \
    claude --dangerously-skip-permissions
```

`./sandbox-agent.sh` runs exactly this (and prints the enforced-capability report first). The blueprint
grants writes to `~/project` + scratch, subtracts your credential/keychain/browser paths, and allows
only HTTPS egress so the model API still works. Narrow `writes` to your actual repo before using it.

Notes:
- `--dangerously-skip-permissions` refuses to run as **root**. `formwork run` doesn't elevate, so
  you stay an ordinary user behind the kernel wall — which is the isolated environment the flag is
  meant for.
- Egress is port-scoped (`net = { ports = [443] }` = any HTTPS host), not host-scoped. The fs
  sandbox — not an egress allowlist — is what stops secrets being read to exfiltrate.

## Axis B — stage an MCP config that routes servers through the gateway

Instead of pointing Claude at an MCP server directly, point it at `formwork gateway`, which shades
the server's tools/resources/prompts and confines the server process. [`mcp.json`](./mcp.json) does
this — its `command` is `formwork` and the real server (`npx … server-filesystem`) is what the
gateway wraps after the `--`:

```jsonc
"files": {
  "type": "stdio",
  "command": "formwork",
  "args": ["gateway", "--blueprint", "./examples/blueprints/mcp-gateway.toml",
           "--server", "files", "--",
           "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
}
```

Claude thinks it's talking to a filesystem server; it's talking to the gateway. With
`[mcp.files] tools = { allow = ["read_file"] }`, only `read_file` is visible — `write_file`,
`edit_file`, and the rest are absent from `tools/list` and refused if called (with the same error a
nonexistent tool gets, so nothing leaks that they exist).

**Staging the override at launch.** Force Claude to use *only* this config, ignoring `~/.claude.json`
and any project `.mcp.json`:

```sh
# run from the repo root so the relative paths in mcp.json resolve
claude --strict-mcp-config --mcp-config ./examples/claude-code/mcp.json
```

- `--mcp-config <file|inline-json>` supplies the config (a path, or an inline JSON string; repeatable).
- `--strict-mcp-config` makes Claude ignore all other MCP sources and use only what you passed —
  the clean way to *override* whatever servers are otherwise configured with the gateway-wrapped set.

Equivalently, register it into project scope (writes `.mcp.json`), noting the `--` before the wrapped
server command:

```sh
claude mcp add files -- formwork gateway \
    --blueprint ./examples/blueprints/mcp-gateway.toml --server files -- \
    npx -y @modelcontextprotocol/server-filesystem .
```

To see the gateway shading a backend end to end without installing anything, run
[`../gateway-demo.sh`](../gateway-demo.sh) (it wraps the repo's built-in fixture instead of the npx
server). For the `npx` server specifically, pre-install it or widen the blueprint's `net`, since a
confined backend with `net = "deny"` cannot fetch the package on first run.

## Both at once

Run Claude confined **and** route its MCP servers through the gateway — Axis A walls the agent,
Axis B walls each tool server:

```sh
formwork run --blueprint ./examples/blueprints/agent-session.toml -- \
    claude --dangerously-skip-permissions \
           --strict-mcp-config --mcp-config ./examples/claude-code/mcp.json
```
