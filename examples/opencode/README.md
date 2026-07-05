# opencode + Formwork

## Axis A — confine opencode, then auto-allow every action

opencode gates actions with its `permission` config (`allow` | `ask` | `deny`, globally or per
tool). Setting `permission: "allow"` (or launching with `--auto`) removes the confirmations. Do that
under `formwork run` and the kernel wall — not the in-app prompt — is what scopes the process:

```sh
formwork run --spec ./examples/specs/agent-session.toml -- opencode
```

with `permission: "allow"` set in [`opencode.json`](./opencode.json). `./sandbox-agent.sh` runs
this (and prints the enforced-capability report first). For a headless one-shot:

```sh
formwork run --spec ./examples/specs/agent-session.toml -- opencode run --auto "summarize the build"
```

The spec grants writes to `~/project` + scratch, subtracts credentials/keychains/browser profiles,
and allows only HTTPS egress so the model API still works. Narrow `writes` to your repo.

## Axis B — route MCP servers through the gateway

opencode declares MCP servers under the top-level `mcp` key. A `type: "local"` server takes a
`command` array; make `formwork gateway` the command and put the real backend after `--`, so
opencode talks to the gateway and the gateway shades + confines the server:

```json
"mcp": {
  "files": {
    "type": "local",
    "enabled": true,
    "command": ["formwork", "gateway", "--spec", "./examples/specs/mcp-gateway.toml",
                "--server", "files", "--",
                "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
  }
}
```

**Staging the override.** opencode loads `opencode.json` from the project root (and a global config
under `~/.config/opencode/`). Drop this repo's `examples/opencode/opencode.json` into your project
root (or merge its `mcp.files` entry) to replace a direct filesystem server with the gateway-wrapped
one. With `[mcp.files] tools = { allow = ["read_file"] }`, opencode sees only `read_file`; the write
tools are absent from the listing and refused if called.

Run [`../gateway-demo.sh`](../gateway-demo.sh) to watch the gateway shade a backend end to end
(against the repo's built-in fixture, so no external server is needed).
