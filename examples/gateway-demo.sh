#!/usr/bin/env bash
# Runnable, dependency-free demo of `formwork gateway`: put the policy gateway in front of an MCP
# backend and watch it shade the protocol. Uses the repo's built-in fixture backend so nothing
# external is needed. The per-host config files (claude-code/mcp.json, codex/config.toml,
# opencode/opencode.json) wrap this exact command in each host's own MCP-server format.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

echo "building formwork + fixture backend..."
cargo build -q -p formwork-cli -p formwork-gateway --bin formwork --bin fw-mcp-fixture

FORMWORK="$REPO/target/debug/formwork"
FIXTURE="$REPO/target/debug/fw-mcp-fixture"
SPEC="$REPO/examples/specs/mcp-gateway.toml"

echo
echo "The fixture backend exposes: read_file, write_file, http_fetch (+ resources, prompts)."
echo "The spec's [mcp.files] grants only read_file. Driving it through the gateway"
echo "(replies stream back as each completes, so match them by id):"
echo

# One connection, three requests. The sleep holds the connection open so backend round-trips
# complete before the client hangs up (the gateway tears down the moment either side closes).
{
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/x"}}}'
    printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"http_fetch","arguments":{}}}'
    sleep 1
} | "$FORMWORK" gateway --spec "$SPEC" --server files -- "$FIXTURE"

echo
echo "Expected:"
echo "  id 1  tools/list  -> only read_file is listed (write_file and http_fetch are absent)"
echo "  id 2  read_file   -> granted, round-trips unchanged (result text \"ok:read_file\")"
echo "  id 3  http_fetch  -> refused as \"Unknown tool\" — same error a nonexistent tool gets,"
echo "                       so the shading leaks no oracle for hidden-but-real tools."
