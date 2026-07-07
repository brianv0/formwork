#!/usr/bin/env bash
# Axis A for codex: let Formwork be the sandbox, so you can bypass codex's own approvals + sandbox
# without going unprotected. `--dangerously-bypass-approvals-and-sandbox` (alias `--yolo`) turns off
# codex's guardrails; running it under `formwork run` replaces them with a kernel-enforced wall.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
cargo build -q -p formwork-cli
FORMWORK="$REPO/target/debug/formwork"
BLUEPRINT="$REPO/examples/blueprints/agent-session.toml"

echo "What this host actually enforces for this blueprint:"
"$FORMWORK" compile --blueprint "$BLUEPRINT" --report-only \
    | awk '/"semantics"/{f=0} /"per-capability"/{f=1} f' | sed 's/^/  /'
echo

CMD=( "$FORMWORK" run --blueprint "$BLUEPRINT" -- codex --dangerously-bypass-approvals-and-sandbox )

echo "Confined launch:"
printf '  '; printf '%q ' "${CMD[@]}"; echo; echo

if command -v codex >/dev/null 2>&1; then
    echo "Launching codex confined. codex's own approvals/sandbox are off; Formwork's kernel wall"
    echo "is what now scopes reads, writes, exec, and egress."
    exec "${CMD[@]}" "$@"
else
    echo "codex is not on PATH, so skipping the real launch. Install codex, then re-run — or run"
    echo "../gateway-demo.sh and the pytest suite (py/) to see the wall enforced end to end."
fi
