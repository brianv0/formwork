#!/usr/bin/env bash
# Axis A for Claude Code: run it confined by Formwork with in-app permission prompts turned off.
# Because the kernel enforces the fs/net/exec wall, --dangerously-skip-permissions is no longer the
# only thing between the model and your machine — so it's safe to let the agent run uninterrupted.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
cargo build -q -p formwork-cli
FORMWORK="$REPO/target/debug/formwork"
SPEC="$REPO/examples/specs/agent-session.toml"

# Never claim more confinement than this host can back — print the per-capability fidelity report.
echo "What this host actually enforces for this spec:"
"$FORMWORK" compile --spec "$SPEC" --report-only \
    | awk '/"semantics"/{f=0} /"per-capability"/{f=1} f' | sed 's/^/  /'
echo

# claude refuses --dangerously-skip-permissions as root; formwork run does not elevate, so this is
# an ordinary user process behind a kernel wall — exactly the isolated environment the flag wants.
CMD=( "$FORMWORK" run --spec "$SPEC" -- claude --dangerously-skip-permissions )

echo "Confined launch:"
printf '  '; printf '%q ' "${CMD[@]}"; echo; echo

if command -v claude >/dev/null 2>&1; then
    echo "Launching Claude Code confined. It can write ~/project and reach HTTPS (its model API),"
    echo "but cannot read ~/.ssh, ~/.aws, keychains, or other projects — whatever it's prompted to do."
    exec "${CMD[@]}" "$@"
else
    echo "claude is not on PATH, so skipping the real launch. Install Claude Code, then re-run —"
    echo "or run ../gateway-demo.sh and the pytest suite (py/) to see the wall enforced end to end."
fi
