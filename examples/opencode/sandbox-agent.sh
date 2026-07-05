#!/usr/bin/env bash
# Axis A for opencode: run it confined by Formwork with approvals set to auto-allow. opencode's
# "stop asking" mode is `permission: "allow"` (or `--auto`); under `formwork run` the kernel wall is
# what scopes the process, so auto-allowing every action no longer means running unprotected.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
cargo build -q -p formwork-cli
FORMWORK="$REPO/target/debug/formwork"
SPEC="$REPO/examples/specs/agent-session.toml"

echo "What this host actually enforces for this spec:"
"$FORMWORK" compile --spec "$SPEC" --report-only \
    | awk '/"semantics"/{f=0} /"per-capability"/{f=1} f' | sed 's/^/  /'
echo

# `permission: "allow"` lives in opencode.json; `--auto` is the launch-time equivalent for `run`.
CMD=( "$FORMWORK" run --spec "$SPEC" -- opencode )

echo "Confined launch (with permission: \"allow\" set in opencode.json):"
printf '  '; printf '%q ' "${CMD[@]}"; echo; echo

if command -v opencode >/dev/null 2>&1; then
    echo "Launching opencode confined. With approvals auto-allowed, Formwork's kernel wall is what"
    echo "scopes reads, writes, exec, and egress."
    exec "${CMD[@]}" "$@"
else
    echo "opencode is not on PATH, so skipping the real launch. Install opencode, then re-run — or"
    echo "run ../gateway-demo.sh and the pytest suite (py/) to see the wall enforced end to end."
fi
