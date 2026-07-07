# Formwork task runner. `just` is a convenience wrapper — every recipe is a plain command you can
# also run by hand. Install: `cargo install just` or `brew install just`.

set shell := ["bash", "-uc"]

# Docker image used for first-line local Linux testing (plan §5). The kernel is the Docker VM's,
# not the image's, so the harness gates on `formwork detect` and skips tiers the kernel can't carry.
linux_image := "formwork-linux-test"
# Unconfined so Docker's own seccomp/AppArmor never masks the sandbox under test (plan §5).
docker_test_flags := "--security-opt seccomp=unconfined --security-opt apparmor=unconfined"

default:
    @just --list

# --- build & test ---------------------------------------------------------------------------

build:
    cargo build --workspace

# Rust unit + integration tests (pure + native-OS backend). Runs on any host.
test:
    cargo test --workspace

# Native macOS tests, including the Seatbelt confiner (Phase 3).
test-macos: test
    @echo "ran native tests (Seatbelt backend exercised where present)"

# First-line Linux path: build a test image and run the suite in a container. Docker's own
# confinement is disabled so only Formwork's sandbox is under test; the kernel is the Docker VM's.
test-linux:
    docker build -t {{linux_image}} -f docker/Dockerfile.linux-test .
    docker run --rm {{docker_test_flags}} {{linux_image}} \
        bash -lc 'formwork detect && cargo test --workspace'

# Full-matrix fallback for tiers Docker's VM kernel can't provide (e.g. Landlock ABI v6
# socket/signal scoping, which needs 6.12+). Requires Lima with a pinned kernel image.
test-linux-full:
    limactl shell formwork -- bash -lc 'cd {{justfile_directory()}} && cargo test --workspace'

# Python end-to-end / adversarial harness (uv-managed modern Python; system python is 3.9).
test-e2e:
    cd py && uv run pytest -v

# --- inspection -----------------------------------------------------------------------------

detect:
    cargo run -q -p formwork-cli -- detect

# Compile the default profile against a synthetic target and print the fidelity report.
compile-default target="macos":
    cargo run -q -p formwork-cli -- compile --blueprint profiles/default.toml --target {{target}} --report-only

fmt:
    cargo fmt --all

lint:
    cargo clippy --workspace --all-targets -- -D warnings

bench:
    cargo bench --workspace

# --- dogfood & unattended dev ---------------------------------------------------------------

# One gate for unattended runs: format check, lint, and the native test suite (real Seatbelt on
# macOS). A green `just check` is the bar every checkpoint commit should clear. Mirrors CI.
check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace

# Self-host: run Claude Code confined by Formwork against THIS checkout — prompts off, kernel wall
# on. Renders examples/blueprints/dev-session.toml.tpl (with your checkout path) into a gitignored
# .dev-session.toml, prints the enforced-capability report, then launches Claude confined.
# macOS-only today (the Linux confiner is a stub). This is the VERIFICATION wall, not the Docker
# loop: the dev blueprint subtracts ~/.docker/** so the host-root docker socket is unreachable, so
# you cannot drive Docker from in here — run `just test-linux` from an unconfined shell for that.
dev-confined *ARGS: build
    #!/usr/bin/env bash
    set -euo pipefail
    repo="{{justfile_directory()}}"
    bp="$repo/.dev-session.toml"
    sed "s#@REPO@#$repo#g" "$repo/examples/blueprints/dev-session.toml.tpl" > "$bp"
    fw="$repo/target/debug/formwork"
    echo "Enforced capabilities for this dev session:"
    "$fw" compile --blueprint "$bp" --report-only \
        | awk '/"semantics"/{f=0} /"per-capability"/{f=1} f' | sed 's/^/  /'
    echo
    if ! command -v claude >/dev/null 2>&1; then
        echo "claude not on PATH — install Claude Code, then re-run. Rendered blueprint: $bp"
        exit 0
    fi
    exec "$fw" run --blueprint "$bp" -- claude --dangerously-skip-permissions {{ARGS}}
