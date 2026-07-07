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
