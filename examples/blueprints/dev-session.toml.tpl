# Self-hosting dev profile: build and test Formwork *itself* while confined by Formwork — the
# ultimate FW-TRA2 check. If `cargo test` and a full edit loop run clean in here with zero spurious
# denials, the confinement is transparent enough for real work.
#
# This is a TEMPLATE. `just dev-confined` renders it to a gitignored .dev-session.toml, substituting
# @REPO@ with your actual checkout path. Blueprints are absolute-path only and the CLI does not yet
# fold the child's cwd into the read grant (docs/spikes.md Spike 2), so the repo path must be named
# explicitly — the recipe does that for you regardless of where you cloned.
#
# It is examples/blueprints/agent-session.toml widened to what a Rust build touches.

# crates.io + git-over-HTTPS (cargo fetch) and the model API. Port-scoped = any HTTPS host; the fs
# wall, not an egress allowlist, is what stops exfiltration. (Once FEP-1's AllowHosts lands, prefer
# naming crates.io + the model host so egress is host-scoped and the SSRF/metadata block applies.)
# DNS still resolves: on macOS it goes through the system resolver (mDNSResponder), not a socket the
# confined process opens, so :443 egress is enough for cargo to reach the network.
net = { ports = [443] }
exec = "unrestricted"
# Scrub secret-shaped env vars but keep the model auth the dev agent needs (FW-ENV2).
env = { scrub = { allow = ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"] } }
# Deliberate widenings (FW-CRED5): the model API key through the launcher strip, and this agent's
# own ~/.claude state. Everything else in the catalog -- including ~/.cargo/credentials.toml, the
# crates.io publish token (type `cargo`) -- stays denied/stripped.
allow-credentials = ["anthropic", "claude"]

[fs]
read-mode = "ambient-minus-subtract"
reads = ["/**"]                      # ambient: rustc, ~/.rustup toolchains, system libs — read-only

# Writable working set (FW-TRA5): the repo (edits + target/ output persist) and the cargo caches a
# fetch/build writes. Everything else stays read-only.
writes = [
    "@REPO@/**",
    "~/.cargo/**",                   # registry / git / package caches cargo writes during a build
    "/tmp/**",
    "/private/tmp/**",
    "/var/tmp/**",
]

# Credential locations (ssh, cloud, keychains, browsers, other agents' state, the crates.io
# publish token, docker -- including run/docker.sock, which is host-root) are denied by the
# compiled-in catalog floor (FW-CRED4); driving Docker from inside this session cannot work, run
# `just test-linux` from an unconfined shell instead. Only the dev-specific hole remains here:
subtract = [
    # Installed binaries run UNSANDBOXED later; don't let a confined agent rewrite them (the FEP-1
    # execution-vector concern). cargo build doesn't write here; cargo install would.
    "~/.cargo/bin/**",
]

# Tamper vectors: write-denied but readable (FW-TRA7). Even developing Formwork, the agent must not
# rewrite this repo's own .git/hooks / .mcp.json / IDE tasks (they'd run unsandboxed on your machine).
write-subtract = [
    "@REPO@/.git/hooks/**",
    "@REPO@/.git/config",
    "**/.mcp.json",
    "**/.vscode/**",
    "**/.idea/**",
]
