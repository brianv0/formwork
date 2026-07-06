# Formwork

An OS-level sandbox for agent sessions: it takes a capability spec and turns the four capabilities
that touch the real operating system — read, write, exec, net — into boundaries the kernel actually
enforces, on Linux and macOS, for an agent process and every child it spawns. Plus an MCP-aware
gateway so every tool call and every byte of egress is forced through one auditable door.

See [`formwork.md`](formwork.md) for the design and end-to-end test spec, and
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) for how it is being built.

Formwork targets **good isolation, not perfect isolation** (design §1, §3): a hard wall against
accidental, careless, and prompt-injected overreach and against untrusted code the agent runs — not
against kernel/LSM exploitation. Every enforcement claim is backed by a real mechanism on the
current host or reported as a gap; Formwork never silently claims containment it cannot deliver.

## Status

Under construction, kernel-mechanism-first (plan §4).

| Phase | What | State |
|---|---|---|
| 1 | Spec, pure compiler, fidelity report, dry-run | **done** — `FW-E2E-026/027` + narrowing/report tests green; `detect` + degraded-host honesty verified on real Linux (Docker) |
| 3 | macOS confiner (Seatbelt) | **done** — real kernel enforcement; `FW-E2E-001..006, 024` green natively |
| 5 | fd-injection transport (seam) | **done** — `FW-E2E-010/011/012` green; transport verified on macOS *and* Linux |
| — | Python E2E harness | **done** — black-box CLI tests + generated traceability, `uv`-managed |
| 6 | Gateway (MCP shading) | **done** — `FW-E2E-013..019` + `FW-ADV-004` green; backend confinement uses real Seatbelt |
| 2 | Linux confiner (Landlock + seccomp) | designed ([`docs/linux-backend.md`](docs/linux-backend.md)); honest stub — needs a 5.13+ kernel to verify |

65 Rust tests pass on macOS (`cargo test`), 8 Python E2E tests pass (`cd py && uv run pytest`),
clippy is clean under `-D warnings`, and the whole workspace cross-compiles for Linux
(`cargo check --target x86_64-unknown-linux-gnu`). On real Linux (Docker, kernel 5.10 — no Landlock)
`formwork detect` and the degraded-host honesty path (FW-E2E-025/026, FW-INV6) are verified.

## Workspace

- `crates/formwork-spec` — capability spec: types, canonical form, narrowing algebra (FW-CAP*).
- `crates/formwork-detect` — `HostProfile` detection (the only impure input to compilation).
- `crates/formwork-compile` — the pure `spec → {confiner, gateway, FidelityReport}` compiler.
- `crates/formwork-confine` — the confiners (Landlock+seccomp / Seatbelt), two postures.
- `crates/formwork-seam` — the fd-injection transport: socketpair-at-spawn + `SCM_RIGHTS` minting.
- `crates/formwork-gateway` — the MCP-aware policy proxy: shading, policing, transparent passthrough.
- `crates/formwork-cli` — the `formwork` binary (v1 embedding surface).
- `profiles/` — the subtractive default profile and sensitive set.
- `py/` — the pytest end-to-end / adversarial harness and MCP/reuse fixtures (dev-only).

## Try it

```sh
cargo build
# What can this host enforce?
cargo run -p formwork-cli -- detect
# Compile a spec to a policy + honest fidelity report, without enforcing (works on any OS):
cargo run -p formwork-cli -- compile --spec examples/e2e-001.toml --report-only
# Cross-platform dry-run: compile a Linux policy while on a Mac (FW-E2E-026):
cargo run -p formwork-cli -- compile --spec examples/e2e-001.toml --target linux-v6 --report-only
```

## Testing

`just test` (or `cargo test --workspace`) runs the pure + native-OS-backend tests on any host.
Linux enforcement is tested first-line in Docker (`just test-linux`) with Docker's own
seccomp/AppArmor disabled so only Formwork's sandbox is under test, and gated on `formwork detect`
so tests skip tiers the Docker VM kernel can't carry; `just test-linux-full` falls back to a Lima
VM with a pinned 6.12+ kernel for the ABI-v6 tier. See plan §5.

## License

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([`LICENSE-MIT`](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
