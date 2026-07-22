# Implementation status

Contributor-facing status by phase (plan §4). The README stays user-facing; requirement
identifiers like `FW-CAP2` cite definitions in [`formwork.md`](../formwork.md) (anchored, so
`formwork.md#fw-cap2` jumps to the definition; see the constitution's *Requirements &
identifiers*).

| Phase | What | State |
|---|---|---|
| 1 | Blueprint, pure compiler, fidelity report, dry-run | **done** — `FW-E2E-026/027` + narrowing/report tests green; degraded-host honesty verified on real Linux (Docker) |
| 2 | Linux confiner (Landlock + seccomp) | **done** — real kernel enforcement ([`docs/linux-backend.md`](linux-backend.md)): Landlock fs + net tiers, seccomp baseline, symlink/`/proc/self`/UDP hardening; enforcement tests gate on the host tier via `formwork detect` (Docker for the common tiers, Lima for ABI-v6) |
| 3 | macOS confiner (Seatbelt) | **done** — real kernel enforcement; `FW-E2E-001..006, 024` green natively |
| 5 | fd-injection transport (seam) | **done** — `FW-E2E-010/011/012` green; transport verified on macOS *and* Linux |
| — | Python E2E harness | **done** — black-box CLI tests + generated traceability, `uv`-managed |
| 6 | Gateway (MCP shading) | **done** — `FW-E2E-013..019` + `FW-ADV-004` green; backend confinement uses real Seatbelt. Pattern shading ([`FW-GW9`](../formwork.md#fw-gw9)): allow/deny regex over tool/resource/prompt names, deny-terminal — `FW-E2E-065..067` (fixture) + `FW-E2E-069` (compile) green everywhere; `FW-E2E-068` drives a real published server (`@modelcontextprotocol/server-everything`) through the gateway in the `mcp-integration` CI job |
| — | Discovery (`learn` / accept loop, FEP-2 Part D) | **macOS only** — the unified-log denial feed is wired (post-hoc, polled to quiescence); on other hosts `learn` fails fast before the workload runs. A Linux feed (Landlock audit, kernel 6.15+) is the open workstream. |

`cargo test --workspace` runs the pure + native-backend tests on any host; `cd py && uv run
pytest` runs the E2E harness (macOS-marked and enforcement-gated tests skip where the host can't
carry them). Clippy is clean under `-D warnings`, and the whole workspace cross-compiles for Linux
(`cargo check --target x86_64-unknown-linux-gnu`).

Adopted enhancement proposals and their planning docs live in this directory: `fep-1.md`
(deferred egress/violation-stream reservations), `fep2.md` + `fep2-plan.md` (credential catalog,
launcher, discovery), `fep-3.md`, and `competition-research.md`.
