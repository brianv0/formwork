# Implementation status

Contributor-facing status by phase (the build order of [`formwork.md`](../formwork.md) §12). The README stays user-facing; requirement
identifiers like `FW-CAP2` cite definitions in [`formwork.md`](../formwork.md) (anchored, so
`formwork.md#fw-cap2` jumps to the definition; see the constitution's *Requirements &
identifiers*).

| Phase | What | State |
|---|---|---|
| 0 | Scaffolding + mechanism spikes | **done** — workspace, CI, and the de-risking spikes ([`docs/spikes.md`](spikes.md)) for Seatbelt / Landlock / seccomp before building |
| 1 | Blueprint, pure compiler, fidelity report, dry-run | **done** — `FW-E2E-026/027` + narrowing/report tests green; degraded-host honesty verified on real Linux (Docker). The narrowing *property* test (fuzzed sequences, [`FW-INV1`](../formwork.md#fw-inv1)) waits on the fuzz infrastructure (register below) |
| 2 | Linux confiner (Landlock + seccomp) | **done** — real kernel enforcement ([`docs/linux-backend.md`](linux-backend.md)): Landlock fs + net tiers, seccomp baseline, symlink/`/proc/self`/UDP hardening; enforcement tests gate on the host tier via `formwork explain --json` (Docker for the common tiers, Lima for ABI-v6). The TOCTOU race test ([`FW-ADV-002`](../formwork.md#fw-adv-002)) is **owed**; a static symlink test stands for it |
| 3 | macOS confiner (Seatbelt) | **done** — real kernel enforcement; `FW-E2E-001..006, 024` green natively |
| 4 | Reuse validation + default-profile tuning | **partial** — default-profile tuning done (credential floor + tamper-vector write-subtracts ship in `profiles/default.toml`); the reuse-workload fixtures (a real pytest/npm/git/C build under the baseline, [`FW-E2E-020`](../formwork.md#fw-e2e-020)..023) and the §8 overhead measurements (spawn, compile, MCP round-trip; `just bench` has no bench targets) are **still owed** |
| 5 | fd-injection transport (seam) | **done, unwired** — `FW-E2E-010/011/012` green; transport verified on macOS *and* Linux. No crate depends on `formwork-seam`: FEP-5 carried egress through the connect supervisor and the authenticated listener instead of minted fds, so the seam has no planned consumer. Wiring it (for MCP) or retiring the crate is an open decision |
| 6 | Gateway (MCP shading) | **done** — `FW-E2E-013..019` + `FW-ADV-004` green; backend confinement uses real Seatbelt. Pattern shading ([`FW-GW9`](../formwork.md#fw-gw9)): allow/deny regex over tool/resource/prompt names, deny-terminal — `FW-E2E-065..067` (fixture) + `FW-E2E-069` (compile) green everywhere; `FW-E2E-068` drives a real published server (`@modelcontextprotocol/server-everything`) through the gateway in the `mcp-integration` CI job. Not built: streamable-http/SSE backends ([`FW-GW1`](../formwork.md#fw-gw1); stdio only), confinement of the gateway's own process ([`FW-GW7`](../formwork.md#fw-gw7)), and the gateway-bypass test [`FW-ADV-003`](../formwork.md#fw-adv-003) |
| 7 | Degraded-host honesty + optional tiers | **done, with gaps** — fail-closed fidelity reporting on incapable hosts; Landlock net port-tier and ABI-v6 socket/signal scoping and exec allow-lists ([`docs/linux-backend.md`](linux-backend.md)). Exec allow-lists are checked by `explain` only, with no kernel test on either backend; [`FW-E2E-025`](../formwork.md#fw-e2e-025) has no automated run on a degraded host, and CI has no old-kernel or 6.12+ job |
| — | Python E2E harness | **done** — black-box CLI tests + generated traceability, `uv`-managed |
| — | FEP-5: host-scoped egress, brokering, channels, isolation | **landed, both OSes** — host rules through the session Gateway ([`FW-EGR7`](../formwork.md#fw-egr7)–15) with the Linux connect supervisor, TLS inspection and credential brokering ([`FW-CRED10`](../formwork.md#fw-cred10)–15), the host-service channel baseline and the `open-url` opener shim ([`FW-ISO13`](../formwork.md#fw-iso13)–18), the Linux isolation tier ([`FW-ISO10`](../formwork.md#fw-iso10)), private temp directories, and host/channel discovery in `learn` ([`FW-DISC12`](../formwork.md#fw-disc12)). Requirements and tests folded into `formwork.md`; record and departures: [`fep-5-plan.md`](fep-5-plan.md). The macOS characterization suite (FEP-5 §6.3) runs on `macos-14` and `macos-15` ([`macos-characterization.md`](macos-characterization.md)), with `FW-E2E-080`/081/091 and `FW-ADV-019`; the macOS peer check makes `net-host-scope` `Enforced`, and the characterization moved three verdicts the other way: other processes' environments are `Unenforceable` (Seatbelt does not mediate `kern.procargs2`; `formwork` zeroes its own), `net-default-deny` is `Partial` (the loopback-callback listener reaches the host's other addresses), and IOKit stays open (`Partial`) |
| — | FEP-6: the egress engine | **landed, both OSes** — the tunnel grade checks the ClientHello's server name ([`FW-EGR16`](../formwork.md#fw-egr16)); one resolution, every address classified, private and host addresses by exact name only ([`FW-EGR17`](../formwork.md#fw-egr17)–19); inspection by default with `allow:` and `tunnel:` replacing `any:` and `https:` ([`FW-BP16`](../formwork.md#fw-bp16)); HTTP/1.1-only ALPN, streamed bodies, authorized forwarding, a keep-alive upstream pool ([`FW-EGR20`](../formwork.md#fw-egr20)–24); a name-constrained session CA ([`FW-EGR25`](../formwork.md#fw-egr25)); the operator's upstream proxy ([`FW-EGR26`](../formwork.md#fw-egr26)); custody, the reflection guard and presentation limits ([`FW-CRED16`](../formwork.md#fw-cred16)–19); refusal reasons and grant records ([`FW-FID12`](../formwork.md#fw-fid12)–13). Requirements and tests folded into `formwork.md`; record and departures: [`fep-6-plan.md`](fep-6-plan.md). The run-level tests and the client matrix (`FW-E2E-094`) run on both OSes, `FW-CRED16` included (`PT_DENY_ATTACH` on macOS, characterized); the time budgets (`FW-E2E-093`, `FW-E2E-096`) run in release on every runner against calibrated budgets, and `FW-E2E-092` holds a 256 MiB upload to 16 MiB of Gateway memory; the integrated scenario forms ([`FW-E2E-100`](../formwork.md#fw-e2e-100)–102, [`FW-E2E-105`](../formwork.md#fw-e2e-105), [`FW-ADV-025`](../formwork.md#fw-adv-025)) and `FW-E2E-092`'s `git push` half are **still owed**, and [`FW-E2E-106`](../formwork.md#fw-e2e-106) is blocked on in-session loopback (FEP-6 §11) |
| — | Discovery (`learn` / accept loop, FEP-2 Part D) | **done, both OSes** — macOS via the unified-log feed (read live with `log stream`, which counts as attached once it reports a probe denial, and post-hoc with `log show`, polled to quiescence, [`FW-E2E-064`](../formwork.md#fw-e2e-064); a session's denies carry a per-session tag, so only its own records are proposed); Linux via the ptrace feed ([`FW-E2E-071`](../formwork.md#fw-e2e-071)): an unconfined `strace` traces the confined run, so denials are exact-attributed with no persistence latency (needs `strace` installed and Landlock). A host with neither fails fast before the workload runs ([`FW-E2E-062`](../formwork.md#fw-e2e-062)). Landlock's native audit feed (kernel 6.15+) remains a future alternative tap. |

`cargo test --workspace` runs the pure + native-backend tests on any host; `cd py && uv run
pytest` runs the E2E harness (macOS-marked and enforcement-gated tests skip where the host can't
carry them). Clippy is clean under `-D warnings`, and the whole workspace cross-compiles for Linux
(`cargo check --target x86_64-unknown-linux-gnu`).

## Owed work

Specified and not built, or built and not tested as the spec states, by where it was specified.
The phase rows above carry the same items in context; this is the list to pick from.

| Item | Specified by | What is missing |
|---|---|---|
| Reuse-workload fixtures | Phase 4, [`FW-E2E-020`](../formwork.md#fw-e2e-020)..023 | a real pytest, npm, git and C build under the default profile; the primary tests of [`FW-TRA1`](../formwork.md#fw-tra1)/[`FW-TRA2`](../formwork.md#fw-tra2) |
| §8 overhead measurements | Phase 4, [`FW-TRA6`](../formwork.md#fw-tra6) | spawn (< 50 ms), compile (< 5 ms) and MCP round-trip (< 2 ms) are unmeasured; only the egress rows are ([`FW-E2E-096`](../formwork.md#fw-e2e-096)) |
| Fuzz/property infrastructure | [`FW-INV1`](../formwork.md#fw-inv1), [`FW-INV2`](../formwork.md#fw-inv2), [`FW-INV4`](../formwork.md#fw-inv4) | no `proptest` or fuzz targets; FEP-6 names the egress parsers as targets |
| Missing black-box tests | pre-FEP spec | [`FW-E2E-008`](../formwork.md#fw-e2e-008) (raw-socket proxy bypass), [`FW-E2E-025`](../formwork.md#fw-e2e-025) (on a degraded host), [`FW-E2E-036`](../formwork.md#fw-e2e-036) (env scrub through `run`; unit-tested only), [`FW-ADV-002`](../formwork.md#fw-adv-002) (TOCTOU race), [`FW-ADV-003`](../formwork.md#fw-adv-003) (gateway bypass); [`FW-E2E-028`](../formwork.md#fw-e2e-028) runs dry, not enforced; [`FW-E2E-024`](../formwork.md#fw-e2e-024)'s macOS sweep probes fs-read and net only, with no Linux sweep |
| "Other projects" in the default deny set | [`FW-TRA3`](../formwork.md#fw-tra3) | the default profile leaves other projects readable (not writable); only an explicit `subtract` denies them, which is how [`FW-E2E-003`](../formwork.md#fw-e2e-003) tests the sibling-project case. Either the requirement narrows or the profile learns where projects live |
| Exec allow-list kernel test | [`FW-ISO4`](../formwork.md#fw-iso4)/[`FW-ISO9`](../formwork.md#fw-iso9) | a paired allow/deny exec probe on both backends; today the report says `Enforced` from `explain` checks alone |
| HTTP/SSE MCP backends | [`FW-GW1`](../formwork.md#fw-gw1) | the gateway fronts stdio backends only |
| Gateway self-confinement | [`FW-GW7`](../formwork.md#fw-gw7) | `formwork gateway` and the session Gateway run unconfined in the `formwork` process; no report row says so. FEP-6 §11 holds the spike |
| Seam wiring | Phase 5 | no consumer; wire it or retire `formwork-seam` |
| Violation stream | FEP-1 [`FW-FID5`](fep-1.md#fw-fid5), [`FW-E2E-040`](fep-1.md#fw-e2e-040) | egress refusals emit records on the operator channel; there is no consumable stream for embedders and no runtime record of fs denials |
| FEP-1 tests | [`FW-E2E-032`](../formwork.md#fw-e2e-032), [`FW-ADV-011`](../formwork.md#fw-adv-011) | the tunnel-grade honesty test and the env-exfiltration composition test |
| FEP-1 default configurations | `docs/fep-1.md` | no `strict` profile; an unset `$HOME` falls back to `/` instead of failing loud; whether `run` folds the working directory into reads is undecided |
| FEP-4 mechanism | `docs/fep-4.md`, `docs/fep-4-plan.md` | the feed spike, `HostProfile` trace feed, `learn --permissive`, the recording run, `--out` freeze, and the tests drafted as `FW-E2E-072`..074; only the pure core landed |
| FEP-5 | `docs/fep-5-plan.md` §5 | nothing in scope; repeat the macOS characterization on a SIP-enabled Mac before a release that changes a verdict |
| FEP-6 integrated scenarios | `docs/fep-6-plan.md` §5 | [`FW-E2E-100`](../formwork.md#fw-e2e-100)–102, [`FW-E2E-105`](../formwork.md#fw-e2e-105), [`FW-ADV-025`](../formwork.md#fw-adv-025) and `FW-E2E-092`'s `git push` half need `git http-backend`, registry and network-namespace fixtures; [`FW-E2E-106`](../formwork.md#fw-e2e-106) is blocked on FEP-6 §11 |
| Unknown MCP server→client requests | [`FW-GW3`](../formwork.md#fw-gw3); the retired implementation plan's risk register | the gateway polices sampling and elicitation and forwards every other server→client frame (`formwork-gateway/src/lib.rs`, the backend reader); the plan listed default-deny of unknown request methods as the mitigation for protocol growth, and it was never built |

## Tracked test-method exceptions

A test that substitutes a single targeted assertion for a spec-stated verification method is a
recorded exception, not an in-code caveat (constitution: *Precedence & Conflicts* — each records the
rule it suspends, the reason, and an expiry). The live register:

| Requirement | Spec method | Standing in | Reason | Expiry / owner |
|---|---|---|---|---|
| [`FW-INV1`](../formwork.md#fw-inv1) | fuzzed blueprint/narrow sequences | example-based unit tests of the narrowing algebra (`crates/formwork-blueprint/src/narrow.rs`) | fuzz/property infra not yet built | deferred; fuzz-infra FEP TBD |
| [`FW-INV2`](../formwork.md#fw-inv2) | fuzzed over random spawn trees | one targeted assertion — a nested forked descendant down to the shed-probe leaf (`crates/formwork-confine/tests/linux_confine.rs`) | fuzz/property infra not yet built | deferred; fuzz-infra FEP TBD |
| [`FW-INV4`](../formwork.md#fw-inv4) | fuzzed over guessed names and out-of-band identifiers | one targeted assertion — a hidden-real and an out-of-band identity per axis (`crates/formwork-gateway/tests/gateway.rs`) | fuzz/property infra not yet built | deferred; fuzz-infra FEP TBD |

## Deprecations

Compat shims are exceptions to the command-surface rule and expire at a named event (constitution:
*Precedence & Conflicts*). The live register is **empty** — the pre-release back-compat shims below
were removed ahead of the first tagged release; each surface now has exactly one spelling:

| Removed surface | Use instead |
|---|---|
| hidden `formwork detect` | `formwork explain --json` (the `host` field) |
| hidden `formwork enforce-self` | `formwork run --confine-self` |
| hidden `formwork accept` | `formwork learn --list` / `--accept` |
| `--spec` alias | `--blueprint` |
| host-rule verbs `https:` and `any:` (FEP-5) | `tunnel:` and `allow:` (FEP-6 §9 j); refused at parse |

Enhancement proposals and their planning docs live in this directory:

- [`fep-1.md`](fep-1.md) — capability model and host-scoped egress (landed and folded); the
  violation stream (deferred) is the remainder.
- [`fep-2.md`](fep-2.md) + [`fep-2-plan.md`](fep-2-plan.md) — credential catalog, launcher, discovery (landed).
- [`fep-3.md`](fep-3.md) — filesystem verb rules (landed).
- [`fep-4.md`](fep-4.md) + [`fep-4-plan.md`](fep-4-plan.md) — permissive recording (`learn --permissive`);
  **in flight** — the pure core has landed, the deviating mechanism has not.
- [`fep-5.md`](fep-5.md) + [`fep-5-plan.md`](fep-5-plan.md) — host-scoped egress, credential brokering,
  host-service channels, process isolation (landed and folded; macOS characterized; the design
  record stays).
- [`fep-6.md`](fep-6.md) + [`fep-6-plan.md`](fep-6-plan.md) — the egress engine: tunnel and inspected
  grades, destination classes, the session CA, brokering in the engine (landed and folded; the
  design record and the scenarios' configurations stay).

Supporting docs: [`linux-backend.md`](linux-backend.md) (Landlock/seccomp design),
[`macos-characterization.md`](macos-characterization.md) (what Seatbelt was observed to do, C1–C9),
[`mcp-tool-patterns.md`](mcp-tool-patterns.md) (FW-GW9 shading), [`spikes.md`](spikes.md)
(mechanism spikes), and the historical records [`competition-research.md`](competition-research.md)
(2026-07 landscape snapshot), [`omnigent-integration-eval.md`](omnigent-integration-eval.md) (the
evaluation that motivated FEP-5), [`usability-review.md`](usability-review.md) and
[`unstated-requirements.md`](unstated-requirements.md).
