# FEP-4 work plan — permissive recording (`learn --permissive`)

Companion to `fep-4.md` (the *what/why*) and `constitution.md` (doctrine). This document is the
*how, in what order, with which touchpoints*. Requirement/test IDs are FEP-4 draft numbering (inline
code until anchored on landing); existing IDs link to `formwork.md`. **Planning only — no code lands
from this document.**

## 1. Scope, constraints, timeline

**In scope (v1):**
- macOS-only permissive recording surfaced as `learn --permissive` (no new top-level command).
- Reuse of `reverse_compile`, the credential floor, and the proposal → accept pipeline.
- An honest `trace-feed: none` gap on Linux (fail loud, write nothing).

**Out of scope (named, deferred):**
- Linux feed (`fanotify`) and Endpoint Security — future; reported as gaps, not stubbed.
- `--out` Blueprint freeze (`FW-DISC10`) — candidate to defer past v1 (§ open decisions).
- Any change to the enforced-`learn` (denial) path.

**Constraints:**
- **Sequences after PR #18.** #18 reshapes the `learn`/`accept` surface (folds `accept` into
  `learn --list/--accept`) and the macOS denial tap in `learn.rs`. FEP-4's CLI + feed work builds on
  that surface, so it rebases onto #18 rather than racing it. Pure-core work (§5.1) is independent.
- **Spike gates mechanism.** The feed choice (fs_usage vs SBPL report vs ASID auditpipe) is unproven
  and determines whether the compile/confine layers change at all (§5.3). No mechanism code before
  the spike resolves.
- **Draft test IDs sit above the highest landed number** and are bumped as merges land tests below
  them: `FW-E2E-065`..067 (above #18's `FW-E2E-062..064`) → `070`..072 after #19 landed the MCP tests
  at `065`..067 → `072`..074 after #22 landed the discovery-trust/Linux-ptrace tests at
  `FW-E2E-070`/`071` (never the landed spec; constitution Requirements & identifiers). See
  `fep-4.md` §4/§6.

**Timeline** is expressed as ordering + the one blocking unknown, not dates: §5.1 (pure core) lands
immediately and independently; the spike (§5.2) is the critical path; §5.3–5.5 follow the spike and
rebase on #18. No calendar commitment.

## 2. Current context (from codebase research)

- `reverse_compile(records, catalog, allow, auto_widen)` in `crates/formwork-blueprint/src/discovery.rs`
  is pure and source-agnostic — it takes `DenialRecord { path, access }` and applies the floor
  (`FW-DISC3`/[FW-INV8](../formwork.md#fw-inv8)), sibling→`parent/**` folding, and zone tagging. It does
  not care whether records came from denials or opens.
- The macOS feed tap already lives in the CLI, not the confiner:
  `crates/formwork-cli/src/learn.rs` parses `log show --style ndjson`. Precedent for a CLI-owned tap.
- The compiler already opens with `(allow default)` for transparency (FW-TRA2,
  `crates/formwork-compile/src/sbpl.rs:19`) and has an **open-universe read mode**
  (`ReadMode::AmbientMinusSubtract`, `sbpl.rs:160`) — reads default-allow, only floor/subtract carve
  holes. The **credential floor is applied unconditionally** (`CompileInput.floor`, `lib.rs`).
- **Writes have no open-default mode** — `render_writes` always emits `(deny file-write* (subpath
  "/"))` then re-allows grants (`sbpl.rs:208`). So "allow all writes except floor" needs a broad
  `write` grant (verify `PathPattern` accepts `/**`) or a one-line write-axis affordance.
- **Consequence:** a floor-only permissive Blueprint = open reads (`AmbientMinusSubtract`) + broad
  write grant + automatic catalog floor. Largely expressible today; **if fs_usage is the feed, the
  compile/confine layers need essentially no change** (recording = existing `spawn_confined` of a
  floor-only Blueprint + external feed). The SBPL report/trace toggle is needed *only* if an
  in-sandbox feed (SBPL `(with report)`/`(trace)`) wins the spike.
- `HostProfile` (`crates/formwork-detect/src/lib.rs`) has no observe-capability field yet.
- CLI commands + `BlueprintArgs` are in `crates/formwork-cli/src/main.rs`; `learn_run` is the wiring
  to mirror.

## 3. Requirements to satisfy (FEP-4 §4)

- `FW-DISC7` permissive recording — a second, explicitly-unconfined observation source; loud,
  opt-in, never default.
- `FW-DISC8` floor-enforced recording — credential catalog is a hard deny during recording.
- `FW-DISC9` open-feed honesty — no feed → fail loud, write nothing; never claim complete coverage;
  output non-authoritative until accepted.
- `FW-DISC10` Blueprint synthesis/freeze — accepted grants may freeze into a standalone Blueprint.
- `FW-INV12` recording floor — no recording can observe, propose, or synthesize a credential
  location.
- Tests `FW-E2E-072` (round-trip), `FW-E2E-073` (floor), `FW-E2E-074` (no-feed fail-loud).

## 4. Design decisions (load-bearing; full rationale in `fep-4.md`)

- `learn --permissive`, not a new command (Growth; user constraint).
- Recording is `spawn_confined` of a **floor-only permissive Blueprint**, not a new Posture.
- Feed is separable from enforcement; fs_usage is the front-runner (spike decides).
- Attribution: build the subtree from **captured fork/exec/exit events, never live `ps`** (short-lived
  children), or preselect by **audit session ID**. Attribution matters more here than for `learn`
  (record's goal is a *tight* Blueprint).
- Output flows through the existing proposal → accept pipeline; stays non-authoritative
  ([FW-INV10](../formwork.md#fw-inv10)).
- **Open sub-decision:** recording enforces the *catalog floor* — does it also apply the default
  profile's protective subtracts (`.env`, agent-state, tamper vectors)? Leaning **bare-floor-only** so
  coverage is not silently narrowed (the catalog still protects secret shapes). Confirm in §5.4.

## 5. Implementation plan (ordered)

### 5.1 Pure core — `formwork-blueprint` (independent of #18 and the spike)
- Rename `DenialRecord` → `AccessRecord` in `discovery.rs`; keep a `DenialRecord` alias for the
  existing `learn.rs` call sites (expand→migrate, no breakage).
- Add `synthesize_blueprint(records, catalog, …) -> Blueprint` beside `reverse_compile`: assemble a
  standalone Blueprint (open-read base + observed reads/writes as grants, floor withheld) rather than
  a discovered-layer diff. Reuse the fold + floor logic.
- Unit tests: floor withheld from synthesis (`FW-INV12` at unit level, mirroring
  `catalog_denials_are_withheld_never_candidates`); deterministic/deduped output; read/write split.
- No OS, no spike dependency — lands immediately.

### 5.2 Spike (critical path; gates 5.3–5.5) — `docs/spikes.md`
- On real macOS: can we capture fs events **and** process fork/exec/exit lineage race-free, and
  attribute a spawn subtree? Compare **fs_usage + fork-event lineage** vs **ASID-preselected
  `auditpipe`**. Pass/fail: every open by a short-lived grandchild (`sh -c 'cc … && ld …'`) is
  attributed to the tree; a concurrent unrelated process's opens are excluded.
- Confirm path resolution (relative → absolute for `PathPattern`) and read/write derivation from
  syscall/flags.
- Decide feed; record the decision. **If fs_usage wins, 5.3 is nearly empty.**

### 5.3 Enforcement policy + (conditional) feed mechanism
- `formwork-compile`/`formwork-blueprint`: produce the floor-only permissive Blueprint (open reads +
  broad writes + catalog floor). Verify `PathPattern` `/**` write grant; else add a minimal write-axis
  open affordance mirroring `AmbientMinusSubtract`.
- **Only if an in-sandbox feed won the spike:** add the SBPL `(with report)`/`(trace)` toggle in
  `crates/formwork-compile/src/sbpl.rs` + `formwork-confine/src/macos`. **If fs_usage won: skip — no
  confiner/compiler mechanism change.**

### 5.4 Detect + honesty — `formwork-detect`
- Add `HostProfile.trace_feed: Option<TraceFeed>` (`fs-usage`/`auditpipe`/`seatbelt-report`/absent per
  spike outcome); `detect` reports it. Linux → `None`.
- Resolve the §4 open sub-decision (bare floor vs default-profile subtracts during recording).

### 5.5 CLI wiring + feed tap — `formwork-cli` (rebases on #18)
- Add `--permissive` (spelling: `--permissive` vs `--unconfined`, pin on landing) to the `learn`
  command in `main.rs`; loud UNCONFINED banner.
- New `permissive_record_run` beside `learn_run`: gate on `trace-feed`; `None` → fail loud, write
  nothing (`FW-DISC9`/[FW-INV6](../formwork.md#fw-inv6)). Spawn floor-only `spawn_confined`; run the feed;
  `reverse_compile` / `synthesize`; route through the existing proposal + `--list/--accept`.
- Feed tap module (extend `learn.rs` if SBPL-report; new module if fs_usage/auditpipe).
- `--out app.blueprint.toml` freeze (`FW-DISC10`) — or defer (open decision).

### 5.6 Tests — Python E2E + Rust
- `FW-E2E-072` round-trip; `FW-E2E-073` floor; `FW-E2E-074` no-feed fail-loud (§6).

## 6. Testing

- **Pure/unit (Rust):** `synthesize_blueprint` floor-withholding, determinism, read/write split
  (§5.1). The spike's attribution logic, if it has a pure core, is unit-tested on injected event
  sequences (the substitution `learn.rs` already uses for quiescence).
- **Real-boundary (macOS, no mocking the kernel — constitution Testing):**
  - `FW-E2E-072` — spawn a workload under the floor-only policy; observed opens synthesize a
    Blueprint; **re-enforcing it runs the same workload clean, and a path it never touched is denied**
    (paired allow/deny, [FW-E2E-024](../formwork.md#fw-e2e-024) pattern).
  - `FW-E2E-073` — a workload reading a credential during recording is denied at the kernel and the
    credential is absent from proposal and synthesized Blueprint.
  - `FW-E2E-074` — on `trace-feed: none`, `learn --permissive` fails loud and writes nothing.
- Deterministic; over-capture handled by the floor/review, not by flaky windows.

## 7. Observability

- Structured `tracing` at the CLI boundary (constitution Observability): the UNCONFINED banner, the
  feed used, observed-open count, and coverage caveat (`FW-DISC9`) on stderr; the proposal pointer is
  product output on stdout (matches #18). No new subscriber (libraries only emit).

## 8. Rollout

- Pre-release, additive/expand-only (new `learn` flag, new optional `HostProfile` field, new artifact
  convention) → no version bump (precedent: FEP-3 "Adopted").
- macOS-first; Linux ships the honest gap. Constitution/`formwork.md` amendments (fep-4 §5) land *with*
  the code, not before; draft IDs gain anchors then.
- Sequenced after #18.

## 9. Security

- Threat model narrows to **trusted recording** (fep-4 §1.1) — recorded as a tracked, expiring
  exception (closed on FEP-4 landing) per constitution Precedence & Conflicts.
- Two structural mitigations, both tested: credential floor **kernel-enforced** during recording
  (`FW-DISC8`) and **withheld** from synthesis by `reverse_compile` (`FW-INV12`); output
  **non-authoritative** until accepted ([FW-INV10](../formwork.md#fw-inv10)).
- **New footprint:** the feed may require `sudo` (fs_usage/auditpipe). This is an escalation over
  today's root-free macOS path — occasional, operator-driven, amortized (record once, enforce many).
  Called out honestly; it does not touch the enforced-`run` path.

## 10. Constitution conformance

| Change | Rule | How it conforms |
|---|---|---|
| `learn --permissive` (no new command) | Growth | one flag, reuses the discovery concept |
| Continues DISC family | Requirements & identifiers | no new family → no Concepts-grade family amendment |
| `spawn_confined` floor-only policy | Concepts / Vocabulary | real confinement; no new Posture/concept |
| `synthesize` in `formwork-blueprint`; feed tap in `formwork-cli` | Layers | pure stays pure; tap follows the `learn.rs` precedent |
| `AccessRecord` rename with alias | Data model | expand→migrate, no breaking change |
| No new crate | Growth (hardest no on deps) | fs_usage/auditpipe via CLI; Linux `fanotify` later extends `formwork-confine` |
| Unconfined-except-floor run vs `FW-DISC1` | Precedence & Conflicts | STOP → amend (fep-4 §5) + tracked exception |
| Draft IDs renumbered above #18 | Requirements & identifiers | renumber the unlanded draft, never the landed spec |
