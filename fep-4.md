# FEP-4 (proposal): permissive recording — synthesize a Blueprint from an observed run

**Formwork Enhancement Proposal 4 — proposal, not landed.** Companion to `formwork.md`
(design + end-to-end spec) and `constitution.md` (doctrine).

**Status: nothing in this document mutates the landed spec or the constitution yet.** Per the
constitution (Requirements & identifiers; Precedence & Conflicts), a draft lives in its FEP until
adoption, and the landed docs stay stable. The amendments in §5 are written as apply-on-landing
blocks for review. Code-wise, the **non-deviating pure core** has landed ahead of the mechanism per
the work plan (`docs/fep4-plan.md` §5.1) — the `AccessRecord` rename (with its `DenialRecord`
alias), `synthesize_blueprint`, and the `floor_only_permissive` Blueprint constructor, all ordinary
confinement exercised only through the pure compiler and tests. The **deviating** parts — a run
without a full wall — stay unlanded (§6). New identifiers are draft numbering (written as inline code, which the
requirements canary skips) until they are anchored on landing; the draft test IDs are renumbered to
sit above the highest landed number (`FW-E2E-069` today) so no landed or drafted number collides —
see §4 and §6 (they moved off `FW-E2E-065`..067 once PR #19 landed the MCP-shading tests there).

---

## 1. Problem

Discovery today ([FW-DISC1](formwork.md#fw-disc1)–6) is *enforce-then-widen*: a `learn` run is
enforced unchanged, the kernel logs **denials**, and those reverse-compile into a reviewable
proposal. This is the right default — the wall never drops — but the denial feed is an **indirect,
lossy, platform-specific** signal: you only learn a workload needs a path when the kernel *denies*
it, *logs* it, and the log *persists* in time, three failures that compound (the macOS
short-lived-workload loss and the Linux "no denial feed at all" gap are exactly PR #18's subject).

There is a complementary need this cannot serve: **bootstrapping a tight Blueprint from zero for a
workload the operator trusts** — a build, a test suite, a known tool. Here the operator wants the
*complete* set of paths the workload touches, not just the ones a baseline happened to deny, and
there is no adversary present during the profiling run. The natural mechanism is to run the workload
**permissively** and observe every file open, then synthesize the allowlist that will confine
*future, untrusted* runs. This is the "locked-down blueprint from a traced execution" idea.

### 1.1 Threat model — trusted recording

A permissive recording runs with **no confinement wall except the credential floor**. That is a
deliberately narrower threat model than `learn`'s, and it must be stated:

> **Trusted-recording threat model.** A permissive recording assumes no adversary is present
> *during recording*: the operator is profiling a workload they trust to synthesize the Blueprint
> that will confine *future, untrusted* runs. The wall protects the enforced run, not the recording
> run. Recording is loud, opt-in, and never a default; it never presents itself as confinement.

Two structural mitigations keep this defensible rather than a "grant-whatever-is-attempted" footgun
(the mode `formwork.md` §5.10 exists to forbid):

1. **The credential floor is enforced *during* the recording** (`FW-DISC8`/`FW-INV12`). The catalog
   ([FW-CRED4](formwork.md#fw-cred4)) compiles into a hard deny even in permissive mode, so a
   credential the workload touches is denied at the kernel and therefore never appears as an
   observed open — it cannot enter the proposal or the synthesized Blueprint. This is the structural
   answer to "permissive tracing launders your secrets into the policy."
2. **The output stays non-authoritative** ([FW-INV10](formwork.md#fw-inv10)). Observed opens flow
   through the *same* proposal → accept pipeline as denial-learning. The recording proposes; the
   operator disposes. A recording is not a live widening of anything — there is no enforced session
   to weaken, because the operator explicitly and loudly ran without one.

## 2. Design

The load-bearing decision is that permissive recording is **not a new concept** — it is a **second
observation source for discovery**, and it reuses the existing machinery almost entirely.

### 2.1 It folds into `learn` (no new top-level command)

Per Growth (default *no* to a new subcommand; PR #18 is actively shrinking the CLI surface by
folding `accept` into `learn`), recording is a flag on `learn`, not a new verb:

```
formwork learn --permissive -- <cmd> …     # unconfined-except-floor; observe every open
formwork learn            -- <cmd> …        # today: enforced; observe denials
formwork learn --list / --accept <N|pat> / --accept-all
```

One observation concept, two sources; the entire review/accept UI ([FW-DISC5](formwork.md#fw-disc5))
is reused verbatim. `--permissive` is loud by construction — the operator must type it — satisfying
"opt-in, never default." (The brasher `--unconfined` spelling is an open naming call, §7.)

### 2.2 The run is `spawn_confined` with a floor-only permissive policy

Recording is **not** a new Posture. Posture is a closed concept (`spawn-confined` / `confine-self`,
"apply the Confiner"), and an "observe posture" that applied no confiner would blur it. Instead the
recording run is an ordinary `spawn_confined` against a **floor-only Blueprint**: allow-default for
everything *except* the credential catalog, which stays a hard deny, plus a "report/trace" toggle so
the backend surfaces the opens it allows.

This keeps every concept intact:

- It is a real [CompiledPolicy](formwork.md#fw-cap5) from a Blueprint (the floor) + a HostProfile —
  the compiler stays pure ([FW-CAP2](formwork.md#fw-cap2)/[FW-E2E-026](formwork.md#fw-e2e-026)).
- It is genuine confinement (the floor *is* enforced), so `spawn_confined` / `confine` keep their
  vocabulary meaning; the run is weak, not absent.
- On macOS the mechanism is the same Seatbelt/SBPL the Confiner already installs, in a permissive
  posture with a report modifier — plausibly **no new `formwork-confine` code beyond a report flag**.

### 2.3 Observed opens reuse `reverse_compile` verbatim

`formwork_blueprint::reverse_compile` already takes `{path, access}` records and is agnostic to
whether they came from denials or opens. Feeding observed opens through it inherits, for free: the
credential floor ([FW-DISC3](formwork.md#fw-disc3)/[FW-INV8](formwork.md#fw-inv8)) — a second line
of defence behind the kernel-enforced floor of §2.2 — sibling→`parent/**` folding, and auto-widen
zone tagging ([FW-DISC4](formwork.md#fw-disc4)). The only rename is `DenialRecord` → `AccessRecord`
(with a kept alias; both are the same shape). This is the largest reuse and the reason the feature
is small.

### 2.4 Output: proposal, then optional freeze

Recorded grants land in the existing proposal and, on accept, the provenance-carrying discovered
layer ([FW-DISC6](formwork.md#fw-disc6)) — reusing the sticky accumulation across runs so an
operator profiles several code paths before deciding. A recording is therefore, like denial-learning,
**non-authoritative until accepted**. As a convenience, `learn --permissive --out app.blueprint.toml`
**freezes** the accepted grants into a standalone Blueprint (the *existing* schema, a new file
convention, `FW-DISC10`) ready to enforce directly. A synthesized Blueprint carries provenance and
is a machine-written, human-reviewed discovery artifact like the others (Data model).

### 2.5 macOS-first; Linux is an honest gap

Growth requires it: "the Phase-2 Landlock crates stay unwired until a real kernel verifies them." An
unverifiable Linux observer would be the same violation, and Linux enforcement itself is still a stub
here. So v1 is **macOS** (Seatbelt is real and end-to-end verifiable — record→enforce round-trips on
the same host). Linux reports `trace-feed: none` and `learn --permissive` **fails loud, writing
nothing** ([FW-INV6](formwork.md#fw-inv6)), exactly as `learn`-on-Linux fails fast today. When Linux
lands, `fanotify` (`FAN_OPEN` + `FAN_REPORT_DFID_NAME`, PID-subtree filtered) is the intended feed,
and it **extends `formwork-confine`** rather than adding a crate (Growth's hardest *no* is on deps).

### 2.6 Where each piece lives (Layers)

| Piece | Crate | Note |
|---|---|---|
| `AccessRecord` rename; reused `reverse_compile`; Blueprint synthesis/freeze | `formwork-blueprint` (pure) | already home to discovery reverse-compile |
| floor-only allow-default policy + report/trace toggle | `formwork-compile` (pure) + `formwork-confine` (macOS SBPL) | a permissive `CompiledPolicy`; report flag on the Seatbelt backend |
| `HostProfile.trace_feed` | `formwork-detect` | small stretch of "what the kernel can enforce" → "+ observe"; a reviewed Data-model surface, not a new concept |
| the open-feed tap | `formwork-cli` | precedent: the macOS denial tap already lives in `learn.rs`, not in `formwork-confine` |

No new crate, no new top-level command, no new concept, no new requirement *family*.

## 3. Surface changes (each measured against Growth)

- **CLI:** one new flag, `learn --permissive` (+ the existing `--out` idea for freeze). No new
  subcommand. Reviewed CLI surface (Data model).
- **`HostProfile.trace_feed: Option<TraceFeed>`** (`fanotify` / `seatbelt-trace` /
  `endpoint-security` / absent). `detect` reports it so recording's availability is honest per host
  (mirrors PR #18's proposed `denial-feed` line). Reviewed CompiledPolicy/HostProfile surface.
- **Blueprint schema:** unchanged. Synthesis emits the existing types; freeze writes a Blueprint file.
- **Discovery artifacts:** the proposal and discovered layer are unchanged; a frozen
  `*.blueprint.toml` is the one new (optional) machine-written surface.

## 4. Proposed requirements (draft numbering — anchored on landing)

Continues the **DISC** family (no new family, therefore no Concepts-grade family amendment) and adds
one invariant. Draft IDs, renumbered above PR #18:

- `FW-DISC7` **Permissive recording.** A second, explicitly-unconfined discovery observation source
  (`learn --permissive`): the run is not enforced except for the credential floor, its file opens
  are observed and reverse-compiled, and it is loud, opt-in, and never a default. The alternative to
  enforced denial-learning ([FW-DISC1](formwork.md#fw-disc1)) when the operator trusts the workload
  and wants complete coverage rather than a baseline's denial gaps (§1.1 threat model).
- `FW-DISC8` **Floor-enforced recording.** During a permissive recording the credential catalog
  ([FW-CRED4](formwork.md#fw-cred4)) is compiled and enforced as a hard deny; only non-floor opens
  are observable, so a credential is denied at the kernel and never enters the proposal or a
  synthesized Blueprint — belt-and-suspenders with the reverse-compile floor
  ([FW-DISC3](formwork.md#fw-disc3)).
- `FW-DISC9` **Open-feed honesty.** A host with no open-observation feed makes recording fail loud
  and write nothing ([FW-INV5](formwork.md#fw-inv5)/[FW-INV6](formwork.md#fw-inv6)); a recording
  never claims complete coverage (it observed only the paths the run executed), and its output is
  non-authoritative ([FW-INV10](formwork.md#fw-inv10)) until accepted or frozen.
- `FW-DISC10` **Blueprint synthesis / freeze.** Accepted recorded grants may be frozen into a
  standalone Blueprint of the existing schema — a machine-written, human-reviewed discovery artifact
  alongside the proposal and discovered layer, carrying provenance ([FW-DISC6](formwork.md#fw-disc6)).

Invariant:

- `FW-INV12` **Recording floor.** Even an unconfined recording enforces the credential floor: no
  permissive recording can observe, propose, or synthesize access to a
  [FW-CRED](formwork.md#fw-cred1)-matched location. The recording-mode strengthening of
  [FW-INV8](formwork.md#fw-inv8), tested to falsify.

Tests (draft, above the landed spec's `FW-E2E-069`). These were originally drafted as
`FW-E2E-065`..067, but PR #19 landed the MCP-pattern-shading tests at exactly those numbers
(`FW-E2E-065`..067, [FW-GW9](formwork.md#fw-gw9)); per the constitution (Requirements & identifiers:
"never renumbered, never reused") the collision is resolved by renumbering the *unlanded* draft up
past the highest landed number, never the landed spec:

- `FW-E2E-070` **Recording round-trip (macOS).** Spawn a workload under the floor-only permissive
  policy; the opens it makes are observed and synthesized into a Blueprint; re-enforcing that
  Blueprint runs the same workload clean, while a path it never touched is denied. Paired allow/deny
  against real Seatbelt ([FW-INV5](formwork.md#fw-inv5), like [FW-E2E-024](formwork.md#fw-e2e-024)).
- `FW-E2E-071` **Recording floor (`FW-INV12`).** A workload that reads a credential during a
  permissive recording is denied at the kernel, and that credential is absent from both the proposal
  and any synthesized Blueprint. (The recording-mode analogue of
  [FW-E2E-051](formwork.md#fw-e2e-051)'s floor property.)
- `FW-E2E-072` **No-feed fail-loud.** On a host reporting `trace-feed: none` (Linux today),
  `learn --permissive` fails loud and writes nothing ([FW-INV6](formwork.md#fw-inv6)); no empty or
  partial Blueprint is emitted.

## 5. Proposed amendments to the landed docs (apply on landing)

None of these are applied yet. On adoption they fold into `formwork.md`/`constitution.md` and the
draft IDs above gain anchors (either by adding `fep-4.md` to the requirements canary's `DEFINING`
list, as `fep-1.md` is, or by folding the definitions into `formwork.md`).

**(a) Scope [FW-DISC1](formwork.md#fw-disc1) so "enforced run" admits the recording alternative.**
Current text pins learning to an enforced run. Proposed replacement:

> **FW-DISC1** Observation source. Discovery observes what a workload touches by one of two sources:
> an **enforced** run whose denials are recorded (the default; the policy is enforced unchanged,
> [FW-INV10](formwork.md#fw-inv10)), or an explicitly **permissive** recording whose opens are
> recorded (`FW-DISC7`; unconfined except the credential floor, `FW-DISC8`). Both are visibly
> distinct from a plain run; neither widens a live enforced session.

**(b) Scope [FW-INV10](formwork.md#fw-inv10)** — no wording change to the guarantee, but a clarifying
clause: a permissive recording is not a "live enforced session" being weakened; it is an operator's
explicit, loud choice to run without a wall in order to *produce* one. The §5.10 guarantee
("never … grant-whatever-is-attempted") is preserved because recorded opens remain non-authoritative
(`FW-DISC9`) and the floor still holds (`FW-INV12`).

**(c) Constitution — Vocabulary.** Add: **record** = a permissive, unconfined-except-floor discovery
run whose opens are observed to synthesize a Blueprint (`FW-DISC7`); distinct from **learn** (an
*enforced* run plus denial observation). Both are surfaced under one command (`learn --permissive`).

**(d) Constitution — Concepts / Data model.** Note that `HostProfile` gains a `trace-feed` field
(what the host can *observe*, beside what it can *enforce*), and that a frozen `*.blueprint.toml` is a
machine-written discovery artifact of the existing Blueprint schema. Both are additive/expand-only
and pre-release, so no version bump (precedent: FEP-3 "Adopted").

**(e) Threat model — `formwork.md` §1/§3.** Add the trusted-recording threat model (§1.1 above) as an
explicitly narrower sibling of the main threat model, with its two structural mitigations.

**(f) Traceability — `formwork.md` §10.** New rows on landing:

| Requirement | Primary test | Also |
|---|---|---|
| `FW-DISC7` Permissive recording | `FW-E2E-070` | `FW-E2E-072` |
| `FW-DISC8` Floor-enforced recording | `FW-E2E-071` | `FW-INV12` |
| `FW-DISC9` Open-feed honesty | `FW-E2E-072` | `FW-E2E-070` |
| `FW-DISC10` Blueprint synthesis/freeze | `FW-E2E-070` | — |
| `FW-INV12` Recording floor | `FW-E2E-071` | `FW-ADV`-class, TBD |

## 6. Decisions (recorded per constitution Precedence & Conflicts)

- **The one genuine deviation — a run without a full wall — is a tracked exception, not a silent
  workaround.** [FW-DISC1](formwork.md#fw-disc1) as landed says learning is an *enforced* run.
  Permissive recording conflicts with that clause. Resolution per Precedence & Conflicts: STOP, state
  it, amend (§5a/§5b), and record the exception with the mitigations that bound it (floor enforced,
  output non-authoritative) and an expiry (adoption of FEP-4 folds the amendment in and closes the
  exception). Until then, no *deviating* code lands — nothing that runs a workload without the full
  wall. The pure, non-deviating core has landed ahead of the mechanism per the work plan
  (`docs/fep4-plan.md` §5.1): the `AccessRecord` rename (with its `DenialRecord` alias),
  `synthesize_blueprint`, and the `floor_only_permissive` Blueprint constructor — all exercised only
  through the pure compiler and tests, citing only landed IDs. That core creates no unconfined run,
  so it opens no seam and triggers no exception; the constitution's "there are none at present" holds
  until the mechanism lands. The `learn --permissive` CLI, the feed tap, and the floor-only *spawn* —
  the parts that actually run without a wall — remain gated on the spike (§7) and land together with
  the §5 amendment and this tracked exception.
- **No new top-level command.** Recording is `learn --permissive`, honoring Growth and the CLI-surface
  reduction already in flight (PR #18). A standalone `record`/`trace`/`profile` verb was rejected as a
  Growth violation (one flag expresses it; a whole verb does not earn its surface).
- **No new requirement family.** Recording continues **DISC**; a new `FW-REC` family would have been a
  Concepts-grade amendment (Requirements & identifiers) for no benefit.
- **No new concept, no new Posture, no new crate.** Recording is `spawn_confined` with a floor-only
  permissive policy (§2.2); the feed tap is a CLI responsibility by existing precedent (§2.6).
- **macOS-first is required, not merely pragmatic.** Growth forbids shipping an unverifiable Linux
  observer; Linux is an honest `trace-feed: none` gap until `fanotify` can be verified end-to-end.
- **Number renumbering.** Draft test IDs sit above the highest landed number. They were first drafted
  as `FW-E2E-065`..067 (above PR #18's `FW-E2E-062`..064), but PR #19 then landed the MCP-pattern
  tests at `FW-E2E-065`..067 and the gateway compile tests through `FW-E2E-069`. The collision is
  resolved by renumbering the *unlanded* draft up to `FW-E2E-070`..072, never the landed spec
  (Requirements & identifiers: "never renumbered, never reused"; precedent: FEP-2,
  `docs/fep2-plan.md` §0). The draft requirement IDs (`FW-DISC7`..10 above the landed `FW-DISC6`,
  `FW-INV12` above the landed `FW-INV11`) do not collide.

## 7. Open questions (a spike decides, before any mechanism code)

- **macOS observation feed — spike A vs B vs fs_usage.** The feed is separable from enforcement:
  the floor-only Seatbelt policy (§2.2) enforces regardless, and the feed only *observes* on top, so
  these compose with the floor rather than replace it. Candidates, on a completeness-vs-cost axis:
  - **(A) SBPL `(trace "file")` profile-generation mode** — a profile *generator*, subtree-scoped for
    free (Seatbelt inheritance, [FW-XR4](formwork.md#fw-xr4)), no root; but private/undocumented and
    version-drifting.
  - **(B) allow-default with a `(with report)` modifier on file rules** — reuses the existing
    structured ndjson `log show` tap (`learn.rs`) to parse *allow* records the way it parses *deny*
    today; subtree-scoped, no root, cheapest if the report modifier logs reliably (incl. on metadata
    ops). Depends on that modifier firing.
  - **fs_usage** (front-runner) — kdebug/ktrace-based, so it captures the **broadest** set: every fs
    syscall including metadata ops (`stat`/`access`/`readlink`/`getattrlist`), which matters here
    because formwork itself enforces metadata denial ([FW-CAP7](formwork.md#fw-cap7)) — a
    data-open-only trace would synthesize a Blueprint too tight for the enforced run.
    Mechanism-independent (no reliance on the undocumented SBPL facilities). The parse-fragility and
    under-load event-loss knocks are **not** weighed against it: this is a bootstrap run made a
    handful of times, and `FW-DISC9` already forbids claiming the trace is complete. The real cost is
    `sudo` (Seatbelt needs none — a footprint escalation, though amortized: record once, enforce many
    times without root) and **attribution** (§7.1). `FW-INV12` still holds: a floor-denied credential
    open that fs_usage records as an *attempt* is withheld by the reverse-compile floor
    ([FW-DISC3](formwork.md#fw-disc3)) regardless of source.

  Endpoint Security (`ES_EVENT_TYPE_NOTIFY_OPEN`) is the supported, structured, complete path but
  carries an Apple entitlement + root + code-signing cost that breaks curl-and-run distribution; it
  stays a reported `Unavailable`/future, not v1. The spike (recorded in `docs/spikes.md`, the same way
  the denial-feed choice was made in `docs/fep2-plan.md` §4) picks the feed before §2.2's mechanism is
  built — fs_usage for completeness, (B) for cost/reuse; the decision is whether metadata-op coverage
  is worth the root requirement.

### 7.1 Attribution — the load-bearing part of a system-wide feed

fs_usage (and any system-wide feed) captures everything, so recording is a **capture → resolve →
filter** pipeline: capture system-wide, reconstruct the workload's process subtree, keep only its
events. Two properties make this correct — and note that attribution matters *more* here than for
denial-learn, because record's whole purpose is a **tight** Blueprint: over-capture that leaks
unrelated processes' paths doesn't just add review noise, it loosens the allowlist against the tool's
own goal, so the filter is load-bearing, not hygiene.

1. **Build the subtree from captured lifecycle events, never a live `ps`.** A post-hoc process-table
   query misses every child that already spawned and exited — for a build/test workload, exactly the
   millisecond helpers (`cc1`, `ld`, `sh -c …`) you most want. That is the same short-lived-loss
   failure class PR #18 fixed for denials; re-introducing it in attribution would silently drop the
   fastest processes. So Phase 1 must capture process **fork/exec/exit with PPID** alongside the fs
   events (fs_usage gives PID+comm per line but not reliable parent linkage), and Phase 2
   reconstructs lineage from those captured events — which include the dead ones. PID reuse is
   negligible over a few-second window.

2. **Or sidestep lineage entirely with the audit session ID (ASID).** macOS `auditpipe(4)` can
   preselect events by audit session — a kernel-maintained id inherited by the whole descendant tree
   by construction. Since formwork is the launcher, it can start the workload in a fresh audit
   session and attribute by ASID with zero lineage reconstruction and zero race. It needs root
   (already paid) and the audit subsystem enabled, and OpenBSM is a rustier subsystem than fs_usage.

The spike's real question is therefore **fs_usage + fork-event lineage vs ASID-preselected
auditpipe**: the former is lighter and reuses a familiar tool; the latter is the "correct"
race-free attribution at the cost of a heavier subsystem. Path resolution (fs_usage occasionally
reports CWD-relative paths; the resolved absolute form is what `PathPattern` needs) is a Phase-3
detail to confirm in the same spike, not a deciding factor.
- **Flag spelling.** `--permissive` (conventional; AppArmor "complain" lineage) vs `--unconfined`
  (the more brazenly honest spelling this repo's fail-loud doctrine tends to favor). Pinned in the
  Vocabulary amendment (§5c) once chosen.
- **Freeze in v1 or later.** Whether `--out` blueprint freeze (`FW-DISC10`) ships in v1 or the first
  cut stops at proposal/accept into the discovered layer (which is already enforceable alongside the
  base blueprint).
