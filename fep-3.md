# FEP-3 (partially landed): filesystem capability rules

**Formwork Enhancement Proposal 3.** Companion to `formwork.md` (design + end-to-end spec) and
`constitution.md` (doctrine).

The filesystem **rule grammar** has landed and been folded into `formwork.md`: a flat
`"<verb>:<path>"` vocabulary and a `mode` posture, desugared into the existing `Blueprint` model at
the CLI edge, with access evaluated **hide → allow → deny-terminal**. What folded where:

- flat verb rules + the `mode` posture — `formwork.md` §4, §5.8
  ([FW-BP6](formwork.md#fw-bp6)/[FW-BP7](formwork.md#fw-bp7)).
- three-layer deny-terminal evaluation and the **create/write split** (the `write` verb /
  `writes-no-create` field) — §4, §5.2
  ([FW-CAP8](formwork.md#fw-cap8)/[FW-CAP9](formwork.md#fw-cap9)), with the structural-floor
  invariant [FW-INV11](formwork.md#fw-inv11) (§6).
- **exec as a verb**, execute-without-read on both backends ([FW-XR6](formwork.md#fw-xr6) parity) —
  §5.3 ([FW-ISO9](formwork.md#fw-iso9)).
- tests [FW-E2E-056](formwork.md#fw-e2e-056)..058 and [FW-E2E-061](formwork.md#fw-e2e-061) — §7.7,
  with traceability in §10.

What remains here are the **two deferred subsystems** — they need new *runtime* machinery
(a provenance path and a report-labelling pass), so they are genuinely follow-up.

## Deferred requirements

| Req | Requirement |
|---|---|
| <a id="fw-fid6"></a>**FW-FID6** Rule provenance & explain | Every effective rule carries provenance — `built-in \| profile \| file \| cli \| discovered`. `formwork explain <path>` reports the winning rule (evaluated via the deny-terminal model, [FW-CAP8](formwork.md#fw-cap8)), its verb, and its provenance, without enforcing. Extends [FW-CAP5](formwork.md#fw-cap5) inspectability; reuses the discovery provenance machinery ([FW-DISC6](formwork.md#fw-disc6)). |
| <a id="fw-fid7"></a>**FW-FID7** Per-deny mechanism labels | The FidelityReport labels each deny by mechanism (`enforced-via-LSM` / `enforced-via-enumeration` / `enforced-via-overmount` / `partial`) and discloses the Linux snapshot asymmetry (allows may go stale post-spawn; denies cannot) and hole-ancestor over-breadth. Extends [FW-XR1](formwork.md#fw-xr1)/[FW-XR6](formwork.md#fw-xr6). |

Reserved test IDs (minted with the work): `FW-E2E-059` explain provenance · `FW-E2E-060` any-depth
rule platform-conditional · `FW-ADV-016` allow-cannot-override-deny · `FW-ADV-017` post-spawn create
under a split dir denied.

## Decisions (recorded per constitution Precedence & Conflicts)

- **`deny` is a verb, not the rejected `subtract` synonym.** FEP-2 declined a free-floating `deny`
  alias for `subtract` (`docs/fep2-plan.md` §8). In the verb model `deny` is a *first-class verb*
  with a distinct meaning inherited from the unveil lineage: an additive override to **zero
  permissions** — a tombstone — evaluated in the terminal deny layer ([FW-CAP8](formwork.md#fw-cap8)).
  It desugars to `subtract` because that is the mechanism, exactly as `readwrite` desugars to
  `writes`; the verb is not a second name for the internal field. This visibly amends FEP-2's ruling
  for the verb only; `subtract` remains the field/vocabulary word.
- **Exec parity reached ([FW-XR6](formwork.md#fw-xr6)).** The Linux exec allow-list grants `Execute`
  only, not `Execute | ReadFile`, matching Seatbelt's read-free `process-exec*`. The same `exec:`
  grant behaves identically on both backends; a binary or script the loader must re-open to run needs
  a separate read grant on either platform (documented, not a divergence).
- **`mode` + `[fs] read-mode` in one layer is a loud conflict, by design.** They are two spellings of
  one posture; picking a winner between spellings in a single layer would be arbitrary, so it fails
  loud. Across layers (`extends`, CLI overrides) they compose by ordinary last-wins
  ([FW-BP2](formwork.md#fw-bp2)) — the conflict is same-layer only, so it does not break `extends`
  ([FW-E2E-057](formwork.md#fw-e2e-057)).
- **`Mode` is a distinct type from `ReadMode`.** It is the typed form of the `mode` key
  (parse-don't-validate at the serde edge), one meaning per name; it maps to `ReadMode` and carries
  no independent semantics. Kept as a two-line enum rather than an untyped string.

## Open at adoption

- **Constitution Concepts / Data-model.** The create/write split ([FW-CAP9](formwork.md#fw-cap9))
  added a `Blueprint` field (`writes-no-create`) and a serialized `LinuxPolicy` field. Folding into
  `formwork.md` (§4 grammar, §5.2, Concepts-grade content) is done here; the matching
  `constitution.md` Concepts-list amendment — the closed capability vocabulary now admits the write
  grade — remains an open, human-reviewed decision. The change is additive/expand-only (every
  pre-FEP-3 blueprint compiles unchanged) and pre-release (canary consumers), so no version bump.
