# FEP-3 (landed): filesystem capability rules

**Formwork Enhancement Proposal 3 — landed in full.** Companion to `formwork.md`
(design + end-to-end spec) and `constitution.md` (doctrine).

Everything this FEP proposed has been implemented and **folded into `formwork.md`**:

- **flat verb rules + the `mode` posture** — a `"<verb>:<path>"` vocabulary and an
  `unveil`/`subtractive` posture, desugared into the existing `Blueprint` model at the
  CLI edge: §4, §5.8 ([FW-BP6](formwork.md#fw-bp6)/[FW-BP7](formwork.md#fw-bp7)).
- **three-layer deny-terminal evaluation and the create/write split** (the `modify` verb /
  `writes-no-create` field): §4, §5.2 ([FW-CAP8](formwork.md#fw-cap8)/[FW-CAP9](formwork.md#fw-cap9)),
  with the structural-floor invariant [FW-INV11](formwork.md#fw-inv11) (§6).
- **exec as a verb**, execute-without-read on both backends ([FW-XR6](formwork.md#fw-xr6)
  parity): §5.3 ([FW-ISO9](formwork.md#fw-iso9)).
- **rule provenance + `formwork explain`** — each effective rule carries its layer
  (`built-in | profile | file | cli | discovered`) and a dry-run `explain <path>` names the
  deciding rule and its origin: §5.6 ([FW-FID6](formwork.md#fw-fid6)).
- tests [FW-E2E-056](formwork.md#fw-e2e-056)..058, [FW-E2E-059](formwork.md#fw-e2e-059),
  and [FW-E2E-061](formwork.md#fw-e2e-061) — §7.7, with traceability in §10.

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
- **The weaker write grade is spelled `modify`, not a bare `write`.** The verb was `write`, which
  collided both ways: against the full-write `writes` field and the `--write` flag (create
  included), and against readers' expectation that a bare `write` is the general write. Renamed to
  `modify` so every "write"-named surface (`writes`, `--write`, `readwrite`) grants create and the
  no-create grade has its own word (constitution Vocabulary, one word per concept). Pre-release, so a
  direct rename, no alias: an old `write:` rule now fails loud with the known-verb list.
- **Per-deny mechanism labels dropped.** A proposed FidelityReport pass would have labelled each
  deny by mechanism (LSM / enumeration / overmount / partial) and disclosed the Linux snapshot
  asymmetry and hole-ancestor over-breadth. Dropped, not deferred: on macOS every deny is uniformly
  LSM-enforced so the label carries no information, and the Linux-only disclosures reference
  machinery not built. If the need returns it is a fresh proposal, not a reserved slot here.

## Adopted

- **Constitution Concepts / Vocabulary.** The create/write split ([FW-CAP9](formwork.md#fw-cap9))
  added a `Blueprint` field (`writes-no-create`) and a serialized `LinuxPolicy` field. The matching
  `constitution.md` amendment landed with this work: the Concepts enumeration now admits the
  write-without-create grade, and the Vocabulary pins one word per grade (**write** = full,
  **modify** = no-create). The change is additive/expand-only (every pre-FEP-3 blueprint compiles
  unchanged) and pre-release (canary consumers), so no version bump.
