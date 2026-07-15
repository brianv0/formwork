# Implementation plan — Proposal A: verb-rule authoring surface over the existing core

> **Assumptions (unresolved references in the request).** No `design_doc_template.md` exists in the
> repo, so this mirrors the section set named in the request (Current context / Requirements / Design
> decisions / Implementation plan / Testing / Observability / Rollout / Security). No target path was
> given, so it lives in `research/` beside the prior docs. Scope = the full Proposal A. This is a
> **plan only** — no code is changed here. All new `FW-*` IDs are **proposed** (inline code, un-minted);
> a real FEP-3 would mint/anchor them. Source of truth for the design: `research/eval-model-proposals.md`
> §4; grounding: `research/codebase-research.md`.

## Current context

- The fs capability today is `FsBlueprint { read_mode, reads, writes, subtract, write_subtract }`
  plus separate `ExecPosture` and `NetPosture`/`EnvPosture` (`crates/formwork-blueprint/src/lib.rs:57-102`).
- **Deny is already terminal** and the credential floor already compiles into the deny set: layer
  merge unions grants/denies without letting an allow reopen a deny (`crates/formwork-blueprint/src/layer.rs:97-128`);
  the compiler folds `catalog.denied_paths(...)` into `subtract` (`crates/formwork-compile/src/lib.rs:72,425`;
  `crates/formwork-blueprint/src/catalog.rs:145-156`). So `FW-BP4`/`FW-INV8` are existing behavior.
- **The two modes already exist** as `ReadMode::Closed` (strict-unveil) vs `AmbientMinusSubtract`
  (subtractive), last-wins under merge (`crates/formwork-blueprint/src/lib.rs:78-84`,
  `crates/formwork-blueprint/src/narrow.rs:71-86`).
- The CLI already has the sugar → `BlueprintLayer` → `merge` path: `BlueprintArgs`/`sugar_layer`
  (`crates/formwork-cli/src/main.rs:124-194`) and `blueprint_load::load_stack` (`crates/formwork-cli/src/blueprint_load.rs:28-79`).
- Provenance exists **only** for the discovered layer today: `ProvenanceEntry` /
  `DiscoveryLayer.provenance` (`crates/formwork-blueprint/src/layer.rs:71-92`).
- Confiner mechanisms are implemented/verified: Landlock hole-bounded expansion + exec allowlist
  (`crates/formwork-confine/src/linux/landlock.rs:111-144,230-233`), SBPL last-match render
  (`crates/formwork-compile/src/sbpl.rs:104-231`).

## Requirements

- `FW-CAP8` three-layer evaluation, deny-terminal (restates `FW-BP4`/`FW-INV8` as the model property).
- `FW-CAP9` verb grammar with create/write split (`write`=rw, `allow`/`readwrite`=rwc), both platforms.
- `FW-ISO9` exec as a verb (`exec`/`readexec`); off by default (reframes `FW-ISO4`).
- `FW-BP6` flat rule surface: `<verb>:<path>`, identical CLI flag and file line; sets merge by union;
  order-independent (denies narrow, allows widen — maps onto `FW-CAP2`).
- `FW-BP7` mode posture: `strict-unveil` vs `subtractive`, last-wins/tighten-only, floor applies in both.
- `FW-FID6` per-rule provenance + `formwork explain <path>` (inspection; extends `FW-CAP5`; reuses `FW-DISC6`).
- `FW-FID7` per-deny mechanism labels + snapshot-asymmetry / over-breadth disclosure (extends `FW-XR1`/`FW-XR6`).
- `FW-INV11` structural floor: floor-in-deny-layer makes bypass impossible; sole lift is `FW-CRED5`.
- Non-negotiable: back-compat (`FW-E2E-041`) and byte-deterministic compile (`FW-FID4`).

## Design decisions

- **Verbs are an authoring surface, not a new evaluation model.** Each `verb:path` desugars into the
  existing `FsBlueprint` fields at the CLI/file edge; the compiler and confiner run unchanged. Desugar map:
  `readonly`/`read`→`reads`; `readwrite`/`allow`→`writes`; `write`→`writes_no_create` (new field, below);
  `readexec`→`reads` + `exec` allowlist; `exec`→`exec` allowlist; `deny`→`subtract`.
- **`mode` maps to `read_mode`** (`strict-unveil`→`closed`, `subtractive`→`ambient-minus-subtract`);
  the nested `[fs]` surface stays valid (both coexist, unioned).
- **The create/write split needs a new domain field**, `FsBlueprint.writes_no_create` (plus a matching
  `LinuxPolicy`/`MacosPolicy` field, and a nested-`[fs]` key `writes-no-create` — see the FW-BP1 parity
  note below) — so Proposal A touches the pure domain type *minimally*; it is not purely a CLI change.
  Enforcement must be specified as a **full op/bit set**, not a two-op sketch (a `write` grant that can
  only write data + chmod would be unable to delete, rename, or set times — a transparency break, `FW-TRA2`):
  - **Landlock:** for `writes_no_create` paths, take today's `write_access` (`from_all(abi)` minus
    `Execute`/`IoctlDev`, `crates/formwork-confine/src/linux/landlock.rs:165,178`) and drop **only** the
    creation bits `MakeReg|MakeDir|MakeSym|MakeSock|MakeFifo|MakeBlock|MakeChar`; keep
    `WriteFile|Truncate|ReadFile|ReadDir` (writes imply reads).
  - **Seatbelt:** allow **all `file-write-*` operations except `file-write-create`** for those paths in
    `render_writes` (`crates/formwork-compile/src/sbpl.rs:174-209`) — i.e. spell out the umbrella
    (`file-write-data`,`-mode`,`-owner`,`-flags`,`-times`,`-unlink`,`-setugid`) minus `file-write-create`,
    rather than the `(allow file-write* …)` wildcard.
  - **Open semantic decision to settle in the FEP:** whether `write` includes **remove/rename**
    (`RemoveFile`/`RemoveDir` on Landlock, `file-write-unlink` on Seatbelt). Default proposed: **include
    them** (modify-existing spans delete/rename); `allow`/`readwrite` additionally grant create. Document
    the choice; a create/write split test (Testing) must assert it on both backends.
- **Exec verb semantics (corrected).** Pure `exec` (execute-without-read) **is** expressible on both
  backends — Seatbelt `render_exec` grants only `process-exec*` (`crates/formwork-compile/src/sbpl.rs:214-221`)
  and Landlock `AccessFs::Execute` is a distinct right. Today's Landlock allowlist ORs in `ReadFile`
  (`crates/formwork-confine/src/linux/landlock.rs:232`); a pure `exec` verb drops that `| ReadFile`,
  while `readexec` keeps a read grant. Caveat to document, not enforce: a dynamically-linked binary still
  needs read of itself + its libraries to actually launch (dyld/`ld.so`; `docs/spikes.md:40-50`).
- **Provenance via a side-table, without breaking `merge`.** Do **not** change the signature of
  `pub fn merge(layers: &[BlueprintLayer]) -> Blueprint` (`crates/formwork-blueprint/src/layer.rs:97`):
  it has ~15 test callers plus the `from_blueprint` / `FW-E2E-041` refactor guard
  (`crates/formwork-blueprint/src/layer.rs:133,355`) and the one production caller
  (`crates/formwork-cli/src/blueprint_load.rs:64`). Add a **parallel** `merge_with_provenance(layers)
  -> (Blueprint, ProvenanceMap)` (or thread an out-param) that returns per-resulting-pattern source
  (`built-in`/`profile`/`file`/`cli`/`discovered`), reusing `ProvenanceEntry`
  (`crates/formwork-blueprint/src/layer.rs:71-92`). `explain` calls the new function; the compile path
  keeps calling plain `merge`, so `Blueprint`, `FW-FID4` determinism, and every existing test are untouched.
- **Provenance must survive canonicalization.** `canonicalize_set` sorts, dedupes, and **drops any
  pattern covered by another** (`crates/formwork-blueprint/src/path.rs:317-333`), so a dropped rule's
  source is lost unless folded onto the surviving (covering) pattern. Define the fold: when pattern X is
  dropped because Y covers it, attach X's provenance to Y (a pattern may then carry multiple sources).
- **`formwork explain <path>`** is a new inspection subcommand (sibling to `compile --report-only`),
  justified under `FW-CAP5`; it enforces nothing. It must **evaluate** the path against the merged model —
  the winning rule is found via `covers`/`matches_path` with deny-terminal precedence
  (`crates/formwork-blueprint/src/path.rs:163-234`), not a raw provenance-table lookup — then report that
  rule's verb and folded provenance.
- **Any-depth `**/`** stays (a)+(c): rule-level any-depth is a build error on Linux
  (`crates/formwork-confine/src/linux/landlock.rs:73-90`, `FW-INV6`), macOS-only as regex; `.env`-shaped
  shapes handled centrally via the catalog/backstop (`FW-CRED6`).
- **FW-BP1 parity (both surfaces equivalent).** Every verb must be expressible in *both* the flat
  `rules`/`--rule` surface and the nested `[fs]` table, or `FW-BP1` breaks. The only verb without a
  pre-existing nested field is `write`, so the new `FsBlueprint.writes_no_create` field is exposed as the
  nested key `writes-no-create` (serde kebab-case, `deny_unknown_fields`), not reachable only via the
  `write:` verb. A parity test (Testing) asserts the two surfaces compile byte-identically.
- **No constitution amendment** — new surface under `FW-BP1`; schema growth is additive/expand-only;
  new vocabulary (`verb`, `strict-unveil`) lives in the FEP/README, not `constitution.md`.
- Proposed IDs above must be re-confirmed against any in-flight FEP at adoption (renumbering precedent:
  `docs/fep2-plan.md:§0`).
- Open item flagged for the feature author: the exact `rules=[...]`/`mode` YAML shape was inferred
  (source text cut off); confirm before FEP-3 (`research/eval-model-proposals.md:§1.3`).

## Implementation plan

Ordered so each step lands compiling, clippy-clean, and green before the next; each is additive.

1. **Verb parse + CLI surface** — add `parse_rule(&str) -> (Verb, PathPattern)` and a `Verb` enum;
   add `--rule` (repeatable) and `--mode` to `BlueprintArgs`, folding into `sugar_layer`
   (`crates/formwork-cli/src/main.rs:124-194`); parse top-level `rules`/`mode` file keys in
   `blueprint_load::load_stack` (`crates/formwork-cli/src/blueprint_load.rs:28-79`). Desugar per the map above.
2. **Modes** — map `mode` → `read_mode` in the same edge; verify strict-unveil/subtractive parity with the
   existing `[fs] read-mode` (no core change; `crates/formwork-blueprint/src/lib.rs:78-84`).
3. **Create/write split** — add `FsBlueprint.writes_no_create` + `FsLayer` optional mirror + merge/narrow
   handling (`crates/formwork-blueprint/src/{lib.rs:57-74,layer.rs:42-65,narrow.rs:64-95}`); add the policy
   field (`crates/formwork-compile/src/policy.rs:34-101`) and compile mapping; split the Landlock write mask
   (`crates/formwork-confine/src/linux/landlock.rs:178`) and SBPL write rules
   (`crates/formwork-compile/src/sbpl.rs:174-209`).
4. **Provenance + `explain`** — add a parallel `merge_with_provenance` alongside the unchanged `merge`
   (`crates/formwork-blueprint/src/layer.rs:97-128`), folding a dropped pattern's source onto its covering
   pattern through `canonicalize_set` (`crates/formwork-blueprint/src/path.rs:317-333`); add the `explain`
   subcommand + handler that evaluates the path (`covers`/`matches_path`, deny-terminal) and reports the
   winning verb + provenance (`crates/formwork-cli/src/main.rs:50-119`).
5. **Report labels** — add `FW-FID7` per-deny mechanism labels and the snapshot-asymmetry / over-breadth
   note to `FidelityReport` (`crates/formwork-compile/src/report.rs:12-43`) and the compile path.
6. **Docs + traceability** — FEP-3 draft minting the IDs, README/`formwork.md` surface notes, traceability rows.

## Testing

- New (proposed): `FW-E2E-056` verb round-trip + create/write split — paired allow/deny probes on **both**
  backends covering the full op set, not just create: under `write`, **create denied** but **modify /
  truncate / chmod allowed** and the settled remove/rename decision asserted; under `readwrite`, create
  allowed; `FW-E2E-057` mode switch byte-deterministic; `FW-E2E-058` order-independent profile stacking;
  `FW-E2E-059` `explain` reports the winning verb + folded provenance for a path a covering rule swallowed;
  `FW-E2E-060` any-depth rule rejected on Linux / accepted on macOS; `FW-E2E-061` **flat-vs-nested surface
  parity** — the same grants authored as `rules`/`--rule` and as an `[fs]` table (incl. `writes-no-create`)
  compile byte-identically (`FW-BP1`, analogous to `FW-E2E-043`); `FW-ADV-016` allow-cannot-override-deny;
  `FW-ADV-017` post-spawn create under a split dir denied (Linux).
- Regression: `FW-E2E-041` back-compat, `FW-E2E-043` CLI/file parity, and `FW-E2E-027`/`FW-FID4`
  determinism must stay green after every step.
- Harness: black-box `formwork` CLI via `py/` with FW-ID markers; kernel probes paired allow/deny (no mocks),
  per `constitution.md` Testing.

## Observability

- `formwork explain <path>` output (winning rule + verb + provenance) is new inspection surface.
- `FW-FID7` deny-mechanism labels appear in the compiled `FidelityReport`; existing credential-floor
  `tracing` itemization (`crates/formwork-cli/src/main.rs:476-502`) is unchanged.

## Rollout

- Additive, expand-only: no contract phase for Proposal A. The nested `[fs]` surface and the flat
  `rules`/`mode` surface coexist; pre-FEP blueprints compile identically (`FW-E2E-041`). Report/schema
  changes are pre-release (canary consumers), no version bump required.

## Security

- Deny-terminality and the credential floor are preserved structurally (`FW-INV8`/`FW-INV11`): the desugaring
  only ever appends to `subtract`/grants; no path lets an allow reopen a deny; the sole lift stays `FW-CRED5`.
- The create/write split *reduces* authority (removes `Make*`/`file-write-create` from a `write` grant) —
  net-tightening, never widening.
- Exec-read nuance documented (above): `readexec` vs `exec`; runnability needs read of the binary + libs.
- No new dependency (Growth); no `constitution.md` change; any-depth stays fail-loud on Linux (`FW-INV6`).
