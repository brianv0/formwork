# FEP-3 (draft, landing): the verb-based evaluation model

**Formwork Enhancement Proposal 3 — in progress on branch
`claude/codebase-research-docs-2s4fhv`.** Companion to `formwork.md` (design + end-to-end spec)
and `constitution.md` (doctrine). The design rationale and the two-proposal comparison live in
`research/eval-model-proposals.md`; the chosen implementation plan (Proposal A) is
`research/proposal-a-implementation-plan.md`.

This FEP adds a **verb-based authoring surface** for filesystem capabilities — a flat
`"<verb>:<path>"` rule vocabulary and a `mode` posture, both desugared into the existing
`Blueprint` model (verbs are a surface, not a second model, [FW-BP1](formwork.md#fw-bp1)) — plus the
**create/write split** it makes expressible, per-rule **provenance** with `formwork explain`, and
per-deny **mechanism labels** in the FidelityReport. The three-layer evaluation model
(hide → allow → deny-terminal) is Formwork's existing compile semantics
([FW-BP4](formwork.md#fw-bp4), [FW-INV8](formwork.md#fw-inv8)); this FEP names it as a first-class
property and extends the vocabulary around it.

New identifiers continue the `formwork.md` sequences and are minted here (this is their defining
document until the FEP lands and folds into `formwork.md`, mirroring `fep-1.md` for FW-EGR/FW-FID5).

## Requirements

| Req | Requirement |
|---|---|
| <a id="fw-cap8"></a>**FW-CAP8** Three-layer evaluation, deny-terminal | Path access resolves in a fixed order: (1) **hide** — unlisted paths are inaccessible (EACCES-shaped, not ENOENT; the report says so, [FW-CAP4](formwork.md#fw-cap4)); (2) **allow** — grants punch holes, more specific wins within the layer; (3) **deny** — applied last and terminal. No allow at any layer, and no rule order, overrides a deny. The only removal of a deny is the typed credential exclude ([FW-CRED5](formwork.md#fw-cred5)), which deletes the deny entry rather than overriding it. The structural form of [FW-BP4](formwork.md#fw-bp4)/[FW-INV8](formwork.md#fw-inv8). |
| <a id="fw-cap9"></a>**FW-CAP9** Verb grammar & create/write split | The fs grant vocabulary is a closed verb set — `read`/`readonly`, `readwrite`, `write`, `allow`, `readexec`, `exec`, `deny`. `write` grants read + modify-existing but **not create**; `allow`/`readwrite` additionally grant create. Enforced on both backends: Landlock drops the `Make*` rights, Seatbelt allows every `file-write-*` op except `file-write-create`. |
| <a id="fw-iso9"></a>**FW-ISO9** Exec as a verb | Execution is expressed as the `exec`/`readexec` verb rather than a separate posture surface; off by default (no verb grants execute ⇒ execute is ungoverned/transparent). Reframes [FW-ISO4](formwork.md#fw-iso4); the internal `ExecPosture` is unchanged (verbs desugar onto it). No traversal token — a covering-directory grant applies. |
| <a id="fw-bp6"></a>**FW-BP6** Flat rule surface | One string is one rule (`"<verb>:<path>"`), identical between the CLI flag (`--rule`), a `--set` fragment, and a file `rules` line. Grants and denies are sets merged by union; the result is order-independent (profile stacking is commutative). Denies narrow from any layer; allows widen and are the only trusted layer (maps onto [FW-CAP2](formwork.md#fw-cap2)). Every verb is expressible in both the flat surface and the nested `[fs]` table ([FW-BP1](formwork.md#fw-bp1) parity). |
| <a id="fw-bp7"></a>**FW-BP7** Mode posture | `strict-unveil` (empty universe) and `subtractive` (ambient minus catalog) are a last-set-wins posture aliasing `[fs] read-mode`, not a union rule; setting both in one layer is a loud error. The credential floor applies in both modes. |
| <a id="fw-fid6"></a>**FW-FID6** Rule provenance & explain | Every effective rule carries provenance — `built-in \| profile \| file \| cli \| discovered`. `formwork explain <path>` reports the winning rule (evaluated via the deny-terminal model), its verb, and its provenance, without enforcing. Extends [FW-CAP5](formwork.md#fw-cap5) inspectability; reuses the discovery provenance machinery ([FW-DISC6](formwork.md#fw-disc6)). |
| <a id="fw-fid7"></a>**FW-FID7** Per-deny mechanism labels | The FidelityReport labels each deny by mechanism (`enforced-via-LSM` / `enforced-via-enumeration` / `enforced-via-overmount` / `partial`) and discloses the Linux snapshot asymmetry (allows may go stale post-spawn; denies cannot) and hole-ancestor over-breadth. Extends [FW-XR1](formwork.md#fw-xr1)/[FW-XR6](formwork.md#fw-xr6). |
| <a id="fw-inv11"></a>**FW-INV11** Structural floor | Because the credential catalog compiles into the deny layer and deny is terminal ([FW-CAP8](#fw-cap8)), no allow, no rule order, no profile, and no discovery path can produce access to a floored location; the sole removal is [FW-CRED5](formwork.md#fw-cred5). The structural form of [FW-INV8](formwork.md#fw-inv8). |

## Tests

Landed (black-box `formwork` CLI, compile-level so they run on any host):

| Test | Scenario |
|---|---|
| <a id="fw-e2e-056"></a>**FW-E2E-056** create/write split | The `write` verb renders every `file-write-*` op except `file-write-create` on its path ([FW-CAP9](#fw-cap9)). |
| <a id="fw-e2e-057"></a>**FW-E2E-057** mode posture | `mode` compiles identically to the equivalent `[fs] read-mode`, for both values ([FW-BP7](#fw-bp7)). |
| <a id="fw-e2e-058"></a>**FW-E2E-058** order independence | Rule order does not change the compiled policy; deny beats allow regardless ([FW-BP6](#fw-bp6)/[FW-CAP8](#fw-cap8)). |
| <a id="fw-e2e-061"></a>**FW-E2E-061** surface parity | The flat rule surface and the nested `[fs]` table compile byte-identically ([FW-BP1](formwork.md#fw-bp1)). |

Reserved (minted with the tests as they land): `FW-E2E-059` explain provenance · `FW-E2E-060`
any-depth rule platform-conditional · `FW-ADV-016` allow-cannot-override-deny · `FW-ADV-017`
post-spawn create under a split dir denied.

## Status

Landing incrementally on the branch. Implemented so far: the flat verb-rule surface + `mode`
posture ([FW-BP6](#fw-bp6)/[FW-BP7](#fw-bp7), verbs desugared onto the existing model), and the
create/write split ([FW-CAP9](#fw-cap9)) across the pure types, the compiler, and both backends.
Remaining: provenance + `explain` ([FW-FID6](#fw-fid6)), per-deny mechanism labels
([FW-FID7](#fw-fid7)), and the black-box E2E tests. On adoption this folds into `formwork.md`
(§4, §5, §10) and the numbering is re-confirmed against any other in-flight FEP
(renumbering precedent: `docs/fep2-plan.md` §0).
