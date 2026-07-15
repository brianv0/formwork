# FEP-3 (draft, landing): filesystem capability rules

**Formwork Enhancement Proposal 3.** Companion to `formwork.md` (design + end-to-end spec) and
`constitution.md` (doctrine).

This FEP adds a flat **rule grammar** for filesystem capabilities — one `"<verb>:<path>"` string per
rule and a `mode` posture — desugared into the existing `Blueprint` model at the CLI edge (verbs are
syntax over that one model, not a second one, [FW-BP1](formwork.md#fw-bp1)), plus the **create/write
split** it makes expressible, per-rule **provenance** with `formwork explain`, and per-deny **mechanism labels**
in the FidelityReport. Access is evaluated **hide → allow → deny-terminal** — deny wins, no allow
reopens it — which is Formwork's existing compile semantics ([FW-BP4](formwork.md#fw-bp4),
[FW-INV8](formwork.md#fw-inv8)); this FEP names that model as a first-class property and extends the
vocabulary around it.

New identifiers continue the `formwork.md` sequences and are minted here (this is their defining
document until the FEP lands and folds into `formwork.md`, mirroring `fep-1.md` for FW-EGR/FW-FID5).

## Grammar (verb rules)

One rule is one `"<verb>:<path>"` string, the same on a `--rule` flag, a `--set` fragment, and a
file `rules = [...]` line. The path takes the same sigils as any grant (`~`, `$CWD`;
[FW-BP5](formwork.md#fw-bp5)). Each verb desugars, at the CLI load edge, into the existing
`Blueprint` fields ([FW-BP1](formwork.md#fw-bp1)) — the pure merge and compiler see only the
desugared form, never verbs:

| Verb | Grants (r=read w=modify c=create x=exec) | Desugars to |
|---|---|---|
| `read` / `readonly` | r | `fs.reads` |
| `write` | r w | `fs.writes-no-create` ([FW-CAP9](#fw-cap9)) |
| `readwrite` | r w c | `fs.writes` |
| `allow` | r w c x | `fs.writes` + exec allow-list |
| `readexec` | r x | `fs.reads` + exec allow-list |
| `exec` | x | exec allow-list only |
| `deny` | — (tombstone) | `fs.subtract` |

`mode` is a friendlier alias of `[fs] read-mode`: `unveil` → `closed`, `subtractive` →
`ambient-minus-subtract` ([FW-BP7](#fw-bp7)). Every verb also has a nested `[fs]` equivalent (e.g.
`write` ↔ `writes-no-create`), so a file and `--rule` say the same thing.

## Requirements

| Req | Requirement |
|---|---|
| <a id="fw-cap8"></a>**FW-CAP8** Three-layer evaluation, deny-terminal | Path access resolves in a fixed order: (1) **hide** — unlisted paths are inaccessible (EACCES-shaped, not ENOENT; the report says so, [FW-CAP4](formwork.md#fw-cap4)); (2) **allow** — grants punch holes, more specific wins within the layer; (3) **deny** — applied last and terminal. No allow at any layer, and no rule order, overrides a deny. The only removal of a deny is the typed credential exclude ([FW-CRED5](formwork.md#fw-cred5)), which deletes the deny entry rather than overriding it. The structural form of [FW-BP4](formwork.md#fw-bp4)/[FW-INV8](formwork.md#fw-inv8). |
| <a id="fw-cap9"></a>**FW-CAP9** Verb grammar & create/write split | The fs grant vocabulary is a closed verb set — `read`/`readonly`, `readwrite`, `write`, `allow`, `readexec`, `exec`, `deny`. `write` grants read + modify-existing but **not create**; `allow`/`readwrite` additionally grant create. Enforced on both backends: Landlock drops the `Make*` rights, Seatbelt allows every `file-write-*` op except `file-write-create`. |
| <a id="fw-iso9"></a>**FW-ISO9** Exec as a verb | Execution is expressed as the `exec`/`readexec` verb rather than a separate posture; off by default (no verb grants execute ⇒ execute is ungoverned/transparent). Reframes [FW-ISO4](formwork.md#fw-iso4); the internal `ExecPosture` is unchanged (verbs desugar onto it). No traversal token — a covering-directory grant applies. |
| <a id="fw-bp6"></a>**FW-BP6** Flat verb rules | One string is one rule (`"<verb>:<path>"`), identical between the CLI flag (`--rule`), a `--set` fragment, and a file `rules` line. Grants and denies are sets merged by union; the result is order-independent (profile stacking is commutative). Denies narrow from any layer; allows widen and are the only trusted layer (maps onto [FW-CAP2](formwork.md#fw-cap2)). Every verb also has a nested `[fs]` equivalent ([FW-BP1](formwork.md#fw-bp1) parity). |
| <a id="fw-bp7"></a>**FW-BP7** Mode posture | `unveil` (empty universe) and `subtractive` (ambient minus catalog) are a last-set-wins posture aliasing `[fs] read-mode`, not a union rule; setting both in one layer is a loud error. The credential floor applies in both modes. |
| <a id="fw-fid6"></a>**FW-FID6** Rule provenance & explain | Every effective rule carries provenance — `built-in \| profile \| file \| cli \| discovered`. `formwork explain <path>` reports the winning rule (evaluated via the deny-terminal model), its verb, and its provenance, without enforcing. Extends [FW-CAP5](formwork.md#fw-cap5) inspectability; reuses the discovery provenance machinery ([FW-DISC6](formwork.md#fw-disc6)). |
| <a id="fw-fid7"></a>**FW-FID7** Per-deny mechanism labels | The FidelityReport labels each deny by mechanism (`enforced-via-LSM` / `enforced-via-enumeration` / `enforced-via-overmount` / `partial`) and discloses the Linux snapshot asymmetry (allows may go stale post-spawn; denies cannot) and hole-ancestor over-breadth. Extends [FW-XR1](formwork.md#fw-xr1)/[FW-XR6](formwork.md#fw-xr6). |
| <a id="fw-inv11"></a>**FW-INV11** Structural floor | Because the credential catalog compiles into the deny layer and deny is terminal ([FW-CAP8](#fw-cap8)), no allow, no rule order, no profile, and no discovery path can produce access to a floored location; the sole removal is [FW-CRED5](formwork.md#fw-cred5). The structural form of [FW-INV8](formwork.md#fw-inv8). |

## Tests

Landed (black-box `formwork` CLI, compile-level so they run on any host):

| Test | Scenario |
|---|---|
| <a id="fw-e2e-056"></a>**FW-E2E-056** create/write split | Compile-level: the `write` verb renders every `file-write-*` op except `file-write-create`. Enforcement (Seatbelt, paired allow/deny): under a `write` grant an existing file is modifiable but a new file/dir cannot be created ([FW-CAP9](#fw-cap9)). |
| <a id="fw-e2e-057"></a>**FW-E2E-057** mode posture | `mode` compiles identically to the equivalent `[fs] read-mode`, for both values ([FW-BP7](#fw-bp7)). |
| <a id="fw-e2e-058"></a>**FW-E2E-058** order independence | Rule order does not change the compiled policy; deny beats allow regardless ([FW-BP6](#fw-bp6)/[FW-CAP8](#fw-cap8)). |
| <a id="fw-e2e-061"></a>**FW-E2E-061** rule/table parity | Flat verb rules and the nested `[fs]` table compile byte-identically ([FW-BP1](formwork.md#fw-bp1)). |

Reserved (minted with the tests as they land): `FW-E2E-059` explain provenance · `FW-E2E-060`
any-depth rule platform-conditional · `FW-ADV-016` allow-cannot-override-deny · `FW-ADV-017`
post-spawn create under a split dir denied.

## Traceability (req → primary test)

[FW-CAP8](#fw-cap8) → [FW-E2E-058](#fw-e2e-058) · [FW-CAP9](#fw-cap9) → [FW-E2E-056](#fw-e2e-056) ·
[FW-BP6](#fw-bp6) → [FW-E2E-058](#fw-e2e-058), [FW-E2E-061](#fw-e2e-061) ·
[FW-BP7](#fw-bp7) → [FW-E2E-057](#fw-e2e-057) · [FW-ISO9](#fw-iso9) → covered by the compiler exec
tests + FW-XR6 parity below. [FW-FID6](#fw-fid6)/[FW-FID7](#fw-fid7) land with their tests.

## Decisions (recorded per constitution Precedence & Conflicts)

- **`deny` is a verb, not the rejected `subtract` synonym.** FEP-2 declined a free-floating `deny`
  alias for `subtract` (`docs/fep2-plan.md` §8). In the verb model `deny` is a *first-class verb*
  with a distinct meaning inherited from the unveil lineage: an additive override to **zero
  permissions** — a tombstone — evaluated in the terminal deny layer ([FW-CAP8](#fw-cap8)). It
  desugars to `subtract` because that is the mechanism, exactly as `readwrite` desugars to `writes`;
  the verb is not a second name for the internal field. This visibly amends FEP-2's ruling for the
  verb only; `subtract` remains the field/vocabulary word.
- **`writes-no-create` is a new capability axis → a Concepts/Data-model decision at adoption.** The
  create/write split ([FW-CAP9](#fw-cap9)) adds a `Blueprint` field and a serialized `LinuxPolicy`
  field, which the constitution treats as Concepts (`FW-CAP1` closed vocabulary) and a Data-model
  change. It is additive/expand-only (every pre-FEP-3 blueprint compiles unchanged) and pre-release
  (canary consumers), so no version bump — but folding into `formwork.md` §4 must add it to the
  grammar and the Concepts list, not just cite an ID. (If the axis is judged not worth it, it is one
  revert; the other verbs desugar onto existing fields with no amendment.)
- **Exec parity reached ([FW-XR6](formwork.md#fw-xr6)).** The Linux exec allow-list now grants
  `Execute` only, not `Execute | ReadFile`, matching Seatbelt's read-free `process-exec*`. The same
  `exec:` grant now behaves identically on both backends; a binary or script the loader must re-open
  to run needs a separate read grant on either platform (documented, not a divergence).
- **`mode` + `[fs] read-mode` in one layer is a loud conflict, by design.** They are two spellings
  of one posture; picking a winner between spellings in a single layer would be arbitrary, so it
  fails loud. Across layers (`extends`, CLI overrides) they compose by ordinary last-wins
  ([FW-BP2](formwork.md#fw-bp2)) — the conflict is same-layer only, so it does not break `extends`
  ([FW-E2E-057](#fw-e2e-057)).
- **`Mode` is a distinct type from `ReadMode`.** It is the typed form of the `mode` key
  (parse-don't-validate at the serde edge), one meaning per name; it maps to `ReadMode` and carries
  no independent semantics. Kept as a two-line enum rather than an untyped string.

## Status

Landing incrementally on the branch. Implemented: flat verb rules + the `mode` posture
([FW-BP6](#fw-bp6)/[FW-BP7](#fw-bp7)), the create/write split ([FW-CAP9](#fw-cap9)) across the pure
types, the compiler, and both backends with a Seatbelt paired allow/deny test, and exec parity
([FW-XR6](formwork.md#fw-xr6)). Remaining: provenance + `explain` ([FW-FID6](#fw-fid6)) and per-deny
mechanism labels ([FW-FID7](#fw-fid7)). On adoption this folds into `formwork.md` (§2, §4, §5, §10)
with the Concepts/Data-model decision above, and the numbering is re-confirmed against any other
in-flight FEP (renumbering precedent: `docs/fep2-plan.md` §0).
