# Evaluation-model feature — two implementation proposals

*Drafted 2026-07-14, grounded in `research/codebase-research.md` and the live tree. This is a
**proposal document**, not a landed spec: every new requirement ID below is written in inline code
and is **proposed only** — none is minted or anchored here. On adoption they would be minted once,
with anchors, in the adopting FEP/`formwork.md` per the constitution's Requirements & identifiers.
Existing IDs (`FW-BP4`, `FW-INV8`, `FW-CRED5`, …) are cited in inline code and already resolve.*

The feature: a **verb-based, three-layer path evaluation model** (hide → allow → deny-terminal) with
a **flat rule syntax**, **two authoring YAML models** (strict-unveil and subtractive), **per-rule
provenance** feeding `formwork explain`, and the already-implemented Linux/macOS deny mechanisms. This
document gives two ways to land it: **Proposal A** (a new authoring *surface* that desugars onto
today's internal model — minimal core change, no constitution amendment) and **Proposal B** (a
first-class verb-set *core model* — cleaner internals, larger blast radius, requires a Concepts +
Data-model amendment).

---

## 0. What is already true today (so we build the minimum)

Two load-bearing pieces of the feature already exist in the tree; both proposals reuse them rather
than reinvent.

1. **Deny is already terminal.** `FW-BP4` (`constitution.md:128`, `formwork.md:228`) states "no allow
   at any layer shadows a deny at any layer — the only un-deny is the typed credential exclude
   (`FW-CRED5`)." The layer merge unions grants and denies and never lets an allow reopen a deny
   (`crates/formwork-blueprint/src/layer.rs:97-128`); the compiler folds the credential floor into the
   deny/subtract set structurally rather than checking it (`crates/formwork-compile/src/lib.rs:72`,
   `:424-425`; `crates/formwork-blueprint/src/catalog.rs:145-156`). The floor's un-bypassability is
   `FW-INV8` (`formwork.md:280`). So the feature's "deny-terminal, floor compiles into the deny layer"
   is Formwork's existing semantics — the proposals make it *explicit vocabulary*, not new behavior.

2. **The two modes already exist as a posture.** `ReadMode::Closed` (universe empty, only grants
   readable) vs `ReadMode::AmbientMinusSubtract` (ambient minus subtract) is exactly strict-unveil vs
   subtractive (`crates/formwork-blueprint/src/lib.rs:78-84`). It is already last-wins under merge
   (`crates/formwork-blueprint/src/layer.rs:100-102`, `crates/formwork-blueprint/src/narrow.rs:71-86`),
   and the catalog floor applies in both modes (folded in the compiler regardless of mode).

3. **The Linux/macOS deny mechanisms are implemented and (per `docs/linux-backend.md:1-9`)
   kernel-verified.** Linux hole-bounded subtractive expansion is `expand`
   (`crates/formwork-confine/src/linux/landlock.rs:111-144`); it skips symlinks (`:124-142`),
   hard-errors on any-depth holes (`holes_of`, `:73-90`), and the `covers`/`strictly_under` split is
   pure path arithmetic (`crates/formwork-blueprint/src/path.rs:92-104`) so a hole reserves its slot
   whether or not the path exists. macOS is last-match-wins SBPL (`crates/formwork-compile/src/sbpl.rs:
   1-8`), with any-depth denies as regex (`any_depth_regex`, `:239-270`). This is the feature's
   "Linux mechanism — implemented, verified" and the honesty story — both proposals inherit it
   unchanged.

What the feature *adds* on top of the above: (a) the flat `verb:path` rule vocabulary; (b) a
create/write split verb (write-without-create); (c) strict-unveil as an authored mode (not just an
internal `read_mode`); (d) per-rule provenance across all layers + `formwork explain`; (e) report
labels per deny mechanism; (f) the settled any-depth decision. Sections 1–3 are common to both
proposals; sections 4–5 are the two implementations.

---

## 1. Shared design — the verb model, rules, and modes

### 1.1 Verb table (both platforms, incl. the create/write split)

| Verb | Perms | Meaning |
|---|---|---|
| `allow` | r w c x | full: read, write, **create**, execute |
| `readwrite` | r w c | read, write, create (no exec) |
| `write` | r w | read + modify existing, **no create** (the split) |
| `readonly` / `read` | r | read only |
| `readexec` | r x | read + execute |
| `exec` | x | execute only |
| `deny` | — | terminal deny; nothing beneath (subject to `FW-CRED5` exclude) |

Bits map to mechanisms:

- **r** → Landlock `AccessFs::ReadFile`/`ReadDir` / Seatbelt `file-read*`.
- **w** → Landlock `WriteFile`/`Truncate` / Seatbelt `file-write-data`,`file-write-mode`.
- **c** (create) → Landlock `MakeReg`/`MakeDir`/`MakeSym`/… / Seatbelt `file-write-create`.
- **x** → Landlock `Execute` / Seatbelt `process-exec*`.
- **deny** → Linux hole in the subtractive expansion / Seatbelt `(deny file-read* file-write* …)`.

The **write vs allow** distinction (w vs w+c) is the feature's create/write split. Today `writes`
grants the full write set including create (`crates/formwork-confine/src/linux/landlock.rs:177-178`
sets `write_access = handled_fs`, i.e. `from_all` including `MakeReg`); SBPL `render_writes` allows
`file-write*` (`crates/formwork-compile/src/sbpl.rs:174-209`). Both proposals split this into two
grades: `write` drops the `Make*`/`file-write-create` bits; `allow`/`readwrite` keeps them. This also
generalizes the existing "create-frozen split dir" behavior (`docs/linux-backend.md:20-22`) from an
enforcement artifact into an authorable verb.

**Exec becomes a verb, not a posture.** `readexec`/`exec` replace `ExecPosture`
(`crates/formwork-blueprint/src/lib.rs:96-102`); default remains off (no verb grants x ⇒ Landlock
drops `Execute` from `handled_fs`, `crates/formwork-confine/src/linux/landlock.rs:162-168`; SBPL emits
no `process-exec` allow). No `exec:/home` traversal token — a covering-dir grant works automatically
and a broad exec grant is dangerous, so it is simply a verb on a path.

### 1.2 Flat rule syntax

One string = one rule: `"<verb>:<path>"`. The CLI flag and the file line are byte-identical:

```
--rule "deny:~/.ssh"          # CLI
"deny:~/.ssh"                 # file line
```

Path sigils (`~`, `$CWD`) expand at the CLI edge exactly as today (`FW-BP5`,
`crates/formwork-cli/src/blueprint_load.rs:144-201`). Rules parse into `PathPattern`
(`crates/formwork-blueprint/src/path.rs:38-118`) — no new pattern grammar.

### 1.3 The two YAML/TOML authoring models

Both are surfaces onto one model (`FW-BP1`). *(Assumed shape, since the feature text was cut off at
"a list of strings like:".)*

**Model 1 — strict-unveil** (universe starts empty; grants punch in; catalog floor denies):

```toml
mode = "strict-unveil"
rules = [
  "readwrite:$CWD/**",
  "readonly:/usr/**",
  "readexec:/bin/**",
  "deny:~/.ssh",
]
```

**Model 2 — subtractive** (ambient reads minus catalog; denies narrow; specific grants widen):

```toml
mode = "subtractive"
rules = [
  "readwrite:$CWD/**",
  "deny:./secrets",
]
```

The existing nested `[fs] { read-mode, reads, writes, subtract, write-subtract }` surface
(`crates/formwork-blueprint/src/lib.rs:57-74`) **stays valid** — `FW-E2E-041` guards that pre-existing
blueprints compile unchanged. `mode` maps to `read_mode` (strict-unveil→`closed`,
subtractive→`ambient-minus-subtract`).

### 1.4 Composition and mode as posture

- **Rules are two sets per verb: grants ∪ grants, denies ∪ denies.** Order-independent, so
  `--profile python-dev --rule "deny:./secrets"` means the same regardless of merge order — the
  existing additive union merge (`crates/formwork-blueprint/src/layer.rs:103-125`).
- **Asymmetry maps onto monotonic narrowing (`FW-CAP2`):** denies always narrow (safe from any
  layer), allows always widen (the only thing needing trust). This is exactly `narrow_fs`
  (`crates/formwork-blueprint/src/narrow.rs:64-95`): denies union, grants intersect.
- **Mode is a posture, not a rule:** it does not union; last-wins/tighten-only, like `read_mode`
  today. The catalog floor applies in both modes (compiler-folded, mode-independent).

### 1.5 Linux/macOS mechanism and honesty (inherited)

Unchanged from the tree (§0.3). Report labels per deny (proposed `FW-FID7`): `enforced-via-LSM`
(macOS regex), `enforced-via-enumeration` (Linux default), `enforced-via-overmount` (Linux upgrade),
`Partial` (Linux last resort). "hide" and "deny" are both EACCES-shaped — the report never claims
ENOENT cloaking (`FW-CAP4`, `formwork.md:155`; `formwork.md:470`). Snapshot asymmetry (Linux `read_dir`
runs once pre-spawn; staleness affects allows only, denies are airtight by construction) is surfaced
in the FidelityReport under `FW-XR6`, and the over-breadth case (a hole's missing intermediate
ancestor materializing post-spawn is denied in full) is one line in report semantics.

### 1.6 Any-depth (`**/`) decision — settled as (a)+(c)

`**/`-shaped patterns cannot be rooted as a Landlock rule, so on Linux a rule-level any-depth pattern
is a **build error** (`crates/formwork-confine/src/linux/landlock.rs:73-90`), preserving `FW-INV6`
(no silent open). macOS handles them as regex (`crates/formwork-compile/src/sbpl.rs:239-270`).
Decision: **(a)** any-depth is a macOS-only pattern *class* the compiler rejects in cross-platform
blueprints, and **(c)** `.env`-shaped shapes are handled once, centrally, through the catalog/backstop
(`FW-CRED6`, `profiles/credential-catalog.toml:138-168`) rather than per-blueprint rules.

---

## 2. Proposed new requirements (shared by both proposals)

Reusing existing families (no new family ⇒ no Concepts-grade family amendment). IDs are **proposed**
(next free numbers as of today: `CAP`→8, `BP`→6, `ISO`→9, `FID`→6, `INV`→11; test blocks
`FW-E2E-056+`, `FW-ADV-016+`, since the landed range ends at `FW-E2E-055`/`FW-ADV-015`).

- `FW-CAP8` **Three-layer evaluation, deny-terminal.** Path access resolves in fixed order: (1) hide —
  unlisted paths are inaccessible (EACCES, not ENOENT; the report says so); (2) allow — grants punch
  holes, more specific wins within the layer; (3) deny — applied last and terminal. No allow at any
  layer, and no rule order, can override a deny. The only removal of a deny is the typed credential
  exclude (`FW-CRED5`), which deletes the deny entry rather than overriding it. *(Restates and
  hardens `FW-BP4`/`FW-INV8` as the model's central property.)*
- `FW-CAP9` **Verb grammar with create/write split.** The fs grant vocabulary is a closed verb set —
  `allow`, `readwrite`, `write`, `readonly`/`read`, `readexec`, `exec`, `deny` — where `write` grants
  modify-but-not-create and `allow`/`readwrite` grant create. Enforced on both platforms
  (Landlock `Make*` bits / Seatbelt `file-write-create`).
- `FW-ISO9` **Exec as a verb.** Execution restriction is expressed as the `exec`/`readexec` verb, not
  a separate posture; off by default (no verb grants execute ⇒ execute is ungoverned/transparent).
  *(Reframes `FW-ISO4`; no traversal token, covering-dir grants apply.)*
- `FW-BP6` **Flat rule surface.** One string is one rule (`<verb>:<path>`), identical between the CLI
  flag (`--rule`) and a file line. Grants and denies are sets merged by union; the result is
  order-independent (profile stacking is commutative). Denies narrow from any layer; allows widen and
  are the only trusted layer (maps onto `FW-CAP2`).
- `FW-BP7` **Mode posture.** `strict-unveil` (empty universe) and `subtractive` (ambient minus
  catalog) are a last-wins/tighten-only posture, not a union rule. The catalog floor applies in both.
- `FW-FID6` **Rule provenance and `explain`.** Every effective rule carries provenance —
  `built-in | profile | file | cli | discovered`. `formwork explain <path>` reports the winning
  rule, its verb, and its provenance, without enforcing (extends `FW-CAP5` inspectability; reuses the
  discovery provenance machinery, `FW-DISC6`).
- `FW-FID7` **Per-deny mechanism labeling + snapshot disclosure.** The FidelityReport labels each
  deny by mechanism (`enforced-via-LSM` / `enforced-via-enumeration` / `enforced-via-overmount` /
  `partial`) and discloses (i) the Linux snapshot asymmetry (allows may go stale post-spawn; denies
  cannot) and (ii) hole-ancestor over-breadth ("denied more than declared"). Extends `FW-XR1`/`FW-XR6`.
- `FW-INV11` **Structural floor.** Because the credential catalog compiles into the deny layer and
  deny is terminal (`FW-CAP8`), no allow, no rule order, no profile, and no discovery path can
  produce access to a floored location; the sole removal is `FW-CRED5`. *(The structural form of
  `FW-INV8`.)*

Proposed tests (a hypothetical FEP-3 would reserve the block): `FW-E2E-056` verb round-trip &
create/write split; `FW-E2E-057` mode switch (strict-unveil vs subtractive) byte-deterministic;
`FW-E2E-058` order-independent profile stacking; `FW-E2E-059` `explain` provenance; `FW-E2E-060`
any-depth rule rejected on Linux, accepted on macOS; `FW-ADV-016` allow-cannot-override-deny (a
`readwrite:~` under a `deny:~/.ssh` still denies the key); `FW-ADV-017` post-spawn create under a
split dir is denied (Linux snapshot deny airtightness).

---

## 3. Cross-proposal comparison at a glance

| Axis | Proposal A — Surface reuse | Proposal B — Verb-set core |
|---|---|---|
| Internal `FsBlueprint` | unchanged; rules desugar into it | replaced by verb-keyed grant/deny sets |
| Blast radius | CLI edge + report + one write-tier bit | blueprint + compile + confine + narrow |
| Create/write split | new access-bit tier in compile/confine | native (`write` is a verb) |
| Provenance | added as a side-table over merge | intrinsic to each rule |
| Constitution | **no amendment** (new surface under `FW-BP1`; vocab lives in FEP/README) | Concepts + Data-model + Vocabulary **amendment required** |
| Migration | additive; both surfaces coexist | expand→migrate→contract on the schema |
| Fidelity to the feature's mental model | approximate (verbs are sugar) | exact (verbs are the model) |

---

## 4. Proposal A — new authoring surface, existing core

**Thesis.** The evaluation model is already Formwork's compile semantics (§0). Land the feature as a
new *serialization surface* (`FW-BP1`: one model, many surfaces) plus a small enforcement addition
(the create/write split) and inspection tooling. Nothing in the pure core's shape changes; the
verb-rule strings and the two YAML models desugar at the CLI edge into today's `FsBlueprint` +
mode, and the compiler/confiner run unchanged.

### 4.1 Desugaring map

Each `verb:path` rule appends to existing fields (`crates/formwork-blueprint/src/lib.rs:57-74`):

| Rule | Desugars to |
|---|---|
| `readonly:P` / `read:P` | `fs.reads += P` |
| `write:P` | `fs.writes += P` **with the no-create bit** (see 4.3) |
| `readwrite:P` / `allow:P` | `fs.writes += P` (create allowed; `allow` also adds exec) |
| `readexec:P` | `fs.reads += P` and `fs.exec = Allowlist(+P)` |
| `exec:P` | `fs.exec = Allowlist(+P)` |
| `deny:P` | `fs.subtract += P` |

`mode = "strict-unveil"` → `fs.read_mode = "closed"`; `mode = "subtractive"` →
`"ambient-minus-subtract"`. `write-subtract` (write-deny-keep-read, `FW-TRA7`) remains available as a
rule verb `writedeny:P` if wanted, mapping to `fs.write_subtract`.

### 4.2 Changes by crate

- **`formwork-cli`** — the bulk of the work.
  - `BlueprintArgs` (`crates/formwork-cli/src/main.rs:124-155`) gains `--rule <string>` (repeatable)
    and `--mode <strict-unveil|subtractive>`. `sugar_layer` (`:168-194`) already turns flags into a
    `BlueprintLayer`; add a `parse_rule(&str) -> (Verb, PathPattern)` and fold each into the
    `FsLayer`. `--rule` composes with the existing `--read/--write/--subtract` sugar.
  - `blueprint_load` (`crates/formwork-cli/src/blueprint_load.rs:28-79`) gains parsing of the
    top-level `rules = [...]` + `mode` keys of a file into the same `FsLayer`, before merge. A file may
    use *either* the nested `[fs]` table or the flat `rules` list (or both, unioned).
  - New subcommand `explain` (`crates/formwork-cli/src/main.rs:50-119`): loads the stack, and for the
    queried path reports the winning verb + provenance. Growth note: this is inspection, sibling to
    `compile --report-only`, justified under `FW-CAP5`.
- **`formwork-blueprint`** — minimal.
  - Provenance side-table: extend `merge` (`crates/formwork-blueprint/src/layer.rs:97-128`) to also
    return, per resulting pattern, the layer index/source it came from (built-in/profile/file/CLI/
    discovered). Reuse `ProvenanceEntry` (`:86-92`). This is additive; `Blueprint` itself is
    unchanged, so the compiler stays byte-deterministic.
  - No change to `narrow`/`path`/`catalog`.
- **`formwork-compile`** — one addition: the create/write split (4.3). Report gains the `FW-FID7`
  deny-mechanism labels in `report.rs` (extend `Backend`, `crates/formwork-compile/src/report.rs:
  31-43`, or add a `deny_mechanism` field to the per-capability rows).
- **`formwork-confine`** — mirror the create/write split bit in the Landlock write mask
  (`crates/formwork-confine/src/linux/landlock.rs:177-178`).

### 4.3 The create/write split (the only real core change)

Introduce a second write grade in `LinuxPolicy`/`MacosPolicy` (`crates/formwork-compile/src/policy.rs:
34-101`): a `writes_no_create: Vec<PathPattern>` alongside `writes`. Compile: `write:P` →
`writes_no_create`; `readwrite`/`allow` → `writes`. Enforce:

- Linux: for `writes_no_create` paths, grant `WriteFile|Truncate` but **not** `MakeReg|MakeDir|
  MakeSym|…` (`crates/formwork-confine/src/linux/landlock.rs:177-178`, split the mask into two
  constants).
- macOS: emit `file-write-data`,`file-write-mode` but not `file-write-create` for those paths in
  `render_writes` (`crates/formwork-compile/src/sbpl.rs:174-209`).

This is additive to the policy schema; existing `writes` behavior (full write incl. create) is
unchanged, so `FW-E2E-041`/027 determinism holds for prior blueprints.

### 4.4 Constitution impact — **none required**

- **Concepts** (`constitution.md:18-62`): the Blueprint concept is unchanged; verbs are a surface,
  not a new concept. `FW-BP1` explicitly allows "multiple surfaces onto one model."
- **Data model** (`constitution.md:64-86`): the schema change is *additive* (`rules`/`mode` keys,
  `writes_no_create` field), human-reviewed, expand-only — the discipline the section already
  mandates, no rule edit.
- **Vocabulary** (`constitution.md:88-118`): the new words (`verb`, `strict-unveil`, `hide-layer`)
  live in the FEP and README as authoring-surface terms; existing vocab (`deny`, `subtract`, `floor`,
  `narrow`, `grant`) already covers the semantics. If the team wants them in the constitution's
  glossary, that is a one-line additive entry — not required for the feature to be correct.
- **Growth** (`constitution.md:240-255`): `--rule`/`--mode`/`rules` reuse the existing sugar/merge
  path; `explain` is inspection. The one genuinely new mechanism is the create/write bit split,
  justified by `FW-CAP9`.

### 4.5 Tradeoffs

- **+** Smallest diff, lowest risk; reuses verified Linux/macOS mechanisms untouched; back-compat is
  free; aligns with the Growth doctrine's default-no; no constitution change.
- **−** Verbs are *sugar*: the internal model is still `reads/writes/subtract/exec`, so `formwork
  explain` reconstructs the "winning rule" from a side-table rather than reading a structured model,
  and a reviewer sees the desugared form in compiled output. The verb model is a lens, not the
  substrate.

---

## 5. Proposal B — first-class verb-set core model

**Thesis.** Make the three-layer, verb-keyed model the *substrate*. Replace `FsBlueprint`'s
`{reads, writes, subtract, write_subtract}` + `ExecPosture` with structured rule sets so that
deny-terminal, the verb grammar, and provenance are intrinsic — the mental model and the code match
one-to-one.

### 5.1 Core types

In `formwork-blueprint`:

```rust
enum Verb { Allow, ReadWrite, Write, ReadOnly, ReadExec, Exec }   // grant verbs; Deny is separate
struct Rule { pattern: PathPattern, provenance: Provenance }
enum Provenance { BuiltIn, Profile(String), File(String), Cli, Discovered { run_id: String } }
struct FsModel {
    mode: Mode,                              // StrictUnveil | Subtractive  (replaces ReadMode)
    grants: BTreeMap<Verb, Vec<Rule>>,       // the allow layer
    denies: Vec<Rule>,                       // the terminal deny layer (verbless)
}
```

- **Merge** (`crates/formwork-blueprint/src/layer.rs:97-128`) becomes set-union per `Verb` plus union
  of `denies`; `mode` last-wins. Order-independence and deny-terminality are now structural
  properties of the type, not conventions.
- **Narrowing** (`crates/formwork-blueprint/src/narrow.rs:64-95`): grants intersect per verb, denies
  union — the same algebra, expressed over the new shape.
- **Exec** folds into `Verb::Exec`/`ReadExec`; `ExecPosture` (`crates/formwork-blueprint/src/lib.rs:
  96-102`) is removed. `NetPosture`/`EnvPosture`/`mcp` are untouched.

### 5.2 Compiler and confiner

- `formwork-compile` lowers `FsModel` to the existing symbolic policy. The compiler is the natural
  place to compute the create/write split (verb bits → access masks) and to keep the credential floor
  fold into `denies` (`crates/formwork-compile/src/lib.rs:72`, `:424-425`). `CompileInput`
  (`:34-49`) is rebuilt from `FsModel` instead of `FsBlueprint`.
- `formwork-confine` is largely unchanged — it already consumes the symbolic `LinuxPolicy`/
  `MacosPolicy`. Only the write-mask split (4.3) is new.
- `formwork explain` reads `FsModel.grants`/`denies` directly and returns the winning `Rule` +
  `Provenance` natively (no reconstruction).

### 5.3 Migration (expand → migrate → contract)

Per `constitution.md:79-82` (a serialization change *is* a contract change):

1. **Expand:** add the `rules`/`mode` surface and `FsModel` alongside `FsBlueprint`; a compatibility
   parser maps the nested `[fs]` table onto `FsModel` so `FW-E2E-041` stays green.
2. **Migrate:** internal code moves to `FsModel`; the report and `formwork explain` adopt it; a
   deterministic serializer keeps `FW-FID4`/027 byte-identical for equivalent inputs.
3. **Contract:** at a version bump, retire the nested `[fs]` authoring form (or keep it as a
   permanently-supported alias — a documented decision).

### 5.4 Constitution impact — **amendment required (flagged)**

Unlike Proposal A, this touches the constitution and must say so:

- **Concepts** (`constitution.md:18-62`): the Blueprint's description enumerates "fs read/write/
  subtract, … exec posture, …". Folding exec into a verb and replacing the fs fields with a verb-set
  model changes that enumeration — a Concepts amendment (`constitution.md:56-62` requires
  amendment-by-proposal, not silent invention). A new sub-concept `Rule`/`Verb` may be named.
- **Data model** (`constitution.md:64-86`): the Blueprint schema is a durable, human-reviewed surface;
  this is a first-class change to it (expand→migrate→contract, as in 5.3).
- **Vocabulary** (`constitution.md:88-118`): `verb`, `grant-layer`, `deny-layer`, `strict-unveil`,
  `subtractive` become first-class terms with one meaning each; `read-mode` is renamed `mode`.

These are legitimate under the constitution's own amendment process, but they are edits — which is
why, if the goal is to *avoid* touching the constitution, Proposal A is the fit and Proposal B is the
deliberate exception.

### 5.5 Tradeoffs

- **+** Code matches the feature's mental model exactly; deny-terminality and order-independence are
  type-level guarantees, not conventions; provenance and `explain` are intrinsic; the create/write
  split is a native verb, not a bolt-on bit.
- **−** Largest blast radius (blueprint + compile + confine + narrow + report + CLI + every test
  fixture); requires constitution amendments; a migration with a contract phase. Higher review cost,
  which the Growth doctrine (`constitution.md:240-255`) says to justify before paying.

---

## 6. Notes common to adoption

- Neither proposal changes the verified Linux/macOS enforcement mechanisms (§0.3); both inherit the
  edge-case table (missing hole ancestor → benign reserved-slot deny; unreadable ancestor →
  grant-nothing fail-closed; any-depth hole → build error; missing grant-root ancestor → empty), the
  symlink-skip, and the snapshot asymmetry disclosure verbatim.
- The catalog stays curated-plus-backstop and can ship full-size: missing entries cost nothing at
  build (no `read_dir` on absent paths) and still protect if the path materializes later
  (`crates/formwork-confine/src/linux/landlock.rs:111-144`; `docs/linux-backend.md`).
- Adoption path: a new **FEP-3** document mints the proposed IDs above (with anchors), reserves the
  test block, and carries the traceability rows — the same shape as `fep-1.md`/`fep2.md` +
  `docs/fep2-plan.md`. Until then, the IDs here remain proposed only.
