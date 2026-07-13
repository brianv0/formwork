# FEP-2 execution plan

Companion to `fep2.md` (what and why). This says how, in what order, with which mechanisms —
the same role `IMPLEMENTATION_PLAN.md` plays for `formwork.md`. Requirement IDs refer to
`fep2.md`; test IDs use the **renumbered** scheme below.

## 0. Conflicts found during planning, and their resolutions

Planning against the current tree (post-FEP-1 main) surfaced three drafting conflicts in
`fep2.md`. Each is resolved by amending the FEP — visibly, per the constitution's
Precedence & Conflicts — not by silently deviating.

**C1 — Test-ID collisions.** `fep2.md` §9 assumed the base sequence ended at FW-E2E-028 /
FW-ADV-006. In fact FEP-1 landed FW-E2E-036..039 into `formwork.md`, and `fep-1.md` reserves
FW-E2E-029..032 + 040 and FW-ADV-007..009 + 011 for the deferred egress/violation-stream work.
FEP-2's tests are renumbered to the next free contiguous blocks:

| fep2.md draft | final ID | scenario |
|---|---|---|
| FW-E2E-029 | **FW-E2E-041** | rename regression |
| FW-E2E-030 | **FW-E2E-042** | override precedence |
| FW-E2E-031 | **FW-E2E-043** | CLI/file parity |
| FW-E2E-032 | **FW-E2E-044** | `extends` composition |
| FW-E2E-033 | **FW-E2E-045** | path credential denied + itemized |
| FW-E2E-034 | **FW-E2E-046** | env credential stripped, absent in tree |
| FW-E2E-035 | **FW-E2E-047** | env-points-to-file dual arm |
| FW-E2E-036 | **FW-E2E-048** | exclude-by-type un-blocks exactly one |
| FW-E2E-037 | **FW-E2E-049** | generic backstop |
| FW-E2E-038 | **FW-E2E-050** | report mechanism labeling |
| FW-E2E-039 | **FW-E2E-051** | learning proposes toolchain, omits secrets |
| FW-E2E-040 | **FW-E2E-052** | auto-widen zone boundary |
| FW-E2E-041 | **FW-E2E-053** | provenance recorded |
| FW-E2E-042 | **FW-E2E-054** | discovery non-authoritative |
| FW-ADV-007 | **FW-ADV-012** | credential oracle probe |
| FW-ADV-008 | **FW-ADV-013** | discovery confused-deputy |
| FW-ADV-009 | **FW-ADV-014** | launcher-bypass honesty |

FW-ADV-010 stays unassigned (a gap `fep-1.md` left); FW-ADV-011 stays reserved for FEP-1
Part A. One name per idea (constitution Vocabulary) is why this is fixed now, before any
marker exists.

**C2 — FW-BP2 precedence order.** The draft listed layers as "default profile → Blueprint
file → `extends` chain → CLI". Read literally with last-wins, a preset a file `extends`
would override the file that extends it — which inverts every known `extends` semantic and
would make presets unusable. Amended to the conventional, coherent order (lowest → highest):

1. **built-in baseline** — the fail-closed empty Blueprint plus the credential-catalog floor;
2. **`extends` chain**, depth-first, bases before deriveds;
3. **the named Blueprint file**;
4. **CLI overrides.**

"Built-in default profile" in the draft is also pinned down: the *baseline* layer is the
fail-closed floor + catalog, not `profiles/default.toml`. The broad-read subtractive profile
remains a preset a Blueprint opts into via `extends` (or `--blueprint profiles/default.toml`).
This keeps closed-mode Blueprints expressible (a union-merged implicit `reads = ["/**"]`
would make `read-mode = "closed"` meaningless) and matches fep2.md §11's own statement that
FW-CAP3 is "now realized concretely by the catalog + backstop".

**C3 — "glob path patterns" (FW-BP4) vs the FW-CAP6 grammar.** The pattern grammar stays
exactly FW-CAP6: absolute paths, `/**` subtrees, and any-depth `**/basename` forms. No
general glob (`id_*`, `.env.*`) is introduced: nothing in FEP-2's tests requires it, Landlock
cannot express it directly (it would ride on the enforce-time expansion only), and a richer
matcher in the security-critical path-narrowing algebra is exactly what the Growth doctrine
says no to first. The generic backstop (FW-CRED6) is expressed with curated any-depth
basenames instead (§3 below). FW-BP4's text is amended to say "path patterns (FW-CAP6
grammar)". If a future FEP shows a concrete secret shape the grammar cannot carry, that FEP
amends FW-CAP6.

*Review addendum:* PR review asked for prefix selectivity on the new any-depth rows, so the
grammar gained the **anchored** form `<prefix>/**/<suffix>[/**]` — the plain `**/` form with an
absolute scope. The backstop was briefly anchored under `~` to use it, but that was reverted:
a catch-all is location-independent by nature and must reach uncatalogued secrets outside `$HOME`
(FW-CRED6), and anchoring also opened an FW-INV8 seam (a non-`$HOME` credential shape the anchored
enforcement floor no longer denied). The backstop's file-shape rows stay filesystem-wide (`**/…`);
the anchored grammar form remains available for future curated rows that genuinely want a prefix.
Still no `*` glob; on Linux both any-depth forms remain unrootable and report Partial (FW-CRED9).
The same review pass fixed a real floor gap it surfaced: `accept` now canonicalizes the catalog
before its floor re-check, so type rows hold in kernel coordinates (a `/tmp`-based `$HOME` no
longer lets a forged entry slip past them onto the backstop).

## 1. The merge algebra (FW-BP1/2/4)

One model, many surfaces means one merge function. New in `formwork-blueprint`:

- **`BlueprintLayer`** — an all-optional mirror of `Blueprint` (every field `Option` /
  empty-default), plus the fields FEP-2 adds: `extends: Vec<String>` (only meaningful in
  files; resolved and emptied by the loader), `allow-credentials: Vec<String>` (FW-CRED5),
  and `[discovery]` (`auto-widen` patterns + provenance, Part D). Parsed with
  `deny_unknown_fields`, kebab-case, like `Blueprint`.
- **`merge(layers: &[BlueprintLayer]) -> Blueprint`** — pure, deterministic:
  - **path sets** (`reads`, `writes`, `subtract`, `write-subtract`, `allow-credentials`)
    **union across layers**. Grants and denies both only accumulate; **deny/subtract beats
    allow at match time** (the existing compile semantic). This is FW-BP2's "overrides are
    an additive last layer" taken at its word — and it is what makes FW-BP4's tie-break a
    structural property rather than an ordering accident: no allow at any layer can shadow
    a deny at any layer. The only un-deny that exists is the typed credential exclude
    (FW-CRED5), which lifts catalog entries by *type*, never by pattern.
  - **postures** (`read-mode`, `net`, `exec`, `env`) — **last-set-wins**; unset inherits.
  - **mcp** — per-server key, last-set-wins (a later layer's `[mcp.foo]` replaces an
    earlier one's wholesale; servers union across layers).
- `Blueprint` itself stays what it is; the merged result feeds the unchanged compiler. The
  existing single-file path (`Blueprint` = one layer over the baseline) keeps working —
  every already-landed blueprint parses and compiles to the same policy (FW-E2E-041).

**Loading (impure, CLI `blueprint_load`):** resolve `extends` recursively relative to the
extending file's directory, depth-first post-order, cycle-detected on the canonicalized file
path (a cycle is a load error naming the cycle). The CLI assembles
`[baseline, …extends…, file, cli_layer]` and calls `merge`.

**CLI surface (FW-BP1/BP3):** one generic override plus sugar, all desugaring into a single
`BlueprintLayer`:

- `--set '<toml>'` (repeatable) — a TOML fragment parsed by the *same* serde model as the
  file. Parity is by construction: the CLI layer literally is a Blueprint-layer document.
- Sugar that appends to path sets / sets postures: `--read`, `--write`, `--subtract`,
  `--write-subtract`, `--allow-cred <type>`, `--net deny|ports:<p,…>`, `--extends <file>`.
- Available uniformly on `compile`, `run`, `enforce-self`, `gateway`, `learn`.

## 2. The credential catalog (FW-CRED1..8)

**Data.** `profiles/credential-catalog.toml`, embedded into `formwork-blueprint` via
`include_str!` and parsed once (`OnceLock`) — data to review, not code, yet available to the
pure compiler with no I/O. Shape:

```toml
version = 1
[types.aws]
paths = ["~/.aws/**"]
envs  = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
[types.gcp]
paths = ["~/.config/gcloud/**"]
envs  = ["GOOGLE_APPLICATION_CREDENTIALS"]
env-file-refs = ["GOOGLE_APPLICATION_CREDENTIALS"]   # FW-CRED3: value names a file
# … ssh, gpg, azure, kube, docker, npm, pypi, github, netrc, anthropic, slack,
#   claude, codex, gemini, cursor, keychain, browser, system …
[backstop]
paths = ["**/.env", "**/.env.local", "**/.env.production", …, "**/credentials",
         "**/credentials.json", "**/.netrc", "**/id_rsa", "**/id_ed25519", …]
```

The catalog absorbs `profiles/sensitive-set.toml` (fep2.md §11: FW-TRA3 is superseded);
the old file is deleted and `default.toml`'s prose points at the catalog. `~` expansion
happens at load/compile boundary against the same `$HOME` the CLI already uses.

**Enforcement split (FW-CRED2):**

- *path arm* → compile: catalog paths for all types **minus `allow-credentials`** (plus the
  backstop, which no type lifts) are appended to the effective subtract set → confiner deny
  (EACCES). Landlock/Seatbelt carry it exactly like today's sensitive set.
- *env arm* → launcher (§3): catalog env names minus allowed types are stripped pre-spawn.

**Report (FW-CRED8).** `FidelityReport` gains a `credentials` section:
`BTreeMap<type, { path: Option<Fidelity>, env: Option<Fidelity>, note }>` where env entries
carry backend `launcher` and the launcher-contingency note verbatim ("holds only while
Formwork is the launching process"). `Backend::Process` is renamed `Backend::Launcher` —
one arm, one name (Vocabulary) — a report-schema change shipped with the workspace version
rename (review decision: no version bump -- the schema is pre-release, canary consumers only).

**Operator/agent split (FW-CRED7).** The operator channel is the existing stderr `tracing`
stream: at spawn, one structured itemization event per arm (types + names/patterns — never
values). The agent channel is the kernel's bare EACCES / the absent variable. No catalog
annotation ever reaches the confined side (FW-INV9).

## 3. The launcher arm (Part C)

The launcher is the CLI's spawn path, now named: the code that builds the child's
environment and applies confinement before handing over control. No new crate — pure
decisions live in `formwork-blueprint` (`launcher.rs`: given ambient vars, catalog, allowed
types, and the env posture → kept vars + stripped names + env-file-ref paths), impure
application stays in `formwork-cli`. Ordering: **catalog strip composes on top of the env
posture** — posture filters first (passthrough/allowlist/scrub), then catalog names minus
allowed types are removed from whatever survived. Deny wins; `allow-credentials` is the
only lift, and it also exempts the type's names from the FW-ENV2 scrub shapes so
`--allow-cred aws` yields a *usable* credential.

FW-CRED3 (env-points-to-file): before stripping, the launcher reads each `env-file-refs`
variable's value from its own environment; a non-empty value is canonicalized and appended
to the enforcement-time subtract set (same fail-loud path rules as any grant). Compile
stays pure — the report's `gcp.env` entry notes the referenced file is denied at spawn.

FW-INV7 (absent through the tree) is inheritance: what the child never receives, no
descendant can inherit. The test proves it at a grandchild. FW-ADV-014 (launcher-bypass
honesty) needs no code beyond FW-CRED8's note — the test asserts the disclosure exists and
that a formwork-less run indeed sees the variable.

## 4. Discovery (Part D)

**Posture: observe-then-widen** (fep2.md §12.2 resolved as recommended). Learning is an
*enforced* run plus observation — enforcement is never weakened by learning (FW-INV10;
policy is installed pre-exec and immutable, FW-XR8). What learning adds is a denial feed
and a reverse compiler.

**Denial feed.** On macOS, Seatbelt violations land in the unified log; `formwork learn`
records the run window and collects post-hoc via
`log show --style ndjson --start <t0> --predicate '(sender == "Sandbox")'`, attributing
events to the session by pid/pgid (the child is spawned in its own process group) with
best-effort fallback matching, then dedupes into `{path, op}` records. Post-hoc `log show`
(not `log stream`) keeps the collection deterministic — no race with stream startup. On
Linux, per-access denial observation needs Landlock audit (kernel 6.15+) which we do not
wire in this FEP: `learn` on Linux runs enforced but reports the observation gap loudly
and emits an empty proposal marked unobserved — fail loud, never silently pretend
(FW-INV5/6). Discovery E2E tests are macOS-marked, the platform honesty is asserted, and
the Linux feed is a documented follow-up.

**Reverse compile (FW-DISC2).** Pure function: denial records + effective Blueprint +
catalog + auto-widen zone → a *proposal*:

- catalog-matched denial → **withheld** (named on the operator channel with its type;
  never a candidate — FW-DISC3/FW-INV8; the zone cannot lift it either);
- denial inside the operator-authored `[discovery] auto-widen` zone → **auto-acceptable**;
- anything else → **needs-review**.

Candidates are literal paths, folded to `parent/**` only when ≥2 denied siblings share a
parent (deterministic clustering). Reads and writes are proposed per the denied operation.

**Artifacts.** A proposal file (TOML, itself a `BlueprintLayer` plus per-entry tags and
run metadata) written next to the blueprint (`<name>.proposal.toml`). Accepted grants live
in a *discovered layer* file (`<name>.discovered.toml`) that carries `[discovery.provenance]`
(pattern → `{ added-via = "discovery" | "discovery-auto", run-id }`); the operator's
blueprint `extends` it (or the CLI stacks it). Authored vs learned stays distinguishable
by file and by provenance table (FW-DISC6). `formwork learn` auto-moves only in-zone
candidates into the discovered layer; `formwork accept --proposal p --entry <pattern>`
(and `--all-reviewed`) moves the rest per-entry after human review (FW-DISC5).

**Sequencing within a run:** observation never changes the running session (FW-DISC1,
FW-E2E-054); the discovered layer takes effect on the *next* run (FW-E2E-052).

## 5. End-to-end test design

All tests are black-box `formwork` CLI via the py harness (markers carry the FW IDs;
traceability is generated). Enforcement tests are macOS-marked (real Seatbelt), matching
the suite's existing posture; compile-level tests run everywhere. New fixtures: a fake
`$HOME` per test (the CLI expands `~` against `$HOME`, so a temp home with planted
`~/.aws/credentials`, `~/.ssh/id_ed25519`, `~/.someprovider/credentials` exercises the
catalog against the real kernel without touching the developer's real secrets).

- **FW-E2E-041 rename regression.** The same capability document compiles via
  `--blueprint` and via the `--spec` back-compat alias, and a pre-FEP-2 single-file
  blueprint (no extends/layers) compiles identically before and after this change:
  byte-identical policy+report JSON. Guards both the landed spec→blueprint rename and
  FEP-2's model refactor.
- **FW-E2E-042 override precedence.** File grants read+write of `W/**`; CLI adds
  `--subtract W/secret.txt`. Enforced run: read of `W/ok.txt` succeeds, `W/secret.txt`
  denied (CLI deny lands); compile asserts deny-wins at equal precedence (same path in
  `reads` and `subtract` of one file → denied).
- **FW-E2E-043 CLI/file parity.** Grant set authored (a) in a file, (b) as
  `--set`/sugar flags over an empty file: `formwork compile` output byte-identical.
- **FW-E2E-044 extends.** `child.toml extends base.toml` (+ a diamond A→[B,C]→D case):
  merged compile deterministic (twice → byte-identical); `a extends b extends a` errors,
  message names the cycle; deep-chain order: child posture beats base.
- **FW-E2E-045 path credential.** Fake home, planted `~/.aws/credentials`; broad-read
  blueprint (extends default profile pattern). Confined `cat ~/.aws/credentials` →
  EACCES-class denial; launcher stderr itemizes type `aws`; child-visible stderr carries
  no type/catalog annotation (assert the denial text the child sees is the plain kernel
  errno).
- **FW-E2E-046 env credential.** `AWS_SECRET_ACCESS_KEY=x formwork run … -- sh -c 'echo
  ${AWS_SECRET_ACCESS_KEY-UNSET}; sh -c "echo ${AWS_SECRET_ACCESS_KEY-UNSET}"'` → both
  levels print UNSET (absent, not empty); operator channel itemizes `aws`; a control var
  (`ORDINARY_VAR`) survives. Runs on both platforms (launcher is kernel-independent).
- **FW-E2E-047 env-points-to-file.** `GOOGLE_APPLICATION_CREDENTIALS=<readable tmp file
  inside the read grant>`: variable absent in child AND the referenced file is denied
  despite the surrounding grant.
- **FW-E2E-048 exclude-by-type.** Same fake home, `--allow-cred aws`: `~/.aws/credentials`
  readable and `AWS_SECRET_ACCESS_KEY` present; `~/.ssh/id_ed25519` still denied and
  `SLACK_BOT_TOKEN` still stripped. Exactly one type moves.
- **FW-E2E-049 backstop.** Planted `~/.someprovider/credentials` and `<proj>/.env.production`
  under a broad grant: both denied with no curated type naming them (backstop rows).
- **FW-E2E-050 report labels.** `formwork compile --report-only` on a catalog-bearing
  blueprint: every env-kind type labeled backend `launcher` with the contingency note;
  every path-kind type labeled with the OS backend; dual-kind types carry both.
- **FW-E2E-051 learning proposes toolchain, omits secrets** *(macOS)*. Fixture: tight
  blueprint (project-only reads) + a script that reads an interpreter path, a fake cache
  dir, and `~/.aws/credentials`. `formwork learn` run: proposal contains the toolchain
  paths, contains no catalog-matched path; withheld list names `aws` on the operator
  channel only.
- **FW-E2E-052 auto-widen boundary** *(macOS)*. Zone = `<proj>/**`. Learning run denies
  `<proj>/.cache/x` (in-zone) and `<other>/y` (out-of-zone). Next enforced run: in-zone
  path readable (auto-accepted into the discovered layer); out-of-zone still denied and
  sitting in the proposal as needs-review.
- **FW-E2E-053 provenance** *(macOS)*. After an accept: discovered layer lists the grant
  under `[discovery.provenance]` with `run-id`; authored grants in the main file carry
  none; `formwork compile` on the stack succeeds.
- **FW-E2E-054 non-authoritative** *(macOS)*. During one `learn` run, a denied read is
  attempted, observed, then re-attempted in the same run: still denied (no live widening).
- **FW-ADV-012 credential oracle.** Probe (a) reads `~/.aws/credentials` and an ungranted
  non-catalog path — identical errno class, no type text; (b) compares
  `os.environ.get("AWS_SECRET_ACCESS_KEY")` under formwork-with-var-set vs a run with the
  var genuinely unset — indistinguishable; no interactive prompt ever surfaces.
- **FW-ADV-013 discovery confused-deputy** *(macOS)*. A learn-mode workload hammers
  `~/.ssh/id_ed25519` N times (with the zone even set to `~/**` to be adversarial): the
  proposal never contains it, the discovered layer never gains it, next run it is still
  denied. The floor holds regardless of attempt count or zone breadth.
- **FW-ADV-014 launcher-bypass honesty.** Same workload run *without* formwork sees the
  variable; the FidelityReport for the blueprint carries the launcher-contingency
  disclosure. Both must hold (the guarantee was never overclaimed).

Rust-side tests accompany each pure piece: merge algebra (union/last-set-wins/
determinism/property-style narrow interaction), extends cycle detection, catalog parse +
version + `deny_unknown_fields`, strip computation, reverse-compile tagging (catalog floor,
zone boundary), proposal/provenance round-trip.

## 6. Order of work

Follows fep2.md §13 (catalog before discovery — the floor must exist before the feature
that must respect it):

1. **FW-BP** — layer/merge/extends/CLI (tests 041–044).
2. **FW-CRED path arm** — catalog data + compile + report `credentials` section + rename
   `Process`→`Launcher` (tests 045, 049, half of 050, path half of ADV-012).
3. **Launcher env arm** — strip + env-file-refs + itemization (tests 046, 047, rest of
   050, ADV-012, ADV-014). FW-CRED5 `--allow-cred` lands with 2–3 (test 048).
4. **FW-DISC** — log tap, reverse compile, zone, proposal/accept, provenance (tests
   051–054, ADV-013).
5. **Docs** — `formwork.md` §2/§4/§5/§10 impact, constitution amendments (Concepts:
   Catalog + Launcher; Vocabulary; Data model), profiles migration, examples, fep2.md
   status flip + traceability.
6. **Verification + constitutional review** — fmt/clippy/tests/py suite/Linux
   cross-compile, then a section-by-section review of the diff against `constitution.md`.

Each phase lands compiling, clippy-clean, and green before the next begins.

## 7. Resolved open decisions (fep2.md §12)

1. **Serialization: stay on TOML.** The pain TOML causes is at MCP nesting depth, which
   FEP-2 does not deepen; layering + `extends` fixes composition; strictness
   (`deny_unknown_fields`) is a security asset; and the file format is a published,
   human-reviewed surface (Data model) — switching costs a migration no requirement pays
   for. Revisit only with a concrete need for logic, per fep2.md §4.
2. **Discovery default: observe-then-widen.** Interactive `SECCOMP_USER_NOTIF` prompting
   stays out of scope (confirmed), documented as a Linux-only future.
3. **Catalog v1: curated set + generic backstop** (the recommendation), absorbing the
   whole FW-TRA3 sensitive set as types so exclude-by-type covers agent-state too.
4. **Auto-widen zone: empty by default.** The operator draws it; nothing self-grants out
   of the box.
5. **Credential brokering: deferred** to a later FEP (unchanged).

## 8. Constitutional review of the execution (post-implementation)

Reviewed section-by-section against `constitution.md`, over the full branch diff.

- **Supremacy / mechanical.** `cargo fmt --check` clean; `clippy --workspace --all-targets
  -D warnings` clean; 25 Rust test binaries and 32 Python E2E tests green on macOS against
  real Seatbelt and the real unified-log feed; the workspace cross-checks for
  `x86_64-unknown-linux-gnu`.
- **Concepts.** Two additions (Catalog, Launcher) amended into the closed list *by this FEP* —
  amendment-by-proposal honored. No parallel concepts: layering is how a Blueprint is
  assembled; discovery is a workflow over launcher + confiner + report; its artifacts are
  named Data-model surfaces. No new door for the agent: the denial feed is operator-side.
- **Data model.** Input schema growth is additive — every pre-FEP-2 blueprint parses and
  compiles unchanged (FW-E2E-041). The report change (credentials section, `process`→
  `launcher` backend rename) needs no version bump per review -- the schema is pre-release with
  canary consumers only. `deny_unknown_fields` on every new
  input type. `sensitive-set.toml` pruned at this release (event-triggered), content migrated
  into the catalog.
- **Vocabulary.** floor / strip / exclude / learn / withheld / accept / provenance recorded,
  one meaning each. A `deny` synonym for `subtract` was deliberately NOT introduced (FW-BP4
  amended instead).
- **Boundaries.** Each new external input parses once at its edge: layer files and `--set`
  fragments (loader), the embedded catalog (parse-once, unit-validated), env-file-ref values
  (loader, loud on non-UTF-8), unified-log ndjson (learn edge → `DenialRecord`), proposals
  (accept edge). No secret values anywhere in artifacts or telemetry — names and types only,
  asserted by FW-E2E-046 (the injected value never appears in any output).
- **Errors.** New failure paths are closed-or-loud: unknown credential type (lists known),
  extends cycle (names the cycle), un-renderable floor/env-file-ref path (refuses, FW-INV6),
  provenance-less discovered grant (refused), feed-less learning (runs enforced, warns, writes
  nothing), forged proposal (refused at the floor).
- **Observability.** New boundary events (floor itemization, strip itemization, learning
  banner/summary/withheld, discovered-layer load, accept) are structured tracing on stderr;
  stdout stays a pure result stream (byte-compared by the parity/determinism tests).
- **Layers.** Direction unchanged; pure decisions (merge, catalog resolution, `construct_env`,
  `reverse_compile`) in the domain crate, IO/env/log/spawn in the CLI shell. `compile()`
  stays kernel-free — the catalog became an explicit *input* precisely to keep it pure.
- **Growth.** One dependency change: `toml` dev→regular in `formwork-blueprint` (already in
  the binary's trust base; justified in the manifest). The pattern grammar was NOT extended
  (glob refused, §0 C3). Three test-only APIs pruned or gated during this review
  (`floors()`, `parse_sandbox_denial` visibility, `from_blueprint` cfg(test));
  `gateway()` refolded onto `prepare_session` to remove a duplicated prologue.
- **Testing.** No mocks; kernel probes are paired allow/deny against real Seatbelt; the
  denial feed is the real unified log. The pure-input carve-out is used only for compile
  determinism (fixed home) and unit isolation (`empty_no_floor`, loudly named). Traceability
  is generated from markers: FW-E2E-041..054 and FW-ADV-012..014, 17/17 implemented and green.
- **Precedence & conflicts.** The three fep2.md drafting conflicts were resolved by visible
  amendment (§0), never silent deviation. Known, *reported* residuals — honesty-pattern gaps,
  not suspended rules: (a) any-depth floor rows are withheld on Linux and the affected types
  + backstop reported Partial (FW-INV5); (b) the denial feed is macOS-only, Linux learning
  warns loud and writes nothing; (c) FW-E2E-051 exercises the learning property with a
  hermetic scripted workload because the FW-E2E-020 reuse fixtures do not exist yet; (d) log
  attribution is window+dedup — over-capture is floored or review-gated by design (FW-INV10).

Follow-ups noted, not blocking: full `formwork.md` reintegration (FEP-1 precedent: separate
docs PR); a Linux denial feed via Landlock audit (kernel 6.15+) when a test kernel exists;
host-example READMEs could mention `--allow-cred` explicitly.
