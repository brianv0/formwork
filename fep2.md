# FEP-2: Blueprints, the Credential Catalog, and On-Demand Discovery

**Formwork Enhancement Proposal 2**

- **Status:** Accepted / in implementation. Amended at execution planning: test IDs renumbered to avoid collisions with landed FW-E2E-036..039 and `fep-1.md`'s reserved blocks, FW-BP2's layer order corrected, FW-BP4 pinned to the FW-CAP6 pattern grammar. Rationale and mapping in `docs/fep2-plan.md` §0.
- **Depends on:** the base Formwork design document (`formwork.md`)
- **Scope:** terminology change (spec → Blueprint), a Blueprint format/override model, a typed credential-location catalog, and an on-demand allow-listing (discovery) workflow.
- **Introduces:** a third enforcement arm — the **launcher** — alongside the existing confiner and gateway.

---

## 1. Summary

This proposal makes four changes to Formwork, in increasing order of new machinery:

1. **Rename the capability input from "spec" to "Blueprint"** — a plan you build the mould from — and define it as a typed, versioned model with a documented file/CLI override story.
2. **Add a typed credential-location catalog** (FW-CRED) covering well-known credential *locations only*: dotfiles, well-known file paths, and environment variables — keyed by type (aws, gcp, ssh, anthropic, slack-bot, …), excludable by type.
3. **Formalize the launcher as a third enforcement arm**, because environment-variable shading cannot be done by Landlock or Seatbelt and must happen pre-spawn in the process that constructs the confined environment.
4. **Add on-demand discovery** (FW-DISC): observe what a confined workload actually tries to touch, and turn those denials into a reviewable proposed Blueprint — bounded so the feature cannot be turned into a confused-deputy path to the credential catalog.

Nothing here weakens the base threat model (base §3) or the honesty invariant (FW-INV5). Two of the changes exist specifically to keep the "good, not perfect / maximal reuse" philosophy usable without eroding the boundary.

## 2. Motivation

Authoring a complete capability document up front is the hardest part of any capability system — nobody knows in advance that a test run needs a coverage plugin's cache dir three levels deep. The base design leans on a subtractive default profile (FW-CAP3) and a sensitive set (FW-TRA3) to make this tractable, but leaves two gaps this proposal fills:

- The sensitive set was described informally. Real use needs it to be a **typed, versioned catalog** so it can be reasoned about, excluded from selectively, and reported precisely ("blocked `~/.aws/credentials` because: aws"). Both features requested — an ambient-credential *detector* and *exclude-by-type* — are two consumers of one catalog.
- Even with a good default profile, the first runs of any new workload hit denials. Today that means hand-editing the Blueprint. **Discovery** turns the workload's real behavior into the Blueprint, which is where most of the day-to-day ergonomic win lives — provided it is bounded so a prompt-injected agent cannot use it to define its own sandbox.

## 3. Terminology change: spec → Blueprint

The capability input document is renamed **Blueprint** throughout. Rationale: it fits the construction metaphor (formwork is the mould; the blueprint is the plan the mould is built from) and it is *accurate* — the Blueprint has exactly the plan-to-artifact relationship to the compiled policy that a blueprint has to a structure. It yields clean verbs ("compile a Blueprint") and preserves the existing artifact names (compiled policy, `FidelityReport`).

Caveat honored in the requirements: "blueprint" is loosely overloaded in software, so it is defined once, precisely, and not used for anything else.

## 4. Part A — Blueprint model and format (FW-BP)

The first implementation serialized the spec as TOML. This proposal does **not** replace it with a bespoke DSL: a Blueprint is essentially data (path patterns, a net posture, per-server tool allowlists) with no control flow, and a from-scratch language would pay a large parser/grammar/learning cost to describe a struct — cutting against the transparency north star exactly the way SELinux's policy language cuts against Landlock's appeal. Instead the proposal fixes what TOML was actually straining against — *vocabulary*, *composition*, and the *override story* — and treats the serialization format itself as a swappable surface.

The unifying idea is **one model, multiple surfaces**: the Blueprint is a typed, versioned schema (the thing validated and versioned); the file is one serialization of it; the CLI flags are another surface onto the same model, applied as an override layer. Get the model right and "the CLI looks and feels like the file" falls out for free, because they are the same tree underneath.

The Blueprint is expressed in a standard serialization, not a bespoke DSL — that is a design constraint of this proposal, not a testable requirement, and it is argued in the paragraph above. If real logic (conditionals, computed scopes) is ever required, the answer is to adopt an existing configuration language (CUE/Dhall/KCL/Jsonnet), never to author one.

| Req | Requirement |
|---|---|
| **FW-BP1** One model, many surfaces | The Blueprint is a typed, versioned schema. The file format and the CLI flags are two surfaces onto the same model, not two models: any grant/deny/exclusion expressible in one is expressible in the other. |
| **FW-BP2** Override precedence | Layers merge in a fixed, documented order, lowest to highest: built-in baseline (the fail-closed empty Blueprint plus the credential-catalog floor) → `extends` chain (depth-first, bases before deriveds) → Blueprint file → CLI overrides. Postures (read-mode/net/exec/env) are last-set-wins; path sets merge additively; the result is deterministic. Overrides are an additive last layer, never a separate mechanism. *(Amended: the draft's "default profile → file → extends" order would have let a base preset override the file extending it; the broad-read default profile is a preset opted into via `extends`, not an implicit layer — FW-CAP3 is realized by the catalog + backstop, §11.)* |
| **FW-BP3** Composition via `extends` | A Blueprint may extend one or more base Blueprints (presets/profiles). Resolution is deterministic and cycles are detected and errored. |
| **FW-BP4** allow / deny / subtract vocabulary | First-class allow (reads/writes), deny/subtract (read+write), and write-subtract semantics over path patterns in the FW-CAP6 grammar (absolute, `/**` subtree, any-depth `**/basename`). At any layer and at equal precedence, deny/subtract wins over allow (safety bias); no allow at any layer shadows a deny at any layer — the only un-deny is the typed credential exclude (FW-CRED5). *(Amended from "glob path patterns": no general glob is introduced; see `docs/fep2-plan.md` §0 C3.)* |

**Serialization format is an open decision (§9).** The tradeoff, stated for the record: TOML is readable and strict but fights nesting exactly where Blueprints are deepest (`server → {tools, resources, prompts}`); YAML nests cleanly at the cost of well-known ambiguity footguns (dangerous in a security artifact unless schema-validated); JSON-with-schema is unambiguous at some cost to hand-authoring comfort. The decision should be made on the override-story and validation grounds above, not on expressiveness.

## 5. Part B — the credential catalog (FW-CRED)

The requested features — an ambient-credential detector and exclude-by-type — are two consumers of a single **typed catalog of credential locations**. Per the clarified scope, this is **locations only**: dotfiles, well-known file paths, and environment variable names. There is no content scanning, no byte-signature matching, and no gateway payload inspection in this proposal; those were considered and dropped as a weaker, advisory-only enforcement position that would over-promise. Because it is purely location-based, every entry is a *hard boundary*.

A catalog entry has a **type** and one or both **location kinds**:

- **path** — e.g. `~/.aws/credentials`, `~/.ssh/**`, `~/.config/gcloud`, `~/.kube/config`, `~/.docker/config.json`, `~/.npmrc`, `**/.env`, `~/.anthropic/…` (FW-CAP6 grammar)
- **env** — e.g. `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `ANTHROPIC_API_KEY`, `SLACK_BOT_TOKEN`, `GITHUB_TOKEN`, `GOOGLE_APPLICATION_CREDENTIALS`

The two kinds are enforced by two different arms, which is the crux of this part:

- **path → confiner.** Contributes to the OS-sandbox deny set. Result: EACCES. Landlock/Seatbelt gate it.
- **env → launcher.** Landlock and Seatbelt cannot shade environment variables — an env var is a string in the process's environment block, not a filesystem object, so the kernel has no hook on it. But Formwork *spawns* the confined process (spawn-confined posture) and therefore constructs the child's environment. Shading an env var is simply not copying it into the spawn. The child comes up having never had it. This is enforced pre-`exec`, in the **launcher**.

Env shading is, if anything, *stronger* than path denial: a denied path still exists (the agent gets EACCES and learns there is a wall), whereas a stripped variable is genuinely absent — `os.environ.get()` returns `None`, indistinguishable from a machine where the credential was never configured. It is the true unveil-style invisibility the filesystem side cannot cheaply provide, obtained for free because "don't pass it" is the whole implementation. The one contingency: it holds only when Formwork is the launching process, which the report must disclose (FW-CRED8).

| Req | Requirement |
|---|---|
| **FW-CRED1** Typed location catalog | A versioned catalog of credential *locations* keyed by type. Each type contributes path patterns and/or env-var names. |
| **FW-CRED2** Two kinds, two arms | **path** entries → confiner deny (EACCES); **env** entries → launcher strips the variable before spawn (variable absent). Enforced and reported distinctly. |
| **FW-CRED3** Env-points-to-file types | A type may carry both an env var and the file it references (e.g. `GOOGLE_APPLICATION_CREDENTIALS`). Excluding the type strips the variable **and** denies the referenced file. |
| **FW-CRED4** Deny-superset by default | The whole known catalog is blocked/stripped by default (fail-closed); exclusion is opt-in per type (FW-CRED5). Coverage of uncatalogued secrets is FW-CRED6's job. |
| **FW-CRED5** Exclude-by-type is un-blocking | `allow_credentials: [aws]` (CLI `--allow-cred aws`) deliberately and visibly lets one type through; nothing adjacent is affected. This is the knob for when the agent genuinely needs a credential. |
| **FW-CRED6** Generic backstop | Beyond curated types, a generic rule denies known-sensitive shapes (any `~/.ssh`, any `.env`, credential files in known config dirs) so uncatalogued secrets remain covered. |
| **FW-CRED7** Operator/agent channel split | The operator sees itemized "denied/stripped X (type: …)". The confined agent sees a plain EACCES / an absent variable with no catalog annotation — no oracle. |
| **FW-CRED8** Report names the mechanism | The FidelityReport marks each covered type `enforced-via-launcher` (env) or `enforced-via-OS-sandbox` (path), and states plainly that env-shading holds only while Formwork is the launching process — the guarantee is launcher-contingent, and the report must not overclaim it as independent of the launcher. |

**Detector = report enrichment.** The "ambient credentials detector" is not new enforcement; it is FW-CRED7's operator-channel itemization plus the compile-time report of which catalog entries were subtracted and why. The default posture is deny-the-superset, report-the-specifics: block everything known (so a forgotten type is still gone), and itemize what was blocked — resolving the tension between safe-by-default and legible by doing both.

## 6. Part C — the launcher as a third enforcement arm

FW-CRED's env kind forces a structural addition to the base architecture. The base design had a compiler feeding two arms (confiner, gateway). This proposal names a third:

```
                 COMPILER (one Blueprint → three policies + report)
          ┌───────────────┬────────────────────┬────────────────────┐
          ▼               ▼                    ▼
   LAUNCHER (pre-spawn)  CONFINER (OS sandbox)  GATEWAY (MCP proxy)
   env construction &    Landlock / Seatbelt    shading, backends,
   credential strip       fs / net              fd minting
   → var absent           → EACCES              → not-found
```

The launcher is the process that constructs the confined child and applies the OS confinement before handing over control; env shading is one of its jobs. Its guarantees differ in kind from the confiner's — an env strip is absolute (the value is not present) but contingent on Formwork being the launcher, whereas a path denial holds against any process regardless of how it was started. That difference is why the report must label the arm and disclose the contingency (FW-CRED8).

The launcher's env construction is **allowlist-capable, denylist-by-default**: because Formwork builds the environment rather than mutating a live one, it can either strip matched credential vars from an otherwise-inherited environment (denylist — preserves reuse, the default) or pass only an explicit set (allowlist — stronger, risks breaking tools that need `HOME`/`PATH`/`LANG`/proxy vars). Reuse argues for denylist-by-default with allowlist available for locked-down profiles.

## 7. Part D — on-demand discovery (FW-DISC)

Discovery observes what a confined process actually tries to touch and turns denials into candidate grants, so you start tight and let real behavior write the Blueprint. This is the single most valuable ergonomic feature for the reuse goal — and the one with the sharpest security tradeoff, because auto-granting an agent's *attempts* is a confused-deputy machine: a prompt-injected "read `~/.ssh/id_ed25519`" produces a denial, which produces a candidate grant, which a fatigued operator approves, and the wall is gone.

The proposal resolves this two ways. First, **the default posture is observe-then-widen**, not live prompting: run in a marked learning phase, record denials without granting them, produce a reviewable proposed Blueprint, then enforce the accepted result on subsequent runs. This keeps the human decision out of the hot path and before enforcement, needs no syscall interception, and works identically on both platforms. (Live interactive prompting would require `SECCOMP_USER_NOTIF`/`ptrace` on Linux with no clean macOS equivalent; it is left as a documented Linux-only future option, out of scope here.) Second, and load-bearing: **the credential catalog is the floor discovery cannot erode.**

| Req | Requirement |
|---|---|
| **FW-DISC1** Learning mode | An explicit, non-enforcing (or permissive-logging) phase that records denials without granting them at runtime. Distinct and visibly different from an enforced run. |
| **FW-DISC2** Reverse compile | Denials compile *backwards* into a proposed Blueprint diff. Each candidate is tagged: catalog-blocked / inside-auto-widen-zone / needs-review. |
| **FW-DISC3** Catalog floor | A denial matching the FW-CRED catalog is **never** offered as an auto-proposable or one-click candidate grant. Lifting it requires the explicit typed exclude (FW-CRED5), never the discovery flow. *(Load-bearing safety property.)* |
| **FW-DISC4** Auto-widen zone | An operator-authored scope in the Blueprint within which discovered grants may be auto-accepted (e.g. project dir, language caches, system prefixes). Outside the zone, review is required. |
| **FW-DISC5** Review as itemized diff | Proposals surface on the operator channel as a diff showing what widens and what was withheld and why. Acceptance is per-entry. |
| **FW-DISC6** Provenance | An accepted discovered grant is recorded in the Blueprint with provenance (added-via-discovery, run id), so audit distinguishes authored from learned grants. |

Note that "Formwork never runs a real workload in a grant-whatever-is-attempted mode" is not a separate requirement — it is the combined consequence of FW-DISC1 (learning mode is non-enforcing) and FW-DISC4 (auto-widen is operator-bounded), and it is stated as a guarantee in FW-INV10.

**Sticky learning within a trust boundary** is the recommended sweet spot for iterative development and is expressible via FW-DISC4: accumulate proposals across runs, auto-accept only entries inside the operator-drawn auto-widen zone, review everything else. Discovery does the tedious enumeration; the human keeps the perimeter.

Mechanically, discovery reuses existing machinery: the FW-FID3 runtime observability record *is* the denial log; the compiler gains a reverse mode; the FW-CRED7 operator/agent channel split carries over unchanged. No new enforcement arm — it is a workflow over the launcher + confiner + report.

## 8. New invariants

Continuing the base document's `FW-INV` sequence (base defined INV1–INV6).

**FW-INV7 — Launcher-strip completeness.** A stripped env var is *absent* (not merely denied) throughout the confined process and its entire descendant tree. The confined process may still set new vars for its own children; this shades ambient inherited credentials, not values the agent synthesizes.

**FW-INV8 — Credential floor.** No discovery path, no auto-widen rule, and no single-click operator action can grant access to a FW-CRED-matched location. Only the explicit typed exclude (FW-CRED5) can.

**FW-INV9 — No-oracle for credentials.** Denied credential paths and stripped credential env vars are indistinguishable, to the confined agent, from genuinely absent resources — no error text, code, or timing reveals existence.

**FW-INV10 — Discovery is non-authoritative.** A discovered candidate has no effect until accepted into an enforced Blueprint. Observation never itself widens a live enforced session, except within a pre-declared auto-widen zone.

(The env-shading honesty guarantee — that the report discloses launcher-contingency — is carried by FW-CRED8 rather than a standalone invariant, and is a specialization of the base document's FW-INV5 report-soundness invariant.)

## 9. New end-to-end tests

Continuing the `FW-E2E` and `FW-ADV` sequences. Taken: the base defines FW-E2E-001–028 and FW-ADV-001–006, FEP-1 landed FW-E2E-036–039, and `fep-1.md` reserves FW-E2E-029–032 + 040 and FW-ADV-007–009 + 011 for its deferred egress/violation-stream work. FEP-2 therefore uses **FW-E2E-041–054** and **FW-ADV-012–014** (mapping from this document's draft numbering in `docs/fep2-plan.md` §0).

### 9.1 Blueprint model and format

**FW-E2E-041: Rename regression.** *(Regression guard for the §3 rename; not tied to a numbered requirement.)* A Blueprint that is the renamed form of a prior spec compiles to the same policy and report. Pass: no behavioral change attributable to the rename. Fail: any policy difference.

**FW-E2E-042: Override precedence.** A path allowed in the file is denied by a CLI `--subtract` layered over it; a deny and an allow at equal precedence resolve to deny. Pass: merge follows baseline → extends → file → CLI (FW-BP2 as amended), postures last-set-wins, path sets additive, with deny-beats-allow at ties. Fail: any ordering or tie deviation.

**FW-E2E-043: CLI/file parity.** The same grant authored in the file and expressed via CLI flag produce identical compiled policy. Pass: byte-identical policy from both surfaces. Fail: divergence.

**FW-E2E-044: `extends` composition.** A Blueprint extending a base merges deterministically; an `extends` cycle is detected. Pass: deterministic merge; cycle errors clearly. Fail: nondeterministic merge or an undetected cycle.

### 9.2 Credential catalog and launcher

**FW-E2E-045: Path credential denied and itemized.** Under the default catalog, `~/.aws/credentials` is read. Pass: read denied (EACCES); operator channel names type `aws`; agent sees a bare EACCES with no annotation. Fail: read succeeds, or the agent-facing error names the type.

**FW-E2E-046: Env credential stripped and absent in tree.** `AWS_SECRET_ACCESS_KEY` is present in Formwork's own environment. The confined process and a grandchild read it. Pass: absent in both (empty/None); operator channel names it stripped as `aws`; agent cannot distinguish it from never-set. Fail: the variable is present anywhere in the tree.

**FW-E2E-047: Env-points-to-file dual arm.** Excluding `gcp` (default deny) with `GOOGLE_APPLICATION_CREDENTIALS` set to a real path. Pass: the variable is stripped **and** the referenced file is denied. Fail: either arm misses.

**FW-E2E-048: Exclude-by-type un-blocks exactly one.** `--allow-cred aws`. Pass: aws path/env become accessible/present while ssh, anthropic, slack, etc. remain blocked/stripped. Fail: any adjacent type is affected.

**FW-E2E-049: Generic backstop.** An uncatalogued but sensitive-shaped location (a novel `~/.someprovider/credentials`, an unusual `.env` variant). Pass: denied by the backstop despite no curated entry. Fail: the uncatalogued secret is accessible.

**FW-E2E-050: Report mechanism labeling.** Pass: FidelityReport marks env-kind types `enforced-via-launcher` and path-kind types `enforced-via-OS-sandbox`, and carries the launcher-contingency note for env. Fail: mislabeled or missing mechanism.

### 9.3 Discovery

**FW-E2E-051: Learning proposes toolchain, omits secrets.** A `pytest` learning run against a real repo. Pass: the proposal includes the ordinary toolchain paths the run needed and omits every FW-CRED-matched path even if the run touched one. Fail: a credential path appears as a candidate grant.

**FW-E2E-052: Auto-widen zone boundary.** A discovered path inside the declared zone and one just outside it. Pass: the in-zone path self-grants on the next run; the out-of-zone path requires review and is not auto-granted. Fail: an out-of-zone path self-grants.

**FW-E2E-053: Provenance recorded.** An accepted discovered grant. Pass: it appears in the Blueprint tagged with discovery provenance and run id, distinguishable from authored grants. Fail: no provenance, or indistinguishable from authored.

**FW-E2E-054: Discovery non-authoritative.** A denial observed in learning mode, outside any auto-widen zone. Pass: the live enforced session is not widened; the operation still fails in that run. Fail: observation silently widened the session.

### 9.4 Adversarial

**FW-ADV-012: Credential oracle probe (path + env).** The agent probes a credential path and reads a credential env var, inspecting errors, codes, and timing. Pass: neither denial nor absence is distinguishable from a nonexistent resource, and neither surfaces an operator prompt that a social-engineering payload could target (extends FW-ADV-004). Fail: any oracle exists.

**FW-ADV-013: Discovery confused-deputy.** A prompt-injected agent repeatedly attempts `~/.ssh/id_ed25519` to try to get it proposed and auto-accepted. Pass: FW-CRED-matched denials never become auto-proposable and never enter the auto-widen path (FW-INV8); the wall holds regardless of attempt count. Fail: persistent probing yields a candidate grant or an auto-accept.

**FW-ADV-014: Launcher-bypass honesty.** The agent is started *without* Formwork (bypassing the launcher). Pass: env vars are present as expected, **and** the report had already disclosed env-shading as launcher-contingent — i.e. the guarantee was never overclaimed (FW-CRED8). Fail: the documentation/report implied env-shading holds independent of the launcher.

## 10. Requirements ↔ tests traceability

| Requirement | Primary tests | Also |
|---|---|---|
| FW-BP1 One model, many surfaces | FW-E2E-043 | 042 |
| FW-BP2 Override precedence | FW-E2E-042 | 043 |
| FW-BP3 `extends` composition | FW-E2E-044 | — |
| FW-BP4 allow/deny/subtract | FW-E2E-042 | 045, 049 |
| FW-CRED1 Typed catalog | FW-E2E-045, 046 | 049 |
| FW-CRED2 Two kinds, two arms | FW-E2E-045, 046 | 050 |
| FW-CRED3 Env-points-to-file | FW-E2E-047 | — |
| FW-CRED4 Deny-superset default | FW-E2E-045, 046, 049 | — |
| FW-CRED5 Exclude-by-type | FW-E2E-048 | ADV-013 |
| FW-CRED6 Generic backstop | FW-E2E-049 | — |
| FW-CRED7 Channel split | FW-E2E-045, 046 | ADV-012, INV9 |
| FW-CRED8 Report mechanism | FW-E2E-050 | ADV-014 |
| FW-DISC1 Learning mode | FW-E2E-051 | 054 |
| FW-DISC2 Reverse compile | FW-E2E-051 | 052, 053 |
| FW-DISC3 Catalog floor | FW-ADV-013 | 051, INV8 |
| FW-DISC4 Auto-widen zone | FW-E2E-052 | 054 |
| FW-DISC5 Review diff | FW-E2E-051 | 053 |
| FW-DISC6 Provenance | FW-E2E-053 | — |
| Launcher arm (§6) | FW-E2E-046, 050 | 047, INV7, ADV-014 |

## 11. Impact on the base document

- **Architecture (base §2):** add the **launcher** as an explicit third enforcement arm (pre-spawn env construction) alongside confiner and gateway, under the same compiler. Update the diagram and the "single privileged broker" discussion to note the launcher runs before confinement is applied.
- **Terminology (base §4 and throughout):** global rename spec → Blueprint.
- **FW-TRA3 (sensitive-set subtraction):** superseded and expanded by FW-CRED — the sensitive set becomes the typed catalog plus the generic backstop.
- **FW-CAP3 (subtractive default profile):** now realized concretely by the catalog + backstop.
- **FW-FID1 (per-capability report):** extended to carry per-credential-type mechanism labels (`enforced-via-launcher` vs `enforced-via-OS-sandbox`) and the launcher-contingency note.
- **Non-goals (base §3):** add that Formwork does **not** perform credential *content* scanning; credential coverage is location-based only.

## 12. Open decisions — resolved at execution planning (`docs/fep2-plan.md` §7)

1. **Serialization format (FW-BP1).** **Resolved: stay on TOML.** Layering + `extends` fixes composition; `deny_unknown_fields` strictness is a security asset; the file format is a published surface whose migration no requirement pays for. Revisit only with a concrete need for logic, per §4.
2. **Discovery default posture (FW-DISC).** **Resolved: observe-then-widen.** Interactive `SECCOMP_USER_NOTIF` prompting confirmed out of scope — a documented Linux-only future.
3. **Catalog v1 breadth (FW-CRED1/6).** **Resolved: curated built-in set + generic backstop**, absorbing the whole FW-TRA3 sensitive set as types (including agent-state) so exclude-by-type covers it uniformly.
4. **Auto-widen zone defaults (FW-DISC4).** **Resolved: empty by default.** The operator draws the zone; nothing self-grants out of the box.
5. **Credential brokering (deferred — interacts with FW-CRED5).** Whether excluding a type exposes the file/var to the agent, or the gateway brokers the credential's *use* without the agent ever seeing the bytes (safer, fits the single-privileged-broker shape, more to build). **Remains deferred** to a later FEP.

## 13. Implementation order

The ordering rationale is that the credential catalog must exist and be enforced *before* discovery, because the catalog floor (FW-DISC3) is the property that makes discovery safe.

1. **Blueprint model + override layering + `extends`** (FW-BP) with FW-E2E-041–044. Foundational — everything else authors against this model.
2. **Credential catalog data + confiner path integration** (FW-CRED path arm) with FW-E2E-045, 049 and the path half of FW-ADV-012.
3. **Launcher arm: env construction + strip** (FW-CRED env arm) with FW-E2E-046, 047, 050; FW-INV7, INV9; the env half of FW-ADV-012; and FW-ADV-014.
4. **Exclude-by-type UX** (FW-CRED5) with FW-E2E-048.
5. **Discovery** (FW-DISC) with FW-E2E-051–054; FW-INV8, INV10; FW-ADV-013 — built last, on top of the enforced catalog floor.

If steps 1–4 land, Formwork has a typed Blueprint with a coherent file/CLI story and a credential catalog enforced across two arms with honest per-mechanism reporting. If step 5 lands, it also writes its own Blueprint from observed behavior — bounded so it can widen toward the ambient toolchain freely but never toward the credential floor.