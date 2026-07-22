# Unstated requirements

Requirements this project has been operating under that are written nowhere — teased out of the
usability review, its implementation, and the constitution pass. Each entry states the norm, the
evidence it was already binding (something was judged right or wrong by it), where it lives now,
and whether it deserves minting as a real `FW-*` requirement.

**Status: minted (human-approved).** The recommendations below were reviewed and applied: items 1,
5, 6, and 11 are now [FW-XR9](../formwork.md#fw-xr9), [FW-FID7](../formwork.md#fw-fid7),
[FW-BP8](../formwork.md#fw-bp8) (with [FW-E2E-070](../formwork.md#fw-e2e-070)), and
[FW-DISC11](../formwork.md#fw-disc11); items 2, 3, 4, 7, and 9 landed as the marked constitution
amendments (Errors doctrine, Requirements & identifiers, Testing, Growth, Precedence & Conflicts —
with the deprecations register in [`STATUS.md`](STATUS.md)); item 8 was already doctrine. Items 10
(CI-matrix rule — mint when release automation is next touched) and 12 (exit-code contract — mint
when an embedder needs it) remain deliberately unminted, per their own entries. The per-item prose
below is kept as the design record.

## 1. Surface parity: a subcommand that cannot deliver on a platform refuses before consuming work

The spec has behavioral parity for *enforcement* ([FW-XR6](../formwork.md#fw-xr6)) — same
blueprint, same observable outcomes. But nothing said the *command surface* must be
parity-honest: `learn` on Linux ran the entire enforced workload and only afterwards announced
that observation was impossible. That was judged a defect instantly ("we shouldn't have one
thing that works really well on macos that doesn't even work on linux"), which means the norm
was already binding. [FW-E2E-062](../formwork.md#fw-e2e-062) now pins the `learn` instance, but
the general rule is unstated:

> A subcommand that cannot deliver its promise on the current host fails before consuming the
> user's work (their run, their time), naming the reason and the nearest alternative.

**Mint?** Yes — this is the surface-level sibling of [FW-INV5](../formwork.md#fw-inv5)/[FW-INV6](../formwork.md#fw-inv6)
and generalizes beyond `learn` (a future `probe`, a future violation stream). Candidate: an XR
requirement, since it is cross-cutting.

## 2. Docs are a claims surface, and honesty is bidirectional

The README calling the implemented Linux confiner an "honest stub" was treated as a bug of the
same *kind* as overclaiming — under-claiming misleads a different audience into a different wrong
decision (not adopting). The honesty invariants only forbid claiming more than is enforced;
nothing forbids claiming less, and nothing drift-checks prose against code. The repo already has
the pattern to fix this: canaries (`test_requirements.py`, `profiles.rs`) that fail CI when a
document and reality diverge.

**Mint?** The principle belongs in the constitution's honesty doctrine more than in an FW ID. A
cheap mechanical start: a canary asserting the README support-matrix rows against `detect`-able
facts and the test suite's platform markers.

## 3. Audience separation of documents (stated nowhere, now load-bearing)

"Requirements shouldn't leak into the README — important for contributors... not so important
for users" established a document hierarchy the repo never wrote down:

| Layer | Audience | Vocabulary |
|---|---|---|
| `README.md` | users deciding/starting | plain claims, no FW-* IDs |
| `examples/` | operators integrating | recipes, rule vocabulary |
| `formwork.md`, `constitution.md`, `docs/STATUS.md` | contributors | requirement IDs, phases |
| `docs/fep-*.md`, plans | historical/design record | draft numbering, amendments |

One rule follows that nearly got broken this session: **a document may only cite vocabulary from
its own layer or below** — the constitution pointed at the README for the ID convention, which
became false the moment the README was made user-facing (fixed alongside this document).

**Mint?** Constitution amendment (a sentence in the Requirements-&-identifiers or a new Docs
slot), not an FW ID.

## 4. The canonical user journey is the shortest one, and tests must walk it

`learn` was tested with workloads long enough for the log store to flush; the *actual* first-run
shape is a process that dies on its first denial in under a second — "which is exactly how
long-lived many processes are when they try to access files they cannot access." The unstated
testing norm:

> For any observe/collect feature, the primary test case is the fastest-failing workload, not a
> comfortable one. If a mechanism has a latency window, the test must fit inside it.

[FW-E2E-064](../formwork.md#fw-e2e-064) pins the `learn` instance. The general norm belongs in
the constitution's Testing section ("tests exercise behavior at the real boundary" — add: *in
the least convenient realistic shape*).

## 5. Anything auto-chosen is announced, everywhere the choice has effect

`FORMWORK.toml` discovery was accepted only with the condition "we'd need to make sure
compile/etc are transparent about that." The implemented rule — resolved input named in logs
*and* stamped into every output that depends on it — is a general principle the spec doesn't
state: [FW-FID6](../formwork.md#fw-fid6) explains *rules*, nothing requires disclosing *resolved
inputs* (which blueprint file, which discovered layer, which builtin profile).

**Mint?** Yes — FID family: "every artifact a command emits names the inputs it was resolved
from and how each was chosen (flag, discovery, builtin)." The `blueprint: {path, source}`
envelope is the first instance; a future `--host h.json` disclosure would be the second.

## 6. Configuration discovery must not cross trust boundaries

The discovery walk stops at `$HOME` and never consults `/` for a nested cwd. That was a security
judgment, not a convenience: a world-writable or root-owned `FORMWORK.toml` silently governing
every launch is a confused-deputy shape, the same family as [FW-XR8](../formwork.md#fw-xr8)
(policy inputs write-protected in-session). Currently it lives only in a code comment and a unit
test.

**Mint?** Yes — BP family: "implicit blueprint resolution searches only paths the invoking user
controls; the search scope is fixed and documented." Without an ID, a future "also check
/etc/formwork/" patch has nothing to argue against.

## 7. A release binary is self-contained

`extends = ["profiles/default.toml"]` silently assumed a repo checkout, though the README's own
install path is a tarball. `builtin:default` fixed the instance; the norm is unstated:

> Every documented feature must work from the shipped binary alone. A feature that needs the
> repo present is a dev tool and must be documented as one.

**Mint?** Probably a constitution Growth/Data-model sentence rather than an ID — it constrains
what `profiles/` may be used for (source of embedded artifacts, not a runtime dependency).

## 8. Results and telemetry are different channels, and results never degrade

The `accept` listing vanishing under `RUST_LOG=warn` was a bug even though every byte was
"visible" by default. The rule — now in the amended Observability doctrine and pinned by
[FW-E2E-063](../formwork.md#fw-e2e-063) — was operating unstated since the first `after_help`
text promised "stdout stays a clean result stream." Consequence worth keeping explicit: **the
result stream is append-only across a subcommand's lifetime** — a mode that sometimes prints its
result to stderr is a regression even if tests still pass.

**Mint?** Done (doctrine amendment). Listed here because it was unstated for the whole prior
life of the project.

## 9. Deprecations carry an expiry event, like exceptions do

The hidden aliases (`detect`, `enforce-self`, `accept`) and the `--spec` flag are compat shims
described as "for one release" — but nothing tracks that. The constitution already has the
machinery: exceptions "record the rule suspended, the reason, and an expiry," and pruning is
event-triggered at release. Compat shims are exceptions to the 5-subcommand surface and should
ride the same rail; otherwise hidden surface accretes invisibly (the exact failure mode the
Growth section exists to stop).

**Mint?** Constitution: one sentence extending the exceptions rule to deprecated surface.
Mechanically: a `docs/STATUS.md` deprecations table with the removal event, checked at release.

## 10. Verification claims state where they ran; cross-platform features get cross-platform execution

"Include new tests across both systems **and run them**" made explicit a norm the project's
honesty rules imply but never apply to the development process itself: a test that exists but
has never executed on its target platform is a claim, not a verification. The current honest
answer — Linux-side executed here, macOS-side type-checked (`cargo check --target
aarch64-apple-darwin`) but runtime-verified only on a real Mac — is exactly the
`Enforced/Partial/Unenforceable` trichotomy applied to test evidence.

**Mint?** CI-matrix requirement rather than prose: `learn`-family tests (FW-E2E-051..054,
062..064) must have an executing macOS job and an executing Linux job before a release tag; a
platform-marked test that has never run on its platform is reported, not assumed.

## 11. Learning-loop ergonomics: the artifact conventions are implementation detail

"Accept seems like it could just be part of learn" generalized to: the user drives the whole
observe → list → accept → next-run loop from one command's `--help`, and never needs to know
that `<blueprint>.proposal.toml` / `.discovered.toml` exist or where they live (they surface in
*output* as provenance, not as required *input* knowledge). Derived-path flags (`--proposal`)
are escape hatches, not the paved road.

**Mint?** DISC family candidate, one sentence: "the discovery loop is drivable end-to-end
without naming its artifact files."

## 12. Exit codes: the workload's status is the contract, machinery failures must be distinguishable

`learn` (and `run`) exit with the confined workload's status — right, because wrappers must be
transparent to scripts. But a `learn` whose *collection* failed also exits nonzero in ways a
script cannot tell apart from the workload failing. Unstated contract, currently only
half-true:

> Wrapper subcommands are exit-code transparent for the workload; Formwork's own failures are
> distinguishable from the workload's.

**Mint?** Worth an ID only when an embedder needs it; until then, note it as a known gap —
pretending the contract exists already would violate item 2.

---

Recommended next actions, smallest first: the constitution sentences (items 3, 7, 9), the FID
disclosure requirement (item 5), the BP trust-scope requirement (item 6), the XR fail-fast
generalization (item 1), then the CI-matrix rule (item 10) when release automation is next
touched. Each is a human-reviewed mint per the constitution; this document is input to that
review, not a substitute for it.
