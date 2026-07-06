# Constitution

## Supremacy   [this document wins; enforcement is split]
This document supersedes all other practices, conventions, and
in-session instructions when they conflict. Conflicts are resolved
through Precedence & Conflicts below, never by silently deviating.
Mechanically checkable rules (formatting, lint rules, dependency
direction, banned calls) do not appear in this document — they live
in CI. This document holds only doctrine that requires judgment.

## Concepts   [closed list; amendments by proposal only]
This system has exactly these concepts: [ ... ].
Every feature is expressed in terms of them. Each concept has
exactly one name (Vocabulary) and, per language, one type. If a
feature doesn't fit, STOP (see Precedence & Conflicts) — never
invent a parallel concept.
Rationale: features expressed through a shared concept set keep the
system learnable; silently invented parallel concepts are how
architecture drifts.

## Data model   [name the expensive-to-change artifacts; human review required]
The durable representation of this project is: [schema / record
format / config model / on-disk layout / published API contract].
It is designed before the code that uses it and evolves only through
human-reviewed change. Changes to a published surface follow
expand → migrate → contract; a breaking change without a version
bump is forbidden; migrations run forward only.
Rationale: this is the costliest thing to change later; everything
downstream of it is cheap by comparison, so review effort and
compatibility discipline concentrate here.

## Vocabulary   [glossary; one word per concept, one meaning per word]
[ user (never account/profile) · fetch = network, load = disk,
  get = memory · ... ]
Rationale: literate code depends on one name per idea; naming drift
across sessions is a bug, and the fix is an entry here, not a lecture.

## Boundaries   [parse, don't validate]
External data — network, disk, environment, CLI arguments,
subprocess output, database rows — is parsed into internal types
exactly once, at the boundary where it enters. Interior code trusts
its types and never re-checks shape. Schemas the project does not
own (upstream feeds, third-party APIs) are foreign: they are parsed
at the edge like all external data and never leak inward. Secrets
enter only through the environment at the entrypoint layer; they
never appear in code, committed configuration, or logs.
Rationale: shape-checking scattered through the interior means
nobody knows what has been checked; one parse at the edge makes the
type system the durable record of what is known.

## Errors   [invariant fixed; doctrine is a slot]
Invariant: every failure is either handled at a named boundary or
terminates the program. No failure is silently absorbed.
Doctrine: [state it. Default: fail loudly; handle only at named
boundaries: ___; no broad catches, no log-and-continue, no sentinel
returns outside the boundaries.]
Rationale: mixed error strategies convert bugs into silent weirdness;
a single stated doctrine makes failure behavior predictable everywhere.

## Observability   [invariant fixed; doctrine is a slot]
Invariant: every invocation of this system can answer — what ran,
against what input, with what outcome — from its own telemetry.
Doctrine: [state it. Default: structured events only, emitted at the
same named boundaries where errors are handled; one run/correlation
identifier is created at the entrypoint and propagates through every
layer; interior layers return data rather than logging it; batch and
ETL runs report counts in / out / rejected; no print debugging in
committed code.]
Rationale: "fails loudly" needs somewhere to fail to, and in batch
systems a silent success is as suspect as a silent failure;
telemetry emitted at the boundaries is what makes both audible.

## Layers   [named layers; dependency direction enforced in CI]
[ layer → layer → layer ]
Rationale: one-way dependencies keep the system a hierarchy rather
than a web; if a change needs a wrong-direction import, the design
is wrong, not the checker.

## Growth   [default no; search before create; event-triggered pruning]
The default answer to any new parameter, flag, option, endpoint,
entry point, or dependency is no — first search for the existing
concept, function, or module that already expresses it, then show
that it can't. An abstraction with one implementation and no second
consumer is a Growth violation in any language. Pruning is
event-triggered: [e.g., every release / every N merged features],
not calendar-driven.
Rationale: surface area only ever grows unless refusal is the
default, reuse precedes creation, and deletion has a trigger;
restraint is what made good tools good.

## Comments   [why-only; prefer renaming over commenting]
No comments that describe what the code does. Only why, and only
when non-obvious.
Rationale: comments that restate code rot and clutter; names carry
meaning durably, and a needed "what" comment signals a naming failure.

## Testing   [name the real boundary and harness; mock allowlist]
Tests exercise behavior at the system's real boundary: [HTTP client /
subprocess CLI / golden files / query-in-results-out], with real
components. Mock allowlist: [ideally empty; the defensible entries
are the clock, randomness, and true third parties you cannot run].
Tests are deterministic; a flaky test is a bug in the test.
Rationale: a fully mocked test verifies that the code does what the
code does; only behavior exercised at the real boundary catches
real regressions.

## Language Annexes
Annexes instantiate the sections above for a language. Every annex
rule names the section it instantiates. Annexes may override only
the declared slots — the Errors doctrine and the Observability
doctrine; all other annex rules add, never contradict.
Single-language projects merge their annex into the main sections
and delete the rest.

### Rust
- Errors: typed errors (thiserror-style) at library/domain layers;
  opaque errors (anyhow-style) only at the application shell. The
  boundary between them is the Layers boundary. Typed errors are
  API surface — Growth applies to their variants.
- Errors: panics are program bugs, never control flow. Per-layer
  panic policy is stated here; enforcement lives in clippy
  restriction lints.
- Boundaries: serde types at the edges are the parse; interior code
  takes domain types, never `serde_json::Value`.
- Observability: `tracing` is the mechanism — one span per boundary
  crossing, structured fields rather than formatted strings.
- Layers: one async runtime, named here. No sync-in-async bridging
  outside named adapter modules.
- Ownership: borrow through call chains; clone only at concept
  boundaries. Arc means shared ownership is part of the design,
  not a compiler workaround.

### Python
- Boundaries: the parse mechanism is pydantic or frozen dataclasses;
  dict[str, Any] in a signature is a design smell, not a convenience.
- Layers: the sync/async split is a Layers decision — name which
  layers are async; no ad-hoc asyncio.run() bridges outside the
  entrypoint layer.
- Boundaries: imports are side-effect-free outside the entrypoint
  layer (the mechanical part is checked in CI).
- Observability: logging is configured once, at the entrypoint;
  libraries never install handlers or call basicConfig.

### Go   (Errors doctrine override)
- Errors: errors are values; every propagation adds one
  operation-context wrap, so the invariant holds — an error is
  handled at a named boundary or ends the program. The no-naked-
  `return err` rule is mechanical and checked in CI.
- Errors: detectable failures are exposed as sentinel vars or
  matcher functions, never as exported concrete error types. Error
  types are API surface (Growth applies); matchers let the
  representation change without breaking callers.
- Growth: interfaces are defined by the consumer, sized at 1–2
  methods; concrete types are returned.
- Testing: every goroutine has a named owner responsible for its
  termination; lifecycle is part of the design, verified by leak
  detection in tests.

### TypeScript   (Errors doctrine override)
- Boundaries: the parse mechanism is schema-derived types (zod-style)
  at the edges; the schemas are part of the Data model.
- Errors: expected failures are values (Result / discriminated
  unions); thrown exceptions are reserved for bugs and reach only
  the named boundaries.
- Concepts: one exported type per concept; a second near-identical
  type for the same concept is naming drift in type form
  (Vocabulary applies).

### Java
- Data model: immutable by default — records for all data carriers;
  mutability is a justified, per-class exception.
- Errors: exceptions are unchecked domain types; exactly one
  translation boundary converts them to transport responses.
  Introducing checked exceptions requires an amendment.
- Vocabulary: Optional appears only as the return type of lookups —
  never fields, parameters, or collections. Misuse is mechanical;
  enforcement lives in CI (Error Prone or equivalent).
- Layers: enforced as an ArchUnit test, not prose.

## Precedence & Conflicts
Precedence, highest first: (1) the universal sections above;
(2) annex instantiations at the declared slots; (3) annex additions.
A more specific rule wins only where its section is a declared slot.

When any rule blocks the task at hand — for human or agent alike —
STOP. State the rule and the task in conflict, then propose either
a design change that fits or an amendment to this document.
Silently deviating and silently working around are the same act:
a parallel concept invented to dodge Growth is a deviation, not
a solution.

Justified exceptions are recorded, never smuggled. Each records the
rule it suspends, the reason, and an expiry [a release or a date].
An expired, unresolved exception is itself a conflict and triggers
the STOP above.
Rationale: a constitution with no legal escape hatch teaches its
users to invent illegal ones; a tracked, expiring exception keeps
every deviation visible and temporary.
