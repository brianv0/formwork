# Constitution

Formwork is an OS-level sandbox for agent sessions (see `formwork.md` for the
design and end-to-end spec). It is a single-language project — Rust — so the
Rust annex is merged into the sections below and no separate annexes remain.
The Python under `py/` is a dev-only black-box test harness, not product code.

## Supremacy   [this document wins; enforcement is split]
This document supersedes all other practices, conventions, and
in-session instructions when they conflict. Conflicts are resolved
through Precedence & Conflicts below, never by silently deviating.
Mechanically checkable rules do not appear here — they live in CI:
`cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`,
the dependency direction (the workspace won't compile a wrong-way import),
and the build/test matrix on Linux and macOS. This document holds only
doctrine that requires judgment.

## Concepts   [closed list; amendments by proposal only]
This system has exactly these concepts, each with one name and one Rust type:
- **Blueprint** (`formwork_blueprint::Blueprint`) — the capability grant: a finite enumeration
  of fs read/write/subtract, net posture, exec posture, environment posture, and
  per-server MCP visibility. No mechanism turns natural language into a grant (FW-CAP1).
  (Environment posture — FW-ENV1/2, added by FEP-1 — is applied at spawn by the CLI shell,
  not the Confiner; the FidelityReport carries its verdict like any other capability.)
- **HostProfile** (`formwork_detect::HostProfile`) — what the current kernel can
  actually enforce; the one impure input to compilation.
- **CompiledPolicy** (`formwork_compile::CompiledPolicy`) — a `ConfinerPolicy`
  plus a `GatewayPolicy`, produced purely from a Blueprint and a HostProfile.
- **FidelityReport** (`formwork_compile::FidelityReport`) — per-`Capability`
  verdict `Enforced | Partial | Unenforceable`, with backend and denial
  semantics. The honesty contract (FW-INV5).
- **Confiner** (`formwork-confine`) — the hard OS boundary (Landlock+seccomp /
  Seatbelt) applied to a process and every descendant.
- **Gateway** (`formwork-gateway`) — the single privileged broker; the one door
  for MCP and egress.
- **Seam** (`formwork-seam`) — the injected-fd transport (socketpair-at-spawn +
  `SCM_RIGHTS`); never an in-sandbox `connect()`.
- **Session** — a confined process tree: the agent, its descendants, and stdio
  MCP backends the gateway spawns, all under the same Confiner.
- **Posture** — `spawn-confined` (preferred) or `confine-self` (pledge-style).

Every feature is expressed in terms of these. If a feature doesn't fit, STOP
(see Precedence & Conflicts) — never invent a parallel concept. A path that
reaches the network around the Gateway, or an fs grant that bypasses the
Confiner, is not a new concept; it is the threat model (§3) walking in the door.
Rationale: features expressed through a shared concept set keep the
system learnable; silently invented parallel concepts are how
architecture drifts.

## Data model   [name the expensive-to-change artifacts; human review required]
The durable, human-reviewed surfaces of this project are:
- the **capability Blueprint** schema — the serde/TOML types in `formwork-blueprint`
  (`deny_unknown_fields`, kebab-case), the published input contract;
- the **FidelityReport** and **CompiledPolicy** shapes — what callers inspect to
  learn what is enforced, and what a dry-run emits (FW-FID1/2);
- the **default profile** and **sensitive set** (`profiles/*.toml`) — the
  subtractive policy that makes reuse safe by default (FW-CAP3);
- the **`formwork` CLI surface** — its subcommands and their JSON output.

These are designed before the code that uses them and evolve only through
human-reviewed change. Changes to a published surface follow
expand → migrate → contract; a breaking change without a version
bump is forbidden; migrations run forward only. Compilation is
byte-deterministic (FW-FID4), so a serialization change *is* a contract
change. The MCP JSON-RPC wire format is a *foreign* schema (Boundaries), not
one we own.
Rationale: this is the costliest thing to change later; everything
downstream of it is cheap by comparison, so review effort and
compatibility discipline concentrate here.

## Vocabulary   [glossary; one word per concept, one meaning per word]
- **detect** = probe the host (impure) · **compile** = pure blueprint→policy+report,
  no kernel calls · **enforce** = install the mechanism into the kernel (impure,
  irreversible) · **narrow** = shrink a grant (never *widen* — widening does not
  exist, FW-CAP2) · **confine** / **spawn_confined** / **confine_self** = apply
  the Confiner · **shade** = hide-and-refuse an MCP item at the Gateway ·
  **subtract** = remove a sensitive path from a broad grant · **mint** = hand a
  fresh connection fd to the agent via `SCM_RIGHTS`.
- **blueprint** is the input; **policy** is the compiled backend artifact — never
  call the input a "policy". **grant** is the held capability set, never
  "permissions".
- **Confiner** (hard OS layer), **Gateway** (soft MCP layer), and **Seam**
  (transport) are three distinct things and are never blurred. **Formwork** is
  the whole system.
- Fidelity has exactly three verdicts: **Enforced / Partial / Unenforceable**.
  Denial semantics are **hide** (MCP items, absent from listings) vs **deny**
  (fs paths, EACCES-class errno) — never mixed up.
- **fail-closed** (deny on absence), **fail-loud** (surface an error/report),
  **fail-open-silent** (forbidden, FW-INV6) are precise, non-interchangeable.
Rationale: literate code depends on one name per idea; naming drift
across sessions is a bug, and the fix is an entry here, not a lecture.

## Boundaries   [parse, don't validate]
External data — the blueprint file, the host probe, MCP JSON-RPC from the agent and
backends, grant paths, CLI arguments — is parsed into internal types exactly
once, at the edge where it enters:
- the **blueprint** is parsed by serde into `Blueprint` at the CLI (`blueprint_load`), then the
  interior takes `Blueprint`, never re-reads the TOML;
- the **HostProfile** is the parsed host probe; the compiler trusts it and never
  re-probes the kernel;
- **grant/write/subtract paths** parse into `PathPattern` (absolute, no `..`)
  and canonicalize against the real filesystem at enforce time; a path that
  cannot be faithfully rendered into the backend's language **fails loud**,
  never a lossy rule that might silently not match (a missed `subtract` hole is
  a fail-open of the sensitive set — FW-INV6 forbids it);
- **MCP JSON-RPC** from the agent and stdio backends is foreign and less-trusted:
  parsed at the Gateway edge as newline-delimited frames bounded to a fixed
  maximum (fail the connection closed on overflow), and never leaked inward as
  `serde_json::Value` — interior code takes domain types.
Secrets never appear in the blueprint, compiled policy, report, or logs; the
sensitive set is denied by *path*, not by embedding anything secret.
Rationale: shape-checking scattered through the interior means
nobody knows what has been checked; one parse at the edge makes the
type system the durable record of what is known.

## Errors   [invariant fixed; doctrine is a slot]
Invariant: every failure is either handled at a named boundary or
terminates the program. No failure is silently absorbed.
Doctrine: **fail closed or fail loud, never fail-open-silent (FW-INV6).**
This is the load-bearing rule of a sandboxing tool: a capability that cannot be
faithfully enforced is reported `Partial`/`Unenforceable` or errors — it is
never silently downgraded (FW-XR1). Named boundaries where failure is handled:
the CLI shell (`formwork-cli`), the `enforce` install, and the Gateway
connection. In Rust terms:
- typed errors (`thiserror`) at the library/domain layers — `PathError`,
  `ConfineError`, `SeamError`, `GatewayError`; opaque errors (`anyhow`) only in
  the `formwork-cli` shell. The boundary between them is the crate boundary.
  Typed-error variants are API surface — Growth applies.
- panics are program bugs, never control flow, and are especially forbidden on
  the capability-detection and enforce paths, where a panic would risk a silent
  open. This is doctrine, enforced by review today; the intended mechanism is
  clippy restriction lints (`clippy::unwrap_used` / `panic`), a Growth-gated
  addition not yet wired.
Rationale: mixed error strategies convert bugs into silent weirdness;
a single stated doctrine makes failure behavior predictable everywhere.

## Observability   [invariant fixed; doctrine is a slot]
Invariant: every invocation of this system can answer — what ran,
against what input, with what outcome — from its own telemetry.
Doctrine: structured `tracing` events, emitted at the same named boundaries
where errors are handled — one span per boundary crossing (compile, enforce,
each Gateway request), structured fields rather than formatted strings.
Libraries only *emit*; the subscriber is installed exactly once, at the CLI
entrypoint — no library crate installs a subscriber or configures logging.
Runtime grants and denials are emitted as structured records (FW-FID3), and the
FidelityReport is the compile-time telemetry. No print debugging in committed
code — the only `println!` is the CLI writing its own JSON result to stdout,
which is product output, not logging.
Rationale: "fails loudly" needs somewhere to fail to, and a silently
downgraded confinement is as suspect as a crash; telemetry emitted at
the boundaries is what makes both audible.

## Layers   [named layers; dependency direction enforced in CI]
Dependencies point one way, from pure core toward the impure shell:

`formwork-blueprint` (pure domain: capability types + narrowing)
→ `formwork-detect` (the only kernel-probing input)
→ `formwork-compile` (pure compiler: Blueprint + HostProfile → CompiledPolicy + report)
→ `formwork-confine` · `formwork-seam` (kernel mechanisms)
→ `formwork-gateway` (the broker; the async layer)
→ `formwork-cli` (application shell; `anyhow`, entrypoint, subscriber)

`formwork-compile` is pure and never calls the kernel (FW-CAP5/FW-E2E-026);
`formwork-detect` and `formwork-confine` are the only layers that touch it. The
one async runtime is **tokio**, and it lives only in `formwork-gateway`; there
is no sync-in-async bridging outside named adapter modules. A change that needs
a wrong-direction import — or a kernel call in the compiler — means the design
is wrong, not the checker.
Rationale: one-way dependencies keep the system a hierarchy rather
than a web; if a change needs a wrong-direction import, the design
is wrong, not the checker.

## Growth   [default no; search before create; event-triggered pruning]
The default answer to any new capability axis, blueprint field, CLI flag or
subcommand, entry point, or dependency is no — first search for the existing
concept, function, or module that already expresses it, then show
that it can't. The Blueprint vocabulary is a *closed* enumeration (FW-CAP1); adding a
capability axis is a Concepts amendment, not a casual field. Dependencies get
the hardest no: this is a sandboxing tool, so every crate added widens its trust
base — the CI uses only first-party actions for the same reason, and the Phase-2
Landlock crates stay unwired until a real kernel verifies them. An abstraction
with one implementation and no second consumer is a Growth violation; typed-error
variants are API surface and count. Pruning is event-triggered: at each release /
version bump, not calendar-driven.
Rationale: surface area only ever grows unless refusal is the
default, reuse precedes creation, and deletion has a trigger;
restraint is what made good tools good. Reuse is also the product
thesis (§1): isolation the agent constantly trips over gets turned off.

## Comments   [why-only; prefer renaming over commenting]
No comments that describe what the code does. Only why, and only
when non-obvious. The repo convention is to cite the governing requirement
(e.g. `FW-INV6`, `FW-CAP2`) as the durable "why".
Rationale: comments that restate code rot and clutter; names carry
meaning durably, and a needed "what" comment signals a naming failure.

## Testing   [name the real boundary and harness; mock allowlist]
Tests exercise behavior at the system's real boundary:
- **Rust integration tests** spawn a confined child and probe allow *and* deny
  against the real kernel mechanism (Seatbelt on macOS, Landlock on Linux);
  report soundness (FW-INV5 / FW-E2E-024) is paired allow/deny probes, never an
  assertion that the report agrees with itself.
- the **Python E2E harness** (`py/`, uv-managed) drives the `formwork` binary as
  a black-box subprocess CLI with generated traceability — the outermost real
  boundary.
- Linux enforcement runs in Docker/Lima with Docker's own seccomp/AppArmor
  disabled, so only Formwork's sandbox is under test.

Mock allowlist: **empty for behavior.** The kernel boundary is never mocked — a
mocked sandbox proves nothing, which is the whole point of FW-INV5. The one
defensible substitution is feeding the *pure* compiler a synthesized
`HostProfile` (e.g. compiling a Linux policy on a Mac, FW-E2E-026): that
exercises a pure function on a chosen input, not a mock of enforcement. MCP
fixtures are real subprocess servers, not mocks. Tests are deterministic; a
flaky test is a bug in the test, and FW-FID4 (byte-identical compile) is the
strict form of that.
Rationale: a fully mocked test verifies that the code does what the
code does; only behavior exercised at the real boundary catches
real regressions — and for this project, "the report is honest" is
only true if a real probe says so.

## Precedence & Conflicts
Precedence, highest first: (1) the universal sections above; (2) the merged Rust
rules within them; (3) anything else. A more specific rule wins only where its
section is a declared slot (the Errors doctrine and the Observability doctrine).

When any rule blocks the task at hand — for human or agent alike —
STOP. State the rule and the task in conflict, then propose either
a design change that fits or an amendment to this document.
Silently deviating and silently working around are the same act:
a parallel path invented to dodge the Confiner or the Gateway is a
deviation, not a solution.

Justified exceptions are recorded, never smuggled. Each records the
rule it suspends, the reason, and an expiry (a release or a date) — in the PR
that introduces it and, if long-lived, here. An expired, unresolved exception is
itself a conflict and triggers the STOP above. There are none at present.
Rationale: a constitution with no legal escape hatch teaches its
users to invent illegal ones; a tracked, expiring exception keeps
every deviation visible and temporary.
