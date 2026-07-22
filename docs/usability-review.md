# Usability review: CLI surface, parity, defaults, docs

> **Status:** implemented — P1, P2, P4, P5–P12 landed with the original branch, and P3 landed
> afterwards via a different mechanism than proposed: a ptrace feed (an unconfined `strace`
> tracing the confined run, [`FW-E2E-071`](../formwork.md#fw-e2e-071)) rather than Landlock
> audit, which needs kernel 6.15+ and remains a future alternative tap. Only P4b (the
> sentinel-bracketed `log stream` variant of the macOS feed) remains future work.

An evaluation of the current `formwork` CLI against seven usability criteria — platform
parity, honest promises, CLI simplicity, documentation, examples, explainability, and good
defaults — with concrete proposals. File/line references are to the tree at the time of
review.

## 1. The parity matrix (criteria 1 & 2)

What each subcommand actually delivers per platform today:

| Command | macOS | Linux | Verdict |
|---|---|---|---|
| `detect` | ✓ | ✓ | parity |
| `compile` / `explain` | ✓ (pure) | ✓ (pure) | parity |
| `run` / `enforce-self` | ✓ Seatbelt | ✓ Landlock+seccomp (5.13+; degraded-host honesty below) | parity — **but the README still says the Linux confiner is a stub** |
| `gateway` | ✓ | ✓ | parity |
| `learn` | partial (misses short-lived workloads, see §2) | **✗ no denial feed at all** | the biggest parity break in the product |
| `accept` | ✓ | ✓ (but only useful where `learn` works) | inherits `learn`'s break |

Two honesty problems fall out of this:

**The README under-reports Linux.** The status table (`README.md`, "Phase 2 … honest stub")
predates the Landlock+seccomp backend, which is now real
(`crates/formwork-confine/src/linux/landlock.rs`, `seccomp.rs`, plus hardening commits for
symlink escape, `/proc/self`, UDP). Under-promising is still misreporting: a Linux user
reading the README today would conclude `formwork run` doesn't work for them.

**`learn` over-promises on Linux.** `formwork learn` on Linux runs the entire enforced
workload and only *afterwards* warns that no proposal can be written
(`crates/formwork-cli/src/main.rs:520-536` — the warn sits after `spawn_confined_child`).
By criterion 2 this is exactly the shape to avoid: a subcommand that appears to work
identically on both OSes but silently delivers nothing on one.

### Proposals

- **P1 — Fix the README status table** (trivial, do first). State what is true: Linux
  enforcement is implemented and tested in Docker/Lima; `learn` is macOS-only.
- **P2 — `learn` on Linux fails fast.** Move the "no denial feed" check *before* spawning
  the workload and make it an error (`bail!`) naming the reason and the alternative
  (`run` + hand-authoring, or macOS). An `--observe-anyway` escape hatch can keep the
  current run-enforced-anyway behavior for anyone who wants it. Running a whole workload
  and then announcing the observation half was impossible wastes the user's time.
- **P3 (longer-term) — a Linux denial feed.** Landlock audit (kernel 6.15+) is the
  principled source; until wired, P2's fail-fast keeps the promise honest. When it lands,
  `detect` should report `denial-feed: true/false` per host so `learn`'s availability is
  itself detectable, not folklore.

## 2. `learn` misses short-lived workloads on macOS (bug)

The denial feed is collected post-hoc: `log show --last {elapsed+4}s`
(`crates/formwork-cli/src/main.rs:523`, `crates/formwork-cli/src/learn.rs:83-115`). Two
problems:

1. **Unified-log persistence latency routinely exceeds 4 s.** `log show` reads the
   *persisted* store; under low logging pressure a process's buffered records can take
   tens of seconds to flush. A workload that dies in under a second — `cat ~/.ssh/id_rsa`
   erroring out on its first denied read, which is exactly the canonical discovery case —
   produces denials that are not yet in the store when we query. Result: "learning run
   complete, 0 candidates" for precisely the runs learning exists for.
2. **`--last Ns` is the wrong anchor.** It is relative to *collection* time, so a slow
   collection can sweep in unrelated pre-run denials, and the window drifts with wall
   clock rather than bracketing the run.

### Proposal

- **P4 — anchor on `--start` and poll to quiescence.** Record the wall-clock start
  timestamp before spawn; collect with `log show --start <ts>`; then re-collect on an
  interval (e.g. every 2 s, up to a ~30 s cap) until two consecutive collections return
  the same record set. Over-capture is already safe by design (candidates are inert until
  accepted, credentials are floored regardless), so the cap can be generous.
- **P4b (stronger, optional) — sentinel-bracketed `log stream`.** Start
  `log stream --style ndjson --predicate 'sender == "Sandbox"'` *before* spawning; close
  the documented stream-startup race by triggering a known, harmless denial from a probe
  and waiting until it appears in the stream before starting the workload; after the
  workload exits, trigger a closing sentinel and read until it appears. Deterministic for
  arbitrarily short workloads, no fixed timeouts. P4 is the cheap fix; P4b is the correct
  one if P4's polling proves flaky.

## 3. CLI surface: 8 subcommands → 5 (criterion 3)

Current: `detect`, `compile`, `run`, `enforce-self`, `learn`, `accept`, `gateway`,
`explain`. Proposed visible surface:

```
formwork run      [--blueprint …] -- cmd …     # enforce (spawn-confined; --confine-self for the exec posture)
formwork learn    [--blueprint …] -- cmd …     # observe-then-widen; also reviews/accepts (§3.3)
formwork explain  [--blueprint …] [PATH …]     # human observability: host, merged policy, per-path verdicts
formwork compile  [--blueprint …] …            # machine observability: policy + fidelity report as JSON
formwork gateway  [--blueprint …] --server …   # MCP shading
```

### 3.1 `detect`

Keep the capability, move the surface. `detect` is load-bearing for scripts (the justfile
and the Docker/Lima harness gate test tiers on it) and for the capture-and-ship
`detect > host.json` → `compile --host` flow, so it cannot simply become help text. But as
a *top-level human door* it earns little.

- **P5 —** `formwork --help` gains a computed one-liner in the epilogue (probing is two
  cheap syscalls): e.g. `This host: macOS 15 (Seatbelt) — full enforcement` /
  `Linux 6.12 (Landlock v6 + seccomp)` / `Linux 5.10 — no Landlock; fs enforcement
  unavailable, compile/dry-run only`. That answers "will this work here?" at the first
  place a new user looks.
- `formwork explain` with no PATH argument prints the same host summary plus the merged
  blueprint's fidelity summary in human-readable form (see §3.4).
- `detect` stays for JSON output, but hidden from the main help listing (clap
  `hide = true`) or documented under "plumbing". No break for scripts.

### 3.2 `enforce-self`

Agreed it isn't pulling its weight as a top-level command. The *posture* is genuinely
useful (PID-preserving exec-replace for embedders and wrapper scripts) and the library API
(`formwork_confine::enforce_self`) must stay. But two top-level commands with identical
arguments differing only in fork-vs-exec is surface bloat.

- **P6 —** fold into `run --confine-self` (default remains spawn-confined, the preferred
  posture per the design). Keep `enforce-self` as a hidden alias for one release. The
  E2E tests that exercise the posture keep working via the flag.

### 3.3 `accept` folds into `learn`

`accept` is the review half of the learn loop and its `--proposal` argument is already
derivable (`<blueprint>.proposal.toml`, `learn.rs:47`). Two commands for one loop means
the user must learn the artifact-file convention just to continue what `learn` started.

- **P7 —**
  - `formwork learn --blueprint b.toml -- cmd …` — observe (unchanged).
  - `formwork learn --blueprint b.toml --list` — list pending candidates by number.
  - `formwork learn --blueprint b.toml --accept 1 --accept '~/foo/**'` / `--accept-all`
    — accept into the discovered layer (same floor re-check, FW-INV8).
  - `--proposal` stays as an escape hatch for a proposal that moved.
  - `accept` remains a hidden alias for a release.
  - The trailing `-- cmd` and the review flags are mutually exclusive; clap can enforce
    that.

### 3.4 `explain` vs `compile`

They overlap because both are observability, but they serve different readers. Rather than
merging, differentiate them honestly and cross-reference in help:

- **P8 —**
  - `compile` = **machine** door: JSON policy + fidelity report, stable shape, for CI and
    diffing. Unchanged, plus it must state the resolved blueprint path in its output
    (needed for P10's transparency).
  - `explain` = **human** door: default output becomes human-readable text (`--json` opt-in
    for the current shape). No PATH → host capabilities + merged-policy / fidelity summary
    (which also absorbs `detect`'s human use, §3.1). One or more PATHs → per-path
    read/write/exec verdicts with the deciding rule and layer, as today. This gives one
    "why/what" command for humans and one for machines — a clean two-door story instead of
    two half-overlapping ones.

### 3.5 Result-stream consistency (explainability)

The stated contract is "stdout is a clean result stream; telemetry goes to stderr"
(`main.rs:41-44`). `accept` with no selection violates it: the candidate listing — the
command's *result* — is emitted via `tracing::info!` to stderr (`learn.rs:297-317`), so
`RUST_LOG=warn` makes the listing vanish entirely.

- **P9 —** candidate listings (and `learn`'s final "proposal written to <path>" pointer)
  print to stdout as results; telemetry stays on stderr. Fold into P7's rework.

## 4. Defaults: `FORMWORK.toml` discovery (criterion 7)

Every blueprint-taking subcommand currently requires `--blueprint`. Proposal:

- **P10 —** blueprint resolution order, identical across `run`/`learn`/`explain`/
  `compile`/`gateway`:
  1. `--blueprint <path>` (explicit always wins);
  2. `FORMWORK.toml` in the current directory (optionally: walk up to the nearest
     ancestor containing one, stopping at `$HOME` or a filesystem boundary — mirrors how
     agents find `CLAUDE.md`);
  3. otherwise a loud error that teaches: name both options and show a minimal
     `FORMWORK.toml` (see P11).

  **Transparency is the load-bearing half.** Auto-discovery must never be silent:
  - every command logs `blueprint: /path/FORMWORK.toml (auto-discovered)` vs `(from
    --blueprint)` at info;
  - `compile` and `explain` include the resolved path *and* how it was chosen in their
    output, so a dry-run always tells you which file it dry-ran;
  - the existing policy-input write-protection (FW-XR8) applies to the discovered file
    exactly as to an explicit one — it already keys off the resolved path, so this is
    free, but a test should pin it.

  No silent fallback to a built-in profile when nothing is found: enforcing a policy the
  user never saw is the opposite of criterion 6.

- **P11 — embed the default profile.** `profiles/default.toml` is a repo file, so
  `extends = ["profiles/default.toml"]` only resolves for people who cloned the repo — a
  binary-download user (the README's own install path) can't reference it. Embed it via
  `include_str!` under a reserved name (`extends = ["builtin:default"]`), so the minimal
  useful `FORMWORK.toml` becomes two honest lines:

  ```toml
  extends = ["builtin:default"]
  rules = ["readwrite:$CWD/**"]
  ```

  `explain`/`compile` provenance already names layers, so the builtin shows up as
  `profile: builtin:default` — no opacity introduced.

## 5. Documentation & README (criteria 4 & 5)

The examples tree is genuinely good — `examples/README.md` (the axis table, the verb
table, the CLI recipes) is the best user-facing writing in the repo. The root README is
the problem: it leads with phase tables, FW-* requirement IDs, traceability conventions,
and test counts — contributor material — before a user learns what a blueprint looks like
or how to run anything.

- **P12 — restructure the README for users:**
  1. What it is (keep the current strong two-paragraph opening and the honesty paragraph);
  2. Install (releases + Gatekeeper note — already good);
  3. Quickstart: a five-line `FORMWORK.toml` + `formwork run -- <agent>` + `formwork
     explain` showing a deny — end-to-end in ~15 lines (depends on P10/P11);
  4. Honest **platform support matrix** (the table from §1, kept current — it fixes P1
     and gives parity a permanent, visible home);
  5. The command surface, one line each;
  6. Pointers: examples/ for integrations, formwork.md for design.

  Move the phase/status table, test counts, and requirement-ID conventions into
  `IMPLEMENTATION_PLAN.md` or a `docs/STATUS.md`, and consider moving the FEP files and
  `competition-research.md` under `docs/` so the repo root reads as a product, not a lab
  notebook.

## 6. Suggested order

| # | Change | Size | Pays into |
|---|---|---|---|
| P1 | README status table tells the truth about Linux | XS | honesty, docs |
| P2 | `learn` fails fast on Linux | S | parity, honesty |
| P4 | `log show --start` + poll-to-quiescence | M | the reported macOS bug |
| P9 | results to stdout (`accept` listing, proposal pointer) | S | explainability |
| P10 | `FORMWORK.toml` discovery + transparency | M | defaults |
| P11 | `builtin:default` profile | S | defaults, quickstart |
| P7 | `accept` → `learn --list/--accept` | M | CLI simplicity |
| P6 | `enforce-self` → `run --confine-self` | S | CLI simplicity |
| P5/P8 | host line in help; `explain` human-first, absorbs `detect`'s human use | M | simplicity, explainability |
| P12 | README rewrite (quickstart depends on P10/P11) | M | docs, examples |
| P3/P4b | Linux denial feed; sentinel-bracketed stream | L | parity, learn robustness |

Back-compat throughout: removed/renamed subcommands stay as hidden aliases for at least
one release, matching the existing `--spec` → `--blueprint` precedent.
