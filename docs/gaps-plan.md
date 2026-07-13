# Gap analysis and execution plan (post-FEP-2)

Companion to `formwork.md` (the canonical spec), `fep-1.md` (the declared remainder), and
`IMPLEMENTATION_PLAN.md` / `docs/fep2-plan.md` (how the landed phases were built). This is a
point-in-time survey of everything the spec promises that the tree does not yet deliver, and
the order in which to deliver it. Snapshot: main @ b2d25fa (FEP-2 reintegrated), 2026-07-13.

## 1. The gap inventory

Measured, not remembered: 42 of 66 spec-defined tests are implemented (counting only real
test functions/markers, not comment mentions). The 24 open IDs and the non-test gaps group
into five clusters, ordered by how much machinery they need.

### A. Product wiring: the fd seam is verified but not shipped (no new subsystem)

The architecture's central claim — *"the confiner makes the gateway unavoidable"* (§2) — is
proven at the mechanism level (FW-E2E-010..012: injected fd + SCM_RIGHTS minting under real
net-deny) but **no CLI path exercises it**. `formwork-cli` never references `formwork-seam`:
`formwork run` spawns a confined child with no gateway door, and the shipped gateway
deployment is the standalone stdio proxy an MCP host launches — which works today only
because the example blueprints open `ports = [443]`. Until `formwork run` can inject
pre-opened gateway fds, the single-door story is a verified component, not a product
property — and host-scoped egress (cluster D) is architecturally meaningless without it,
since `AllowHosts` is gateway-mediated by definition.

Also here: the gateway fronts stdio backends only. FW-GW1 promises http/sse uniformly; the
framing layer is transport-agnostic (`AsyncRead`/`AsyncWrite`), so this is an adapter, not a
redesign.

### B. Small hardening + defaults (hours each, some spec-mandated)

- **`$HOME`-unset falls back to `/`** (`main.rs` `home()`): `~/.ssh/**` silently expands to
  `/.ssh/**` — a silent miss of the credential floor. `fep-1.md` already flags it; FW-BP5
  set the precedent (`$CWD` fails loud). Make it fail loud (FW-INV6).
- **cwd is not folded into the read grant** (`docs/spikes.md` Spike 2): interpreters started
  outside the read scope break. Decide: fold-by-default vs document `--read '$CWD/**'` as
  the idiom. The `$CWD` sigil (FW-BP5) makes the explicit form cheap; recommendation is a
  loud startup warning when cwd is unreadable, not a silent implicit grant (FW-CAP1: grants
  are authored, not inferred).
- **No strict profile.** `read-mode = "closed"` is implemented and tested but no shipped
  profile uses it. Add `profiles/strict.toml` (closed reads, explicit grants, scrub env).
- **FW-E2E-036 tag debt**: the FW-ENV2 heuristic scrub is unit-tested but its E2E scenario
  is untagged in the harness; the neighboring FW-E2E-046 fixture makes this a small test.

### C. Test debt on landed capabilities (no new machinery, CI-viable today)

| IDs | What | Why open |
|---|---|---|
| FW-E2E-007, 008 | direct DNS denied; proxy-env-bypass denied | net-deny is enforced on both platforms; the probes were simply never written |
| FW-ADV-002, 003 | TOCTOU/symlink race; gateway-bypass egress | adversarial companions to landed FW-E2E-004/006 |
| FW-ADV-001 | sandbox shedding (setuid exec, `prctl` clear, re-exec) | Linux-leaning; NO_NEW_PRIVS+seccomp are landed, unprobed |
| FW-ADV-005 | fd smuggling (backend confers descriptors to the agent) | seam + gateway are landed; the adversarial hand-off probe was never written |
| FW-ADV-006 | cross-domain UNIX-socket reach-around | Landlock scoping is kernel-gated (6.12+ abstract-socket scope); implement as report-honesty on older kernels, like FW-E2E-009 |
| FW-E2E-009 | Landlock net port tier | ubuntu-22.04 CI (5.15, ABI v1) lacks net ABI v4 — implement as the report-honesty half (FW-E2E-025 pattern); full enforcement needs a 6.7+ runner or Lima |
| FW-E2E-025 | degraded-host honesty, enforce-side | the report half exists (`test_compile.py`); the behavior-matches-report half doesn't |
| FW-E2E-028 | cross-platform equivalence | most py E2Es are `macos`-marked; needs the fs/discovery suites parameterized over the Linux backend (CI ubuntu job already runs Landlock Rust tests) |
| FW-E2E-020..023 | pytest/npm/git reuse, graceful degradation | Phase 4 was validated by hand; the harness has no hermetic workload fixtures (noted in `test_discovery.py`) |

### D. FEP-1 remainder Part A: host-scoped egress (FW-EGR1–6) — the big one

The declared frontier: `net` becomes `Deny | Ports([u16]) | AllowHosts([HostPattern])` with a
gateway forward proxy, hostname canonicalization (FW-EGR3), SSRF/metadata default-block
(FW-EGR4), honest `Partial` fidelity without TLS interception (FW-EGR5), and no
unauthenticated door (FW-EGR6). Tests FW-E2E-029..032 + FW-ADV-007..009, 011, all against
the real gateway with loopback fixtures and a controlled resolver. This is the largest
work item (new proxy subsystem, Growth-gated) and it *retires* the worst shipped default:
`agent-session.toml`'s `ports = [443]`, which reaches cloud metadata (the fix is migrating
the example to `AllowHosts`, per FW-EGR4).

### E. FEP-1 remainder: FW-FID5 violation stream — mostly already built

`formwork learn` already ships the runtime denial feed FW-FID5 was deferred for: the
unified-log tap (`collect_denials` + `parse_sandbox_denial` in `learn.rs`). What remains is
shaping, not plumbing: extract the tap into a reusable feed, emit schema-stable structured
violation events (capability, path/host, backend, timestamp) on the observability channel
for *any* enforced run (opt-in flag), wire the gateway's refusals into the same stream, and
land FW-E2E-040. Cheap, and a prerequisite worth doing **before** FW-EGR: the egress test
harness (`fep-1.md`) asserts blocked egress *by violation event*, never by network timing.

Non-gaps, for the record: the Linux confiner is built and CI-exercised (contrary to older
notes — `linux/{landlock,seccomp}.rs`, tests green on ubuntu-22.04 ABI v1); the FW-E2E-011
seam flake was fixed by serializing the fork/exec-bearing tests; macOS signing is wired and
waits only on repo secrets (operator action, not code).

## 2. Execution order

Dependency-driven: honesty and cheap hardening first, the violation stream before egress
(egress tests consume it), the seam before egress (AllowHosts is gateway-mediated), the
proxy last because it is the only genuinely new subsystem.

1. **Hardening + base test-debt sprint** (cluster B + the today-viable half of C):
   `$HOME` fail-loud, cwd decision + warning, `profiles/strict.toml`, FW-E2E-007/008/036,
   FW-ADV-002/003/005, FW-E2E-025 enforce-side. Exit: every landed capability has its spec'd
   probe or an honest report-match test; no silent fail-opens remain in defaults.
2. **FW-FID5 violation stream** (cluster E): generalize the learn tap into a violation
   feed, structured events for confiner + gateway denials, FW-E2E-040. Exit: an embedding
   host can turn a denial into an escalation prompt; the egress harness's assertion
   primitive exists.
3. **Seam productization** (cluster A): `formwork run` grows MCP wiring — spawn the
   gateway, inject pre-opened connection fds via `formwork-seam`, agent reaches MCP with
   `net = "deny"`. The examples gain a no-port-grant variant. Then the http/sse backend
   adapter (FW-GW1). Exit: the §2 diagram is a shipped command; FW-E2E-010..012 have a
   product-level twin.
4. **Host-scoped egress FW-EGR1–6** (cluster D): the `AllowHosts` enum + compiler support,
   the gateway forward proxy over the seam, canonicalization + SSRF defaults, fidelity
   honesty; FW-E2E-029..032, FW-ADV-007..009, 011; migrate `agent-session.toml` off
   `ports = [443]`. Exit: the network layer stops being the weakest part of the design —
   the bet every competitor lost.
5. **Reuse + parity closure** (rest of C): hermetic workload fixtures for FW-E2E-020..023,
   Linux-parameterized fs/discovery suites for FW-E2E-028, FW-ADV-001 on a capable runner,
   FW-E2E-009 and FW-ADV-006 as report-honesty (full enforcement when a 6.7+/6.12+ kernel
   is in reach). Exit: the §10 traceability table has no unimplemented primary test.

Steps 1–2 are days and land independently. Step 3 unlocks step 4; step 4 is the multi-week
center of gravity and should be its own FEP-sized review (it is already specified in
`fep-1.md`, so adoption is an execution plan like `docs/fep2-plan.md`, not a new proposal).
Step 5 can interleave anywhere after 1.
