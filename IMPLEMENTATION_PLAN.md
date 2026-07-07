# Formwork implementation plan

Companion to `formwork.md`. That document says *what* and *why*; this one says *how, in what
order, with which mechanisms and libraries*. Requirement/test IDs (FW-XR*, FW-E2E-*, …) refer
to the design doc.

## 1. Language split

**Rust** carries everything load-bearing: the blueprint types, the pure compiler, both confiners,
the fd seam, the gateway, and the CLI. Rationale: the confiner does `pre_exec`-window syscall
work (fork-safety matters), the gateway is the single privileged broker (memory safety
matters), and the compiler must be deterministic (FW-FID4).

**Python** carries everything that sits *outside* the trust boundary:

- the end-to-end / adversarial test harness (`pytest`), which orchestrates the Rust binaries
  and asserts the FW-E2E-* / FW-ADV-* pass/fail conditions;
- probe scripts that run *inside* the sandbox (which doubles as a continuous test of ambient
  interpreter reuse, FW-TRA1);
- fixture MCP servers (stdio and streamable-http, via the official `mcp` Python SDK) used by
  the gateway tests;
- reuse-workload fixtures (a real pytest project, an npm project, a git repo, a small C build)
  for FW-E2E-020..023.

Optional later: `pyo3`-based Python bindings for embedding (`formwork.compile()`,
`formwork.run()`). Not in v1 — the CLI is the v1 embedding surface.

## 2. Repository layout

```
formwork/
├── Cargo.toml                    # workspace
├── crates/
│   ├── formwork-blueprint/            # capability blueprint: types, serde, canonical form,
│   │                             # narrowing algebra (FW-CAP1, FW-CAP2)
│   ├── formwork-compile/         # pure blueprint → {ConfinerPolicy, GatewayPolicy,
│   │                             # FidelityReport}; no kernel calls (FW-CAP5, FW-FID*)
│   ├── formwork-detect/          # HostProfile detection (Landlock ABI, seccomp,
│   │                             # Seatbelt, OS version) — the only impure input
│   ├── formwork-confine/         # Confiner trait + spawn-confined / confine-self;
│   │   ├── src/linux/            # Landlock + seccomp + NO_NEW_PRIVS
│   │   └── src/macos/            # Seatbelt: SBPL generation + sandbox_init FFI
│   ├── formwork-seam/            # fd injection: socketpair setup at spawn, control
│   │                             # protocol, SCM_RIGHTS minting (FW-XR7, FW-GW6)
│   ├── formwork-gateway/         # MCP-aware policy proxy (tokio)
│   ├── formwork/                 # umbrella library API: detect / compile / enforce /
│   │                             # spawn_confined / run_gateway
│   └── formwork-cli/             # `formwork` binary: detect, compile, run, gateway, probe
├── profiles/
│   ├── default.toml              # subtractive default profile (FW-CAP3)
│   └── sensitive-set.toml        # data-driven sensitive superset (FW-TRA3)
├── py/
│   ├── pyproject.toml            # uv-managed; dev-only, never shipped
│   ├── harness/                  # pytest suite, one module per §7 group, markers = test IDs
│   ├── probes/                   # scripts run inside the sandbox (fs/net/exec/shed probes)
│   ├── mcp_fixtures/             # fixture MCP servers (stdio + streamable-http)
│   └── workloads/                # pytest/npm/git/C reuse fixtures (FW-E2E-020..023)
├── docs/
└── justfile                      # build, test-linux (Docker first, Lima fallback),
                                  # test-macos, bench
```

## 3. Key technical decisions

### 3.1 Blueprint and deterministic compile

- Blueprint is TOML on disk, `serde` in memory, with a **canonical form** (sorted keys, normalized
  paths, canonical JSON serialization) so FW-E2E-027's byte-identical requirement is a
  property of the encoder, not luck.
- `compile(blueprint, host: &HostProfile) -> CompiledPolicy` is pure. All host facts (Landlock ABI
  level, macOS version, seccomp availability) enter through the explicit `HostProfile` value,
  produced by `formwork-detect` or supplied synthetically. That is what makes "compile a Linux
  policy on a Mac" (FW-E2E-026) trivial: pass a synthetic Linux profile.
- The compiled `ConfinerPolicy` is **symbolic** (path patterns + access bits + subtract set +
  a seccomp filter description), not expanded against the live filesystem. Expansion happens
  at `enforce()` time (see 3.3). This keeps compile deterministic even though the subtractive
  profile depends on what exists under `$HOME`.
- seccomp BPF is built with `seccompiler` (rust-vmm; pure Rust, no libseccomp C dependency,
  deterministic output). Landlock via the official `landlock` crate (ABI negotiation,
  best-effort mode disabled — we do our own fidelity accounting instead, FW-XR1).

### 3.2 Linux confiner

Spawn-confined posture (preferred): `Command::pre_exec` hook, in order:

1. `prctl(PR_SET_NO_NEW_PRIVS, 1)` (FW-ISO8);
2. apply Landlock ruleset via `landlock_restrict_self` — fs read/write/exec rights, plus
   net `ACCESS_NET_*` and scope flags where the ABI has them (survives `execve`, inherited by
   all descendants: FW-XR4);
3. install the seccomp filter;
4. `execve` the target.

Confine-self posture is the same sequence exposed as a library call (`enforce_self()`).

**Net default-deny below Landlock net ABI (v4)** is done in seccomp: deny `socket(2)` for
`AF_INET`/`AF_INET6`/`AF_PACKET` (and `AF_NETLINK` except the route-read families toolchains
need), allow `AF_UNIX` and `socketpair`. Denying socket *creation* still permits full use of
inherited connected fds — exactly the seam semantics FW-XR7 wants. On ABI ≥ 4 kernels,
Landlock TCP rules additionally enforce the optional port tier (FW-ISO5); the report states
which mechanism carried net-deny on this host.

**Seccomp baseline** (FW-ISO8) is deny-list-shaped, not allow-list-shaped, to honor
transparency (FW-TRA2): block confinement-shedding and escalation surfaces (`ptrace` of
non-descendants, `keyctl`, `add_key`, `bpf`, `mount`/`move_mount`/`fsmount`, `setns`,
`unshare(CLONE_NEWUSER)`, `kexec*`, `init_module*`, `open_by_handle_at`, `userfaultfd`,
`perf_event_open`) and the socket families above. Everything else passes. Landlock ABI v6
scope flags add abstract-unix-socket and signal scoping where available (FW-ADV-006);
below v6 the gap is reported `Partial`.

**Landlock is allowlist-only — the subtractive profile compiles to an expansion.** "read
`$HOME/**` minus `~/.ssh`" cannot be expressed as a deny rule. `enforce()` expands it:
enumerate the direct children of each broad-grant root, grant each child that is not in the
subtract set, recursing only where a subtract entry sits deeper than the grant root.
Consequences, stated in the FidelityReport: directories created under a broad-grant root
*after* enforcement are not readable (fail-closed, acceptable); enumeration happens once at
spawn, so it is TOCTOU-safe with respect to later renames because Landlock rules bind to the
opened directory fds, not to path strings.

### 3.3 macOS confiner

Seatbelt via SBPL and `sandbox_init(3)` — deprecated since 10.8 and exactly what the design
calls for; it remains the mechanism under `sandbox-exec`, Chromium, and Bazel. Concretely:

- `formwork-compile` emits SBPL text deterministically from templates: `(version 1)`,
  `(deny default)`-style is *not* used — the profile is `(allow default)` with explicit
  `(deny network*)`, `(deny file-read* file-write* <sensitive paths>)`, and write scope as
  deny-all-writes-then-allow-granted. Seatbelt supports real deny rules with
  last-match-wins, so the subtractive profile is native here — no expansion step.
- **Spawn-confined**: `fork()`, then in the child call `sandbox_init(profile, SBPL, &err)`
  and `execve` the target. Seatbelt persists across exec and is inherited by descendants
  (FW-XR4). FFI is three symbols from `libsystem_sandbox.dylib` (`sandbox_init`,
  `sandbox_free_error`); we declare them ourselves with `#[allow(deprecated)]` semantics —
  no crate dependency needed. `sandbox-exec -p` is kept as a debugging tool only, not a
  runtime dependency.
- **Confine-self**: same `sandbox_init` call on the current process.
- Net: `(deny network*)` with no `network-outbound` allowances; the optional port tier
  compiles to `(allow network-outbound (remote tcp "*:8080"))`-style filters. Seatbelt can
  also path-gate UNIX sockets, which is why the cross-domain-socket row is `Enforced` on
  macOS (§9).
- `sandbox_init_with_parameters` (private) is deliberately avoided in v1; parameterization is
  done by generating the SBPL text per-spawn.

### 3.4 fd seam (`formwork-seam`)

- At spawn, the launcher creates `socketpair(AF_UNIX, SOCK_STREAM)` pairs: one **control fd**
  plus zero or more pre-opened per-server connection fds, passed to the child at fixed fd
  numbers advertised via `FORMWORK_FD_*` environment variables.
- Default is **pre-open all known connections at spawn** with on-demand minting as the escape
  hatch (resolving the §11 open question in favor of the simple default).
- On-demand minting: a 3-message protocol on the control fd (`mint {server} → fd via
  SCM_RIGHTS | error`), implemented with `sendmsg`/`recvmsg` ancillary data; identical code on
  both platforms. The gateway enforces that minting is the *only* way a new connection
  appears (FW-ADV-005: backends can't confer fds because backends have no control fd — only
  the agent does, and the gateway never forwards ancillary data between domains).

### 3.5 Gateway (`formwork-gateway`)

- tokio-based. Backends: stdio (spawned **through `formwork-confine`** with their own grant —
  FW-GW5/FW-E2E-019) and streamable-http/SSE via `reqwest` limited to allowlisted endpoints
  (FW-GW7). The gateway's own process is itself confined to its minimal fs scope; on Linux
  its egress confinement (netns vs nftables, §11) is deferred to Phase 7 and reported
  honestly meanwhile.
- **Interception layer, not a re-serving SDK.** For FW-GW8 transparent passthrough, the proxy
  parses only the JSON-RPC envelope plus the policed methods (`initialize`, `tools/*`,
  `resources/*`, `prompts/*`, `notifications/*/list_changed`, `sampling/createMessage`,
  `elicitation/create`) and forwards everything else, and all granted payloads, as
  `serde_json::value::RawValue` — bytes preserved, no semantic re-encoding. The official
  `rmcp` SDK is used for its protocol *types* in tests and fixtures, not in the proxy hot
  path.
- **Oracle-free refusals (FW-ADV-004) by construction:** the gateway validates `tools/call`
  names against the *shaded* list. Any name not on it — hidden-but-real and nonexistent
  alike — takes the identical local code path: same JSON-RPC error object (MCP
  "unknown tool" shape), never consults the backend, so content, error code, and timing are
  indistinguishable because they are the same path, not because we tuned two paths to match.
  Same construction for resources (URI not in shaded list) and prompts.
- `list_changed` handling: the gateway re-runs the shading filter on every refreshed listing
  before forwarding the notification (FW-E2E-016); policy is static per session, listings are
  dynamic.

### 3.6 FidelityReport

One Rust type shared by compile and enforce:

```rust
enum Fidelity { Enforced { backend: Backend }, Partial { backend: Backend, reason: String },
                Unenforceable { reason: String } }
struct FidelityReport { per_capability: BTreeMap<CapabilityKey, Fidelity>,
                        semantics: BTreeMap<CapabilityKey, DenialSemantics /* Hide | Deny */>,
                        host: HostProfile }
```

`enforce()` consumes the compiled report and may only *confirm or degrade-loudly*: if a
mechanism the report promised fails to install, `enforce()` aborts (fail-closed) rather than
continuing with a weaker set (FW-XR1, FW-INV6). Runtime denials are logged as structured
JSONL (FW-FID3).

### 3.7 CLI surface (v1 embedding API)

```
formwork detect                             # HostProfile as JSON
formwork compile  --blueprint s.toml [--host h.json]   # policy + report, no enforcement
formwork run      --blueprint s.toml -- cmd args…      # spawn-confined
formwork enforce-self --blueprint s.toml               # confine-self, then exec $SHELL or --exec
formwork gateway  --blueprint s.toml --servers m.toml  # run broker; used by `run` internally
formwork probe    --report r.json                 # paired allow/deny probes (FW-E2E-024)
```

## 4. Phases

Follows §12 of the design doc, with a de-risking Phase 0 added and reuse validation kept
deliberately early.

### Phase 0 — scaffolding + mechanism spikes (de-risk before building)

Workspace, CI skeleton, justfile, local Linux testing setup (Docker image + container run
flags first; Lima VM config as the full-matrix fallback — see §5). Then four short spike
programs, each answering a question the whole design leans on:

1. **Seatbelt + inherited fds:** under `(deny network*)`, confirm read/write on an
   already-connected inherited socket still works (the seam depends on it). If Seatbelt
   mediates data transfer and not just `connect`, the SBPL needs a scoped allowance — find it
   now, not in Phase 5.
2. **`sandbox_init` from Rust** in a forked child pre-exec: confirm the deprecated API is
   callable, inherited across exec, and error-reportable on macOS 15/26.
3. **seccomp `socket(2)` domain-arg filtering** coexisting with glibc/musl resolver and
   toolchain behavior (does blocking `AF_NETLINK` break `ip`/`getifaddrs` paths pytest or npm
   touch?).
4. **Landlock expansion cost:** enumerate-and-grant over a realistic `$HOME` (target: within
   the 50 ms spawn budget, §8).

Exit: spike notes committed to `docs/spikes.md`; any design amendment fed back into
`formwork.md`.

### Phase 1 — blueprint, compiler, fidelity, dry-run

`formwork-blueprint`, `formwork-compile`, `formwork-detect`, CLI `detect|compile`.
Golden-file tests for canonical encoding; property test for narrowing monotonicity (FW-CAP2).
**Exit: FW-E2E-026, FW-E2E-027 green on macOS and Linux CI; a Linux policy compiles on macOS.**

### Phase 2 — Linux confiner

`formwork-confine` Linux backend (Landlock fs + seccomp baseline + net-deny +
NO_NEW_PRIVS), both postures, subtractive expansion, `formwork run`/`probe`. Python harness
bootstrapped here (probes + fixtures).
**Exit: FW-E2E-001..005, FW-ADV-001, FW-ADV-002, FW-E2E-024 green on Linux.**

### Phase 3 — macOS confiner

Seatbelt backend, same test set, plus the parity suite.
**Exit: the Phase-2 test set green on macOS; FW-E2E-028 green across both.**

### Phase 4 — reuse validation and default-profile tuning

Run the real workloads (`py/workloads/`) under `profiles/default.toml`; iterate on the
profile and sensitive set until zero happy-path denials. This is the philosophy checkpoint:
if the default profile can't be made transparent, stop and rework before building the seam
and gateway on top of it.
**Exit: FW-E2E-020..023 green on both platforms; §8 overhead numbers recorded by a benchmark
harness (`just bench`), within target.**

### Phase 5 — fd seam

`formwork-seam`: pre-open at spawn, control protocol, SCM_RIGHTS minting; a stub echo
"gateway" suffices for the seam tests.
**Exit: FW-E2E-010, 011, 012 green on both platforms.**

### Phase 6 — gateway

`formwork-gateway`: stdio + streamable-http backends, full-surface shading, oracle-free
refusals, `list_changed` re-filtering, sampling/elicitation policing, transparent
passthrough (byte-compared against direct-connection ground truth), backend-confinement
recursion. Python MCP fixtures land here.
**Exit: FW-E2E-013..019, FW-ADV-003, 004, 005 green.**

### Phase 7 — degraded-host honesty and optional tiers

Port tier (Landlock ABI v4 / Seatbelt remote filters), optional exec allowlist (FW-ISO4,
shipped as enabled-optional — it is nearly free once Phase 2/3 exist), ABI-v6 socket/signal
scoping, degraded-host test matrix (old-kernel container images in CI), gateway egress
isolation decision (netns via `pasta` vs direct nftables — decide from Phase-6 experience).
**Exit: FW-E2E-009, FW-E2E-025, FW-ADV-006 green; fidelity matrix in §9 of the design doc
reproduced by `formwork detect + compile` on each CI target.**

## 5. Test and CI strategy

- **Harness:** every FW-E2E/FW-ADV test is a pytest with a marker carrying its ID; the
  traceability table in §10 of the design doc is *generated* from markers by a small script,
  so it cannot drift.
- **Probes run in Python inside the sandbox** (exercising interpreter reuse for free); the
  few probes needing exact syscalls (raw `socket(2)`, `prctl`, `execve` of setuid) are tiny
  Rust helpers under `formwork-cli probe`.
- **CI matrix:** `macos-15` (Seatbelt), `ubuntu-24.04` (kernel 6.8 → Landlock ABI v4: fs +
  net-port tests), a 6.12+ runner or container-in-VM job for ABI v6 scoping tests, and a
  deliberately old-kernel job (no Landlock) for FW-E2E-025/026 honesty tests. Platform-gated
  tests skip-with-reason, never silently pass.
- **Local dev** on macOS: `just test-macos` runs natively. For Linux, Docker is the
  first-line path — `just test-linux` runs the suite in a container because it is fast,
  needs no VM management, and is what most contributors already have. Two caveats the
  justfile handles rather than documents:
  - **Docker's own sandboxing must not mask ours.** The default seccomp profile only
    recently allowlisted the `landlock_*` syscalls, and AppArmor confinement can shadow
    Landlock denials with its own. Test containers run with
    `--security-opt seccomp=unconfined --security-opt apparmor=unconfined` so the only
    sandbox under test is Formwork's. Nested seccomp (ours inside Docker's, when not
    unconfined) and Landlock-inside-container both work on capable kernels, but the
    unconfined options keep test failures attributable.
  - **The kernel is the VM's, not the image's.** On Docker Desktop the Landlock ABI is
    whatever the linuxkit VM kernel provides (recent versions are 6.x, typically ABI v4+).
    The harness therefore starts every containerized run with `formwork detect` and
    skips-with-reason any test the detected ABI cannot carry, same as CI.

  When the Docker VM kernel is too old for a test tier (ABI v6 socket/signal scoping needs
  6.12+), `just test-linux-full` falls back to a Lima VM with a pinned 6.12+ kernel image —
  the only local path that exercises the complete matrix.
- **Fuzzing** (FW-INV1/2/4): `proptest` for blueprint/narrow sequences and spawn trees; a
  guessed-name fuzzer for shading; nightly CI job, not per-PR.

## 6. Risk register

| Risk | Phase | Mitigation |
|---|---|---|
| Seatbelt blocks inherited-fd data transfer under `deny network*` | 0 | Spike 1; scoped SBPL allowance if needed; the seam design already avoids in-sandbox `connect` |
| Subtractive→additive expansion too slow or too coarse on Landlock | 0/2 | Spike 4; cache expansion; degrade to coarser grants with `Partial` report, never silent |
| seccomp baseline breaks a real toolchain (netlink, io_uring, etc.) | 2/4 | Deny-list shape; Phase 4 gate exists precisely to catch this before the API freezes |
| Docker's seccomp/AppArmor or an old Docker-VM kernel masks or blocks Landlock in local runs | 0/2 | Unconfined container run flags baked into the justfile; every run gated on `formwork detect`; Lima fallback for tiers Docker can't carry |
| `sandbox_init` behavior shifts in a macOS update (deprecated API) | 0/3 | Spike 2 re-run per macOS release in CI; `sandbox-exec` fallback path kept working as a canary |
| MCP protocol evolution (new server→client request types) breaks full-surface policing | 6 | Gateway default-denies *unknown* server→client request methods; report lists policed surface |
| Oracle leakage via gateway timing under load | 6 | Refusal path never touches the backend (identical code path by construction); ADV-004 includes a timing assertion |

## 7. Resolved-here open questions (from §11)

- **fd-minting default:** pre-open at spawn; on-demand `SCM_RIGHTS` as escape hatch (3.4).
- **Exec restriction in v1:** ships enabled-optional in Phase 7 (cheap once confiners exist).
- **Sensitive-set discovery:** data-driven broad superset in `profiles/sensitive-set.toml`,
  caller-narrowable — the fail-closed answer the design doc already leans toward.
- **Naming** and **Linux gateway egress build-vs-buy** stay open; the latter is decided at
  Phase 7 with real data.
