# Formwork: an OS-level sandbox for agent sessions

Working name. Design proposal with end-to-end test specification.

Formwork is a sandboxing substrate for agent sessions. It turns the four capabilities that touch the real operating system — read, write, exec, net — into enforceable boundaries, on Linux and macOS, for an agent process and every child it spawns.

Formwork is standalone. It takes a capability spec and produces an enforced sandbox plus an honest report of what it could and could not enforce. A host — Claude Code, OpenCode, or a bare shell wrapper — depends on Formwork; Formwork depends on nothing above it. The name is the metaphor: formwork is the temporary mould that contains poured concrete until it cures — a frame that constrains where the material can go. That is a sandbox around a process tree.

## 1. Design philosophy: good isolation, maximal reuse

The load-bearing decision in this design is that Formwork targets **good isolation, not perfect isolation**. This is a deliberate scoping choice, not a limitation to be apologized for, and it drives most of the requirements below.

The goal is a boundary that reliably contains an agent — and code the agent runs, and MCP servers it fronts — from casually or accidentally reading, writing, or exfiltrating things outside its lane, including when the agent is driven by a prompt-injected or otherwise adversarial instruction stream. The goal is **not** to withstand an adversary writing kernel exploits against Landlock or Seatbelt. Formwork raises the bar a great deal and fails closed on egress; it does not claim to be an airtight security boundary against local privilege escalation or a kernel zero-day. Section 3 states this threat model precisely, and every enforcement claim in this document is scoped to it.

The second half of the philosophy is **transparency and reuse**. Formwork is not a minimal-from-empty jail that the agent must have a bespoke image built for. It starts from the real, ambient environment — the host's interpreters, toolchains, shared libraries, and language package caches — and *subtracts* a sensitive set (credentials, keys, other projects, browser profiles). The confined agent should be able to run `pytest`, `npm test`, `git`, and a normal build against the environment that is already there, with zero denials on the common path. Isolation the agent constantly trips over is isolation that gets turned off. Formwork earns its keep by being nearly invisible to well-behaved work while remaining a hard wall around the sensitive set and all network egress.

These two halves are in tension, and the resolution is the third principle: **honesty**. Formwork always reports what it actually enforces on the current platform and kernel, and never silently claims containment it cannot deliver. A caller that needs a stronger guarantee than the current host can provide learns that from the fidelity report rather than discovering it in an incident.

## 2. Architecture overview

Formwork has two enforcement arms driven by a single capability compiler, with an fd seam to the agent.

```
┌──────────────────────────────────────────────────────────────────┐
│  CAPABILITY SPEC (unveil-style)                                    │
│  read(path) · write(path) · [exec(path)] · net-posture ·          │
│  mcp(server → {tools, resources, prompts} visibility)             │
├──────────────────────────────────────────────────────────────────┤
│  COMPILER (pure; no kernel calls)                                  │
│  spec → { confiner policy, gateway policy } + FidelityReport      │
├───────────────────────────────┬──────────────────────────────────┤
│  CONFINER  (hard boundary)     │  GATEWAY  (soft boundary)         │
│  Linux: Landlock + seccomp     │  MCP-aware policy proxy           │
│  macOS: Seatbelt (SBPL)        │  shades tools/resources/prompts   │
│  fs read/write, net-deny,      │  fronts stdio + http/sse backends │
│  descendant inheritance        │  mints connection fds (SCM_RIGHTS)│
└───────────────┬───────────────┴───────────────┬──────────────────┘
                │ confines                        │ one control fd
                ▼                                 ▼
        ┌───────────────┐                 ┌───────────────┐
        │  AGENT         │◄────fd seam─────│  (no net, no   │
        │  (confined)    │   injected fd   │   fs except    │
        └───────────────┘                 │   the fd)      │
                ▲                          └───────────────┘
                │ confines (recursion)
        ┌───────────────┐
        │ stdio MCP      │  spawned by gateway, itself confined
        │ backend        │  by the same confiner
        └───────────────┘
```

Three things make this hang together:

**The confiner makes the gateway unavoidable.** Because the confined agent has no network and no filesystem beyond its grant plus one injected fd, every MCP interaction and every byte of egress is *forced* through the gateway. That is what upgrades tool-shading from a suggestion into a control: there is no other door.

**The transport is an injected fd, never an in-sandbox connect.** The gateway (outside the sandbox) opens connections and hands the agent a connected file descriptor at spawn, or mints new ones on demand over a control channel via `SCM_RIGHTS`. Formwork never relies on the filesystem sandbox to selectively *allow* a socket path — a mechanism that is coarse and bleeding-edge on Linux (section 9). Inside the sandbox it is just an inherited fd, which behaves identically on both platforms.

**One privileged broker, everything else in a mould.** The gateway is the only process holding real network and broad filesystem access. The agent and every stdio MCP backend the gateway spawns are confined by the same confiner. The trust boundary is a single, small, auditable component.

Naming note (open, section 11): this document uses **Formwork** for the whole system, **confiner** for the hard OS layer, and **gateway** for the soft MCP layer. There is an argument that the name Formwork should be reserved for the confiner alone, since the mould metaphor is about containment. Left as an open decision.

## 3. Threat model

**In scope — Formwork is a boundary against these:**

- A confined process (the agent, code it runs, or an MCP backend) reading files outside its granted read scope, including the sensitive set (credentials, SSH/cloud config, keychains, other projects, browser profiles).
- A confined process writing outside its granted write scope.
- A confined process making network egress by any means other than the gateway fd — direct `connect()`, raw sockets, direct DNS, ignoring proxy environment variables.
- A confined process reaching processes outside its domain via abstract or pathname UNIX sockets, or via signals, where the platform supports scoping.
- The agent invoking or even discovering MCP tools, resources, or prompts that policy does not grant.
- A descendant process shedding or widening the confinement it inherited.
- Prompt-injected instruction streams driving any of the above: the boundary is enforced by the OS and the gateway, not by the model's cooperation.

**Out of scope — Formwork does not claim to defend against these:**

- Kernel or LSM exploitation (a Landlock/Seatbelt bypass, a kernel zero-day). Formwork's guarantees are only as strong as the underlying mechanism.
- Covert channels and side channels (timing, cache, resource-contention inference).
- Resource-exhaustion denial of service as a *security* property. Formwork may set cgroup/rlimit bounds for stability, but does not claim them as an airtight control.
- Confining inference, GPUs, or the model itself.
- Hostile multi-tenant co-tenancy at cloud scale. Formwork is a personal/team substrate, not a hosted platform isolating mutually adversarial tenants.
- Perfect unveil-style invisibility of the filesystem. Formwork accepts EACCES-style denial (section 4); it does not emulate ENOENT for every ungranted path.

## 4. The capability spec and its interpreter

Formwork consumes a finite, enumerable spec — the unveil/pledge lineage, narrowed to what an OS sandbox can carry:

```
read(path-pattern)        # filesystem read
write(path-pattern)       # filesystem write (implies read of the same)
exec(path-pattern)        # OPTIONAL: execute only these binaries (off by default)
net: Deny                 # default: no direct egress at all
   | Ports([u16])         # optional: allow direct TCP connect to these ports
mcp(server): {            # per-MCP-server visibility policy
    tools:     Allow([...]) | AllowAll | Deny,
    resources: Allow([...]) | AllowAll | Deny,
    prompts:   Allow([...]) | AllowAll | Deny,
    sampling:  Allow | Deny,     # server→client sampling requests
    elicitation: Allow | Deny,   # server→client elicitation requests
}
```

The compiler is the single authority that maps this spec to concrete mechanisms. It is pure — it never touches the kernel — so it runs in CI on any box, lets a Linux policy be compiled and inspected on a Mac, and is deterministic. It emits two policy objects (confiner, gateway) and a `FidelityReport`.

Two semantics choices, both settled earlier in design:

- **EACCES denial is acceptable; invisibility is preferred only where free.** Filesystem denials surface as the platform's natural errno (EACCES on Landlock, EPERM/EACCES on Seatbelt). Formwork does not build a mount-namespace or FUSE layer to fake ENOENT. The one place invisibility *is* cheap and *is* required is MCP tool/resource/prompt shading at the gateway, where an ungranted item is simply absent from the listing.
- **The default profile is subtractive, not minimal.** Rather than granting an empty world and adding paths, the default profile grants broad read over the ambient environment (system prefixes, interpreters, shared libraries, standard tool locations, language caches) and subtracts a configured sensitive set. This is the reuse principle expressed as policy.

Two further points pin the vocabulary above down so it is unambiguous to the compiler and gateway:

- **MCP item identity.** Shading matches items by their natural MCP identifier: tools and prompts by `name`, resources by `uri`, and resource templates by `uriTemplate`. A `resources` `Allow([...])` list therefore contains URIs (for concrete resources, matched on `resources/list` and `resources/read`) and/or URI templates (for `resources/templates/list`); tool and prompt lists contain names. An item that lacks its identifier field is treated as ungranted (fail-closed). This is what keeps the resource axis consistent across list, read, and templates rather than silently matching one of them on a different key.
- **Grant paths must be representable.** Grant, write, and `subtract` paths are canonicalized against the real filesystem at enforce time (symlink and firmlink resolution) so kernel path-matching lines up. A resolved path that cannot be faithfully rendered into the backend's policy language — e.g. a non-UTF-8 byte path — makes enforcement **fail loud**, never emit a lossy rule that might silently not match. A `subtract` hole that failed to match would be a silent fail-open of the sensitive set, which FW-INV6 forbids.

## 5. Requirements

### 5.1 Cross-cutting requirements

| Req | Requirement |
|---|---|
| **FW-XR1** Fidelity honesty | Every enforcement Formwork claims is backed by a real mechanism on the current host, or is reported as Partial/Unenforceable. `enforce()` never silently downgrades a claim made by `compile()`. |
| **FW-XR2** Good-not-perfect boundary | Formwork is a containment boundary against accidental, careless, and prompt-injected overreach and against untrusted code the agent runs — not against kernel/LSM exploitation. Every guarantee in this document is scoped to section 3. |
| **FW-XR3** Fail-closed egress | Absent a working confiner, network defaults to full deny. The agent reaches the world only through the gateway fd. No configuration and no capability-detection failure produces silent open egress. |
| **FW-XR4** Descendant inheritance | Confinement applies to the confined process and every descendant. A child cannot shed, relax, or widen it. |
| **FW-XR5** Single privileged broker | Exactly one component (the gateway) holds real network and broad filesystem access. The agent and all stdio MCP backends are confined by the same confiner. |
| **FW-XR6** Behavioral parity | An identical spec yields equivalent observable behavior for the enforceable intersection across Linux and macOS. Platform divergence appears only in the FidelityReport, never as a silent behavior change. |
| **FW-XR7** fd-injection transport | The agent reaches the gateway via an inherited fd. Formwork never depends on an in-sandbox `connect()` nor on the filesystem sandbox selectively *allowing* a socket path. |

### 5.2 Capability model (FW-CAP)

| Req | Requirement |
|---|---|
| **FW-CAP1** Enumerable vocabulary | The spec is a finite enumeration of read/write/exec/net/mcp. No mechanism accepts natural language and produces a grant. |
| **FW-CAP2** Monotonic narrowing | A session may narrow its own grant but never widen it. A child's grant is a subset of its parent's. |
| **FW-CAP3** Subtractive default profile | The default profile is broad-read over the ambient environment minus a configured sensitive set, not minimal-from-empty. |
| **FW-CAP4** Invisibility for MCP, denial for fs | Ungranted MCP tools/resources/prompts are absent from listings and non-invocable. Ungranted filesystem paths may return EACCES rather than ENOENT. |
| **FW-CAP5** Single inspectable interpreter | The compiler is the sole spec→mechanism authority, and its output (compiled policy + report) is inspectable without enforcing. |

### 5.3 OS isolation / confiner (FW-ISO)

| Req | Requirement |
|---|---|
| **FW-ISO1** Read confinement | Enforce filesystem read scope (Landlock FS access rights / Seatbelt `file-read*`). |
| **FW-ISO2** Write confinement | Enforce filesystem write scope; write to a read-only-granted path is denied. |
| **FW-ISO3** Net default-deny | Deny all direct network egress by default (no Landlock net grants + scope flags / Seatbelt `network*` deny), except the injected fd. |
| **FW-ISO4** Optional exec restriction | When set, restrict execution to an allowlist (Landlock `FS_EXECUTE` on paths / seccomp on `execve` / Seatbelt `process-exec*`). Off by default (transparency). |
| **FW-ISO5** Optional port tier | When requested, allow direct TCP connect to an explicit port set (Landlock net ABI v4+); report Unenforceable on older kernels. |
| **FW-ISO6** Two postures | Support spawn-confined (launcher confines a child; preferred) and confine-self (process restricts itself; pledge-style). |
| **FW-ISO7** Capability detection | Detect Landlock ABI / seccomp / Seatbelt availability at runtime and degrade with a report; never crash and never silently no-op. |
| **FW-ISO8** Anti-shedding baseline | On Linux, set `NO_NEW_PRIVS` and a seccomp baseline that blocks confinement-shedding and privilege-escalation paths, while remaining permissive enough that normal toolchains run unmodified. |

### 5.4 Gateway / MCP (FW-GW)

| Req | Requirement |
|---|---|
| **FW-GW1** Transport-agnostic backends | Front stdio and http/sse/streamable-http MCP servers uniformly behind one agent-facing interface. |
| **FW-GW2** Tool shading | Ungranted tools are absent from `tools/list` **and** `tools/call` on a guessed name is refused. |
| **FW-GW3** Full-surface policy | Policy covers resources (list/read/templates), prompts (list/get), `list_changed` re-filtering, and server→client sampling/elicitation. |
| **FW-GW4** Single door | Shading is binding because the confiner removes every alternative path to the backend. |
| **FW-GW5** Backend confinement | stdio backends the gateway spawns are themselves confined by the confiner to their own grant. |
| **FW-GW6** fd minting | The gateway supplies connection fds to the agent (pre-opened at spawn or minted on demand via `SCM_RIGHTS`); the agent never performs an in-sandbox `connect()`. |
| **FW-GW7** Least-privilege gateway | The gateway holds real network only to allowlisted MCP endpoints, and its own filesystem scope is minimal. |
| **FW-GW8** Transparent passthrough | For *granted* items, the gateway is protocol-transparent: no semantic mangling, so agents behave as if talking to the backend directly. |

Note (stability, not a security property per §3): the gateway parses newline-delimited JSON-RPC from less-trusted peers — the agent and the stdio backends it spawns — and bounds each frame to a fixed maximum, failing the connection closed on overflow rather than buffering without limit. This is a robustness bound in the spirit of §3's "rlimit bounds for stability," not a claim of DoS resistance (which §3 scopes out). A dead gateway is fail-closed regardless: the confined agent has lost its only door.

### 5.5 Transparency & environment reuse (FW-TRA)

| Req | Requirement |
|---|---|
| **FW-TRA1** Ambient reuse | The confined process reuses host interpreters, toolchains, shared libraries, and language package caches, read-only by default. |
| **FW-TRA2** Toolchains run clean | Under the default profile, common toolchains (python/pytest, node/npm, git, a C build) run unmodified with zero denials on the happy path. |
| **FW-TRA3** Sensitive-set subtraction | Credentials, SSH/cloud config, keychains, other projects, and browser profiles are denied/hidden by default even under broad grants. |
| **FW-TRA4** Graceful denial | Denials surface as standard errno, never as sandbox-specific crashes; a tool probing an optional ungranted path continues rather than aborting. |
| **FW-TRA5** Writable working set | The project directory, a scratch/tmp area, and (optionally) build caches are writable, so the agent can do real work and persist within scope. |
| **FW-TRA6** Low overhead | Confinement setup and per-operation overhead stay within the section 8 performance target so interactive agent loops remain responsive. |

### 5.6 Operability & fidelity (FW-FID)

| Req | Requirement |
|---|---|
| **FW-FID1** Per-capability report | `compile()` returns, per capability: `Enforced \| Partial(reason) \| Unenforceable(reason)`, plus backend and semantics (hide vs deny). |
| **FW-FID2** Dry-run / audit | Produce the compiled policy and report without enforcing (CI on non-capable boxes; cross-platform policy development). |
| **FW-FID3** Runtime observability | Emit a structured record of grants and denials at runtime, suitable for a host's journal when embedded, or standalone logging otherwise. |
| **FW-FID4** Deterministic compile | The same spec compiles to a byte-identical policy and report. |

## 6. Invariants

These hold for every session under every backend, and are the properties the tests in section 7 exist to falsify.

**FW-INV1 — No widening.** After `enforce()`, the held capability set can only shrink. No code path widens it. Verified by fuzzing spec/narrow sequences and asserting against probes.

**FW-INV2 — Descendant containment.** No descendant escapes or relaxes the confiner. Re-exec, setuid/setgid execution, and `prctl` attempts to clear `NO_NEW_PRIVS` do not restore access. Fuzzed over random spawn trees.

**FW-INV3 — Egress only via the gateway fd.** A confined process has no network path except the injected fd. Direct `connect()`, raw sockets, and direct DNS fail closed. Verified adversarially.

**FW-INV4 — Shading completeness.** No ungranted tool, resource, or prompt is invocable, whether or not it appears in any listing. Fuzzed over guessed names and out-of-band identifiers.

**FW-INV5 — Report soundness.** Anything reported `Enforced` is actually enforced, verified by paired allow/deny probes; anything the platform cannot enforce is reported, not claimed. This is the load-bearing invariant — it is what makes "good, not perfect" honest rather than hand-wavy.

**FW-INV6 — No silent open.** No capability-detection failure yields a running-but-unconfined session without an explicit, surfaced `Unenforceable`. Formwork fails closed or fails loud, never fails open-silent.

## 7. End-to-end tests

Each test names a concrete scenario with Pass/Fail conditions. Filesystem and process tests run against both the in-simulator/dry-run compile path and real enforcement, and — except where a test is platform-specific — against both the Linux and macOS backends.

### 7.1 Filesystem confinement

**FW-E2E-001: Granted read succeeds, ungranted read denied.** A session is granted `read(/work/project/**)`. It reads a file inside the project (succeeds) and attempts to read `/work/other-project/secrets.env` (denied). Run under both spawn-confined and confine-self postures. Pass: in-scope read returns bytes; out-of-scope read returns EACCES-class error under both postures. Fail: any out-of-scope read succeeds, or an in-scope read is denied.

**FW-E2E-002: Write scope and read-only enforcement.** Granted `read(/work/**), write(/work/project/**)`. Writes inside the project succeed; a write to `/work/reference/` (read-granted only) is denied; a write to `/etc/` is denied. Pass: exactly the write-granted paths are writable. Fail: any write outside write scope succeeds.

**FW-E2E-003: Sensitive-set subtraction under a broad grant.** Granted broad `read($HOME/**)` with the default sensitive set subtracted. The session reads an ordinary file under `$HOME` (succeeds) and attempts `~/.ssh/id_ed25519`, `~/.aws/credentials`, and a sibling project directory (all denied). Pass: ordinary reads succeed while every sensitive-set path is denied despite the broad grant. Fail: any sensitive-set path is readable.

**FW-E2E-004: Symlink escape blocked.** Inside a writable directory the session creates a symlink pointing at `/etc/passwd` and at an ungranted sibling project, then reads and writes through the symlink. Pass: access through the symlink is denied — the target's scope governs, not the link's location. Fail: the symlink grants access to the target.

**FW-E2E-005: Descendant inheritance.** The confined session spawns `bash`, which spawns a child process that attempts an out-of-scope read and attempts to relax its own sandbox. Pass: the grandchild is denied and cannot re-grant; confinement is intact across the tree. Fail: any descendant reads out of scope or widens the grant.

### 7.2 Network / egress

**FW-E2E-006: Direct egress denied.** With `net: Deny`, the session runs `curl https://example.com`. Pass: the connection fails closed (no route to a network the process can reach). Fail: any bytes leave the host by a path other than the gateway fd.

**FW-E2E-007: Direct DNS denied.** The session attempts name resolution via the system resolver (UDP/TCP 53). Pass: direct resolution fails; name resolution is available only through the gateway. Fail: the process resolves names via a direct network path.

**FW-E2E-008: Proxy-env-bypass attempt.** A program that ignores `HTTP_PROXY`/`ALL_PROXY` and opens a raw socket to a remote host is run. Pass: the direct connection is denied; there is no cooperative-only bypass. Fail: the raw connection succeeds.

**FW-E2E-009: Optional port tier (Linux, ABI-gated).** With `net: Ports([8080])` and a loopback service on 8080 and 9090, the session connects to each. Pass on capable kernels: 8080 succeeds, 9090 denied. On kernels below Landlock net support: the capability is reported Unenforceable and the test asserts the report matches the (fail-closed) behavior rather than asserting port-level enforcement. Fail: behavior contradicts the report.

### 7.3 Transport / fd seam

**FW-E2E-010: MCP over injected fd with zero net.** The agent has `net: Deny` and one injected fd to the gateway. It performs `initialize`, `tools/list`, and a `tools/call` round-trip. Pass: the full MCP exchange completes with no network capability inside the sandbox. Fail: the exchange requires any in-sandbox network or filesystem-socket access.

**FW-E2E-011: fd minting via SCM_RIGHTS.** After start, the agent requests a connection to a second backend over its control fd. The gateway opens the backend and passes back a new connected fd. Pass: the agent uses the new fd; no in-sandbox `connect()` occurs; the confiner's net-deny is unchanged. Fail: the agent must `connect()` itself, or net-deny had to be relaxed.

**FW-E2E-012: No dependence on socket-path gating.** A pathname UNIX socket for the gateway exists on disk. The test runs the full agent workload twice: once with filesystem access to the socket path granted, once denied. Pass: the workload succeeds identically in both cases (the agent uses the injected fd, not the path), and granting the path does not by itself create any egress. Fail: behavior depends on the socket's filesystem grant.

### 7.4 Gateway / MCP shading

**FW-E2E-013: Tool invisibility.** A backend exposes tools `read_file`, `write_file`, `http_fetch`. Policy grants `read_file` only. The agent calls `tools/list`. Pass: only `read_file` appears; the others are absent, not present-and-flagged. Fail: an ungranted tool appears in the listing.

**FW-E2E-014: Ungranted call refused as not-found.** The agent calls `http_fetch` by its exact name despite it being hidden. Pass: the call is refused, and the error is shaped like a genuine absence (matches a "unknown tool / not available" pattern) rather than "permission denied" — no oracle that confirms the tool exists. Fail: the call executes, or the error reveals that the tool exists but is blocked.

**FW-E2E-015: Resource and prompt shading.** The backend exposes resources and prompts; policy grants a subset. The agent lists and reads both. Pass: only granted resources/prompts are listed, readable, and gettable; ungranted ones are absent and non-fetchable by direct URI/name. Fail: any ungranted resource or prompt is listed or fetchable.

**FW-E2E-016: `list_changed` re-filtering.** After connection, the backend adds a new tool and emits `notifications/tools/list_changed`. The new tool is not in policy. Pass: the gateway re-applies policy; the new tool stays hidden and non-invocable. Fail: the runtime-added tool becomes visible or callable.

**FW-E2E-017: Sampling/elicitation policing.** A backend issues a server→client `sampling/createMessage` request. Policy denies sampling for that server. Pass: the request is refused at the gateway and never reaches the agent/model. Fail: the sampling request passes through.

**FW-E2E-018: Transparent passthrough for granted items.** For a granted tool, the request and response bytes observed by the agent are semantically identical to those from talking to the backend directly (compared against a direct-connection ground truth). Pass: no semantic divergence for granted traffic. Fail: the gateway mangles or reshapes granted request/response content.

**FW-E2E-019: Backend confinement recursion.** The gateway spawns a stdio MCP backend whose grant is `read(/srv/data/**)`. The backend attempts to read `/work/project` and to open a direct network connection. Pass: the backend is confined to its own grant — both attempts denied. Fail: the spawned backend has broader access than its grant.

### 7.5 Transparency & reuse

**FW-E2E-020: pytest reuse, zero denials.** A real Python repository with installed dependencies and a populated cache is present on the host. Under the default profile with the project writable and the interpreter/site-packages/cache read-only, the session runs `pytest`. Pass: the suite runs to its normal result with no sandbox-induced denials in the run log. Fail: any denial forces a test error that would not occur outside the sandbox.

**FW-E2E-021: node/npm reuse.** The session runs `npm test` (or a node script) against host `node_modules` and the npm cache, read-only. Pass: the script runs as it would unsandboxed, modulo network, with no denials on the happy path. Fail: a denial breaks an otherwise-passing run.

**FW-E2E-022: git works; push gated.** The session runs `git status`, `git diff`, and `git commit` within the project (succeed) and `git push` (network). Pass: local git operations succeed within scope; `git push` is blocked unless routed through the gateway. Fail: local git is broken by confinement, or push egresses directly.

**FW-E2E-023: Graceful degradation on optional paths.** A tool probes an optional, ungranted config path (e.g., `~/.config/tool/optional.toml`) as part of normal startup. Pass: the probe receives a standard errno and the tool continues with defaults. Fail: the probe crashes the tool or produces a sandbox-specific error the tool cannot handle.

### 7.6 Fidelity & operability

**FW-E2E-024: Report soundness.** For a rich spec, `compile()` yields a report. For every capability marked `Enforced`, a paired probe asserts the allowed operation succeeds and the denied operation fails. Pass: every `Enforced` claim survives its probe pair; nothing marked `Enforced` is bypassable by the probe suite. Fail: any `Enforced` capability is bypassable, or any probe contradicts the report.

**FW-E2E-025: Report honesty on a degraded host.** On a kernel lacking Landlock network support, a spec requesting `net: Ports([...])` is compiled and enforced. Pass: the net-port capability is reported Partial/Unenforceable, the fail-closed deny still holds (no egress), and observed behavior matches the report exactly. Fail: the report claims port enforcement that does not hold, or egress leaks.

**FW-E2E-026: Dry-run compile without enforcement.** `compile()` runs on a host lacking Landlock, and on macOS compiling a Linux profile. Pass: a policy and report are produced and nothing is enforced on the running process. Fail: `compile()` requires kernel support, mutates the process, or crashes.

**FW-E2E-027: Deterministic compile.** The same spec is compiled twice. Pass: byte-identical policy and report. Fail: any nondeterministic difference.

**FW-E2E-028: Cross-platform equivalence.** The same spec is enforced on Linux and macOS and exercised by the section 7.1–7.5 workloads. Pass: for the enforceable intersection, observable behaviors match across platforms; all differences are reflected in the FidelityReport, not in silent behavior. Fail: an observable behavior differs across platforms without a corresponding report entry.

### 7.7 Adversarial

**FW-ADV-001: Sandbox shedding.** The confined process attempts, in sequence: `execve` of a setuid binary, `prctl` to clear `NO_NEW_PRIVS`, and re-exec to try to drop the seccomp filter. Pass: all fail; confinement persists across every attempt. Fail: any attempt restores access or relaxes the filter.

**FW-ADV-002: TOCTOU / symlink race.** A loop races creating a symlink from a writable path to a sensitive target and accessing it, attempting to win between check and use. Pass: no access to the sensitive target succeeds; enforcement is at the kernel access, not a userspace pre-check. Fail: the race yields out-of-scope access.

**FW-ADV-003: Gateway bypass.** The agent extracts an MCP endpoint host from a granted tool's metadata and tries to reach that host directly. Pass: direct egress is denied; only the gateway fd reaches it. Fail: the agent egresses to the endpoint outside the gateway.

**FW-ADV-004: Shading oracle probe.** The agent enumerates candidate tool names and inspects error messages, response timing, and error codes to detect which hidden tools exist. Pass: refusals for hidden-but-real tools are indistinguishable from refusals for nonexistent tools — no oracle. Fail: any signal distinguishes a blocked-existing tool from a nonexistent one.

**FW-ADV-005: fd smuggling.** A confined stdio backend attempts to pass its own descriptors to the agent, or to open new sockets, to widen access. Pass: only the gateway mints egress fds; the backend cannot manufacture or hand off a broader capability. Fail: a confined process obtains or confers access beyond its grant via fd passing.

**FW-ADV-006: Cross-domain socket reach-around (Linux).** The confined process attempts to connect to an abstract UNIX socket and a pathname UNIX socket belonging to a host process outside the domain (e.g., a desktop bus or terminal multiplexer). Pass on capable kernels: blocked via UNIX-socket scoping; on kernels lacking it, the gap is reported Partial and the fail-closed net posture still prevents remote egress. Fail: the confined process talks to an out-of-domain service without the gap being reported.

## 8. Performance target

Confinement is setup-once plus per-operation overhead. The target keeps interactive agent loops responsive and the reuse story credible:

| Path | Target |
|---|---|
| Sandbox setup (spawn-confined launch) | < 50 ms added to process start |
| Per-filesystem-op overhead (Landlock/Seatbelt) | negligible; within noise of the raw syscall |
| Gateway round-trip added latency (granted tool) | < 2 ms over a direct backend call, local |
| Full default-profile compile + report | < 5 ms, no kernel calls |

A reuse-heavy workload (FW-E2E-020/021) must complete within a small bounded overhead of its unsandboxed baseline; a sandbox that materially slows the normal build/test loop violates FW-TRA6.

## 9. Platform backend matrix

**Linux — Landlock + seccomp (+ optional netns for the gateway side).**

- Filesystem read/write scope: Landlock filesystem access rights (available since ABI v1). Clean.
- Exec restriction: Landlock `FS_EXECUTE` on allowed paths, or seccomp on `execve`. Optional (FW-ISO4).
- Net default-deny: no Landlock net grants; deny is the absence of grant plus scope flags.
- Net port allowlist: Landlock `ACCESS_NET_CONNECT_TCP` (ABI v4+, port-only, no host filtering). Reported Unenforceable below v4.
- Cross-domain socket scoping: `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` and the pathname-socket scope are recent and coarse (they block sockets created outside the domain by parent/child relationship, not per-path allowlisting). Formwork uses them where present for FW-ADV-006 and reports the gap otherwise — and, critically, does **not** rely on them for the transport (that is the injected fd, FW-XR7).
- Anti-shedding: `NO_NEW_PRIVS` + seccomp baseline (FW-ISO8).

**macOS — Seatbelt (SBPL via `sandbox_init`).**

- Filesystem read/write scope: `file-read*` / `file-write*` with path filters. Clean.
- Exec restriction: `process-exec*` path filters. Optional.
- Net default-deny and host/port filtering: `network*` deny with `network-outbound` allowances. Seatbelt can filter by remote host/port and can gate UNIX-socket endpoints by path (the mechanism Chromium's macOS sandbox relies on) — so cross-domain socket control is cleaner here than on Linux.
- Descendant inheritance: the profile applies to the process and its children.

**Both.** The injected-fd transport behaves identically, since it is an inherited descriptor, not a mediated `connect()`. This is why FW-XR6/FW-XR7 hold across platforms rather than diverging on socket semantics.

**Fidelity summary (typical modern host).**

| Capability | Linux | macOS |
|---|---|---|
| fs read/write scope | Enforced | Enforced |
| net default-deny | Enforced | Enforced |
| net host allowlist (direct) | Unenforceable direct (use gateway) | Partial (Seatbelt remote filters) |
| net port allowlist (direct) | Enforced (ABI v4+) / else Reported | Enforced |
| exec allowlist | Enforced (optional) | Enforced (optional) |
| MCP tool/resource/prompt shading | Enforced (gateway) | Enforced (gateway) |
| cross-domain UNIX socket block | Partial (recent, coarse) | Enforced (path-gated) |
| filesystem invisibility (ENOENT) | Not provided (EACCES) | Not provided (EPERM/EACCES) |

## 10. Requirements ↔ tests traceability

| Requirement | Primary tests | Also covered by |
|---|---|---|
| FW-XR1 Fidelity honesty | FW-E2E-024, 025 | 026, INV5 |
| FW-XR2 Good-not-perfect boundary | (whole §3, §7.7) | ADV-001..006 |
| FW-XR3 Fail-closed egress | FW-E2E-006, 025 | 007, 008, ADV-003 |
| FW-XR4 Descendant inheritance | FW-E2E-005 | ADV-001, 005, INV2 |
| FW-XR5 Single privileged broker | FW-E2E-019 | 010, ADV-005 |
| FW-XR6 Behavioral parity | FW-E2E-028 | 024 |
| FW-XR7 fd-injection transport | FW-E2E-010, 012 | 011, ADV-006 |
| FW-CAP1 Enumerable vocabulary | FW-E2E-013, 001 | — |
| FW-CAP2 Monotonic narrowing | FW-E2E-005 | INV1 |
| FW-CAP3 Subtractive default profile | FW-E2E-003, 020 | 021, 022 |
| FW-CAP4 Invisibility/denial split | FW-E2E-013, 014 | 001, 023 |
| FW-CAP5 Inspectable interpreter | FW-E2E-026, 027 | 024 |
| FW-ISO1 Read confinement | FW-E2E-001 | 003, 004 |
| FW-ISO2 Write confinement | FW-E2E-002 | 004 |
| FW-ISO3 Net default-deny | FW-E2E-006 | 007, 008, INV3 |
| FW-ISO4 Optional exec restriction | FW-ADV-001 | — |
| FW-ISO5 Optional port tier | FW-E2E-009 | 025 |
| FW-ISO6 Two postures | FW-E2E-001 | — |
| FW-ISO7 Capability detection | FW-E2E-025, 026 | INV6 |
| FW-ISO8 Anti-shedding baseline | FW-ADV-001 | 002, INV2 |
| FW-GW1 Transport-agnostic backends | FW-E2E-010 | 019 |
| FW-GW2 Tool shading | FW-E2E-013, 014 | ADV-004 |
| FW-GW3 Full-surface policy | FW-E2E-015, 016, 017 | — |
| FW-GW4 Single door | FW-E2E-012 | ADV-003 |
| FW-GW5 Backend confinement | FW-E2E-019 | ADV-005 |
| FW-GW6 fd minting | FW-E2E-011 | 010 |
| FW-GW7 Least-privilege gateway | FW-E2E-019 | ADV-003 |
| FW-GW8 Transparent passthrough | FW-E2E-018 | 020, 021 |
| FW-TRA1 Ambient reuse | FW-E2E-020, 021 | 022 |
| FW-TRA2 Toolchains run clean | FW-E2E-020, 021, 022 | 023 |
| FW-TRA3 Sensitive-set subtraction | FW-E2E-003 | 004 |
| FW-TRA4 Graceful denial | FW-E2E-023 | 020, 021 |
| FW-TRA5 Writable working set | FW-E2E-002, 022 | 020 |
| FW-TRA6 Low overhead | §8 targets | 020, 021 |
| FW-FID1 Per-capability report | FW-E2E-024 | 025 |
| FW-FID2 Dry-run / audit | FW-E2E-026 | 027 |
| FW-FID3 Runtime observability | FW-E2E-024 | — |
| FW-FID4 Deterministic compile | FW-E2E-027 | 026 |

## 11. Open questions

**Naming of the layers.** Whether *Formwork* names the whole system or the confiner alone, with a separate name for the gateway. The mould metaphor argues for confiner-only; product convenience argues for the umbrella. Unresolved.

**Exec restriction in v1.** FW-ISO4 is off by default and nearly free to implement. Whether it ships enabled-optional in v1 or is deferred is a scope call; confining fs + net already contains most of what a rogue exec could do.

**fd-minting default.** Whether the default is pre-open-all-known-fds at spawn (simple, requires the connection set to be known up front) or a control-fd with on-demand `SCM_RIGHTS` minting (general, slightly more machinery). Likely pre-open as default with on-demand as the escape hatch.

**Sensitive-set discovery.** How much of the subtracted set (FW-TRA3) is auto-detected (known credential locations, cloud-config dirs, keychains, browser profiles) versus configured. Auto-detection improves safety-by-default but risks missing new locations; the fail-closed answer is to deny a broad known-sensitive superset by default and let callers narrow.

**Linux gateway egress isolation build-vs-buy.** Whether the gateway's own network confinement reuses `bubblewrap`/`pasta`/`slirp4netns` for its netns setup or drives `unshare`/nftables directly. Out of the agent's confinement path (FW-XR7), but a real implementation decision for FW-GW7.

**Windows.** Out of scope for this proposal. If needed later, the analogous primitives (AppContainer, Restricted Tokens, Named Pipes for the fd seam) would be a third backend behind the same compiler.

## 12. Implementation order

Kernel-mechanism-first, honesty-first, reuse-validated-early:

1. **Compiler + FidelityReport + dry-run**, with the deterministic-compile and dry-run tests (FW-E2E-026, 027). No kernel calls; runs anywhere, including CI on macOS for Linux policies.
2. **Linux confiner** (Landlock fs + seccomp baseline + net-deny), spawn-confined posture, with the filesystem, descendant, and anti-shedding tests (FW-E2E-001..005, ADV-001, 002) and report-soundness (FW-E2E-024).
3. **macOS confiner** (Seatbelt), same test set, then cross-platform equivalence (FW-E2E-028).
4. **Reuse validation** against real toolchains (FW-E2E-020..023) — early, because if the default profile is not transparent enough to reuse the environment, the philosophy has failed and the profile needs rework before anything else is built on it.
5. **fd-injection transport** and the seam tests (FW-E2E-010, 011, 012), establishing that the agent never depends on in-sandbox connect or socket-path gating.
6. **Gateway** (transport-agnostic backends, shading, full-surface policy, transparent passthrough, backend-confinement recursion) with FW-E2E-013..019 and ADV-003, 004, 005.
7. **Degraded-host honesty and optional tiers** (FW-E2E-009, 025, ADV-006), confirming Formwork reports rather than pretends when a kernel cannot enforce a requested capability.

If steps 1–4 pass, Formwork is a transparent, reusable filesystem confiner that behaves the same on both platforms and tells the truth about itself. If steps 5–7 pass, it is a complete agent sandbox: one privileged broker, everything else in a mould, egress forced through a policy gateway, and every claim backed by a mechanism or reported as a gap.