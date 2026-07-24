# Formwork: an OS-level sandbox for agent sessions

Working name. Design proposal with end-to-end test specification.

Formwork is a sandboxing substrate for agent sessions. It turns the four capabilities that touch the real operating system — read, write, exec, net — into enforceable boundaries, on Linux and macOS, for an agent process and every child it spawns.

Formwork is standalone. It takes a capability blueprint and produces an enforced sandbox plus an honest report of what it could and could not enforce. A host — Claude Code, OpenCode, or a bare shell wrapper — depends on Formwork; Formwork depends on nothing above it. The name is the metaphor: formwork is the temporary mould that contains poured concrete until it cures — a frame that constrains where the material can go. That is a sandbox around a process tree.

## 1. Design philosophy: good isolation, maximal reuse

The load-bearing decision in this design is that Formwork targets **good isolation, not perfect isolation**. This is a deliberate scoping choice, not a limitation to be apologized for, and it drives most of the requirements below.

The goal is a boundary that reliably contains an agent — and code the agent runs, and MCP servers it fronts — from casually or accidentally reading, writing, or exfiltrating things outside its lane, including when the agent is driven by a prompt-injected or otherwise adversarial instruction stream. The goal is **not** to withstand an adversary writing kernel exploits against Landlock or Seatbelt. Formwork raises the bar a great deal and fails closed on egress; it does not claim to be an airtight security boundary against local privilege escalation or a kernel zero-day. Section 3 states this threat model precisely, and every enforcement claim in this document is scoped to it.

The second half of the philosophy is **transparency and reuse**. Formwork is not a minimal-from-empty jail that the agent must have a bespoke image built for. It starts from the real, ambient environment — the host's interpreters, toolchains, shared libraries, and language package caches — and *subtracts* a sensitive set (credentials, keys, other projects, browser profiles). The confined agent should be able to run `pytest`, `npm test`, `git`, and a normal build against the environment that is already there, with zero denials on the common path. Isolation the agent constantly trips over is isolation that gets turned off. Formwork earns its keep by being nearly invisible to well-behaved work while remaining a hard wall around the sensitive set and all network egress.

These two halves are in tension, and the resolution is the third principle: **honesty**. Formwork always reports what it actually enforces on the current platform and kernel, and never silently claims containment it cannot deliver. A caller that needs a stronger guarantee than the current host can provide learns that from the fidelity report rather than discovering it in an incident.

## 2. Architecture overview

Formwork has three enforcement arms driven by a single capability compiler, with an fd seam to the agent. The **launcher** runs first — the pre-spawn arm that constructs the confined child's environment, strips catalog credentials (variable absent, not denied), and write-protects its own policy inputs before control transfers. Then the **confiner** (the hard OS boundary) and the **gateway** (the soft MCP boundary) hold for the lifetime of the session.

```
┌───────────────────────────────────────────────────────────────────────┐
│  CAPABILITY BLUEPRINT (unveil-style; layered file+CLI surfaces)       │
│  read(path) · write(path) · [exec(path)] · net-posture · env ·        │
│  allow-credentials · mcp(server → visibility)                         │
├───────────────────────────────────────────────────────────────────────┤
│  COMPILER (pure; no kernel calls; credential catalog is an input)     │
│  blueprint → { launcher, confiner, gateway } + FidelityReport         │
├───────────────────────┬─────────────────────┬─────────────────────────┤
│ LAUNCHER (pre-spawn)  │ CONFINER (hard)     │ GATEWAY (soft)          │
│ env construction &    │ Linux: Landlock     │ MCP-aware policy proxy  │
│ credential strip      │  + seccomp          │ shades tools/resources/ │
│ → var absent          │ macOS: Seatbelt     │ prompts; fronts stdio + │
│ policy-input write-   │ fs r/w, net-deny,   │ http/sse backends;      │
│ protect (FW-XR8)      │ descendant inherit  │ mints fds (SCM_RIGHTS)  │
└───────────────────────┴──────────┬──────────┴────────────┬────────────┘
                                   │ confines              │ one control fd
                                   ▼                       ▼
                           ┌───────────────┐       ┌───────────────┐
                           │  AGENT        │◄─fd── │ (no net, no fs│
                           │  (confined)   │ seam  │ except the fd)│
                           └───────────────┘       └───────────────┘
                                   ▲
                                   │ confines (recursion)
                           ┌───────────────┐
                           │ stdio MCP     │  spawned by gateway, itself
                           │ backend       │  confined by the same confiner
                           └───────────────┘
```

Four things make this hang together:

**The launcher is where non-kernel capabilities are applied.** Landlock and Seatbelt cannot shade an environment variable — it is a string in the process's environment block, not a filesystem object. But Formwork *spawns* the confined process, so it constructs the child's environment: shading a variable is simply not copying it into the spawn. The child comes up having never had it — stronger, in kind, than a path denial (a denied path still announces a wall; a stripped variable is indistinguishable from never-configured, [FW-INV9](#fw-inv9)). The one contingency: it holds only while Formwork is the launching process, which the report must disclose ([FW-CRED8](#fw-cred8)).

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
- Credential *content* scanning. Credential coverage is location-based only — the typed catalog plus a generic backstop (FEP-2 FW-CRED); Formwork never inspects bytes to decide what is secret.
- Perfect unveil-style invisibility of the filesystem. Formwork accepts EACCES-style denial (section 4); it does not emulate ENOENT for every ungranted path.

## 4. The capability blueprint and its interpreter

Formwork consumes a finite, enumerable **Blueprint** — the unveil/pledge lineage, narrowed to what an OS sandbox can carry. (The name fits the construction metaphor: formwork is the mould; the Blueprint is the plan the mould is built from. It is defined once, here, and used for nothing else.)

```
extends: [blueprint]          # base Blueprints/presets this one layers over (FW-BP3)
read(path-pattern)            # filesystem read
write(path-pattern)           # filesystem write + create (implies read of the same)
write-no-create(path-pattern) # write existing files but NOT create new ones — the split (FW-CAP9)
subtract(path-pattern)        # carve a sensitive hole out of the read+write grant (deny wins)
write-subtract(path-pattern)  # write-deny but keep readable: tamper vectors (FW-TRA7)
exec(path-pattern)            # OPTIONAL: execute only these binaries (off by default)
net: Deny                     # default: no direct egress at all
   | Ports([u16])             # optional: allow direct TCP connect to these ports
env: Passthrough              # default: inherit the launcher's environment
   | Allowlist([name])        # only the named vars survive
   | Scrub({allow, deny})     # drop secret-shaped vars by name/value, minus an allowlist (FW-ENV1/2)
allow-credentials: [type]     # lift named credential-catalog types — the ONLY un-deny (FW-CRED5)
discovery.auto-widen: [path]  # zone in which a learning run may self-grant (FW-DISC4)
mcp(server): {                # per-MCP-server visibility policy
    tools:     Allow([...]) | AllowAll | Deny,
    resources: Allow([...]) | AllowAll | Deny,
    prompts:   Allow([...]) | AllowAll | Deny,
    sampling:  Allow | Deny,     # server→client sampling requests
    elicitation: Allow | Deny,   # server→client elicitation requests
}
```

The compiler is the single authority that maps this blueprint to concrete mechanisms. It is pure — it never touches the kernel — so it runs in CI on any box, lets a Linux policy be compiled and inspected on a Mac, and is deterministic. It takes the credential catalog (§5.9) as an explicit input — the floor cannot be forgotten, only resolved — and emits the launcher, confiner, and gateway policies plus a `FidelityReport`.

The Blueprint is a typed, versioned schema with **multiple surfaces onto one model** ([FW-BP1](#fw-bp1)): the TOML file is one serialization; the CLI flags are another, applied as an override layer. It is deliberately a standard serialization, not a bespoke DSL — a Blueprint is data with no control flow, and a policy language would pay SELinux's legibility cost to describe a struct. If real logic is ever required, the answer is an existing configuration language, never a new one.

A third way to write the same grants (FEP-3): flat **verb** rules (`"<verb>:<path>"`, e.g. `deny:~/.ssh`) and a `mode` posture ([FW-BP6](#fw-bp6)/[FW-BP7](#fw-bp7)), evaluated **hide → allow → deny-terminal** ([FW-CAP8](#fw-cap8)). Verbs desugar into the fields above at the CLI edge — `read`/`readwrite`/`modify`/`allow`/`readexec`/`exec`/`deny`, where `modify` is the write-without-create grade of the create/write split ([FW-CAP9](#fw-cap9)) — and `mode` (`unveil`/`subtractive`) aliases `[fs] read-mode`.

Two semantics choices, both settled earlier in design:

- **EACCES denial is acceptable; invisibility is preferred only where free.** Filesystem denials surface as the platform's natural errno (EACCES on Landlock, EPERM/EACCES on Seatbelt). Formwork does not build a mount-namespace or FUSE layer to fake ENOENT. The one place invisibility *is* cheap and *is* required is MCP tool/resource/prompt shading at the gateway, where an ungranted item is simply absent from the listing. For the sensitive *subset*, metadata is also denied where a backend supports it (Seatbelt `file-read-metadata`), so a credential's existence, size, and mtime do not leak through `stat` ([FW-CAP7](#fw-cap7)); where a backend cannot (Landlock), that residual is reported Partial rather than left as a blanket concession.
- **The default profile is subtractive, not minimal.** Rather than granting an empty world and adding paths, the default profile grants broad read over the ambient environment (system prefixes, interpreters, shared libraries, standard tool locations, language caches) and subtracts a configured sensitive set. This is the reuse principle expressed as policy.

Five further points pin the vocabulary above down so it is unambiguous to the compiler and gateway:

- **MCP item identity.** Shading matches items by their natural MCP identifier: tools and prompts by `name`, resources by `uri`, and resource templates by `uriTemplate`. A `resources` allow list therefore contains URIs (for concrete resources, matched on `resources/list` and `resources/read`) and/or URI templates (for `resources/templates/list`); tool and prompt lists contain names. An item that lacks its identifier field is treated as ungranted (fail-closed). This is what keeps the resource axis consistent across list, read, and templates rather than silently matching one of them on a different key.
- **MCP identifiers match exactly or by anchored pattern, with a terminal deny ([FW-GW9](#fw-gw9)).** Each axis is an **allow** scope minus a terminal **deny** list. A list entry is either an exact identifier or an anchored regex written `/…/` — compiled as `\A(?:…)\z`, so it matches the whole identifier (`/get_.*/` covers `get_issue`, not the substring hit `forget_me`). `permits(id)` holds iff the allow scope admits `id` **and** no deny pattern matches it, so a deny always wins over any allow — the same deny-terminal bias as the fs model ([FW-CAP8](#fw-cap8)), here over protocol names rather than paths. Authoring is one shape on every axis: the keyword `"allow-all"`/`"deny"`, `{ allow = [...] }`, `{ allow = [...], deny = [...] }`, or a deny-only `{ deny = [...] }` (omitting `allow` means "all", an explicit `allow = []` means "none", and an empty `{}` is a loud error). Unlike the fs axis this is a *userspace* string match in the privileged gateway, not a kernel path rule, so a general regex here is sound where a general fs glob is not ([FW-BP4](#fw-bp4)): a mismatch shades one protocol frame, never silently unroots a kernel deny. A `/…/` that will not compile fails loud at parse ([FW-INV6](#fw-inv6)).
- **Grant paths must be representable.** Grant, write, and `subtract` paths are canonicalized against the real filesystem at enforce time (symlink and firmlink resolution) so kernel path-matching lines up. A resolved path that cannot be faithfully rendered into the backend's policy language — e.g. a non-UTF-8 byte path — makes enforcement **fail loud**, never emit a lossy rule that might silently not match. A `subtract` hole that failed to match would be a silent fail-open of the sensitive set, which [FW-INV6](#fw-inv6) forbids. Patterns are absolute, an any-depth basename form (`**/.env`) that matches a trailing component at any depth, or the prefix-anchored refinement (`<prefix>/**/<suffix>`) that matches only below an absolute prefix ([FW-CAP6](#fw-cap6)); no `..` traversal exists, and all forms canonicalize deterministically ([FW-FID4](#fw-fid4)).
- **Path sigils are a closed set, expanded at the CLI edge.** `~` → `$HOME` and `$CWD` → the launch directory, expanded *before* patterns reach the compiler, so a grant can be written relative to the project it runs in ([FW-BP5](#fw-bp5)). Fixed tokens only — never general `$VAR` interpolation, since the environment is exactly what the launcher strips ([FW-CRED2](#fw-cred2)). An unresolvable sigil fails loud, never silently widening ([FW-INV6](#fw-inv6)).
- **Layers merge in a fixed order, and deny beats allow.** Baseline (the fail-closed empty Blueprint plus the credential-catalog floor) → `extends` chain (depth-first, bases before deriveds) → the file → CLI overrides ([FW-BP2](#fw-bp2)). Postures are last-set-wins; path sets merge additively; at any layer and any precedence, deny/subtract wins over allow — the only un-deny anywhere is the typed credential exclude ([FW-BP4](#fw-bp4), [FW-CRED5](#fw-cred5)).
- **Environment is a capability, applied at spawn.** The `env` posture ([FW-ENV1](#fw-env1)) governs what environment the confined child receives — passthrough, an allowlist of names, or a scrub of secret-shaped vars. The launcher, not the confiner, builds the child's environment: the credential-catalog strip partitions first ([FW-CRED4](#fw-cred4)), then the posture filters what remains; the `FidelityReport` carries the verdict like any other capability. The default profile's scrub ([FW-ENV2](#fw-env2)) is heuristic, so it is reported Partial, never a silent over-claim.

## 5. Requirements

Every requirement, invariant, and end-to-end test in this document carries a stable identifier: `FW-<FAMILY><n>` for requirements (families: XR, CAP, ISO, GW, TRA, FID, ENV, BP, CRED, DISC — plus EGR, reserved in `docs/fep-1.md`), `FW-INV<n>` for invariants (§6), and `FW-E2E-<nnn>` / `FW-ADV-<nnn>` for tests (§7). An ID is minted once, in the document that defines it, and is never renumbered or reused; enhancement proposals continue the sequences and reserve blocks at adoption. Each definition carries an HTML anchor named for the lowercase ID, so any document can cite a requirement as a link — `[FW-CAP2](formwork.md#fw-cap2)` — and code cites the bare, greppable ID. The full convention is doctrine (`constitution.md`, Requirements & identifiers) and CI-checked (`py/harness/test_requirements.py`).

### 5.1 Cross-cutting requirements

| Req | Requirement |
|---|---|
| <a id="fw-xr1"></a>**FW-XR1** Fidelity honesty | Every enforcement Formwork claims is backed by a real mechanism on the current host, or is reported as Partial/Unenforceable. `enforce()` never silently downgrades a claim made by `compile()`. |
| <a id="fw-xr2"></a>**FW-XR2** Good-not-perfect boundary | Formwork is a containment boundary against accidental, careless, and prompt-injected overreach and against untrusted code the agent runs — not against kernel/LSM exploitation. Every guarantee in this document is scoped to section 3. |
| <a id="fw-xr3"></a>**FW-XR3** Fail-closed egress | Absent a working confiner, network defaults to full deny. The agent reaches the world only through the gateway fd. No configuration and no capability-detection failure produces silent open egress. |
| <a id="fw-xr4"></a>**FW-XR4** Descendant inheritance | Confinement applies to the confined process and every descendant. A child cannot shed, relax, or widen it. |
| <a id="fw-xr5"></a>**FW-XR5** Single privileged broker | Exactly one component (the gateway) holds real network and broad filesystem access. The agent and all stdio MCP backends are confined by the same confiner. |
| <a id="fw-xr6"></a>**FW-XR6** Behavioral parity | An identical blueprint yields equivalent observable behavior for the enforceable intersection across Linux and macOS. Platform divergence appears only in the FidelityReport, never as a silent behavior change. |
| <a id="fw-xr7"></a>**FW-XR7** fd-injection transport | The agent reaches the gateway via an inherited fd. Formwork never depends on an in-sandbox `connect()` nor on the filesystem sandbox selectively *allowing* a socket path. |
| <a id="fw-xr8"></a>**FW-XR8** No agent-influenced escalation | No mechanism lets a confined process — or its instruction stream — disable, weaken, retry-outside, or reconfigure its own confinement. The policy is compiled and installed *before* the process runs ([FW-CAP2](#fw-cap2): narrowing only; widening does not exist). Any escalation a host chooses to offer is an out-of-band action on an unconfined process, never a signal the confined process can emit. |
| <a id="fw-xr9"></a>**FW-XR9** Surface fail-fast | A subcommand that cannot deliver its promise on the current host fails *before* consuming the user's work (their run, their time), naming the missing mechanism and the nearest alternative. The command-surface sibling of [FW-INV5](#fw-inv5)/[FW-INV6](#fw-inv6): enforcement honesty says a wall that isn't real is reported, this says a *feature* that isn't real here refuses up front — running an entire workload and only then announcing the point of the command was impossible is a silent overpromise even when every byte was logged. [FW-E2E-062](#fw-e2e-062) pins the `learn` instance; the rule governs every future observe/probe/stream surface. |

### 5.2 Capability model (FW-CAP)

| Req | Requirement |
|---|---|
| <a id="fw-cap1"></a>**FW-CAP1** Enumerable vocabulary | The blueprint is a finite enumeration of read/write/subtract/exec/net/env/mcp — the fs write grade admits a create/write split ([FW-CAP9](#fw-cap9)). No mechanism accepts natural language and produces a grant. It is authored as typed fields or, equivalently, as flat verb rules ([FW-BP6](#fw-bp6)). |
| <a id="fw-cap2"></a>**FW-CAP2** Monotonic narrowing | A session may narrow its own grant but never widen it. A child's grant is a subset of its parent's. |
| <a id="fw-cap3"></a>**FW-CAP3** Subtractive default profile | The default profile is broad-read over the ambient environment minus a configured sensitive set, not minimal-from-empty. *(Realized concretely by FEP-2's compiled-in credential catalog + backstop, applied as a floor under every blueprint — [FW-CRED4](#fw-cred4).)* |
| <a id="fw-cap4"></a>**FW-CAP4** Invisibility for MCP, denial for fs | Ungranted MCP tools/resources/prompts are absent from listings and non-invocable. Ungranted filesystem paths may return EACCES rather than ENOENT. |
| <a id="fw-cap5"></a>**FW-CAP5** Single inspectable interpreter | The compiler is the sole blueprint→mechanism authority, and its output (compiled policy + report) is inspectable without enforcing. |
| <a id="fw-cap6"></a>**FW-CAP6** Anchored & basename patterns | Beyond absolute paths, the pattern vocabulary admits an any-depth basename form (`**/.env`) that matches a trailing component at any depth within a grant, and (FEP-2) its prefix-anchored refinement `<prefix>/**/<suffix>` that matches only below an absolute prefix. All forms canonicalize deterministically ([FW-FID4](#fw-fid4)) and stay fail-loud on non-representable resolution; no relative `..` traversal is introduced. |
| <a id="fw-cap7"></a>**FW-CAP7** Metadata denial for the sensitive set | Where the backend can express it (Seatbelt denies `file-read-metadata` per path), subtracted sensitive paths are denied at the metadata layer too, so existence/size/mtime of credentials do not leak via `stat`. Where it cannot (Linux/Landlock), the residual is reported Partial — narrowing the §3 EACCES-not-ENOENT concession specifically for credentials. |
| <a id="fw-cap8"></a>**FW-CAP8** Three-layer evaluation, deny-terminal | Path access resolves in a fixed order: (1) **hide** — unlisted paths are inaccessible (EACCES-shaped, not ENOENT; the report says so, [FW-CAP4](#fw-cap4)); (2) **allow** — grants punch holes, more specific wins within the layer; (3) **deny** — applied last and terminal. No allow at any layer, and no rule order, overrides a deny. The only removal of a deny is the typed credential exclude ([FW-CRED5](#fw-cred5)), which deletes the deny entry rather than overriding it. The structural form of [FW-BP4](#fw-bp4)/[FW-INV8](#fw-inv8). *(Added by FEP-3.)* |
| <a id="fw-cap9"></a>**FW-CAP9** Verb grammar & create/write split | The fs grant vocabulary is a closed verb set — `read`/`readonly`, `readwrite`, `modify`, `allow`, `readexec`, `exec`, `deny`. `modify` grants read + modify-existing but **not create**; `allow`/`readwrite` additionally grant create. The weaker grade is a distinct word (`modify`, not a bare `write`) so it never reads as full write — everything named "write" (the `writes` field, the `--write` flag, `readwrite`) grants create. Enforced on both backends: Landlock drops the `Make*` rights, Seatbelt allows every `file-write-*` op except `file-write-create`. *(Added by FEP-3; the `modify`/`writes-no-create` axis is the create/write split of [FW-CAP1](#fw-cap1).)* |

### 5.3 OS isolation / confiner (FW-ISO)

| Req | Requirement |
|---|---|
| <a id="fw-iso1"></a>**FW-ISO1** Read confinement | Enforce filesystem read scope (Landlock FS access rights / Seatbelt `file-read*`). |
| <a id="fw-iso2"></a>**FW-ISO2** Write confinement | Enforce filesystem write scope; write to a read-only-granted path is denied. |
| <a id="fw-iso3"></a>**FW-ISO3** Net default-deny | Deny all direct network egress by default (no Landlock net grants + scope flags / Seatbelt `network*` deny), except the injected fd. |
| <a id="fw-iso4"></a>**FW-ISO4** Optional exec restriction | When set, restrict execution to an allowlist (Landlock `FS_EXECUTE` on paths / seccomp on `execve` / Seatbelt `process-exec*`). Off by default (transparency). |
| <a id="fw-iso5"></a>**FW-ISO5** Optional port tier | When requested, allow direct TCP connect to an explicit port set (Landlock net ABI v4+); report Unenforceable on older kernels. |
| <a id="fw-iso6"></a>**FW-ISO6** Two postures | Support spawn-confined (launcher confines a child; preferred) and confine-self (process restricts itself; pledge-style). |
| <a id="fw-iso7"></a>**FW-ISO7** Capability detection | Detect Landlock ABI / seccomp / Seatbelt availability at runtime and degrade with a report; never crash and never silently no-op. |
| <a id="fw-iso8"></a>**FW-ISO8** Anti-shedding baseline | On Linux, set `NO_NEW_PRIVS` and a seccomp baseline that blocks confinement-shedding and privilege-escalation paths, while remaining permissive enough that normal toolchains run unmodified. |
| <a id="fw-iso9"></a>**FW-ISO9** Exec as a verb | Execution is expressed as the `exec`/`readexec` verb rather than a separate posture; off by default (no verb grants execute ⇒ execute is ungoverned/transparent). Reframes [FW-ISO4](#fw-iso4); the internal exec posture is unchanged (verbs desugar onto it). No traversal token — a covering-directory grant applies. The exec grant confers execute only, not read, on both backends ([FW-XR6](#fw-xr6) parity). *(Added by FEP-3.)* |

### 5.4 Gateway / MCP (FW-GW)

| Req | Requirement |
|---|---|
| <a id="fw-gw1"></a>**FW-GW1** Transport-agnostic backends | Front stdio and http/sse/streamable-http MCP servers uniformly behind one agent-facing interface. |
| <a id="fw-gw2"></a>**FW-GW2** Tool shading | Ungranted tools are absent from `tools/list` **and** `tools/call` on a guessed name is refused. |
| <a id="fw-gw3"></a>**FW-GW3** Full-surface policy | Policy covers resources (list/read/templates), prompts (list/get), `list_changed` re-filtering, and server→client sampling/elicitation. |
| <a id="fw-gw4"></a>**FW-GW4** Single door | Shading is binding because the confiner removes every alternative path to the backend. |
| <a id="fw-gw5"></a>**FW-GW5** Backend confinement | stdio backends the gateway spawns are themselves confined by the confiner to their own grant. |
| <a id="fw-gw6"></a>**FW-GW6** fd minting | The gateway supplies connection fds to the agent (pre-opened at spawn or minted on demand via `SCM_RIGHTS`); the agent never performs an in-sandbox `connect()`. |
| <a id="fw-gw7"></a>**FW-GW7** Least-privilege gateway | The gateway holds real network only to allowlisted MCP endpoints, and its own filesystem scope is minimal. |
| <a id="fw-gw8"></a>**FW-GW8** Transparent passthrough | For *granted* items, the gateway is protocol-transparent: no semantic mangling, so agents behave as if talking to the backend directly. |
| <a id="fw-gw9"></a>**FW-GW9** Pattern-matched shading | Each shaded axis (tools/prompts by `name`, resources/templates by `uri`/`uriTemplate`, [design §4](#fw-cap4)) carries an **allow** scope and a terminal **deny** list. Entries are exact identifiers or anchored regex written `/…/`, matched against the *whole* identifier (`\A(?:…)\z`), so an allow pattern cannot admit a substring nor a deny over-reach onto an unrelated name. `permits(name)` holds iff the allow scope admits it **and** no deny matches — deny is terminal, the MCP-surface form of the deny-terminal fs model ([FW-CAP8](#fw-cap8)/[FW-BP4](#fw-bp4)) applied to protocol identities. This is a *userspace* string match in the privileged gateway, never a kernel path boundary, so it does not reopen the "no general glob" fs doctrine ([FW-BP4](#fw-bp4)); the `regex` engine matches in guaranteed linear time, so a hostile blueprint pattern cannot wedge the gateway. A `/…/` that will not compile, and an ambiguous empty policy table, fail loud at parse ([FW-INV6](#fw-inv6)) rather than degrading to a silent deny-all or allow-all; pattern sets canonicalize deterministically ([FW-FID4](#fw-fid4)) and refusals stay oracle-free ([FW-ADV-004](#fw-adv-004)) since a deny-hidden name refuses exactly as a nonexistent one does. |

Note (stability, not a security property per §3): the gateway parses newline-delimited JSON-RPC from less-trusted peers — the agent and the stdio backends it spawns — and bounds each frame to a fixed maximum, failing the connection closed on overflow rather than buffering without limit. This is a robustness bound in the spirit of §3's "rlimit bounds for stability," not a claim of DoS resistance (which §3 scopes out). A dead gateway is fail-closed regardless: the confined agent has lost its only door.

### 5.5 Transparency & environment reuse (FW-TRA)

| Req | Requirement |
|---|---|
| <a id="fw-tra1"></a>**FW-TRA1** Ambient reuse | The confined process reuses host interpreters, toolchains, shared libraries, and language package caches, read-only by default. |
| <a id="fw-tra2"></a>**FW-TRA2** Toolchains run clean | Under the default profile, common toolchains (python/pytest, node/npm, git, a C build) run unmodified with zero denials on the happy path. |
| <a id="fw-tra3"></a>**FW-TRA3** Sensitive-set subtraction | Credentials, SSH/cloud config, keychains, other projects, and browser profiles are denied/hidden by default even under broad grants. *(Superseded and expanded by the typed credential catalog — §5.9, [FW-CRED1](#fw-cred1)..9 — which adds the env-var arm and exclude-by-type.)* |
| <a id="fw-tra4"></a>**FW-TRA4** Graceful denial | Denials surface as standard errno, never as sandbox-specific crashes; a tool probing an optional ungranted path continues rather than aborting. |
| <a id="fw-tra5"></a>**FW-TRA5** Writable working set | The project directory, a scratch/tmp area, and (optionally) build caches are writable, so the agent can do real work and persist within scope. |
| <a id="fw-tra6"></a>**FW-TRA6** Low overhead | Confinement setup and per-operation overhead stay within the section 8 performance target so interactive agent loops remain responsive. |
| <a id="fw-tra7"></a>**FW-TRA7** Execution-vector write protection | A default write-subtract set masks code-execution and policy-tampering vectors even inside writable grants — `.git/hooks/**`, `.git/config`, `.mcp.json`, editor/agent-config dirs (`.vscode`/`.idea`/`.claude`/…), shell rc files — so a confined agent cannot plant something that later runs unsandboxed. Deny wins over the write grant; the paths stay readable so tooling is unbroken. |
| <a id="fw-tra8"></a>**FW-TRA8** Agent-state & local-secret coverage | The sensitive set covers agent-tool state holding OAuth creds/transcripts (`~/.claude*`, `~/.codex/**`, `~/.gemini/**`, `~/.cursor/**`, the whole `~/.docker/**`) and project-local secrets (`**/.env`), denied even under a broad read grant. |

### 5.6 Operability & fidelity (FW-FID)

| Req | Requirement |
|---|---|
| <a id="fw-fid1"></a>**FW-FID1** Per-capability report | `compile()` returns, per capability: `Enforced \| Partial(reason) \| Unenforceable(reason)`, plus backend and semantics (hide vs deny). *(Extended by FEP-2 with a per-credential-type section labeling each arm — `enforced-via-launcher` vs OS sandbox — and the launcher-contingency disclosure, [FW-CRED8](#fw-cred8).)* |
| <a id="fw-fid2"></a>**FW-FID2** Dry-run / audit | Produce the compiled policy and report without enforcing (CI on non-capable boxes; cross-platform policy development). |
| <a id="fw-fid3"></a>**FW-FID3** Runtime observability | Emit a structured record of grants and denials at runtime, suitable for a host's journal when embedded, or standalone logging otherwise. |
| <a id="fw-fid4"></a>**FW-FID4** Deterministic compile | The same blueprint compiles to a byte-identical policy and report. |
| <a id="fw-fid6"></a>**FW-FID6** Rule provenance & explain | Each effective fs/exec rule carries the layer it came from — `built-in \| profile \| file \| cli \| discovered`. `formwork explain <path>` reports the read, write, and exec verdict for a path, the rule that decides each under the deny-terminal model ([FW-CAP8](#fw-cap8)), and that rule's provenance, without enforcing. Exec is a separate axis ([FW-ISO9](#fw-iso9)): the read/write credential floor never governs it, matching enforcement where an exec grant confers execute only ([FW-XR6](#fw-xr6)). It reflects the merged Blueprint (like `compile`), not the session-only denies `run` adds ([FW-CRED3](#fw-cred3), [FW-XR8](#fw-xr8)). The provenance is a side table beside the merged Blueprint, so the compiler and its determinism ([FW-FID4](#fw-fid4)) are untouched. Extends [FW-CAP5](#fw-cap5) inspectability; the layer tag reuses the discovery provenance idea ([FW-DISC6](#fw-disc6)). *(Added by FEP-3.)* |

| <a id="fw-fid7"></a>**FW-FID7** Resolved-input disclosure | Every artifact a command emits names the inputs it was resolved from and how each was chosen — `flag \| auto-discovered \| builtin` — so anything auto-chosen is announced everywhere the choice has effect. Explaining *rules* ([FW-FID6](#fw-fid6)) is not enough when the *file the rules came from* was picked by a walk the user never saw: the `blueprint: {path, source}` stamp on `compile`/`explain` output and the resolution line on the operator channel are the first instance; any future auto-resolved input (a host profile, a feed choice) carries the same disclosure. |

### 5.7 Environment (FW-ENV)

Applied by the launcher at spawn (§2) — not the confiner — and reported in the `FidelityReport` like any other capability.

| Req | Requirement |
|---|---|
| <a id="fw-env1"></a>**FW-ENV1** Environment axis | The blueprint carries an `env` posture — passthrough, allowlist (only named vars survive), or scrub (secret-shaped vars removed) — and the child's environment is built at spawn from the filtered set, not inherited wholesale. A capability axis parallel to fs/net/exec/mcp. |
| <a id="fw-env2"></a>**FW-ENV2** Default secret-shaped scrub | The default profile scrubs env vars whose *name* matches a secret shape (`TOKEN\|SECRET\|PASSWORD\|KEY\|AUTH\|CREDENTIAL\|CERT`) or whose *value* matches a high-confidence secret shape (PEM blocks, `ghp_…`, `AKIA…`, `AIza…`, JWT), minus a blueprint-named allowlist for vars the agent legitimately needs (its model API key). Transparency ([FW-TRA2](#fw-tra2)) is preserved by the allowlist; the scrub is heuristic, so it is reported Partial, never a silent over-claim. |

### 5.8 Blueprint model & format (FW-BP)

The Blueprint is one typed model with multiple surfaces (§4); these requirements pin the layering and the authoring vocabulary.

| Req | Requirement |
|---|---|
| <a id="fw-bp1"></a>**FW-BP1** One model, many surfaces | The Blueprint is a typed, versioned schema. The file format and the CLI flags are two surfaces onto the same model, not two models: any grant/deny/exclusion expressible in one is expressible in the other. |
| <a id="fw-bp2"></a>**FW-BP2** Override precedence | Layers merge in a fixed, documented order, lowest to highest: built-in baseline (the fail-closed empty Blueprint plus the credential-catalog floor) → `extends` chain (depth-first, bases before deriveds) → Blueprint file → CLI overrides. Postures (read-mode/net/exec/env) are last-set-wins; path sets merge additively; the result is deterministic. Overrides are an additive last layer, never a separate mechanism. |
| <a id="fw-bp3"></a>**FW-BP3** Composition via `extends` | A Blueprint may extend one or more base Blueprints (presets/profiles). Resolution is deterministic and cycles are detected and errored. |
| <a id="fw-bp4"></a>**FW-BP4** allow / deny / subtract vocabulary | First-class allow (reads/writes), deny/subtract (read+write), and write-subtract semantics over path patterns in the [FW-CAP6](#fw-cap6) grammar. At any layer and at equal precedence, deny/subtract wins over allow (safety bias); no allow at any layer shadows a deny at any layer — the only un-deny is the typed credential exclude ([FW-CRED5](#fw-cred5)). No general glob exists. |
| <a id="fw-bp5"></a>**FW-BP5** Path sigils | Blueprint path patterns admit a closed set of authoring sigils, expanded at the CLI edge *before* compilation: `~` → `$HOME` and `$CWD` → the launch directory, so a grant can be written relative to the project it runs in. Fixed tokens only — never general `$VAR` interpolation, since the process environment is exactly what the launcher strips ([FW-CRED2](#fw-cred2)), and letting an arbitrary variable name a path would reopen that surface. An expanded sigil is an absolute path that canonicalizes like any grant ([FW-CAP6](#fw-cap6)/[FW-FID4](#fw-fid4)); an unresolvable sigil (e.g. no readable working directory) fails loud, never silently widening ([FW-INV6](#fw-inv6)). |
| <a id="fw-bp6"></a>**FW-BP6** Flat verb rules | One string is one rule (`"<verb>:<path>"`), identical between the CLI flag (`--rule`), a `--set` fragment, and a file `rules` line — a third surface onto the one model ([FW-BP1](#fw-bp1)). Grants and denies are sets merged by union; the result is order-independent (profile stacking is commutative). Denies narrow from any layer; allows widen and are the only trusted layer (maps onto [FW-CAP2](#fw-cap2)). Verbs desugar into the fields above at the CLI edge, so every verb also has a nested `[fs]` equivalent. *(Added by FEP-3.)* |
| <a id="fw-bp7"></a>**FW-BP7** Mode posture | `unveil` (empty universe) and `subtractive` (ambient minus catalog) are a last-set-wins posture aliasing `[fs] read-mode` ([FW-BP2](#fw-bp2)), not a union rule; setting both in one layer is a loud error, but across layers they compose by ordinary last-wins. The credential floor applies in both modes. *(Added by FEP-3.)* |
| <a id="fw-bp8"></a>**FW-BP8** Discovery trust scope | Implicit blueprint resolution (the `FORMWORK.toml` walk) consults only paths the invoking user controls, and its scope is fixed and documented: launch directory upward, ending at the first ancestor the user does not own (before consulting it), at `$HOME` (compared symlink-resolved, so a symlinked home cannot extend the walk), and never at the filesystem root for a nested cwd. A candidate file the user does not own is refused loudly, fail-closed. A policy file planted in a world-writable or foreign-owned directory silently governing a session is a confused-deputy of the same family [FW-XR8](#fw-xr8) forbids in-session; `--blueprint` remains the explicit door for any file discovery will not trust. |

### 5.9 Credential catalog & launcher (FW-CRED)

A versioned, typed catalog of credential **locations only** — dotfiles, well-known file paths, and environment variable names, keyed by type (aws, gcp, ssh, anthropic, …) — compiled into the binary and applied as a floor under every Blueprint. There is no content scanning and no byte-signature matching (§3 non-goals): because every entry is location-based, every entry is a *hard boundary*. The two location kinds are enforced by two different arms: **path** entries join the confiner's deny set (EACCES); **env** entries are stripped by the launcher pre-spawn (variable absent — see §2 for why this is stronger in kind, and on what it is contingent). The "ambient credentials detector" is not separate machinery: it is [FW-CRED7](#fw-cred7)'s operator-channel itemization of this catalog — deny the superset, report the specifics.

| Req | Requirement |
|---|---|
| <a id="fw-cred1"></a>**FW-CRED1** Typed location catalog | A versioned catalog of credential *locations* keyed by type. Each type contributes path patterns and/or env-var names. |
| <a id="fw-cred2"></a>**FW-CRED2** Two kinds, two arms | **path** entries → confiner deny (EACCES); **env** entries → launcher strips the variable before spawn (variable absent). Enforced and reported distinctly. |
| <a id="fw-cred3"></a>**FW-CRED3** Env-points-to-file types | A type may carry both an env var and the file it references (e.g. `GOOGLE_APPLICATION_CREDENTIALS`). Excluding the type strips the variable **and** denies the referenced file. |
| <a id="fw-cred4"></a>**FW-CRED4** Deny-superset by default | The whole known catalog is blocked/stripped by default (fail-closed); exclusion is opt-in per type ([FW-CRED5](#fw-cred5)). Coverage of uncatalogued secrets is [FW-CRED6](#fw-cred6)'s job. |
| <a id="fw-cred5"></a>**FW-CRED5** Exclude-by-type is un-blocking | `allow-credentials: [aws]` (CLI `--allow-cred aws`) deliberately and visibly lets one type through; nothing adjacent is affected. This is the knob for when the agent genuinely needs a credential. |
| <a id="fw-cred6"></a>**FW-CRED6** Generic backstop | Beyond curated types, a generic rule denies known-sensitive *shapes* — files literally named like credentials or SSH private keys — at any depth, anywhere. A catch-all is location-independent by nature: it must reach the containers, CI runners, and project trees where uncatalogued secrets actually live, not just `$HOME`, and it stays denied even under a broad grant. Liftable only as the whole named pseudo-type `backstop`. |
| <a id="fw-cred7"></a>**FW-CRED7** Operator/agent channel split | The operator sees itemized "denied/stripped X (type: …)". The confined agent sees a plain EACCES / an absent variable with no catalog annotation — no oracle. |
| <a id="fw-cred8"></a>**FW-CRED8** Report names the mechanism | The FidelityReport marks each covered type `enforced-via-launcher` (env) or `enforced-via-OS-sandbox` (path), and states plainly that env-shading holds only while Formwork is the launching process — the guarantee is launcher-contingent, and the report must not overclaim it as independent of the launcher. |
| <a id="fw-cred9"></a>**FW-CRED9** Floor enforceability is honest per platform | Any-depth floor rows — the `**/…` form, its anchored refinement `<prefix>/**/<suffix>`, and the generic backstop ([FW-CRED6](#fw-cred6)) — are enforceable as a Seatbelt regex (start-pinned for the anchored form, floating for the plain `**/…`) but cannot be rooted by Landlock. Where a floor row is unenforceable on the host it is withheld from the compiled deny set and the affected types (and the backstop) are reported **Partial**, never silently claimed `Enforced` ([FW-INV5](#fw-inv5)). |

### 5.10 Discovery (FW-DISC)

Discovery observes what a confined workload actually tries to touch and turns denials into candidate grants, so you start tight and let real behavior write the Blueprint — the single most valuable ergonomic feature for the reuse goal, and the one with the sharpest tradeoff, because auto-granting an agent's *attempts* is a confused-deputy machine. Two properties resolve it. First, the default posture is **observe-then-widen**, never live prompting: a marked learning run records denials without granting them, produces a reviewable proposal, and the accepted result applies to *subsequent* runs — the human decision stays out of the hot path, and no syscall interception is needed on either platform. Second, and load-bearing: **the credential catalog is the floor discovery cannot erode** ([FW-DISC3](#fw-disc3)/[FW-INV8](#fw-inv8)).

| Req | Requirement |
|---|---|
| <a id="fw-disc1"></a>**FW-DISC1** Learning mode | An explicit, non-enforcing-of-widenings learning phase that records denials without granting them at runtime. Distinct and visibly different from an enforced run; the policy itself is enforced unchanged ([FW-INV10](#fw-inv10)). |
| <a id="fw-disc2"></a>**FW-DISC2** Reverse compile | Denials compile *backwards* into a proposed Blueprint diff. Each candidate is tagged: catalog-blocked / inside-auto-widen-zone / needs-review. |
| <a id="fw-disc3"></a>**FW-DISC3** Catalog floor | A denial matching the FW-CRED catalog is **never** offered as an auto-proposable or one-click candidate grant. Lifting it requires the explicit typed exclude ([FW-CRED5](#fw-cred5)), never the discovery flow. The match is by credential *shape* wherever the kernel observed the denial — denial collection is deliberately over-capture-tolerant (a denial can surface from another process or a different `$HOME`), so a credential-shaped path is withheld regardless of location — and the floor is re-checked again at **accept**, because the proposal file is untrusted input. |
| <a id="fw-disc4"></a>**FW-DISC4** Auto-widen zone | An operator-authored scope in the Blueprint within which discovered grants may be auto-accepted (e.g. project dir, language caches). Outside the zone, review is required. Empty by default — nothing self-grants out of the box. |
| <a id="fw-disc5"></a>**FW-DISC5** Review as itemized diff | Proposals surface on the operator channel as a diff showing what widens and what was withheld and why. Acceptance is per-entry. |
| <a id="fw-disc6"></a>**FW-DISC6** Provenance | An accepted discovered grant is recorded with provenance (added-via-discovery, run id), so audit distinguishes authored from learned grants. |
| <a id="fw-disc11"></a>**FW-DISC11** Loop drivability | The discovery loop — observe, list, accept, next run — is drivable end-to-end from the `learn` surface without the user naming its artifact files: `<blueprint>.proposal.toml` and `<blueprint>.discovered.toml` are implementation conventions that surface in *output* as provenance, never as required *input* knowledge. Derived-path flags (`--proposal`) are escape hatches, not the paved road, and a flag a mode would ignore is refused, never silently dropped ([FW-INV6](#fw-inv6) at the CLI surface). *(`FW-DISC7`–`FW-DISC10` are reserved by the in-flight FEP-4 draft and are not landed numbers.)* |

"Formwork never runs a real workload in a grant-whatever-is-attempted mode" is not a separate requirement — it is the combined consequence of [FW-DISC1](#fw-disc1) and [FW-DISC4](#fw-disc4), stated as a guarantee in [FW-INV10](#fw-inv10). Sticky learning within a trust boundary is the recommended workflow: accumulate proposals across runs, auto-accept only inside the operator-drawn zone, review everything else — discovery does the tedious enumeration; the human keeps the perimeter.

## 6. Invariants

These hold for every session under every backend, and are the properties the tests in section 7 exist to falsify.

<a id="fw-inv1"></a>**FW-INV1 — No widening.** After `enforce()`, the held capability set can only shrink. No code path widens it. Verified by fuzzing blueprint/narrow sequences and asserting against probes.

<a id="fw-inv2"></a>**FW-INV2 — Descendant containment.** No descendant escapes or relaxes the confiner. Re-exec, setuid/setgid execution, and `prctl` attempts to clear `NO_NEW_PRIVS` do not restore access. Fuzzed over random spawn trees.

<a id="fw-inv3"></a>**FW-INV3 — Egress only via the gateway fd.** A confined process has no network path except the injected fd. Direct `connect()`, raw sockets, and direct DNS fail closed. Verified adversarially.

<a id="fw-inv4"></a>**FW-INV4 — Shading completeness.** No ungranted tool, resource, or prompt is invocable, whether or not it appears in any listing. Fuzzed over guessed names and out-of-band identifiers.

<a id="fw-inv5"></a>**FW-INV5 — Report soundness.** Anything reported `Enforced` is actually enforced, verified by paired allow/deny probes; anything the platform cannot enforce is reported, not claimed. This is the load-bearing invariant — it is what makes "good, not perfect" honest rather than hand-wavy.

<a id="fw-inv6"></a>**FW-INV6 — No silent open.** No capability-detection failure yields a running-but-unconfined session without an explicit, surfaced `Unenforceable`. Formwork fails closed or fails loud, never fails open-silent.

<a id="fw-inv7"></a>**FW-INV7 — Launcher-strip completeness.** A stripped env var is *absent* (not merely denied) throughout the confined process and its entire descendant tree. The confined process may still set new vars for its own children; this shades ambient inherited credentials, not values the agent synthesizes.

<a id="fw-inv8"></a>**FW-INV8 — Credential floor.** No discovery path, no auto-widen rule, and no single-click operator action can grant access to a FW-CRED-matched location. Only the explicit typed exclude ([FW-CRED5](#fw-cred5)) can. A location is "matched" by credential *shape* wherever its denial was observed, and the floor is evaluated both when a candidate is proposed and again at accept (proposals are untrusted input), so neither over-capture nor a forged proposal opens a seam ([FW-DISC3](#fw-disc3)).

<a id="fw-inv9"></a>**FW-INV9 — No-oracle for credentials.** Denied credential paths and stripped credential env vars are indistinguishable, to the confined agent, from genuinely absent resources — no error text, code, or timing reveals existence.

<a id="fw-inv10"></a>**FW-INV10 — Discovery is non-authoritative.** A discovered candidate has no effect until accepted into an enforced Blueprint. Observation never itself widens a live enforced session, except within a pre-declared auto-widen zone.

<a id="fw-inv11"></a>**FW-INV11 — Structural floor.** Because the credential catalog compiles into the deny layer and deny is terminal ([FW-CAP8](#fw-cap8)), no allow, no rule order, no profile, and no discovery path can produce access to a floored location; the sole removal is the typed exclude ([FW-CRED5](#fw-cred5)). The structural form of [FW-INV8](#fw-inv8) (added by FEP-3).

(The env-shading honesty guarantee — that the report discloses launcher-contingency — is carried by [FW-CRED8](#fw-cred8) rather than a standalone invariant, and is a specialization of [FW-INV5](#fw-inv5) report-soundness.)

## 7. End-to-end tests

Each test names a concrete scenario with Pass/Fail conditions. Filesystem and process tests run against both the in-simulator/dry-run compile path and real enforcement, and — except where a test is platform-specific — against both the Linux and macOS backends.

### 7.1 Filesystem confinement

<a id="fw-e2e-001"></a>**FW-E2E-001: Granted read succeeds, ungranted read denied.** A session is granted `read(/work/project/**)`. It reads a file inside the project (succeeds) and attempts to read `/work/other-project/secrets.env` (denied). Run under both spawn-confined and confine-self postures. Pass: in-scope read returns bytes; out-of-scope read returns EACCES-class error under both postures. Fail: any out-of-scope read succeeds, or an in-scope read is denied.

<a id="fw-e2e-002"></a>**FW-E2E-002: Write scope and read-only enforcement.** Granted `read(/work/**), write(/work/project/**)`. Writes inside the project succeed; a write to `/work/reference/` (read-granted only) is denied; a write to `/etc/` is denied. Pass: exactly the write-granted paths are writable. Fail: any write outside write scope succeeds.

<a id="fw-e2e-003"></a>**FW-E2E-003: Sensitive-set subtraction under a broad grant.** Granted broad `read($HOME/**)` with the default sensitive set subtracted. The session reads an ordinary file under `$HOME` (succeeds) and attempts `~/.ssh/id_ed25519`, `~/.aws/credentials`, and a sibling project directory (all denied). Pass: ordinary reads succeed while every sensitive-set path is denied despite the broad grant. Fail: any sensitive-set path is readable.

<a id="fw-e2e-004"></a>**FW-E2E-004: Symlink escape blocked.** Inside a writable directory the session creates a symlink pointing at `/etc/passwd` and at an ungranted sibling project, then reads and writes through the symlink. Pass: access through the symlink is denied — the target's scope governs, not the link's location. Fail: the symlink grants access to the target.

<a id="fw-e2e-005"></a>**FW-E2E-005: Descendant inheritance.** The confined session spawns `bash`, which spawns a child process that attempts an out-of-scope read and attempts to relax its own sandbox. Pass: the grandchild is denied and cannot re-grant; confinement is intact across the tree. Fail: any descendant reads out of scope or widens the grant.

<a id="fw-e2e-037"></a>**FW-E2E-037: Sensitive-set metadata does not leak.** A subtracted credential path is `stat()`ed under an otherwise-broad grant. Pass on macOS: existence, size, and mtime are denied (the `subtract` deny covers `file-read-metadata`), while metadata on non-sensitive ungranted paths still resolves ([FW-TRA4](#fw-tra4)). On Linux, where the residual is unenforceable, the capability is reported Partial and observed behavior matches the report. Fail: metadata of a sensitive path leaks on a platform that reports it denied, or the report over-claims ([FW-CAP7](#fw-cap7)).

<a id="fw-e2e-038"></a>**FW-E2E-038: Any-depth patterns deny at real depth.** A blueprint expressing `**/.env` is compiled and enforced over a project tree containing a nested `<proj>/.env`. Pass: the nested `.env` is denied at depth while a sibling non-secret file stays readable, and the pattern compiles byte-identically twice ([FW-FID4](#fw-fid4)). Fail: a matching path at depth is missed (a silent fail-open of the sensitive set, [FW-INV6](#fw-inv6)), or compilation is nondeterministic ([FW-CAP6](#fw-cap6)).

<a id="fw-e2e-039"></a>**FW-E2E-039: Tamper vectors are read-through, write-denied.** Under a writable project grant, a `write-subtract` set masks execution/policy-tampering vectors (`.git/hooks/**`, `.git/config`, `.mcp.json`, `.vscode/**`, shell rc). Pass: writing `<proj>/.git/config` is denied though the surrounding tree is writable, while reading it still succeeds so git and tooling keep working. Fail: any tamper path is writable under a normal project grant ([FW-TRA7](#fw-tra7)).

### 7.2 Network / egress

<a id="fw-e2e-006"></a>**FW-E2E-006: Direct egress denied.** With `net: Deny`, the session runs `curl https://example.com`. Pass: the connection fails closed (no route to a network the process can reach). Fail: any bytes leave the host by a path other than the gateway fd.

<a id="fw-e2e-007"></a>**FW-E2E-007: Direct DNS denied.** The session attempts name resolution via the system resolver (UDP/TCP 53). Pass: direct resolution fails; name resolution is available only through the gateway. Fail: the process resolves names via a direct network path.

<a id="fw-e2e-008"></a>**FW-E2E-008: Proxy-env-bypass attempt.** A program that ignores `HTTP_PROXY`/`ALL_PROXY` and opens a raw socket to a remote host is run. Pass: the direct connection is denied; there is no cooperative-only bypass. Fail: the raw connection succeeds.

<a id="fw-e2e-009"></a>**FW-E2E-009: Optional port tier (Linux, ABI-gated).** With `net: Ports([8080])` and a loopback service on 8080 and 9090, the session connects to each. Pass on capable kernels: 8080 succeeds, 9090 denied. On kernels below Landlock net support: the capability is reported Unenforceable and the test asserts the report matches the (fail-closed) behavior rather than asserting port-level enforcement. Fail: behavior contradicts the report.

### 7.3 Transport / fd seam

<a id="fw-e2e-010"></a>**FW-E2E-010: MCP over injected fd with zero net.** The agent has `net: Deny` and one injected fd to the gateway. It performs `initialize`, `tools/list`, and a `tools/call` round-trip. Pass: the full MCP exchange completes with no network capability inside the sandbox. Fail: the exchange requires any in-sandbox network or filesystem-socket access.

<a id="fw-e2e-011"></a>**FW-E2E-011: fd minting via SCM_RIGHTS.** After start, the agent requests a connection to a second backend over its control fd. The gateway opens the backend and passes back a new connected fd. Pass: the agent uses the new fd; no in-sandbox `connect()` occurs; the confiner's net-deny is unchanged. Fail: the agent must `connect()` itself, or net-deny had to be relaxed.

<a id="fw-e2e-012"></a>**FW-E2E-012: No dependence on socket-path gating.** A pathname UNIX socket for the gateway exists on disk. The test runs the full agent workload twice: once with filesystem access to the socket path granted, once denied. Pass: the workload succeeds identically in both cases (the agent uses the injected fd, not the path), and granting the path does not by itself create any egress. Fail: behavior depends on the socket's filesystem grant.

### 7.4 Gateway / MCP shading

<a id="fw-e2e-013"></a>**FW-E2E-013: Tool invisibility.** A backend exposes tools `read_file`, `write_file`, `http_fetch`. Policy grants `read_file` only. The agent calls `tools/list`. Pass: only `read_file` appears; the others are absent, not present-and-flagged. Fail: an ungranted tool appears in the listing.

<a id="fw-e2e-014"></a>**FW-E2E-014: Ungranted call refused as not-found.** The agent calls `http_fetch` by its exact name despite it being hidden. Pass: the call is refused, and the error is shaped like a genuine absence (matches a "unknown tool / not available" pattern) rather than "permission denied" — no oracle that confirms the tool exists. Fail: the call executes, or the error reveals that the tool exists but is blocked.

<a id="fw-e2e-015"></a>**FW-E2E-015: Resource and prompt shading.** The backend exposes resources and prompts; policy grants a subset. The agent lists and reads both. Pass: only granted resources/prompts are listed, readable, and gettable; ungranted ones are absent and non-fetchable by direct URI/name. Fail: any ungranted resource or prompt is listed or fetchable.

<a id="fw-e2e-016"></a>**FW-E2E-016: `list_changed` re-filtering.** After connection, the backend adds a new tool and emits `notifications/tools/list_changed`. The new tool is not in policy. Pass: the gateway re-applies policy; the new tool stays hidden and non-invocable. Fail: the runtime-added tool becomes visible or callable.

<a id="fw-e2e-017"></a>**FW-E2E-017: Sampling/elicitation policing.** A backend issues a server→client `sampling/createMessage` request. Policy denies sampling for that server. Pass: the request is refused at the gateway and never reaches the agent/model. Fail: the sampling request passes through.

<a id="fw-e2e-018"></a>**FW-E2E-018: Transparent passthrough for granted items.** For a granted tool, the request and response bytes observed by the agent are semantically identical to those from talking to the backend directly (compared against a direct-connection ground truth). Pass: no semantic divergence for granted traffic. Fail: the gateway mangles or reshapes granted request/response content.

<a id="fw-e2e-019"></a>**FW-E2E-019: Backend confinement recursion.** The gateway spawns a stdio MCP backend whose grant is `read(/srv/data/**)`. The backend attempts to read `/work/project` and to open a direct network connection. Pass: the backend is confined to its own grant — both attempts denied. Fail: the spawned backend has broader access than its grant.

<a id="fw-e2e-065"></a>**FW-E2E-065: Regex allow shades the listing ([FW-GW9](#fw-gw9)).** A backend exposes a spread of tool names (`read_file`, `list_dir`, `write_file`, `delete_file`, `http_fetch`). Policy grants `tools = { allow = ["/read_.*/", "/list_.*/"] }`. The agent calls `tools/list`. Pass: exactly the pattern-matched names (`read_file`, `list_dir`) appear; the rest are absent, indistinguishable from an exact allowlist. Fail: a non-matching tool appears, or a matching one is hidden.

<a id="fw-e2e-066"></a>**FW-E2E-066: Deny is terminal over allow ([FW-GW9](#fw-gw9)/[FW-CAP8](#fw-cap8)).** Under `tools = { allow = ["/.*/"], deny = ["/delete_.*/", "http_fetch"] }`, the agent lists tools and calls a deny-matched name. Pass: deny-matched tools are absent from `tools/list` despite allow-all, the guessed call is refused, and a name matching allow *and* deny is removed (deny wins); a name the deny does not match still round-trips. Fail: a deny-matched tool is listed or callable, or the overlap resolves to allow.

<a id="fw-e2e-067"></a>**FW-E2E-067: Deny stays oracle-free ([FW-GW9](#fw-gw9)/[FW-ADV-004](#fw-adv-004)).** With a deny pattern hiding a real backend tool, the agent calls the hidden-but-real name and a nonexistent name that also matches the deny. Pass: both are refused with the same error code and an identical message shape (modulo the echoed name), so the deny does not confirm the tool exists. Fail: the refusals differ, or the message says "denied".

<a id="fw-e2e-069"></a>**FW-E2E-069: Pattern policy compiles and fails loud ([FW-GW9](#fw-gw9)/[FW-FID4](#fw-fid4)/[FW-INV6](#fw-inv6)).** Black-box through the CLI on any host (dry-run compile, no kernel): a blueprint with `tools = { allow = ["/re/", …], deny = ["/re/"] }` compiles, the allow/deny patterns survive verbatim into the compiled `gateway.servers.<s>.tools`, and recompiling is byte-identical. A `/…/` that will not compile and an empty `{}` table each make the compile exit non-zero with the reason named. Pass: patterns round-trip and malformed input fails loud. Fail: a pattern is dropped or reordered nondeterministically, or a bad pattern/empty table silently compiles.

<a id="fw-e2e-068"></a>**FW-E2E-068: Pattern shading against a real MCP server ([FW-GW9](#fw-gw9)).** In a Linux container, the gateway fronts a real published server (`@modelcontextprotocol/server-everything`, pinned) spawned as the backend, driven through the production shading path (`Gateway::run`, what the `formwork gateway` CLI wraps). Policy is a regex allow/deny over that server's real tool names. Driven as an MCP host would (initialize, `tools/list`, `tools/call`): every listed tool matches the allow set and none match the deny; an allowed tool round-trips; both an allow-miss and a deny-matched real tool are refused, oracle-free and identically. Skips (never fails) where the host lacks node. Isolates shading so it runs without a host confiner; the backend-confinement arm ([FW-GW5](#fw-gw5)) is host-gated and covered by [FW-E2E-019](#fw-e2e-019). Pass: shading holds end-to-end against a server Formwork did not write. Fail: a denied real tool is listed or callable, or an allowed one is shaded out.

### 7.5 Transparency & reuse

<a id="fw-e2e-020"></a>**FW-E2E-020: pytest reuse, zero denials.** A real Python repository with installed dependencies and a populated cache is present on the host. Under the default profile with the project writable and the interpreter/site-packages/cache read-only, the session runs `pytest`. Pass: the suite runs to its normal result with no sandbox-induced denials in the run log. Fail: any denial forces a test error that would not occur outside the sandbox.

<a id="fw-e2e-021"></a>**FW-E2E-021: node/npm reuse.** The session runs `npm test` (or a node script) against host `node_modules` and the npm cache, read-only. Pass: the script runs as it would unsandboxed, modulo network, with no denials on the happy path. Fail: a denial breaks an otherwise-passing run.

<a id="fw-e2e-022"></a>**FW-E2E-022: git works; push gated.** The session runs `git status`, `git diff`, and `git commit` within the project (succeed) and `git push` (network). Pass: local git operations succeed within scope; `git push` is blocked unless routed through the gateway. Fail: local git is broken by confinement, or push egresses directly.

<a id="fw-e2e-023"></a>**FW-E2E-023: Graceful degradation on optional paths.** A tool probes an optional, ungranted config path (e.g., `~/.config/tool/optional.toml`) as part of normal startup. Pass: the probe receives a standard errno and the tool continues with defaults. Fail: the probe crashes the tool or produces a sandbox-specific error the tool cannot handle.

<a id="fw-e2e-036"></a>**FW-E2E-036: Secret-shaped environment scrub, allowlist survives.** Under the default profile, a confined child is launched via `formwork run` and its environment inspected. Pass: name- or value-secret-shaped vars (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, a PEM-valued variable) are absent, while a blueprint-allowlisted `ANTHROPIC_API_KEY` survives so the workload still reaches its model API. Fail: any secret-shaped var reaches the child, or an allowlisted var is stripped. The scrub is heuristic, so the capability is reported Partial ([FW-INV5](#fw-inv5)), never a silent over-claim ([FW-ENV1](#fw-env1)/2).

### 7.6 Fidelity & operability

<a id="fw-e2e-024"></a>**FW-E2E-024: Report soundness.** For a rich blueprint, `compile()` yields a report. For every capability marked `Enforced`, a paired probe asserts the allowed operation succeeds and the denied operation fails. Pass: every `Enforced` claim survives its probe pair; nothing marked `Enforced` is bypassable by the probe suite. Fail: any `Enforced` capability is bypassable, or any probe contradicts the report.

<a id="fw-e2e-025"></a>**FW-E2E-025: Report honesty on a degraded host.** On a kernel lacking Landlock network support, a blueprint requesting `net: Ports([...])` is compiled and enforced. Pass: the net-port capability is reported Partial/Unenforceable, the fail-closed deny still holds (no egress), and observed behavior matches the report exactly. Fail: the report claims port enforcement that does not hold, or egress leaks.

<a id="fw-e2e-026"></a>**FW-E2E-026: Dry-run compile without enforcement.** `compile()` runs on a host lacking Landlock, and on macOS compiling a Linux profile. Pass: a policy and report are produced and nothing is enforced on the running process. Fail: `compile()` requires kernel support, mutates the process, or crashes.

<a id="fw-e2e-027"></a>**FW-E2E-027: Deterministic compile.** The same blueprint is compiled twice. Pass: byte-identical policy and report. Fail: any nondeterministic difference.

<a id="fw-e2e-028"></a>**FW-E2E-028: Cross-platform equivalence.** The same blueprint is enforced on Linux and macOS and exercised by the section 7.1–7.5 workloads. Pass: for the enforceable intersection, observable behaviors match across platforms; all differences are reflected in the FidelityReport, not in silent behavior. Fail: an observable behavior differs across platforms without a corresponding report entry.

### 7.7 Blueprint model & format

<a id="fw-e2e-041"></a>**FW-E2E-041: Rename regression.** *(Regression guard for the spec → Blueprint rename; not tied to a numbered requirement.)* A Blueprint that is the renamed form of a prior spec compiles to the same policy and report. Pass: no behavioral change attributable to the rename. Fail: any policy difference.

<a id="fw-e2e-042"></a>**FW-E2E-042: Override precedence.** A path allowed in the file is denied by a CLI `--subtract` layered over it; a deny and an allow at equal precedence resolve to deny. Pass: merge follows baseline → extends → file → CLI ([FW-BP2](#fw-bp2)), postures last-set-wins, path sets additive, with deny-beats-allow at ties. Fail: any ordering or tie deviation.

<a id="fw-e2e-043"></a>**FW-E2E-043: CLI/file parity.** The same grant authored in the file and expressed via CLI flag produce identical compiled policy. Pass: byte-identical policy from both surfaces. Fail: divergence.

<a id="fw-e2e-044"></a>**FW-E2E-044: `extends` composition.** A Blueprint extending a base merges deterministically; an `extends` cycle is detected. Pass: deterministic merge; cycle errors clearly. Fail: nondeterministic merge or an undetected cycle.

<a id="fw-e2e-055"></a>**FW-E2E-055: Path sigils scope a grant ([FW-BP5](#fw-bp5)).** A blueprint grants `$CWD/**` and is run from a project directory. Pass: a file under the launch directory is readable while a sibling outside it is denied by the real kernel; `~` still expands to `$HOME`; a non-sigil path is untouched; and `$CWD` resolving to `$HOME` or `/` warns (a broad-grant nudge) rather than silently widening. Fail: a path outside `$CWD` is granted, or a sigil expands wrong.

<a id="fw-e2e-056"></a>**FW-E2E-056: Create/write split ([FW-CAP9](#fw-cap9)).** The `modify` verb compiles to every `file-write-*` op except `file-write-create`; under real Seatbelt a paired allow/deny probe shows an existing file modifiable but a new file/dir uncreatable. Pass: modify allowed, create (file and dir) denied. Fail: create succeeds, or modify is denied.

<a id="fw-e2e-057"></a>**FW-E2E-057: Mode posture ([FW-BP7](#fw-bp7)).** `mode` compiles identically to the equivalent `[fs] read-mode` for both values, and a child's `mode` overrides a base's `read-mode` across `extends` while both-in-one-layer errors loud. Pass: byte-identical compile; last-wins across layers; same-layer conflict rejected. Fail: divergence, or a same-layer conflict silently picked.

<a id="fw-e2e-058"></a>**FW-E2E-058: Rule order independence ([FW-BP6](#fw-bp6)/[FW-CAP8](#fw-cap8)).** The same verb rules in different orders compile to the same policy, and a deny beats an allow regardless of order. Pass: order-independent compile; deny terminal. Fail: order changes the policy, or an allow reopens a deny.

<a id="fw-e2e-061"></a>**FW-E2E-061: Rule/table parity ([FW-BP1](#fw-bp1)).** Grants authored as flat verb rules and as the nested `[fs]` table compile byte-identically. Pass: byte-identical policy from both. Fail: divergence.

<a id="fw-e2e-059"></a>**FW-E2E-059: Explain names the winning rule and provenance ([FW-FID6](#fw-fid6)).** `explain <path>` over a layered blueprint reports, per path, the read/write/exec verdict, the deciding rule, and its origin: a granted path names the file rule; a `--rule` deny is terminal and attributed to `cli`; a credential-floor path is denied as `built-in`; an unlisted path under `unveil` is hidden, not ambient; an `exec:` grant shows execute even where read is closed (FW-ISO9/FW-XR6). Pass: each verdict names the right rule and origin without enforcing. Fail: a wrong rule/origin, or a deny that does not win.

<a id="fw-e2e-060"></a>**FW-E2E-060: CLI overrides compose with an `unveil` blueprint ([FW-BP1](#fw-bp1)/[FW-BP2](#fw-bp2)/[FW-BP7](#fw-bp7)).** Over an empty-universe (`unveil`) file, the CLI override surface behaves as an operator expects: a `--read`/`--write` sugar grant fills the closed universe (write implies read); `--rule exec:` closes exec to an allow-list on a separate axis (the listed binary runs but is unreadable, an unlisted one does not run); the `--mode unveil` flag flips a subtractive file to closed by last-wins (ambient-only path hidden, explicit grant kept); and the credential floor stays un-liftable under a broad `--read`. Pass: each verdict matches, dry-run on any host. Fail: a CLI grant that does not populate the universe, an exec allow-list that leaks, a mode flag that does not override, or a floor a `--read` lifts.

<a id="fw-e2e-070"></a>**FW-E2E-070: Discovery walk stays inside the trust boundary ([FW-BP8](#fw-bp8)).** Dry-run on any host. A `FORMWORK.toml` planted (a) in an ancestor directory the invoking user does not own, (b) above a symlinked `$HOME` (the walk reaching territory a textual home comparison would miss), and (c) as a foreign-owned file inside the user's own directory. Pass: none of the planted files governs a session — (a) ends the walk unconsulted, (b) stops at the resolved home, (c) is refused with a warning and does not fall through to a farther match — while the user's own launch-directory file still resolves, and `--blueprint` still opens any file explicitly. Ownership is exercised with an injected predicate at the unit boundary (chown requires root; the same pure-substitution allowance as the compiler's HostProfile), the symlinked-home arm against the real filesystem. Fail: implicit policy from territory the user does not control.

### 7.8 Credential catalog & launcher

<a id="fw-e2e-045"></a>**FW-E2E-045: Path credential denied and itemized.** Under the default catalog, `~/.aws/credentials` is read. Pass: read denied (EACCES); operator channel names type `aws`; agent sees a bare EACCES with no annotation. Fail: read succeeds, or the agent-facing error names the type.

<a id="fw-e2e-046"></a>**FW-E2E-046: Env credential stripped and absent in tree.** `AWS_SECRET_ACCESS_KEY` is present in Formwork's own environment. The confined process and a grandchild read it. Pass: absent in both (empty/None); operator channel names it stripped as `aws`; agent cannot distinguish it from never-set. Fail: the variable is present anywhere in the tree.

<a id="fw-e2e-047"></a>**FW-E2E-047: Env-points-to-file dual arm.** With `gcp` enforced (default deny) and `GOOGLE_APPLICATION_CREDENTIALS` set to a real path. Pass: the variable is stripped **and** the referenced file is denied. Fail: either arm misses.

<a id="fw-e2e-048"></a>**FW-E2E-048: Exclude-by-type un-blocks exactly one.** `--allow-cred aws`. Pass: aws path/env become accessible/present while ssh, anthropic, slack, etc. remain blocked/stripped. Fail: any adjacent type is affected.

<a id="fw-e2e-049"></a>**FW-E2E-049: Generic backstop.** An uncatalogued but sensitive-shaped location (a novel `~/.someprovider/credentials`, an unusual `.env` variant). Pass: denied by the backstop despite no curated entry. Fail: the uncatalogued secret is accessible.

<a id="fw-e2e-050"></a>**FW-E2E-050: Report mechanism labeling.** Pass: FidelityReport marks env-kind types `enforced-via-launcher` and path-kind types `enforced-via-OS-sandbox`, carries the launcher-contingency note for env, and marks any-depth floor rows Partial where the host cannot root them ([FW-CRED9](#fw-cred9)). Fail: mislabeled or missing mechanism.

### 7.9 Discovery

<a id="fw-e2e-051"></a>**FW-E2E-051: Learning proposes toolchain, omits secrets.** A learning run of a real workload that needs ordinary toolchain paths and also touches a credential. Pass: the proposal includes the ordinary paths the run needed and omits every FW-CRED-matched path however hard it was hit; the withheld itemization goes to the operator channel. Fail: a credential path appears as a candidate grant.

<a id="fw-e2e-052"></a>**FW-E2E-052: Auto-widen zone boundary.** A discovered path inside the declared zone and one just outside it. Pass: the in-zone path self-grants on the next run; the out-of-zone path requires review and is not auto-granted. Fail: an out-of-zone path self-grants.

<a id="fw-e2e-053"></a>**FW-E2E-053: Provenance recorded.** An accepted discovered grant. Pass: it appears in the discovered layer tagged with discovery provenance and run id, distinguishable from authored grants. Fail: no provenance, or indistinguishable from authored.

<a id="fw-e2e-054"></a>**FW-E2E-054: Discovery non-authoritative.** A denial observed in learning mode, outside any auto-widen zone. Pass: the live enforced session is not widened; the operation still fails in that run. Fail: observation silently widened the session.

<a id="fw-e2e-062"></a>**FW-E2E-062: Learning without a denial feed fails fast ([FW-INV5](#fw-inv5)/[FW-INV6](#fw-inv6)).** `formwork learn -- cmd` on a host with no wired denial feed. Pass: the invocation errors *before* the workload spawns, naming the missing feed and the alternatives (`run` + hand-authored grants, `--observe-anyway`); no proposal file appears; with `--observe-anyway` the run is enforced, the absence of observation is reported loudly, and still no proposal is written. Fail: the workload runs and the missing feed is only announced afterwards, or an empty proposal pretends observation happened.

<a id="fw-e2e-063"></a>**FW-E2E-063: Review loop closes over the proposal ([FW-DISC5](#fw-disc5)/[FW-DISC6](#fw-disc6)).** From a proposal holding needs-review candidates, driven entirely through the CLI: listing prints the candidates numbered on stdout (the result stream, present under quiet telemetry); accepting by 1-based number and by exact pattern moves exactly the selected entries into the discovered layer with discovery provenance and rewrites the proposal without them; `--accept-all` consumes the remainder; a credential-floor-matching entry is refused at accept regardless of what the proposal claims ([FW-INV8](#fw-inv8)). Dry-run on any host — the proposal file is input, no kernel needed. Pass: each behavior as stated. Fail: a listing lost to the telemetry channel, an unselected entry consumed, provenance missing, or a floored entry accepted.

<a id="fw-e2e-064"></a>**FW-E2E-064: Short-lived workload denials are captured ([FW-DISC1](#fw-disc1)/[FW-DISC2](#fw-disc2)).** A learning run whose workload dies on its first denial (`cat` of an ungranted file — exiting in well under a second, the canonical discovery shape). Pass: the denied path still appears in the proposal, despite denial-feed persistence latency exceeding the workload's lifetime (collection is anchored to the run start and polled to quiescence under a cap, with two settle floors: a repeated non-empty read is self-evidencing and concludes at the ordinary floor, while a repeated *empty* read — indistinguishable from a feed that is still flushing — is held to a longer floor before it is trusted as "this run denied nothing"). Fail: an empty proposal because collection concluded on a window the feed had not yet flushed.

<a id="fw-e2e-071"></a>**FW-E2E-071: Linux denial feed via ptrace ([FW-DISC1](#fw-disc1)/[FW-DISC2](#fw-disc2)/[FW-XR6](#fw-xr6)).** On a Landlock-capable Linux host with `strace` installed, `formwork learn -- cmd` runs the workload enforced under an **unconfined** `strace` ancestor tracing a `run --confine-self` shim: the tracer needs no policy hole (it sits outside the wall, is the tracee's ancestor — no Yama exception — and the confined tree cannot reach it, [FW-XR8](#fw-xr8)). Denied file syscalls (`EACCES`/`EPERM` on the open/exec/mutate families — never `stat`/`access` probes, which Landlock does not govern) become denial records: the millisecond-`cat` shape ([FW-E2E-064](#fw-e2e-064)'s property) lands in the proposal with no persistence-latency window at all (the trace is complete when the tracee exits), a credential hit is withheld by the floor ([FW-DISC3](#fw-disc3)) through this tap exactly as through the macOS one, and attribution is exact — only this run's process tree is in the trace. Without `strace` on PATH, or without Landlock, `learn` fails fast naming the gap ([FW-E2E-062](#fw-e2e-062)/[FW-XR9](#fw-xr9)). Pass: each behavior as stated. Fail: a denial the kernel produced is missing from the proposal, a credential is proposed, or the tracer required weakening the policy.

### 7.10 Adversarial

<a id="fw-adv-001"></a>**FW-ADV-001: Sandbox shedding.** The confined process attempts, in sequence: `execve` of a setuid binary, `prctl` to clear `NO_NEW_PRIVS`, and re-exec to try to drop the seccomp filter. Pass: all fail; confinement persists across every attempt. Fail: any attempt restores access or relaxes the filter.

<a id="fw-adv-002"></a>**FW-ADV-002: TOCTOU / symlink race.** A loop races creating a symlink from a writable path to a sensitive target and accessing it, attempting to win between check and use. Pass: no access to the sensitive target succeeds; enforcement is at the kernel access, not a userspace pre-check. Fail: the race yields out-of-scope access.

<a id="fw-adv-003"></a>**FW-ADV-003: Gateway bypass.** The agent extracts an MCP endpoint host from a granted tool's metadata and tries to reach that host directly. Pass: direct egress is denied; only the gateway fd reaches it. Fail: the agent egresses to the endpoint outside the gateway.

<a id="fw-adv-004"></a>**FW-ADV-004: Shading oracle probe.** The agent enumerates candidate tool names and inspects error messages, response timing, and error codes to detect which hidden tools exist. Pass: refusals for hidden-but-real tools are indistinguishable from refusals for nonexistent tools — no oracle. Fail: any signal distinguishes a blocked-existing tool from a nonexistent one.

<a id="fw-adv-005"></a>**FW-ADV-005: fd smuggling.** A confined stdio backend attempts to pass its own descriptors to the agent, or to open new sockets, to widen access. Pass: only the gateway mints egress fds; the backend cannot manufacture or hand off a broader capability. Fail: a confined process obtains or confers access beyond its grant via fd passing.

<a id="fw-adv-006"></a>**FW-ADV-006: Cross-domain socket reach-around (Linux).** The confined process attempts to connect to an abstract UNIX socket and a pathname UNIX socket belonging to a host process outside the domain (e.g., a desktop bus or terminal multiplexer). Pass on capable kernels: blocked via UNIX-socket scoping; on kernels lacking it, the gap is reported Partial and the fail-closed net posture still prevents remote egress. Fail: the confined process talks to an out-of-domain service without the gap being reported.

<a id="fw-adv-012"></a>**FW-ADV-012: Credential oracle probe (path + env).** The agent probes a credential path and reads a credential env var, inspecting errors, codes, and timing. Pass: neither denial nor absence is distinguishable from a nonexistent resource, and neither surfaces an operator prompt that a social-engineering payload could target (extends [FW-ADV-004](#fw-adv-004)). Fail: any oracle exists.

<a id="fw-adv-013"></a>**FW-ADV-013: Discovery confused-deputy.** A prompt-injected agent repeatedly attempts `~/.ssh/id_ed25519` to try to get it proposed and auto-accepted — with the auto-widen zone adversarially drawn over the whole home. Pass: FW-CRED-matched denials never become auto-proposable and never enter the auto-widen path ([FW-INV8](#fw-inv8)); a forged proposal naming the key is refused at accept; the wall holds regardless of attempt count. Fail: persistent probing yields a candidate grant, an auto-accept, or an accepted forgery.

<a id="fw-adv-014"></a>**FW-ADV-014: Launcher-bypass honesty.** The agent is started *without* Formwork (bypassing the launcher). Pass: env vars are present as expected, **and** the report had already disclosed env-shading as launcher-contingent — i.e. the guarantee was never overclaimed ([FW-CRED8](#fw-cred8)). Fail: the documentation/report implied env-shading holds independent of the launcher.

<a id="fw-adv-015"></a>**FW-ADV-015: Discovery fold cannot re-grant a credential ([FW-INV8](#fw-inv8)).** A credential-shaped file *outside* `$HOME` (`/srv/app/id_rsa`) sits alongside ordinary files that a learning run touches, with the auto-widen zone drawn over the directory. Pass: the key is withheld by the shape floor, its ordinary siblings stay granular (no `…/**` fold that would cover the key), nothing auto-accepted covers it, and a subsequent run still cannot read it — enforcement (deny beats allow) denies the key regardless, and the fold guard keeps the proposal itself honest. Fail: a fold or auto-widen grant transitively covers the withheld credential, or the key is readable in a later run.

## 8. Performance target

Confinement is setup-once plus per-operation overhead. The target keeps interactive agent loops responsive and the reuse story credible:

| Path | Target |
|---|---|
| Sandbox setup (spawn-confined launch) | < 50 ms added to process start |
| Per-filesystem-op overhead (Landlock/Seatbelt) | negligible; within noise of the raw syscall |
| Gateway round-trip added latency (granted tool) | < 2 ms over a direct backend call, local |
| Full default-profile compile + report | < 5 ms, no kernel calls |

A reuse-heavy workload ([FW-E2E-020](#fw-e2e-020)/021) must complete within a small bounded overhead of its unsandboxed baseline; a sandbox that materially slows the normal build/test loop violates [FW-TRA6](#fw-tra6).

## 9. Platform backend matrix

**Linux — Landlock + seccomp (+ optional netns for the gateway side).**

- Filesystem read/write scope: Landlock filesystem access rights (available since ABI v1). Clean.
- Exec restriction: Landlock `FS_EXECUTE` on allowed paths, or seccomp on `execve`. Optional ([FW-ISO4](#fw-iso4)).
- Net default-deny: no Landlock net grants; deny is the absence of grant plus scope flags.
- Net port allowlist: Landlock `ACCESS_NET_CONNECT_TCP` (ABI v4+, port-only, no host filtering). Reported Unenforceable below v4.
- Cross-domain socket scoping: `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` and the pathname-socket scope are recent and coarse (they block sockets created outside the domain by parent/child relationship, not per-path allowlisting). Formwork uses them where present for [FW-ADV-006](#fw-adv-006) and reports the gap otherwise — and, critically, does **not** rely on them for the transport (that is the injected fd, [FW-XR7](#fw-xr7)).
- Anti-shedding: `NO_NEW_PRIVS` + seccomp baseline ([FW-ISO8](#fw-iso8)).

**macOS — Seatbelt (SBPL via `sandbox_init`).**

- Filesystem read/write scope: `file-read*` / `file-write*` with path filters. Clean.
- Exec restriction: `process-exec*` path filters. Optional.
- Net default-deny and host/port filtering: `network*` deny with `network-outbound` allowances. Seatbelt can filter by remote host/port and can gate UNIX-socket endpoints by path (the mechanism Chromium's macOS sandbox relies on) — so cross-domain socket control is cleaner here than on Linux.
- Descendant inheritance: the profile applies to the process and its children.

**Both.** The injected-fd transport behaves identically, since it is an inherited descriptor, not a mediated `connect()`. This is why [FW-XR6](#fw-xr6)/[FW-XR7](#fw-xr7) hold across platforms rather than diverging on socket semantics.

**Fidelity summary (typical modern host).**

| Capability | Linux | macOS |
|---|---|---|
| fs read/write scope | Enforced | Enforced |
| net default-deny | Enforced | Enforced |
| net host allowlist (direct) | Unenforceable direct (use gateway) | Partial (Seatbelt remote filters) |
| net port allowlist (direct) | Enforced (ABI v4+) / else Reported | Enforced |
| fs write vs create split ([FW-CAP9](#fw-cap9)) | Enforced (Landlock drops `Make*`) | Enforced (deny `file-write-create`) |
| exec allowlist | Enforced (optional) | Enforced (optional) |
| MCP tool/resource/prompt shading | Enforced (gateway) | Enforced (gateway) |
| cross-domain UNIX socket block | Partial (recent, coarse) | Enforced (path-gated) |
| filesystem invisibility (ENOENT) | Not provided (EACCES) | Not provided (EPERM/EACCES) |
| sensitive-set metadata denial | Partial (stat residual) | Enforced (metadata deny) |
| environment secret-scrub | Partial (heuristic) | Partial (heuristic) |
| credential floor: absolute rows | Enforced (Landlock deny) | Enforced (Seatbelt deny) |
| credential floor: any-depth rows | Partial (withheld; Landlock cannot root `**/`) | Enforced (regex) |
| credential env strip | Enforced (launcher-contingent) | Enforced (launcher-contingent) |
| `learn` denial feed | Provided (ptrace tap via installed `strace`, [FW-E2E-071](#fw-e2e-071)) | Provided (unified log, post-hoc) |

## 10. Requirements ↔ tests traceability

| Requirement | Primary tests | Also covered by |
|---|---|---|
| [FW-XR1](#fw-xr1) Fidelity honesty | [FW-E2E-024](#fw-e2e-024), 025 | 026, INV5 |
| [FW-XR2](#fw-xr2) Good-not-perfect boundary | (whole §3, §7.10) | ADV-001..006, 012..015 |
| [FW-XR3](#fw-xr3) Fail-closed egress | [FW-E2E-006](#fw-e2e-006), 025 | 007, 008, ADV-003 |
| [FW-XR4](#fw-xr4) Descendant inheritance | [FW-E2E-005](#fw-e2e-005) | ADV-001, 005, INV2 |
| [FW-XR5](#fw-xr5) Single privileged broker | [FW-E2E-019](#fw-e2e-019) | 010, ADV-005 |
| [FW-XR6](#fw-xr6) Behavioral parity | [FW-E2E-028](#fw-e2e-028) | 024, 071 |
| [FW-XR7](#fw-xr7) fd-injection transport | [FW-E2E-010](#fw-e2e-010), 012 | 011, ADV-006 |
| [FW-XR8](#fw-xr8) No agent-influenced escalation | [FW-ADV-001](#fw-adv-001) | [FW-E2E-005](#fw-e2e-005), INV1 |
| [FW-XR9](#fw-xr9) Surface fail-fast | [FW-E2E-062](#fw-e2e-062) | INV5, INV6 |
| [FW-CAP1](#fw-cap1) Enumerable vocabulary | [FW-E2E-013](#fw-e2e-013), 001 | — |
| [FW-CAP2](#fw-cap2) Monotonic narrowing | [FW-E2E-005](#fw-e2e-005) | INV1 |
| [FW-CAP3](#fw-cap3) Subtractive default profile | [FW-E2E-003](#fw-e2e-003), 020 | 021, 022 |
| [FW-CAP4](#fw-cap4) Invisibility/denial split | [FW-E2E-013](#fw-e2e-013), 014 | 001, 023 |
| [FW-CAP5](#fw-cap5) Inspectable interpreter | [FW-E2E-026](#fw-e2e-026), 027 | 024 |
| [FW-CAP6](#fw-cap6) Anchored & basename patterns | [FW-E2E-038](#fw-e2e-038) | [FW-FID4](#fw-fid4) |
| [FW-CAP7](#fw-cap7) Metadata denial (sensitive set) | [FW-E2E-037](#fw-e2e-037) | INV5 |
| [FW-CAP8](#fw-cap8) Three-layer evaluation, deny-terminal | [FW-E2E-058](#fw-e2e-058) | INV11, [FW-BP4](#fw-bp4) |
| [FW-CAP9](#fw-cap9) Verb grammar & create/write split | [FW-E2E-056](#fw-e2e-056) | 061 |
| [FW-ISO1](#fw-iso1) Read confinement | [FW-E2E-001](#fw-e2e-001) | 003, 004 |
| [FW-ISO2](#fw-iso2) Write confinement | [FW-E2E-002](#fw-e2e-002) | 004 |
| [FW-ISO3](#fw-iso3) Net default-deny | [FW-E2E-006](#fw-e2e-006) | 007, 008, INV3 |
| [FW-ISO4](#fw-iso4) Optional exec restriction | [FW-ADV-001](#fw-adv-001) | — |
| [FW-ISO5](#fw-iso5) Optional port tier | [FW-E2E-009](#fw-e2e-009) | 025 |
| [FW-ISO6](#fw-iso6) Two postures | [FW-E2E-001](#fw-e2e-001) | — |
| [FW-ISO7](#fw-iso7) Capability detection | [FW-E2E-025](#fw-e2e-025), 026 | INV6 |
| [FW-ISO8](#fw-iso8) Anti-shedding baseline | [FW-ADV-001](#fw-adv-001) | 002, INV2 |
| [FW-ISO9](#fw-iso9) Exec as a verb | [FW-E2E-061](#fw-e2e-061) | [FW-XR6](#fw-xr6) |
| [FW-GW1](#fw-gw1) Transport-agnostic backends | [FW-E2E-010](#fw-e2e-010) | 019 |
| [FW-GW2](#fw-gw2) Tool shading | [FW-E2E-013](#fw-e2e-013), 014 | ADV-004 |
| [FW-GW3](#fw-gw3) Full-surface policy | [FW-E2E-015](#fw-e2e-015), 016, 017 | — |
| [FW-GW4](#fw-gw4) Single door | [FW-E2E-012](#fw-e2e-012) | ADV-003 |
| [FW-GW5](#fw-gw5) Backend confinement | [FW-E2E-019](#fw-e2e-019) | ADV-005 |
| [FW-GW6](#fw-gw6) fd minting | [FW-E2E-011](#fw-e2e-011) | 010 |
| [FW-GW7](#fw-gw7) Least-privilege gateway | [FW-E2E-019](#fw-e2e-019) | ADV-003 |
| [FW-GW8](#fw-gw8) Transparent passthrough | [FW-E2E-018](#fw-e2e-018) | 020, 021 |
| [FW-GW9](#fw-gw9) Pattern-matched shading | [FW-E2E-065](#fw-e2e-065), 066, 067 | 068, 069, ADV-004 |
| [FW-TRA1](#fw-tra1) Ambient reuse | [FW-E2E-020](#fw-e2e-020), 021 | 022 |
| [FW-TRA2](#fw-tra2) Toolchains run clean | [FW-E2E-020](#fw-e2e-020), 021, 022 | 023 |
| [FW-TRA3](#fw-tra3) Sensitive-set subtraction | [FW-E2E-003](#fw-e2e-003) | 004 |
| [FW-TRA4](#fw-tra4) Graceful denial | [FW-E2E-023](#fw-e2e-023) | 020, 021 |
| [FW-TRA5](#fw-tra5) Writable working set | [FW-E2E-002](#fw-e2e-002), 022 | 020 |
| [FW-TRA6](#fw-tra6) Low overhead | §8 targets | 020, 021 |
| [FW-TRA7](#fw-tra7) Execution-vector write protection | [FW-E2E-039](#fw-e2e-039) | — |
| [FW-TRA8](#fw-tra8) Agent-state & local-secret coverage | [FW-E2E-038](#fw-e2e-038) | [FW-E2E-003](#fw-e2e-003) |
| [FW-FID1](#fw-fid1) Per-capability report | [FW-E2E-024](#fw-e2e-024) | 025 |
| [FW-FID2](#fw-fid2) Dry-run / audit | [FW-E2E-026](#fw-e2e-026) | 027 |
| [FW-FID3](#fw-fid3) Runtime observability | [FW-E2E-024](#fw-e2e-024) | — |
| [FW-FID4](#fw-fid4) Deterministic compile | [FW-E2E-027](#fw-e2e-027) | 026 |
| [FW-FID6](#fw-fid6) Rule provenance & explain | [FW-E2E-059](#fw-e2e-059) | [FW-CAP5](#fw-cap5), [FW-CAP8](#fw-cap8) |
| [FW-FID7](#fw-fid7) Resolved-input disclosure | [FW-E2E-069](#fw-e2e-069) | 059, 062 |
| [FW-ENV1](#fw-env1) Environment axis | [FW-E2E-036](#fw-e2e-036) | [FW-FID1](#fw-fid1) |
| [FW-ENV2](#fw-env2) Default secret-shaped scrub | [FW-E2E-036](#fw-e2e-036) | [FW-TRA2](#fw-tra2) |
| [FW-BP1](#fw-bp1) One model, many surfaces | [FW-E2E-043](#fw-e2e-043), 060 | 042 |
| [FW-BP2](#fw-bp2) Override precedence | [FW-E2E-042](#fw-e2e-042), 060 | 043 |
| [FW-BP3](#fw-bp3) `extends` composition | [FW-E2E-044](#fw-e2e-044) | — |
| [FW-BP4](#fw-bp4) allow/deny/subtract | [FW-E2E-042](#fw-e2e-042) | 045, 049 |
| [FW-BP5](#fw-bp5) Path sigils | [FW-E2E-055](#fw-e2e-055) | — |
| [FW-BP6](#fw-bp6) Flat verb rules | [FW-E2E-058](#fw-e2e-058), 061 | [FW-CAP9](#fw-cap9) |
| [FW-BP7](#fw-bp7) Mode posture | [FW-E2E-057](#fw-e2e-057), 060 | — |
| [FW-BP8](#fw-bp8) Discovery trust scope | [FW-E2E-070](#fw-e2e-070) | [FW-XR8](#fw-xr8) |
| [FW-CRED1](#fw-cred1) Typed catalog | [FW-E2E-045](#fw-e2e-045), 046 | 049 |
| [FW-CRED2](#fw-cred2) Two kinds, two arms | [FW-E2E-045](#fw-e2e-045), 046 | 050 |
| [FW-CRED3](#fw-cred3) Env-points-to-file | [FW-E2E-047](#fw-e2e-047) | — |
| [FW-CRED4](#fw-cred4) Deny-superset default | [FW-E2E-045](#fw-e2e-045), 046, 049 | — |
| [FW-CRED5](#fw-cred5) Exclude-by-type | [FW-E2E-048](#fw-e2e-048) | ADV-013 |
| [FW-CRED6](#fw-cred6) Generic backstop | [FW-E2E-049](#fw-e2e-049) | ADV-015 |
| [FW-CRED7](#fw-cred7) Channel split | [FW-E2E-045](#fw-e2e-045), 046 | ADV-012, INV9 |
| [FW-CRED8](#fw-cred8) Report mechanism | [FW-E2E-050](#fw-e2e-050) | ADV-014 |
| [FW-CRED9](#fw-cred9) Floor enforceability | [FW-E2E-050](#fw-e2e-050) | INV5; Linux kernel enforcement deferred |
| [FW-DISC1](#fw-disc1) Learning mode | [FW-E2E-051](#fw-e2e-051) | 054, 062, 064, 071 |
| [FW-DISC2](#fw-disc2) Reverse compile | [FW-E2E-051](#fw-e2e-051) | 052, 053, 064, 071 |
| [FW-DISC3](#fw-disc3) Catalog floor | [FW-ADV-013](#fw-adv-013), 015 | 051, INV8 |
| [FW-DISC4](#fw-disc4) Auto-widen zone | [FW-E2E-052](#fw-e2e-052) | 054 |
| [FW-DISC5](#fw-disc5) Review diff | [FW-E2E-051](#fw-e2e-051), 063 | 053 |
| [FW-DISC6](#fw-disc6) Provenance | [FW-E2E-053](#fw-e2e-053) | 063 |
| [FW-DISC11](#fw-disc11) Loop drivability | [FW-E2E-063](#fw-e2e-063) | 062 |
| Launcher arm (§2) | [FW-E2E-046](#fw-e2e-046), 050 | 047, INV7, ADV-014 |

## 11. Open questions

**Naming of the layers.** Whether *Formwork* names the whole system or the confiner alone, with a separate name for the gateway. The mould metaphor argues for confiner-only; product convenience argues for the umbrella. Unresolved.

**Exec restriction in v1.** [FW-ISO4](#fw-iso4) is off by default and nearly free to implement. Whether it ships enabled-optional in v1 or is deferred is a scope call; confining fs + net already contains most of what a rogue exec could do.

**fd-minting default.** Whether the default is pre-open-all-known-fds at spawn (simple, requires the connection set to be known up front) or a control-fd with on-demand `SCM_RIGHTS` minting (general, slightly more machinery). Likely pre-open as default with on-demand as the escape hatch.

**Credential brokering.** Excluding a type ([FW-CRED5](#fw-cred5)) exposes the file/var to the agent. The stronger alternative — the gateway brokers the credential's *use* without the agent ever seeing the bytes — fits the single-privileged-broker shape but presupposes TLS termination and a secret-handling path through the broker. Deferred to a later FEP. *(The older sensitive-set-discovery question — auto-detect vs configure the subtracted set — was resolved by the typed catalog + backstop, §5.9, deny-the-superset by default, and observe-then-widen discovery, §5.10.)*

**Blueprint serialization format.** TOML is the shipped surface (strict, `deny_unknown_fields` as a security asset), fixed at FEP-2 planning; it fights nesting exactly where Blueprints are deepest. Revisit only with a concrete need for logic, and then by adopting an existing configuration language (§4), never authoring one.

**Linux gateway egress isolation build-vs-buy.** Whether the gateway's own network confinement reuses `bubblewrap`/`pasta`/`slirp4netns` for its netns setup or drives `unshare`/nftables directly. Out of the agent's confinement path ([FW-XR7](#fw-xr7)), but a real implementation decision for [FW-GW7](#fw-gw7).

**Host-scoped egress and violation streaming.** The net axis today is `Deny | Ports`. A host-allowlist posture (FW-EGR — so a blueprint can say "reach the model API and nothing else") and a real-time violation stream for embedding hosts ([FW-FID5](docs/fep-1.md#fw-fid5)) are specified in `docs/fep-1.md`, deferred pending the gateway forward-proxy and log-tap subsystems they require.

**Windows.** Out of scope for this proposal. If needed later, the analogous primitives (AppContainer, Restricted Tokens, Named Pipes for the fd seam) would be a third backend behind the same compiler.

## 12. Implementation order

Kernel-mechanism-first, honesty-first, reuse-validated-early:

1. **Compiler + FidelityReport + dry-run**, with the deterministic-compile and dry-run tests ([FW-E2E-026](#fw-e2e-026), 027). No kernel calls; runs anywhere, including CI on macOS for Linux policies.
2. **Linux confiner** (Landlock fs + seccomp baseline + net-deny), spawn-confined posture, with the filesystem, descendant, and anti-shedding tests ([FW-E2E-001](#fw-e2e-001)..005, ADV-001, 002) and report-soundness ([FW-E2E-024](#fw-e2e-024)).
3. **macOS confiner** (Seatbelt), same test set, then cross-platform equivalence ([FW-E2E-028](#fw-e2e-028)).
4. **Reuse validation** against real toolchains ([FW-E2E-020](#fw-e2e-020)..023) — early, because if the default profile is not transparent enough to reuse the environment, the philosophy has failed and the profile needs rework before anything else is built on it.
5. **fd-injection transport** and the seam tests ([FW-E2E-010](#fw-e2e-010), 011, 012), establishing that the agent never depends on in-sandbox connect or socket-path gating.
6. **Gateway** (transport-agnostic backends, shading, full-surface policy, transparent passthrough, backend-confinement recursion) with [FW-E2E-013](#fw-e2e-013)..019 and ADV-003, 004, 005.
7. **Degraded-host honesty and optional tiers** ([FW-E2E-009](#fw-e2e-009), 025, ADV-006), confirming Formwork reports rather than pretends when a kernel cannot enforce a requested capability.
8. **Capability-model hardening** (FEP-1): the env axis ([FW-ENV1](#fw-env1)/2), execution-vector write-subtract ([FW-TRA7](#fw-tra7)), sensitive-set metadata denial ([FW-CAP7](#fw-cap7)), any-depth patterns ([FW-CAP6](#fw-cap6)), extended sensitive set ([FW-TRA8](#fw-tra8)), and the anti-escalation guarantee ([FW-XR8](#fw-xr8)) — landed and compiled/enforced on both backends. The fs additions are real-Seatbelt verified ([FW-E2E-037](#fw-e2e-037)..039); the env axis (a CLI-shell spawn transform, not a kernel capability) by unit tests plus the FidelityReport. Host-scoped egress (FW-EGR) and the violation stream ([FW-FID5](docs/fep-1.md#fw-fid5)) remain deferred in `docs/fep-1.md`.

9. **Blueprints, the credential catalog, and discovery** (FEP-2): the layered Blueprint model with `extends`, a CLI override surface, and path sigils ([FW-BP1](#fw-bp1)–5), the typed credential catalog enforced across the confiner and the launcher arm with per-type report labels and per-platform honesty ([FW-CRED1](#fw-cred1)–9), and observe-then-widen discovery bounded by the catalog floor ([FW-DISC1](#fw-disc1)–6; [FW-INV7](#fw-inv7)–10) — landed and folded into this document (§2, §4, §5.8–5.10, §6, §7.7–7.10), verified on real Seatbelt + the unified-log denial feed ([FW-E2E-041](#fw-e2e-041)..055, [FW-ADV-012](#fw-adv-012)..015). On Linux the catalog's path arm rides whatever carries fs enforcement, with any-depth floor rows reported Partial per [FW-CRED9](#fw-cred9). Credential brokering remains deferred (§11).

10. **Filesystem capability rules** (FEP-3): a flat verb-rule grammar and a `mode` posture over the existing model ([FW-BP6](#fw-bp6)/[FW-BP7](#fw-bp7)), the three-layer deny-terminal evaluation named as a first-class property ([FW-CAP8](#fw-cap8), [FW-INV11](#fw-inv11)), the create/write split ([FW-CAP9](#fw-cap9)), exec-as-a-verb with cross-backend parity ([FW-ISO9](#fw-iso9)/[FW-XR6](#fw-xr6)), and rule provenance + `formwork explain` ([FW-FID6](#fw-fid6)) — landed and folded into this document (§4, §5.2–5.3, §5.6, §5.8, §6, §7.7, §9, §10), with a Seatbelt paired allow/deny probe for the split ([FW-E2E-056](#fw-e2e-056)..058, [FW-E2E-061](#fw-e2e-061)) and a dry-run explain probe ([FW-E2E-059](#fw-e2e-059)). FEP-3 landed in full; one proposed extra, per-deny mechanism labels, was dropped (on macOS every deny is uniformly LSM-enforced so the label carries no information, and its Linux-only disclosures reference machinery not built).

If steps 1–4 pass, Formwork is a transparent, reusable filesystem confiner that behaves the same on both platforms and tells the truth about itself. If steps 5–7 pass, it is a complete agent sandbox: one privileged broker, everything else in a mould, egress forced through a policy gateway, and every claim backed by a mechanism or reported as a gap.