# Formwork codebase research — as-built

*Research date: 2026-07-14. Branch: `claude/codebase-research-docs-2s4fhv` (in sync with
`origin/main` at `c97a81e`). This document describes the codebase exactly as it exists today:
what the code, docs, profiles, tests, and CI contain. It records no recommendations, no gap
analysis beyond what the code/docs already report about themselves, and no future work.*

## High-level summary

Formwork is a Rust workspace (7 crates, ~9,900 lines of Rust) plus a `uv`-managed Python
black-box test harness. It is an OS-level sandbox for agent sessions: it takes a capability
**Blueprint**, compiles it — purely, with no kernel calls — into a **CompiledPolicy** (a
confiner policy, a gateway policy, and a **FidelityReport**), and enforces it through three arms:
a **launcher** (pre-spawn env construction + credential strip), a **confiner** (Landlock+seccomp
on Linux / Seatbelt on macOS, applied to a process and every descendant), and a **gateway**
(an MCP-aware policy proxy). The agent reaches the gateway only through an injected file
descriptor (the **seam**: socketpair-at-spawn + `SCM_RIGHTS` minting), never an in-sandbox
`connect()`. The design centers on three principles stated in `formwork.md:9-17` — good-not-perfect
isolation, transparency/reuse, and honesty (the report never claims containment a host cannot
deliver). Requirements carry stable IDs (`FW-<FAMILY><n>`, `FW-INV<n>`, `FW-E2E-<nnn>`,
`FW-ADV-<nnn>`) defined in `formwork.md`/`fep-1.md`, cited bare in code and as links in markdown,
with CI canaries enforcing that they resolve.

Verified live on this host (Linux, kernel 6.18.5, `landlock-abi: null`, `seccomp: true`):
`cargo build --workspace` and `cargo test --workspace` pass (all crate suites green; macOS-gated
suites hold 0 tests on Linux); `cd py && uv run pytest` reports 15 passed, 22 skipped (the skips
are macOS/Seatbelt-gated).

---

## 1. Repository layout and governing documents

### 1.1 Top-level structure

```
formwork/
├── Cargo.toml                 # workspace manifest (7 members)
├── constitution.md            # project doctrine (supreme document)
├── formwork.md                # design + end-to-end test spec (~80 KB); mints most FW-* IDs
├── IMPLEMENTATION_PLAN.md     # how/order/mechanisms companion to formwork.md
├── fep-1.md                   # FEP-1 deferred remainder (FW-EGR family, FW-FID5)
├── fep2.md                    # FEP-2 (landed pointer)
├── competition-research.md    # competitive research, dated 2026-07-06
├── justfile                   # task runner recipes
├── crates/                    # the 7 Rust crates
├── profiles/                  # default.toml + credential-catalog.toml
├── py/                        # uv-managed Python E2E/adversarial harness (dev-only)
├── docs/                      # linux-backend.md, spikes.md, fep2-plan.md, fep2-examples.md
├── examples/                  # blueprints + per-host (claude-code/codex/opencode) wiring
├── docker/                    # Dockerfile.linux-test, Dockerfile.linux-dev
└── .github/workflows/         # ci.yml, release.yml
```

### 1.2 Workspace manifest

`Cargo.toml:1-44` defines a resolver-2 workspace with 7 members (`Cargo.toml:3-11`), shared
`workspace.package` (`version = "0.1.0"`, `edition = "2021"`, `rust-version = "1.85"`,
`license = "MIT OR Apache-2.0"`, `Cargo.toml:13-18`), and shared dependencies (`Cargo.toml:20-40`):
`serde`, `serde_json`, `toml`, `clap`, `anyhow`, `thiserror`, `tracing`, `tracing-subscriber`, plus
the Linux-only confiner backends `landlock = "0.4"` and `seccompiler = "0.4"` (`Cargo.toml:33-34`,
commented as "the whole of" the trust-base widening). `[profile.release] lto = "thin"`
(`Cargo.toml:42-43`).

### 1.3 Constitution (`constitution.md`)

The supreme document (`constitution.md:8-16`). It fixes a **closed concept list** with one Rust
type each (`constitution.md:18-62`): Blueprint, Catalog, Launcher, HostProfile, CompiledPolicy,
FidelityReport, Confiner, Gateway, Seam, Session, Posture. It pins the **data model** — the
Blueprint schema, FidelityReport/CompiledPolicy shapes, default profile + credential catalog,
discovery artifacts, and the CLI surface (`constitution.md:64-86`) — with expand→migrate→contract
change discipline and byte-deterministic compile (`FW-FID4`). It fixes **vocabulary** one word per
concept (`constitution.md:88-118`: detect/compile/enforce/narrow/confine/shade/subtract/mint/floor/
strip/exclude/learn/withheld/accept/provenance; three fidelity verdicts; hide vs deny; fail-closed/
fail-loud/fail-open-silent). It defines the **requirement-ID convention** (`constitution.md:120-157`)
and the **layer dependency direction** (`constitution.md:219-239`):

```
formwork-blueprint (pure domain) → formwork-detect → formwork-compile
  → formwork-confine · formwork-seam → formwork-gateway → formwork-cli
```

Other sections: Boundaries/parse-don't-validate (`:159-181`), Errors/fail-closed-or-loud
(`:182-201`), Observability/tracing at boundaries (`:203-217`), Growth/default-no (`:240-255`),
Comments/why-only (`:257-263`), Testing/no-mock-for-behavior (`:265-288`), Precedence & Conflicts
(`:290-308`). It records **no active exceptions** (`constitution.md:305`).

### 1.4 Design spec (`formwork.md`) and plan (`IMPLEMENTATION_PLAN.md`)

`formwork.md` holds: design philosophy (`:9-17`), architecture with the ASCII diagram (`:19-63`),
threat model in/out of scope (`:65-85`), the blueprint grammar (`:87-129`), the full requirement
tables §5 (`:131-260`), invariants §6 (`:262-286`), end-to-end tests §7 (`:288-424`), performance
targets §8 (`:426-437`), the platform backend matrix §9 (`:439-475`), the requirements↔tests
traceability table §10 (`:477-546`), open questions §11 (`:548-564`), and implementation order §12
(`:566-581`). `IMPLEMENTATION_PLAN.md` is the how/order companion: language split (`:7-27`), repo
layout (`:29-61`), key technical decisions per mechanism (`:63-206`), phases 0–7 (`:208-282`),
test/CI strategy (`:284-317`), risk register (`:318-329`), and resolved open questions (`:330-339`).

### 1.5 FEP documents

- `fep2.md` — **landed in full and folded into `formwork.md`** (`fep2.md:1-31`): the spec→Blueprint
  rename + layered model (`FW-BP1`–5), the typed credential catalog (`FW-CRED1`–9), the launcher as
  a third arm, observe-then-widen discovery (`FW-DISC1`–6), invariants `FW-INV7`–10, and tests
  `FW-E2E-041`–055 / `FW-ADV-012`–015. Deferred beyond it: credential brokering and live
  interactive discovery prompting (`fep2.md:33-42`).
- `fep-1.md` — the **deferred remainder** (`fep-1.md:1-24`): the capability-model half landed
  (env axis, write-subtract, agent-state coverage, `**/` patterns, metadata denial, anti-escalation);
  what remains is **Part A host-scoped egress** (new `FW-EGR1`–6, needs a gateway forward proxy,
  `fep-1.md:41-148`) and **`FW-FID5` real-time violation stream** (`fep-1.md:150-168`).
- `docs/fep2-plan.md` — FEP-2 execution record: drafting-conflict resolutions (test-ID
  renumbering table `:23-42`, the `FW-BP2` layer-order fix `:47-62`, `FW-BP4` pinned to the `FW-CAP6`
  grammar `:64-84`), the merge algebra (`:86-123`), catalog data/enforcement (`:124-167`), launcher
  arm (`:169-189`), discovery (`:191-231`), E2E test design (`:233-305`), and a post-implementation
  constitutional review (`:342-397`).

### 1.6 Status as the docs state it

`README.md:19-35` records phase completion (Phase 1 done, Phase 3 macOS Seatbelt done, Phase 5
seam done, Python E2E done, Phase 6 gateway done; Phase 2 Linux confiner marked "designed…honest
stub — needs a 5.13+ kernel to verify"). `docs/linux-backend.md:1-9` then records the Linux backend
as **"implemented and kernel-verified"** against a real ABI-v6 kernel, with a hardening-decisions
list (`docs/linux-backend.md:11-37`). `docs/spikes.md` records the Phase-0 spike findings, including
degraded-host honesty verified on real Linux at kernel 5.10 (no Landlock) (`docs/spikes.md:82-96`).
`competition-research.md` is dated 2026-07-06 and its TL;DR lists gaps (write-protection, Linux
enforcement) that the later `docs/linux-backend.md` and shipped `write-subtract` defaults address —
i.e. it predates those landings (`competition-research.md:1-24`).

---

## 2. `formwork-blueprint` — pure capability domain

The pure data + pure functions crate; no I/O of its own (`crates/formwork-blueprint/src/lib.rs:1-2`,
`catalog.rs:1-4`, `discovery.rs:1-6`). Modules declared and re-exported at
`crates/formwork-blueprint/src/lib.rs:4-19`: `catalog`, `discovery`, `launcher`, `layer`, `narrow`,
`path`.

### 2.1 Core Blueprint types (`src/lib.rs`)

- `struct Blueprint` (`crates/formwork-blueprint/src/lib.rs:26-45`): `fs: FsBlueprint`, `net:
  NetPosture`, `exec: ExecPosture`, `env: EnvPosture`, `mcp: BTreeMap<String, McpPolicy>`,
  `allow_credentials: Vec<String>`, `discovery: DiscoveryBlueprint`. Serde `deny_unknown_fields`,
  kebab-case. `allow_credentials` is documented as the only lift of a typed catalog entry
  (`:39-42`).
- `struct DiscoveryBlueprint` (`:49-54`): `auto_widen: Vec<PathPattern>` — the operator-drawn
  self-grant zone, empty by default.
- `struct FsBlueprint` (`:57-74`): `read_mode`, `reads`, `writes`, `subtract`, `write_subtract`.
  Documented semantics: writes imply reads; `subtract` denies read+write; `write_subtract` denies
  write only, keeps readable (tamper vectors).
- `enum ReadMode` (`:78-84`): `Closed` (default) | `AmbientMinusSubtract`.
- `enum NetPosture` (`:88-94`): `Deny` (default) | `Ports(Vec<u16>)`.
- `enum ExecPosture` (`:96-102`): `Unrestricted` (default) | `Allowlist(Vec<PathPattern>)`.
- `enum EnvPosture` (`:108-118`): `Passthrough` (default) | `Allowlist(Vec<String>)` |
  `Scrub(EnvScrub)`; methods `apply` (`:135-144`), `dropped_names` (`:147-161`, telemetry, never
  values), `canonicalize` (`:163-174`).
- `struct EnvScrub` (`:123-130`): `allow`/`deny`; `keeps` (`:178-186`, allow wins then deny then
  drop-if-secret-shaped).
- Secret-shape heuristic (`FW-ENV2`): `env_is_secret_shaped` (`:205-223`, name markers at
  `:206-217`), `env_value_is_secret` (`:225-236`: PEM, `ghp_`/`gho_`/`github_pat_`, `xoxb-`/`xoxp-`,
  `sk-`, `AKIA`, `AIza`, JWT), `is_jwt` (`:239-241`).
- `struct McpPolicy` (`:244-257`): `tools`/`resources`/`prompts: Visibility`, `sampling`/
  `elicitation: Gate`; `Default` default-denies the whole surface (`:259-270`).
- `enum Visibility` (`:274-281`): `AllowAll` | `Allow(Vec<String>)` | `Deny` (default); `permits`
  (`:284-290`).
- `enum Gate` (`:293-299`): `Allow` | `Deny` (default).
- `Blueprint::empty()` — the fail-closed floor (`:304-314`); `Blueprint::canonicalize()` canonicalizes
  every field for byte-determinism (`:318-343`).

### 2.2 Path patterns (`src/path.rs`)

Three grammars documented at `crates/formwork-blueprint/src/path.rs:1-7`: (1) plain absolute with
optional `/**` subtree; (2) recursive-basename `**/<suffix>`; (3) anchored `<prefix>/**/<suffix>`.

- `struct PathPattern` (`:15-25`): private `base`, `subtree`, `any_depth`, `anchor`.
- `enum PathError` (`:27-35`): `NotAbsolute` | `Empty` | `EscapesRoot`.
- `parse` (`:38-118`): recursive-basename branch (`:45-61`), anchored branch (`:66-96`), plain branch
  (`:98-117`).
- `canonical` (`:141-158`) round-trips through `parse`.
- `matches_path` (`:163-190`) — kernel-style pattern→concrete-path match; any-depth uses a sliding
  `windows` match for subtree, trailing-component match otherwise.
- `covers` (`:198-234`) — the pattern→pattern narrowing primitive; four cases keyed on
  `(self.any_depth, other.any_depth)`; `(true,false)` is always `false` (conservative per
  `FW-INV6`, `:196-197`).
- `normalize_absolute` (`:238-256`) / `normalize_relative` (`:260-283`) — purely lexical.
- `canonicalize_set` (`:317-333`) — sort, dedupe, drop patterns covered by another.

### 2.3 Layered composition (`src/layer.rs`)

- `struct BlueprintLayer` (`crates/formwork-blueprint/src/layer.rs:14-38`): all-optional mirror of
  `Blueprint` plus `extends`, `allow_credentials`, `discovery`. `Option`/`skip_serializing_if`
  because layers are also written out.
- `struct FsLayer` (`:42-55`): `read_mode: Option<ReadMode>` so absent means inherit.
- `struct DiscoveryLayer` (`:71-78`): `auto_widen` (capability, merged) + `provenance` (metadata,
  deliberately not merged).
- `struct ProvenanceEntry` (`:86-92`): `added_via` (`discovery`|`discovery-auto`), `run_id`.
- `fn merge(layers) -> Blueprint` (`:97-128`): read_mode last-set-wins; path sets union; net/exec/env
  wholesale-replace if `Some`; mcp per-server last-set-wins; allow_credentials + auto_widen union;
  returns `canonicalize()`. The credential floor is **not** applied here — that is the compiler's
  job (`:94-96`).

### 2.4 Credential catalog (`src/catalog.rs`)

- Builtin embedded via `include_str!("../../../profiles/credential-catalog.toml")`
  (`crates/formwork-blueprint/src/catalog.rs:18`); `BACKSTOP = "backstop"` (`:16`).
- `struct Catalog` (`:20-26`) / `CatalogEntry` (`:28-41`, `paths`/`envs`/`env_file_refs`) /
  `BackstopEntry` (`:43-47`).
- `Catalog::builtin()` (`:52-57`, `OnceLock`), `resolve(home)` (`:69-105`, expands `~` and fails loud
  on unparsable patterns).
- `struct ResolvedCatalog` (`:111-117`) / `ResolvedEntry` (`:119-125`) — compiler-facing form.
- `denied_paths(allow)` (`:145-156`) — confiner-deny patterns for non-excluded types + backstop;
  `enforced_types(allow)` (`:159-167`); `floor_type_of(allow, candidate)` (`:180-207`) — which type
  or `BACKSTOP` floors a candidate (equality / either-direction `covers` / `matches_path`), skipping
  the backstop when the candidate falls inside an excluded type's scope (`:194-205`).

### 2.5 Discovery reverse-compile (`src/discovery.rs`)

- `enum DenialAccess` (`:12-17`), `struct DenialRecord` (`:20-24`), `enum CandidateTag`
  (`AutoAccepted`|`NeedsReview`, `:26-33`), `struct Candidate` (`:35-41`), `struct WithheldEntry`
  (`:46-50`), `struct ProposalOutcome` (`:52-56`).
- `fn reverse_compile(records, catalog, allow, auto_widen)` (`:61-140`): parse+dedupe+floor
  (`:71-88`, floor matches are withheld and skipped); sibling fold to `parent/**` only when ≥2
  siblings and the fold is not floored and would not cover a withheld path (`:90-132`); deterministic
  ordering (`:133-134`).
- `fn fold_would_cover_withheld` (`:144-148`) — `FW-INV8` defense-in-depth. `fn tag_candidate`
  (`:150-165`).

### 2.6 Narrowing algebra (`src/narrow.rs`, `FW-CAP2`)

Grants intersect (conservative under-approximation), deny-holes union (`crates/formwork-blueprint/
src/narrow.rs:1-4`). Primitives: `clamp_to` (`:12-18`), `intersect_grants` (`:23-27`, public — the
compiler uses it to clamp the `FW-CRED5` exemption to the grant surface), `union_grants` (`:29-33`).
`Blueprint::narrow` (`:37-61`) narrows each field; `allow_credentials` and `auto_widen` intersect.
Per-field: `narrow_fs` (`:64-95`, subtract/write_subtract union, writes intersect, four-way read-mode
combination), `narrow_net` (`:97-109`), `narrow_exec` (`:111-122`), `narrow_mcp`/`narrow_mcp_policy`
(`:124-146`), `narrow_visibility` (`:148-161`), `narrow_env` (`:169-193`), `narrow_gate` (`:195-201`).

Tests: `lib.rs:399-509`, `path.rs:335-508`, `layer.rs:158-359`, `catalog.rs:210-337`,
`discovery.rs:167-307`, `narrow.rs:203-360`.

---

## 3. `formwork-detect` — the one impure compile input

`HostProfile` is the single impure input to compilation; `detect()` probes the running kernel, but
profiles can be synthesized for cross-platform dry-run (`crates/formwork-detect/src/lib.rs:1-3`).

- `enum Os` (`crates/formwork-detect/src/lib.rs:7-13`): `Linux` | `MacOs` (serde lowercase,
  `macos`).
- `struct HostProfile` (`:17-32`): `os`, `landlock_abi: Option<u32>` (v1 fs / v4 +TCP-port / v6
  +abstract-unix+signal scoping), `seccomp: bool`, `seatbelt: bool`, `os_version: String`
  (report-only). Serializable so `formwork detect > host.json` can feed `compile --host`.
- `synthetic_linux(abi)` (`:35-43`), `synthetic_macos()` (`:45-53`).
- `fn detect()` (`:58-77`) — cfg-gated: Linux → `linux::detect()`, macOS → `macos::detect()`, else a
  fail-closed unsupported profile (all off, `os_version = "unsupported"`).
- Linux module (`:79-136`): `landlock_abi()` (`:86-101`, the `landlock_create_ruleset(NULL, 0,
  LANDLOCK_CREATE_RULESET_VERSION)` version probe), `seccomp_available()` (`:103-106`,
  `prctl(PR_GET_SECCOMP) >= 0`), `kernel_version()` (`:111-125`, `uname`).
- macOS module (`:138-185`): `product_version()` (`:142-174`, `sysctlbyname("kern.osrelease")`),
  `detect()` (`:176-184`). No tests in this crate.

---

## 4. `formwork-compile` — the pure compiler

Maps a `Blueprint` + `HostProfile` + `ResolvedCatalog` → `CompiledPolicy` (confiner + gateway +
FidelityReport); never touches the kernel (`crates/formwork-compile/src/lib.rs:1-4`). Modules
declared at `crates/formwork-compile/src/lib.rs:6-9`: `linux`, `policy`, `report`, `sbpl`.

### 4.1 Data flow

`compile(blueprint, host, catalog) -> CompiledPolicy` (`crates/formwork-compile/src/lib.rs:83-176`):
canonicalize blueprint (`:88`) → build `CompileInput::from_blueprint` (`:89`, defined `:51-78`) →
branch on `host.os` to `compile_macos`/`compile_linux` (`:91-109`) → insert host-independent rows
(`FsInvisibility` always `Unenforceable` `:111-119`; env rows `:125-146`; `McpShading` `:149-157`)
→ build `CredentialReport` (`:159`, defined `:184-237`) → assemble `FidelityReport`, `GatewayPolicy`,
return `CompiledPolicy` (`:160-175`). `to_canonical_json` (`:441-445`) is byte-identical for equal
inputs (`BTreeMap` + canonicalized vectors).

`struct CompileInput` (`:34-49`): `read_mode`, `effective_reads` (reads + writes), `writes`,
`subtract`, `write_subtract`, `floor` (from `catalog.denied_paths`), `floor_exempt` (excluded types'
scopes, `FW-CRED5`), `net`, `exec`. `from_blueprint` (`:52-77`).

### 4.2 Policy types (`src/policy.rs`)

Output is symbolic (patterns + seccomp plan), expanded at enforce time to keep `compile()` pure
(`crates/formwork-compile/src/policy.rs:1-3`).

- `CompiledPolicy { confiner, gateway, report }` (`:11-16`).
- `enum ConfinerPolicy` (tagged `platform`, `:20-32`): `Linux(LinuxPolicy)` | `Macos(MacosPolicy)` |
  `Unavailable { reason }`.
- `LinuxPolicy` (`:34-50`): `landlock_abi_target: Option<u32>`, `read_mode`, `reads`, `writes`,
  `subtract`, `write_subtract`, `exec: ExecPlan`, `net: LinuxNetPlan`, `seccomp: SeccompPlan`,
  `no_new_privs: bool`.
- `enum LinuxNetPlan` (`:52-62`): `SeccompDenyInet` | `LandlockTcp { ports }`.
- `enum ExecPlan` (`:65-70`): `Unrestricted` | `Allowlist { paths }`.
- `SeccompPlan` (`:74-86`): `deny_syscalls` (sorted), `deny_socket_families`, `restrict_userns`,
  `set_no_new_privs`. `enum SocketFamily` (`:88-96`): `Inet`/`Inet6`/`Packet`/`NetlinkNonRoute`.
- `MacosPolicy { sbpl: String }` (`:98-101`).
- `GatewayPolicy { servers: BTreeMap<String, McpPolicy>, direct_tcp_ports: Vec<u16> }` (`:105-110`).

### 4.3 FidelityReport (`src/report.rs`)

The honesty ledger; `enforce()` may only confirm or degrade, never upgrade
(`crates/formwork-compile/src/report.rs:1-3`).

- `enum Capability` (`:12-27`, `Ord`): `FsRead`, `FsWrite`, `NetDefaultDeny`, `NetPortTier`, `Exec`,
  `McpShading`, `CrossDomainSocket`, `FsInvisibility`, `EnvScrub`.
- `enum Backend` (`:31-43`): `Landlock`, `Seccomp`, `Seatbelt`, `Gateway`, `Launcher`, `None`.
- `enum DenialSemantics` (`:48-54`): `Hide` | `Deny` | `NotApplicable`.
- `enum Fidelity` (tagged `status`, `:58-71`): `Enforced { backend }` | `Partial { backend, reason }`
  | `Unenforceable { reason }`; `is_enforced()` (`:74-76`).
- `struct FidelityReport` (`:82-87`): `host`, `per_capability`, `semantics`, `credentials`.
- `struct CredentialReport` (`:93-103`): `catalog_version`, `allowed`, `per_type`, `backstop:
  Option<Fidelity>`, `launcher_contingency: String`.
- `struct CredentialFidelity` (`:109-116`): `path: Option<Fidelity>`, `env: Option<Fidelity>` (both
  `skip_serializing_if = "Option::is_none"`).
- `net_is_fail_closed()` (`:145-150`) — true iff `NetDefaultDeny` is `Enforced` or `Partial`.

Honesty representation: env `Scrub` reported `Partial` (heuristic) vs `Allowlist` `Enforced`
(`src/lib.rs:127-145`); Linux-without-Landlock → `FsRead`/`FsWrite` `Unenforceable` (`:301-311`);
any-depth credential rows downgraded `Partial` on Linux (`:197-209`); `FsInvisibility` permanently
`Unenforceable` (`:112-118`); no confiner → `ConfinerPolicy::Unavailable` (`:410-416`).

### 4.4 SBPL generation (`src/sbpl.rs`)

Last-match-wins ordering (`crates/formwork-compile/src/sbpl.rs:1-8`). `render` (`:15-41`) emits
`(version 1)` + `(allow default)` then net/reads/writes/exec. `render_net` (`:43-56`):
`(deny network*)` + optional per-port allows. Curated device/essentials literals (`:62-102`).
`render_reads` (`:104-172`): Closed-mode root-deny + re-allows; floor denies both `file-read*` and
`file-read-metadata` (`:144-151`); exemptions clamped via `intersect_grants` (`:155-166`).
`render_writes` (`:174-209`), `render_exec` (`:211-219`). `filter` (`:221-231`) chooses
`(regex …)`/`(subpath …)`/`(literal …)`; `any_depth_regex` (`:239-270`).

### 4.5 Linux policy generation (`src/linux.rs`)

Deny-list-shaped seccomp for transparency (`crates/formwork-compile/src/linux.rs:1-6`).
`LANDLOCK_NET_ABI = 4` (`:14`); `BASELINE_DENY` sorted syscall list (`:18-46`); `seccomp_plan`
(`:50-76`); `net_plan` (`:79-109`, `Deny` → `SeccompDenyInet`; `Ports` at ABI≥4 → `LandlockTcp`,
else `SeccompDenyInet` + `UnenforceableBelowAbi4`); `enum PortTier` (`:111-116`). `compile_linux`
(`src/lib.rs:277-439`), `compile_macos` (`:239-275`).

Tests: `tests/phase1.rs` (`FW-E2E-026` cross-platform `:41-66`, `FW-E2E-027` determinism `:69-84`,
`FW-INV5` every-enforced-names-a-backend `:87-104`, `FW-INV6` net-never-silently-open `:107-145`),
plus inline unit tests (`src/lib.rs:447-699`, `sbpl.rs:303-483`, `linux.rs:118-171`).

---

## 5. `formwork-confine` — the confiners (two postures)

Turns a `ConfinerPolicy` into kernel enforcement of a process and all descendants; Landlock+seccomp
on Linux, Seatbelt on macOS (`crates/formwork-confine/src/lib.rs:1-5`).

### 5.1 Public API (`src/lib.rs`)

- `enum ConfineError` (`crates/formwork-confine/src/lib.rs:21-31`): `Unavailable` |
  `MechanismFailed` | `Unimplemented` | `Io`.
- `spawn_confined(command, policy)` (`:35-42`) — configures (does not spawn) a `Command`;
  fail-closed.
- `enforce_self(policy)` (`:45-52`) — irreversible confine-self.
- `backend_label` (`:13-19`). Backend selection via `#[path]` cfg (`:54-71`); non-Linux/macOS →
  `Unimplemented` stub.

The two postures (`FW-ISO6`): **spawn-confined** installs in the forked child's `pre_exec` before
`execve` (Linux `src/linux/mod.rs:59-68`, macOS `src/macos/mod.rs:62-72`); **confine-self** restricts
in place (Linux `src/linux/mod.rs:70-74`, macOS `src/macos/mod.rs:74-77`).

### 5.2 Linux orchestration (`src/linux/mod.rs`)

Allocation-heavy work in the parent; the child's `pre_exec` issues only syscalls in kernel-required
order `NO_NEW_PRIVS → Landlock restrict_self → seccomp` (`crates/formwork-confine/src/linux/mod.rs:
1-6`). `linux_policy` (`:17-25`), `struct Plan` (`:27-33`), `build` (`:35-41`), `apply` (`:46-57`,
allocation-free on success), `spawn_confined` (`:59-68`), `enforce_self` (`:70-74`).

### 5.3 Landlock half (`src/linux/landlock.rs`)

Allow-list-only, so it re-adds Closed-mode essentials and does subtractive expansion; enforces at
exactly the compiler's `landlock_abi_target` and asserts `FullyEnforced` after `restrict_self`
(`crates/formwork-confine/src/linux/landlock.rs:1-9`). `READ_ESSENTIALS` (`:36-44`), `RW_DEVICES`
(`:45-51`). `abi_of` (`:53-64`). `struct Hole` + `covers`/`strictly_under` (`:66-104`), `holes_of`
(`:73-90`, rejects any-depth `**/` — "Linux enforcement of `**/` is pending"). `expand` (`:111-144`,
subtractive expansion, skips symlink entries). `build` (`:155-252`): drops `Execute` from
`handled_fs` unless exec allowlist (`:162-168`), always drops `IoctlDev` (`:169-176`),
`CompatLevel::HardRequirement` (`:180-183`), net governed only for `LandlockTcp` at ABI≥4 (`:184-189`),
`Scope::from_all` at ABI≥6 (`:190-199`). `apply` (`:258-277`) asserts `FullyEnforced`; `add_proc_self`
(`:282-290`) grants the child's own `/proc/self` post-fork.

### 5.4 seccomp half (`src/linux/seccomp.rs`)

Deny-list BPF, default `Allow` (`crates/formwork-confine/src/linux/seccomp.rs:1-5`). `build`
(`:24-83`): `deny_syscalls` as unconditional-match rules (an unresolved name refuses to install,
`FW-INV6`); `deny_socket_families` as `SYS_socket` arg0 conditions (AF_UNIX/socketpair untouched,
`FW-XR7`); `restrict_userns` via masked-flag `CLONE_NEWUSER` rule. `socket_family_rules` (`:110-136`,
`NetlinkNonRoute` = AF_NETLINK AND protocol≠NETLINK_ROUTE). `syscall_number` (`:140-166`) — explicit
match of 22 names; unknown → build error.

### 5.5 macOS Seatbelt (`src/macos/mod.rs`)

`extern "C"` declares `sandbox_init`/`sandbox_free_error` from libSystem, `flags = 0` treats the
profile as a literal SBPL string (`crates/formwork-confine/src/macos/mod.rs:18-21`). `sbpl_of`
(`:23-37`), `apply` (`:41-60`, returns the libsandbox error string on failure), `spawn_confined`
(`:62-72`), `enforce_self` (`:74-77`).

### 5.6 Probe binaries (test support, not shipped)

`fw-connect-probe.rs` (TCP connect to `93.184.216.34:80`, exit 0=leaked/7=denied/8=other),
`fw-udp-probe.rs` (UDP socket create+send, same codes), `fw-ioctl-probe.rs` (Linux `TIOCGWINSZ` on
`/dev/null`, exit 0=reached/7=denied/8=open-failed).

Tests: `tests/linux_confine.rs` (`#![cfg(target_os = "linux")]`, 11 tests incl. read grant, subtract,
write scope, symlink non-escape, `/proc/self`, device ioctls, net TCP/UDP deny, baseline transparency,
userns deny, confiner-matches-host); `tests/macos_confine.rs` (`#![cfg(target_os = "macos")]`, incl.
`FW-E2E-001`–006, 024 report-soundness, 037 metadata, 038 any-depth, 039 write-subtract, confine-self
posture).

---

## 6. `formwork-seam` — fd-injection transport

The agent reaches the gateway via an inherited or `SCM_RIGHTS`-passed fd, never an in-sandbox
`connect()` or a socket path; identical code on both platforms (`crates/formwork-seam/src/lib.rs:
1-8`). Entire implementation `#[cfg(unix)]` (`:26-30`). Docs note no production crate consumes it yet
(`:10-13`).

### 6.1 Public surface

- `enum SeamError` (`:15-24`): `Io` | `Protocol` | `Env`.
- `struct SeamPlan` (`:54-60`): `control: bool`, `preopen: Vec<String>`; builders `new`/
  `with_control`/`preopen` (`:63-75`).
- `struct Seam` (`:80-84`): holds child ends across the fork; `spawn` (`:89-92`), `into_host`
  (`:98-106`, drops child ends so the child's close is observable as EOF).
- `fn inject(command, plan) -> Seam` (`:112-194`) — sets up socketpairs, computes an fd `ceiling`
  above every source (`:153-165`), assigns target fds and advertises them via `FORMWORK_FD_*`
  env vars (`:167-172`), installs a `pre_exec` `dup2` closure (`:178-187`). Does not spawn.
- `struct SeamHost` (`:196-199`): `take_connection` (`:207-209`), `recv_mint_request` (`:219-254`,
  byte-by-byte, bounded by `MAX_CONTROL_LINE = 4096`), `fulfill_mint` (`:256-260`), `mint_socketpair`
  (`:264-270`), `accept_mint` (`:273-281`).
- `struct Minted` (`:201-204`).
- `mod child` (`:286-334`): `control()` (`:295-300`), `connection(name)` (`:303-307`), `mint(control,
  name)` (`:310-333`).
- `send_fd` (`:348-390`) / `recv_fd` (`:394-457`) — `sendmsg`/`recvmsg` with a 1-byte iov + a
  `SOL_SOCKET`/`SCM_RIGHTS` cmsg carrying one fd; `recv_fd` treats `MSG_CTRUNC` as fail-closed and
  sets CLOEXEC on any received fd (`FW-ADV-005`, `:453-455`).
- `env_var_for` (`:474-485`, deterministic sanitizer), `fd_from_env` (`:488-506`, fail-closed).
- Constants: `ENV_PREFIX = "FORMWORK_FD_"`, `ENV_CONTROL`, `STATUS_OK`/`STATUS_ERR` (`:40-44`).

### 6.2 `fw-seam-child` + test scaffolding

`src/bin/fw-seam-child.rs` — the in-sandbox test "agent" (exit 0=ok, 3=workload-failed, 4=net-leak,
`:20-22`); dispatches `preopen`/`mint` scenarios (`:69-116`), optional `--assert-net-denied` net
probe. `tests/common/mod.rs` — the stub echo "gateway" (`serve_ok` writes `"ok:<req>\n"`, `:46-52`).

Tests: `tests/seam_transport.rs` (cross-platform, `FW-E2E-010`/011/012 + missing-env honesty),
`tests/seam_confined.rs` (`#![cfg(target_os = "macos")]`, the zero-net halves under real Seatbelt,
incl. `012` run twice with the socket dir granted then denied to prove path-independence).

---

## 7. `formwork-gateway` — MCP-aware policy proxy

Between a confined agent and one backend; shading is binding only because the confiner leaves no
other door (`FW-GW4`, `crates/formwork-gateway/src/lib.rs:1-8`). Oracle-free refusals by
construction; stateless `*/list` filtering; byte-exact passthrough of granted traffic.

### 7.1 Public surface + internals

- `enum GatewayError` (`crates/formwork-gateway/src/lib.rs:26-32`): `Io` | `Confine`.
- `struct Gateway { policy: McpPolicy }` (`:157-160`); `new` (`:163-165`); `run<AR,AW,BR,BW>` (async,
  `:167-207`).
- `confined_command(program, args, backend_policy)` (`:439-448`) — builds a `std::process::Command`
  confined to the backend's own grant (`FW-GW5`).
- `enum ListKind` (`:34-40`), `enum Frame` (`:46-80`, variants `ToolCall`/`ResourceRead`/`PromptGet`/
  `ListRequest`/`Sampling`/`Elicitation`/`Response`/`Passthrough`), `Frame::parse` (`:83-141`),
  `Frame::into_raw` (`:143-154`). `MAX_FRAME_BYTES = 16 MiB` (`:24`).

### 7.2 Mechanism

`run` wraps writers in `Arc<Mutex>` and shares a `pending: HashMap<String, ListKind>` (`:181-183`),
launches two pumps, and `tokio::select!`s them so a one-sided hangup tears the connection down
(`:200-206`). `read_frame` (`:325-358`) is newline-delimited, fail-closed on oversize. `Frame::parse`
routes on `(method, id)` (`:100-140`); `raw` preserves exact bytes; pumps route on the variant, never
on parsed JSON.

- Agent→backend pump (`:210-279`): `ToolCall`/`ResourceRead`/`PromptGet` forward if `permits`, else
  `refuse` (`-32602` tool/prompt, `-32002` resource); `ListRequest` records into `pending` and
  forwards.
- Backend→agent pump (`:281-321`): `Sampling`/`Elicitation` forward if `Gate::Allow` else `police`;
  `Response` re-filters tracked list responses via `filter_list`.
- `filter_list` (`:364-385`) shades tools by `name`, resources by `uri`, templates by `uriTemplate`,
  prompts by `name`; drops items missing their id-field (fail-closed).
- `refuse` (`:390-400`) — logs `item`+`target` for the operator but returns only `message` (identical
  for hidden-real and nonexistent, `FW-ADV-004`). `police` (`:404-415`) answers the backend locally
  with `-32601`. `write_frame` (`:426-434`) locks the writer per frame.

### 7.3 `fw-mcp-fixture` + tests

`src/bin/fw-mcp-fixture.rs` — a hand-rolled stdio MCP backend (3 tools, 2 resources, 2 prompts, 2
templates) reacting to `trigger/list_changed` (`:118-123`), `trigger/sampling` (`:124-129`), and
`trigger/probe` (fs read + TCP connect probe for backend-confinement, `:130-144`).

Tests: `tests/gateway.rs` (`FW-E2E-013` invisibility, `014`/`ADV-004` oracle-free refusal, `015`
resource/prompt/template shading, `016` list_changed re-filtering, `017` sampling policing + allowed
passthrough, `018` transparent passthrough, `019` backend-confinement recursion `#[cfg(macos)]`);
inline unit tests (`src/lib.rs:450-531`).

---

## 8. `formwork-cli` — the `formwork` binary (v1 embedding surface)

One binary `formwork` from `crates/formwork-cli/src/main.rs` (`Cargo.toml [[bin]]`). Modules
`blueprint_load` and `learn` (`crates/formwork-cli/src/main.rs:20-21`).

### 8.1 Subcommands (clap)

`enum Cmd` (`crates/formwork-cli/src/main.rs:50-119`), seven subcommands:

| Subcommand | Defn | Handler | Notes |
|---|---|---|---|
| `detect` | `:52-53` | `:299-302` | HostProfile as JSON |
| `compile` | `:54-67` | `:303-319` | `--host`/`--target`/`--report-only` |
| `run` | `:68-74` | `:320` | spawn-confined; trailing `argv` |
| `enforce-self` | `:75-81` | `:321` | confine-self, then exec |
| `learn` | `:82-92` | `:322` | observe-then-widen (`FW-DISC1`) |
| `accept` | `:93-106` | `:323-327` | `--proposal`/`--entry`/`--all` |
| `gateway` | `:107-118` | `:328-332` | `--server`; fronts a stdio MCP backend |

Shared `BlueprintArgs` (`:124-155`): `--blueprint` (alias `--spec`), `--set`, `--read`, `--write`,
`--subtract`, `--write-subtract`, `--allow-cred`, `--net`, `--extends`. `load` (`:161-166`) assembles
the layer stack; `sugar_layer` (`:168-194`) desugars flags into one `BlueprintLayer`; `parse_net`
(`:197-216`); `enum Target` (`:218-238`, `linux-v1/v4/v6`, `macos`); `resolve_host` (`:254-266`).

Entry/telemetry: `init_telemetry` (`:270-282`, stderr subscriber, `EnvFilter` default `info`),
`main` (`:284-335`, root span `formwork{run_id, cmd}`), `home()` (`:240-242`), `cwd()` (`:247-252`,
fails loud per `FW-INV6`).

### 8.2 Enforcement path

`struct Session` (`:356-360`); `prepare_session` (`:362-395`): load stack → resolve catalog → extend
subtract with `env_file_ref_denies` (`FW-CRED3`) → `protect_policy_inputs` (`FW-XR8`) →
canonicalize-for-enforcement → `detect()` → `compile` → `itemize_credential_floor`.
`spawn_confined_child` (`:397-411`), `run` (`:413-428`), `learn_run` (`:433-469`, macOS window then
`learn::conclude_learning_run`; other hosts warn no-feed and write nothing),
`itemize_credential_floor` (`:476-502`), `apply_env` (`:508-524`, `construct_env` then `env_clear` +
set kept), `gateway`/`proxy` (`:530-576`), `exec_replace` (`#[cfg(unix)]`, `:578-590`).

### 8.3 `learn.rs`

`ProposalFile` (`crates/formwork-cli/src/learn.rs:29-36`), `ProposalEntry` (`:38-45`),
`proposal_path`/`discovered_path` (`:47-53`), `parse_sandbox_denial` (`:57-80`, parses a unified-log
Sandbox record), `collect_denials` (`:83-115`, `log show --style ndjson --last <n>s --predicate
'sender == "Sandbox"'`), `conclude_learning_run` (`:120-221`), `merge_proposal_entries` (`:228-247`,
sticky), `merge_into_discovered` (`:251-284`), `accept` (`:291-386`, re-checks the floor with no
exclusions and refuses matches, `FW-INV8`). Tests `:388-448`.

### 8.4 `blueprint_load.rs`

The impure CLI edge (`crates/formwork-cli/src/blueprint_load.rs:1-5`): `load_stack` (`:28-79`,
FW-BP2 stack baseline→extends→file→`--set`→discovered→sugar, validates `allow_credentials`),
`resolve_file`/`resolve_layer` (`:83-134`, cycle-detecting depth-first), `struct Sigils` (`:144-201`,
leading `~`/`$CWD` only), `canonicalize_for_enforcement` (`:209-222`), `parse_discovered_layer`
(`:226-251`, forbids `extends`, requires provenance `FW-DISC6`), `protect_policy_inputs` (`:257-279`),
`env_file_ref_denies` (`:287-321`), `canonicalize_catalog_for_enforcement` (`:326-336`),
`canon_pattern`/`canonicalize_existing_prefix` (`:338-399`). Tests `:401-611`.

### 8.5 `tests/profiles.rs`

Catalog-consistency canaries (`crates/formwork-cli/tests/profiles.rs:1-5`): `CORE_LOCATIONS` (23
patterns, `:11-35`), `CORE_ENV_STRIPS` (`:37-44`), `catalog_floor_covers_the_core_sensitive_locations`
(`:46-62`), `catalog_floor_strips_the_core_env_credentials` (`:64-79`),
`catalog_is_versioned_and_non_trivial` (`:81-90`, version≥1, types≥15).

---

## 9. Profiles

### 9.1 `profiles/default.toml`

Subtractive, not minimal (`FW-CAP3`, `profiles/default.toml:1-9`): `net = "deny"` (`:13`),
`exec = "unrestricted"` (`:15`), `env = { scrub = {} }` (`:20`), `[fs] read-mode =
"ambient-minus-subtract"` (`:26`), `reads = ["/**"]` (`:30-32`), `writes` = project + tmp scratch
(`:36-41`), `subtract = []` (`:46`, credential locations live in the catalog),
`write-subtract` = tamper vectors `.git/hooks`, `.git/config`, `.mcp.json`, `.vscode`, `.idea`
(`FW-TRA7`, `:52-58`).

### 9.2 `profiles/credential-catalog.toml`

Typed, versioned, locations-only, embedded at build time (`FW-CRED1`, `profiles/credential-catalog.
toml:1-14`). `version = 1`. Types include `aws` (`:18-31`, paths + envs + env-file-refs), `gcp`,
`azure`, `kube`, `docker` (whole `~/.docker/**`), `secrets-mount`, `ssh`, `gpg`, `keychain`,
`github`, `netrc`, `npm`, `cargo` (publish token only), `pypi`, `anthropic`, `openai`, `slack`,
`claude`, `codex`, `gemini`, `cursor`, `browser`, `system` (`/etc/shadow`, sudoers), `dotenv`
(`**/.env` family, `:138-148`), and `[backstop]` (`FW-CRED6`, generic any-depth rows `**/credentials`,
`**/id_rsa`, `**/id_ed25519`, …, `:160-168`).

---

## 10. Python E2E / adversarial harness (`py/`)

Dev-only, `uv`-managed black-box CLI suite; never links the Rust crates (`py/README.md:1-5`,
`py/harness/helpers.py:1-2`). `requires-python >= 3.11` (`py/pyproject.toml:5`); sole dep
`pytest>=8` (`:6-10`).

### 10.1 Fixtures + invocation

`conftest.py`: `formwork_bin` (session-scoped, `cargo build -q -p formwork-cli`,
`py/harness/conftest.py:15-20`), `cli` (`:23-28`), `workspace` (`:31-33`). `helpers.py`: `REPO_ROOT`
(`:11-12`), `CliResult` (`:15-19`), `run_cli` (`:22-40`, env overlays `os.environ`), `Workspace` +
`make_workspace` (`:43-73`), `write_blueprint` (`:80-102`).

### 10.2 Platform skipping + traceability

`pytest_collection_modifyitems` (`py/harness/conftest.py:44-60`) adds skip-with-reason for
`@pytest.mark.macos`/`.linux` off-platform. Markers declared at `py/pyproject.toml:15-24` (`fw_e2e`,
`fw_adv`, `macos`, `linux`). `_fw_id` (`conftest.py:36-41`) + `pytest_terminal_summary` (`:63-70`)
generate the traceability section at run end. Standalone `traceability.py` (`:1-33`) shells
`pytest --collect-only`.

### 10.3 Requirement-ID canaries (`test_requirements.py`)

Enforces the repo-wide ID discipline (`py/harness/test_requirements.py:1-5`). Defining docs
`("formwork.md", "fep-1.md")` (`:14`); ID grammar (`:16-19`); `test_every_definition_is_anchored_
exactly_once` (`:62-68`), `test_every_cited_id_resolves_to_a_definition` (`:71-81`),
`test_markdown_requirement_links_land` (`:84-97`).

### 10.4 Test modules by theme

- `test_compile.py` — cross-platform compiler E2E (`FW-E2E-026`/027, detect), `:11-52`.
- `test_fs_confinement.py` — macOS fs confinement (`FW-E2E-001`/002/003), `:19-74`.
- `test_net_egress.py` — macOS egress deny (`FW-E2E-006`, exit code exactly 7), `:28-42`.
- `test_credential_catalog.py` — mostly macOS (`FW-E2E-045`–050, path/env/env-file/exclude/backstop/
  report-labels), `:55-216`.
- `test_adv_credentials.py` — `FW-ADV-012` oracle probe (macOS), `FW-ADV-014` launcher-bypass
  honesty, `:61-116`.
- `test_discovery.py` — macOS (`FW-E2E-051`–054, `FW-ADV-013`/015), `:78-232`.
- `test_blueprint_model.py` — `FW-E2E-041`–044, 055 (rename/precedence/parity/extends/`$CWD` sigil),
  `:29-178`.
- `test_examples_gateway.py` — macOS gateway shading (`FW-E2E-013`/018, `FW-ADV-004`), `:76-113`.
- `test_examples_blueprints.py` — example blueprints compile + `FW-E2E-014` loud-config-error +
  `FW-E2E-024` (macOS), `:13-54`.

---

## 11. Examples, CI, and containers

### 11.1 Examples (`examples/`)

Two composable axes (`examples/README.md:1-9`): **A** confine the agent (`formwork run … --
<agent>`); **B** shade its MCP servers (`formwork gateway …`). Blueprints: `e2e-001.toml` (closed
reads, `[mcp.files]` allows only `read_file`), `blueprints/agent-session.toml` (`net = { ports =
[443] }`, anthropic/claude creds allowed), `blueprints/dev-session.toml.tpl` (self-host template,
rendered by `just dev-confined`), `blueprints/mcp-gateway.toml` (Axis B). Per-host dirs
`claude-code/`, `codex/`, `opencode/` each carry a `sandbox-agent.sh` + MCP config wiring `formwork
gateway` as the MCP server command. `gateway-demo.sh` is a dependency-free Axis-B demo.

### 11.2 CI (`.github/workflows/`)

`ci.yml` — first-party `actions/*` only (`ci.yml:1-4`); `contents: read` (`:13-14`);
`lint` job (`fmt --check` + `clippy --workspace --all-targets --locked -D warnings`, ubuntu-22.04,
`:26-51`); `test` job matrix `[ubuntu-22.04, macos-14]` running `cargo build`/`test --workspace
--locked` (`:53-84`). `release.yml` — builds four native targets (`aarch64/x86_64-apple-darwin`,
`x86_64/aarch64-unknown-linux-gnu`, `:61-72`); version tags → versioned release, main pushes →
rolling `canary` prerelease, `workflow_dispatch` builds without publishing (`:1-38`); optional macOS
Developer-ID signing + notarization via `rcodesign` when secrets exist (`:95-138`); checksums +
create/update release (`:166-217`).

### 11.3 Containers + justfile

`docker/Dockerfile.linux-test` (`rust:1-bookworm` + python/node/git/C toolchains + uv; builds and
installs `formwork`; `CMD` runs `formwork detect && cargo test --workspace`).
`docker/Dockerfile.linux-dev` (`rust:1-bookworm` + clippy). `justfile` recipes: `build`, `test`,
`test-macos`, `test-linux` (Docker with `--security-opt seccomp=unconfined --security-opt
apparmor=unconfined`, `justfile:30-34`), `test-linux-full` (Lima fallback, `:37-38`), `test-e2e`,
`detect`, `compile-default`, `fmt`, `lint`, `bench`, `check` (`:66-69`, fmt+clippy+test),
`dev-confined` (`:77-92`, self-host Claude Code under Formwork).

---

## 12. Cross-component data flows

**Compile-time (pure):** CLI `blueprint_load` parses TOML → `BlueprintLayer` stack → `merge` →
`Blueprint`; `detect()` (or `--host`/`--target`) → `HostProfile`; `ResolvedCatalog::builtin_for_home`
→ catalog. `compile(blueprint, host, catalog)` → `CompiledPolicy { ConfinerPolicy, GatewayPolicy,
FidelityReport }` (`formwork-compile`). The catalog floor is applied *in the compiler* (via
`CompileInput.floor` from `denied_paths`), never in the layer merge, so no layer stack can carry it
away (`crates/formwork-blueprint/src/layer.rs:94-96`, `crates/formwork-compile/src/lib.rs:52-77`).

**Enforce-time (impure, CLI):** `prepare_session` canonicalizes paths against the real filesystem,
adds `env_file_ref_denies` and `protect_policy_inputs`, then `spawn_confined` installs the
`ConfinerPolicy` in the forked child's `pre_exec` (Landlock+seccomp / Seatbelt) after `apply_env`
builds the stripped child environment (`construct_env`). The confiner makes the gateway the only door
(`formwork.md:57`).

**Runtime transport:** `formwork-seam` injects fds at spawn (pre-open + optional control fd for
`SCM_RIGHTS` minting) advertised via `FORMWORK_FD_*`; the agent adopts them (`child::connection`/
`child::mint`) with no `connect()`. `formwork-gateway` runs the two-pump proxy over any
`AsyncRead`/`AsyncWrite` quad; the intended pairing of seam-injected fds as the gateway transport is
described in both crates' docs but is not wired together in code within them (the seam docstring
states no production crate consumes it yet, `crates/formwork-seam/src/lib.rs:10-13`). The
gateway↔confiner coupling *is* present via `confined_command` → `formwork_confine::spawn_confined`
(`crates/formwork-gateway/src/lib.rs:439-448`).

**Discovery loop:** `formwork learn` runs enforced, collects kernel-logged denials post-hoc
(`learn::collect_denials`, macOS unified log), and `reverse_compile`s them into a `<name>.proposal.
toml` plus an auto-accepted `<name>.discovered.toml` (in-zone only); `formwork accept` moves
needs-review entries per-entry after re-checking the credential floor. The floor is re-evaluated at
propose *and* accept (`FW-INV8`), and the discovered layer keeps `[discovery.provenance]` so learned
grants stay distinguishable from authored ones (`FW-DISC6`).

---

## 13. Verification performed (this host, 2026-07-14)

- `formwork detect` → `{ "os": "linux", "landlock-abi": null, "seccomp": true, "seatbelt": false,
  "os-version": "6.18.5" }` — no Landlock ABI on this kernel, so kernel fs enforcement is
  unavailable here; seccomp is present.
- `cargo build --workspace` — all 7 crates compiled.
- `cargo test --workspace` — green: `formwork-blueprint` 54, `formwork-cli` 9 + `profiles` 3,
  `formwork-compile` 26 + `phase1` 4, `formwork-confine` `linux_confine` 11, `formwork-gateway` 4 +
  `gateway` 8, `formwork-seam` 2 + `seam_transport` 4, plus doc-tests. macOS-gated suites compile
  with 0 tests on Linux.
- `cd py && uv run pytest` — 15 passed, 22 skipped (the skips are macOS/Seatbelt-gated tests).
