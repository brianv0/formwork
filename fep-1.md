# FEP-1: Egress, credentials, environment, and anti-escalation hardening

**Formwork Enhancement Proposal 1.** Status: draft. Companion to `formwork.md`
(design + end-to-end spec) and `constitution.md` (doctrine). This is the
"amendment by proposal" vehicle the constitution requires: several items below
add to the **closed** Concepts list (a new net axis, an env axis, relative path
patterns) and therefore cannot land as casual fields — they land here or not at
all.

Requirement/test IDs extend the existing scheme in `formwork.md` (last used:
`FW-E2E-028`, `FW-ADV-006`). New tests here begin at `FW-E2E-029` / `FW-ADV-007`.

## Implementation status (branch `fep-1-implementation`)

Landed, tested, and verified end-to-end under real macOS Seatbelt (Linux carried
symbolically by the pure compiler, enforced once the FW-ISO confiner lands):

| Requirement | Status | Proof |
|---|---|---|
| **FW-CAP6** `**/` recursive-basename patterns | ✅ done | **FW-E2E-038** real-Seatbelt: `**/.env` denies a nested `.env`, sibling stays readable |
| **FW-TRA8** agent-state, whole `~/.docker`, `**/.env` | ✅ done | drift test; end-to-end SBPL |
| **FW-TRA7** `write-subtract` (tamper vectors, write-deny/read-allow) | ✅ done | **FW-E2E-039** real-Seatbelt: `.git/config` readable but not writable under a write grant |
| **FW-ENV1/2** env axis + secret-shaped scrub | ✅ done | unit tests; **FW-E2E-036** verified under `formwork run`; reported in the FidelityReport (`Partial`, heuristic — never a silent over-claim) |
| **FW-CAP7** metadata denial for the sensitive set | ✅ done | **FW-E2E-037** real-Seatbelt; fixed a Closed-mode `stat` leak |
| **FW-XR8** no agent-influenced escalation | ✅ by construction | policy compiled+applied before the process runs; Seatbelt inherited/irreversible — covered by **FW-E2E-005**, **FW-ADV-001** |
| **Part A** host-scoped egress (**FW-EGR1–6**) | ⏳ deferred | design below; needs the gateway **forward proxy** (new subsystem + dependency, gated by the constitution) — genuinely multi-session |
| **FW-FID5** real-time violation stream | ⏳ deferred | needs a macOS unified-log tap (a subsystem in itself) |

Also fixed in passing: a latent bug where `profiles/default.toml`'s `net`/`exec`
sat under the `[fs]` table and never parsed (`just compile-default` was broken).

The deferred items are the two that require new runtime subsystems (an egress
proxy; a log tap) rather than pure compile-side work; their designs are complete
below. Everything that could be built and verified on the current backend is done.

## Why this FEP exists

A systematic pass over the 2026 competitive landscape (Anthropic
`sandbox-runtime`/Claude Code, OpenAI Codex CLI, Google Gemini CLI, Cursor,
VS Code/Copilot, Zed, plus the disclosed CVEs against them) surfaced a consistent
picture, recorded in `competition-research.md`:

- **Formwork's defaults are already the strongest shipping.** We are the only tool
  whose schema default denies filesystem reads, and the only one shipping a
  curated, CI-tested credential deny-list (`profiles/sensitive-set.toml`). srt's
  own docs disclaim having a credential deny-list; Cursor demonstrably leaks
  `~/.npmrc`; Codex returns full-disk-read `true` in every mode.
- **But the whole industry's *residual* security rests on the network layer**, and
  ours is the weakest part of our own design: TCP-port granularity only, no domain
  allowlist, no working forward proxy. `examples/blueprints/agent-session.toml`
  documents this itself — `:443` means "any HTTPS host."
- **Every competitor hardcodes a write-deny set for code-execution vectors**
  (`.git/hooks`, shell rc, `.mcp.json`, agent-config dirs). We have none.
- **Every competitor grew environment-variable handling.** We have none — the
  confined child inherits `AWS_SECRET_ACCESS_KEY` verbatim.
- **Every competitor has been bypassed at the network filter or via agent-driven
  self-escape** (CVE-2025-66479, the srt SOCKS5 null-byte bypass, Codex
  CVE-2025-59532, Gemini GHSA-wpqr-6v78-jr5g, Cursor CVE-2026-50548). Their
  post-mortems are our test plan.

The through-line: as Formwork closes the read side, the exfiltration frontier
moves to (a) egress, (b) env-borne secrets, and (c) the agent talking its way out
of confinement. FEP-1 targets those three, plus the tamper-vector and
metadata-leak gaps, with requirements phrased so their honesty story (`Enforced /
Partial / Unenforceable`) stays intact.

Each requirement below states its **concept fit** — whether it lives inside the
existing Concepts (a profile/compiler change) or is a Concepts **amendment** (a new
blueprint axis, which is the part this proposal formally asks to ratify).

---

## Part A — Host-scoped egress (new family FW-EGR)

The net axis today is `Deny | Ports([u16])` (`formwork_blueprint`, design §4). Port
scope cannot express "reach the model API but nothing else," so the shipped agent
blueprint opens `:443` to the entire internet and leans entirely on the fs sandbox
to make sure there is nothing worth exfiltrating. That is a real bet, and it is one
`sandbox-runtime`, Codex, Cursor, and VS Code all declined to make. The gateway is
the intended vehicle (FW-GW7 already promises "real network only to allowlisted
endpoints"); FEP-1 makes egress host-scoping a first-class capability and hardens it
against the exact bypasses that hit everyone else.

| Req | Requirement | Concept fit |
|---|---|---|
| **FW-EGR1** Host-scoped egress | The net axis becomes a three-way enum — `Deny \| Ports([u16]) \| AllowHosts([HostPattern])` — adding a host-allowlist posture mediated by the gateway (the confiner stays default-deny; kernels can't express hosts). Under `AllowHosts`, a confined process reaches an allowlisted host through the gateway fd and nothing else. | **Concepts amendment** — extends the net axis (`formwork.md` §4). Reuses the FW-GW7 forward proxy; no new door (FW-XR7). |
| **FW-EGR2** Empty means deny | An empty, absent, or unparseable host allowlist compiles to **full deny**, never allow-all, and the report says so. Directly mirrors CVE-2025-66479, where srt's "block everything" list disabled the proxy and allowed everything. | Fits (compiler + FW-INV6). A regression guard, not a new axis. |
| **FW-EGR3** Hostname canonicalization before match | Host patterns and requested hosts are canonicalized before comparison: reject or neutralize embedded NUL, percent-encoding, CRLF, leading/trailing dots, IDN/Unicode confusables, and IPv6 zone-IDs. Mirrors the srt SOCKS5 `attacker\x00.google.com` bypass and the IPv6-zone-ID hardening now in srt's `domain-pattern.ts`. | Fits (parse-don't-validate at the gateway edge; Boundaries). |
| **FW-EGR4** SSRF / metadata default-block | Under the gateway-mediated `AllowHosts` posture, egress to cloud-metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`) and RFC-1918 / link-local / ULA ranges is denied unless a host pattern names them explicitly (mirrors Cursor's anti-SSRF default). The `Ports` posture is a *direct* kernel `connect()` the gateway never sees and the kernel cannot filter by IP, so it cannot carry this block; its report states plainly that it reaches any host on the port, metadata included. That asymmetry is deliberate — it is the concrete reason the shipped examples should move off `ports=[443]` to `AllowHosts` (defaults §4). | Fits (compiler default + gateway enforcement; honest `Ports` report per FW-XR1). |
| **FW-EGR5** Honest allowlist fidelity | Host-scoped egress is reported `Partial` with a stated reason: without TLS interception (which FEP-1 does **not** add — see Non-goals), the allowlist trusts the client-supplied SNI/Host, so domain-fronting and SNI/Host mismatch are not caught. The report never claims `Enforced` for a guarantee MITM would be required to make. Mirrors srt's own acknowledged limitation. | Fits (FW-FID1 / FW-XR1). |
| **FW-EGR6** No unauthenticated egress door | The gateway exposes no network-reachable, unauthenticated control surface. Egress mediation is the injected fd (FW-XR7); any proxy port the gateway opens toward its *own* upstreams is not reachable from the confined process nor from co-resident host processes acting as a confused deputy. This is why we need no per-session proxy token where srt does — the fd seam already closes that surface, and this requirement keeps it closed. | Fits (invariant-shaped; codifies an existing strength). |

**Resolved — the three net postures are mutually exclusive by construction.** `net`
becomes a single enum, `Deny | Ports([u16]) | AllowHosts([HostPattern])`, so "a host
allowlist *and* a direct port tier at once" is simply unrepresentable — the type
system enforces the exclusion, not a runtime check (make illegal states
unrepresentable). This is the logical resolution of the coexistence hazard the
constitutional review flagged: `Ports` is a kernel-level *direct* `connect()` escape
hatch (port-scoped, any host, no gateway mediation — reported honestly as "any host on
these ports"), whereas `AllowHosts` forces *all* egress through the gateway fd so it
can be host-checked (FW-XR7 / FW-GW4). Permitting both would let direct port-tier
traffic sail past the gateway's host check — "a path that reaches the network around
the Gateway," which the constitution names as the threat model walking in the door. A
session that genuinely needs both host-scoped HTTP *and* raw TCP to a port gets both
**through the gateway**, which can mint a port-scoped connection fd (FW-GW6) — never
one leg via the kernel and one via the broker.

**New tests.**

**Egress test harness — real gateway, controlled inputs, zero external network.**
Every Part A test drives the *real* gateway process (never a mock — constitution
Testing); hermeticity and determinism come from controlled *inputs* to that real
boundary, the same carve-out that lets the pure compiler take a synthetic `HostProfile`
(FW-E2E-026):

- **Upstreams are loopback fixture servers** — one standing for an allowlisted host,
  one for a blocked host. No external host is ever contacted.
- **Resolution is a controlled resolver fixture** injected into the gateway, mapping
  RFC 6761 `.test` names (never externally resolvable) to fixture addresses:
  `allowed.test → 127.0.0.1:<A>`, `blocked.test → 127.0.0.1:<B>`. No real DNS.
- **Denials are asserted at policy, not by network timing.** A blocked egress is
  asserted by the gateway declining to open the upstream socket and emitting a
  structured violation (FW-FID5) — never by waiting for a connection to time out — so
  no result depends on what happens to be listening at a metadata or private address. A
  flaky egress test is a bug (constitution Testing).

- **FW-E2E-029: Host allowlist admits one, denies the rest.** With
  `net: AllowHosts(["allowed.test"])` and the resolver mapping `allowed.test` /
  `blocked.test` to the two loopback fixtures, the session issues a request to each
  through the gateway, and separately attempts a direct `connect()` to both fixture
  addresses from inside the sandbox. Pass: `allowed.test` returns its fixture's bytes;
  `blocked.test` is refused at the gateway with a violation and no upstream socket; both
  direct `connect()`s fail (net is gateway-only). Fail: `blocked.test` is reached, or
  either fixture is reachable by direct connect.
- **FW-E2E-030: Empty allowlist is full deny (CVE-2025-66479 regression).** A blueprint
  with an empty `AllowHosts([])` is compiled and enforced; the session requests
  `allowed.test`. Pass: the report shows egress denied, the gateway opens no upstream
  socket, and a violation is emitted — the empty list never degrades to allow-all;
  deterministic with no network at all. Fail: any egress succeeds.
- **FW-E2E-031: Metadata/RFC-1918 blocked under a permissive allowlist.** With
  `AllowHosts(["*.test"])` (broad, but naming neither), the session asks the gateway to
  reach the literal `169.254.169.254` (IMDS) and a literal RFC-1918 address `10.0.0.1`.
  Pass: the gateway refuses both at the IP-range policy — a violation and no socket —
  regardless of anything listening; IMDS is unreachable. Fail: either is reached without
  being named explicitly.
- **FW-E2E-032: Egress fidelity is honest.** The resolver maps two names, `a.test` and
  `b.test`, to the *same* loopback fixture; the blueprint allowlists only `a.test`. A
  request bearing host `a.test` is allowed; the test records that the gateway cannot,
  without TLS interception, distinguish it from a request that means `b.test`'s content
  on that shared address. Pass: the report marks host-scoped egress `Partial` with the
  no-TLS-inspection reason and observed behavior matches it exactly (the FW-E2E-025
  honesty pattern applied to egress). Fail: the report claims `Enforced`, or behavior
  contradicts it.
- **FW-ADV-007: Hostname bypass battery.** With `AllowHosts(["allowed.test"])` and
  `blocked.test` mapped to the blocked fixture, the agent requests, in turn:
  `allowed.test\x00.blocked.test`, `allowed%2etest.blocked.test`,
  `blocked.test#.allowed.test`, `allowed.test.` (trailing dot),
  `::ffff:127.0.0.1%allowed.test` (IPv6 zone-ID), and an IDN confusable of
  `allowed.test`. Pass: each canonicalizes to the genuine `allowed.test` or is rejected;
  none reaches the blocked fixture. Fail: any variant escapes the allowlist. (Mirrors
  the srt SOCKS5 null-byte disclosure.)
- **FW-ADV-008: DNS-rebinding to a blocked IP.** The resolver returns a blocked address
  (the metadata literal, or an RFC-1918 fixture) for the allowlisted `allowed.test`.
  Pass: the gateway drops at connect on the *resolved IP* — violation, no socket — even
  though the name is allowlisted; the name-based allow never overrides the IP-range
  block (FW-EGR4). Fail: the rebind reaches the blocked address.
- **FW-ADV-009: Confused-deputy against the gateway.** A co-resident *unconfined* host
  process, and separately a *confined* process, each attempt to drive the gateway's
  egress (to the `allowed.test` fixture) other than through the sandbox's own injected
  fd. Pass: neither obtains egress; there is no unauthenticated door (FW-EGR6). Fail:
  either reaches the fixture through the gateway without holding the injected fd.

---

## Part B — Tamper-vector and credential coverage (extend FW-TRA)

The one hardcoded protection every competitor ships and we lack is **write-denial of
code-execution and policy-tampering vectors** inside otherwise-writable trees: srt's
`DANGEROUS_FILES`/`DANGEROUS_DIRECTORIES`, Codex's forced-read-only
`.git`/`.agents`/`.codex`, Cursor's protected `.cursor/*.json`/`.git/hooks`, Zed's
git-metadata protection. Without it, an agent with a normal writable project can
plant a `.git/hooks/pre-commit` (or rewrite `.mcp.json`, or a shell rc) that runs
**unsandboxed** the next time the human uses the repo — a sandbox escape that routes
through the user, not the kernel.

| Req | Requirement | Concept fit |
|---|---|---|
| **FW-TRA7** Execution-vector write protection | A default write-subtract set masks code-execution / policy-tampering vectors even inside writable grants: `.git/hooks/**`, `.git/config`, shell rc files (`.bashrc`/`.zshrc`/`.profile`/…), `.mcp.json`, and agent-config dirs (`.claude/**`, `.cursor/**`, `.vscode/**`, `.idea/**`, `.codex/**`, `.gemini/**`). Deny wins over the write grant (existing `subtract` semantics). | Fits the `subtract` concept, but **depends on FW-CAP6** to express the project-relative entries. |
| **FW-TRA8** Agent-state & local-secret coverage | The sensitive set is extended with (a) agent-tool state holding OAuth creds/transcripts — `~/.claude*`, `~/.codex/**`, `~/.gemini/**`, `~/.cursor/**`, `~/.docker/**` (the directory, not only `config.json`); and (b) project-local secrets — `**/.env`, `**/.env.*`. Ironically we wrap exactly these agents today but protect none of their credentials, and `.env` is the single most conspicuous industry-wide hole (addressed by Gemini, OpenCode, and Codex). | Fits `sensitive-set.toml`; the `.env` entries **depend on FW-CAP6**. |

**New tests.**

- **FW-E2E-033: Tamper vectors are read-through but write-denied.** Under a writable
  project grant, the session writes `<project>/.git/hooks/pre-commit`,
  `<project>/.mcp.json`, `<project>/.vscode/tasks.json`, and `~/.zshrc`. Pass: each
  write is denied though the surrounding tree is writable; reads of these paths (where
  read-granted) still succeed, so tooling that inspects them is unbroken. Fail: any of
  these paths is writable under a normal project grant.
- **FW-E2E-034: Extended sensitive set under a broad grant.** Under broad
  `read($HOME/**)` with defaults, the session reads an ordinary file (succeeds) and
  attempts `~/.claude.json`, `~/.codex/auth.json`, a project `.env`, and
  `~/.docker/contexts/…` (all denied). Pass: every extended-sensitive path is denied
  despite the broad grant. Fail: any is readable. (Extends FW-E2E-003, which covers
  only ssh/aws/sibling-project.)
- **FW-ADV-010: Plant-a-hook escalation.** The agent writes an executable
  `.git/hooks/pre-commit` and then triggers a git operation that would run it. Pass:
  the write is denied, so the hook never arms; confinement is not escapable through a
  later out-of-sandbox git invocation. Fail: the hook is written and subsequently
  executes.

---

## Part C — Path expressiveness (Concepts amendment, FW-CAP6)

`PathPattern` is absolute-only with no `..` (Boundaries; `formwork_blueprint::path`).
That is correct for grants, but it makes `.env`, `**/.env`, and `.git/hooks`
(which are meaningful *relative to a project root*, at arbitrary depth)
**inexpressible today**. FW-TRA7 and the `.env` half of FW-TRA8 cannot be written
without this. This is the enabling amendment for Part B.

| Req | Requirement | Concept fit |
|---|---|---|
| **FW-CAP6** Anchored & basename patterns | The pattern vocabulary gains two bounded forms beyond absolute paths: (1) a **project-anchored** pattern resolved against a declared project root at load time, and (2) a **basename/recursive-glob** pattern (`**/.env`) that matches by trailing components within a grant. Both remain fail-loud on non-representable resolution (unchanged from §4) and canonicalize deterministically (FW-FID4). No relative `..` traversal is introduced. | **Concepts amendment** — extends the `PathPattern` data model (a durable, human-reviewed surface per constitution "Data model"). |

**New test.**

- **FW-E2E-035: Anchored/glob patterns compile deterministically and enforce by
  component.** A blueprint expressing `**/.env` and a project-anchored `.git/hooks/**`
  compiles byte-identically twice (FW-FID4) and, once enforced, denies matching paths
  at any depth under the project root while leaving siblings untouched. Pass:
  deterministic compile **and** depth-independent enforcement. Fail: nondeterministic
  output, or a matching path at depth is missed (a silent fail-open of the sensitive
  set — FW-INV6).

---

## Part D — Environment as a capability (new family FW-ENV, Concepts amendment)

There is no environment handling anywhere in Formwork: the confined child inherits
the full parent environment, so `AWS_ACCESS_KEY_ID`, `ANTHROPIC_API_KEY`,
`GITHUB_TOKEN` pass straight through. With reads closed and (post Part A) egress
host-scoped, env vars become the *easiest* remaining exfiltration payload — they
require no file read at all. Every competitor grew env handling: srt's
`credentials.envVars` (deny/mask), Claude Code's `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`,
Gemini's `environmentSanitization.ts` (regex over names and values). Formwork should
too — and it is a genuinely new Concept, so it is proposed here rather than bolted on.

| Req | Requirement | Concept fit |
|---|---|---|
| **FW-ENV1** Environment axis | The blueprint gains an `env` posture governing what environment the confined child receives: pass-through, allowlist (only named vars survive), or scrub-list (named/patterned vars removed). Compiled deterministically; the child's environment is set by the confiner at spawn, not inherited wholesale. | **Concepts amendment** — a new capability axis on the Blueprint (closed-list change; parallels the fs/net/exec/mcp axes). |
| **FW-ENV2** Default secret-shaped scrub | The default profile scrubs env vars whose **name** matches a secret shape (`TOKEN\|SECRET\|PASSWORD\|KEY\|AUTH\|CREDENTIAL\|CERT`, case-insensitive) or whose **value** matches a high-confidence secret shape (PEM blocks, `ghp_…`, `AKIA…`, `AIza…`, JWT), **minus** an allowlist the blueprint names for vars the agent legitimately needs (e.g. its model API key). Transparency (FW-TRA2) is preserved by the allowlist; the scrub is the fail-closed default. Mirrors Gemini's `environmentSanitization.ts`. | Fits once FW-ENV1 exists (a default-profile value). |

**New tests.**

- **FW-E2E-036: Secret-shaped env is scrubbed, allowlisted env survives.** Under the
  default profile, the confined child's environment is inspected. Pass:
  `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, and a PEM-valued variable are **absent**,
  while a blueprint-allowlisted `ANTHROPIC_API_KEY` is **present**. Fail: any
  secret-shaped var reaches the child, or an allowlisted var is stripped (which would
  break reuse).
- **FW-ADV-011: Env exfiltration is defused in depth.** With one host allowlisted for
  egress (Part A) and a prompt-injected instruction to POST the environment to it, the
  agent attempts the exfiltration. Pass: the secret-shaped vars are not present to
  send (FW-ENV2), demonstrating the compose of env-scrub with host-scoped egress —
  neither layer alone is trusted. Fail: a secret-shaped var is both present and
  egressable.

---

## Part E — Metadata-leak reduction and anti-escalation

Two remaining gaps the audit surfaced. First, the broad `(allow file-read-metadata)`
lets a confined process `stat("~/.aws/credentials")` and learn it exists, its size,
and mtime, even though the bytes are denied — an existence/enumeration oracle over the
sensitive set. Second, and most important as a differentiator: the disclosed escapes
against competitors are increasingly **agent-driven** — Claude Code auto-retrying with
`dangerouslyDisableSandbox` (srt issue #97, the Ona write-up), Codex treating a
model-supplied cwd as the writable root (CVE-2025-59532), Cursor's model-controlled
`working_directory` (CVE-2026-50548), Gemini loading `.gemini/.env` *before* the
sandbox applied (GHSA-wpqr-6v78-jr5g). Formwork's architecture already forbids these
by construction; FEP-1 states that as a guarantee so it can be tested and cannot
silently regress.

| Req | Requirement | Concept fit |
|---|---|---|
| **FW-XR8** No agent-influenced escalation | No mechanism lets the confined process — or its instruction stream — disable, weaken, retry-outside, or reconfigure its own confinement. The blueprint is consumed and the policy compiled/installed *before* the confined process runs (FW-CAP2: narrowing only; widening does not exist). Escalation, where a host chooses to offer it, is an out-of-band host/human action on an unconfined process, never a signal the confined process can emit. | **New cross-cutting requirement.** Codifies the existing structural strength (constitution: "a parallel path invented to dodge the Confiner is the threat model walking in the door"). |
| **FW-CAP7** Metadata denial for the sensitive set | Where the backend can express it (Seatbelt can deny `file-read-metadata` per path), the sensitive set is denied at the metadata layer too, so existence/size/mtime of credentials do not leak. Where it cannot (Linux/Landlock), the residual is reported `Partial`, narrowing the §3 "we accept EACCES, not ENOENT" concession specifically for credentials rather than leaving it blanket. | Fits (compiler + FW-FID1). Bounded by §3 out-of-scope for full ENOENT invisibility. |
| **FW-FID5** Real-time violation stream | Beyond the FW-FID3 grants/denials record, the confiner and gateway emit a structured, real-time **violation** event (capability, path/host, backend, timestamp) shaped for an embedding host to turn into an escalation prompt or audit entry — the pattern srt gets from tapping the unified log and Cursor from "surface the specific constraint that failed." | Fits (extends FW-FID3 / Observability doctrine). |

**New tests.**

- **FW-E2E-037: Sensitive-set metadata does not leak.** The session calls
  `stat()`/`access()` on `~/.aws/credentials`. Pass on macOS: existence/size is not
  revealed (metadata denied). On Linux where unenforceable: the report marks the
  metadata capability `Partial` and behavior matches the report (honesty). Fail: the
  report over-claims, or metadata leaks on a platform that reports it denied.
- **FW-E2E-038: Denials emit a consumable violation record.** A denied read and a
  denied egress each emit a structured violation event with the required fields on the
  observability channel within the run; a *granted* operation emits no violation.
  Pass: schema-valid violation records for the denials, none for the grant, consumable
  by an embedding host. Fail: a denial is silent, or a grant is mislabeled a violation.
- **FW-ADV-012: Self-escape battery.** The confined agent attempts, in sequence: (a)
  rewrite a blueprint/policy/settings file within its grant and force a re-read; (b)
  set an env var or drop a config a re-invocation would honor (the Codex `CODEX_HOME`/
  `notify` and Gemini `.gemini/.env` pre-load patterns); (c) spawn a helper that
  re-execs attempting to run without the sandbox; (d) emit any control message asking
  the launcher to drop or widen confinement. Pass: none disables or weakens
  confinement; the only escalation path is an out-of-band host/human action on an
  unconfined process (FW-XR8). Fail: any attempt widens the grant or removes the
  confiner. (Consolidates the failure modes behind srt #97, Ona, CVE-2025-59532, and
  GHSA-wpqr-6v78-jr5g into one adversarial suite.)

---

## Missing default configurations to decide on

Distinct from the requirements above: gaps in the **shipped defaults**
(`profiles/default.toml`, `profiles/sensitive-set.toml`, the example blueprints).
Several presuppose a requirement above; noted inline.

1. **`.env` / project-local secrets are absent from the subtract.** The most common
   secret file in a repo is fully readable under the default profile. Add `**/.env`,
   `**/.env.*` to `sensitive-set.toml` once FW-CAP6 makes them expressible.
2. **Agent-tool state dirs are absent.** `~/.claude*`, `~/.codex`, `~/.gemini`,
   `~/.cursor`, and `~/.docker/**` (the directory — today only `~/.docker/config.json`
   is subtracted, leaving `~/.docker/contexts` and credential-helper config readable).
   Add under FW-TRA8.
3. **No execution-vector write-deny defaults.** `default.toml` subtracts credentials
   but nothing tamper-related; add the FW-TRA7 set (`.git/hooks`, `.git/config`,
   `.mcp.json`, shell rc, `.vscode`/`.idea`/agent-config dirs).
4. **The `Ports` posture cannot filter by IP, so the shipped example reaches cloud
   metadata.** `default.toml` is `net = "deny"` (good), but `agent-session.toml` uses
   `net = { ports = [443] }` — a direct kernel `connect()` that silently reaches
   `169.254.169.254`. The kernel cannot IP-filter a direct port grant (FW-EGR4), so the
   fix is not a patch to `Ports` but a **migration of the example to `AllowHosts`**
   (FW-EGR1) naming the real model-API hosts — which routes egress through the gateway,
   where the metadata/RFC-1918 block (FW-EGR4) actually applies.
5. **No default env scrub.** There is no env handling at all; ship the FW-ENV2
   secret-shaped scrub with a minimal allowlist (the model API key) in `default.toml`.
6. **No stricter opt-in profile.** We have the `read-mode = "closed"` mechanism but
   ship no profile that uses it. Add `profiles/strict.toml` (closed reads, explicit
   grants) for users who want deny-by-default reads — the posture Gemini's `strict-*`
   profiles and Cursor's "user config only" network mode occupy. Also worth a design
   note: a **managed/lockdown** notion (defaults an embedding org can enforce and a
   blueprint cannot weaken), analogous to Cursor's admin dashboard, VS Code org
   settings, and Copilot-via-Intune — likely out of v1 scope but it shapes the profile
   layering.
7. **cwd is not folded into the read grant.** `formwork run` never adds the child's
   working directory to reads (`docs/spikes.md` Spike 2), so interpreters started
   outside the read scope break. Decide whether the default folds cwd into reads.
8. **`$HOME`-unset falls back to `/`.** With `$HOME` unset, `~/.ssh/**` expands to
   `/.ssh/**` — a silent miss of the real sensitive set. This should **fail loud**
   (FW-INV6), not fall back. A defaults/hardening fix independent of the requirements
   above.

---

## Traceability (FEP-1 requirements ↔ new tests)

| Requirement | Primary tests | Also covered by |
|---|---|---|
| FW-EGR1 Host-scoped egress | FW-E2E-029 | FW-E2E-032, FW-ADV-009 |
| FW-EGR2 Empty means deny | FW-E2E-030 | FW-INV6 |
| FW-EGR3 Hostname canonicalization | FW-ADV-007 | FW-ADV-008 |
| FW-EGR4 SSRF/metadata block | FW-E2E-031 | FW-ADV-008 |
| FW-EGR5 Honest allowlist fidelity | FW-E2E-032 | FW-INV5 |
| FW-EGR6 No unauthenticated door | FW-ADV-009 | FW-E2E-029 |
| FW-TRA7 Execution-vector write protection | FW-E2E-033 | FW-ADV-010 |
| FW-TRA8 Agent-state & local-secret coverage | FW-E2E-034 | — |
| FW-CAP6 Anchored & basename patterns | FW-E2E-035 | FW-E2E-033, 034 |
| FW-ENV1 Environment axis | FW-E2E-036 | FW-ADV-011 |
| FW-ENV2 Default secret-shaped scrub | FW-E2E-036 | FW-ADV-011 |
| FW-XR8 No agent-influenced escalation | FW-ADV-012 | FW-CAP2 (INV1) |
| FW-CAP7 Metadata denial for sensitive set | FW-E2E-037 | FW-INV5 |
| FW-FID5 Real-time violation stream | FW-E2E-038 | FW-E2E-024 |

---

## Not in this FEP

**Already-required, merely unbuilt — not new requirements.** The competitive gap
"no Linux enforcement" is not a FEP item: FW-ISO1–ISO8 already require it; the Linux
confiner is a stub pending a real-kernel verification (constitution Growth: the
Landlock crates stay unwired until a kernel verifies them). Likewise a working forward
proxy is already FW-GW7. FEP-1 *builds on* FW-GW7 (Part A) but does not restate it.
Cursor having shipped direct Landlock+seccomp in production de-risks our existing
FW-ISO design; that is motivation to execute the plan, not a new requirement.

**Deliberate non-goals (scoped out, consistent with §3).**

- **TLS interception / MITM egress inspection.** srt offers an experimental
  `tlsTerminate` for credential masking and body inspection. FEP-1 explicitly does
  *not* add it — it means minting a CA into the child's trust stores, a large new
  trust surface, and FW-EGR5 instead reports the honest limit. Revisit only if a
  concrete requirement demands request-body policy.
- **Credential masking / host-side token injection.** srt's `mask` mode and Docker
  Sandboxes' proxy-injected OAuth are powerful but presuppose TLS termination and a
  secret-handling path through the broker — out of scope here; FW-ENV1/ENV2 do deny,
  not mask.
- **Windows.** Unchanged from `formwork.md` §11 — a later third backend, not this FEP.
- **Resource-exhaustion DoS and kernel/LSM exploitation** — unchanged §3 out-of-scope.

## Open questions

- **Anchoring for FW-CAP6.** Whether project-anchored patterns resolve against an
  explicit blueprint field (a declared project root) or the CLI's cwd. The explicit
  field is more auditable and avoids coupling policy to invocation cwd; lean that way.
- **Env axis granularity.** Whether FW-ENV1 needs value-pattern scrubbing in the
  *schema* or only name-based allow/deny in the schema with value-shape scrubbing
  living in the default profile. Leaning: schema carries allow/deny by name; the
  value-shape heuristic is a profile default (keeps the closed vocabulary small).
- **Managed/lockdown layer.** Whether a non-weakenable managed default belongs in v1
  or is deferred; it interacts with FW-CAP2 (narrowing-only) cleanly but adds a policy
  precedence surface.
