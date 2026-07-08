# FEP-1 (remainder): host-scoped egress and real-time violation streaming

**Formwork Enhancement Proposal 1 — deferred remainder.** Companion to `formwork.md`
(design + end-to-end spec) and `constitution.md` (doctrine).

The capability-model half of FEP-1 has **landed and been folded into `formwork.md`**:
the environment axis (FW-ENV1/2), execution-vector write-subtract (FW-TRA7), agent-state
& local-secret coverage (FW-TRA8), any-depth `**/` patterns (FW-CAP6), sensitive-set
metadata denial (FW-CAP7), and the anti-escalation guarantee (FW-XR8) — verified on real
Seatbelt and Landlock (FW-E2E-036..039; see `formwork.md` §4, §5, §7, §10). The shipped
defaults gained the matching entries (`.env`/agent-state/`~/.docker` subtracts, the
tamper-vector write-subtract set, and the default secret-shaped env scrub).

What remains here are the **two deferred subsystems** — the FEP items that need new
*runtime* machinery rather than pure compile-side work, and so are genuinely
multi-session:

- **Part A — host-scoped egress (FW-EGR1–6):** needs the gateway **forward proxy** (a new
  subsystem + dependency, gated by the constitution's Growth doctrine).
- **FW-FID5 — real-time violation stream:** needs a structured violation event path (on
  macOS, a unified-log tap is one option).

New requirement/test IDs continue the `formwork.md` scheme: egress uses FW-E2E-029..032 /
FW-ADV-007..009, 011; the violation-stream test is FW-E2E-040.

## Why these remain the frontier

As Formwork closes the read side (the credential deny-list, `.env`, tamper vectors, and
env scrub are now shipping), the exfiltration frontier moves to the network layer — and
that is the weakest part of our own design: TCP-port granularity only, no domain
allowlist, no working forward proxy. `examples/blueprints/agent-session.toml` documents
this itself — `:443` means "any HTTPS host." Every competitor's *residual* security rests
on the network layer, and every one has been bypassed there or via agent-driven
self-escape (CVE-2025-66479, the srt SOCKS5 null-byte bypass, Codex CVE-2025-59532, Gemini
GHSA-wpqr-6v78-jr5g, Cursor CVE-2026-50548); their post-mortems are the test plan below.
The violation stream is the other half: what lets an embedding host turn a denial into an
escalation prompt or audit entry instead of a silent failure. See `competition-research.md`.

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
- **FW-ADV-011: Env exfiltration is defused in depth.** With one host allowlisted for
  egress and a prompt-injected instruction to POST the environment to it, the agent
  attempts the exfiltration. Pass: the secret-shaped vars are not present to send (the
  now-shipped FW-ENV2 scrub), demonstrating the compose of env-scrub with host-scoped
  egress — neither layer alone is trusted. Fail: a secret-shaped var is both present and
  egressable. (The env half ships today; this test lands with Part A.)

---

## FW-FID5 — Real-time violation stream

Beyond the FW-FID3 grants/denials record, the confiner and gateway emit a structured,
real-time **violation** event (capability, path/host, backend, timestamp) shaped for an
embedding host to turn into an escalation prompt or audit entry — the pattern srt gets
from tapping the unified log and Cursor from "surface the specific constraint that
failed." Fits the Observability doctrine (extends FW-FID3), but needs a runtime event
path (a macOS unified-log tap is one option), which is why it is deferred rather than
compile-side.

**New test.**

- **FW-E2E-040: Denials emit a consumable violation record.** A denied read and a denied
  egress each emit a structured violation event with the required fields on the
  observability channel within the run; a *granted* operation emits no violation. Pass:
  schema-valid violation records for the denials, none for the grant, consumable by an
  embedding host. Fail: a denial is silent, or a grant is mislabeled a violation.

---

## Still-open default configurations

The FEP's default-config gaps that presuppose the deferred work above (the ones that
shipped — `.env`/agent-state/`~/.docker` subtracts, tamper write-subtract, the env
scrub — are now in `profiles/default.toml`):

- **The `Ports` posture cannot filter by IP, so the shipped example reaches cloud
  metadata.** `default.toml` is `net = "deny"` (good), but `agent-session.toml` uses
  `net = { ports = [443] }` — a direct kernel `connect()` that silently reaches
  `169.254.169.254`. The kernel cannot IP-filter a direct port grant (FW-EGR4), so the
  fix is a **migration of the example to `AllowHosts`** (FW-EGR1) naming the real
  model-API hosts — which routes egress through the gateway, where the metadata/RFC-1918
  block actually applies.
- **No stricter opt-in profile.** We have the `read-mode = "closed"` mechanism but ship
  no profile that uses it. Add `profiles/strict.toml` (closed reads, explicit grants).
  Also worth a design note: a **managed/lockdown** notion (defaults an embedding org can
  enforce and a blueprint cannot weaken) — likely out of v1 scope but it shapes the
  profile layering.
- **cwd is not folded into the read grant.** `formwork run` never adds the child's
  working directory to reads (`docs/spikes.md` Spike 2), so interpreters started outside
  the read scope break. Decide whether the default folds cwd into reads.
- **`$HOME`-unset falls back to `/`.** With `$HOME` unset, `~/.ssh/**` expands to
  `/.ssh/**` — a silent miss of the real sensitive set. This should **fail loud**
  (FW-INV6), not fall back.

---

## Not in this FEP

**Deliberate non-goals (scoped out, consistent with `formwork.md` §3).**

- **TLS interception / MITM egress inspection.** srt offers an experimental
  `tlsTerminate` for credential masking and body inspection. FEP-1 explicitly does
  *not* add it — it means minting a CA into the child's trust stores, a large new
  trust surface, and FW-EGR5 instead reports the honest limit. Revisit only if a
  concrete requirement demands request-body policy.
- **Credential masking / host-side token injection.** srt's `mask` mode and Docker
  Sandboxes' proxy-injected OAuth presuppose TLS termination and a secret-handling path
  through the broker — out of scope here; the shipped FW-ENV1/ENV2 deny, not mask.
- **Windows.** Unchanged from `formwork.md` §11 — a later third backend, not this FEP.
- **Resource-exhaustion DoS and kernel/LSM exploitation** — unchanged §3 out-of-scope.

## Open questions

- **Managed/lockdown layer.** Whether a non-weakenable managed default belongs in v1 or
  is deferred; it interacts with FW-CAP2 (narrowing-only) cleanly but adds a policy
  precedence surface.
- **Egress host-pattern grammar.** Exact wildcard/suffix semantics for `HostPattern`
  (e.g. `*.example.com` vs `example.com`), fixed at the parse edge (FW-EGR3), before any
  match.
