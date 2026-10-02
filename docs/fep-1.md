# FEP-1 (remainder): real-time violation streaming

**Formwork Enhancement Proposal 1 — deferred remainder.** Companion to `formwork.md`
(design + end-to-end spec) and `constitution.md` (doctrine).

FEP-1 has landed except for one subsystem. Its capability-model half was folded into
`formwork.md` first: the environment axis ([FW-ENV1](../formwork.md#fw-env1)/2), execution-vector
write-subtract ([FW-TRA7](../formwork.md#fw-tra7)), agent-state & local-secret coverage
([FW-TRA8](../formwork.md#fw-tra8)), any-depth `**/` patterns ([FW-CAP6](../formwork.md#fw-cap6)),
sensitive-set metadata denial ([FW-CAP7](../formwork.md#fw-cap7)), and the anti-escalation guarantee
([FW-XR8](../formwork.md#fw-xr8)), with the fs additions verified on real Seatbelt and Landlock
([FW-E2E-037](../formwork.md#fw-e2e-037)..039) and the environment axis by unit tests
([FW-E2E-036](../formwork.md#fw-e2e-036) as a black-box run is owed).

Its host-scoped egress half (Part A) landed through FEP-5 (`docs/fep-5.md`), which gave it a
transport — host rules in `rules`, carried by the session Gateway and, on Linux, the connect
supervisor — and FEP-6 (`docs/fep-6.md`), which built the engine that serves them. Part A's
requirements and tests are folded into `formwork.md`: [FW-EGR1](../formwork.md#fw-egr1)–6 in §5.11,
[FW-E2E-029](../formwork.md#fw-e2e-029)..032 in §7.2, and [FW-ADV-007](../formwork.md#fw-adv-007)..009
and [FW-ADV-011](../formwork.md#fw-adv-011) in §7.10. Folding amended three requirements to what
landed — FW-EGR1 (the posture is written as host rules), FW-EGR5 (the uninspected case is the
`tunnel:` grade) and FW-EGR6 (the egress listener) — and restated FW-E2E-032 for the tunnel grade.
The proposal text as adopted, with the egress test harness and the bypass record it drew on
(CVE-2025-66479, the srt SOCKS5 null-byte bypass, Codex CVE-2025-59532, Gemini
GHSA-wpqr-6v78-jr5g, Cursor CVE-2026-50548), is in git history (`git log -- docs/fep-1.md`).

What remains here is the **real-time violation stream** ([FW-FID5](#fw-fid5)), which needs a
structured violation event path an embedding host can consume. Egress refusals already emit
violation records with a closed reason set ([FW-FID12](../formwork.md#fw-fid12)) and one
self-explaining operator line each ([FW-FID9](../formwork.md#fw-fid9)); filesystem and channel
denials reach the operator only through `learn` and the platform logs. The test is
[FW-E2E-040](#fw-e2e-040).

---

<a id="fw-fid5"></a>
## [FW-FID5](#fw-fid5) — Real-time violation stream

Beyond the [FW-FID3](../formwork.md#fw-fid3) grants/denials record, the confiner and gateway emit a structured,
real-time **violation** event (capability, path/host, backend, timestamp) shaped for an
embedding host to turn into an escalation prompt or audit entry — the pattern srt gets
from tapping the unified log and Cursor from "surface the specific constraint that
failed." Fits the Observability doctrine (extends [FW-FID3](../formwork.md#fw-fid3)), but needs a runtime event
path (a macOS unified-log tap is one option), which is why it is deferred rather than
compile-side.

**New test.**

- <a id="fw-e2e-040"></a>**FW-E2E-040: Denials emit a consumable violation record.** A denied read and a denied
  egress each emit a structured violation event with the required fields on the
  observability channel within the run; a *granted* operation emits no violation. Pass:
  schema-valid violation records for the denials, none for the grant, consumable by an
  embedding host. Fail: a denial is silent, or a grant is mislabeled a violation.

---

## Still-open default configurations

The FEP's default-config gaps that are still open. The ones that shipped —
`.env`/agent-state/`~/.docker` subtracts, tamper write-subtract, the env scrub — are in
`profiles/default.toml`, and the shipped agent examples moved off `net = { ports = [443] }` to host
rules with FEP-5, so egress goes through the Gateway, where the metadata block applies
([FW-EGR4](../formwork.md#fw-egr4)).

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
  ([FW-INV6](../formwork.md#fw-inv6)), not fall back.

---

## Not in this FEP

**Deliberate non-goals (scoped out, consistent with `formwork.md` §3).** (TLS interception and
credential brokering, once listed here, landed with FEP-5 and FEP-6.)

- **Windows.** Unchanged from `formwork.md` §11 — a later third backend, not this FEP.
- **Resource-exhaustion DoS and kernel/LSM exploitation** — unchanged §3 out-of-scope.

## Open questions

- **Managed/lockdown layer.** Whether a non-weakenable managed default belongs in v1 or
  is deferred; it interacts with [FW-CAP2](../formwork.md#fw-cap2) (narrowing-only) cleanly but adds a policy
  precedence surface.
