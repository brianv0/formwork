# FEP-12 (proposal): egress disclosure records — markers, an account of what left, and the bytes nobody scanned

**Formwork Enhancement Proposal 12 — proposal, not landed.** Companion to `formwork.md`
(design + end-to-end spec), `constitution.md` (doctrine), `docs/fep-5.md` (inspection and
brokering) and `docs/fep-6.md` (the egress engine).

**Status.** Nothing in this document mutates the landed spec or the constitution. The §7
amendments are apply-on-landing blocks. New identifiers are draft numbering, written as inline code
so the requirements canary skips them, until they are anchored on landing. This FEP holds the
reserved blocks `FW-EGR31`..`FW-EGR35`, `FW-FID27`..`FW-FID30`, `FW-BP26`, `FW-INV22`,
`FW-E2E-169`..`FW-E2E-177` and `FW-ADV-046`..`FW-ADV-047`. They start above the blocks the open
drafts hold (FEP-7 to `FW-E2E-116`, FEP-8 to `FW-E2E-132`, FEP-9 to `FW-E2E-144` and `FW-FID24`,
FEP-10 to `FW-E2E-156` and `FW-EGR30`, FEP-11 to `FW-E2E-168`, `FW-FID26` and `FW-INV21`) and
above the highest landed numbers. No code has landed.

---

## 1. Problem

A host rule decides where a session may send. Nothing reports what it sent there.

- **The grant record excludes the content by requirement.**
  [FW-FID13](../formwork.md#fw-fid13) gives each admitted request a record of host, grade, method,
  canonical path, status, byte counts and duration, "and no header value, body byte or query
  string". The exclusion is correct: those fields hold secrets, and a record that copied them would
  be a second place to leak them. Its consequence is that a value the operator never meant to leave
  can sit in a header of every request to a granted host and no record shows it.
- **The grant record reaches nobody.** `Shared::grant` emits it at `debug`
  (`crates/formwork-gateway/src/egress.rs:454`) and keeps the last 1,024 in memory
  (`MAX_KEPT_RECORDS`, `egress.rs:48`). `EgressProxy::grants` has no caller outside
  `crates/formwork-gateway/tests/`. A `run` at the default log level ends with no account of which
  hosts were contacted or how many bytes went to each.
- **The only outbound content check covers one kind of value.** `scan_placeholders`
  (`crates/formwork-gateway/src/inspect.rs:1054`) searches the request target and header values
  for the per-session placeholder prefix ([FW-CRED14](../formwork.md#fw-cred14)). The reflection
  guard ([FW-CRED17](../formwork.md#fw-cred17), `crates/formwork-gateway/src/http.rs:343`) searches
  responses. Request bodies are forwarded unsearched.
- **The Launcher discards what it could search for.** `construct_env` partitions the launching
  environment and keeps the names and types of the variables it strips
  (`crates/formwork-blueprint/src/launcher.rs:47-60`); the values are dropped. If a stripped
  credential reaches the session by another route (a file outside the catalog, an MCP tool result,
  a shell history line), its value leaving through a granted host looks like any other request.

The case this FEP is written for is unintentional. A reported incident (Hacker News, November
2026; summarized at `cellcog.ai/blog/claude-code-email-leak/`, which the drafting session could not
fetch, so the details below are the search summary's and are unverified): a coding agent placed
the account's email address in the `User-Agent` header of its web requests to third-party sites for
about two months before anyone noticed. No rule was broken. Every destination was one the agent was
allowed to reach, the value was not a credential, and the tool that sent it was doing what it was
built to do. Under Formwork today the same session produces `debug`-level grant records naming the
hosts and paths and nothing else.

The same shape recurs with other values: an absolute home path (which carries the login name) in a
telemetry body, the machine's hostname in a crash report, a git author address in a package
registry request, an access token in a query string. Each goes to a granted host.

Who is hurt: the operator, who granted `api.example.com` for one purpose and has no way to learn
that identifying data went with it; an embedding host, which cannot show its user what a session
disclosed.

### 1.1 Constraints this FEP holds to

- **No secret in any record** (constitution Boundaries). A record names a marker; it never carries
  the marker's bytes, an encoding of them, or the surrounding content.
- **The limit is stated in the report.** A search for known byte strings finds what was sent as
  one of a closed set of encodings. A session that encrypts, splits or re-encodes a value passes
  it. The capability is `Partial` on every host and the reason says why
  ([FW-INV5](../formwork.md#fw-inv5)); nothing here is a data-loss-prevention claim.
- **Memory stays bounded.** The search holds at most **body-buffer** bytes per direction
  ([FW-EGR21](../formwork.md#fw-egr21)).
- **The latency budget holds.** [FW-E2E-096](../formwork.md#fw-e2e-096) passes with the search on.
- **No new dependency without a measurement** (constitution Growth). §3.3 states what is in the
  tree today.
- **Not an activity log.** Draft FEP-9 (`docs/fep-9.md` on its branch, §8) declines to record
  every admitted request because "recording every admitted request would make the record an
  activity log of every host contacted". This FEP keeps that decision: it adds one record per
  *match* and one per-host *aggregate* at session end, not a per-request log.

## 2. Prior art

- **Formwork's own two guards.** The placeholder scan refuses a placeholder outside its bound
  host and header; the reflection guard ends a response that would return a brokered secret,
  holding back "the longest suffix of the stream that is a proper prefix of an encoding"
  (`http.rs:340-378`). Both search streams for known byte strings in bounded memory. This FEP
  applies the same matcher to the request direction and to operator-named values.
- **Secret scanners on the commit path** (gitleaks, trufflehog, GitHub push protection) search for
  credential *shapes* by pattern. Formwork's env scrub already uses a shape heuristic, on
  variable names ([FW-ENV2](../formwork.md#fw-env2)). Shapes produce false positives on request
  bodies that carry code, which is most of what an agent sends to a model API; this FEP searches
  for exact values instead and leaves shapes out (§8).
- **Canary tokens** plant a value and alert when it appears somewhere else. A declared marker is
  the same idea applied at the egress door: the operator names a value and learns where it went.
- **Egress logging in hosted sandboxes** records destination and byte counts per connection. That
  is the per-host aggregate in §3.6, which Formwork already computes and discards.

## 3. Design

### 3.1 Markers

A **marker** is a named byte string the operator does not expect to leave the session. The Gateway
holds markers the way it holds brokered secrets: read once by the Launcher, handed to the engine in
memory, absent from the blueprint, the compiled policy, the report and every record.

Markers come from three sources.

| Source | Declared by | Default action |
|---|---|---|
| **stripped** — the value of each environment variable the Launcher strips under [FW-CRED4](../formwork.md#fw-cred4) | nobody; derived at spawn | `refuse` |
| **brokered** — the secret of each brokered credential ([FW-CRED11](../formwork.md#fw-cred11)) | nobody; already in the vault | `refuse` |
| **declared** — a value the blueprint points at | `[net] markers` | `observe` |

A declared marker names where its value is read from, never the value:

```toml
[net]
hosts   = ["allow:api.anthropic.com", "allow:GET:crates.io"]
markers = [
  "env:OPERATOR_EMAIL",             # read from the launching environment
  "file:~/.config/formwork/markers", # one value per line, `name = value`
  "identity:git-email",              # a closed set, below
]
```

`identity:` takes exactly one of `home` (the home directory path), `hostname`, `git-email`
(`user.email` from the operator's git configuration) and `login` (the login name). A source that
yields no value is a load error naming the source ([FW-INV6](../formwork.md#fw-inv6)).

Two limits apply at load. A value shorter than **marker-min** (8 bytes) is refused, because a
short value matches unrelated content; `identity:login` is refused on most hosts for that reason
and the error says so. A blueprint that resolves more than **marker-limit** (32) declared markers
is refused, which bounds the search cost in §3.3.

A marker may name hosts where the value is expected, so that a model API that receives working
directory paths in every prompt does not report each one:

```toml
markers = ["identity:home except api.anthropic.com"]
```

`except` takes host patterns in the host-rule grammar ([FW-BP16](../formwork.md#fw-bp16)). A
stripped or brokered marker has no `except`.

### 3.2 Encodings searched

For each marker the Gateway searches for exactly these **marker-encodings**: the raw bytes; the
percent-encoded form with upper-case and with lower-case hex digits; hex in lower and upper case;
the JSON string-escaped form where it differs from the raw bytes; and base64 in the standard and
URL-safe alphabets at each of the three byte alignments, trimmed to the characters the alignment
fixes. The set is closed and part of the requirement (`FW-EGR31`), so the report's reason can list
it and a test can enumerate it.

### 3.3 Where the search runs

| Traffic | Head (target and header values) | Body |
|---|---|---|
| Inspected request ([FW-EGR10](../formwork.md#fw-egr10)) | searched before the head is forwarded | searched as it streams |
| Plain HTTP request | same | same |
| Body with a `Content-Encoding` other than `identity` | searched | **unscanned**, counted |
| Bytes after a `101` upgrade | — | **unscanned**, counted |
| `tunnel:` host | — | **unscanned**, counted |
| MCP `tools/call` params, agent to backend (phase C) | — | searched per frame |

The search runs on the bytes the session wrote, before `present` substitutes a brokered secret
(`inspect.rs:1112`), so the Gateway never matches its own substitution.

In `observe` the body search needs no hold-back: bytes are forwarded as they arrive and a match is
recorded when it completes. In `refuse` it uses the reflection guard's contract: no byte that
begins an occurrence is released, and the request ends.

**Cost.** `Guard::scan` compares every encoding at every offset (`http.rs:358-362`). That is
acceptable for two encodings of one credential on a response. With 32 declared markers and the
stripped and brokered ones, at about a dozen encodings each, it is several hundred patterns over a
request body that [FW-E2E-092](../formwork.md#fw-e2e-092) sizes at 256 MiB. The matcher is
therefore replaced by one that indexes patterns by first byte and uses `memchr`, which `serde_json`
already brings into every crate. `aho-corasick` is in `Cargo.lock` as an optional dependency of
`regex` and is not compiled today (`cargo tree -i aho-corasick` prints nothing); enabling it is a
Growth decision this FEP defers to a measurement (§9).

### 3.4 The disclosure record

Each request in which the search finds a marker emits one **disclosure** record:

| Field | Value |
|---|---|
| `marker` | the marker's name (`env:OPERATOR_EMAIL`, `stripped:GITHUB_TOKEN`, `brokered:anthropic`) |
| `host`, `port`, `grade` | as in the grant record |
| `method`, `path` | canonical path; no query string |
| `location` | `target`, `header:<lower-case name>` or `body` |
| `encoding` | one name from the closed set in §3.2 |
| `count` | occurrences in this request |
| `action` | `observed` or `refused` |
| `timestamp` | milliseconds |

It carries no byte of the marker and no byte of the request around it. The header *name* is
recorded; [FW-FID13](../formwork.md#fw-fid13) excludes header values, and stays as it is. The
record is emitted at `warn` on the operator channel with the wording of
[FW-FID9](../formwork.md#fw-fid9) lines, and kept for the end-of-run account.

For the incident in §1 the operator declares `identity:git-email` or `env:OPERATOR_EMAIL` and the
first request prints:

```
formwork: disclosure observed: env:OPERATOR_EMAIL in header:user-agent (raw) to crates.io:443 GET /api/v1/crates
```

### 3.5 Refusing

A marker whose action is `refuse` turns a match into a refusal. In the head, the request is not
forwarded and the session receives the generic refusal. In the body, the stream ends at the match
and the upstream connection is closed, not returned to the pool. Both emit a violation record with
the new reason `marker` in the closed set of [FW-FID12](../formwork.md#fw-fid12).

Stripped and brokered markers default to `refuse`. A session holds neither value by construction:
the Launcher removed the one and the Gateway never disclosed the other
([FW-CRED16](../formwork.md#fw-cred16)). Either value in an outbound request means the floor was
crossed by a route Formwork did not close, and forwarding it would complete the disclosure. A
credential the blueprint lifts with `allow-credentials` is not stripped and is not a marker.

Declared markers default to `observe`; `action = "refuse"` on a marker, or `--set
net.markers-action=refuse`, changes it.

### 3.6 The account at session end

When a `run` ends, the Launcher writes one **egress account** on the operator channel at `info`:
for each host contacted, the number of requests, bytes up and down, the grades used, the number of
disclosures, the number of **unscanned** bytes sent, and the distinct request header names seen
(names only, the first **header-names-kept** (64) per host).

```
formwork: egress account
  api.anthropic.com:443  inspected  214 requests  up 3.1 MiB  down 9.8 MiB  disclosures 0  unscanned 0
  crates.io:443          inspected   12 requests  up 4.2 KiB  down 1.1 MiB  disclosures 12 unscanned 0
      headers: accept, accept-encoding, host, user-agent
  github.com:443         tunnel       3 tunnels   up 48 KiB   down 2.0 MiB  disclosures -  unscanned 48 KiB
```

The account is an aggregate of counters the engine already keeps per grant. It is the per-host
form of the data FEP-9 declines to record per request, and it is what makes an unexpected upload
(a 40 MiB `up` to a documentation host) visible without a marker. If FEP-9's session record lands,
disclosures and the account are rows in it and the JSON shape is defined there; until then they
are operator lines and an `EgressProxy` accessor for embedders.

### 3.7 The report row

`compile` gains the capability `net-disclosure`, present when the blueprint resolves at least one
marker or brokers or strips a credential.

| Condition | Verdict | Reason names |
|---|---|---|
| every host rule is inspected or plain | `Partial` | the closed encoding set; coded bodies and upgraded streams are unscanned |
| at least one `tunnel:` rule | `Partial` | the same, and the tunnelled hosts by rule |
| markers declared and no Gateway carries egress (`net = "allow"`, a port tier, `--confine-self`) | `Unenforceable` | no door to search at |

The row is never `Enforced`.

### 3.8 Asymmetries that remain

- **Tunnelled hosts are unsearched on both platforms.** The account counts their bytes; nothing
  else is known about them.
- **An MCP backend with its own network grant is a second door.** Phase C searches what the agent
  sends the backend. What the backend then sends elsewhere is governed by the Confiner the backend
  runs under (constitution Concepts, **Session**), not by this FEP.
- **Direct egress under a port tier bypasses the Gateway**, so no search runs; §3.7 reports it.
- **A value the session transforms is not found.** `FW-ADV-047` asserts this, so the limit is a
  tested statement and not an omission.

## 4. Surface changes (each measured against Growth)

| Change | Existing concept searched first | Why it does not fit |
|---|---|---|
| Blueprint: `[net] markers`, `[net] markers-action` | `allow-credentials` and the Catalog name credential *locations* to deny or broker | a marker is a value to recognise, is not a credential, and is not denied to the session |
| Vocabulary: **marker**, **disclosure**, **unscanned** | **placeholder** is the stand-in the session holds; **reflection** is the response direction | neither names an operator-chosen value in the request direction |
| Violation reason `marker` | `placeholder`, `reflection` | the value is neither |
| Capability `net-disclosure` in the report | `net-inspection` reports whether TLS is terminated | whether content is searched, and for what, is a separate claim with a separate verdict |
| Operator lines: disclosure, egress account | FW-FID9 refusal lines | these are not refusals |
| Launcher keeps stripped values in memory until the engine has them | none | today they are dropped at partition |
| Dependencies | — | none added; `memchr` is already compiled into every crate |

No new concept: markers are held and searched for by the **Gateway**, declared in the
**Blueprint**, read by the **Launcher**, and reported by the **FidelityReport**. No new requirement
family.

## 5. Proposed requirements (draft numbering — anchored on landing)

| ID | Statement |
|---|---|
| `FW-BP26` Marker declarations | The CLI shall accept `[net] markers` entries whose source is exactly one of `env:`, `file:` and `identity:` (`home`, `hostname`, `git-email`, `login`), and shall refuse at load a source that yields no value, a value shorter than **marker-min** bytes, and a blueprint that resolves more than **marker-limit** declared markers. |
| `FW-EGR31` Head search | Before forwarding the head of an inspected or plain-HTTP request, the Gateway shall search the request target and every header value for each **marker-encoding** (exactly the set in FEP-12 §3.2) of each marker not excepted for the request's host. |
| `FW-EGR32` Body search | The Gateway shall search the body of every inspected or plain-HTTP request with identity content coding for the same encodings as it streams, holding at most **body-buffer** bytes. |
| `FW-EGR33` Derived markers | The Launcher shall register as a marker the value of every environment variable it strips under FW-CRED4 and the secret of every brokered credential, where the value is at least **marker-min** bytes. |
| `FW-EGR34` Marker refusal | For a marker whose action is `refuse`, the Gateway shall not forward a request head in which the search finds it, and shall end a request body without releasing any byte that begins an occurrence of it. |
| `FW-EGR35` MCP frames | The Gateway shall search the `params` of every `tools/call` request it forwards to a backend for the same encodings, and shall refuse the call where a matched marker's action is `refuse`. |
| `FW-FID27` Disclosure record | For each request in which the search finds a marker, the Gateway shall emit exactly one record per marker and location carrying the marker's name, host, port, grade, method, canonical path, location, encoding name, count, action and timestamp. |
| `FW-FID28` Unscanned bytes | The Gateway shall count per host the request bytes it forwards without searching (a tunnel, a body with a content coding other than identity, a stream after an upgrade). |
| `FW-FID29` Egress account | At the end of a `run` that carried egress through the Gateway, the Launcher shall write for each contacted host the request count, bytes up, bytes down, grades, disclosure count, unscanned byte count and at most **header-names-kept** distinct request header names. |
| `FW-FID30` Disclosure verdict | The compiler shall report `net-disclosure` as `Partial`, naming the encoding set and every `tunnel:` rule, where a Gateway carries the session's egress, and as `Unenforceable` where markers are declared and no Gateway does. |
| `FW-INV22` Markers stay in the Gateway | No record, report, log line at any level, error message or response to the session shall contain the bytes of a marker or a marker-encoding of them. |

**Parameters**, defined once: **marker-min** = 8 bytes; **marker-limit** = 32;
**header-names-kept** = 64; **body-buffer** as landed.

## 6. Verification plan

Fixtures are the loopback HTTPS upstreams of `crates/formwork-gateway/tests/support`, which record
every request they receive. Each test asserts on records and on what the upstream saw, never on
operator prose.

| ID | Test |
|---|---|
| `FW-E2E-169` | The §1 incident: a client sends a declared marker in `User-Agent` to a granted inspected host. One disclosure record names `header:user-agent`; the upstream received the request (`observe`). |
| `FW-E2E-170` | A marker in a request body split across two writes at every offset of the marker. One record, `location = body`; the upstream received every byte in order. |
| `FW-E2E-171` | Each marker-encoding in turn, in the target and in the body, produces a record naming that encoding. Table-driven over the closed set, so adding an encoding without a row fails. |
| `FW-E2E-172` | A stripped credential's value sent to a granted host is refused: the upstream receives no head; a violation record carries `marker`. Paired with the same request without the value, which is admitted. |
| `FW-E2E-173` | The same value in a body in `refuse`: the upstream receives no byte that begins the value and the connection is not reused. |
| `FW-E2E-174` | A `tunnel:` host, a `gzip`-coded body and a WebSocket upgrade each add their byte count to **unscanned** for the host and produce no disclosure record. |
| `FW-E2E-175` | The egress account after a three-host run lists each host with its counts and header names, and nothing for a host that was refused. |
| `FW-E2E-176` | `compile` with a marker and `net = "allow"` reports `net-disclosure` `Unenforceable`; with one `tunnel:` rule the reason names it; `identity:login` with a four-byte login fails at load naming **marker-min**. |
| `FW-E2E-177` | [FW-E2E-096](../formwork.md#fw-e2e-096) and [FW-E2E-092](../formwork.md#fw-e2e-092) re-run with **marker-limit** declared markers: the latency budget and the 16 MiB memory bound hold. |
| `FW-ADV-046` | `FW-INV22`: with `RUST_LOG=trace`, run `FW-E2E-169`..173, then search stdout, stderr, the operator channel, every record and the `explain`/`compile` JSON for every marker-encoding of every marker. No occurrence. |
| `FW-ADV-047` | The stated limit: the marker sent ROT13-coded, and split across two requests, is admitted with no record. The test asserts the `Partial` reason names the closed encoding set. |

`FW-EGR35` is tested through `fw-mcp-fixture` in `crates/formwork-gateway/tests/gateway.rs`: a
`tools/call` whose arguments carry a declared marker yields one record; with `refuse` the backend
receives no frame. The matcher gets unit tests for overlap, a pattern that is a prefix of another,
and a property test against a naive search once the fuzz infrastructure in `docs/STATUS.md` exists.

**Phasing.**

- **A — account and derived markers.** `FW-FID28`, `FW-FID29`, `FW-EGR33`, `FW-EGR34`, head search
  only. No blueprint change; `FW-E2E-172`, `FW-E2E-174`, `FW-E2E-175`.
- **B — declared markers and the body.** `FW-BP26`, `FW-EGR31`, `FW-EGR32`, `FW-FID27`,
  `FW-FID30`, `FW-INV22`; the remaining tests.
- **C — the MCP door.** `FW-EGR35`.

Phase A changes no published input and can land alone.

## 7. Amendments to the landed docs (apply on landing)

**(a) `formwork.md` §5.** Add the rows of §5 above, anchored. Add `marker` to the closed reason set
under [FW-FID12](../formwork.md#fw-fid12).

**(b) `formwork.md` §7 and §10.** Add `FW-E2E-169`..177 and `FW-ADV-046`..047 and their
traceability rows.

**(c) `formwork.md` §9 (fidelity matrix).** Add the `net-disclosure` row with the verdicts of §3.7.

**(d) `constitution.md` Vocabulary.** Add: **marker** = a named value the Gateway searches outbound
requests for, held like a brokered secret · **disclosure** = a marker found in a request the
session sent · **unscanned** = request bytes the Gateway forwarded without searching.

**(e) `constitution.md` Concepts, Blueprint.** Add "egress markers (`FW-BP26`)" to the enumeration.

**(f) `README.md`.** One paragraph under the egress section: what a marker is, the account, and the
sentence "this finds a value sent as written or in a common encoding; it does not stop a session
that sets out to hide one".

**(g) `docs/STATUS.md`.** A phase row for this FEP.

## 8. Decisions (recorded per constitution Precedence & Conflicts)

- **Exact values, not shapes.** A shape pattern (an email regex, a token prefix) fires on source
  code and documentation in request bodies to a model API. An exact value fires when that value
  leaves. Shapes stay where they are, in the env scrub.
- **`observe` by default for declared markers.** A declared marker is often expected somewhere the
  operator has not listed yet; refusing on first use would turn a visibility feature into a
  breakage and get it turned off (constitution Growth, the reuse thesis).
- **`refuse` by default for stripped and brokered markers.** The session cannot hold these by
  design, so no working flow depends on sending them. This changes behavior for existing
  blueprints; no release has shipped, so it is made outright.
- **An aggregate, not a log.** Per-request grant records stay at `debug`, as FEP-9 decided.
- **The record names the header, not its value.** FW-FID13's exclusion is unchanged.
- **`Partial`, never `Enforced`.** The encoding set is closed and an adversary is not bound by it.

## 9. Open questions

| Question | Owner | Closes at |
|---|---|---|
| Does a first-byte index over `memchr` hold `FW-E2E-096` at **marker-limit**, or is `aho-corasick` needed? Measure both before phase B. | implementer of phase B | phase B review |
| Should raw matching fold ASCII case for `identity:git-email` (mail addresses are sent in mixed case)? | reviewer | adoption |
| Should `identity:` exist at all, or should every declared marker come from `env:` and `file:`? It adds four sources the Launcher must read (`git config` among them). | reviewer | adoption |
| Does the account belong on the operator channel before FEP-9's session record exists, or should phase A wait for it? | reviewer of FEP-9 | FEP-9 adoption |
| A per-host upload budget (`refuse` above N bytes up) is a natural next step from the account. It is a new blueprint field and is left out. | — | a later FEP |
| Request bodies with `Content-Encoding: gzip` could be decoded for search at a memory cost. Left **unscanned** here. | — | after phase B measurements |
