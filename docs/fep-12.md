# FEP-12 (proposal): tagged data at the egress door — tag regulated values, then audit or block them

**Formwork Enhancement Proposal 12 — proposal, not landed.** Companion to `formwork.md`
(design + end-to-end spec), `constitution.md` (doctrine), `docs/fep-5.md` (inspection and
brokering) and `docs/fep-6.md` (the egress engine).

**Status.** Nothing in this document mutates the landed spec or the constitution. The §7
amendments are apply-on-landing blocks. New identifiers are draft numbering, written as inline code
so the requirements canary skips them, until they are anchored on landing; each links to its
definition below. This FEP holds the reserved blocks
[`FW-EGR31`..`FW-EGR35`](#draft-fw-egr31), [`FW-FID27`..`FW-FID30`](#draft-fw-fid27),
[`FW-BP26`](#draft-fw-bp26), [`FW-DISC20`](#draft-fw-disc20), [`FW-INV22`](#draft-fw-inv22),
[`FW-E2E-169`..`FW-E2E-177`](#draft-fw-e2e-169), [`FW-E2E-221`](#draft-fw-e2e-221) and
[`FW-ADV-046`..`FW-ADV-047`](#draft-fw-adv-046). They start above the blocks the open drafts hold
(FEP-7 to `FW-E2E-116`, FEP-8 to `FW-E2E-132`, FEP-9 to `FW-E2E-144` and `FW-FID24`, FEP-10 to
`FW-E2E-156` and `FW-EGR30`, FEP-11 to `FW-E2E-168`, `FW-FID26` and `FW-INV21`) and above the
highest landed numbers. Phase A (§6) is implemented in a pull request on the earlier vocabulary
(`marker`, `observe`, `refuse`), which takes this document's names on adoption.

**What this is.** Both observability and enforcement. A tagged value has an action: `audit`
records where it went, and `block` stops the request. A blocked request is refused, but the claim
stays `Partial` (§3.8): the search finds a value sent as written or in a common encoding, not one a
session sets out to hide. This is not data-loss prevention and not a compliance claim.

**Vocabulary note.** This document says **view** for what the landed spec calls *grade*: how much
of a connection the Gateway sees, `tunnel` (the server name) or `inspected` (each request). The
rename of the landed spec is a separate change.

---

## 1. Problem

A session handles **regulated information**: credentials, and personal data in the sense of the
GDPR ("any information relating to an identified or identifiable natural person", Art. 4(1)) and
of NIST SP 800-122 (personally identifiable information, PII). The operator wants three things
from Formwork:

1. **Tag** it: say which values are regulated, and of what class.
2. **Audit** it: learn when a tagged value leaves the session, to which host, and where in the
   request.
3. **Block** it, where the class or the operator says it must not leave.

Formwork does none of this today. A host rule decides *where* a session may send; nothing looks at
*what* it sends.

- **The grant record excludes content by requirement.** [FW-FID13](../formwork.md#fw-fid13) gives
  each admitted request a record with no header value, body byte or query string, because those
  fields hold secrets. A record looks like this:

  ```json
  {"host":"crates.io","port":443,"grade":"inspected","method":"GET","path":"/api/v1/crates",
   "status":200,"bytes_up":0,"bytes_down":10873,"duration_ms":38}
  ```

  For an inspected request `bytes_up` and `bytes_down` count body bytes (head excluded); for a
  tunnel they count every byte each way. It is emitted at `debug` and read by nothing outside the
  Gateway's tests.
- **The Launcher discards what it could look for.** `construct_env` strips credential variables
  and drops their values (`crates/formwork-blueprint/src/launcher.rs`). If one reaches the session
  by another route (a file outside the catalog, an MCP tool result), its value leaves through a
  granted host like any other request.
- **The only outbound content check covers placeholders.** `scan_placeholders` searches the
  request head for the per-session placeholder prefix ([FW-CRED14](../formwork.md#fw-cred14));
  request bodies go unsearched.

The case this FEP is written for is unintentional. A coding agent was reported to have put the
account's email address in the `User-Agent` of its requests to third-party sites for about two
months (Hacker News, November 2026; unverified, see `cellcog.ai/blog/claude-code-email-leak/`).
Every destination was allowed. The same thing happens by prompt injection: a page that says "enter
your email to continue", or a `401` that asks for an identity. The value is not a credential, but
it is personal data. It sits in `~/.gitconfig` next to the user's full name, and it is normally
kept from third parties. A home path (it carries the login name), the hostname and the git author
name leave the same way. Tagging catches the value whatever made the session send it.

### 1.1 Constraints this FEP holds to

- **No tagged value in any record** (constitution Boundaries). A record names the tag; it never
  carries the value, an encoding of it, or the bytes around it.
- **The limit is in the report** ([FW-INV5](../formwork.md#fw-inv5)): `Partial` on every host,
  never `Enforced`.
- **No oracle** ([FW-INV9](../formwork.md#fw-inv9)): a block must not confirm a value the session
  could have guessed (§3.2).
- **The session learns nothing new.** Tagged values stay in the Gateway; nothing is added to the
  session's environment or filesystem.
- **Memory stays bounded** ([FW-EGR21](../formwork.md#fw-egr21)), and
  [FW-E2E-096](../formwork.md#fw-e2e-096)'s latency budget holds with the search on.
- **No new dependency without a measurement** (constitution Growth).
- **Not an activity log.** Draft FEP-9 declines to record every admitted request. This FEP adds one
  record per *match* and one per-host *aggregate* at session end.

## 2. Prior art

- **NIST SP 800-53 Rev. 5** names the three parts: AC-16 *Security and Privacy Attributes* (tag
  information), AC-4 *Information Flow Enforcement* (decide a flow by its attributes), and AU-2/AU-3
  *Event Logging* and *Content of Audit Records* (record it). The PT family (*PII Processing and
  Transparency*) frames personal data as its own class of controls.
- **NIST SP 800-122** defines PII as information that can distinguish or trace an individual's
  identity, alone or linked with other information. Name, email address and user identifiers are
  its examples; that is why a home path or hostname counts when it carries a login.
- **The GDPR** gives the class boundary and the vocabulary. Art. 4(1) and Recital 30 cover online
  identifiers. Art. 4(2) counts "disclosure by transmission" as processing. Art. 5(1)(c) (data
  minimisation) and Art. 25 (data protection by design and by default) are the reasons to block
  personal data that has no purpose at a host. Art. 30 (records of processing) is the reason the
  account in §3.7 exists. Formwork is a control and an audit trail; it does not make an operator
  compliant.
- **Commercial DLP** (sensitivity labels, classifier "info types") uses the same shape: classify,
  then audit or block per class. It matches *shapes* (regexes, checksums). This FEP matches
  *exact values* instead, because shapes fire on the source code an agent sends to a model API
  (§8).
- **Formwork's own guards** search byte streams for known values in bounded memory: the
  placeholder scan and the reflection guard ([FW-CRED17](../formwork.md#fw-cred17)). This FEP
  applies the same idea in the request direction.

## 3. Design

### 3.1 Tags and classes

A **tag** names a value and gives it a **class**. The Gateway holds tagged values the way it holds
brokered secrets: read once by the Launcher, handed to the engine in memory, absent from the
blueprint, the compiled policy, the report and every record. The session is given nothing.

The classes are a closed set.

| Class | Values | Source | Default action |
|---|---|---|---|
| `credential` | each variable the Launcher strips under [FW-CRED4](../formwork.md#fw-cred4), and each brokered secret ([FW-CRED11](../formwork.md#fw-cred11)) | derived at spawn | `block`, fixed |
| `personal` | the operator's identity, read from well-known places (below), and any value the blueprint adds | derived at spawn, plus the blueprint | `audit` |
| `confidential` | anything else the operator wants kept in: a project codename, an internal hostname | the blueprint | `audit` |

### 3.2 Derived tags: no configuration

Just before it starts the session, the Launcher reads the well-known places that name the operator,
and tags what it finds as `personal`:

| Tag | Read from |
|---|---|
| `identity:git-email` | `user.email` from git's configuration, global and for the launch directory |
| `identity:git-name` | `user.name`, the same way |
| `identity:login` | the login name |
| `identity:home` | the home directory path |
| `identity:hostname` | the host name |

Each `credential` value is tagged as `stripped:<VARIABLE>` or `brokered:<name>`, except one that
names a **location**: it starts with `/` or `~/`, or its variable is a catalog file reference
(`KUBECONFIG`, `GOOGLE_APPLICATION_CREDENTIALS`, ...). A path is guessable, so blocking it would
tell the session it guessed right ([FW-INV9](../formwork.md#fw-inv9)); and it is a location the
floor already denies ([FW-CRED3](../formwork.md#fw-cred3)), not a secret.

A derived value shorter than **tag-min** (8 bytes) is skipped, and its name is listed on the
operator channel; a short value matches unrelated content. A source that is absent (no git
configuration) is skipped the same way.

So a blueprint with no `[tags]` section already audits the operator's identity and blocks
credentials. The `[tags]` section exists to change that.

### 3.3 In a blueprint

`[tags]` is a top-level table, next to `rules` and `[fs]`. It has four keys:
- `personal` and `confidential` list added values by source (`env:VAR`, or `file:PATH` with one
  `name = value` per line), never the value itself;
- `block` lists the classes whose matches are refused, which are otherwise audited;
- `expect` maps a tag to the hosts where its value is expected, in the host-rule grammar
  ([FW-BP16](../formwork.md#fw-bp16)). A match there is neither audited nor blocked.

**`examples/blueprints/claude-code.toml`, unchanged.** It carries no `[tags]`, and the derived tags
apply. The agent sends its working directory to the model API in every prompt, so the first run
reports it:

```
formwork: disclosure audited: personal identity:home in body (raw) to api.anthropic.com:443 POST /v1/messages
formwork: egress account
  api.anthropic.com:443     inspected  214 requests  up 3.1 MiB  down 9.8 MiB  disclosures 214 unscanned 0
  statsig.anthropic.com:443 inspected   31 requests  up 22 KiB   down 4.0 KiB  disclosures 0   unscanned 0
```

`formwork learn` turns that into a proposal (§3.6): `expect` the home path at the model API.

**The same blueprint, after the proposal is accepted, with personal data blocked elsewhere:**

```toml
extends = ["agent-base.toml"]

rules = [
    "allow:api.anthropic.com",
    "allow:console.anthropic.com",
    "allow:claude.ai",
    "allow:statsig.anthropic.com",
    "allow:sentry.io",
]
allow-credentials = ["claude"]
channels = ["desktop"]

[fs]
writes = ["~/.claude/**"]

[tags]
# The model API is sent the working directory in every prompt, and the account email at login.
expect = { "identity:home" = ["api.anthropic.com"], "identity:git-email" = ["console.anthropic.com", "claude.ai"] }
# Telemetry hosts get no identity at all.
block = ["personal"]
```

With this, the operator's email in a `User-Agent` to `sentry.io` is refused, and the account shows
the refusal; the same email at login to `claude.ai` passes without a record.

**`examples/blueprints/codex-api-key.toml`, with a project codename.** The brokered key is a
`credential` tag already: if the real key ever appears in a request the session wrote (it holds
only a placeholder), the request is blocked, on any host. The blueprint adds one value of its own:

```toml
extends = ["agent-base.toml"]

rules = [
    "allow:api.openai.com",
    "allow:chatgpt.com",
]
allow-credentials = ["codex", "broker:openai"]

[fs]
writes = ["~/.codex/**"]

[tags]
confidential = ["env:PROJECT_CODENAME"]   # read from the launching shell, never written here
block = ["confidential"]
expect = { "env:PROJECT_CODENAME" = ["api.openai.com"] }   # the model may see it; nobody else
```

**`agent-base.toml`.** Nothing changes: tags follow the hosts an agent uses, so they belong in each
agent's blueprint, not in the shared base.

### 3.4 Encodings searched

For each value the Gateway searches exactly these **tag-encodings**:
- raw;
- percent-encoded with upper- and lower-case hex;
- hex in lower and upper case;
- JSON string-escaped;
- base64 in the standard and URL-safe alphabets at each of the three byte alignments, trimmed to
  the characters the alignment fixes.

The set is closed and part of the requirement, so the report's reason can name it and a test can
enumerate it. Matching is exact; whether `identity:git-email` should fold ASCII case is open (§9).

### 3.5 Where the search runs

| Traffic | Head | Body |
|---|---|---|
| Inspected request ([FW-EGR10](../formwork.md#fw-egr10)) or plain HTTP | the CONNECT line, the method, the target as sent and decoded, every header name and value, the canonical path | searched as it streams |
| Body with a `Content-Encoding` other than `identity` | searched | **unscanned**, counted |
| Bytes after a `101` upgrade | — | **unscanned**, counted |
| `tunnel:` host | — | **unscanned**, counted |
| MCP `tools/call` params, agent to backend (phase C) | — | searched per frame |

The canonical path is searched because removing dot-segments can join a value split across
segments. The search reads the bytes the session wrote, before a brokered secret is substituted
in, so the Gateway never matches its own substitution.

`audit` needs no hold-back in the body: bytes go through as they arrive, and a match is recorded
when it completes. `block` uses the reflection guard's contract: no byte that begins an occurrence
is released, and the request ends. In the head, a blocked request is not forwarded and the session
receives the generic refusal; in the body, the upstream connection is closed, not pooled. Both emit
a violation record with the new reason `tagged` in the closed set of
[FW-FID12](../formwork.md#fw-fid12).

**Cost.** The matcher indexes patterns by first byte (std only). Phase A measured about 9 µs on a
350-byte head with 32 values. Whether body search at **tag-limit** needs `aho-corasick` (in
`Cargo.lock`, not compiled) is measured in phase B (§9).

### 3.6 Records, and what `learn` does with them

Each request in which the search finds a tagged value emits one **disclosure** record per tag and
location:

| Field | Value |
|---|---|
| `tag`, `class` | the tag's name (`identity:git-email`, `env:PROJECT_CODENAME`, `stripped:GITHUB_TOKEN`) and class |
| `host`, `port`, `view` | as in the grant record |
| `method`, `path` | canonical path, no query string |
| `location` | `target`, `header:<lower-case name>` or `body` |
| `encoding` | one name from §3.4 |
| `count`, `action`, `timestamp` | occurrences; `audited` or `blocked`; milliseconds |

The operator channel prints the first disclosure of each tag, host and location at `warn`; the
rest are counted in the account, so a value sent in every prompt is one line, not hundreds.

`formwork learn` reads the disclosure records of its run and proposes `[tags]` entries
(`FW-DISC20`), the same way it proposes host rules from refusals
([FW-DISC12](../formwork.md#fw-disc12)):
- a tag audited at a host the blueprint grants: `expect` it there, or `block` its class;
- a `credential` tag: never proposed for `expect`, and itemized as withheld, as
  [FW-DISC3](../formwork.md#fw-disc3) withholds credential paths.

`learn` proposes by tag name; it never prints a value.

### 3.7 The account at session end

When a `run` ends, the Launcher writes one **egress account** on the operator channel at `info`,
one line per host the Gateway forwarded a request or tunnel to: requests, bytes up and down, views
used, disclosures, **unscanned** bytes, and the request header names seen (names only, the first
**header-names-kept** (64) per host). §3.3 shows one.

This is the record of what left (GDPR Art. 30's question, per session), and it shows an unexpected
upload (40 MiB up to a documentation host) without any tag. It aggregates counters the engine
already keeps.

### 3.8 The report row

`compile` gains the capability `net-disclosure`, present whenever a tag exists, derived or
declared.

| Condition | Verdict | Reason names |
|---|---|---|
| every host rule is inspected or plain | `Partial` | the closed encoding set; coded bodies and upgraded streams are unscanned |
| at least one `tunnel:` rule | `Partial` | the same, and the tunnelled hosts |
| no Gateway carries egress (`net = "allow"`, a port tier, `--confine-self`) | `Unenforceable` | no door to search at |

### 3.9 What remains open

- Tunnelled hosts are unsearched; the account counts their bytes.
- An MCP backend with its own network grant is a second door; phase C searches what the agent
  sends it, and the backend's own Confiner governs the rest.
- A value the session transforms (encrypts, splits, re-encodes) passes, and
  [`FW-ADV-047`](#draft-fw-adv-047) asserts it.
- Personal data the Launcher cannot find in a well-known place (an email the agent read from a
  project file) is not tagged unless the blueprint adds it.

## 4. Surface changes (each measured against Growth)

| Change | Existing concept searched first | Why it does not fit |
|---|---|---|
| Blueprint: top-level `[tags]` (`personal`, `confidential`, `block`, `expect`) | `allow-credentials` and the Catalog name credential *locations*; `rules` name paths and hosts | a tag names a value to recognise, which the session may hold |
| Launcher reads git configuration, login, home and hostname | the Launcher already reads the environment and the Catalog | these are the well-known places personal data sits |
| Vocabulary: **tag**, **class**, **disclosure**, **unscanned** | **placeholder**, **reflection** | neither names an operator-classified value in the request direction |
| Violation reason `tagged` | `placeholder`, `reflection` | the value is neither |
| Capability `net-disclosure` | `net-inspection` (whether TLS is terminated) | whether content is searched is a separate claim |
| Operator lines: disclosure, egress account | FW-FID9 refusal lines | an audit is not a refusal |
| `learn` proposes `[tags]` entries | `learn` proposes rules and channels | the same mechanism, one more output |
| Dependencies | — | none |

## 5. Proposed requirements (draft numbering — anchored on landing)

| ID | Statement |
|---|---|
| <a id="draft-fw-bp26"></a>`FW-BP26` Tag declarations | The CLI shall accept a top-level `[tags]` table with exactly the keys `personal` and `confidential` (lists of `env:` and `file:` sources), `block` (a list of classes) and `expect` (a map from a tag name to host patterns); and shall refuse at load a source that yields no value, a value shorter than **tag-min** bytes, more than **tag-limit** declared values, an `expect` entry for a `credential` tag, and a tag name `expect` names that no source defines. |
| <a id="draft-fw-egr31"></a>`FW-EGR31` Head search | Before forwarding the head of an inspected or plain-HTTP request, the Gateway shall search the CONNECT request line, the method, the target as sent and percent-decoded, every header name and value, and the canonical path for each **tag-encoding** (exactly the set in FEP-12 §3.4) of each tagged value not expected at the request's host. |
| <a id="draft-fw-egr32"></a>`FW-EGR32` Body search | The Gateway shall search the body of every inspected or plain-HTTP request with identity content coding for the same encodings as it streams, holding at most **body-buffer** bytes. |
| <a id="draft-fw-egr33"></a>`FW-EGR33` Derived tags | Before it starts the session, the Launcher shall tag as `credential` the value of every environment variable it strips under FW-CRED4, unless the value names a location, and the secret of every brokered credential; and as `personal` the git `user.email` and `user.name` (global and for the launch directory), the login name, the home path and the host name; each where the value is at least **tag-min** bytes. |
| <a id="draft-fw-egr34"></a>`FW-EGR34` Blocking | For a tagged value whose class is `credential` or listed in `block`, the Gateway shall not forward a request head in which the search finds it, and shall end a request body without releasing any byte that begins an occurrence of it. |
| <a id="draft-fw-egr35"></a>`FW-EGR35` MCP frames | The Gateway shall search the `params` of every `tools/call` request it forwards to a backend for the same encodings, and shall refuse the call where a matched tag is blocked. |
| <a id="draft-fw-fid27"></a>`FW-FID27` Disclosure record | For each request in which the search finds a tagged value, the Gateway shall emit exactly one record per tag and location carrying the tag's name and class, host, port, view, method, canonical path, location, encoding name, count, action and timestamp. |
| <a id="draft-fw-fid28"></a>`FW-FID28` Unscanned bytes | The Gateway shall count per host the request bytes it forwards without searching (a tunnel, a body with a content coding other than identity, a stream after an upgrade). |
| <a id="draft-fw-fid29"></a>`FW-FID29` Egress account | At the end of a `run` that carried egress through the Gateway, the Launcher shall write on the operator channel, for each host the Gateway forwarded a request head or a tunnel to, the request count, bytes up, bytes down, views, disclosure count, unscanned byte count and at most **header-names-kept** distinct request header names. |
| <a id="draft-fw-fid30"></a>`FW-FID30` Disclosure verdict | The compiler shall report `net-disclosure` as `Partial`, naming the encoding set and every `tunnel:` rule, where a Gateway carries the session's egress, and as `Unenforceable` where none does. |
| <a id="draft-fw-disc20"></a>`FW-DISC20` Tag proposals | `learn` shall propose, for each tag audited at a granted host during its run, an `expect` entry for that host and a `block` entry for the tag's class, by tag name only; and shall withhold and itemize every `credential` tag. |
| <a id="draft-fw-inv22"></a>`FW-INV22` Tagged values stay in the Gateway | No record, report, proposal, log line at any level, error message or response to the session shall contain a tagged value or a tag-encoding of it. |

**Parameters**, defined once: **tag-min** = 8 bytes; **tag-limit** = 32 declared values;
**header-names-kept** = 64; **body-buffer** as landed.

## 6. Verification plan

Fixtures are the loopback HTTPS upstreams of `crates/formwork-gateway/tests/support`, which record
every request they receive. Each test asserts on records and on what the upstream saw.

| ID | Test |
|---|---|
| <a id="draft-fw-e2e-169"></a>`FW-E2E-169` | The §1 incident under a blueprint with no `[tags]`: a fixture git configuration sets `user.email`; the session sends it in `User-Agent` to a granted inspected host. One disclosure record names `identity:git-email` and `header:user-agent`; the upstream received the request (`audit`). |
| `FW-E2E-170` | A tagged value in a request body split across two writes at every offset. One record, `location = body`; the upstream received every byte in order. |
| `FW-E2E-171` | Each tag-encoding in turn, in the target and the body, produces a record naming it. Table-driven over the closed set. |
| `FW-E2E-172` | A stripped credential's value in a head is blocked: the upstream receives nothing; a violation carries `tagged`. A stripped path is admitted. |
| `FW-E2E-173` | A value in a body under `block`: the upstream receives no byte that begins it and the connection is not reused. With `expect` for that host, the same body is admitted with no record. |
| `FW-E2E-174` | A `tunnel:` host, a `gzip` body and a WebSocket upgrade each add to **unscanned** and produce no disclosure record. |
| `FW-E2E-175` | The account after a three-host run lists each host with its counts and header names, and nothing for a refused host. |
| `FW-E2E-176` | `compile` with `net = "allow"` reports `net-disclosure` `Unenforceable`; a `tunnel:` rule is named in the reason; an `env:` source holding four bytes fails at load naming **tag-min**; `expect` on a `stripped:` tag fails at load. |
| `FW-E2E-177` | [FW-E2E-096](../formwork.md#fw-e2e-096) and [FW-E2E-092](../formwork.md#fw-e2e-092) with **tag-limit** tags: the latency budget and the 16 MiB memory bound hold. |
| <a id="draft-fw-e2e-221"></a>`FW-E2E-221` | `learn` over a run in which `identity:home` is sent to a granted host and a stripped token to another: the proposal holds `expect = { "identity:home" = [<host>] }` and `block = ["personal"]`, the token's tag is itemized as withheld, and no proposal line contains either value. |
| <a id="draft-fw-adv-046"></a>`FW-ADV-046` | `FW-INV22`: under `RUST_LOG=trace`, run 169..173 and 221 and search stdout, stderr, the operator channel, every record, the proposal and the `explain`/`compile` JSON for every encoding of every tagged value. No occurrence. |
| <a id="draft-fw-adv-047"></a>`FW-ADV-047` | The stated limit: a value sent ROT13-coded, or split across two requests, is admitted with no record; the `Partial` reason names the encoding set. |

**Phasing.**

- **A — credential tags, head blocking, the account.** `FW-EGR33` (credential half), `FW-EGR34`
  (head), `FW-FID28`, `FW-FID29`; tests 172, 174, 175. No blueprint change. Implemented (see
  Status).
- **B — personal tags, `[tags]`, the body.** `FW-EGR33` (personal half), `FW-BP26`, `FW-EGR31`,
  `FW-EGR32`, `FW-FID27`, `FW-FID30`, `FW-INV22`; tests 169..171, 173, 176, 177 and the ADV tests.
- **C — the MCP door.** `FW-EGR35`.
- **D — `learn` proposals.** `FW-DISC20`; test 221.

## 7. Amendments to the landed docs (apply on landing)

- **(a) `formwork.md` §5.** The rows of §5, anchored; `tagged` in the [FW-FID12](../formwork.md#fw-fid12) reason set.
- **(b) `formwork.md` §7 and §10.** The tests of §6 and their traceability rows.
- **(c) `formwork.md` §9.** The `net-disclosure` row of §3.8.
- **(d) `constitution.md` Vocabulary.**
  - **tag**: a named value the Gateway searches outbound requests for, held like a brokered secret;
  - **class**: `credential`, `personal` or `confidential`;
  - **disclosure**: a tagged value found in a request the session sent;
  - **unscanned**: request bytes forwarded without searching.
- **(e) `constitution.md` Concepts, Blueprint.** Add "egress tags (`FW-BP26`)".
- **(f) `README.md`.** One paragraph: tags, classes, the account, and "this finds a value sent as
  written or in a common encoding; it does not stop a session that sets out to hide one".
- **(g) `docs/STATUS.md`.** A phase row.
- **(h) `examples/blueprints/`.** `claude-code.toml`, `claude-code-api-key.toml`, `codex.toml`,
  `codex-api-key.toml` and `opencode.toml` each gain a commented `[tags]` block with `expect` for
  their model API, as in §3.3.

## 8. Decisions (recorded per constitution Precedence & Conflicts)

- **Exact values, not shapes.** An email regex fires on every address in the source code sent to a
  model API. An exact value fires only when that value leaves.
- **Derive personal tags at spawn, not in the session.** The Launcher already runs outside the
  session with the operator's view of the host; reading the well-known places there tags the
  operator's identity without configuration and gives the session nothing.
- **A closed set of classes.** Three classes are enough to say which rule applies (credential: always
  block; personal and confidential: the operator's choice) and to label records; more would be
  taxonomy without a different behavior.
- **`audit` by default for personal and confidential.** A value is often expected somewhere the
  operator has not listed yet; blocking on first use would turn the feature into a breakage that
  gets turned off (constitution Growth). `learn` closes the gap in one run.
- **`block`, fixed, for credentials.** No working flow sends a value the session cannot hold.
- **No tag for a credential location** ([FW-INV9](../formwork.md#fw-inv9), §3.2).
- **An aggregate, not a log.** Per-request grant records stay at `debug`; repeated disclosures are
  counted, not printed.
- **The record names the header, not its value.** FW-FID13's exclusion is unchanged.
- **`Partial`, never `Enforced`.**

## 9. Open questions

| Question | Owner | Closes at |
|---|---|---|
| Does the first-byte index hold `FW-E2E-096` with body search at **tag-limit**, or is `aho-corasick` needed? | implementer of phase B | phase B review |
| Should matching fold ASCII case for `identity:git-email`? | reviewer | adoption |
| Are these the right well-known places? Candidates left out: the comment of `~/.ssh/*.pub` (often an email), `$EMAIL`, `npm`'s `init-author-email`. | reviewer | adoption |
| Should `personal` default to `block` instead of `audit`, on GDPR Art. 25's "by default"? | reviewer | adoption |
| Should `learn` also look for email-*shaped* strings in request heads, to find personal data no well-known place names? A shape match has no tag name to report by, so the proposal would have to describe the value without printing it. | reviewer | phase D |
| A per-host upload budget (block above N bytes up) follows from the account; it is a new field and is left out. | — | a later FEP |
| `gzip` request bodies could be decoded for search at a memory cost; left **unscanned**. | — | after phase B measurements |
