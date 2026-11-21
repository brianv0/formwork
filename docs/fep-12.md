# FEP-12 (proposal): tagged data at the egress door — tag regulated values, then audit or block them

**Formwork Enhancement Proposal 12 — proposal, not landed.** Companion to `formwork.md`
(design + end-to-end spec), `constitution.md` (doctrine), `docs/fep-5.md` (inspection and
brokering) and `docs/fep-6.md` (the egress engine).

**Status.** Nothing in this document mutates the landed spec or the constitution. The §7
amendments are apply-on-landing blocks. New identifiers are draft numbering, written as inline code
so the requirements canary skips them, until they are anchored on landing; each links to its
definition below. This FEP holds the reserved blocks
[`FW-EGR31`..`FW-EGR35`](#draft-fw-egr31), [`FW-FID27`..`FW-FID30`](#draft-fw-fid27),
[`FW-BP26`](#draft-fw-bp26), [`FW-INV22`](#draft-fw-inv22),
[`FW-E2E-169`..`FW-E2E-177`](#draft-fw-e2e-169) and
[`FW-ADV-046`..`FW-ADV-047`](#draft-fw-adv-046). They start above the blocks the open drafts hold
(FEP-7 to `FW-E2E-116`, FEP-8 to `FW-E2E-132`, FEP-9 to `FW-E2E-144` and `FW-FID24`, FEP-10 to
`FW-E2E-156` and `FW-EGR30`, FEP-11 to `FW-E2E-168`, `FW-FID26` and `FW-INV21`) and above the
highest landed numbers. Phase A (§6) is implemented in a pull request on the earlier vocabulary
(`marker`, `observe`, `refuse`), which takes this document's names on adoption.

**What this is.** Both observability and enforcement. A tagged value has an action: `audit`
records where it went, and `block` stops the request. A blocked request is refused, but the claim
stays `Partial` (§3.7): the search finds a value sent as written or in a common encoding, not one a
session sets out to hide. This is not data-loss prevention and not a compliance claim.

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
  could have guessed (§3.1).
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
  account in §3.6 exists. Formwork is a control and an audit trail; it does not make an operator
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
blueprint, the compiled policy, the report and every record.

The classes are a closed set.

| Class | Values | Declared by | Default action |
|---|---|---|---|
| `credential` | each variable the Launcher strips under [FW-CRED4](../formwork.md#fw-cred4), and each brokered secret ([FW-CRED11](../formwork.md#fw-cred11)) | nobody; derived at spawn | `block`, fixed |
| `personal` | personal data: the `identity:` sources, or any `env:`/`file:` source the operator puts here | the blueprint | `audit` |
| `confidential` | anything else the operator wants kept in: a project codename, an internal hostname | the blueprint | `audit` |

A `credential` value that names a **location** is not tagged: it starts with `/` or `~/`, or its
variable is a catalog file reference (`KUBECONFIG`, `GOOGLE_APPLICATION_CREDENTIALS`, ...). A path
is guessable, so blocking it would tell the session it guessed right ([FW-INV9](../formwork.md#fw-inv9)).
It is also a location the floor already denies ([FW-CRED3](../formwork.md#fw-cred3)), not a secret.

A declared tag names where its value is read from, never the value:

```toml
[net.tags]
personal     = ["identity:git-email", "identity:git-name", "identity:home except api.anthropic.com"]
confidential = ["env:PROJECT_CODENAME"]

[net.tags.action]
personal = "block"   # default "audit"
```

- `identity:` takes exactly one of `home`, `hostname`, `login`, `git-email` (`user.email`) and
  `git-name` (`user.name`).
- `except` takes host patterns in the host-rule grammar ([FW-BP16](../formwork.md#fw-bp16)), for a
  host where the value is expected: a model API that receives working-directory paths in every
  prompt.
- A source that yields no value is a load error naming the source
  ([FW-INV6](../formwork.md#fw-inv6)).
- A value shorter than **tag-min** (8 bytes) is refused, because a short value matches unrelated
  content.
- More than **tag-limit** (32) declared tags is refused; this bounds the search cost.

### 3.2 Encodings searched

For each value the Gateway searches exactly these **tag-encodings**:
- raw;
- percent-encoded with upper- and lower-case hex;
- hex in lower and upper case;
- JSON string-escaped;
- base64 in the standard and URL-safe alphabets at each of the three byte alignments, trimmed to
  the characters the alignment fixes.

The set is closed and part of the requirement, so the report's reason can name it and a test can
enumerate it. Matching is exact; whether `git-email` should fold ASCII case is open (§9).

### 3.3 Where the search runs

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
is released, and the request ends.

**Cost.** The matcher indexes patterns by first byte (std only). Phase A measured about 9 µs on a
350-byte head with 32 values. Whether body search at **tag-limit** needs `aho-corasick` (in
`Cargo.lock`, not compiled) is measured in phase B (§9).

### 3.4 The audit record

Each request in which the search finds a tagged value emits one **disclosure** record per tag and
location:

| Field | Value |
|---|---|
| `tag`, `class` | the tag's name (`env:PROJECT_CODENAME`, `identity:git-email`, `stripped:GITHUB_TOKEN`) and class |
| `host`, `port`, `grade` | as in the grant record |
| `method`, `path` | canonical path, no query string |
| `location` | `target`, `header:<lower-case name>` or `body` |
| `encoding` | one name from §3.2 |
| `count`, `action`, `timestamp` | occurrences; `audited` or `blocked`; milliseconds |

It is emitted at `warn` on the operator channel:

```
formwork: disclosure audited: personal identity:git-email in header:user-agent (raw) to crates.io:443 GET /api/v1/crates
```

### 3.5 Blocking

In the head, a blocked request is not forwarded and the session receives the generic refusal. In
the body, the stream ends at the match and the upstream connection is closed, not pooled. Both
emit a violation record with the new reason `tagged` in the closed set of
[FW-FID12](../formwork.md#fw-fid12).

`credential` values are always blocked. The session holds neither kind by construction
([FW-CRED16](../formwork.md#fw-cred16)), so one in a request means the floor was crossed by a route
Formwork did not close, and no working flow depends on sending it. A credential the blueprint
lifts with `allow-credentials` is not stripped and is not tagged.

### 3.6 The account at session end

When a `run` ends, the Launcher writes one **egress account** on the operator channel at `info`,
one line per host the Gateway forwarded a request or tunnel to:

```
formwork: egress account
  api.anthropic.com:443  inspected  214 requests  up 3.1 MiB  down 9.8 MiB  disclosures 0  unscanned 0
  crates.io:443          inspected   12 requests  up 4.2 KiB  down 1.1 MiB  disclosures 12 unscanned 0
      headers: accept, accept-encoding, host, user-agent
  github.com:443         tunnel       3 tunnels   up 48 KiB   down 2.0 MiB  disclosures -  unscanned 48 KiB
```

This is the record of what left (GDPR Art. 30's question, per session), and it shows an unexpected
upload (40 MiB up to a documentation host) without any tag. It aggregates counters the engine
already keeps; header names only, the first **header-names-kept** (64) per host.

### 3.7 The report row

`compile` gains the capability `net-disclosure`, present when the blueprint declares a tag or
strips or brokers a credential.

| Condition | Verdict | Reason names |
|---|---|---|
| every host rule is inspected or plain | `Partial` | the closed encoding set; coded bodies and upgraded streams are unscanned |
| at least one `tunnel:` rule | `Partial` | the same, and the tunnelled hosts |
| tags declared and no Gateway carries egress (`net = "allow"`, a port tier, `--confine-self`) | `Unenforceable` | no door to search at |

### 3.8 What remains open

- Tunnelled hosts are unsearched; the account counts their bytes.
- An MCP backend with its own network grant is a second door; phase C searches what the agent
  sends it, and the backend's own Confiner governs the rest.
- A value the session transforms (encrypts, splits, re-encodes) passes, and
  [`FW-ADV-047`](#draft-fw-adv-047) asserts it.

## 4. Surface changes (each measured against Growth)

| Change | Existing concept searched first | Why it does not fit |
|---|---|---|
| Blueprint: `[net.tags]`, `[net.tags.action]` | `allow-credentials` and the Catalog name credential *locations* | a tag names a value to recognise, which the session may hold |
| Vocabulary: **tag**, **class**, **disclosure**, **unscanned** | **placeholder**, **reflection** | neither names an operator-classified value in the request direction |
| Violation reason `tagged` | `placeholder`, `reflection` | the value is neither |
| Capability `net-disclosure` | `net-inspection` (whether TLS is terminated) | whether content is searched is a separate claim |
| Operator lines: disclosure, egress account | FW-FID9 refusal lines | an audit is not a refusal |
| Dependencies | — | none |

## 5. Proposed requirements (draft numbering — anchored on landing)

| ID | Statement |
|---|---|
| <a id="draft-fw-bp26"></a>`FW-BP26` Tag declarations | The CLI shall accept `[net.tags]` entries under exactly the classes `personal` and `confidential`, each with a source of exactly `env:`, `file:` or `identity:` (`home`, `hostname`, `login`, `git-email`, `git-name`) and optional `except` host patterns, and an action of `audit` or `block` per class; and shall refuse at load a source that yields no value, a value shorter than **tag-min** bytes, and more than **tag-limit** declared tags. |
| <a id="draft-fw-egr31"></a>`FW-EGR31` Head search | Before forwarding the head of an inspected or plain-HTTP request, the Gateway shall search the CONNECT request line, the method, the target as sent and percent-decoded, every header name and value, and the canonical path for each **tag-encoding** (exactly the set in FEP-12 §3.2) of each tagged value not excepted for the request's host. |
| <a id="draft-fw-egr32"></a>`FW-EGR32` Body search | The Gateway shall search the body of every inspected or plain-HTTP request with identity content coding for the same encodings as it streams, holding at most **body-buffer** bytes. |
| <a id="draft-fw-egr33"></a>`FW-EGR33` Credential tags | The Launcher shall tag as `credential` the value of every environment variable it strips under FW-CRED4, unless the value names a location, and the secret of every brokered credential, where the value is at least **tag-min** bytes. |
| <a id="draft-fw-egr34"></a>`FW-EGR34` Blocking | For a tagged value whose action is `block`, the Gateway shall not forward a request head in which the search finds it, and shall end a request body without releasing any byte that begins an occurrence of it. |
| <a id="draft-fw-egr35"></a>`FW-EGR35` MCP frames | The Gateway shall search the `params` of every `tools/call` request it forwards to a backend for the same encodings, and shall refuse the call where a matched tag's action is `block`. |
| <a id="draft-fw-fid27"></a>`FW-FID27` Disclosure record | For each request in which the search finds a tagged value, the Gateway shall emit exactly one record per tag and location carrying the tag's name and class, host, port, grade, method, canonical path, location, encoding name, count, action and timestamp. |
| <a id="draft-fw-fid28"></a>`FW-FID28` Unscanned bytes | The Gateway shall count per host the request bytes it forwards without searching (a tunnel, a body with a content coding other than identity, a stream after an upgrade). |
| <a id="draft-fw-fid29"></a>`FW-FID29` Egress account | At the end of a `run` that carried egress through the Gateway, the Launcher shall write on the operator channel, for each host the Gateway forwarded a request head or a tunnel to, the request count, bytes up, bytes down, grades, disclosure count, unscanned byte count and at most **header-names-kept** distinct request header names. |
| <a id="draft-fw-fid30"></a>`FW-FID30` Disclosure verdict | The compiler shall report `net-disclosure` as `Partial`, naming the encoding set and every `tunnel:` rule, where a Gateway carries the session's egress, and as `Unenforceable` where tags are declared and no Gateway does. |
| <a id="draft-fw-inv22"></a>`FW-INV22` Tagged values stay in the Gateway | No record, report, log line at any level, error message or response to the session shall contain a tagged value or a tag-encoding of it. |

**Parameters**, defined once: **tag-min** = 8 bytes; **tag-limit** = 32;
**header-names-kept** = 64; **body-buffer** as landed.

## 6. Verification plan

Fixtures are the loopback HTTPS upstreams of `crates/formwork-gateway/tests/support`, which record
every request they receive. Each test asserts on records and on what the upstream saw.

| ID | Test |
|---|---|
| <a id="draft-fw-e2e-169"></a>`FW-E2E-169` | The §1 incident: a `personal` value in `User-Agent` to a granted inspected host. One disclosure record names `header:user-agent`; the upstream received the request (`audit`). |
| `FW-E2E-170` | A tagged value in a request body split across two writes at every offset. One record, `location = body`; the upstream received every byte in order. |
| `FW-E2E-171` | Each tag-encoding in turn, in the target and the body, produces a record naming it. Table-driven over the closed set. |
| `FW-E2E-172` | A stripped credential's value in a head is blocked: the upstream receives nothing; a violation carries `tagged`. A stripped path is admitted. |
| `FW-E2E-173` | The same value in a body under `block`: the upstream receives no byte that begins it and the connection is not reused. |
| `FW-E2E-174` | A `tunnel:` host, a `gzip` body and a WebSocket upgrade each add to **unscanned** and produce no disclosure record. |
| `FW-E2E-175` | The account after a three-host run lists each host with its counts and header names, and nothing for a refused host. |
| `FW-E2E-176` | `compile` with a tag and `net = "allow"` reports `net-disclosure` `Unenforceable`; a `tunnel:` rule is named in the reason; a four-byte `identity:login` fails at load naming **tag-min**. |
| `FW-E2E-177` | [FW-E2E-096](../formwork.md#fw-e2e-096) and [FW-E2E-092](../formwork.md#fw-e2e-092) with **tag-limit** tags: the latency budget and the 16 MiB memory bound hold. |
| <a id="draft-fw-adv-046"></a>`FW-ADV-046` | `FW-INV22`: under `RUST_LOG=trace`, run 169..173 and search stdout, stderr, the operator channel, every record and the `explain`/`compile` JSON for every encoding of every tagged value. No occurrence. |
| <a id="draft-fw-adv-047"></a>`FW-ADV-047` | The stated limit: a value sent ROT13-coded, or split across two requests, is admitted with no record; the `Partial` reason names the encoding set. |

**Phasing.**

- **A — credential tags, head blocking, the account.** `FW-EGR33`, `FW-EGR34` (head), `FW-FID28`,
  `FW-FID29`; tests 172, 174, 175. No blueprint change. Implemented (see Status).
- **B — declared tags and the body.** `FW-BP26`, `FW-EGR31`, `FW-EGR32`, `FW-FID27`, `FW-FID30`,
  `FW-INV22`; the remaining tests.
- **C — the MCP door.** `FW-EGR35`.

## 7. Amendments to the landed docs (apply on landing)

- **(a) `formwork.md` §5.** The rows of §5, anchored; `tagged` in the [FW-FID12](../formwork.md#fw-fid12) reason set.
- **(b) `formwork.md` §7 and §10.** The tests of §6 and their traceability rows.
- **(c) `formwork.md` §9.** The `net-disclosure` row of §3.7.
- **(d) `constitution.md` Vocabulary.**
  - **tag**: a named value the Gateway searches outbound requests for, held like a brokered secret;
  - **class**: `credential`, `personal` or `confidential`;
  - **disclosure**: a tagged value found in a request the session sent;
  - **unscanned**: request bytes forwarded without searching.
- **(e) `constitution.md` Concepts, Blueprint.** Add "egress tags (`FW-BP26`)".
- **(f) `README.md`.** One paragraph: tags, classes, the account, and "this finds a value sent as
  written or in a common encoding; it does not stop a session that sets out to hide one".
- **(g) `docs/STATUS.md`.** A phase row.

## 8. Decisions (recorded per constitution Precedence & Conflicts)

- **Exact values, not shapes.** An email regex fires on every address in the source code sent to a
  model API. An exact value fires only when that value leaves.
- **A closed set of classes.** Three classes are enough to say which rule applies (credential: always
  block; personal and confidential: the operator's choice) and to label records; more would be
  taxonomy without a different behavior.
- **`audit` by default for declared tags.** A declared value is often expected somewhere the
  operator has not listed yet; blocking on first use would turn the feature into a breakage that
  gets turned off (constitution Growth).
- **`block`, fixed, for credentials.** No working flow sends a value the session cannot hold.
- **No tag for a credential location** ([FW-INV9](../formwork.md#fw-inv9), §3.1).
- **An aggregate, not a log.** Per-request grant records stay at `debug`.
- **The record names the header, not its value.** FW-FID13's exclusion is unchanged.
- **`Partial`, never `Enforced`.**

## 9. Open questions

| Question | Owner | Closes at |
|---|---|---|
| Does the first-byte index hold `FW-E2E-096` with body search at **tag-limit**, or is `aho-corasick` needed? | implementer of phase B | phase B review |
| Should matching fold ASCII case for `identity:git-email`? | reviewer | adoption |
| Should `identity:` exist, or should every declared tag come from `env:` and `file:`? It adds five sources the Launcher reads (`git config` among them). | reviewer | adoption |
| Should `personal` default to `block` instead of `audit`, on GDPR Art. 25's "by default"? | reviewer | adoption |
| `grade` (`tunnel` or `inspected`) is how much of the connection the Gateway sees, not an authorization; a rename in the landed spec (e.g. **visibility**) is a separate change. | reviewer | before phase B |
| A per-host upload budget (block above N bytes up) follows from the account; it is a new field and is left out. | — | a later FEP |
| `gzip` request bodies could be decoded for search at a memory cost; left **unscanned**. | — | after phase B measurements |
