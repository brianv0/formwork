# FEP-17 (proposal): remediation of a second security audit — the MCP door, inbound sockets, the denial feed, and report rows that follow the kernel

**Formwork Enhancement Proposal 17 — proposal, not landed.** This draft is the FEP form of a second
security audit of `main` at `e6e4572` (working title FSE). It describes fail-opens that are not
yet fixed. Companion to `formwork.md`, `constitution.md`, and draft FEP-13 to FEP-16.

**Status.** Nothing here mutates the landed spec. New identifiers are draft numbering in inline
code. This FEP holds `FW-GW15`..`FW-GW17`, `FW-ISO33`..`FW-ISO37`, `FW-EGR36`..`FW-EGR38`,
`FW-CRED36`..`FW-CRED37`, `FW-DISC17`..`FW-DISC19`, `FW-FID33`..`FW-FID35`, `FW-BP32`,
`FW-E2E-203`..`FW-E2E-220` and `FW-ADV-056`..`FW-ADV-058`, above FEP-16's blocks and above
FEP-8's `FW-GW14`. `FSE-n` and `FSE-E2E-n` are the audit's working labels; they are outside the
constitution's closed identifier families and do not survive into the spec. §5 maps each to the
identifiers here.

**What changed in translation.** The audit's findings were checked against `main` at `e6e4572`
by reading the cited code. Ten of its proposed fixes
are changed here: eight because they were unsound or incomplete (FSE-03, 04, 05, 07, 10, 11,
12, 17) and two for a stronger form (FSE-01, 19). One finding's Linux half is dropped because
the kernel's access rules contradict it (FSE-09), and one is recorded as a decision on a landed
requirement instead of a defect (FSE-05). Each difference is stated where it occurs.

**Independent check.** A second review session applied the audit's patch to `e6e4572` and ran
it: all 22 `fse*` tests pass; `cargo fmt --check` reports 14 diffs and `clippy -D warnings` one
error; a kernel probe confirmed that Landlock refuses `execve` of a file without the read right.

**Maintainer decisions, 2026-11-17.** Five questions the first draft left open are decided and
applied below: inet listening is refused under host rules (§2.2); the macOS loopback listen
becomes opt-in (§2.5); Mach lookups become default-deny with a shipped service profile (§2.5);
`.npmrc` is not floored and operators deny it themselves (§2.6); `extends` bases are checked
and warned about, not refused (§2.6). §8 records each.

---

## 1. Problem

The audit found 19 places where a component decides on one view of an input and another
component acts on a different one, or where the report claims a wall the host does not build.
They group into five.

1. **The MCP door decides by request id, and forwards bytes it did not decide on.** List
   responses are matched to requests through a map keyed by the JSON-RPC id and consumed on
   first use (`crates/formwork-gateway/src/lib.rs:438`, `:505-509`). A reused id, a second list
   kind under the same id, or an id the backend echoes in another spelling (`1.0` and `1`)
   leaves a response with no entry, and a response with no entry is forwarded unfiltered. The
   agent then sees names [FW-CAP4](../formwork.md#fw-cap4) says are absent. Separately, a frame
   is routed on a `serde_json::Value`, where a repeated key resolves to its last occurrence,
   and forwarded as the original bytes, where a first-wins backend reads the other one
   (`lib.rs:139-158`).
2. **Linux mediates connecting out, and nothing mediates listening.** Under host rules, the
   strictest posture, stream sockets exist for the supervisor to gate. The notify filter covers
   `connect` and addressed `sendto`; no rule covers `bind`, `listen` or `accept`, and no
   Landlock net right is handled in this plan (`crates/formwork-compile/src/linux.rs:130-134`,
   `crates/formwork-confine/src/linux/landlock.rs:199`). The report says
   `net-default-deny: enforced`. The baseline filter also has no bound on the syscall number, so
   on an x86_64 kernel built with the x32 ABI every baseline deny can be reached under its x32
   number (`crates/formwork-confine/src/linux/seccomp.rs:88-94`); the notify filter refuses
   that range and the baseline does not. `AF_SMC`, a stream family that falls back to TCP, is
   one more family the deny-list omits (FEP-14 §1).
3. **`learn` trusts files the session can write, and a loader that checks some keys.** The
   denial feed is a file in the shared temp root that the workload can append to
   (`crates/formwork-cli/src/main.rs:2019`, `:2073-2077`); the parser accepts any line of the
   right shape. A discovered layer may carry an `auto-widen` zone with no provenance
   (`crates/formwork-cli/src/blueprint_load.rs:684-757`). `accept` writes where the proposal
   file says and prints a count.
4. **The Gateway checks one header and forwards several.** The Host check reads the first
   `Host` field and every copy is forwarded
   (`crates/formwork-gateway/src/inspect.rs:434-444`, `http.rs:48-53`). Three smaller gaps sit
   beside it: the operator's proxy credential has no reflection guard, an unauthenticated
   attempt leaves no record, and the placeholder scan reads the target before decoding.
5. **Report rows that do not follow the host.** `tamper-vectors` is `enforced` wherever Landlock
   exists, though the truncate right arrives at ABI 3
   (`crates/formwork-compile/src/lib.rs:618-631`). On macOS an exec allow-list renders no
   `process-exec*` deny for a subtracted path (`crates/formwork-compile/src/sbpl.rs:481-489`),
   and the Mach baseline is a deny-list of the services that were characterized
   (`sbpl.rs:195-220`); the report names neither.

### 1.1 Constraints

- **Reuse.** A session binds UNIX sockets and runs loopback servers. A fix that refuses every
  `bind` is not acceptable (constitution Growth, the reuse thesis; FEP-6 S10).
- **seccomp reads scalars.** It sees a descriptor and a pointer at `bind`, never the address or
  the socket's family.
- **Characterize before anchoring** (constitution Vocabulary). No macOS requirement here is
  anchored until a CI test records what Seatbelt does.
- **No secret and no vulnerable-behaviour test lands before its fix.** The audit's `fse*` tests
  assert the defect; each becomes a regression test in the commit that fixes it (§6).

## 2. Design

### 2.1 The MCP door (audit FSE-01, FSE-19)

**Filter by what a response is.** The Gateway filters every backend response whose `result`
has a list shape — a top-level `tools`, `resources`, `resourceTemplates` or `prompts` array —
with the policy for that shape, whether or not a request is pending under its id. The pending
map is no longer what makes filtering happen, so reuse, cross-kind reuse and id respelling stop
mattering, and a list response nobody asked for is filtered too. A non-list response that
happens to carry such an array at the top of `result` is filtered as well; that fails closed.

*Changed from the audit*, which keeps id-keyed filtering and adds id checks.

**Id discipline, as a second layer.** The Gateway refuses an agent request whose id equals the
id of a request it has forwarded and not yet seen answered, comparing numeric ids by value, and
refuses an id with a fractional part.

**Typed frames.** The envelope (`jsonrpc`, `id`, `method`, `params`) and the parameters the
Gateway decides on (`name`, `uri`, the completion reference) are parsed into typed structures.
A `serde`-derived structure rejects a repeated field, so a frame with a duplicate key on a
decided path is refused before routing. This is also what the constitution's Boundaries section
already requires: MCP frames are "never leaked inward as `serde_json::Value`".

*Changed from the audit*, which proposes a pre-parse byte scan.

### 2.2 Linux: listening, and the syscall-number bound (audit FSE-02, FSE-04, FSE-08)

**Bound the number.** On x86_64 every posture refuses a syscall whose number has the x32 bit
set. `seccompiler` rules are keyed by number and cannot express a range, so this is a second,
four-instruction filter installed beside the baseline; stacked filters return the most
restrictive result. The condition is a kernel built with `CONFIG_X86_X32_ABI`; the fix is
unconditional.

**Refuse inet listening where connecting is mediated.** Under supervised connect a session does
not listen on an inet socket at all, loopback included. The notify filter also notifies on
`listen`; the supervisor reads the socket's domain from its own copy of the descriptor
(`SO_DOMAIN`) and answers:

| Socket | Supervisor's answer to `listen` |
|---|---|
| `AF_UNIX` | continue (the filesystem rules govern the path) |
| `AF_INET`, `AF_INET6` | `EACCES` |

A TCP socket accepts nothing until it listens, so `bind` and `accept` need no rule. Two simpler
mechanisms were considered and do not work alone:

- **seccomp refusing `listen` outright** also refuses every UNIX-socket listener, because
  seccomp sees a descriptor and not its family.
- **Landlock `BindTcp` handled with no rule** refuses `bind`, but an unbound TCP socket binds
  itself to the wildcard address when it starts listening, and that path does not go through
  the bind check Landlock hooks. This is to be characterized (§9); the `listen` notification
  does not depend on the answer.

*Changed from the audit*, which has seccomp refuse `bind`, `listen` and `accept` outright.

**Cost, accepted.** A dev server or test server inside a session cannot listen on TCP under
host rules. FEP-6 scenario S10 and [FW-E2E-106](../formwork.md#fw-e2e-106) stay unbuilt, and a
login flow that waits for a loopback callback does not work on Linux under host rules (§3).
UNIX-socket servers are unaffected.

Until this lands, `net-default-deny` under host rules on Linux is `Partial` with the reason
"inbound connections are not mediated" (`FW-FID33`).

**Families and protocols.** `AF_SMC` is closed by FEP-14's family allow-list (`FW-ISO28`); it is
added to that FEP's probe list. This FEP adds the protocol argument: an inet stream socket is
admitted only with protocol `0` or `IPPROTO_TCP`. Landlock's port rules are TCP rules, and
whether they govern `IPPROTO_MPTCP` or `IPPROTO_SCTP` stream sockets on current kernels is not
established (§9); the allow-list makes the answer irrelevant.

### 2.3 The `learn` trust chain (audit FSE-03, FSE-06, FSE-07)

**The feed is not a file.** `learn` gives strace a descriptor it holds (`-o /dev/fd/N`, a pipe)
and reads the feed from it. No path exists for the workload to open. `learn` already passes its
report descriptor to the shim this way.

*Changed from the audit*, which moves the file into a 0700 directory. The workload has the same
uid; mode bits do not stop it.

The parser takes the open flags from the flags argument by position (the substring test that
grades a file named `O_WRONLY-notes.txt` as a write is a parser defect; it is fixed with public
issue #51). Filtering records to traced pids is hygiene and is not relied on.

**The discovered layer has a closed key set.** The loader refuses a discovered layer that
contains any key other than `fs.reads`, `fs.writes`, host `rules`, channel lifts and
`discovery.provenance`. `auto-widen` is authoring and is refused with the rest. This is the fix
for a defect the first review found (a discovered layer also loads `allow-credentials`, `net`,
`env`, `mode` and `fs.writes-no-create` with no provenance); the audit's FSE-06 is one more key
it removes.

**`accept` names what it does.** The destination is the discovered layer of the blueprint the
invocation resolved (public issue #54), and `accept` prints every entry it accepts.

*Declined from the audit:* comparing the proposal's hash with the one `--list` saw. The writer
it defends against is an unconfined process of the same user, which can edit the blueprint; the
session cannot write the proposal ([FW-XR8](../formwork.md#fw-xr8)).

### 2.4 Gateway requests and records (audit FSE-13, FSE-14, FSE-16, FSE-17, FSE-18)

- **Forwarded framing is the decided framing.** The first review found that `end_to_end`
  (`crates/formwork-gateway/src/http.rs:91-101`) drops every header the request's `Connection`
  header names, `Content-Length` and `Transfer-Encoding` included, after the body framing was
  computed from the original head (`inspect.rs:425-431`, `:506-509`, `:597`). The upstream then
  receives a head with no framing and the body bytes behind it, and reads them as a second
  request that no rule decided and no record shows. With `post:api.test/allowed` as the only
  rule, a second request with another method, path and `Host` reached the fixture upstream. The
  fix is the one a codec-based proxy has by construction: the Gateway writes the upstream
  `Content-Length` or `Transfer-Encoding: chunked` from the framing it decided, never from the
  client's header list, on requests and on responses.
- **Singleton fields.** A request with more than one `Host` field is refused with `malformed`
  (RFC 9112 §3.2), in both grades. The same holds for every field the Gateway decides on:
  `Content-Length`, `Transfer-Encoding` and each brokered header name. Both changes close "the
  upstream reads a request the Gateway did not decide".
- **Registry lifetime.** The supervisor registers a source port after its connect succeeds and
  removes it when the connection ends or the connect fails.
- **Proxy credential.** On the plain-through-proxy path the reflection guard also covers the
  operator's `Proxy-Authorization` value. The cost is identity coding on that path.
- **Listener refusals.** Attempts refused before a request is read (no credential, wrong
  credential, unregistered peer) are counted per reason and reported as one record per reason
  with its count. One record per attempt would let a flood evict real records from the
  1,024-entry queue. *Changed from the audit.*
- **Decoded scan.** The placeholder scan also searches the percent-decoded target. FEP-12's
  marker search uses the same routine.

### 2.5 Report rows and macOS (audit FSE-05, FSE-09, FSE-10, FSE-15)

- **ABI-gated write rows.** Below Landlock ABI 3 (Linux before 6.2, which includes 5.15 and
  6.1), `tamper-vectors` and `fs-write` are `Partial` and the reason names truncation.
- **Exec allow-lists respect denies on macOS.** For each subtract and floor row the profile
  carries a `process-exec*` deny, rendered after the exec allows (Seatbelt is last-match-wins).
  On Linux the hole set is passed to the exec expansion for consistency. *The audit's Linux
  claim is dropped:* an exec open is a read open, Landlock requires the read right as well as
  the execute right for it, and a subtract hole removes read; PR #38 reports the same on 6.18.
- **Mach lookups are default-deny, with a shipped service profile.** The macOS profile denies
  `mach-lookup` and allows the services a **service profile** names. The profile is data, like
  the credential catalog: `profiles/macos-services.toml`, versioned, embedded at build time, a
  closed list of global names in named groups (for example `core`, `tls`, `dns`, `logging`).
  `core` is always allowed; the existing channel lifts
  ([FW-ISO13](../formwork.md#fw-iso13)) and `os-keyring` map onto their groups as today.
  - **The profile must make ordinary work run.** It is built by measurement, not by guess: a CI
    run on `macos-14` and `macos-15` executes the agent examples
    ([FW-E2E-084](../formwork.md#fw-e2e-084)) and the toolchain set (git, curl, Python, Node, a
    C build, `cargo`) with lookups allowed and reported, and the names observed are the first
    `core`. The default flips to deny in the same change that lands a profile under which those
    runs pass.
  - **A session that needs more says so.** `learn` records a denied lookup as a channel
    candidate naming the service ([FW-DISC12](../formwork.md#fw-disc12)); the operator accepts
    it into the discovered layer like any other lift.
  - **A service that acts for the caller stays a named risk.** Where an allowed service performs
    a write the file rules deny (the audit's `cfprefsd` case, if characterization confirms it and
    reads cannot work without the service), the report says `Partial` and names the service.
  - **Two constraints already on record.** CoreFoundation reads preferences through `cfprefsd`,
    so that service is expected to land in `core`; and POSIX shared memory cannot be denied or
    prefixed without breaking Python's `multiprocessing` (characterization C7), so this FEP
    leaves `ipc-posix-shm*` alone.
  *Changed from the audit* only in order: the allow set is measured before the default flips.
- **The macOS loopback listen becomes opt-in.**
  [FW-EGR15](../formwork.md#fw-egr15) requires the allow under every posture, and the report
  already says `Partial` with the reason (`lib.rs:405-421`). Seatbelt's local filter accepts
  only `*` or `localhost`, so the literal-loopback fix the audit proposes cannot be written.
  FW-EGR15 is amended (§7 c): the two allow rows are emitted only when the blueprint requests a
  loopback callback. A session that does not request one cannot listen, and its
  `net-default-deny` row is `Enforced`; one that does keeps today's `Partial` row.

### 2.6 Loader and catalog (audit FSE-11, FSE-12)

- **Bases are checked, and the operator is told.** For every `extends` base that is a file not
  owned by the invoking user or root, or that is group- or world-writable (the test
  [FW-BP8](../formwork.md#fw-bp8) applies to the discovery walk), the CLI writes one operator
  line naming the file, and loads it. Each base is named in the provenance stamp. Files outside
  the sandbox are the operator's to protect; Formwork reports what it sees and does not refuse.
  *Changed from the audit*, which refuses absolute and out-of-root bases.
- **Catalog entries** go to FEP-16's version bump: `.env.<env>.local` for the listed
  environments, `id_dsa`, `id_ecdsa_sk`, `id_ed25519_sk`, any-depth `.git-credentials`.
- **`.npmrc` is not floored.** Projects commit one with no secret in it, and denying it by
  default breaks `npm install`. An operator who keeps a token there denies the file in the
  blueprint. `examples/README.md` gains the recipe, in the form that works on both platforms:
  `deny:$CWD/.npmrc`. The any-depth form (`deny:**/.npmrc`) is a Seatbelt regex and cannot be a
  Landlock rule, so it is a macOS-only spelling (public issue #57, FEP-13 §2.3).
- *Declined:* near-miss suffixes such as `credentials.bak`.

## 3. Asymmetries that remain

- **Loopback callbacks are macOS-only.** Linux refuses inet listening under every posture
  except `net = "allow"` (`net = "deny"` has no inet socket; the port tier refuses `bind`; host
  rules refuse `listen`). macOS permits it where the blueprint requests a callback. A login flow
  that waits for a browser redirect to `localhost` therefore works on macOS and not on Linux,
  and the report names it ([FW-XR6](../formwork.md#fw-xr6)).
- A first-wins MCP backend and a last-wins one now see the same frame, because the Gateway
  refuses the ambiguous one; a backend that reorders keys by some other rule is out of scope.
- The x32 bound is x86_64 only; aarch64 has no such range.

## 4. Surface changes (each measured against Growth)

| Change | Note |
|---|---|
| Violation record: one reason, `unauthenticated`, added to FW-FID12's closed set, and a `count` field | a Data-model change; versions with the record schema |
| Report: three reasons, no new capability | `net-default-deny` (Linux, inbound), `tamper-vectors`/`fs-write` (ABI), `privileged-interfaces` (Mach) |
| Notify filter: `listen` | supervised posture only |
| `profiles/macos-services.toml`, embedded | a second build-time data artifact beside the credential catalog (constitution Data model) |
| Operator line for an unowned or writable `extends` base | a warning; nothing is refused |
| A second seccomp filter (x32 bound) | x86_64 only |
| Discovered layer: keys outside the closed set are refused | a narrowing; no release has shipped the wider form |
| `accept` prints each accepted entry | prose, not contract |
| FW-EGR15 amendment: the loopback listen is requested, not ambient | how it is requested is open (§9) |

No blueprint field, flag, concept or dependency.

## 5. Proposed requirements (draft numbering), with the audit label each replaces

| ID | Audit | Statement |
|---|---|---|
| `FW-GW15` Shape-bound filtering | FSE-01 | The Gateway shall apply the server's list policy to every backend response whose `result` carries a top-level `tools`, `resources`, `resourceTemplates` or `prompts` array, whether or not a request is pending under the response's id. |
| `FW-GW16` Request ids | FSE-01 | The Gateway shall refuse an agent request whose id equals, by JSON value, the id of a forwarded request not yet answered, and a request whose numeric id has a fractional part. |
| `FW-GW17` Unambiguous frames | FSE-19 | The Gateway shall refuse a frame in which the envelope or a parameter object it decides on repeats a key. |
| `FW-ISO33` Syscall-number bound | FSE-02 | On x86_64, in every posture, the Confiner shall refuse every system call whose number has bit 30 set. |
| `FW-ISO34` No inet listening | FSE-04 | Under supervised connect, the Gateway shall receive every `listen` and shall refuse it for a socket whose domain is `AF_INET` or `AF_INET6`. |
| `FW-ISO35` Stream protocols | FSE-08 | For every net posture other than `allow`, the Confiner shall refuse creation of an inet stream socket whose protocol is neither `0` nor `IPPROTO_TCP`. |
| `FW-ISO37` Mach service allow-list | FSE-10 | The macOS profile shall deny `mach-lookup` for every global name outside the embedded service profile's `core` group and the groups the blueprint's channel and credential lifts name. |
| `FW-ISO36` Exec respects denies | FSE-09 | Under an exec allow-list, the Confiner shall refuse execution of a path that a subtract row or an unexposed floor row covers. |
| `FW-DISC17` Feed integrity | FSE-03 | `learn` shall read the denial feed only from a descriptor it created, with no filesystem path a confined process can open for writing. |
| `FW-DISC18` Discovered-layer keys | FSE-06 | The CLI shall refuse a discovered layer containing any key other than `fs.reads`, `fs.writes`, host `rules`, channel lifts and `discovery.provenance`. |
| `FW-DISC19` Accept names its effect | FSE-07 | `accept` shall write only to the discovered layer of the blueprint the invocation resolved, and shall print each entry it accepts. |
| `FW-EGR36` Singleton fields | FSE-13 | The Gateway shall refuse a request that carries more than one `Host`, `Content-Length` or `Transfer-Encoding` field, or more than one field bearing a brokered header name. |
| `FW-EGR38` Decided framing | — | For every request and response it forwards, the Gateway shall write the message framing (`Content-Length` or `Transfer-Encoding`) from the framing it decided, and shall forward no framing field received from the peer. |
| `FW-EGR37` Registry lifetime | FSE-14 | The supervisor shall hold a source port in the admission registry only while the connection it made from that port is open. |
| `FW-CRED36` Proxy credential guard | FSE-16 | For a request it forwards with the operator's proxy credential, the Gateway shall end the response without releasing any byte that begins an occurrence of that credential. |
| `FW-CRED37` Decoded placeholder scan | FSE-18 | The Gateway shall apply the placeholder scan to the request target both as received and percent-decoded. |
| `FW-FID33` Inbound is reported | FSE-04 | Where a Linux net posture leaves inbound connections unmediated, the compiler shall report `net-default-deny` as `Partial`, naming inbound connections. |
| `FW-FID34` ABI-gated write rows | FSE-15 | For a Linux host below Landlock ABI 3, the compiler shall report `tamper-vectors` and `fs-write` as `Partial`, naming truncation. |
| `FW-FID35` Listener refusals | FSE-17 | The Gateway shall record, per reason, the count of connection attempts it refused before reading a request. |
| `FW-BP32` Base ownership notice | FSE-12 | For each `extends` base file that is not owned by the invoking user or root, or that is group- or world-writable, the CLI shall write one operator line naming the file. |

FSE-05 and FSE-11 mint nothing here: the first is the FW-EGR15 amendment (§7 c), the second is
catalog data in FEP-16. The service profile's content is data and carries no identifier; its
version is reported beside the catalog's.

## 6. Verification plan

Each test asserts the fixed behaviour and lands in the commit that fixes it. The audit's `fse*`
unit tests are the starting point for each; they assert the defect today and are inverted.

| ID | Audit label | Test |
|---|---|---|
| `FW-E2E-203` | FSE-E2E-01 | Through `fw-mcp-fixture`, a backend whose lists hold a denied name: a repeated id, a second kind under one id, an id echoed in another spelling, and an unsolicited list response. The agent receives the denied name in none. |
| `FW-E2E-204` | FSE-E2E-19 | A `tools/call` whose `params` key repeats is refused and the backend receives no frame. |
| `FW-E2E-205` | FSE-E2E-02 | The compiled filter refuses an x32-range number for `socket`, `io_uring_setup` and the x32 numbers of `ptrace` and `process_vm_writev` (521, 540). On a CI kernel with the x32 ABI, a probe makes the call and gets `EPERM`; elsewhere the kernel arm reports not exercised. |
| `FW-E2E-206` | FSE-E2E-04 | Host rules: `listen` is refused on a wildcard-bound, a loopback-bound and an unbound inet socket, for both families; a UNIX-socket listener works; a peer outside the session cannot connect; the Gateway path still works. |
| `FW-E2E-207` | FSE-E2E-08 | `socket()` with `AF_SMC`, and with `IPPROTO_MPTCP` and `IPPROTO_SCTP` on `AF_INET`, is refused under `net = "deny"`, the port tier and host rules. |
| `FW-E2E-208` | FSE-E2E-09 | Exec allow-list over a tree with a subtracted static binary: `execve` of it is refused on both backends; a sibling runs. |
| `FW-E2E-209` | FSE-E2E-03 | `learn` under the default profile: the workload searches the temp root for a feed file and finds none; a line it writes to any path it can reach yields no candidate. |
| `FW-E2E-210` | FSE-E2E-06 | A discovered layer carrying `auto-widen`, and one for each other key outside the set, is refused naming the key. |
| `FW-E2E-211` | FSE-E2E-07 | `accept` on a proposal naming another project's blueprint is refused; a normal `accept` prints each accepted pattern. |
| `FW-E2E-212` | FSE-E2E-13 | A request with two `Host` fields, and one with two of each other singleton field, is refused with a violation record; the upstream receives nothing. A request whose `Connection` header names `content-length`, and one naming `transfer-encoding`, reaches the upstream as exactly one request with its framing intact; the same holds for a response. |
| `FW-E2E-213` | FSE-E2E-14 | After a failed supervised connect, and after a closed one, the registry does not hold the port. |
| `FW-E2E-214` | FSE-E2E-15 | `compile` for ABI 1 and ABI 2 hosts with a write-subtract row reports `Partial` naming truncation; for ABI 3, `Enforced`. |
| `FW-E2E-215` | FSE-E2E-16 | The plain-through-proxy fixture with a reflecting upstream: the response ends without the credential. |
| `FW-E2E-216` | FSE-E2E-17 | Three attempts without a credential yield one record with count 3. |
| `FW-E2E-217` | FSE-E2E-18 | The percent-encoded placeholder in a query is refused with `placeholder`. |
| `FW-E2E-218` | FSE-E2E-12 | A base owned by another user, and a world-writable base, each load and each produce one operator line naming the file; a root-owned `/etc` base and a user-owned absolute base load with no line. |
| `FW-E2E-219` | FSE-E2E-05 | macOS: with no callback requested, `bind` and `listen` on `127.0.0.1` and on `0.0.0.0` are refused and `net-default-deny` is `Enforced`; with the callback requested both are admitted and the row is `Partial`. |
| `FW-E2E-220` | FSE-E2E-10, -11 | macOS: under the shipped service profile the agent examples and the toolchain set run; a lookup of a name outside the profile is refused and `learn` proposes it; characterization C10–C13 record what each service the audit names does for a confined caller. With FEP-16's catalog, `explain` marks each adopted shape withheld, and a project `.npmrc` is readable until `deny:$CWD/.npmrc` is added. |
| `FW-ADV-056` | — | MCP id and shape table: every pairing of list kind, id spelling and response order; no denied name reaches the agent. |
| `FW-ADV-057` | — | With FEP-14's `FW-ADV-051` sweep: every syscall number in the x32 range is refused under every posture. |
| `FW-ADV-058` | — | A confined workload tries to influence its own `learn` result by every writable route (temp root, session temp, launch directory); the proposal holds only kernel-observed denials. |

**Phasing.**

- **A — filters and parsers:** `FW-ISO33`, `FW-ISO35`, `FW-EGR36`, `FW-EGR38`, `FW-GW15`..`FW-GW17`,
  `FW-DISC17`, `FW-DISC18`, `FW-FID33`, `FW-FID34`.
- **B — the supervisor:** `FW-ISO34`.
- **C — small:** `FW-EGR37`, `FW-CRED36`, `FW-CRED37`, `FW-FID35`, `FW-DISC19`, `FW-BP32`.
- **D — macOS, each after its measurement:** the service profile and `FW-ISO37` (the default
  flips when the measured profile passes); `FW-ISO36`; the FW-EGR15 amendment.

## 7. Amendments (apply on landing)

**(a) `formwork.md` §5.** The rows of §5, anchored. Add `unauthenticated` to the closed reason
set under [FW-FID12](../formwork.md#fw-fid12). `FW-ISO33` and `FW-ISO35` are folded into
FEP-14's block if that FEP is adopted first.

**(b) `formwork.md` §9.** Linux `net-default-deny` under host rules; `tamper-vectors` and
`fs-write` by ABI; macOS `privileged-interfaces`.

**(c) [FW-EGR15](../formwork.md#fw-egr15).** Replace "Under every net posture" with "Where the
blueprint requests a loopback callback", and name the request (§9).

[FW-E2E-091](../formwork.md#fw-e2e-091) asserts today that a confined listener accepts a
connection on the host's LAN address; it is rewritten to the two cases of `FW-E2E-219`.

**(c2) [FW-ISO8](../formwork.md#fw-iso8), [FW-ISO13](../formwork.md#fw-iso13).** The macOS
baseline becomes an allow-list of Mach services; the channel rows name groups of the service
profile. `constitution.md` Data model: add the service profile beside the credential catalog.

**(c3) `examples/README.md`.** The `.npmrc` recipe of §2.6.

**(d) `docs/linux-backend.md`.** Correct "nothing inside the sandbox resolves names under the port
tier"; state that exec roots
are expanded around holes; add `bind`/`listen` to the supervisor's description.

The audit also asks to remove the sentence that Landlock refuses ptrace-class access outside
the domain. That sentence is correct (Landlock has restricted ptrace across domains since ABI 1)
and stays; an earlier version of this draft repeated the audit's error.

**(e) `crates/formwork-confine/src/lib.rs` doc.** The "no unconfined-child path" sentence is
false for the filesystem on a host with seccomp and no Landlock; the report already says
`Unenforceable` there.

## 8. Decisions (recorded per constitution Precedence & Conflicts)

- **Filter by shape, not by id.** An id is chosen by the party being confined.
- **No inet listening under host rules** (maintainer, 2026-11-17). Chosen over admitting
  loopback listeners. In-session TCP servers and Linux loopback callbacks are given up for a
  rule with no address parsing. Implemented as a `listen` notification with a domain check,
  because neither seccomp alone nor Landlock's bind right closes it without collateral.
- **A pipe, not a protected file, for the denial feed.** A path is something to defend; a
  descriptor is not.
- **Mach lookups default-deny, with a shipped profile that keeps ordinary work running**
  (maintainer, 2026-11-17). The profile is measured in CI before the default flips; a deny-list
  of characterized services is replaced by an allow-list of measured ones.
- **The macOS loopback listen is opt-in** (maintainer, 2026-11-17). FW-EGR15 is amended.
- **`.npmrc` is the operator's to deny** (maintainer, 2026-11-17). The floor does not cover a
  file most projects commit without a secret.
- **Outside the sandbox is the operator's concern** (maintainer, 2026-11-17). An `extends` base
  the operator's blueprint names is loaded; Formwork warns when it is unowned or writable by
  others and refuses nothing. The same principle is why the audit's proposal-hash check is
  declined (§2.3).
- **Count listener refusals.** A record per attempt is a way to erase other records.
- **No test of a defect lands before its fix.**

## 9. Open questions

| Question | Owner | Closes at |
|---|---|---|
| Does `listen` on an unbound TCP socket pass Landlock's bind check, on ABI 4 through 7? The design does not depend on it; the answer decides whether the port tier, which relies on Landlock alone, also needs the `listen` rule. | implementer | spike before phase B |
| What names the loopback-callback request for FW-EGR15: the `open-url` channel lift, or a new field? Growth prefers the channel. | maintainer | adoption |
| Should the same request admit a loopback listener on Linux, for parity? It needs the address check this draft dropped. Until decided, callbacks are macOS-only and reported. | maintainer | after phase B |
| Which Mach services does `core` need? Measure with lookups allowed and reported on `macos-14` and `macos-15`; confirm that Seatbelt reports allowed lookups, or collect by another means. | implementer | before phase D |
| Can CoreFoundation preferences be read with `cfprefsd` denied? If not, `cfprefsd` is in `core` and its write path stays a named `Partial`. | implementer | characterization C10 |
| May an operator allow one Mach service by name in a blueprint, outside the profile's groups, or only through `learn` and the discovered layer? | maintainer | adoption |
| Do Landlock's TCP port rules govern `IPPROTO_MPTCP` and `IPPROTO_SCTP` stream sockets on ABI 4 through 7? Characterize; `FW-ISO35` holds either way. | implementer | spike before phase A |
| Which shipping kernels enable the x32 ABI? The audit names three distributions without evidence. It does not change the fix; it sets the advisory's severity. | implementer | advisory drafting |
| Does Seatbelt permit `execve` of a file whose read is denied and whose exec is allowed? `FW-ISO36` on macOS rests on it. | implementer | characterization, before phase D |
