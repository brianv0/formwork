# FEP-6 (proposal): the egress engine, an in-process Rust HTTP(S) proxy inside the Gateway

**Formwork Enhancement Proposal 6 — proposal, not landed.** Companion to `formwork.md` (design +
end-to-end spec), `constitution.md` (doctrine), `docs/fep-1.md` (what host-scoped egress permits) and
`docs/fep-5.md` (how a confined connection reaches the Gateway, the host-rule grammar, inspection and
brokering). Motivated by the Omnigent comparison in `docs/omnigent-integration-eval.md`.

FEP-5 specifies what the Gateway enforces for egress and how the confined process's connections
reach it. It does not specify the program that serves those connections: which protocols it parses,
how it resolves and pins destinations, how it mints certificates, how it presents and guards
credentials, what it refuses to forward, and what it is built from. This FEP specifies that program,
the **egress engine**, and records the research behind the build decision.

**Status: nothing in this document mutates the landed spec, the constitution, or FEP-5.** Draft
identifiers are inline code, as in FEP-5, and start above the highest drafted number: FEP-5 drafted
up to `FW-EGR15`, `FW-CRED15`, `FW-FID11`, `FW-INV14`, `FW-E2E-091` and `FW-ADV-020`; FEP-4 drafted
`FW-INV12` and `FW-DISC7`–`FW-DISC10`. This FEP starts at `FW-EGR16`, `FW-CRED16`, `FW-FID12`,
`FW-INV15`, `FW-E2E-092` and `FW-ADV-021`. Changes to FEP-5 or FEP-1 drafts are listed in §9.

**The question that opened this FEP.** Omnigent does not use Envoy, Squid or mitmproxy. Its egress
proxy is about 2,900 lines of its own Python (asyncio, the standard-library `ssl` module, and
`cryptography` for certificates) under `omnigent/inner/egress/`. The proxy is present in the
repository's first public commit (2026-06-13), and no commit message in its 4,165-commit history
names another proxy. Formwork can build the equivalent in Rust (§3). Every protocol parser and state
machine in the proposed engine is Rust; the cryptographic primitives come from `ring`, which is Rust
with C and assembly cores (§3.3).

---

## 1. Problem

FEP-5 Phases 2 and 3 need an engine behind the egress listener. Four inputs fix its shape.

- **The policy surface is settled.** FEP-5 §4 fixes the host-rule grammar (`FW-BP13`), one grade per
  host (`FW-BP14`), brokering (`FW-BP12`, `FW-CRED11`) and the report keys. This FEP adds no
  blueprint field and no CLI flag.
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
| Every CONNECT is TLS-terminated | Every client must trust the CA, including for hosts that need only a host allowlist; clients that ignore env-var trust fail on every host | Tunnel grade splices without termination (FEP-5 §4; §4.3 here) |
| CA key stored on disk for 365 days | Any same-uid process outside the sandbox that reads the key file can mint certificates that every later session's clients trust for a year | In-memory CA per session, with name constraints (§4.6) |
| Request bodies are framed by `Content-Length` only; no code path reads `Transfer-Encoding: chunked` | A chunked upload is not forwarded and stalls until a timeout. `git push` sends chunked bodies for packs above `http.postBuffer` (1 MiB by default) | `hyper` framing; a head with both headers is refused (`FW-EGR11`) |
| The whole request body is read into memory (`readexactly(content_length)`) with no cap | Memory use is bounded only by the client | Bodies stream (§4.9, `FW-EGR21`) |
| `Connection: close` is forced on every upstream request | One TCP connect and one TLS handshake to the upstream per request | A per-session pool of keep-alive upstream connections (§4.4) |
| The 403 body names the method, host and path (`"GET https://h/p denied by policy"`) | The agent learns which rule refused it | Fixed body; the detail goes to the operator channel |
| Path globs match the raw request path | `/repos/acme/../other/x` matches `/repos/acme/**` (verified in the evaluation) | Canonicalize before matching (`FW-EGR11`) |
| Upstream reads time out after 60 s of silence | A model response that pauses longer than 60 s is cut | No per-read timeout on an open response body; idle limits apply between requests (§4.9) |

### 2.2 Other implementations

<!-- research agent 2 -->

### 2.3 The Rust building blocks

<!-- research agent 1 -->

---

## 3. Build or buy

<!-- decision after research -->

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
   non-ASCII names refused (clients send A-labels).
4. **Host decision.** Look the host up in `EgressPolicy`: `deny` rules first (terminal), then exact
   names, then wildcard suffixes. The result is not listed, denied, tunnel, or inspected.
5. **Destination.** Resolve and classify (§4.5); the result is an ordered list of admitted
   addresses.
6. **Grade.** Tunnel (§4.3) or inspected (§4.4).

The front door is the only stage that knows how the connection arrived. A later front door, such as
an original-destination mode fed by the supervisor's registration record (FEP-5 §9 "Transparent
mode"), reuses stages 3 to 6 unchanged.

### 4.3 Tunnel grade

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

The upstream side is a pool of keep-alive HTTP/1.1 connections keyed by host and port. Its connector
resolves and classifies (§4.5), connects to admitted addresses in answer order, and verifies the
upstream certificate for the host name against the host trust store (`FW-EGR24`). A pooled
connection is reused only for the host it was opened for.

### 4.5 Destination policy

The engine resolves names with the host's own resolver (`getaddrinfo`, through
`tokio::net::lookup_host`), so `/etc/hosts`, NSS and split-horizon corporate DNS behave for the
session as they do for the operator. One resolution per upstream connection; every returned address
is classified; if any address is refused, the connection is refused (`address-class`), because a
mixed public and private answer is the rebinding pattern. The engine then connects only to addresses
from that answer (`FW-EGR17`).

Classes, checked on the address and, for IPv6 forms that embed an IPv4 address, on the embedded
address as well:

| Class | Ranges | Admitted by |
|---|---|---|
| Metadata | `169.254.169.254`, `fd00:ec2::254`, `100.100.100.200` (Alibaba), `168.63.129.16` (Azure WireServer) | an IP-literal rule naming the address ([FW-EGR4](fep-1.md#fw-egr4)) |
| Gateway endpoints | the session's own listener addresses and ports | never (`FW-EGR18`) |
| Local and private | `0.0.0.0/8`, `127.0.0.0/8`, `::1`, `::`, RFC 1918, `100.64.0.0/10`, `169.254.0.0/16`, `fe80::/10`, `fc00::/7` | an IP-literal rule, or an exact-name rule (`FW-EGR19`); never a wildcard rule |
| Special-purpose | `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`, `255.255.255.255`, multicast, `100::/64`, `2001:db8::/32` | an IP-literal rule |
| Global | everything else | any matching rule |

Embedding forms: IPv4-mapped (`::ffff:0:0/96`), IPv4-compatible (`::/96`), NAT64
(`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`) and Teredo (`2001::/32`, the client address
is XOR-obfuscated). `64:ff9b::a9fe:a9fe` reaches `169.254.169.254` on a NAT64 network, so it is
classified as metadata. The table is written out in the engine: the standard library's
`Ipv4Addr::is_global` and `Ipv6Addr::is_global` are unstable.

Two changes from FEP-1 are proposed (§9 b, §10). FEP-1 does not list loopback, so a wildcard rule
whose name an attacker controls could reach services on the operator's loopback interface; loopback
joins the local class. FEP-1 also lets only IP literals name private ranges, which makes every
intranet host unreachable by name and conflicts with its own `FW-E2E-029`, where `allowed.test`
resolves to `127.0.0.1`. The table admits local and private addresses for exact-name rules and never
for wildcards: the rebinding attacks in the record depend on a name the attacker controls, which a
wildcard grants and an exact name does not.

### 4.6 Session CA and leaf certificates

The CA exists only when the blueprint has an inspected rule. It is generated in memory at Gateway
start with `rcgen` and its private key is never serialized (FEP-5 `FW-EGR13`).

| Field | CA | Leaf |
|---|---|---|
| Key | ECDSA P-256, generated per session | ECDSA P-256, one key per session shared by all leaves |
| Basic constraints | CA, path length 0 | not a CA |
| Key usage | `keyCertSign`, `cRLSign` | `digitalSignature`; EKU `serverAuth` |
| Subject alternative name | none | the host as a DNS name, or an IP address for an IP-literal rule |
| Name constraints | permitted subtrees: each inspected exact name, each wildcard's suffix, each inspected IP literal (`FW-EGR25`) | none |
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
**(characterize)** (`FW-CRED16`). The confined child is unaffected, since `execve` resets the flag
for the new image.

**Presentation limits.** The engine never presents a credential on OPTIONS (`FW-CRED18`), and TRACE
is refused outright on inspected hosts (`FW-EGR23`). A request that already carries a
non-placeholder credential header is forwarded unchanged.

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

| Traffic | Treatment | Phase (§7.3) |
|---|---|---|
| TLS to a tunnel host, any ALPN (HTTP/2, gRPC) | server-name check, then splice | A |
| Plain HTTP (absolute-form, port 80 rule) | the inspected request pipeline without TLS; reported unencrypted per FEP-5 §4 | A |
| HTTP/1.1 over TLS to an inspected host | terminate, match, broker, forward | B |
| HTTP/2 to an inspected host | not offered in ALPN; clients fall back to HTTP/1.1. A ClientHello whose ALPN list excludes `http/1.1` is refused as `alpn` (`FW-EGR20`), and the operator line suggests tunnel grade for the host | spike-gated (§11) |
| WebSocket over an inspected host | the upgrade GET is matched and brokered like any request; frames after `101` pass uninspected, and the report line says so | C |
| An operator's upstream proxy | the engine connects through the proxy named in `formwork run`'s own environment; the proxy resolves names, so address classification is `Partial` and the report says so (`FW-EGR26`) | C |
| HTTP/3 and QUIC | UDP is closed under host rules (FEP-5 `FW-ISO11`); clients fall back to TCP | — |
| Non-HTTP TCP (SSH, database protocols) | refused under host rules; a port-scoped fd ([FW-GW6](../formwork.md#fw-gw6)) is the FEP-1 answer and has no grammar yet (§11) | — |

HTTP/1.1-only ALPN on inspected hosts serves the model APIs and package registries the shipped
examples use, all of which accept HTTP/1.1. gRPC requires HTTP/2 and therefore tunnel grade.

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

`FW-E2E-094` turns this table into a recorded matrix on both CI operating systems.

### 4.12 Asymmetries

The engine is the same program on both platforms. The differences come from the transport (FEP-5
§3.6) and from the host trust store: on Linux `rustls-native-certs` reads the system bundle; on
macOS it reads the keychain's trusted roots. On both it reads `SSL_CERT_FILE` and `SSL_CERT_DIR`
from `formwork run`'s own environment when they are set, and uses only those locations; the
resolved-input disclosure ([FW-FID7](../formwork.md#fw-fid7)) names the source.

---

## 5. Surface changes (each measured against Growth)

**Blueprint, CLI, profiles.** None. The engine implements FEP-5's surface.

**Report.** No new capability key. The `credential-broker` verdict's reason names the reflection
guard's content-coding condition. Violation records gain the closed `reason` set (§4.10), a
Data-model surface that versions with the record schema.

**Types.** `HostName`, `HostPattern` and `CanonicalPath` in `formwork-blueprint`; `EgressPolicy` in
`formwork-compile`'s `GatewayPolicy` (a `CompiledPolicy` shape change, so a contract change per
[FW-FID4](../formwork.md#fw-fid4)); `EgressError` in `formwork-gateway`, whose variants are API
surface.

**Dependencies.**

<!-- dependency table after research -->

---

## 6. Proposed requirements (draft numbering — anchored on landing)

These continue the EGR, CRED, FID and INV families. One obligation per ID; rationale lives in §4.

| Req | Requirement |
|---|---|
| `FW-EGR16` Tunnel server name | For a tunnel-grade host, the Gateway shall forward bytes upstream only after buffering a complete TLS ClientHello whose server name equals the canonical CONNECT host, and shall refuse a connection whose first byte is not a TLS handshake record. |
| `FW-EGR17` Single resolution | Before connecting upstream, the Gateway shall resolve the host once, classify every returned address, including any IPv4 address embedded in an IPv6 address, refuse the connection if any address is in a class the matching rule does not admit, and connect only to addresses from that resolution. |
| `FW-EGR18` Gateway self-exclusion | The Gateway shall refuse every upstream connection to its own listener endpoints. |
| `FW-EGR19` Local and private admission | The Gateway shall admit a loopback, private, shared or link-local address other than a metadata address only for a host matched by an exact-name or IP-literal rule. |
| `FW-EGR20` Inspected ALPN | For an inspected host, the Gateway shall offer only `http/1.1` in ALPN and shall refuse a ClientHello whose ALPN list is present and excludes `http/1.1`. |
| `FW-EGR21` Streamed bodies | The Gateway shall forward request and response bodies as they arrive, holding at most **body-buffer** bytes of a body per direction in memory. |
| `FW-EGR22` Authorized forwarding | For an inspected request, the Gateway shall send upstream a request line built from the method and canonical path that matched, with hop-by-hop headers and `Proxy-Authorization` removed. |
| `FW-EGR23` Reflective methods | On an inspected host, the Gateway shall refuse TRACE and CONNECT requests under every rule. |
| `FW-EGR24` Upstream verification | The Gateway shall verify every upstream TLS certificate for the requested host name against the host trust store it loaded at session start, and shall never trust the session CA or a file a confined process can write for upstream verification. |
| `FW-EGR25` Constrained session CA | The session CA certificate shall carry name constraints whose permitted subtrees are exactly the session's inspected exact names, wildcard suffixes and IP literals. |
| `FW-EGR26` Upstream proxy | When `formwork run`'s environment names an upstream proxy, the Gateway shall send admitted egress through it and report destination classification `Partial` with the reason. |
| `FW-CRED16` Broker custody | While it holds a brokered credential, the Gateway process shall be non-dumpable (Linux) or deny debugger attachment (macOS). |
| `FW-CRED17` Reflection guard | For a response to a request on which it presented a brokered credential, the Gateway shall request identity content coding, refuse a response with another content coding, and end the response without releasing any byte that begins a wire encoding of the presented credential. |
| `FW-CRED18` No credential on OPTIONS | The Gateway shall not present a brokered credential on an OPTIONS request. |
| `FW-FID12` Egress refusal reasons | Every egress violation record shall carry exactly one reason from the closed set in §4.10. |
| `FW-FID13` Egress grant records | For each admitted tunnel and inspected request, the Gateway shall emit a grant record with host, grade, method, canonical path, status, byte counts and duration, and no header value, body byte or query string. |

Invariant:

- `FW-INV15` **Unparsed is unforwarded.** No byte from a confined process reaches an upstream unless
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

### 7.2 Tests

Draft numbers continue above `FW-E2E-091` and `FW-ADV-020`.

- `FW-E2E-092` **Chunked and large uploads (both).** Against an inspected fixture: a `git push` of a
  pack larger than 1 MiB, and a 256 MiB `POST` from curl. Pass: the fixture receives both bodies
  byte-identical, and the Gateway's resident memory grows by less than 16 MiB during the upload.
  Fail: either body differs or stalls, or memory grows past the bound.
- `FW-E2E-093` **Streaming (both).** A fixture emits one server-sent event every 200 ms for 30 s on
  an inspected host with a brokered credential. Pass: every event reaches the client within 20 ms of
  the fixture writing it. Fail: any event is later.
- `FW-E2E-094` **Client matrix (both).** curl, git, Python `requests`, Python `urllib`, pip, Node
  `fetch` and `https` with the Launcher's variables, npm, Go `net/http`, uv, cargo and rustup each
  fetch from a tunnel fixture and an inspected fixture. Pass: the results match the matrix recorded
  in the repository, which also records name-constraint enforcement per client. Fail: a result
  differs from the recorded matrix.
- `FW-E2E-095` **Upstream reuse (both).** Twenty sequential requests from one client to one
  inspected fixture. Pass: the fixture observes one TLS handshake. Fail: more than one.
- `FW-E2E-096` **Latency budget (both).** Medians over 1,000 requests against a loopback fixture,
  compared with the same client connecting directly. Pass: the §9 (f) targets. Fail: any median
  exceeds its target.
- `FW-E2E-097` **Session CA shape (both).** Pass: the bundle's session certificate is a CA with path
  length 0 and the name constraints `FW-EGR25` lists; no file under the session scratch, `$HOME` or
  the temporary directories contains the CA private key after the session starts; the leaf for an
  inspected host verifies with `openssl verify` against the bundle. Fail: any of these does not
  hold.
- `FW-ADV-021` **Credential reflection.** Under `broker:anthropic` bound to `allowed.test`, the
  fixture echoes the request's `x-api-key` in its body with the value split across two writes 50 ms
  apart, in a response header, and in a gzip-encoded body; the client also sends TRACE. Pass: no
  byte sequence of length 8 or more from the credential reaches the client, and each case emits
  `reflection` or a TRACE refusal. Fail: any credential sequence reaches the client.
- `FW-ADV-022` **Name disagreement.** A CONNECT to `allowed.test` with server name `blocked.test`; a
  matching server name with `Host: blocked.test` inside an inspected tunnel; a tunnel whose first
  byte is not `0x16`; a ClientHello offering only `h2` to an inspected host. Pass: each is refused
  with `sni-mismatch`, `host-mismatch`, `not-tls` or `alpn`, and the blocked fixture sees no
  connection. Fail: any reaches a fixture.
- `FW-ADV-023` **Address classes.** Under `https:*.test`, the resolver fixture answers
  `127.0.0.1`, `10.0.0.1`, `100.100.100.200`, `168.63.129.16`, `::ffff:169.254.169.254`,
  `64:ff9b::a9fe:a9fe`, `2002:a9fe:a9fe::1`, `fe80::1`, a public address mixed with `10.0.0.1`, and
  the Gateway's own listener address. Then, under the exact rule `https:allowed.test`, it answers
  `127.0.0.1` and then `169.254.169.254`. Pass: every wildcard case and the exact-name metadata case
  are refused with `address-class`, and the exact-name loopback case is admitted. Fail: any other
  outcome.
- `FW-ADV-024` **Parser battery (`FW-INV15`).** Heads carrying both `Content-Length` and
  `Transfer-Encoding`, two differing `Content-Length` values, obsolete line folding, a bare LF, a NUL
  in a header value, an invalid method token, a head over **head-limit**, CONNECT authorities with
  userinfo, a path, a zone identifier or a percent-encoded dot, and a truncated ClientHello. Pass:
  the fixture upstream receives no byte from any of them. Fail: any byte arrives.

The parsers in `FW-ADV-024` (authority, path canonicalization, ClientHello buffering) are also fuzz
targets once the fuzz infrastructure that `docs/STATUS.md` defers exists.

### 7.3 Phasing

Each phase lands with the FEP-5 phase that needs it, and the report is honest at every boundary.

- **Phase A**, with FEP-5 Phase 2: the front door, authority parsing, the host table, destination
  classification, tunnel grade, plain HTTP, records. `FW-EGR16`–`FW-EGR19`, `FW-EGR21`,
  `FW-FID12`, `FW-FID13`, `FW-INV15`.
- **Phase B**, with FEP-5 Phase 3: inspection, the session CA, the upstream pool, brokering, the
  reflection guard and custody. `FW-EGR20`, `FW-EGR22`–`FW-EGR25`, `FW-CRED16`–`FW-CRED18`.
- **Phase C**: WebSocket upgrade on inspected hosts; upstream proxy chaining (`FW-EGR26`).
- **HTTP/2 on inspected hosts**: after the §11 spike.

---

## 8. Comparison after this FEP

Conditional on FEP-5's transport landing and on the **(characterize)** marks above.

| Property | Omnigent | Formwork engine |
|---|---|---|
| Implementation | Python asyncio, `ssl`, `cryptography`; parent-process thread | Rust, `hyper`, `rustls`; in the Gateway's `tokio` runtime |
| Grades | every host terminated; HTTP/2 relayed opaquely for unrestricted hosts | tunnel (server-name check, no termination) or inspected, fixed per host |
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

## 9. Proposed amendments (apply on landing)

None of these are applied yet except (g).

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

---

## 10. Decisions (recorded per constitution Precedence & Conflicts)

<!-- build decisions after research -->

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
- **One leaf key per session.** A key per host buys nothing when every key lives in the same process;
  a shared key makes minting a signature only.
- **Name constraints on the session CA.** They cost one extension and bound what a leaked key could
  impersonate to the hosts the file already inspects.
- **HTTP/1.1 first.** Every model API and registry the examples use accepts it, and the HTTP/2
  server adds the `h2` crate and the stream-reset denial-of-service class to the Gateway (§2.3).
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
  which breaks test suites that start a local server. Admitting loopback connections to ports bound
  by session processes closes this on Linux; on macOS, SBPL cannot express "bound by the session",
  and `localhost:*` would open every host service on loopback.
- **Non-HTTP TCP.** SSH to a Git host and database protocols need a rule form for a port-scoped fd
  (FEP-1, [FW-GW6](../formwork.md#fw-gw6)). A grammar proposal belongs with FEP-5's `rules`.
- **Encrypted Client Hello.** Refused today as a server-name mismatch. If an agent toolchain enables
  ECH by default, tunnel grade needs a policy for the outer name.
- **Upstream proxy authentication.** `FW-EGR26` supports proxies without authentication or with
  Basic credentials in the proxy URL. NTLM and Kerberos proxies are not supported.
