# FEP-6 execution record

Companion to `fep-6.md` (what and why). This records how FEP-6 was built on the engine FEP-5 landed,
where the build departed from the proposal and why, and what is still owed. Requirement and test IDs
are defined in `formwork.md`, where FEP-6's were folded after landing, anchored there, and cited
bare in code.

## 1. What landed

| Area | Scope | Where |
|---|---|---|
| Grammar | `allow:` and `tunnel:` replace `any:` and `https:` with no alias; inspection is the default grade; host targets need a dot, `localhost` or an IP literal (`FW-BP16`); one grade per host and port (`FW-BP14`); fs `allow:` is read, write and create, with `exec` separate | `formwork-blueprint/src/egress.rs`, `formwork-cli/src/blueprint_load.rs` |
| Parse edge | the authority grammar of §4.2 (`[A-Za-z0-9.-]`, numeric spellings read as IPv4 and accepted only dotted-decimal, bracketed IPv6 without a zone); `CanonicalPath` as the one form rules match and the Gateway forwards | `formwork-blueprint/src/egress.rs` |
| Destination | the §4.5 class table with embedded IPv4 (mapped, compatible, NAT64, 6to4, Teredo); one resolution, every address classified, a mixed answer refused whole (`FW-EGR17`); the Gateway's own endpoints (`FW-EGR18`); local, private and host addresses by exact name or IP literal only (`FW-EGR19`); the host's interface addresses from `getifaddrs` | `formwork-blueprint/src/egress.rs` (`classify`, `admit_addresses`), `formwork-detect` (`interface_addresses`), `formwork-gateway/src/egress.rs` |
| Front door and tunnel | limits and timeouts of §4.9; the ClientHello buffered and parsed with rustls's `Acceptor` before a byte goes upstream (`FW-EGR16`) | `formwork-gateway/src/egress.rs` |
| Inspected grade | server name and ALPN checked before the handshake (`FW-EGR20`); streamed bodies (`FW-EGR21`); the request line written from the canonical path with hop-by-hop fields removed (`FW-EGR22`); TRACE and CONNECT refused (`FW-EGR23`); a per-session keep-alive pool; WebSocket spliced after `101`; plain HTTP through the same pipeline | `formwork-gateway/src/{http,inspect}.rs` |
| Brokering | the placeholder scan; no credential on OPTIONS (`FW-CRED18`) or over plain HTTP (`FW-CRED19`); the reflection guard (`FW-CRED17`); the operator line on a brokered `401`/`403`; custody (`FW-CRED16`); the compiler refuses a binding whose only inspected rule is on port 80 (§9 i) | `formwork-gateway/src/inspect.rs`, `formwork-confine` (`deny_inspection_of_self`), `formwork-blueprint/src/credential.rs` |
| Session CA | ECDSA P-256, path length 0, `keyCertSign` and `cRLSign`, name-constrained to the inspected hosts (`FW-EGR25`); one leaf key per session, distinct from the CA's; random positive serials; subject and authority key identifiers; §4.9 lifetimes; a 1,024-host LRU with re-minting at half life | `formwork-gateway/src/ca.rs` |
| Upstream proxy | `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` from `formwork run`'s own environment (`FW-EGR26`) | `formwork-gateway/src/upstream.rs`, `formwork-cli/src/main.rs` |
| Records | violation records with a reason from the closed set and the capability (`FW-FID12`); grant records (`FW-FID13`) | `formwork-gateway/src/egress.rs` |
| Launcher | both spellings of the proxy and `no_proxy` variables, `NODE_USE_ENV_PROXY=1` (§9 c), and an inherited npm proxy setting overridden | `formwork-cli/src/main.rs` |
| Operator surface | `learn` proposes `allow:` for an unlisted host, withholds `address-class` refusals, and names the `tunnel:` rule for a host whose client rejected the session CA; `explain --hosts` reports per-host address classification and the upstream trust source | `formwork-blueprint/src/discovery.rs`, `formwork-cli/src/{learn,main}.rs` |
| Amendments | §9 (a)–(j) | `formwork.md`, `constitution.md`, `fep-1.md`, `fep-5.md`, `examples/`, `README.md` |

## 2. Mechanisms, as built

**The pipeline.** The front door reads the proxy head within **head-timeout** and **head-limit**,
checks the per-session credential, and dispatches `CONNECT` to the host decision and an
absolute-form request to the plain-HTTP relay. A `CONNECT` host is decided, then its destination is
resolved and classified, and only then does the client get `200`: a refused host or address is a
`403` before any certificate is minted. A tunnel reads the ClientHello, checks the server name,
dials the first reachable admitted address, replays the buffered bytes and copies. An inspected host
reads the same ClientHello, checks the server name and ALPN, and completes the handshake with the
host's leaf over the replayed bytes.

**Requests.** Each inner request is read strictly (token method, visible-ASCII target, CRLF only, at
most 100 fields), then decided in order: target form, canonical path, framing, `Host`, TRACE and
CONNECT, host (plain HTTP only), method and path, placeholders. A refused request with a readable
body has the body drained and gets `403` on a connection that stays open; a request the engine
cannot frame gets `400` and the connection closes, as does a `Host` mismatch. The upstream is taken
from the pool, whose idle connections are probed for a close before reuse, or dialed; a bodiless
request whose reused connection turns out closed is retried once on a fresh one.

**The reflection guard.** For a request on which a credential was presented, the Gateway replaces
`Accept-Encoding` with `identity`, drops `Sec-WebSocket-Extensions`, refuses a response with any
other content coding, scans response headers and trailers, and scans the body stream holding back
only the longest suffix that is a proper prefix of an encoding (the secret, and the full scheme
value: `Bearer <secret>` or the base64 of `user:secret`). On a match the client connection is
dropped mid-response and a `reflection` record is written.

**Custody.** Before the Launcher spawns a workload whose blueprint brokers a credential, the
`formwork` process calls `prctl(PR_SET_DUMPABLE, 0)` on Linux and `ptrace(PT_DENY_ATTACH)` on
macOS. `FW-CRED16`'s Linux test observes the effect from outside: the process's `/proc` entries
belong to root, and a same-uid reader of its `environ` is refused. Its macOS test attaches `lldb`
to a plain process (control) and fails to attach to the brokering Gateway. On macOS the
environment needs more than `PT_DENY_ATTACH`: `kern.procargs2` returns any same-uid process's
exec-time environment and Seatbelt does not mediate it, so `formwork` moves its environment to the
heap and zeroes the exec-time strings first thing in `main` (every subcommand, brokering or not),
and a confined reader finds them blank.

**The upstream proxy.** `https_proxy` (or `HTTPS_PROXY`) carries TLS by `CONNECT`, `http_proxy` (or
`HTTP_PROXY`) carries plain HTTP in absolute form with the URL's Basic credentials, and `no_proxy`
(or `NO_PROXY`) exempts names by suffix, addresses and CIDR blocks. A name the proxy carries is not
resolved by the Gateway; an IP literal is classified either way.

## 3. Departures from the proposal

Each is a visible amendment in the sense of the constitution's Precedence & Conflicts, recorded here
rather than silently deviated.

- **No `hyper`; FEP-5's hand-written HTTP/1.1 stays.** §5 recommends `hyper`, `hyper-util` and
  `http-body-util`. The landed framing (content length or chunked, never both, strict heads) already
  met `FW-EGR11`, and the requirements FEP-6 adds -- streaming, authorized forwarding, the pool, the
  guard's re-chunking -- are a few hundred lines on it. The engine adds no crate, stays on `rcgen`
  0.13 and `time` 0.3.44, and keeps the MSRV at 1.85 (§5's toolchain note applies only to the
  recommended set). `hyper` stays the answer if the §11 HTTP/2 spike adds a server codec.
- **The types keep their landed names.** FEP-6 §5 names `HostName`, `HostPattern`, `CanonicalPath`,
  `EgressPolicy` and `EgressError`. As built: `CanonicalHost` (a name or an IP literal, the one
  value the parse edge yields for both), `HostPattern` and `CanonicalPath` in `formwork-blueprint`;
  the compiled table is the landed `HostTable` in `GatewayPolicy`, matched by a linear scan, since
  host tables run to tens of rules and a map would change the serialized shape for no measured gain;
  the engine's error is the crate-internal `Refusal`, so no variant is API surface.
- **`FW-BP16` also reads `**` as a path.** An any-depth pattern (`deny:**/.env`) begins with `**`,
  which no host can, so the anchored statement lists it beside `/`, `~` and `$`.
- **Admission failures are operator lines, not violation records.** A connection the supervisor did
  not register, and a proxy request without the session credential, come from outside the
  session's egress; the closed reason set of `FW-FID12` covers refusals of the session's own
  traffic. Both still produce one operator line (the unregistered connection) or a `407`.
- **A record names the deciding rule, not its layer.** The Gateway holds the compiled table, which
  carries no provenance; the record's `explain` invocation prints the layer. Carrying provenance
  into the Gateway is deferred until an embedder needs it in the record.
- **Timeouts.** **head-timeout** runs from accept for the proxy head, from the `200` reply for the
  first inner request, and from the first byte for later ones; the wait for that first byte is
  **idle-timeout**. A response has no timeout at all, head included: a non-streaming model request
  can take minutes before its first byte.
- **The guard ends the connection by dropping it.** §4.7 says "resets"; the TLS stream is dropped
  without `close_notify`, which the client reads as a truncated response, and no TCP `RST` is forced.
- **OPTIONS loses its placeholder.** `FW-CRED18` withholds the credential; the header that carried
  the placeholder is removed too, so the upstream sees no credential-shaped value.
- **The placeholder scan runs in every session**, brokered or not: an `fwcred-` value with no known
  placeholder is refused as unknown.
- **WebSocket after a brokered upgrade.** `Sec-WebSocket-Extensions` is removed so frames stay
  uncompressed and scannable; the guard scans the upstream's frame bytes, so an echo split across
  fragments is not recognized. The `credential-broker` verdict is `Partial` and names this and the
  identity-coding condition.
- **Upstream proxy scope.** Loopback destinations (`localhost`, loopback literals) are always exempt,
  as in Go's `net/http`. `https://` and SOCKS proxy URLs are refused at session start. Per-host
  classification is reported by `explain --hosts` and one session-start operator line; the compile
  report stays a pure function of the blueprint and the HostProfile and carries no environment.
- **`learn` does not propose `tunnel:`.** A host whose client rejected the session CA already has an
  inspected rule, and a `tunnel:` rule beside it fails `FW-BP14`. `learn` names the rule to swap in
  an operator line, listed apart from the proposals.
- **Protocol details.** A `CONNECT` authority without a port is `malformed` (FEP-5 defaulted it to
  443). An absolute-form request to a tunnel host is refused as `not-tls`. The Gateway answers
  `Expect: 100-continue` itself and does not forward the header. An IP-literal leaf carries a
  subject name that is not host-shaped, so OpenSSL does not check it against the CA's DNS
  constraints.
- **npm's proxy settings are overridden (FEP-6 §4.11 amended).** `FW-E2E-094` found npm going
  around the Gateway: it prefers an inherited `npm_config_https_proxy` to `https_proxy`, so the
  session's npm dialed the operator's proxy and the supervisor refused it. The Launcher now
  overrides `npm_config_proxy`, `npm_config_https_proxy` and `npm_config_noproxy` when inherited.
- **The client matrix uses proxied names.** npm (and Go's `net/http`) never send a loopback
  destination through a proxy, so a matrix against `127.0.0.1` measures that, not the Launcher's
  variables. `FW-E2E-094` names its hosts and reaches them through an operator's proxy fixture
  (`FW-EGR26`), which resolves them, so the Gateway needs no DNS.
- **cargo reads the session bundle (FEP-6 §4.11 amended).** `FW-E2E-094` found cargo honoring
  `CARGO_HTTP_CAINFO` and not `SSL_CERT_FILE`; the Launcher sets it with the other trust variables.
- **macOS: the Gateway conceals its environment** (custody, above), and the peer check
  authenticates the listener's connections (FEP-5 §3.1 as amended; `net-host-scope` `Enforced`).
- **`FW-E2E-096` decides on an interval against a calibrated budget (FEP-6 §8 amended).** A fixed
  millisecond bound on a shared runner is a flaky test. Each sample pairs the request direct and
  through the Gateway; a row passes when the 95% interval for the median difference lies under the
  target times the runner's speed factor -- a calibration workload of in-memory TLS handshakes and
  records, timed between batches, over its time on the reference `ubuntu-24.04` runner, clamped to
  [1, 3]. An interval that straddles the budget takes more pairs, up to 4,000.
- **`FW-E2E-093` decides on the 99th percentile (FEP-6 §8 amended).** "Every event within 20 ms"
  is a maximum, the statistic a shared runner's noise reaches first, and a 200 ms cadence over 30 s
  gives 150 events, too few for an interval. Events come every 20 ms, 1,000 at a time; the 95%
  interval for their delays' 99th percentile is held to 20 ms times `FW-E2E-096`'s node factor, and
  the maximum is reported. Measured at a 99th percentile of 0.6 ms locally.
- **`FW-E2E-092` measures the `formwork` process.** The Gateway runs in it; the workload waits for
  the test to sample the idle baseline, then streams 256 MiB with `curl -T` to a fixture that
  hashes the body without holding it. Growth was 3 MiB of the 16 MiB bound; a Gateway that held a
  length-framed body before forwarding it grew 259 MiB and failed.
- **The pool waited a timer tick per reused request (found by `FW-E2E-096`).** Its idle-connection
  check was `timeout(Duration::ZERO, ..)`, which tokio resolves on the timer's next 1 ms tick, so
  every request on a reused connection added about 1.3 ms. One poll replaces it (0.06-0.11 ms
  added), and a test covers a pooled connection the upstream closed while idle.
- **The FW-ENV2 scrub judges git's environment config per entry (found by `FW-E2E-094`).** By
  variable name, every `GIT_CONFIG_KEY_<n>` went (it contains `KEY`) while `GIT_CONFIG_COUNT` and
  the values stayed, so git refused to start, and an `http.extraheader` credential in a value
  passed through. Each entry is now judged by its config key and value, dropped entries are
  removed and the rest renumbered under a matching count (`formwork.md` FW-ENV2 amended); the
  matrix no longer clears the operator's git environment.
- **`fw-egress-probe` is not built.** The gateway tests drive rustls clients and raw sockets
  directly, which produce every case the probe was for (a mismatched server name, a mismatched
  `Host`, a non-TLS first byte, an `h2`-only ALPN offer, the raw heads of `FW-ADV-024`).

## 4. Tests

Gateway-level tests drive the in-process listener over real sockets with the fixture resolver.
Run-level tests drive the built `formwork` binary against the real supervisor and kernel, with real
clients, loopback fixtures, and the operator's `SSL_CERT_FILE` naming the fixture root (§7.1).

| ID | Where | Runs on | Coverage |
|---|---|---|---|
| `FW-E2E-092` | `fep6_run.rs` (`fw_e2e_092_…`: a 256 MiB curl upload through `run`, the `formwork` process's resident memory sampled), `formwork-gateway/tests/inspect.rs` (`fw_egr21_…`: 3 MiB chunked and length-framed) | both | the `git push` half is owed with the integrated forms' git fixture |
| `FW-E2E-093` | `formwork-gateway/tests/latency.rs` (the 20 ms bound, in release with `FW-E2E-096`), `formwork-gateway/tests/inspect.rs` (ordering through the guard) | both | as amended: a 95% interval for the 99th percentile delay against 20 ms scaled to the runner |
| `FW-E2E-094` | `formwork-cli/tests/fep6_run.rs`; CI records it per OS | both | the matrices below |
| `FW-E2E-095` | `formwork-gateway/tests/inspect.rs` | both | full |
| `FW-E2E-096` | `formwork-gateway/tests/latency.rs`, in release in its own CI step | both | as amended: a 95% interval for the median added latency against the target scaled to the runner (below) |
| `FW-E2E-097` | `formwork-gateway/tests/inspect.rs` (`fw_egr25_…`), `src/ca.rs`, `fep6_run.rs` (`FW-E2E-098`, `FW-E2E-094`: OpenSSL, LibreSSL, GnuTLS, Node, Go and Python verify constrained leaves) | both | the constraints' effect, not an `openssl verify` transcript |
| `FW-E2E-098` | `fep6_run.rs` (rows 1, 8, 9, and an upstream the Gateway cannot verify), `formwork-gateway/tests/{egress,inspect}.rs` (rows 2, 6, 7) | both | rows 3–5 are FEP-5's `FW-E2E-075` |
| `FW-E2E-099` | `fep6_run.rs` (every row through `run`), `formwork-gateway/tests/inspect.rs` (`fw_e2e_078_…`) | both | row 4's 20 ms bound is `FW-E2E-093`'s |
| `FW-E2E-103` | `fep6_run.rs` (rows 1, 2, 4 through `run`), `formwork-gateway/tests/egress.rs` (`fw_egr26_…`, `fw_adv_023_…`) | both | row 3 is FEP-5's `FW-E2E-075`; row 5 at the Gateway |
| `FW-E2E-104` | `fep6_run.rs` | both | full |
| `FW-ADV-021` | `formwork-gateway/tests/inspect.rs`, `fep6_run.rs` (`FW-E2E-099`'s reflection row) | both | full |
| `FW-ADV-022` | `formwork-gateway/tests/{egress,inspect}.rs` (`fw_egr16_…`, `fw_egr10_…`, `fw_egr20_…`) | both | full |
| `FW-ADV-023` | `formwork-gateway/tests/egress.rs` | both | the Gateway's own listener case is a unit test (`gateway_endpoints_and_host_addresses_are_classes`): the listener port is not known before the table is written |
| `FW-ADV-024` | `formwork-gateway/tests/egress.rs`, `src/http.rs`, `src/egress.rs` | both | full |
| `FW-CRED16` | `fep6_run.rs` (`fw_cred16_…`) | both (Linux unprivileged) | Linux: root owns every `/proc` entry, so a root runner cannot observe it; macOS: `lldb` against the Gateway, and its environment read blank |
| `FW-EGR17`, `FW-EGR19` through the host resolver | `fep6_run.rs` (`fw_egr17_…`) | both | `localhost` by exact name; an unresolvable name refused as `resolution` |
| `learn`'s `tunnel:` line (§9 j) | `fep6_run.rs` | both | full |

The recorded client matrix (`FW-E2E-094`), with the Launcher's variables alone and an inherited
`npm_config_https_proxy`, on ubuntu-22.04 and 24.04 and on macos-14 and 15 (CI prints it on every
run, with each refusal's last line of output). Each cell reads inspected / tunnel. The fixture
origin presents a leaf issued by a test root, as a real origin does; the operator's `SSL_CERT_FILE`
names the root.

| Client | Linux | macOS | Reads |
|---|---|---|---|
| curl | reached / reached | reached / reached | `https_proxy`, `CURL_CA_BUNDLE` |
| Python `urllib` | reached / reached | reached / reached | `https_proxy`, `SSL_CERT_FILE` |
| Python `requests` | reached / reached where installed | absent from the runner's Python | `https_proxy`, `REQUESTS_CA_BUNDLE` |
| Node `fetch`, `https` (22.22) | reached / reached | reached / reached | `NODE_USE_ENV_PROXY`, `NODE_EXTRA_CA_CERTS`; Node below 22.21 (or 24.5) is expected refused |
| git | reached / reached | reached / reached | `https_proxy`, `GIT_SSL_CAINFO` |
| pip, `python3 -m pip` | reached / reached | reached / reached | `https_proxy`, `PIP_CERT`. pip verifies through `truststore`, which on macOS hands the bundle's CA certificates to the platform verifier as anchors |
| npm 10 | reached / reached | reached / reached | `npm_config_https_proxy` (overridden), `NODE_EXTRA_CA_CERTS` |
| Go `net/http` | reached / reached | refused / refused | `HTTPS_PROXY`; `SSL_CERT_FILE` on Linux, the platform verifier on macOS |
| Swift `URLSession` | -- | refused / refused | neither: the system proxy settings and the keychain. It connects directly, which the session refuses |
| uv 0.8 | reached / reached | reached / reached | `https_proxy`, `SSL_CERT_FILE` -- without `UV_NATIVE_TLS` |
| cargo | reached / reached | reached / reached | `https_proxy`, `CARGO_HTTP_CAINFO` |
| rustup | reached / reached | refused / refused | `https_proxy`; `SSL_CERT_FILE` on Linux, the platform verifier on macOS |

Go's and rustup's macOS refusals are the platform-verifier caveat of FEP-5 §3.2: the inspected row
fails on the session CA, the tunnel row on a root the keychain does not hold; against a real
origin, whose root the keychain holds, the tunnel row reaches. Swift's `URLSession` never reaches
the Gateway: it ignores the proxy variables and connects directly, which the session refuses.

The latency budget (`FW-E2E-096`), median added latency over 1,000 pairs, as the runners measured
it when the reference was set (every factor 1.00):

| Row (target) | ubuntu-22.04 | ubuntu-24.04 | macos-14 | macos-15 |
|---|---|---|---|---|
| Tunnel grade, new connection, to first byte (2 ms) | 0.25 ms | 0.23 ms | 0.38 ms | 0.23 ms |
| Inspected grade, reused connection, per request (1 ms) | 0.090 ms | 0.114 ms | 0.106 ms | 0.059 ms |
| Inspected grade, first connection to a host (5 ms) | 0.82 ms | 0.82 ms | 1.07 ms | 0.59 ms |

## 5. Still owed

- **The integrated scenario forms `FW-E2E-100`, `101`, `102`, `105` and `FW-ADV-025`** need fixture
  `git http-backend`, npm and pip registries and a second network namespace for wildcard success
  paths (§7.1). Their mechanisms are covered by the gateway tests above; the integrated flows are
  not.
- **`FW-E2E-106`** stays blocked on FEP-6 §11 (in-session loopback).
- **`FW-E2E-092`'s `git push` half** (a pack over 1 MiB, chunked) needs the integrated forms' `git
  http-backend` fixture; chunked uploads are covered at the gateway level (`fw_egr21_…`).
