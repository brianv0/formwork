# FEP-5 (proposal): closing the sandbox gap with meta-harness sandboxes

**Formwork Enhancement Proposal 5 — proposal, not landed.** Companion to `formwork.md` (design +
end-to-end spec), `constitution.md` (doctrine), and `docs/fep-1.md` (host-scoped egress, which this
FEP builds on). Motivated by `docs/omnigent-integration-eval.md`.

**Status: nothing in this document changes the landed spec or the constitution yet.** New
identifiers use draft numbering, written as inline code so the requirements canary skips them. They
sit above the highest landed or drafted number: `FW-E2E-074` and `FW-ADV-015`, the landed families'
highest anchors, `FW-INV12` in FEP-4, and `FW-EGR6`/`FW-FID5` in FEP-1. Amendments to landed text are
written as apply-on-landing blocks (§7).

---

## 1. Problem

Omnigent's OS sandbox ("OmniBox": bubblewrap, `sandbox-exec`, a mandatory L7 egress proxy) was
compared with Formwork in `docs/omnigent-integration-eval.md`. Each system covers much of what the
other lacks. Formwork's lead is on the capability model:
- the credential floor under broad grants;
- the exec allowlist;
- tamper-vector write-subtract;
- the create/modify split;
- the FidelityReport, `explain` and `learn`;
- MCP shading.

Omnigent leads on six points:

| # | Omnigent capability | Formwork today |
|---|---|---|
| G1 | Egress restricted to an allowlist by **host, method and path**, and mandatory: the sandbox has no route except the proxy | `Deny` or `Ports`. `AllowHosts` is specified in [FW-EGR1](fep-1.md#fw-egr1) but has no transport and no forward proxy |
| G2 | **Credential injection**: the proxy adds the token and the agent never holds it | Credentials are denied or exposed through `allow-credentials` ([FW-CRED5](../formwork.md#fw-cred5)). Brokering is an open question (`formwork.md` §11) |
| G3 | **UDP** closed unless the proxy carries it | UDP is unrestricted under `Ports` on Linux, and the report does not say so |
| G4 | **Pathname AF_UNIX** sockets are unreachable unless mounted | `connect()` is unmediated on Linux, even in `closed` read mode |
| G5 | **PID/IPC/UTS namespaces**, fresh `/proc`, private `/tmp` | None. Other processes' `/proc/<pid>/cmdline` is readable in ambient mode, and `/tmp` is shared |
| G6 | macOS: signals and `process-info` limited to self; `iokit-open` and `mach-priv*` not granted | The Seatbelt base is `(allow default)` |

This FEP proposes closing G1–G6 within the closed concept list:
- G1, G3 and G4 become one Linux mechanism, a `connect()` supervisor. The supervisor is the
  on-demand form of fd minting ([FW-GW6](../formwork.md#fw-gw6)).
- G2 extends the Catalog and the Gateway.
- G5 is an optional Confiner tier.
- G6 is a change to the SBPL base.

The six defects the evaluation found come first as Phase 0 (§2), because they block the default
profile on Linux.

### 1.1 Constraints this FEP holds to

- **No new concept.** The supervisor is the Gateway minting fds over the Seam. Brokering is the
  Catalog plus the Gateway. The namespace tier is Confiner mechanism.
- **Kernel-first transport.** The confined process never gets network access around the Gateway
  ([FW-XR7](../formwork.md#fw-xr7)). Proxy environment variables are a convenience for clients, never
  the thing that enforces the boundary.
- **Honesty.** Each new capability has a FidelityReport line. A tier that the host cannot provide is
  reported `Unenforceable`, and fails loudly when requested, never silently.
- **Growth.** Every new dependency and blueprint field is justified in §6. TLS termination is opt-in
  per host, not the default egress path.

---

## 2. Phase 0 — defects (bug fixes, no Concepts amendment)

Found and reproduced during the evaluation. Each is a fix to an existing requirement's
implementation or to its report, so none needs a new ID.

| # | Defect | Violates | Proposed fix |
|---|---|---|---|
| D1 | `extends = ["builtin:default"]` fails at enforce time on Linux with `any-depth pattern **/.git/config cannot be a rooted Landlock rule`. The `write-subtract` rows pass through the compiler unfiltered (`formwork-compile/src/lib.rs:440`), while the floor's `**/` rows are withheld (`:432`). | [FW-INV5](../formwork.md#fw-inv5): the report says fs-write is `Enforced`, but the install then fails | Withhold `**/` write-subtract rows on Linux the same way floor rows are, and report the tamper-vector set as `Partial` with the reason. Add an E2E test that runs `builtin:default` under real Landlock, which is missing today. |
| D2 | `formwork explain $CWD/sub/.env` answers "denied (credential floor)" on Linux, but the file is readable | [FW-INV5](../formwork.md#fw-inv5) | `explain` gives the platform verdict for any-depth rows ("withheld on this host") next to the model verdict |
| D3 | New files can't be created in a "split" directory (one that contains a hole). `protect_policy_inputs` write-denies `FORMWORK.toml` and its siblings, so the project root is always split, and `echo > ./new` returns EACCES. | [FW-TRA1](../formwork.md#fw-tra1) reuse | Move the discovery artifacts (`*.proposal.toml`, `*.discovered.toml`) out of the project to a per-blueprint state directory under `$XDG_STATE_HOME/formwork/`. Report create-in-split-directory as `Partial` for the holes that remain. |
| D4 | Under `Ports` on Linux, UDP is unrestricted, but the report says `net-default-deny enforced` | [FW-INV5](../formwork.md#fw-inv5), [FW-ISO5](../formwork.md#fw-iso5) | Report `Partial: UDP unrestricted under the port tier` now. Phase 2 enforces it (`FW-ISO11`). |
| D5 | The reason text for the Linux CrossDomainSocket `Partial` verdict doesn't say that pathname `connect()` is unmediated | [FW-INV5](../formwork.md#fw-inv5) | Reword the reason. Phase 2 enforces it (`FW-ISO12`). |
| D6 | The Gateway forwards these frames unfiltered: non-JSON frames, JSON-RPC batch arrays, and `tools/call`, `resources/read` or `prompts/get` without an `id` | [FW-GW2](../formwork.md#fw-gw2), [FW-GW4](../formwork.md#fw-gw4) | Non-JSON frame: close the connection (fail closed). Batch array: refuse it (MCP 2025-06-18 removed batching). A gated method without an `id` is policy-checked like any other and dropped if not granted. Add `FW-ADV-016`. |

---

## 3. Design

### 3.1 Egress transport: the `connect()` supervisor (G1, G3, G4)

FEP-1 specifies *what* host-scoped egress permits. What it leaves open is how an unmodified HTTP
client — `node`, `curl`, `git`, `pip` — reaches the Gateway, when all the confined process has is an
inherited fd. Clients need a TCP endpoint.

- Omnigent answers with a network namespace plus an in-namespace TCP relay.
- Landlock alone cannot answer: `ConnectTcp` is port-only, so granting the relay port grants that
  port on every host. The evaluation shows this is enough to exfiltrate.

**Linux: seccomp user notification.** For the `AllowHosts` posture, the Confiner installs a seccomp
filter that returns `SECCOMP_RET_USER_NOTIF` for `connect()` on AF_INET, AF_INET6 and AF_UNIX
sockets. The listener fd is passed to the spawning `formwork` process, which is outside the sandbox,
over the spawn socketpair. That process is the supervisor, a Gateway component. For each notification
it:

1. copies the `sockaddr` out of the target and then validates the notification id
   (`SECCOMP_IOCTL_NOTIF_ID_VALID`);
2. decides, using its own copy;
3. if allowed, performs the connection itself. It opens a TCP socket to the Gateway's egress
   listener, registers that socket's local port with the Gateway as an authenticated seam
   connection, and installs the socket in place of the target's fd with
   `SECCOMP_IOCTL_NOTIF_ADDFD` + `SECCOMP_ADDFD_FLAG_SETFD`, returning 0;
4. otherwise returns `EACCES` and emits a violation record ([FW-FID5](fep-1.md#fw-fid5)).

The kernel never re-reads the target's buffer and the target never performs the connection, so the
time-of-check/time-of-use weakness of user notification with pointer arguments does not apply. The
decision acts on a copy, and the action belongs to the supervisor.

The same filter handles the other paths out:
- **UDP:** `socket()` for `SOCK_DGRAM` on AF_INET/6 is denied outright.
- **TCP Fast Open:** `sendto`/`sendmsg` with a non-null address on a stream socket is denied.

This closes G3 for the `AllowHosts` posture. Under `AllowHosts` the client does not resolve names:
the proxy resolves in the Gateway, which is where [FW-ADV-008](fep-1.md#fw-adv-008) pins DNS.

For **AF_UNIX pathname** sockets (G4):
- The supervisor resolves `sun_path` against the target's `/proc/<pid>/root` and `cwd`, opening it
  `O_PATH` on the supervisor side.
- It allows the connect if the socket is granted (§3.1.1) or if the socket was bound inside the
  session.
- If allowed, it connects through `/proc/self/fd/<n>` and injects the result. Otherwise it returns
  `EACCES`.

This mechanism makes three things one:
- the transport for [FW-EGR1](fep-1.md#fw-egr1);
- on-demand fd minting, the `formwork.md` §11 "fd-minting default" question;
- the connection path that is authenticated by construction, which is what
  [FW-EGR6](fep-1.md#fw-egr6) requires.

The Gateway's egress listener accepts a connection only when its source port was registered by the
supervisor. A co-resident process that connects to the listener has no registration and is refused.
No proxy token is needed.

**Kernel floor.**
- `SECCOMP_IOCTL_NOTIF_ADDFD` with `SETFD` needs Linux 5.9 or later. This is below the Landlock ABI 4
  floor (6.7) that the port tier already needs.
- `confine-self` has no outside process to act as supervisor, so under that posture `AllowHosts` is
  reported `Unenforceable` and fails loudly when requested.

**Optional namespace path.** Where unprivileged user namespaces exist and the namespace tier
(§3.3) is requested, the Confiner can instead place the session in a network namespace with only
`lo`, and start the relay in the namespace on the Seam. This is Omnigent's shape. The supervisor
stays the default because it needs no user namespace, and bubblewrap fails in exactly the
environments where user namespaces are missing: Docker's default seccomp profile, and distributions
that restrict them through AppArmor.

**macOS.**
- The SBPL policy grants only `(remote tcp "localhost:<P>")` for the Gateway's egress listener,
  replacing `*:port`.
- The listener requires a per-session `Proxy-Authorization` credential. The launcher delivers it
  inside `HTTP(S)_PROXY`.
- The confused-deputy exposure is limited to same-uid processes that can read the agent's
  environment. The report says so ([FW-EGR6](fep-1.md#fw-egr6) is `Partial` on macOS).
- UDP is covered by the existing `(deny network*)`. Pathname AF_UNIX gating is already `Enforced`
  on macOS.

#### 3.1.1 Granting a unix socket

A socket a session needs, such as `SSH_AUTH_SOCK` for a `git` push the operator wants, is named with
the existing `allow` path verb on the socket path. Growth: no new verb. Its meaning is extended to
connect for socket files, and `explain` shows it. Catalog entries whose env var names a socket
(ssh-agent) stay floor-denied unless excluded ([FW-CRED5](../formwork.md#fw-cred5)).

### 3.2 Inspection and credential brokering (G1 method/path, G2)

FEP-1 lists TLS interception and credential masking as non-goals, "revisit only if a concrete
requirement demands request-body policy". Two concrete requirements now exist:
- restricting a writable API to a path scope, for example `POST api.github.com/repos/acme/**` but not
  other orgs. With SNI/CONNECT-level scoping, any repo on the allowed host can be written;
- the `formwork.md` §11 credential-brokering question, which the catalog is now shaped to answer.

This FEP therefore adds an **inspected** host grade, opt-in per host. The CONNECT/SNI grade from
FEP-1 stays the default for plain host grants, and stays `Partial` per
[FW-EGR5](fep-1.md#fw-egr5).

**Inspected hosts.**
- A host rule that carries `methods`, `paths` or a brokered credential is inspected:
  - the Gateway terminates TLS with a leaf certificate minted for the SNI and verified against the
    CONNECT target and the `Host` header;
  - it then evaluates the request line against the rule and re-originates the request upstream with
    the host trust store.
- For inspected hosts, host identity is `Enforced`: SNI, `Host` and the upstream certificate are
  checked against one another.
- **CA:** generated in memory per session.
  - The private key never touches disk. Omnigent caches its key under `~/.cache` at 0600; this is
    the improvement over that.
  - The certificate, concatenated with the host bundle, is written read-only into the session
    scratch.
  - The launcher points `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`,
    `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` and `PIP_CERT` at it.
  - A client that pins certificates or ignores these variables fails the handshake: fail closed.
- **Request canonicalization before matching.**
  - Percent-decode unreserved characters, then remove dot-segments (RFC 3986 §5.2.4).
  - Reject encoded `/` (`%2F`), NUL and backslash, and requests carrying both `Content-Length` and
    `Transfer-Encoding`.
  - Match the path without the query.
  - Omnigent's matcher does not normalize, so `/repos/acme/../other` matches `/repos/acme/**` there.
    `FW-ADV-017` is that case.
- **Protocol.** Inspected connections negotiate HTTP/1.1 through ALPN. HTTP/2 inspection is an open
  question (§8).

**Brokering.**
- Catalog entries gain an optional `broker` block with three fields:
  - `hosts`: the hosts the credential may be presented to;
  - `scheme`: `bearer`, `basic`, or `header:<name>` (Anthropic uses `x-api-key`, which Omnigent's
    `Authorization`-only injector cannot express);
  - `source`: the existing catalog env var or file.
- A blueprint lists `broker-credentials = ["github", "anthropic"]`. For each listed type:
  - **The floor is unchanged.** The launcher still strips the variable and the confiner still
    denies the file. The bytes never enter the sandbox.
  - **The Gateway reads the source at session start** (and on a stated refresh interval), holding it
    outside the Confiner.
  - **Placeholder:** the launcher sets the catalog env var to a random placeholder
    (`fwcred_<type>_<nonce>`), so a client that refuses to start without the variable still runs.
  - **Rewrite:** on an inspected request to a bound host, the Gateway replaces the placeholder
    wherever the scheme's header carries it. If the header is absent, it adds the header.
  - **Refusal:** a placeholder sent to any other host is refused with a violation record. It never
    leaves the Gateway.
- Brokering a type makes its bound hosts inspected. The compiler rejects a brokered type whose hosts
  are not in the allowlist, loudly at compile time.
- **Out of scope for brokering:**
  - request-signing schemes (AWS SigV4, GCP service-account JWT minting): these need a signer, not a
    header;
  - SSH agent forwarding.

  Both are recorded in §8.

### 3.3 Namespace tier (G5)

This is an optional Confiner tier, requested by the blueprint (`isolate`, §6), because PID
isolation changes what `ps`, debuggers and IDE bridges see. Transparency is the default.

**Linux, when unprivileged user namespaces are available.**
- **Namespaces:** the confined child is placed in new user (uid and gid mapped to themselves), PID,
  IPC, UTS and mount namespaces.
- **Order:** this happens before Landlock and seccomp are installed. The seccomp baseline keeps
  denying `CLONE_NEWUSER` and the mount family afterwards
  ([FW-ISO8](../formwork.md#fw-iso8)).
- **Mounts:** a fresh `procfs` on `/proc`, and a `tmpfs` on `/tmp` (the private `/tmp`).
- **Filesystem view:** no other mount changes. The view is the host's, so paths are unchanged, and
  that is still a Formwork property. Landlock remains the file boundary.
- **Init:** a minimal init owned by Formwork runs as PID 1 of the namespace. It reaps processes and
  forwards signals; the agent is its child.

**Without user namespaces.**
- The tier is `Unenforceable`, and a blueprint that requests it fails loudly
  ([FW-INV6](../formwork.md#fw-inv6)).
- The private-`/tmp` half has a fallback without namespaces: the launcher creates a per-session
  directory, sets `TMPDIR`/`TMP`/`TEMP`, and grants writes there instead of `/tmp/**`. It is reported
  `Partial`, because tools that hardcode `/tmp` break.

**Stacked under Omnigent's bwrap** (evaluation Option B), the outer layer already provides this tier
and the blueprint leaves it unset.

### 3.4 macOS Seatbelt base (G6)

The base stays `(allow default)`, for transparency, and gains denies:
- `(deny signal (target others))` and `(deny process-info* (target others))`, with a re-allow for
  the session's own process group;
- `(deny iokit-open)`, with re-allows for the classes developer tools need, collected by a spike;
- `(deny mach-priv-host-port)` and `(deny mach-priv-task-port)`.

Each is reported by name. Whether these ship in the default profile or only in the FEP-1 `strict`
profile is decided by the spike's transparency results against real toolchains
([FW-E2E-020](../formwork.md#fw-e2e-020)..023).

---

## 4. Proposed requirements (draft numbering — anchored on landing)

Continues existing families: EGR, ISO, CRED, FID and GW. No new family.

| Req | Requirement |
|---|---|
| `FW-EGR7` **Supervised connect (Linux)** | Under the host-allowlist posture, the Confiner shall deliver every `connect()` on AF_INET, AF_INET6 and AF_UNIX sockets to a supervisor outside the sandbox. The supervisor shall perform any allowed connection itself and install the result in the target, so that no confined process completes a `connect()` of its own. |
| `FW-EGR8` **Registered egress** | The Gateway egress listener shall accept a connection only if its source endpoint was registered by the supervisor (Linux) or the connection presents the session's proxy credential (macOS). |
| `FW-EGR9` **Inspected host rule** | For a host rule that names `methods`, `paths` or a brokered credential, the Gateway shall terminate TLS, verify that the SNI, `Host` header and CONNECT target agree, and admit a request only if its method and canonicalized path (`FW-EGR10`) match the rule. |
| `FW-EGR10` **Request canonicalization** | Before matching, the Gateway shall remove dot-segments, decode percent-encoded unreserved characters, and reject any request that contains an encoded `/`, a NUL, a backslash in the path, or both `Content-Length` and `Transfer-Encoding`. |
| `FW-EGR11` **Ephemeral CA** | The Gateway shall generate the inspection CA in memory per session. It shall not write the CA private key to any file, nor expose it to any confined process. |
| `FW-CRED10` **Brokered credential** | For each type in `broker-credentials`, the Launcher shall strip the type's env var and the Confiner shall deny its files exactly as for an unlisted type ([FW-CRED4](../formwork.md#fw-cred4)). The Gateway shall hold the credential outside the sandbox. |
| `FW-CRED11` **Placeholder binding** | When a brokered type has an env var, the Launcher shall set it to a per-session placeholder. The Gateway shall replace the placeholder only in requests to that type's bound hosts, and refuse, with a violation record, any request that carries it to another host. |
| `FW-CRED12` **Broker host closure** | The compiler shall reject a blueprint that brokers a type whose bound hosts are absent from the host allowlist. |
| `FW-ISO10` **Namespace tier** | When a blueprint requests `isolate`, the Confiner shall place the session in new user, PID, IPC, UTS and mount namespaces, with a fresh `/proc` and a private `/tmp`, before installing Landlock and seccomp. If the host cannot create these namespaces, it shall fail loudly. |
| `FW-ISO11` **UDP closure** | Under the host-allowlist posture, the Confiner shall deny AF_INET and AF_INET6 `SOCK_DGRAM` socket creation. Under the port posture, the FidelityReport shall mark UDP unrestricted. |
| `FW-ISO12` **Pathname socket mediation (Linux)** | Under supervised connect, the supervisor shall refuse `connect()` to a pathname AF_UNIX socket unless the socket path is granted by an `allow` rule or was bound by a process in the session. |
| `FW-ISO13` **Seatbelt cross-process denies** | The macOS profile shall deny `signal` and `process-info*` against processes outside the session, and deny `mach-priv-host-port`/`mach-priv-task-port`. |
| `FW-FID8` **Egress report lines** | The FidelityReport shall carry separate verdicts for host scoping, per-host inspection, UDP, pathname socket mediation, brokering, and the namespace tier. |

Invariant:

- `FW-INV13` **Broker non-disclosure.** No brokered credential's bytes appear in a confined
  process's environment, in a file readable by it, or in any response the Gateway returns to it.
  This is tested to falsify.

Tests (draft):

- `FW-E2E-075` **Supervised connect admits only the Gateway (Linux).** Under
  `AllowHosts(["allowed.test"])`:
  - a request through `HTTP_PROXY` reaches the fixture;
  - a direct `connect()` to the fixture's address, to `169.254.169.254`, and to the Gateway listener
    without registration each fails;
  - UDP `socket()` fails.
  Each denial has a violation record.
- `FW-E2E-076` **Pathname socket (Linux).** A socket bound by a host process outside the session is
  refused. A socket named by an `allow` rule connects. A socket bound inside the session connects.
- `FW-E2E-077` **Inspected path scope.** With `POST allowed.test/repos/acme/**`, a POST to
  `/repos/acme/x` passes, while a POST to `/repos/other/x` and a GET to `/repos/acme/x` are refused.
- `FW-E2E-078` **Brokered header.**
  - With `broker-credentials = ["anthropic"]` bound to `allowed.test`, the fixture receives the real
    `x-api-key`.
  - The confined process's `env` shows the placeholder, and reading the catalog file is denied.
  - The same placeholder sent to `other.test` is refused.
- `FW-E2E-079` **Namespace tier.** With `isolate` requested:
  - `/proc` in the session lists only session PIDs;
  - `/tmp` is empty at start and not shared with the host;
  - `kill` of a host PID fails.
  On a host without user namespaces the run fails loudly and never starts unisolated.
- `FW-ADV-016` **Gateway frame bypass (D6).** A batch array, a non-JSON frame, and an id-less
  `tools/call` for a shaded tool each fail to reach the backend.
- `FW-ADV-017` **Path traversal against an inspected rule.** Each of these, sent against
  `allowed.test/repos/acme/**`, is refused or canonicalizes outside the scope:
  - `/repos/acme/../other/x`
  - `/repos/acme/%2e%2e/other/x`
  - `/repos/acme%2F..%2Fother/x`
  - a `Content-Length` + `Transfer-Encoding` smuggle
- `FW-ADV-018` **Supervisor race.** A multithreaded target rewrites its `sockaddr` buffer from a
  second thread in a tight loop while `connect()` is pending. Pass: the connection lands only where
  the supervisor's copy was allowed, never at the rewritten address.

---

## 5. Parity after this FEP

| Capability | Omnigent (bwrap/Seatbelt) | Formwork today | Formwork after FEP-5 |
|---|---|---|---|
| Egress host allowlist, mandatory | Enforced (netns / SBPL) | Not provided | Linux Enforced (supervisor), macOS Enforced (SBPL `localhost`) |
| Method/path rules | Enforced (MITM), no path normalization | Not provided | Enforced on inspected hosts, canonicalized |
| Credential injection | `Authorization` only; CA key cached on disk | Not provided | Any header scheme; ephemeral CA; floor still enforced |
| Private IP / metadata block | Enforced | Not provided under `Ports` | Enforced under `AllowHosts` ([FW-EGR4](fep-1.md#fw-egr4)) |
| UDP | Closed with egress | Open under `Ports` (unreported) | Closed under `AllowHosts`, reported under `Ports` |
| Pathname AF_UNIX | Unmounted, so unreachable | Unmediated (Linux) | Mediated (Linux supervisor), Enforced (macOS) |
| PID/IPC/UTS, `/proc`, private `/tmp` | Enforced | Not provided | Opt-in tier where user namespaces exist; `/tmp` fallback `Partial` |
| Runs without user namespaces | No (bwrap fails) | Yes | Yes, except the namespace tier |
| macOS cross-process signal/info | Self only | Open | Session only |
| Windows | Job Object kill-on-close only | Not provided | Not provided (non-goal) |
| ENOENT invisibility | Yes (Linux) | No | No (non-goal, `formwork.md` §3) |

The rows where Formwork already leads are unchanged:
- credential floor under broad grants;
- exec allowlist;
- tamper vectors (on Linux after D1);
- create/modify split;
- `explain`/`learn`;
- MCP shading.

After FEP-5, Formwork can serve as an Omnigent backend on Linux without bwrap, including when egress
rules are set. The evaluation's stacked arrangement (Option B) is still available for hosts where
both layers are wanted.

---

## 6. Surface changes (each measured against Growth)

- **Blueprint schema.**
  - **Host rules:** FEP-1's `AllowHosts([HostPattern])` becomes `AllowHosts([HostRule])`, where a
    `HostRule` is a `HostPattern` with optional `methods` and `paths`. A bare string still parses as
    a host-only rule (expand → migrate → contract). The shape was considered as a new axis and
    rejected: it is the same net axis at a finer grain.
  - **`broker-credentials`:** a list of catalog types. The typed complement of `allow-credentials`:
    one exposes the credential's bytes, the other brokers its use. A type in both lists is a compile
    error.
  - **`isolate`:** a list drawn from `["pid", "ipc", "uts", "tmp"]`. Considered as automatic behavior
    and rejected: PID isolation is visible to tools, and transparency is the default.
- **Catalog.** An optional `broker` block per entry (`hosts`, `scheme`). It is data in the embedded
  catalog, so a catalog version bump.
- **Dependencies (the hardest no).**
  - Inspection needs a TLS stack and certificate minting (`rustls`, `rcgen`) and an HTTP/1.1 codec
    (`hyper`).
  - All of them sit in `formwork-gateway`, which is already the tokio layer. No other crate gains a
    dependency.
  - The supervisor needs no new crate. It uses raw `seccomp(2)` with `SECCOMP_FILTER_FLAG_NEW_LISTENER`
    beside the existing `seccompiler` baseline.
  - The TLS stack is justified because G1's method/path rules and G2 cannot be expressed without it.
    `rustls` is chosen over OpenSSL to keep the trust base memory-safe.
- **CLI.** No new subcommand. `explain` gains the socket-path and host-rule verdicts.
- **Embedding.** Two additions, both for Omnigent-style launchers:
  - a `--blueprint -` stdin input, so a generated blueprint needs no temp file;
  - publishing the release binary as a platform wheel, so a Python orchestrator can depend on it.
    This is the pattern used by `ruff` and `uv`, and it does not make `py/` product code.

---

## 7. Proposed amendments to the landed docs (apply on landing)

- **`docs/fep-1.md` Non-goals.** Replace the TLS-interception and credential-masking bullets with a
  pointer to FEP-5 §3.2, which states the requirement that reopened them. The CONNECT/SNI grade stays
  the default.
- **`formwork.md` §9 fidelity table.** Add rows for supervised connect, UDP, pathname-socket
  mediation, inspection, brokering, and the namespace tier. Correct the Linux UDP and AF_UNIX rows
  per D4/D5.
- **`formwork.md` §11.** Close "fd-minting default" (on-demand, through the supervisor) and
  "Credential brokering" (FEP-5 §3.2). Narrow "Linux gateway egress isolation build-vs-buy" to the
  optional namespace path.
- **`constitution.md` Vocabulary.**
  - **broker** = the Gateway presenting a credential it holds on the agent's behalf, never
    disclosing its bytes;
  - **placeholder** = the per-session stand-in value the Launcher sets for a brokered env var;
  - **inspect** = TLS termination at the Gateway for a host rule that needs request-level policy;
  - **supervise** = the Gateway receiving a confined `connect()` through seccomp user notification
    and minting the connection itself.

---

## 8. Open questions

- **HTTP/2 on inspected hosts.** Offer only HTTP/1.1 through ALPN (simple; most clients downgrade),
  or add an h2 codec (more dependencies, and it is needed for gRPC APIs). Decided by a spike against
  the model-API clients Formwork wraps.
- **Request-signing credentials.** AWS SigV4 and GCP token minting need a signer in the Gateway
  rather than header substitution. Deferred. Until then the types stay floor-denied or excluded.
- **Placeholder in request bodies.** Some clients send the key in a JSON body or query string.
  Substitution is limited to the scheme's header here. Bodies stay out of scope unless a catalog
  type requires them.
- **Transparent mode.** The supervisor could redirect *any* allowed `connect()`, removing the need
  for proxy env vars. That needs a DNS answer path (a stub that resolves only allowlisted names),
  which this FEP does not specify.
- **Namespace-tier init.** Whether the PID-1 reaper is a forked Formwork process or the launcher
  itself re-parented. The pre-exec code is allocation-free, which constrains the choice.
- **Seatbelt `iokit-open` classes.** The re-allow set comes from the §3.4 spike. If the set is too
  broad to be meaningful, the deny ships only in the `strict` profile.
- **Landlock pathname-socket scoping.** If a future Landlock ABI mediates pathname AF_UNIX
  `connect()`, `FW-ISO12` moves from the supervisor to Landlock, and the supervisor keeps only
  egress.
