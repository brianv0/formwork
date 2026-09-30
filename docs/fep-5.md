# FEP-5 (landed): host-scoped egress, credential brokering, host-service channels, and process isolation on both backends

**Formwork Enhancement Proposal 5 — landed, macOS characterization owed.** Companion to
`formwork.md` (design + end-to-end spec), `constitution.md` (doctrine), and `docs/fep-1.md`
(host-scoped egress, which this FEP gives a transport). Motivated by
`docs/omnigent-integration-eval.md`.

**Status.** Phases 0–4 are implemented on both backends, with the opener shim and host and channel
discovery; `docs/fep-5-plan.md` records how, every departure from the text below, and what is
still owed. The requirements stay defined here, anchored, and code cites them bare; the §7
amendments are applied to `formwork.md`, `docs/fep-1.md`, `docs/unstated-requirements.md` and
`constitution.md`. What remains is the macOS characterization suite (§6.3) and the macOS-only
tests that depend on it; until it runs, the report keeps every macOS verdict it would settle at
`Partial`. The draft-numbering note below is kept as the record of how the numbers were chosen:
`FW-E2E-074` and `FW-ADV-015` were the highest landed; `FW-INV12` and `FW-DISC7`–`FW-DISC10` were
drafted or reserved by FEP-4; `FW-EGR6` and `FW-FID5` were drafted by FEP-1. Three PRs touched this
FEP's ground and are accounted for in §2 and §8: #28 (spec-conformance fixes), #29 (UDP/raw
closure under the port tier), #30 (adversarial and invariant coverage).

**Platform stance.** Each gap is closed on both backends, or the report states the difference
(§3.6). Blueprint vocabulary is portable: no field value is a platform name, and the same blueprint
means the same thing on both backends ([FW-XR6](../formwork.md#fw-xr6)). A macOS claim not yet
observed on Seatbelt is marked **(characterize)** and is settled by the characterization suite
(§6.3) before the requirement it supports is anchored. Nothing is reported `Enforced` from reasoning
alone ([FW-INV5](../formwork.md#fw-inv5)).

---

## 1. Problem

Omnigent's OS sandbox (bubblewrap on Linux, `sandbox-exec` with `(deny default)` on macOS, and a
mandatory L7 egress proxy) was compared with Formwork in `docs/omnigent-integration-eval.md`. Each
system covers much of what the other lacks. Formwork leads on the capability model: the credential
floor under broad grants, the exec allowlist, tamper-vector write-subtract, the create/modify split,
the FidelityReport with `explain` and `learn`, and MCP shading. The gaps, per platform:

| # | Gap | Omnigent Linux | Omnigent macOS | Formwork Linux | Formwork macOS |
|---|---|---|---|---|---|
| G1 | Mandatory egress, allowlisted by host, method and path | netns + proxy | SBPL allows `localhost:<relay>` only | `Deny` / `Ports` | `Deny` / `Ports` |
| G2 | Credential injection: the agent never holds the token | proxy injects `Authorization` | same | deny or expose ([FW-CRED5](../formwork.md#fw-cred5)) | same |
| G3 | UDP closed | closed (netns) | closed (`deny default`) | open under `Ports`; closed by PR #29 | closed (`deny network*`) |
| G4 | Pathname AF_UNIX (Docker, ssh-agent, session bus) | not mounted | denied except the relay | `connect()` unmediated | closed except the resolver literal |
| G5 | Process isolation: other PIDs, `/proc`, IPC, private `/tmp` | namespaces | `signal` / `process-info` limited to self | none; shared `/tmp` | none; shared `/tmp` and `$DARWIN_USER_TEMP_DIR` |
| G6 | Privileged kernel interfaces (IOKit, `mach-priv*`) | n/a (seccomp) | not granted | seccomp baseline ([FW-ISO8](../formwork.md#fw-iso8)) | allowed: `(allow default)` has no baseline |
| G7 | Host-service channels: a service outside the sandbox that runs code, opens URLs, or releases secrets for the confined process | closed (private `$XDG_RUNTIME_DIR`, `DBUS_*` stripped) | AppleEvents/`lsopen` presumed closed **(characterize)**; all `mach-lookup` allowed | open: session bus, `systemd --user`, X11/Wayland sockets | open: `appleevent-send`, `lsopen`, all `mach-lookup` |
| G8 | Other processes' arguments and environment | hidden (PID ns) | `kern.procargs2` readable **(characterize)** | open for same-uid processes (verified: a confined process read a sibling's `environ` and `cmdline`) | `kern.procargs2` returns same-uid environments **(characterize)** |

G7 is the largest gap. A confined process that can reach a host service acting on its behalf leaves
the sandbox without breaking anything in it. On macOS, `(allow default)` permits `open <url>`
(LaunchServices starts the browser outside the sandbox), `osascript … do script` (a shell outside
the sandbox), `pbpaste`, and `security find-generic-password -w` for keychain items that do not
prompt. On Linux, when a user session is running, an unmediated socket permits `systemd-run --user`,
`xdg-open`, the Secret Service, and the X11 or Wayland sockets. Container and CI hosts run no user
session, which is why the Linux evaluation found this by reading code rather than by a denial; the
verification plan (§6.1) and `detect` (`FW-FID10`) both account for that blind spot.

The closure, within the closed concept list: G1, G3 and G4 are one Linux mechanism, a `connect()`
supervisor, which is the on-demand form of fd minting ([FW-GW6](../formwork.md#fw-gw6)); on macOS
the same three are static SBPL rules. G2 extends the Catalog and the Gateway. G5 and G8 are an
opt-in Confiner tier plus one default-on deny. G6 and G7 extend the anti-shedding baseline to both
backends.

### 1.1 Constraints this FEP holds to

- **No new concept.** The supervisor is the Gateway minting fds over the Seam. Brokering is the
  Catalog plus the Gateway. The isolation tier and the channel baseline are Confiner mechanism.
- **Kernel-first transport.** The confined process has no network path around the Gateway
  ([FW-XR7](../formwork.md#fw-xr7)). Proxy environment variables help clients find the Gateway;
  they are never the enforcement.
- **Honesty.** Each new capability has a FidelityReport line per backend. A request the host cannot
  provide is refused before the workload starts ([FW-XR9](../formwork.md#fw-xr9)). A `Partial`
  verdict runs, with a report line and one operator-channel line naming the residual.
- **Portable vocabulary.** New blueprint values name what is granted (`clipboard`, `os-keyring`,
  `processes`), never how one platform implements it. The compiler maps each value per backend.
- **Transparency** ([FW-TRA2](../formwork.md#fw-tra2)). The macOS base stays `(allow default)`.
  A new default deny ships only after passing the toolchain gate ([FW-E2E-020](../formwork.md#fw-e2e-020)..023)
  and the agent-example gate (`FW-E2E-084`); a deny that fails either moves to the `strict` profile
  and the default reports it `Partial`.
- **Growth.** No new subcommand and no new CLI flag. Two new blueprint fields (`channels`,
  `isolate`) and two extended ones (`rules`, `allow-credentials`), each justified in §4. TLS
  termination is opt-in per host.

---

## 2. Defects (Phase 0)

Each row is a fix to an existing requirement's implementation or report, so none needs a new ID.
Rows marked *verified* were reproduced on a Linux 6.18 host (Landlock ABI 7).

| # | Platform | Defect | Violates | Fix |
|---|---|---|---|---|
| D1 | Linux | `extends = ["builtin:default"]` fails at enforce time: `any-depth pattern **/.git/config cannot be a rooted Landlock rule`. `write-subtract` `**/` rows reach the Landlock builder (`formwork-compile/src/lib.rs:440`) while the floor's are withheld (`:432`). The README quickstart does not start on Linux (verified). PR #28 adds six more `**/` rows to the same list. | [FW-INV5](../formwork.md#fw-inv5), [FW-XR6](../formwork.md#fw-xr6) | Withhold these rows as the floor's are withheld; report the tamper-vector set `Partial` with the reason. Add an E2E test that runs the README quickstart verbatim on both CI OSes. |
| D2 | Linux | `formwork explain $CWD/sub/.env` answers "denied (credential floor)" while the file is readable. | [FW-INV5](../formwork.md#fw-inv5), [FW-FID6](../formwork.md#fw-fid6) | `explain` prints the per-host verdict ("withheld on this host") beside the model verdict. |
| D3 | Linux | New files cannot be created in the project root: `protect_policy_inputs` write-denies `FORMWORK.toml` and its derived files, which splits the root (verified). | [FW-TRA1](../formwork.md#fw-tra1) | Accept `.formwork/blueprint.toml` as a discovery location beside `FORMWORK.toml` (the [FW-BP8](../formwork.md#fw-bp8) walk is otherwise unchanged) and keep derived files in `.formwork/`, so the protected hole is one directory. `run` and `explain` say when a root is split and name the layout. Alternatives: §9. |
| D4 | Linux | Under `Ports`, UDP and raw sockets were unrestricted while the report said `net-default-deny enforced`. | [FW-INV5](../formwork.md#fw-inv5), [FW-ISO3](../formwork.md#fw-iso3) | Fixed by PR #29 (seccomp denies inet `SOCK_DGRAM`/`SOCK_RAW` under the port tier; the report is honest). Consequence: under `Ports` on Linux there is no name resolution at all, since UDP is closed and no Gateway runs; host rules (§3.1) restore resolution through the Gateway. `FW-ISO11` extends the same deny to the host-allowlist posture. |
| D5 | Linux | The CrossDomainSocket `Partial` reason omits that pathname `connect()` is unmediated, which includes the session bus and `systemd --user` (an escape, G7). | [FW-INV5](../formwork.md#fw-inv5) | Reword the reason and name the escape. The default scrub strips `DBUS_SESSION_BUS_ADDRESS`, `DISPLAY` and `WAYLAND_DISPLAY`, which hides the sockets without closing them, so the verdict stays `Partial`. `FW-ISO12` closes it. |
| D6 | both | The Gateway forwards non-JSON frames, JSON-RPC batch arrays, and id-less `tools/call` / `resources/read` / `prompts/get` unfiltered. (PR #28 closes the separate `resources/subscribe` and `completion/complete` passthrough.) | [FW-GW2](../formwork.md#fw-gw2), [FW-GW4](../formwork.md#fw-gw4) | Close the connection on a non-JSON frame; refuse batch arrays (MCP 2025-06-18 removed batching); check gated methods against policy whether or not they carry an `id`. Test: `FW-ADV-016`. |
| D7 | macOS | No report line for host-service channels or privileged interfaces. | [FW-INV5](../formwork.md#fw-inv5), [FW-XR1](../formwork.md#fw-xr1) | Report both `Unenforceable` now; `FW-ISO13`/`FW-ISO14` close them. |
| D8 | macOS | The port tier's mDNSResponder literal is a name-resolution channel the report does not list; after PR #29 it is also asymmetric with Linux, where the port tier resolves nothing. | [FW-INV5](../formwork.md#fw-inv5), [FW-XR6](../formwork.md#fw-xr6) | Report it under the port tier; drop the literal under the host-allowlist posture (`FW-EGR12`). |
| D9 | Linux | `formwork.md` §9 names a Landlock "pathname-socket scope" that no ABI provides; scoping covers abstract sockets and signals. A confined process connected to an out-of-domain pathname socket and read a same-uid sibling's `environ` (both verified on ABI 7). PR #30's `FW-ADV-006` capable-kernel arm asserts the opposite and would fail on an ABI ≥ 6 runner. | [FW-INV5](../formwork.md#fw-inv5); honesty is bidirectional (constitution Errors) | Correct §9 (done on this branch); add the report lines `process-environment disclosure: Partial (same-uid readable)` and the D5 reason. PR #30's arm is reworded to the reported-gap form; `FW-E2E-076` supersedes it once `FW-ISO12` lands. |
| D10 | both | `extends = ["builtin:default"]` plus `mode = "unveil"` is not closed: the profile carries an explicit `reads = ["/**"]`, explicit grants survive the mode flip ([FW-E2E-060](../formwork.md#fw-e2e-060) case 4), and `explain /etc/hostname` answers `granted, rule /**, builtin:default` (verified). | [FW-INV6](../formwork.md#fw-inv6), [FW-BP7](../formwork.md#fw-bp7) | The ambient universe is a property of `read-mode`, not a row: remove `reads = ["/**"]` from `builtin:default`, and make the compiler refuse a `/**` read row under `closed`, naming the layer it came from. |
| D11 | Linux | Under `closed`, `/proc/self` is granted to the direct child only (a post-fork inode grant, `landlock.rs:305-313`); a grandchild's `/proc/self` is a different directory and is denied. `/etc` is not in the closed-mode essentials. A shell that launches `node`, `cargo` or `go` fails (verified). | [FW-TRA1](../formwork.md#fw-tra1), [FW-TRA2](../formwork.md#fw-tra2) | Add `/etc` (read) to the Linux essentials, matching macOS's `/private/etc`. Grant `/proc` read in closed mode and report process-environment disclosure `Partial` (D9). |

---

## 3. Design

### 3.1 Egress transport (G1, G3, G4)

FEP-1 specifies what host-scoped egress permits. This section specifies how an unmodified HTTP client
reaches the Gateway, and how each platform guarantees that the Gateway's endpoint is the only endpoint
the confined process can reach.

`formwork run` hosts the Gateway in-process whenever the blueprint carries a host rule (§4). The
operator starts nothing else. The Launcher sets `HTTP(S)_PROXY`, `NO_PROXY=` (empty), the CA
variables (§3.2) and `TMPDIR` in the child, and overrides an inherited proxy value with an
operator-channel line. The `formwork gateway` subcommand stays MCP-only. Under `confine-self` no
process sits outside the sandbox to host the Gateway, so a host rule is refused before exec
([FW-XR9](../formwork.md#fw-xr9)) and the refusal names the spawn posture.

#### Linux: seccomp user notification

Under a host rule the Confiner installs a filter that returns `SECCOMP_RET_USER_NOTIF` for
`connect()` on AF_INET, AF_INET6 and AF_UNIX sockets. The listener fd goes to the spawning
`formwork` process (the supervisor, part of the Gateway) over the spawn socketpair. For each
notification the supervisor:

1. copies the `sockaddr` and validates the notification id (`SECCOMP_IOCTL_NOTIF_ID_VALID`);
2. decides, using its copy;
3. if allowed, opens a TCP socket to the Gateway listener, registers the socket's local port as an
   authenticated seam connection, installs it in the target with `SECCOMP_IOCTL_NOTIF_ADDFD` +
   `SECCOMP_ADDFD_FLAG_SETFD`, and returns 0;
4. otherwise returns `EACCES` and emits a violation record ([FW-FID5](fep-1.md#fw-fid5)).

The kernel never re-reads the target's buffer and the target never completes a connection, so the
pointer-argument time-of-check/time-of-use weakness of user notification does not apply. The same
filter keeps PR #29's inet `SOCK_DGRAM`/`SOCK_RAW` deny, denies `sendto`/`sendmsg` carrying an
address on a stream socket (TCP Fast Open), and delivers addressed `sendto`/`sendmsg` on AF_UNIX
datagram sockets to the supervisor, because a datagram socket reaches a path without `connect()`
(`/dev/log` is the common case).

For pathname AF_UNIX sockets the supervisor resolves `sun_path` against the target's
`/proc/<pid>/root` and `cwd`, opening it `O_PATH` on its own side; allows the connection only if the
socket is granted (§3.1.1) or was bound inside the session; and, if allowed, connects through
`/proc/self/fd/<n>` and injects the result.

The Gateway listener accepts only connections whose source port the supervisor registered; a
co-resident process is refused, which satisfies [FW-EGR6](fep-1.md#fw-egr6) with no proxy token.
The mechanism needs Linux 5.9 or later, below the Landlock ABI 4 floor (6.7) the port tier already
needs. Where unprivileged user namespaces exist and the isolation tier (§3.3) is requested, the
session can instead receive an `lo`-only network namespace with an in-namespace relay on the Seam.

#### macOS: static SBPL and an authenticated local endpoint

The profile keeps `(deny network*)` and re-allows exactly
`(allow network-outbound (remote tcp "localhost:<P>"))` for the session's listener. SBPL remote
filters accept only `*` or `localhost` as the host **(characterize)**, so the listener authenticates
connections itself, in two layers: a per-session credential in `HTTP(S)_PROXY`
(`http://fw:<nonce>@127.0.0.1:<P>`), and a peer-process check that maps the loopback 4-tuple to its
owning PID (`proc_pidfdinfo` / `PROC_PIDFDSOCKETINFO`) and requires that PID to belong to the
session; an unresolvable peer is refused. [FW-EGR6](fep-1.md#fw-egr6) is `Enforced` on macOS if the
peer check characterizes as reliable, otherwise `Partial` with the residual named (a same-uid
process that reads the agent's environment).

UDP and pathname sockets are closed by `(deny network*)` apart from granted literals. Under a host
rule the mDNSResponder literal is dropped; HTTP clients using a proxy do not resolve names locally,
so every lookup happens in the Gateway, which pins it ([FW-ADV-008](fep-1.md#fw-adv-008)). The
profile allows `network-bind` and `network-inbound` on `localhost:*` under every net posture, so a
confined login flow can accept the callback an unconfined browser makes to it. Seatbelt denials reach
[FW-FID5](fep-1.md#fw-fid5) through the unified-log tap after the fact, and the report says so.

#### 3.1.1 Granting a unix socket

A session that needs a socket (`SSH_AUTH_SOCK` for a `git push` the operator wants) names its path
with the existing `allow` verb; `explain` shows the grant. On Linux the supervisor admits the socket;
on macOS the compiler emits `(allow network-outbound (literal …))`. Catalog-located sockets
(ssh-agent) stay floor-denied unless excluded ([FW-CRED5](../formwork.md#fw-cred5)).

### 3.2 Inspection and credential brokering (G1 method/path, G2)

FEP-1 declared TLS interception and credential masking non-goals "unless a concrete requirement
demands" them. Two such requirements exist: path-scoped writes (`post:api.github.com/repos/acme/**`
and nothing else, which CONNECT or SNI scoping cannot express), and the credential-brokering question
of `formwork.md` §11, which the Catalog is now shaped to answer.

#### Inspected hosts

A host rule that names HTTP methods, or that a brokered credential is bound to, is *inspected*. For
such a host the Gateway terminates TLS with a leaf certificate minted for the SNI; checks that the
SNI, the `Host` header and the CONNECT target agree; canonicalizes the request (`FW-EGR11`) and
matches it against the rule; and sends the request upstream with the host trust store. Plain host
rules (`https:`) keep FEP-1's CONNECT/SNI grade, which is `Partial` per
[FW-EGR5](fep-1.md#fw-egr5). Omnigent's matcher does not canonicalize (`/repos/acme/../other/x`
matches `/repos/acme/**` there, verified against `omnigent/inner/egress/rules.py`); `FW-ADV-017`
pins that case.

#### CA and client trust

The CA is generated in memory per session and its key never touches disk. The certificate plus the
host bundle is written read-only into the session scratch, a Launcher-owned path that is readable in
every read mode (`FW-TRA9`). The Launcher points `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`,
`REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` and `PIP_CERT` at it. OpenSSL, BoringSSL,
rustls-native-certs, Node, Python and Go honor these variables on Linux; `uv` does not by default
(`UV_NATIVE_TLS=1` opts in), and the `uv` recipe in `examples/` sets it. On macOS,
Security.framework clients (Go on darwin, so `gh`; Swift `URLSession`; Apple tools) ignore them and
fail closed against an inspected host. Installing the CA into the user's keychain search list would
change trust host-wide and is excluded. The per-host verdict reads
`Enforced (env-trust clients); platform-verifier clients refused`, and `explain` prints the caveat
before the run for any brokered type whose typical client is such a client.

A client that rejects the session CA fails with an opaque error (`x509: certificate signed by unknown
authority`). The Gateway observes the `unknown_ca` alert and emits one operator-channel line naming
the host, the likely cause (the client does not read `SSL_CERT_FILE`; on macOS, the
Security.framework note), and the options: drop inspection for that host, or use a client that
honors the variable (`FW-FID9`).

#### Brokering

Brokering is a grade on the existing `allow-credentials` entry, spelled with the verb-prefix idiom
`rules` already uses:

```toml
allow-credentials = ["claude", "broker:anthropic", "broker:github"]
```

A bare type exposes the credential to the agent (the landed meaning). `broker:<type>` keeps the
floor (the variable is stripped, the file denied) and the Gateway holds the credential outside the
sandbox, reading the source at session start and at a stated refresh interval. The same type in both
forms resolves to `broker`, with an operator-channel line. An entry may also be an inline binding for
a credential the Catalog does not know:
`{ name = "ghe", env = "GHE_TOKEN", hosts = ["ghe.corp.internal"], scheme = "bearer" }`.

The Catalog `broker` block is a list of `{ hosts, scheme }` pairs, because one type needs different
schemes on different hosts: `github` is `basic` (user `x-access-token`) on `github.com` for
`git push` and `bearer` on `api.github.com` for the API. Schemes are `bearer`, `basic` and
`header:<name>` (Anthropic's `x-api-key`).

Presentation has two paths. When the type has an env var, the Launcher sets it to
`fwcred-<type>-<nonce>` after the Catalog strip and the [FW-ENV2](../formwork.md#fw-env2) scrub
have run, so a `KEY`/`TOKEN` name shape never removes it, and the Gateway substitutes the credential
where the scheme's header carries the placeholder. When a request to a bound host carries no
credential header, the Gateway adds one; this is what makes `git push` work with no credential
helper, since git sends no `Authorization` on its own. A placeholder sent to any other host is
refused with a violation record. A brokered credential requires an inspected rule for each bound
host; a blueprint that brokers a type without one fails at compile, and the message names the line
to add (`any:api.github.com/**`).

Claude Code prefers an API key over its OAuth login when `ANTHROPIC_API_KEY` is set, so a brokered
placeholder switches its auth mode; the Claude Code example brokers `anthropic` only in its API-key
variant, and its OAuth variant lifts `claude` and brokers nothing. Signing schemes (AWS SigV4, GCP
JWT minting) and SSH agent brokering are out of scope (§9).

The README-layer shape of the feature:

```toml
extends = ["builtin:default"]
rules = ["readwrite:$CWD/**", "any:api.anthropic.com"]     # this host only, inspected by the gateway
allow-credentials = ["broker:anthropic"]                   # the agent sees a placeholder, never the key
```

### 3.3 Process isolation (G5, G8)

#### Default-on: other processes' environments (`FW-ISO16`)

Environment disclosure is a credential-disclosure path, so it is not part of the opt-in tier. On
macOS the default profile denies `sysctl-read` of `kern.procargs2` **(characterize)**, which returns
the full environment of same-uid processes. On Linux, access to `/proc/<pid>/environ` is decided
by `ptrace_may_access`, and Landlock hooks that check: a confined process is refused ptrace-class
access to any process outside its domain. A process holding `CAP_SYS_ADMIN` or `CAP_PERFMON` gets
past the refusal, so a root container reads a same-uid sibling's environment while an ordinary user
does not (both verified; the first observation, from a root container, was recorded as "readable"
and is corrected here). The Linux verdicts are `Enforced` by Landlock for an unprivileged run;
`Partial` when `detect` finds `CAP_SYS_ADMIN`, `CAP_PERFMON` or `CAP_SYS_PTRACE` in the effective
set, with the residual named; `Unenforceable` without Landlock; and `Enforced` under
`isolate = ["processes"]`, where the fresh `procfs` lists only session processes. An outer PID
namespace, which `detect` recognizes from a multi-field `NSpid` in `/proc/self/status`, narrows the
residual and is named in it.

#### Default-on: a private temporary directory (`FW-TRA10`)

The Launcher creates a per-session directory, points `TMPDIR`/`TMP`/`TEMP` at it, and grants it
read-write in every read mode. `builtin:default` keeps its `/tmp/**` write grant, so tools that
hardcode `/tmp` keep working and share; the report says
`private tmp: Partial (directory form; /tmp shared by profile grant)`, and a blueprint that drops
the `/tmp/**` grant gets `Enforced`. On macOS the directory is created beneath
`$DARWIN_USER_TEMP_DIR` (`confstr(_CS_DARWIN_USER_TEMP_DIR)`), so `confstr` callers resolve inside
the session. Under `isolate = ["processes"]` on Linux the directory is a tmpfs in the mount namespace.
The directory is named in `explain` output and on the operator channel
([FW-FID7](../formwork.md#fw-fid7)).

#### Opt-in tier: `isolate`

The tier is opt-in because it changes what `ps`, debuggers and IDE bridges see. It has two portable
members.

| Member | Linux | macOS |
|---|---|---|
| `processes`: other processes are not visible, signalable or inspectable, including their arguments | user + PID namespaces with a fresh `/proc` (plus UTS); a minimal Formwork init as PID 1. `Enforced` where user namespaces exist | `(deny process-info* (target others))`, `(deny signal (target others))` with session re-allows **(characterize)**; `sysctl-read` denies on the process-enumeration MIBs. `Enforced` or `Partial` per characterization |
| `ipc`: SysV and POSIX IPC confined to the session | IPC namespace. `Enforced` where user namespaces exist | `ipc-sysv-*` denied; POSIX names restricted to a session prefix **(characterize)**. `Partial` (POSIX names are global) |

On Linux the user, PID, IPC, UTS and mount namespaces are created before Landlock and seccomp are
installed; the seccomp baseline still denies `CLONE_NEWUSER` and the mount family afterwards
([FW-ISO8](../formwork.md#fw-iso8)). A member the host cannot provide (`processes` or `ipc` on Linux
without user namespaces) is refused before spawn ([FW-XR9](../formwork.md#fw-xr9)); the refusal
names every alternative the host offers: on an AppArmor-restricted Ubuntu 24.04, the one-line
`sysctl kernel.apparmor_restrict_unprivileged_userns=0`, running under bwrap (Ubuntu ships an
AppArmor profile for it), or dropping the member. A member the host provides as `Partial` runs with
one operator-channel line. A CI matrix that spans kernels should not request `processes` in a shared
blueprint. Stacked under Omnigent's bwrap, the outer layer provides the tier and the blueprint leaves
`isolate` unset.

### 3.4 Host-service channels and privileged interfaces (G6, G7)

The anti-shedding baseline ([FW-ISO8](../formwork.md#fw-iso8)) extends to both backends and to
services that act on the process's behalf. It is on in every blueprint. A channel is lifted by name
in the `channels` field (a closed, portable enum), or through the Catalog's typed exclusion when the
channel is a credential store.

| Channel | Lifted by | macOS mechanism (SBPL deny) | Linux mechanism |
|---|---|---|---|
| `run-outside` | `channels` | `appleevent-send`; `mach-lookup` of launchd job submission and the AppleEvent server **(characterize: names)** | supervisor denies the session-bus and `systemd --user` sockets; `DBUS_*` stripped |
| `open-url` | `channels`; brokered, never a host-service lift | the Gateway opens the URL on the host; `lsopen` and `launchservicesd` stay denied | the Gateway opens the URL on the host; the session bus stays denied |
| `clipboard` | `channels` | `mach-lookup` `com.apple.pasteboard.*` | X11/Wayland sockets; abstract X11 is scoped by Landlock ABI 6 |
| `screen` | `channels` | `mach-lookup` of WindowServer/screencapture services **(characterize)** | X11/Wayland sockets |
| `camera`, `microphone` | `channels` | `iokit-open` of those classes; `mach-lookup` `com.apple.cmio.*` / `com.apple.audio.*` | `/dev/video*`, `/dev/snd/*` denied by default subtract |
| `os-keyring` | `allow-credentials` (a Catalog type) | `mach-lookup` of `securityd` / `SecurityServer` **(characterize)** | session bus `org.freedesktop.secrets` (coupled with `run-outside`, below); `$XDG_RUNTIME_DIR/keyring/*` |
| (none) | — | `mach-priv-host-port`, `mach-priv-task-port`; `iokit-open` outside the shipped allowlist | seccomp (unchanged) |

#### `open-url` is brokered

On Linux the portal, `systemd --user` and the Secret Service share one socket, `$XDG_RUNTIME_DIR/bus`;
a `connect()` supervisor sees one `sun_path` and cannot tell `OpenURI` from `StartTransientUnit`, so
lifting the socket for URLs would lift code execution. The channel therefore uses the
single-privileged-broker pattern: in every spawned session the Launcher places a Formwork-owned
`xdg-open` / `open` shim first in `PATH` and in `BROWSER`; the shim sends the URL over the Seam; the
Gateway refuses it unless `open-url` is lifted, and otherwise accepts
`http` and `https` URLs only, refuses `file:`, `javascript:` and custom schemes, records the URL on
the operator channel, and opens it with the host opener outside the sandbox. No host service is
lifted on either platform, closed mode needs no grant, and `learn` proposes the channel from the
shim's refusal record. What the agent gains is "open this web page in the user's browser", which is
the login use case.

#### The Linux session bus couples `os-keyring` with `run-outside`

Lifting the Secret Service on a Linux desktop lifts the bus, and the bus also carries
`systemd --user`. The report says `os-keyring: Partial (Linux: shares the session bus with
run-outside)` and `explain os-keyring` prints the same. A D-Bus filtering proxy would separate them
and is an open question (§9). On macOS `securityd` has its own mach service.

#### A lifted channel re-admits the variables its clients need

D5 strips `DBUS_SESSION_BUS_ADDRESS`, `DISPLAY` and `WAYLAND_DISPLAY` by default. Lifting
`clipboard` or `screen` on Linux re-admits `DISPLAY` and `WAYLAND_DISPLAY`; lifting `run-outside` or
`os-keyring` re-admits `DBUS_SESSION_BUS_ADDRESS`. The compiler derives this from the channel table.
Without it a lifted channel whose client cannot find its socket is a silent no-op.

#### Groups

The `channels` field takes the shape of the MCP policy tables ([FW-GW9](../formwork.md#fw-gw9)):
an `allow` scope and a terminal `deny` list whose entries are channel names or group names.

```toml
channels = "deny"                                      # the default: empty allow scope
channels = ["clipboard"]                               # sugar for { allow = ["clipboard"] }
channels = { allow = ["desktop"] }                     # the group an interactive login needs
channels = { allow = ["desktop"], deny = ["screen"] }  # deny is terminal, from any layer
```

Groups are exact enumerations fixed in the schema, expanded at the parse edge like a sigil
([FW-BP5](../formwork.md#fw-bp5)): `desktop` is `clipboard` and `open-url`, the two channels an
interactive session uses by hand, neither of which runs code outside the sandbox; `media` is
`screen`, `camera` and `microphone`, the TCC-tier privacy set. `run-outside` belongs to no group and
is lifted only by its own name. `os-keyring` stays under `allow-credentials` because it is a
credential. Terminal text paste is done by the terminal, outside the sandbox; only programmatic
clipboard access (`pbpaste`, `wl-paste`, image paste) needs `clipboard`, and `explain clipboard`
says so.

Layering follows the fs model ([FW-CAP8](../formwork.md#fw-cap8)): `allow` unions across layers,
`deny` entries are terminal from any layer, and the `"deny"` keyword is the default posture (an empty
allow scope), not a terminal list. A team file therefore allows the widest channel set any member
needs and hosts that want less narrow at the leaf (`--set 'channels = { deny = ["desktop"] }'` in a
CI workflow); a base layer that denies `desktop` locks every downstream user out, as an fs `subtract`
does. `explain desktop` prints each member's verdict, deciding layer, and host reachability
(`FW-FID10`).

#### Interactions the design accounts for

- **TCC.** macOS attributes a child's privacy-sensitive access to the responsible app (the terminal
  or IDE). The camera, screen and input rows stop a confined agent from using TCC grants the user gave
  that app.
- **Keychain granularity.** Seatbelt gates the keychain as one service. Lifting `os-keyring` opens
  every keychain item that does not prompt and lets the agent trigger keychain prompts; the `explain`
  and report lines state both. A narrower lift is not available on macOS (§9).
- **Claude Code.** On macOS it stores its OAuth credential in the keychain **(characterize: item
  name)** and opens a browser to log in, listening on `localhost:<port>` for the callback. The `claude`
  Catalog type gains the keychain as its macOS location, so `allow-credentials = ["claude"]` lifts
  `os-keyring` there with the granularity note; the example lifts `desktop`; the loopback listen is
  allowed under every posture (`FW-EGR15`). PR #28 adds `**/.claude/**` to the default
  `write-subtract`, and an operator-layer write-subtract is terminal, so under that profile Claude
  Code cannot write its own state and `allow-credentials = ["claude"]` does not lift it; `FW-E2E-084`
  detects this, and §8 records the resolution to choose.
- **Agent examples.** `FW-E2E-084` runs each shipped example on both CI OSes with the baseline on.

### 3.5 Operator surface

The mechanisms above add four kinds of denial: host, request, channel and supervised socket. Each is
explainable with the tools the operator already uses and discoverable through `learn`.

- **`explain`** takes the new kinds as positional arguments, typed by shape ([FW-FID6](../formwork.md#fw-fid6)
  extended, no new subcommand): a value with `scheme://` is a URL and gives the host-rule verdict,
  the method and path match, the grade and the deciding rule; a member of the channel enum or a group
  name gives the channel verdict, its lift, and host reachability; anything else is a path, and a
  socket path gives the supervised-connect verdict. `explain --hosts` prints the resolved host table,
  one host per line with its grade, methods, paths, broker binding and deciding layer.
- **`learn`** proposes hosts and channels (`FW-DISC12`). Gateway egress violations reverse-compile
  into host rules (`https:<host>`, or `<methods>:<host>/<path>` when the host is inspected); channel
  denials into `channels` entries, from supervisor violations on Linux and from unified-log
  `mach-lookup`/`lsopen`/`appleevent-send` denials on macOS, mapped back to the portable name. A host
  a wildcard already tunnels is proposed at the tunnel grade, never as a method rule that would fail
  compile (§4). Metadata and private IPs ([FW-EGR4](fep-1.md#fw-egr4)) and `os-keyring` are withheld
  and itemized, following the floor rule ([FW-DISC3](../formwork.md#fw-disc3)). Under `closed`, an
  enforced `learn` run from an empty universe proposes one path per pass; the refusal text names
  FEP-4's permissive recording (`FW-DISC7`) as the bootstrapping tool.
- **Refusals explain themselves** (`FW-FID9`). A Gateway refusal, a supervised-connect denial, an
  opener-shim refusal and a TLS `unknown_ca` rejection each emit one operator-channel line naming what
  was refused, the deciding rule, and the `explain` invocation that reproduces the verdict. The
  confined process receives only a generic refusal (HTTP 403 `denied by formwork policy`, or
  `EACCES`), per [FW-CRED7](../formwork.md#fw-cred7).
- **Host-session disclosure** (`FW-FID10`). `detect` probes the facilities that make channels
  reachable (on Linux the session bus, the user manager, display sockets and a keyring service under
  `$XDG_RUNTIME_DIR`, falling back to `/run/user/<uid>`, and `/tmp/.X11-unix`; on macOS whether a GUI
  login session owns the process) and PID-namespace nesting, and records them in the HostProfile, so
  `compile` stays pure ([FW-CAP5](../formwork.md#fw-cap5), [FW-FID4](../formwork.md#fw-fid4)). The
  report's channel lines say `reachable on this host` with the socket found, or `not present on this
  host`.
- **Resolved-input disclosure** ([FW-FID7](../formwork.md#fw-fid7)). `compile` and `explain` name
  the Gateway listener endpoint, the session CA path, the per-session temp directory, and the
  `.formwork/` layout when discovered. Placeholders are named by type, never by value.
- **Exit codes** (`FW-XR10`, `FW-XR11`). `run` exits with the workload's status and writes nothing
  of its own to stdout, because its stdout is the workload's (for an SDK harness, the protocol
  stream). A Formwork failure after spawn (the Gateway dying, the supervisor losing its listener)
  exits `125`, the value `git` and `docker` use, with one `formwork:`-prefixed line on stderr. A
  workload that itself exits `125` is indistinguishable by code alone, so the line is the contract.
- **Embedding.** A generated blueprint needs no temp file: `--blueprint /dev/fd/N` with the
  descriptor passed at spawn works with the landed flag and is disclosed as `fd:N`. A blueprint given
  by path or fd is never a discovery input, and nothing is written into `$CWD/.formwork/` unless the
  blueprint was discovered there. Releases also publish platform wheels carrying the signed binary
  (the `ruff`/`uv` pattern) so a Python orchestrator can depend on Formwork directly.
- **Machine-readable report.** Every new report line has a stable JSON key in `compile
  --report-only` and `explain --json`, extending the landed `per_capability` map with the
  `Capability` values `net-host-scope`, `net-inspection`, `net-udp`, `net-unix-socket`,
  `net-resolver`, `credential-broker`, `isolate-processes`, `isolate-ipc`, `private-tmp`,
  `channel-<name>`, `privileged-interfaces` and `process-environment`. A channel entry carries
  `{ verdict, reason, host: { present, via } }`. Rules the backend could not install are listed under
  `withheld`. The shape is a Data-model surface and versions with the report.

### 3.6 Asymmetries that remain

| Property | Linux | macOS | Why |
|---|---|---|---|
| Violation latency | synchronous per `connect()` | post-hoc (unified log) | Seatbelt has no notification channel |
| Egress endpoint authentication | by construction | credential + peer-PID check | SBPL cannot scope `localhost` to a session |
| TLS inspection clients | all env-trust clients | excludes Security.framework clients | no per-process trust on macOS |
| Keychain lift granularity | per bus name (Secret Service as a whole) | whole keychain channel | Seatbelt gates `securityd` as one service |
| `os-keyring` lift | `Partial` (shares the session bus with `run-outside`) | `Enforced` (own mach service) | D-Bus routes by bus name inside the socket |
| Other processes' environment | `Enforced` unprivileged; `Partial` with `CAP_SYS_ADMIN`/`CAP_PERFMON`/`CAP_SYS_PTRACE` | `Enforced` (sysctl deny) | Landlock's ptrace refusal yields to those capabilities |
| Any-depth `**/` rows | `Partial` | `Enforced` | Landlock cannot root them |
| `stat` on denied paths | `Partial` | `Enforced` | kernel mechanism |
| `isolate` members | `Enforced` where user namespaces exist | `Partial` or `Enforced` per characterization | no namespaces on macOS |
| Private tmp | directory form by default; tmpfs under `isolate` | directory form | no mount namespace on macOS |
| Name resolution under `Ports` | none (PR #29 closes UDP; no Gateway) | mDNSResponder literal | reported (D8); host rules restore it through the Gateway on both |
| ENOENT invisibility | not provided | not provided | `formwork.md` §3 non-goal |
| Enforcement API | stable kernel ABI | `sandbox_init` (deprecated, still shipped) | §9 |

---

## 4. Surface changes (each measured against Growth)

**`rules` (extended).** Host-scoped egress is written in the verb-rule form the file already uses
for paths, so there is one mini-language:

```toml
rules = [
  "readwrite:$CWD/**",                           # fs rule (landed)
  "https:api.anthropic.com",                     # plain host grant: tunnel grade, not inspected
  "get,post,patch:api.github.com/repos/acme/**", # HTTP methods: inspected grade, path-scoped
  "get:*.npmjs.org/**",                          # wildcard host
  "https:internal.corp:8443",                    # explicit port
  "deny:telemetry.example.com",                  # terminal, as for paths
]
```

The verb position is a comma-separated list of atoms on both axes, and the verb decides the axis. The
fs atoms are `read`, `write` (create included, per Vocabulary), `modify` and `exec`; `read,write:` is
`readwrite:` and `read,exec:` is `readexec:`, and the landed compound spellings stay as aliases.
`write` alone still implies read ([FW-TRA3](../formwork.md#fw-tra3)). The HTTP atoms are `get`,
`post`, `put`, `patch`, `delete`, `head`, `options` and `any`; `https` is the host-only verb; `deny`
applies to both axes. One grammar covers every rule: `<atom>[,<atom>…]:<target>`, where the target
is a path pattern or `host[:port][/path-glob]`. Any host rule sets the net posture to FEP-1's
`AllowHosts`; combining host rules with `net = { ports = [...] }` is a compile error, as FEP-1
requires. The target grammar, pinned because an embedder must translate into it:

- **host**: an exact DNS name, or `*.example.com` for one or more labels under `example.com` (the
  apex is not included). IP literals are accepted and, for private ranges, are the explicit naming
  [FW-EGR4](fep-1.md#fw-egr4) requires.
- **port**: `host:port`, default 443; port 80 is proxied unencrypted and reported so.
- **path**: optional after the host, a glob over the canonicalized path without query: `*` matches
  one segment, `**` any depth, `?` one character; absent means `/**`. Omnigent's `"GET,POST host/path"`
  rules translate by moving the space to a colon.

Every host resolves to exactly one grade, *tunnel* (`https:`) or *inspected* (method verbs), and
nothing changes a host's grade without a line in the file:

- Two rules at the same grade for one host union.
- A plain rule and a method rule that both match a host, directly or through a wildcard, are a
  compile error naming both lines; otherwise the plain rule would admit everything and the path rule
  would be decoration.
- `deny:host` is terminal. `deny:host/path` needs the inspected grade; on a tunnel host it is a
  compile error, never a silent no-op.
- `broker:<type>` requires an inspected rule for each bound host; the error names the line to add.

The verb also names the layer that enforces it, and the report follows:

| Rule form | Layer | Enforced by | Verdict |
|---|---|---|---|
| `net = { ports = [443] }` | L4 | kernel (Landlock `ConnectTcp` / Seatbelt) | `Enforced`; any host on the port; UDP/raw denied (PR #29); no name resolution on Linux |
| `https:host[:port]` | L4 target + TLS SNI | Gateway at CONNECT, unterminated | `Partial` ([FW-EGR5](fep-1.md#fw-egr5)): trusts client SNI/Host; request opaque |
| `<methods>:host[/glob]` | L7 | Gateway, TLS terminated | `Enforced` for env-trust clients; platform-verifier clients refused (§3.2) |

`https:` is the most a rule can say without terminating TLS: where the connection goes and the name
the client claims. Method or path is L7 and needs the certificate, which is why inspection is spelled
by the verb rather than inferred from a path.

**`allow-credentials` (extended).** Entries are a bare Catalog type (expose), `broker:<type>`, or
an inline binding table `{ name, env, hosts, scheme }` for a credential the Catalog does not know.
One list governs the Catalog.

**`channels` (new).** `"deny"` (default) or `{ allow, deny }` over the closed enum `run-outside`,
`open-url`, `clipboard`, `screen`, `camera`, `microphone` plus the fixed groups `desktop` and
`media`; a bare list is sugar for `allow`. An unknown name fails at parse and the error lists the
valid names (`deny_unknown_fields` discipline).

**`isolate` (new).** A subset of `["processes", "ipc"]`.

**Catalog.** An optional `broker` block (a list of `{ hosts, scheme }`), a `services` location kind
(mach names on macOS; bus names and sockets on Linux), the `os-keyring` type, and the `claude` type's
macOS keychain location. Embedded data, so a catalog version bump.

**CLI.** No new subcommand, and one new flag: `explain --hosts` prints the resolved host table.
(`--net` was the first choice, but it is already the net-posture override every blueprint-taking
subcommand shares.) `explain` accepts URLs, channel and group names, and socket paths
positionally. Two Launcher-provided files
appear at run time, the opener shim and the CA bundle, both under `FW-TRA9`.

**Profiles.** `builtin:default` only. It loses its explicit `reads = ["/**"]` row (D10) and gains
the channel baseline, the privileged-interface baseline and the environment-disclosure deny, each
gated as §1.1 states.

**Examples.** The `claude-code`, `codex` and `opencode` blueprints move from `ports = [443]` to host
rules with brokering; each gains a note on what the baseline blocks and how to lift it. The README
quickstart stays at most five lines and carries no FW IDs (document audience rule).

**Dependencies** (the hardest no). `rustls`, `rcgen` and `hyper`, confined to `formwork-gateway`,
needed only for inspection; `rustls` over OpenSSL keeps the trust base memory-safe. The Linux
supervisor uses raw `seccomp(2)` and needs no new crate. The macOS peer check uses `libproc` through
`libc`.

**Deprecations.** None. The FEP adds surface and renames nothing.

---

## 5. Proposed requirements (draft numbering — anchored on landing)

These continue existing families: EGR, CRED, TRA, ISO, BP, FID, DISC and XR. One obligation per
ID; discussion and rationale live in §3.

| Req | Requirement |
|---|---|
| <a id="fw-egr7"></a>**FW-EGR7** Supervised connect (Linux) | Under the host-allowlist posture on Linux, the Confiner shall deliver every `connect()` on AF_INET, AF_INET6 and AF_UNIX sockets, and every addressed `sendto`/`sendmsg` on an AF_UNIX datagram socket, to a supervisor outside the sandbox, which shall perform any allowed operation itself and install the result in the target. |
| <a id="fw-egr8"></a>**FW-EGR8** Sole egress endpoint (macOS) | Under the host-allowlist posture on macOS, the compiled profile shall permit outbound network only to `localhost:<P>` for the session's Gateway listener and to pathname sockets granted by `allow`. |
| <a id="fw-egr9"></a>**FW-EGR9** Registered egress | The Gateway egress listener shall accept a connection only if its source endpoint was registered by the supervisor (Linux), or if it presents the session credential and its peer PID belongs to the session (macOS). |
| <a id="fw-egr10"></a>**FW-EGR10** Inspected host rule | For an inspected host, the Gateway shall terminate TLS, verify that the SNI, the `Host` header and the CONNECT target agree, and admit a request only if its method and canonicalized path match a rule for that host. |
| <a id="fw-egr11"></a>**FW-EGR11** Request canonicalization | Before matching, the Gateway shall remove dot-segments and decode percent-encoded unreserved characters, and shall reject a request carrying an encoded `/`, a NUL, a backslash in the path, or both `Content-Length` and `Transfer-Encoding`. |
| <a id="fw-egr12"></a>**FW-EGR12** Resolver closure | Under the host-allowlist posture, the Confiner shall deny every local name-resolution path: UDP and the resolver sockets on Linux, and the mDNSResponder literal on macOS. |
| <a id="fw-egr13"></a>**FW-EGR13** Ephemeral CA | The Gateway shall generate the inspection CA in memory per session and shall not write the CA private key to any file nor expose it to any confined process. |
| <a id="fw-egr14"></a>**FW-EGR14** Gateway hosting | `formwork run` in the spawn posture shall host the Gateway whenever the blueprint carries a host rule. |
| <a id="fw-egr15"></a>**FW-EGR15** Loopback listen (macOS) | Under every net posture, the macOS profile shall permit `network-bind` and `network-inbound` on `localhost:*`. |
| <a id="fw-cred10"></a>**FW-CRED10** Brokered floor | For each brokered credential, the Launcher and the Confiner shall strip and deny its locations exactly as for an unlisted type ([FW-CRED4](../formwork.md#fw-cred4)). |
| <a id="fw-cred11"></a>**FW-CRED11** Credential presentation | The Gateway shall present a brokered credential only on requests to its bound hosts, using the scheme bound to that host: substituting where the request carries the session placeholder, adding the header where the request carries no credential, and refusing with a violation record where the placeholder is carried toward any other host. |
| <a id="fw-cred12"></a>**FW-CRED12** Broker host closure | The compiler shall reject a blueprint that brokers a credential without an inspected rule for each of its bound hosts, naming the rule to add. |
| <a id="fw-cred13"></a>**FW-CRED13** Service-located credentials | The Catalog shall express credential locations that are services (macOS mach names; Linux bus names and sockets), ship the `os-keyring` type floor-denied by default, and map the `claude` type's macOS location to the keychain. |
| <a id="fw-cred14"></a>**FW-CRED14** Placeholder timing | When a brokered type has an env var, the Launcher shall set it to the per-session placeholder after the Catalog strip and the environment scrub have run. |
| <a id="fw-cred15"></a>**FW-CRED15** Credential custody | The Gateway shall hold each brokered credential outside the sandbox, reading its source at session start and again at the interval the Catalog entry states. |
| <a id="fw-tra9"></a>**FW-TRA9** Launcher-owned paths | Paths the Launcher creates for a session (the session scratch holding the CA bundle, the private temporary directory, the opener shim directory) shall be granted in every read mode, read-only except the temporary directory, and named in the resolved-input disclosure ([FW-FID7](../formwork.md#fw-fid7)). |
| <a id="fw-tra10"></a>**FW-TRA10** Private temporary directory | The Launcher shall create a per-session temporary directory and set `TMPDIR`, `TMP` and `TEMP` to it in the confined environment. |
| <a id="fw-iso10"></a>**FW-ISO10** Isolation tier | When a blueprint requests `isolate`, the Confiner shall apply each member (`processes`, `ipc`) with the §3.3 mechanism for the platform. |
| <a id="fw-iso11"></a>**FW-ISO11** Datagram and raw closure (Linux) | Under every net posture, the Confiner shall deny AF_INET and AF_INET6 `SOCK_DGRAM` and `SOCK_RAW` socket creation (PR #29 for `Deny` and `Ports`; extended here to the host-allowlist posture). |
| <a id="fw-iso12"></a>**FW-ISO12** Pathname socket mediation (Linux) | Under supervised connect, the supervisor shall refuse a `connect()` or addressed send to a pathname AF_UNIX socket unless the socket is granted by `allow` or was bound by a process in the session. |
| <a id="fw-iso13"></a>**FW-ISO13** Channel baseline | In every blueprint, the Confiner shall deny each channel in the shipped baseline set that is not lifted by `channels` or by a typed credential exclusion, using the mechanism listed for its platform. |
| <a id="fw-iso14"></a>**FW-ISO14** Privileged-interface baseline (macOS) | The macOS profile shall deny `mach-priv-host-port`, `mach-priv-task-port`, and `iokit-open` outside the shipped IOKit allowlist. |
| <a id="fw-iso16"></a>**FW-ISO16** Process-environment disclosure | The Confiner shall deny a confined process reading the environment of any process outside the session where the platform provides a mechanism (macOS `kern.procargs2` deny; Linux PID namespace under `isolate`). |
| <a id="fw-iso17"></a>**FW-ISO17** Opener shim | In every spawned session, the Launcher shall place a Formwork-owned opener first in `PATH` and in `BROWSER`; it hands each URL to the Gateway, which opens it only when `open-url` is lifted and otherwise records a refusal. |
| <a id="fw-iso18"></a>**FW-ISO18** Brokered URL open | The Gateway shall accept from the opener shim `http` and `https` URLs only, record each on the operator channel, and open it with the host opener outside the session. |
| <a id="fw-bp9"></a>**FW-BP9** Channel policy shape | The Blueprint shall express channel lifts as an `allow` scope and a `deny` list over the closed channel enum and the fixed groups `desktop` (`clipboard`, `open-url`) and `media` (`screen`, `camera`, `microphone`), with groups expanded at the parse edge. |
| <a id="fw-bp10"></a>**FW-BP10** Channel layering | Across layers, channel `allow` scopes shall union, `deny` entries shall be terminal, and the `"deny"` keyword shall mean an empty `allow` scope. |
| <a id="fw-bp11"></a>**FW-BP11** Locator variables | The Launcher shall re-admit the environment variables by which a lifted channel's platform clients locate it. |
| <a id="fw-bp12"></a>**FW-BP12** Credential entry forms | `allow-credentials` shall accept a bare Catalog type, `broker:<type>`, or an inline binding `{ name, env, hosts, scheme }`; a type present in both bare and `broker:` forms shall resolve to `broker`. |
| <a id="fw-bp13"></a>**FW-BP13** Host-rule grammar | `rules` shall accept host rules of the form `<atoms>:host[:port][/glob]` with the §4 grammar, where the atoms are HTTP methods, `any`, `https` or `deny`; any host rule shall set the net posture to host-allowlist, and a host rule together with a port tier shall be a compile error. |
| <a id="fw-bp14"></a>**FW-BP14** One host, one grade | The compiler shall reject a blueprint in which a tunnel rule and an inspected rule both match one host, or in which a path-scoped `deny` names a host that has no inspected rule, naming the conflicting lines. |
| <a id="fw-bp15"></a>**FW-BP15** Verb atoms | The verb position of a rule shall be a comma-separated list of atoms; for the fs axis the atoms shall be `read`, `write`, `modify` and `exec`, with the landed compound verbs accepted as aliases of the same meaning. |
| <a id="fw-fid8"></a>**FW-FID8** Per-backend report lines | The FidelityReport shall carry, each under the stable JSON key §3.5 names, per-backend verdicts for host scoping, inspection, UDP, pathname sockets, resolver closure, brokering, each `isolate` member, private tmp, each channel, privileged interfaces and process-environment disclosure, and a `withheld` list naming every rule the backend could not install. |
| <a id="fw-fid9"></a>**FW-FID9** Self-explaining refusals | For each Gateway refusal, supervised-connect denial, opener-shim refusal and TLS `unknown_ca` rejection of the session CA, Formwork shall emit on the operator channel, within the run, one line naming what was refused, the deciding rule, and the `explain` invocation that reproduces the verdict, while the confined process receives only a generic refusal ([FW-CRED7](../formwork.md#fw-cred7)). |
| <a id="fw-fid10"></a>**FW-FID10** Host-session detection | `detect` shall probe for the host facilities that make each channel reachable (session bus, user manager, display server, keyring service; GUI session on macOS) and for PID-namespace nesting, and record them in the HostProfile. |
| <a id="fw-fid11"></a>**FW-FID11** Explain for hosts and channels | `explain` shall accept a URL, a channel or group name, or a socket path as a positional argument and print the verdict, the deciding rule and layer, the grade for a host, and host reachability for a channel; `explain --hosts` shall print every effective host once with its grade, methods, paths, broker binding and deciding layer. |
| <a id="fw-disc12"></a>**FW-DISC12** Host and channel discovery | `learn` shall reverse-compile Gateway egress violations and channel denials into proposal entries (host rules, `channels`) on both backends, at the grade an existing rule for the host already has, and shall withhold and itemize metadata and private-IP destinations and credential-typed channels ([FW-DISC3](../formwork.md#fw-disc3)). |
| <a id="fw-xr10"></a>**FW-XR10** Wrapper transparency | Wrapper subcommands shall exit with the workload's status and write nothing of their own to stdout. |
| <a id="fw-xr11"></a>**FW-XR11** Failure attribution | A Formwork failure after the workload is spawned shall exit `125` and emit one `formwork:`-prefixed line on stderr attributing the failure to Formwork. |

Invariants:

- <a id="fw-inv13"></a>**FW-INV13 — Broker non-disclosure.** A brokered credential's bytes do not appear in a confined
  process's environment, in a file or service it can read, or in any Gateway response to it.
- <a id="fw-inv14"></a>**FW-INV14 — No out-of-sandbox execution.** A confined process cannot, through any channel its
  blueprint has not lifted, cause a process outside its session to execute a command, open a URL, or
  perform network egress.

---

## 6. Verification plan

### 6.1 Test design

CI runs both OSes, so every test is written to run on a hosted runner. Each test follows the
constitution's Testing section and these rules:

- **Control run first.** A negative test first runs its probe unconfined and asserts that the channel
  is live on this runner (the marker file is written, the clipboard round-trips, the fixture receives
  the request), then runs the probe confined and asserts the denial. This is the paired allow/deny
  rule applied to host services; without the control, a runner with no pasteboard server passes while
  proving nothing.
- **Not exercised is a failure in CI.** When the control run fails, the test skips locally with the
  reason; in CI `FW_REQUIRE_EXERCISED=1` turns that skip into a failure.
- **Positive assertion of the denial.** Tests assert the denial record (the supervisor's violation,
  the unified-log `deny` line, the 403), and check the absence of a side effect after the process
  tree has exited, never by waiting.
- **Least convenient shape.** Every probe is the fastest-failing workload: a process that dies on its
  first denial within milliseconds, inside the unified-log latency window
  ([FW-E2E-064](../formwork.md#fw-e2e-064)).
- **Hermetic escape markers.** No test depends on Safari, Finder or a TCC grant. Each "run outside"
  or "open" channel is exercised against a fixture app built by the test: a minimal `.app` bundle
  whose executable writes a marker file where the confined process cannot write. `open -g -n
  fixture.app` exercises LaunchServices, `launchctl submit` exercises launchd, and an AppleEvent to
  the fixture app exercises `appleevent-send`. Where a TCC consent would be needed for the control run
  on a hosted runner, the test asserts only the confined-side deny record and is entered in the
  `docs/STATUS.md` test-method exceptions register that PR #30 introduces.
- **The runner is headless, so the suite brings the session.** Every Linux channel test starts its own
  session `dbus-daemon`, a fixture socket service that runs commands it receives (a stand-in for
  `systemd --user` with the same socket shape) under a per-test `$XDG_RUNTIME_DIR`, and `Xvfb` for a
  display socket under `/tmp/.X11-unix`, and proves each live with the control run. A desktop-only
  facility CI cannot provide (a `systemd --user` instance, a Wayland compositor) is entered in the same
  exceptions register, and the requirement's report line covers the difference on a desktop
  (`FW-FID10`).
- **Fixture services, not mocks.** The egress tests use FEP-1's loopback fixtures and resolver
  fixture; every service is a subprocess, as the MCP fixtures are.
- **Traceability.** Every test carries its `fw_e2e` / `fw_adv` marker and `macos` / `linux` marker.

### 6.2 CI changes

The constitution's first-party-actions rule holds; nothing third-party is added.

| Change | Why |
|---|---|
| Add `macos-15` to the matrix beside `macos-14` | Seatbelt service names and `sysctl` behavior change across releases; characterization runs on the current and previous major |
| Add `ubuntu-24.04` beside `ubuntu-22.04` | 24.04 restricts unprivileged user namespaces through AppArmor, so the `isolate` refusal path is exercised on a runner |
| Install `dbus` and `xvfb` on Linux runners | session-bus and display fixtures for `FW-E2E-082` and `FW-E2E-087`; distribution packages, not actions |
| Set `FW_REQUIRE_EXERCISED=1` in CI | a skipped platform test is a claim, not a verification |
| Run the README quickstart and each `examples/` blueprint on both OSes | D1 and `FW-E2E-084` |

### 6.3 macOS characterization suite

These run in CI on `macos-14` and `macos-15` with `FW_REQUIRE_EXERCISED=1`. Each records the
observed behavior as a fixture that the requirement tests assert against, so a change across macOS
releases fails CI instead of widening the sandbox unnoticed. Every **(characterize)** mark above is
settled by one of them.

| # | Question | Test shape |
|---|---|---|
| C1 | Do SBPL remote filters accept only `*` / `localhost` hosts? | compile profiles with a literal-IP remote filter and assert on the `sandbox_init` result |
| C2 | Is the `PROC_PIDFDSOCKETINFO` peer lookup reliable under churn and for reparented descendants? | 1,000 connections from a confined process tree with 10 % reparented; assert every one is attributed |
| C3 | Which `mach-lookup` names do `open`, `launchctl submit`, AppleEvents, `pbcopy`/`pbpaste`, `security` and `screencapture` use? | run each probe under `(deny mach-lookup)` and harvest the deny records; the set becomes the checked-in channel map |
| C4 | Are `lsopen` and `appleevent-send` checked for a `sandbox_init` process? Does `(deny default)` close them? | fixture app with a control run |
| C5 | Does `kern.procargs2` return same-uid environments, and does a `sysctl-name` deny close it? Which MIBs does `ps` use? | canary sibling; control run, then confined |
| C6 | Which `(target …)` forms keep in-session process management working? | shell job control, `node` `child_process`, `make -j`, `python -m multiprocessing` under the filters |
| C7 | Can POSIX IPC be confined to a session prefix? | `multiprocessing` shared memory, Node workers |
| C8 | IOKit allowlist and transparency | the toolchain suite plus `swift build`, Homebrew, `gh` and Xcode CLT under the privileged-interface baseline; harvest the `iokit-open` denies |
| C9 | What are Claude Code's keychain item and login flow? | run the example's smoke command; record the keychain and `lsopen` denies |

### 6.4 Tests

Each test is written as Pass/Fail. Draft numbers continue above `FW-E2E-074` and `FW-ADV-015`.

- <a id="fw-e2e-075"></a>**FW-E2E-075: Sole egress path (both).** Under `rules = ["https:allowed.test"]`, a request through
  `HTTP_PROXY` reaches the fixture; a direct `connect()` to the fixture, a direct `connect()` to
  `169.254.169.254`, an unregistered (Linux) or uncredentialed (macOS) connection to the listener, a
  UDP send, and `getaddrinfo("blocked.test")` are each attempted. Pass: the proxied request succeeds
  and each direct attempt is denied with a violation record. Fail: any direct attempt succeeds.
- <a id="fw-e2e-076"></a>**FW-E2E-076: Pathname socket (both).** Three sockets, each with an unconfined control: one bound
  by an out-of-session fixture, one granted by `allow`, one bound in-session. Pass: the first is
  refused and the other two connect. Fail: the first connects, or a granted one is refused.
- <a id="fw-e2e-077"></a>**FW-E2E-077: Inspected path scope (both).** Under `post:allowed.test/repos/acme/**`. Pass:
  `POST /repos/acme/x` passes; `POST /repos/other/x` and `GET /repos/acme/x` are refused with a
  generic 403 and an operator-channel line naming the rule. Fail: either refused request reaches the
  fixture, or the 403 body names the rule.
- <a id="fw-e2e-078"></a>**FW-E2E-078: Brokered header (both).** Under `allow-credentials = ["broker:anthropic"]` bound to
  `allowed.test`. Pass: the fixture receives the credential in `x-api-key`; the confined `env` shows
  the placeholder; the Catalog file is unreadable; the placeholder sent to `other.test` is refused;
  the credential bytes appear on no confined-readable surface the test can enumerate (`FW-INV13`).
  Fail: any of these does not hold.
- <a id="fw-e2e-079"></a>**FW-E2E-079: Isolation tier (Linux, both runners).** With `isolate = ["processes"]`. Pass on
  `ubuntu-22.04`: `/proc` lists only session PIDs, `$TMPDIR` is a tmpfs, `kill` of a host PID fails.
  Pass on `ubuntu-24.04`: the run is refused before spawn and the message names AppArmor, the
  `sysctl` remedy, bwrap, and dropping the member. Fail: the tier is applied partially on either.
- <a id="fw-e2e-080"></a>**FW-E2E-080: Isolation tier (macOS).** With the same request. Pass: `kill` and `proc_pidinfo` on
  an unconfined control sibling fail, and the report's `processes` verdict matches what `ps` shows.
  Fail: a host process is signalable or the report and `ps` disagree.
- <a id="fw-e2e-081"></a>**FW-E2E-081: Channels (macOS).** Under the default profile, `open -g -n fixture.app`,
  `launchctl submit` of a marker job, an AppleEvent to the fixture app, `pbcopy`/`pbpaste` of a nonce,
  and `security find-generic-password` against a test item in a test keychain are each attempted.
  Pass: each is denied with a sandbox deny record and no marker appears; with
  `channels = ["clipboard"]` only the clipboard probe succeeds; with
  `allow-credentials = ["os-keyring"]` only the keychain probe succeeds. Fail: a marker appears, or a
  lift opens more than its channel.
- <a id="fw-e2e-082"></a>**FW-E2E-082: Channels (Linux).** Against a session `dbus-daemon` and the fixture service under
  supervised connect: `gdbus call --session`, the fixture's "run this" request, and a connection to a
  fixture X11-shaped socket. Pass: each is denied with a violation record, and each succeeds under its
  matching lift. Fail: a denial is missing or a lift opens an unrelated socket.
- <a id="fw-e2e-083"></a>**FW-E2E-083: Environment disclosure (both).** An unconfined sibling carries `FW_CANARY=<nonce>`;
  the control (`ps -E` on macOS, `/proc/<pid>/environ` on Linux) shows it. Pass on macOS: the confined
  run under the default profile does not show it. Pass on Linux: the default profile shows it and
  the report says `Partial` with the residual ([FW-E2E-025](../formwork.md#fw-e2e-025) pattern);
  under `isolate = ["processes"]` on `ubuntu-22.04` it is not shown and the report says `Enforced`.
  Fail: the report and the observation disagree.
- <a id="fw-e2e-084"></a>**FW-E2E-084: Agent examples under the baseline (both).** Each shipped `examples/` blueprint runs
  its agent's non-interactive smoke command with the baseline on; the Claude Code login flow runs
  with the fixture opener standing in for the browser. Pass: zero denials outside the lift set the
  example documents. Fail: any other denial, including a write to `~/.claude` under the default
  profile.
- <a id="fw-e2e-085"></a>**FW-E2E-085: Discovery of hosts and channels (both).** `learn` runs a millisecond workload that
  requests `blocked.test` through the proxy and touches the clipboard, and a second that requests
  `169.254.169.254`. Pass: `https:blocked.test` and `channels = ["clipboard"]` are proposed; the
  metadata address produces a withheld line. Fail: the metadata address is proposed, or a proposal is
  missing.
- <a id="fw-e2e-086"></a>**FW-E2E-086: Exit codes (both).** A workload exiting 3; then a run whose Gateway is killed
  mid-session. Pass: the first makes `run` exit 3 with nothing of its own on stdout; the second exits
  125 with the attribution line on stderr and stdout untouched. Fail: stdout carries a Formwork line,
  or the code differs.
- <a id="fw-e2e-087"></a>**FW-E2E-087: Host-session detection (both).** Pass on a bare Linux runner: `detect` reports each
  channel `not present on this host`. Pass with the §6.1 fixture session: `detect` names the bus,
  user-manager and display sockets, `run` prints the matching `Partial` line, and the same run under
  supervised connect prints `Enforced`. Pass on macOS: `detect` reports the GUI-session verdict and
  the channel lines match `FW-E2E-081`. Fail: a present facility is reported absent or the reverse.
- <a id="fw-e2e-088"></a>**FW-E2E-088: Channel groups (both).** Under `channels = ["desktop"]`. Pass: the clipboard and
  URL-open probes succeed; `screen` and `run-outside` are denied; on Linux `DISPLAY` and
  `WAYLAND_DISPLAY` are present in the confined environment and `DBUS_SESSION_BUS_ADDRESS` is not;
  with a downstream `channels = { deny = ["desktop"] }` both probes are denied and `explain desktop`
  names the denying layer; a base `channels = "deny"` with a downstream `channels = ["clipboard"]`
  admits the clipboard; `channels = { allow = ["desk"] }` fails at parse listing the valid names.
  Fail: any branch differs.
- <a id="fw-e2e-089"></a>**FW-E2E-089: Launcher-owned paths under `closed` (both).** A blueprint with `mode = "unveil"`
  and only `readwrite:$CWD/**`. Pass: `$TMPDIR` is set inside the session and writable, and on macOS
  `confstr(_CS_DARWIN_USER_TEMP_DIR)` resolves beneath it; a grandchild reads the session CA bundle,
  `/proc/self/status` and `/etc/hosts`; `explain` names the tmp directory and the CA path. Fail: any
  read is denied or a path is undisclosed.
- <a id="fw-e2e-090"></a>**FW-E2E-090: Brokered `open-url` (both).** Under `channels = ["open-url"]`. Pass: the confined
  `xdg-open`/`open` of an `https://` URL causes the fixture opener on the host to receive it and the
  operator channel records it; a `file:` URL is refused with a violation record; `lsopen` (macOS) and
  the session bus (Linux) stay denied throughout. Fail: the `file:` URL is opened, or a host service
  is reachable.
- <a id="fw-e2e-091"></a>**FW-E2E-091: Loopback callback (macOS).** A confined process binds `localhost:<ephemeral>` and
  an unconfined control process connects and sends a nonce, under `net = "deny"`, `ports` and a host
  rule. Pass: the confined process receives the nonce under each posture. Fail: the bind or the
  accept is denied.
- <a id="fw-adv-016"></a>**FW-ADV-016: Gateway frame bypass (D6).** A batch array, a non-JSON frame, and an id-less
  `tools/call` for a shaded tool. Pass: none reaches the backend. Fail: any does.
- <a id="fw-adv-017"></a>**FW-ADV-017: Path traversal against an inspected rule.** Against `post:allowed.test/repos/acme/**`:
  `/repos/acme/../other/x`, `/repos/acme/%2e%2e/other/x`, `/repos/acme%2F..%2Fother/x`, and a
  request carrying both `Content-Length` and `Transfer-Encoding`. Pass: each is refused or
  canonicalizes outside the scope. Fail: any reaches `/repos/other`.
- <a id="fw-adv-018"></a>**FW-ADV-018: Supervisor race (Linux).** A second thread rewrites the `sockaddr` while `connect()`
  is pending. Pass: the connection lands only where the supervisor's copy was allowed. Fail: it lands
  at the rewritten address.
- <a id="fw-adv-019"></a>**FW-ADV-019: Endpoint theft (macOS).** An unconfined same-uid process holding `P` and the
  credential connects to the listener. Pass: the peer check refuses it; or, if C2 found the peer check
  unreliable, the report is `Partial` and names this residual. Fail: the connection is admitted while
  the report says `Enforced`.
- <a id="fw-adv-020"></a>**FW-ADV-020: Exfiltration through a host service (both).** Under `rules = ["https:allowed.test"]`
  the agent tries to send a nonce to the `blocked.test` fixture through the opener with a URL
  argument, an AppleEvent, the Linux fixture service running `curl`, and a clipboard hand-off to an
  unconfined reader. Pass: the nonce never reaches the fixture, checked after the process tree exits.
  Fail: it arrives by any route.

### 6.5 Phasing

Each phase lands independently, and the report is honest at every boundary.

- **Phase 0** — defects (§2), with D10 and D11 first because they block the closed read mode.
- **Phase 1** — baselines that need no new transport: channels and privileged interfaces (§3.4),
  environment disclosure and private tmp (§3.3), and their report lines.
- **Phase 2** — egress transport: the Linux supervisor, the macOS endpoint, resolver closure (§3.1),
  and the host-rule grammar (§4).
- **Phase 3** — inspection and brokering (§3.2).
- **Phase 4** — the `isolate` tier (§3.3).
- Throughout — `explain`, `learn` and refusal messages (§3.5) land with the phase that introduces
  each denial kind.

---

## 7. Amendments to the landed docs

Applied on landing: each block below is now in the named document, and the IDs are anchored in this
one.

**(a) `formwork.md` [FW-XR7](../formwork.md#fw-xr7).** Current: "The agent reaches the gateway via
an inherited fd. Formwork never depends on an in-sandbox `connect()` nor on the filesystem sandbox
selectively *allowing* a socket path." Proposed replacement:

> **FW-XR7** fd-injection transport | The agent reaches the gateway via an inherited fd, or via a
> `connect()` it issues that the gateway performs on its behalf and installs (`FW-EGR7`). Formwork
> never depends on a `connect()` the confined process completes itself, nor on the filesystem sandbox
> selectively *allowing* a socket path.

**(b) `formwork.md` [FW-ISO8](../formwork.md#fw-iso8).** Current: "On Linux, set `NO_NEW_PRIVS` and
a seccomp baseline that blocks confinement-shedding and privilege-escalation paths, while remaining
permissive enough that normal toolchains run unmodified." Proposed replacement:

> **FW-ISO8** Anti-shedding baseline | Install a baseline that blocks confinement-shedding and
> privilege-escalation paths and the host-service channels through which a process outside the
> session could act on the confined process's behalf (`FW-ISO13`, `FW-ISO14`): on Linux
> `NO_NEW_PRIVS` and a seccomp deny-list; on macOS the named SBPL denies. The baseline stays
> permissive enough that common toolchains run unmodified ([FW-TRA2](../formwork.md#fw-tra2)).

**(c) `formwork.md` [FW-BP2](../formwork.md#fw-bp2).** Current merge order: "built-in baseline →
`extends` chain → Blueprint file → CLI overrides." Proposed replacement of that clause, matching the
loader (`blueprint_load.rs:198-258`):

> built-in baseline (the fail-closed empty Blueprint plus the credential-catalog floor) → `extends`
> chain (depth-first, bases before deriveds) → Blueprint file → `--set` fragments → the discovered
> layer (`<blueprint>.discovered.toml`, [FW-DISC6](../formwork.md#fw-disc6)) → CLI sugar flags.

**(d) `formwork.md` §3, in-scope list.** Add:

> - A confined process causing a process outside its session to act on its behalf — execute a
>   command, open a URL, perform egress, or disclose a secret — through a host service (AppleEvents,
>   LaunchServices, launchd, the session bus, display-server sockets).

**(e) `formwork.md` §9.** Add the macOS SBPL operations and the Linux supervisor to the backend
bullets; add a fidelity row per `FW-FID8` line; copy §3.6; correct the Linux UDP row per PR #29 and
the macOS resolver row per D8. (The Landlock scoping bullet is already corrected on this branch.)

**(f) `formwork.md` §11.** Close "fd-minting default" (on-demand through the supervisor on Linux; a
static endpoint on macOS) and "Credential brokering" (§3.2); narrow "Linux gateway egress isolation
build-vs-buy" to the optional netns path.

**(g) `docs/fep-1.md`.** In Non-goals, replace the TLS-interception and credential-masking bullets
with:

> - **TLS interception and credential brokering** are specified by FEP-5 §3.2 as an opt-in
>   per-host grade; the CONNECT/SNI grade here remains the default for a plain host rule.

Spell `AllowHosts` as host rules in `rules` (FEP-5 §4), and close the open host-pattern question with
the §4 grammar.

**(h) `docs/unstated-requirements.md`.** Mark item 12 minted as `FW-XR10`/`FW-XR11` and item 10 as
applied by §6.2.

**(i) `constitution.md` Vocabulary.** Add:

> - **broker** = the Gateway presenting a credential it holds, never disclosing its bytes ·
>   **placeholder** = the per-session stand-in for a brokered env var · **inspect** = TLS termination
>   at the Gateway for a host rule that needs request-level policy · **supervise** = the Gateway
>   receiving a confined `connect()` through seccomp user notification and minting the connection
>   itself · **channel** = a host service that can act outside the sandbox on a confined process's
>   behalf, named by a portable enum value · **characterize** = a CI test that records how a platform
>   mechanism behaves, run before a requirement relying on it is anchored.

---

## 8. Decisions (recorded per constitution Precedence & Conflicts)

Each decision names the alternative considered and the evidence that decided it. Four simulated
operators (a solo macOS developer with Claude Code; a headless Ubuntu 24.04 CI job with `codex`; an
Omnigent embedder; a four-person team on Linux GNOME, macOS, a devcontainer and CI) walked an earlier
revision under `read-mode = "closed"`, and the findings below cite them by role.

- **Host rules live in `rules`, not in a `net.hosts` table.** A `{ host, methods, paths }` table was
  a second grammar beside the verb rules and reached TOML's nesting limit at the first path-scoped
  rule. The verb form is one grammar, and Omnigent's egress strings translate into it directly.
- **One host, one grade; no inference.** A host matched by both a plain and a method rule would let
  the plain rule admit everything. A brokered credential silently promoting its host to inspected
  hid a grade change from the file. Both are compile errors now (`FW-BP14`, `FW-CRED12`).
- **Brokering is a grade on `allow-credentials`, not a second list.** A separate `broker-credentials`
  list with a parse error at its intersection was asked to be one list by three of the four operators;
  the team could not un-broker a type from a downstream layer. `broker:<type>` reuses the verb-prefix
  idiom (`FW-BP12`).
- **Per-host schemes and swap-on-access.** One scheme per type cannot serve `github.com` (Basic, for
  `git push`) and `api.github.com` (Bearer) in one PR flow, and git presents no placeholder, so a
  header is added when absent (`FW-CRED11`). Embedder bindings exist because Omnigent's credentials
  are user-defined.
- **Launcher-owned paths are implicit grants.** All four operators found the session CA bundle
  unreadable under `closed`, where every TLS client would then fail and the diagnosis would blame the
  client (`FW-TRA9`).
- **Private tmp is default behavior, not an `isolate` member.** Two operators wanted it without PID
  isolation; the directory form is free on both platforms (`FW-TRA10`).
- **`isolate` refuses rather than degrading.** A best-effort spelling ("isolate if you can") would
  request a verdict the blueprint cannot request ([FW-INV6](../formwork.md#fw-inv6)); the refusal
  names every remedy instead, and a CI matrix that spans kernels does not request `processes` in a
  shared file.
- **`open-url` is brokered through the Gateway.** Lifting LaunchServices on macOS and the portal on
  Linux was the first design; the team scenario showed the Linux portal shares its socket with
  `systemd --user`, so the lift would have been `run-outside`. The shim (`FW-ISO17`, `FW-ISO18`)
  lifts no host service on either platform, and makes a standing `desktop` grant acceptable.
- **`os-keyring` on Linux is reported as coupled.** A D-Bus filtering proxy would separate it from
  `run-outside`; it is a new component and stays an open question.
- **A lifted channel re-admits its locator variables.** The team's first paste under a lifted
  `clipboard` was a silent no-op because `WAYLAND_DISPLAY` had been scrubbed (`FW-BP11`).
- **Channel groups inside `channels`; no `builtin:desktop`; no `desktop = true`.** A top-level
  boolean could not be turned off by a downstream layer without a new merge rule; a second embedded
  profile was redundant for a solo user and unreachable for a team whose file already names
  `builtin:default`. Groups are exact schema lists, never patterns
  ([FW-CAP2](../formwork.md#fw-cap2)).
- **Deny-terminal channels are kept.** A shared file is written at its widest and narrowed at the
  leaf; making channel denies reopenable would give channels a merge rule paths lack. Stated in §3.4.
- **`channels = "deny"` is a posture.** As a terminal list it would lock out every downstream user
  who extends a base that wrote it "to be safe" (`FW-BP10`).
- **Loopback listen is allowed under every posture.** Claude Code's OAuth callback failed under
  `(deny network*)`; the solo-developer scenario found it (`FW-EGR15`).
- **Refusals are explained to the operator, not the agent.** The 403 body once named the rule, which
  [FW-CRED7](../formwork.md#fw-cred7) forbids (`FW-FID9`).
- **The attribution line is on stderr.** `run`'s stdout is the workload's, and for Omnigent's SDK
  path it is the stream-json protocol (`FW-XR10`, `FW-XR11`).
- **No `--blueprint -`, no `--gateway <socket>`.** Reading the blueprint from stdin hands an SDK
  harness an exhausted stdin under `confine-self`; `--blueprint /dev/fd/N` already works. The
  refusal under `confine-self` plus the spawn posture covers what `--gateway` would have.
- **Report lines have stable JSON keys, and host probing lives in `detect`.** The embedder could not
  gate on prose, and a filesystem probe in the compiler broke its purity
  ([FW-CAP5](../formwork.md#fw-cap5)).
- **Environment disclosure on Linux follows the process's capabilities.** An earlier claim that
  Landlock blocked `/proc/<pid>/environ` was checked in a root container and found false (D9). CI
  on ordinary runners then showed it true: Landlock refuses ptrace-class access outside the domain,
  and only `CAP_SYS_ADMIN` or `CAP_PERFMON` gets past it. The verdict is `Enforced` for an
  unprivileged run and `Partial`, with the capability named, otherwise.
- **`.formwork/` in the project for D3.** A per-user state directory would keep the root unsplit but
  make learned grants machine-local; the team workflow commits them.
- **Accepted limitations.** Brokering a credential whose client verifies through Security.framework
  does not work on macOS (`gh`); the pre-run notice makes it visible, and a mixed-OS team exposes
  `github` instead. Lifting `os-keyring` on macOS exposes every non-prompting item, which makes
  brokering `github` on the same Mac largely redundant. Closed-mode fs grants are platform-shaped
  (half of the team's file); D11 widens the essentials, and portable fs groups are the recommended
  FEP-7 (§9). `/proc/**` under `closed` on Linux reopens G8 and is reported `Partial`.
- **Interaction with PR #28's `**/.claude/**` write-subtract.** Under that profile Claude Code
  cannot write `~/.claude`, and `allow-credentials = ["claude"]` does not lift an operator
  write-subtract. The options are to narrow the row to the executable parts of that tree
  (`**/.claude/settings.json`, `**/.claude/hooks/**`) or to make the typed exclusion lift the
  matching write-subtract rows. This FEP recommends the first, since a typed exclusion that lifts
  tamper protection widens what "exclude" means; the decision belongs with PR #28. *Resolved: PR
  #28 landed the first, narrowing the row to `**/.claude/settings.json` and
  `**/.claude/settings.local.json`.*

---

## 9. Open questions

- **D-Bus filtering proxy (Linux).** The only way to separate `os-keyring` from `run-outside` on a
  Linux desktop is a bus proxy that admits named destinations (`org.freedesktop.secrets`) and refuses
  others (xdg-dbus-proxy is what Flatpak uses). A new component with its own trust surface; the
  coupling is reported until then.
- **HTTP/2 on inspected hosts.** HTTP/1.1 only through ALPN, or an h2 codec? A spike against the
  model-API clients decides.
- **Per-process trust on macOS.** Security.framework clients ignore env-var trust; a keychain search
  list is per user and `SecTrustSettings` has no per-process scope. Revisit if a brokered type's
  primary client cannot be replaced.
- **Narrower keychain lifts on macOS.** Brokering the Claude credential would need the Gateway to read
  the item and substitute it, which works only if the client also reads its token from an env var or
  file; C9 decides.
- **Request-signing credentials** (SigV4, GCP token minting) need a signer in the Gateway. Deferred.
- **Placeholders in request bodies.** Substitution is limited to the scheme's header.
- **Transparent mode.** The supervisor could redirect any allowed `connect()` on Linux, given a DNS
  answer path; on macOS it would need a Network Extension, which requires a signed system extension
  and an entitlement and is not proposed while releases are unsigned.
- **Namespace-tier init (Linux).** A forked Formwork process, or the launcher re-parented; the
  pre-exec code does not allocate, which constrains the choice.
- **`(deny default)` base on macOS.** A candidate for `strict` once C3 and C8 yield a complete
  allowlist for common toolchains.
- **`sandbox_init` deprecation.** The replacements are Endpoint Security (entitlement required) or
  App Sandbox containers (which do not fit arbitrary CLI trees); the Compiler/Confiner split keeps
  the change within one crate.
- **Landlock pathname-socket scoping.** If a future ABI mediates pathname `connect()`, `FW-ISO12`
  moves to Landlock.
- **D3 layout.** `.formwork/` in the project is recommended; a per-user state directory and Landlock
  `Make*` rights on the split root were the alternatives.
- **Local overlay convention.** A member who wants a personal file has no discovered location for it
  (the [FW-BP8](../formwork.md#fw-bp8) walk finds the project file first). A gitignored
  `.formwork/local.toml` would give the idiom; Growth says no until a second team asks.
- **Discovered layer per platform.** Learned fs paths are platform-shaped and two OSes rewrite one
  `.formwork/*.discovered.toml`; host and channel proposals are portable. A FEP-4-adjacent question.
- **Portable fs groups for `closed` mode.** Half of a mixed-OS team's file is platform paths
  (`/opt/homebrew`, `/System`, `~/Library/Caches` beside `/lib64`, `~/.cache`). One or two exact
  schema groups that expand per backend the way `desktop` does (`caches`, `toolchain`) would make
  unveil mode the reasonable default on a laptop. The same move this FEP makes for channels, and the
  recommended FEP-7 (FEP-6 took the egress engine).
- **`any:` as the all-methods verb.** Whether `https:` with a path should imply inspection instead,
  which would drop `any:`; kept because it keeps the grade visible in the verb.

---

## 10. Parity after this FEP

Conditional on the characterization suite confirming the **(characterize)** marks.

| Capability | Omnigent Linux | Omnigent macOS | Formwork Linux | Formwork macOS |
|---|---|---|---|---|
| Mandatory egress host allowlist | Enforced (netns) | Enforced (SBPL) | Enforced (supervisor) | Enforced (SBPL + authenticated listener), or `Partial` per C2 |
| Method/path rules | Enforced, not canonicalized | same | Enforced, canonicalized | Enforced for env-trust clients; platform-verifier clients refused |
| Credential injection | `Authorization` only; CA key on disk | same | any header scheme; ephemeral CA; floor holds | same, with the client-trust caveat |
| Private IP / metadata block | Enforced | Enforced | Enforced under host rules ([FW-EGR4](fep-1.md#fw-egr4)) | same |
| UDP / local resolver | closed | closed | closed (PR #29, `FW-EGR12`) | closed under host rules; resolver reported under `Ports` |
| Pathname AF_UNIX | unreachable (not mounted) | denied | mediated (supervisor) | Enforced (literals) |
| Host-service channels | closed | partly (mach open) | closed under supervised connect, else `Partial` | closed; keychain lift is whole-channel |
| Privileged interfaces | seccomp | not granted | seccomp | denied, IOKit allowlist |
| Other processes' environment | hidden | open **(characterize)** | `Enforced` unprivileged (Landlock); `Partial` with ptrace-class capabilities; `Enforced` under `isolate` | blocked, default-on |
| Process visibility / IPC | namespaces | self-only signal/info | opt-in, namespaces | opt-in, filters |
| Runs without user namespaces | no | n/a | yes, except `isolate` | n/a |
| `explain` / `learn` for egress and channels | no | no | yes | yes |
| Windows | Job Object only | — | not provided (non-goal) | — |
