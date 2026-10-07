# FEP-10 (proposal): credential sources — brokered secrets from keychains and password managers, and brokered OAuth refresh

**Formwork Enhancement Proposal 10 — proposal, not landed.** Companion to `formwork.md`
(design + end-to-end spec) and `constitution.md` (doctrine).

**Status: nothing in this document mutates the landed spec or the constitution.** Per the
constitution (Requirements & identifiers; Precedence & Conflicts), a draft lives in its FEP until
adoption. New identifiers are draft numbering, written as inline code, which the requirements canary
skips, until they are anchored on landing. This FEP holds the reserved blocks `FW-CRED23`..31,
`FW-EGR27`..30, `FW-INV20`, `FW-E2E-145`..156 and `FW-ADV-039`..042, and uses every number in them.
The §7 amendments are apply-on-landing blocks. No code has landed.

---

## 1. Problem

Brokering ([FW-CRED10](../formwork.md#fw-cred10)–[FW-CRED19](../formwork.md#fw-cred19)) keeps a
credential out of the session and presents it on bound hosts, but the Gateway can only get the
credential from one place: the environment of the process that runs `formwork`.
`crates/formwork-cli/src/main.rs:1370-1404` takes the first non-empty variable of the type's
`envs` and otherwise refuses to start ("none of its variables is set here"); the Catalog header
says so (`profiles/credential-catalog.toml:14-16`, "the credential's source is the type's first
env var set on the launching host"), and an inline binding names only an `env`
(`crates/formwork-blueprint/src/credential.rs:285-301`). Four consequences:

1. **The secret leaves the store the operator keeps it in.** To broker an API key held in
   1Password, the macOS keychain or a Secret Service collection, the operator exports it into a
   shell, where every process that shell starts inherits it and where, on macOS, a same-uid process
   reads an ancestor's exec-time environment through `kern.procargs2` (characterization C5).
   `formwork` zeroes its own exec-time environment for that reason (FEP-6 §4.7); the shell that
   launched it is outside its reach.
2. **No rotation.** [FW-CRED15](../formwork.md#fw-cred15) says the Gateway re-reads the source "at
   the interval the Catalog entry states", but a Catalog `broker` block carries only `hosts` and
   `scheme` (`crates/formwork-blueprint/src/catalog.rs:59-62`), and the CLI reads once. A
   short-lived token (OAuth access tokens commonly live an hour) expires mid-session and the
   session has to be restarted with a new export.
3. **OAuth tools are exposed, not brokered.** A tool that logs in with OAuth holds a refresh token
   that outlives the session. FEP-5 §3.2 records the result for Claude Code: its OAuth variant
   "lifts `claude` and brokers nothing" (`docs/fep-5.md:257-259`), so the agent holds the account's
   refresh token.
4. **Custody is weaker than the floor it serves.** `Broker` derives `Clone` and holds the secret
   as a `String` (`crates/formwork-gateway/src/inspect.rs:43-52`); `present` formats the scheme
   value into fresh `String`s (`inspect.rs:1127-1141`) that are dropped without being overwritten.

Two adjacent gaps sit in the same area. The password-manager CLIs' own session credentials,
`BW_SESSION` and `OP_SESSION_<account>`, contain none of the [FW-ENV2](../formwork.md#fw-env2) name
markers (`crates/formwork-blueprint/src/lib.rs:389-410`) and no Catalog type names them, so under
the default profile a confined process inherits an unlocked Bitwarden session key. And an inline
binding accepts any `env` and any `hosts` (`credential.rs:285-301`) from any layer, including a
`FORMWORK.toml` auto-discovered in a cloned repository
(`crates/formwork-cli/src/blueprint_load.rs:86-171`): such a file can direct the Gateway to present
any variable of the operator's environment to a host the same file inspects. Sources that reach the
keychain or a vault would widen that scope of impact from the operator's environment to every
secret the operator stores.

Who is hurt: operators who keep secrets in a keychain or password manager and will not export them;
anyone running an OAuth-authenticated agent; long sessions against short-lived tokens; operators
who clone repositories carrying a `FORMWORK.toml`.

### 1.1 Constraints this FEP holds to

- **No new concept.** A source is Blueprint data on an existing entry (`allow-credentials`,
  [FW-BP12](../formwork.md#fw-bp12)); the stores a source reads are Catalog locations, floored like
  every other ([FW-CRED4](../formwork.md#fw-cred4)); custody, refresh and token capture are Gateway
  mechanism. No family is added: CRED, EGR and INV carry everything.
- **Kernel-first floor.** Every store a source reads is denied to the session by the Confiner or
  stripped by the Launcher; the Gateway's handling is never the only thing standing between the
  agent and the store.
- **Fail loud before spawn.** A source that cannot be read stops the run before the workload starts
  ([FW-XR9](../formwork.md#fw-xr9), [FW-INV6](../formwork.md#fw-inv6)).
- **No agent-triggerable source access.** No confined action causes a source read or an
  interactive unlock prompt; an operator prompt is the social-engineering surface
  [FW-ADV-012](../formwork.md#fw-adv-012) already rules out for the floor.
- **Growth.** No CLI flag, no subcommand, no new crate. One extended Blueprint entry, two Catalog
  types and an env-name prefix form, one report section and key, one refusal reason, one stored
  document format.
- **Honesty.** Each source kind has a report verdict per platform (§3.10); a store the platform
  cannot close is `Partial`, with the reason.

---

## 2. Prior art: nono

Citations are `nono@9edf3ea:<path>:<line>`; after a file's first citation, later ones give the
file name, or only the line within the same file.

### 2.1 Mechanism and behavior

**Sources named by URI.** nono dispatches a credential reference by URI scheme: `env://VAR`,
`file:///path`, `op://vault/item/field`, `bw://item[/field]`, `apple-password://server/account`,
`keyring://service/account`, and anything else as an account in the keyring service `nono`
(nono@9edf3ea:crates/nono/src/keystore.rs:10-17, dispatch :283-310). Each scheme has a validator:
1Password needs at least three non-empty segments (:320-363); Bitwarden at most two, none starting
with `-` because the field is passed before `--` (:381-446); `keyring://` takes exactly
`service/account`, one query (`?decode=go-keyring`, for values Go tools store base64-wrapped) and at
most 1,024 bytes (:549, :587-647, decode :1633-1663); `file://` must be absolute with no `..`
(:846-888); `env://` must be a word and not a loader or interpreter control variable (:159-190,
:800-835). A shared forbidden-character set keeps shell metacharacters out of every program
argument (:193-195). The same blocklist guards the destination variable a phantom is written to
(`validate_destination_env_var`, :897-929).

**How each store is reached.** The keyring goes through the `keyring` crate (macOS Keychain, Linux
Secret Service), behind a feature whose declarations are pinned so a release cannot pull in libdbus
(nono@9edf3ea:crates/nono/Cargo.toml:41-70). 1Password, Bitwarden and Apple Passwords are programs:
`op read -- <uri>` (keystore.rs:1253-1318), `bw get` (:1321-1414),
`security find-internet-password -s <server> -a <account> -w` (:1502-1574), each with stdin closed,
a 30 s timeout (:36) and stderr classified into typed errors (`classify_op_error` :1666-1696,
`classify_bw_error` :1753-1795). Keyring calls run on a thread with a 120 s timeout chosen so an
operator can finish a KeePassXC unlock (issue #967), overridable by an environment variable
(:41-89, :94-113). Values are `Zeroizing<String>` (:19, :115-120); the module documents that the
child's stdout `Vec` is not zeroized (:276-280).

**Program trust.** The programs are resolved by bare name on `PATH`, outside the sandbox. A live
manual pentest found that a trojan `op` planted in a directory the session was about to be granted
write access to ran unsandboxed; the fix strips every sandbox-writable `PATH` entry before the
lookup (CHANGELOG #1733, nono@9edf3ea:CHANGELOG.md:429; `broker_command_with_path`
keystore.rs:1179-1206) and refuses when nothing safe remains (#1895, CHANGELOG.md:15). Its tests
are `broker_command_skips_trojan_in_writable_path_dir` (keystore.rs:2152),
`broker_command_errors_when_sanitized_path_is_empty` (:2204) and
`load_secrets_sanitizes_path_against_known_outer_caps` (:2244).

**When sources are read.** The proxy loads every route's credential at startup; a missing or locked
one is logged, recorded as a diagnostic, and the route stays configured but unavailable, so the
session starts and requests on that route are denied
(nono@9edf3ea:crates/nono-proxy/src/credential.rs:200-221, :276-300); the TLS smoke suite relies on
interception activating "regardless of resolution" (nono@9edf3ea:tests/integration/test_tls_intercept.sh:39-44).
A `cmd://` source runs a command lazily on the first matching request and caches its output
(keystore.rs:151-153; nono@9edf3ea:docs/cli/features/credential-injection.mdx:433). On a miss, the hint builder
looks the same name up in the other store, which for the keychain can raise a prompt
(credential.rs:779-835).

**OAuth.** Two mechanisms. `TokenCache` performs the `client_credentials` grant, refreshes 30 s
before expiry, assumes 3,600 s when `expires_in` is absent, bounds the token response to 64 KiB, and
on a failed refresh returns the stale token with a warning (nono@9edf3ea:crates/nono-proxy/src/oauth2.rs:1-17,
:30-39, :149-184). Sandboxed OAuth capture lets the tool log in inside the sandbox: the proxy
intercepts declared token endpoints, rewrites `access_token` and `refresh_token` to
`nono_<64hex>` phantoms (JWT-shaped for `id_token`), resolves a phantom in a refresh request body,
and fails closed when a token-shaped field appears on an undeclared path or an error body
(nono@9edf3ea:docs/cli/features/sandboxed-oauth-logins.mdx:17-24, :175-185;
nono@9edf3ea:crates/nono-proxy/src/oauth_capture/mod.rs:339-583, rewrite.rs:127-212). The captured tokens persist in a JSON file under nono's state directory with
owner-only permissions, kept up to 90 days and 4,096 phantoms, described as "plaintext-at-rest"
(sandboxed-oauth-logins.mdx:378-385; oauth_capture/persist.rs:67-121; mod.rs:51-52). Logging in
needs `--allow-launch-services` (sandboxed-oauth-logins.mdx:568-572). Logins of shipped agents are
verified by manual QA only (nono@9edf3ea:docs/cli/development/oauth-capture-manual-qa.mdx:6-10).

**Workload identity and signing.** SPIFFE JWT-SVIDs from a SPIRE agent socket, as a bearer or as a
`jwt-bearer` client assertion (nono@9edf3ea:docs/cli/features/spiffe.mdx:6-30), through the
`spiffe` crate (nono@9edf3ea:crates/nono-proxy/Cargo.toml:84); AWS SigV4 re-signing of each request
(credential-injection.mdx:715-752).

### 2.2 nono's tests in this area

`keystore.rs` carries 199 unit tests (from :2139): per-scheme validation, one test per forbidden
character, redaction, error classification, file trimming (`test_load_from_file_*`, :4209-4286),
keyring timeouts behind a process-global `ENV_LOCK` and an `EnvGuard` (:4040-4142), and dispatch
tests that pass whether or not `op`/`bw` is installed, asserting on message text
(`test_load_secret_by_ref_dispatches_op` :3634, `_bw` :3361). `credential.rs` has 18, including
`test_loaded_credential_debug_redacts_secrets` (:911) and
`test_load_missing_env_credential_records_credential_not_found` (:993). `oauth2.rs` has 15,
including `test_exchange_token_chunked_response` (:725, the #1976 regression) and
`test_token_cache_detects_expiry` (:863), which asserts the stale-token fallback.
`oauth_capture/mod.rs` has 16 (:339-784). `test_env_sanitization.sh` checks that
`OP_SERVICE_ACCOUNT_TOKEN` and `OP_SESSION_my` do not reach the child
(nono@9edf3ea:tests/integration/test_env_sanitization.sh:110-114).

### 2.3 Defects and limitations

- No reflection guard: nothing stops an upstream echoing an injected secret back into the sandbox.
  Formwork's [FW-CRED17](../formwork.md#fw-cred17) covers it, and §3.9 extends it to every source.
- A session starts with an unresolvable credential (credential.rs:200-221).
- A refresh failure presents a token known to be expired (oauth2.rs:149-184).
- Captured OAuth tokens rest in a plaintext file for up to 90 days (persist.rs:67-121).
- A bare reference falls back to a keyring lookup, so a typo reads the keychain (keystore.rs:306-309).
- `cmd://` runs a profile-named command lazily, at a time the agent's traffic chooses.
- The secret-manager child receives nono's whole environment, and the stdout buffer is not zeroized.
- Interactive login needs LaunchServices lifted; the browser hand-off is not brokered.
- Dispatch tests are host-dependent and match prose.

### 2.4 What Formwork adopts and declines

| nono quality | Formwork |
|---|---|
| URI-named sources, same spellings | **adopt** (`FW-CRED23`); a bare reference and `cmd://` are refused |
| Per-scheme validation, forbidden set, `?decode=go-keyring` | **adopt** |
| Programs for 1Password, Bitwarden, Apple Passwords | **adopt**, and programs for the OS keyring too (§3.3) instead of the `keyring` crate |
| `PATH` sanitization for source programs | **adopt**, extended to modify grants and to the file itself (`FW-CRED26`) |
| Read at startup | **adopt**, and refuse to start on failure (`FW-CRED24`) |
| Zeroized values, redacted `Debug` | **adopt**; every Formwork-owned buffer included (`FW-CRED25`) |
| Stripping the managers' session variables | **adopt** as Catalog types (`FW-CRED27`) |
| Refresh before expiry, 64 KiB token bound, chunked decoding | **adopt** (`FW-CRED30`) |
| Stale token on refresh failure | **decline**: refuse with `credential-unavailable` |
| Capture at the token endpoint; refresh-body substitution; undeclared-path backstop | **adopt** (`FW-EGR27`–29) |
| Plaintext capture store | **decline**: tokens live in the binding's own source (`FW-CRED31`) |
| `client_credentials` grant, JWT-shaped `id_token` phantoms | **decline** for now (§9) |
| SPIFFE, SigV4 | **decline** (§8) |

---

## 3. Design

### 3.1 Source vocabulary, and where it lives in the blueprint

A **source** is where the Gateway reads a brokered credential, named by a URI on the broker entry.
It extends the existing entry forms ([FW-BP12](../formwork.md#fw-bp12)); no field is added to the
Blueprint:

```toml
rules = ["allow:api.anthropic.com", "allow:github.com", "allow:api.github.com", "allow:ghe.corp.internal"]
allow-credentials = [
  "broker:openai",                                                         # landed form: env source
  { broker = "anthropic", source = "op://Private/Anthropic API/credential" },
  { broker = "github", source = "keyring://gh:github.com/octocat?decode=go-keyring" },
  { name = "ghe", env = "GHE_TOKEN", hosts = ["ghe.corp.internal"], scheme = "bearer",
    source = "file://~/.config/ghe/token" },
]
```

The kinds, exactly: `env://<NAME>` (`NAME` matches `[A-Za-z0-9_]+`); `file://<path>` (absolute or
`~/`-prefixed, the [FW-BP5](../formwork.md#fw-bp5) sigil, no `..`); `keyring://<service>/<account>`
with the optional query `?decode=go-keyring` and at most 1,024 bytes; `op://<vault>/<item>/<field>`
with an optional section segment before the field; `bw://<item>[/<field>]`;
`apple-password://<server>/<account>`. The **source forbidden set** is the control characters and
`` ` $ ; | & < > ( ) { } ! \ " ' ``; no segment may be empty, begin with `-`, or contain `?` or `#`
outside the one keyring query. A bare string, an unknown scheme and `cmd://` are parse errors.

Without `source`, a Catalog type keeps the landed default (its `envs`, first set wins) and an inline
binding reads its own `env`. With `source`, the variable named by the binding's `env`, or every
variable in the Catalog type's `envs`, carries the placeholder ([FW-CRED14](../formwork.md#fw-cred14))
and the launcher environment is not consulted. URIs are not secrets: the operator line prints the
source as written, since only a layer the operator chose may name one (§3.7).

### 3.2 When a source is read, and how it fails

Every static source is read once, by `formwork run`, after compile and before the workload is
spawned (`FW-CRED24`). First-use resolution is declined: it would make an unlock prompt appear at
a time the agent's traffic chooses, and would discover a missing credential after the session had
started working. A failure stops the run, emitting one operator line per failed binding with a
cause from the closed set `not-found`, `locked`, `timed-out`, `program-missing`,
`program-untrusted`, `malformed`, `too-large`; the confined process never starts. The typed error
behind it is `formwork_gateway::SourceError` with exactly those seven variants, none of which
carries program output (stderr is classified, then dropped). Static secrets do not rotate
mid-session; a 401 or 403 from a bound host already produces an operator line (FEP-6 §4.7), and the
remedy is a restart. Only OAuth bindings renew (§3.8).

### 3.3 How each kind is reached

| Kind | Linux | macOS | Write (OAuth) |
|---|---|---|---|
| `env://` | the launch environment captured at `main` | same | no |
| `file://` | `open(O_NOFOLLOW)`, at most **source-limit** bytes | same | yes: temporary file in the same directory, mode 0600, renamed over |
| `keyring://` | `secret-tool lookup service <s> username <a>` | `/usr/bin/security find-generic-password -s <s> -a <a> -w` | yes: `secret-tool store`, or `security -i` with `add-generic-password -U`, the value on stdin **(characterize)** |
| `apple-password://` | refused at compile | `/usr/bin/security find-internet-password -s <s> -a <a> -w` | no |
| `op://` | `op read -- <uri>` | same | no |
| `bw://` | `bw get item -- <item>`, field from the item JSON (login fields first, then custom fields) | same | no |

The attribute names `service` and `username` match the items `go-keyring` and Python `keyring`
write, so a token a tool already stored is readable without copying. Programs are run, not linked:
the `keyring` crate brings a D-Bus stack on Linux, which nono itself pins to keep libdbus out; a
program adds nothing to the build, `/usr/bin/security` is on the SIP-protected system volume, and
`op`, `bw` and `secret-tool` are run only when a blueprint names their kind. Each program runs with
stdin closed for reads, the value on stdin for writes, an environment of exactly `PATH`, `HOME`
and that program's own session variables (`OP_*` for `op`, `BW_*` for `bw`,
`DBUS_SESSION_BUS_ADDRESS` for `secret-tool`), and **source-timeout** to exit. No credential byte
is ever an argument or an environment variable of a program.

### 3.4 Program trust

`formwork run` resolves each needed program to an absolute path before spawn, walking `PATH`
in order and skipping relative entries and any candidate whose file or ancestor directory lies
under a write or modify grant of the session ([FW-CAP9](../formwork.md#fw-cap9): a modify grant
lets the session rewrite an existing `op` in place, which a directory-only check misses). `security`
is only ever `/usr/bin/security`. No candidate is executed during resolution; every read and
write in the session runs the resolved path (`FW-CRED26`).

### 3.5 The stores are floored

A source is useless as custody if the session can read its store. The Launcher and the Confiner
deny the session every location a named source reads, whatever the grants say (`FW-CRED27`): the
`file://` path, joined to the session's deny set the way [FW-CRED3](../formwork.md#fw-cred3) joins
a referenced file; `os-keyring` for `keyring://` and `apple-password://`
([FW-CRED13](../formwork.md#fw-cred13)); and two new Catalog types:

```toml
[types.1password]
envs = ["OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN", "OP_SESSION_*"]
paths = ["~/.config/op/**", "~/.op/**"]

[types.bitwarden]
envs = ["BW_SESSION", "BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD"]
paths = ["~/.config/Bitwarden CLI/**", "~/Library/Application Support/Bitwarden CLI/**"]
```

`OP_SESSION_*` needs a Catalog env-name prefix form: a trailing `*`, and nowhere else. Both types
are floored by default, so the gap of §1 closes for every session, brokering or not. The compiler
refuses a blueprint where floor and source collide (`FW-CRED28`): a `file://` source under a write
or modify grant; a type named bare in `allow-credentials` that shares a location with a source's
store type (`os-keyring` itself, or `claude`, whose macOS keychain services are the same); an inline
binding whose `env` is in the **control set** (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`,
`DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH`, `BASH_ENV`, `ENV`, `IFS`,
`CDPATH`, `PROMPT_COMMAND`, `NODE_OPTIONS`, `NODE_PATH`, `PYTHONSTARTUP`, `PYTHONPATH`, `PERL5OPT`,
`PERL5LIB`, `RUBYOPT`, `RUBYLIB`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `DOTNET_STARTUP_HOOKS`,
`GOFLAGS`, `PATH`, `HOME`, `SHELL`, compared case-insensitively; nono's list, keystore.rs:159-190);
`apple-password://` for a Linux host; `keyring://` for a Linux host whose HostProfile records no
session bus ([FW-FID10](../formwork.md#fw-fid10)); an OAuth binding whose source is not
`keyring://` or `file://`. Because grant paths canonicalize only at enforce time, `formwork run`
repeats the write-grant check on the canonical `file://` path, and opens it without following a
final symlink.

### 3.6 Custody in the Gateway

Every credential read from a source or captured at a token endpoint lives in a `Secret`: one owned
buffer, allocated at **source-limit** capacity so it never reallocates, overwritten with zeros on
drop and on replacement (`zeroize`), with no `Clone`, `Display` or `Serialize`, and a `Debug` that
prints `Secret([redacted])`. The scheme value (`Bearer …`, the Basic base64) and the rendered
request head that carries it are built into zeroizing buffers sized before the first write, so
they never reallocate either; the reflection guard's
encoding set holds `Secret`s (`FW-CRED25`). Program stdout is read into such a buffer and trimmed
in place. Token-endpoint JSON is located by scanning the buffered body for member byte ranges, not
by building a `serde_json::Value`, whose strings would be freed unzeroed. The `formwork`
process is made non-dumpable ([FW-CRED16](../formwork.md#fw-cred16)) before the first source read,
as it is today before the first environment read (`main.rs:1364-1367`). Nothing here ever reaches
a log record, an operator line or the FidelityReport, which carries the source kind only.
Swap and hibernation images are outside the threat model ([FW-XR2](../formwork.md#fw-xr2)).

### 3.7 Which layer may name a source

A source, and an inline binding (whose `hosts` choose where a secret goes), are honored only from a
layer the operator chose: the `--blueprint` file and its `extends` chain, `--set` fragments, and
`builtin:` profiles. The compiler refuses them from an auto-discovered `FORMWORK.toml`
([FW-FID7](../formwork.md#fw-fid7) source `auto-discovered`), from any file reached through that
file's `extends`, and from the discovered layer, naming the file and the `--blueprint` remedy
(`FW-CRED29`). `broker:<type>` with no source stays legal in a discovered file: the Catalog fixes
both the variable and the hosts. The check needs the layer of each `allow-credentials` entry, so
the [FW-FID6](../formwork.md#fw-fid6) provenance side table gains those entries.

### 3.8 OAuth

An OAuth binding is a broker entry with an `oauth` table:

```toml
rules = ["allow:api.example.test", "post:auth.example.test/oauth/token"]
allow-credentials = [
  { name = "example", env = "EXAMPLE_TOKEN", hosts = ["api.example.test"], scheme = "bearer",
    source = "keyring://formwork/example",
    oauth = { token-endpoint = "auth.example.test/oauth/token", client-id = "example-cli" } },
]
```

**The slot.** Per binding, the Gateway holds a slot: refresh token, access token, expiry, and two
placeholders, `fwcred-<name>-a-<64 hex>` for the access token and `fwcred-<name>-r-<64 hex>` for the
refresh token. The slot is stored in the source as one document, so the placeholders a tool
persisted in its own store keep working in the next session:

```json
{"formwork-oauth-slot":1,"access-token":"…","expires-at":1791331200,"refresh-token":"…",
 "placeholders":{"access":"fwcred-example-a-…","refresh":"fwcred-example-r-…"}}
```

An absent source entry is the one non-fatal read result: the session starts with an empty slot,
fresh placeholders and one operator line saying no login is stored; requests that need the token
are refused with `credential-unavailable` until a login completes.

**Presentation and refresh.** The access placeholder goes on the binding's `env`. The Gateway
presents the held access token by the binding's scheme while more than **refresh-margin** of its
lifetime remains; otherwise it first performs the refresh-token grant (RFC 6749 §6:
`grant_type=refresh_token`, the held refresh token, `client_id`) at the token endpoint, under one
lock per binding, through the same destination pipeline a confined request takes
([FW-EGR17](../formwork.md#fw-egr17), [FW-EGR24](../formwork.md#fw-egr24),
[FW-EGR26](../formwork.md#fw-egr26)) and only over TLS. Concurrent requests at expiry wait on the
lock and share one grant. A failed grant or an empty slot refuses the request with the new reason
`credential-unavailable` and one operator line; an expired token is never presented (`FW-CRED30`).
A missing `expires_in` means **default-lifetime**.

**Capture at the token endpoint.** The tool may refresh itself, and its login exchanges a code at
the same endpoint. On a request to the endpoint the Gateway buffers the body (at most
**token-limit**) and puts the held refresh token where the refresh placeholder is the whole value
of a top-level `refresh_token` (JSON) or a `refresh_token` field (form); the placeholder anywhere
else refuses the request as `placeholder` (`FW-EGR28`). On the response it buffers the body, takes
custody of the top-level `access_token` and `refresh_token` strings, writes the same placeholders in
their place, and forwards the body only if no other member, at any depth, whose name ends in
`token` (`token_type` excepted) carries a string (`FW-EGR27`). Both refresh paths take the per-binding
lock and substitute the current refresh token, so a Gateway refresh and a tool refresh cannot
consume a rotating refresh token twice. Every other response from the endpoint's host and port, on
any path and with any status, is scanned as it streams for a quoted `"access_token"`,
`"refresh_token"` or `"id_token"` member with a string value and ended as `reflection` on a match
(`FW-EGR29`). A response carrying `id_token` is refused; tools that parse one locally are not
supported (§9).

**Write-back.** Within **write-timeout** of any slot change the Gateway writes the slot to the
source, on the program's stdin (`FW-CRED31`); a failure is one operator line, and the response is
still forwarded, because withholding it would leave the tool holding a consumed refresh token.

**Login under the opener channel.** No new verb: `formwork run --blueprint login.toml -- <tool>
login` with `channels = ["open-url"]`. The tool's authorize URL goes through the opener shim
([FW-ISO17](../formwork.md#fw-iso17)) to the host browser ([FW-ISO18](../formwork.md#fw-iso18));
the browser's redirect reaches the tool's loopback listener, which the macOS profile admits
([FW-EGR15](../formwork.md#fw-egr15)) and which the Linux supervisor does not mediate (it sees only
the session's `connect()`s); the tool's code exchange passes through the Gateway, which captures the
tokens and writes the slot. LaunchServices and the session bus stay denied throughout. One residual
remains on both platforms: the authorization code and the tool's PKCE verifier pass through the
confined tool, so any host the login blueprint lets the session send to could carry them out before
redemption. The report states it (§3.10); a login blueprint should admit only the token and API
hosts.

### 3.9 The reflection guard covers every source

[FW-CRED17](../formwork.md#fw-cred17) needs only the encodings the Gateway presented, so it applies
unchanged to a credential from any source. Two OAuth additions: for a request to the token endpoint
the presented encodings include the refresh token substituted into the body, and for its response
the guard also scans for the values it has captured, after their members are replaced. A refresh
token echoed in an `error_description`, for example, ends the response as `reflection`.

### 3.10 What the FidelityReport says

`credentials.broker-sources` gains one entry per brokered binding, `{ kind, oauth, verdict }`, and
`per_capability.credential-source` carries the weakest of them ([FW-FID8](../formwork.md#fw-fid8)
amendment, §7). The compiler decides each verdict from the kind and the HostProfile; it does not
read the store.

| Kind | Linux | macOS |
|---|---|---|
| `env://` | the `process-environment` verdict ([FW-ISO16](../formwork.md#fw-iso16)); `Partial` names the launching processes' environments | `Partial` (Launcher): an ancestor's exec-time environment is readable through `kern.procargs2` (C5) |
| `file://` | `Enforced` (Landlock) | `Enforced` (Seatbelt) |
| `keyring://` | `Enforced` (Supervisor: the Secret Service bus is refused, [FW-ISO13](../formwork.md#fw-iso13)) | `Enforced` (Seatbelt: `securityd` services denied) |
| `apple-password://` | refused at compile | `Enforced` (Seatbelt) |
| `op://` | `Enforced` (Launcher and Supervisor: session variables stripped, `~/.config/op` denied, out-of-session sockets refused, [FW-ISO12](../formwork.md#fw-iso12)) **(characterize)** | `Partial` (Seatbelt): the 1Password app's integration service is reachable by Mach lookup, so a confined `op` can raise an approval prompt **(characterize)** |
| `bw://` | `Enforced` (Launcher and Landlock) | `Enforced` (Launcher and Seatbelt) |
| any kind with `oauth` | at most `Partial`: the login residual of §3.8 | same |

The existing `credential-broker` line (`Partial`, the reflection guard's limits) is unchanged.

### 3.11 Limits

Each value is defined here once and implemented as a named constant in `formwork-gateway`.

| Name | Value | Applies to |
|---|---|---|
| **source-timeout** | 120 s | from spawning a source program at session start to its exit (an interactive unlock; nono issue #967) |
| **write-timeout** | 10 s | from a slot change to the write-back program's exit |
| **source-limit** | 64 KiB | a source program's stdout or a `file://` source; the capacity of every `Secret` buffer |
| **token-limit** | 64 KiB | a token-endpoint request or response body buffered for substitution or capture |
| **refresh-margin** | 30 s | remaining access-token lifetime below which the Gateway refreshes first |
| **default-lifetime** | 3,600 s | access-token lifetime when the token response omits `expires_in` |

### 3.12 Where each piece lives

| Piece | Crate | Why there |
|---|---|---|
| `CredentialSource` parse, `OAuthBinding`, typed `BrokerError`, conflict and layer checks | `formwork-blueprint` (pure) | parsed once at the edge; beside `resolve_brokers` |
| Catalog types, env prefix form | `formwork-blueprint` + `profiles/credential-catalog.toml` | the floor |
| `broker-sources` verdicts | `formwork-compile` (pure) | HostProfile-only decision |
| `Secret`, program resolution, reads and writes (`source.rs`); slot, refresh, capture (`oauth.rs`) | `formwork-gateway` | custody and tokio live here; the Gateway already spawns stdio backends |
| Session-start read, file-source deny, placeholders | `formwork-cli` | the Launcher |

### 3.13 Asymmetries that remain

`apple-password://` is macOS-only. `op://` is `Partial` on macOS until the 1Password integration
service is characterized and denied. The memory property (`FW-CRED25`) has a black-box test on Linux
only, where a root harness can read the Gateway's memory; on macOS
[FW-CRED16](../formwork.md#fw-cred16)'s `PT_DENY_ATTACH` blocks the same probe, and unit tests stand in.

---

## 4. Surface changes (each measured against Growth)

- **Blueprint: `source` and `oauth` on `allow-credentials` entries, and the `{ broker, source }`
  table form.** Searched: the inline binding's `env` names both where the secret comes from and
  where the placeholder goes, and only the launcher environment can hold the former; `--allow-cred`
  exposes; `--set` already carries any Blueprint value, so no flag is needed. The entry is the
  [FW-BP12](../formwork.md#fw-bp12) field, extended expand-only (`deny_unknown_fields` keeps typos
  loud).
- **Catalog: types `1password` and `bitwarden`, and the trailing-`*` env form; `version = 3`.**
  Searched: the [FW-ENV2](../formwork.md#fw-env2) scrub is heuristic, reported `Partial` and liftable by
  `allow`, so it cannot be the floor; `OP_SESSION_<account>` cannot be enumerated without a prefix form.
- **Report: `credentials.broker-sources` and `per_capability.credential-source`.** Searched: the
  `credentials.brokered` list names types but has no room for a verdict per binding, and
  `credential-broker` is about presentation, not custody. Expand-only.
- **Refusal reason `credential-unavailable`** in the closed [FW-FID12](../formwork.md#fw-fid12) set.
  Searched: `placeholder` means the confined request is wrong and `reflection` that a response is;
  neither says the Gateway lacks the credential.
- **Stored format: the OAuth slot document v1.** A new Data-model surface, written only into the
  operator's own store; versioned by its `formwork-oauth-slot` key.
- **Typed errors:** `SourceError` (seven variants, §3.2) and `BrokerError`, which replaces the
  `Vec<String>` `resolve_brokers` returns today so tests assert variants, not prose. The OAuth
  module's `CaptureError`, `SlotError` and `GrantError` are `pub(crate)`, so they are not API
  surface. `RefusalReason` gains `CredentialUnavailable`.
- **Dependencies:** `zeroize` becomes a direct dependency of `formwork-gateway`. It is already in
  `Cargo.lock` through `rustls` and `rustls-pki-types`, so the build graph is unchanged. Declined:
  `keyring`, `security-framework`, `secret-service`, `spiffe`. Runtime programs (`op`, `bw`,
  `secret-tool`, `/usr/bin/security`) are optional and run only for their kind.
- **CLI:** none. Login is `formwork run -- <tool> login`.

---

## 5. Proposed requirements (draft numbering — anchored on landing)

| Req | Requirement |
|---|---|
| `FW-CRED23` **Source grammar** | The Blueprint parser shall accept as the `source` of an `allow-credentials` broker entry exactly the six kinds of §3.1 and shall reject, naming the entry, any other value and any value with an empty segment, a segment beginning with `-`, a character of the source forbidden set, a query other than `?decode=go-keyring` on `keyring://`, more than 1,024 bytes on `keyring://`, or a `..` component on `file://`. |
| `FW-CRED24` **Resolved before spawn** | `formwork run` shall read every brokered credential before spawning the workload, and, when any source other than an absent OAuth slot fails, shall exit non-zero without spawning it, emitting one operator line per failed binding naming the binding, the source as written and one cause from exactly `not-found`, `locked`, `timed-out`, `program-missing`, `program-untrusted`, `malformed`, `too-large`. |
| `FW-CRED25` **Zeroized custody** | The Gateway shall overwrite with zeros, before releasing it, every buffer it owns that holds a credential read from a source or captured at a token endpoint, the rendered scheme value and request head included. |
| `FW-CRED26` **Source program trust** | Before spawning the workload, `formwork run` shall resolve each source program the blueprint needs to an absolute path whose file and ancestor directories lie outside every write and modify grant of the session (`security` only as `/usr/bin/security`), shall refuse to start when no `PATH` entry yields one, and shall run only that path for the session's reads and writes. |
| `FW-CRED27` **Source stores floored** | The Launcher and the Confiner shall deny the session every location a named source reads: the `file://` path, and the locations of the source's store type (`os-keyring` for `keyring://` and `apple-password://`, `1password` for `op://`, `bitwarden` for `bw://`). |
| `FW-CRED28` **Source conflicts refused** | The compiler shall reject a blueprint in which any of the following holds (the list is exhaustive), naming the entry: a `file://` source under a write or modify grant; a type named bare in `allow-credentials` sharing a path, variable or service with a source's store type; an inline binding `env` in the control set; `apple-password://` for a Linux host; `keyring://` for a Linux host with no session bus; an OAuth binding whose source is not `keyring://` or `file://`. |
| `FW-CRED29` **Sources from chosen layers** | The compiler shall reject a `source` or an inline binding that comes from an auto-discovered blueprint file, from a file reached through such a file's `extends` chain, or from the discovered layer, naming the file and the `--blueprint` remedy. |
| `FW-CRED30` **OAuth presentation** | For an OAuth binding, the Gateway shall present the held access token only while more than **refresh-margin** of its lifetime remains, shall otherwise first obtain a new one by the refresh-token grant at the binding's token endpoint over TLS with at most one grant in flight per binding, and shall refuse the request with reason `credential-unavailable` when it holds no refresh token or the grant fails. |
| `FW-CRED31` **OAuth write-back** | Within **write-timeout** of any change to a binding's slot, the Gateway shall write the slot document to the binding's source through the source program's standard input, and shall emit one operator line naming the binding and its source when the write fails. |
| `FW-EGR27` **Token response capture** | For a response from an OAuth binding's token endpoint, the Gateway shall take custody of the top-level `access_token` and `refresh_token` strings, replace them with the binding's placeholders, and forward the body only if it is a JSON object of at most **token-limit** bytes in which no other member whose name ends in `token`, other than `token_type`, carries a string. |
| `FW-EGR28` **Token request substitution** | For a request to an OAuth binding's token endpoint, the Gateway shall substitute the held refresh token for the refresh placeholder only where the placeholder is the whole value of a top-level JSON `refresh_token` member or form `refresh_token` field of a body of at most **token-limit** bytes, and shall refuse the request with reason `placeholder` when the placeholder appears anywhere else in it. |
| `FW-EGR29` **Token host backstop** | For every other response from the host and port of an OAuth binding's token endpoint, the Gateway shall end the response with reason `reflection` before releasing any byte of a member named `access_token`, `refresh_token` or `id_token` whose value is a string. |
| `FW-EGR30` **Token endpoint closure** | The compiler shall reject an OAuth binding whose token endpoint is not covered by an inspected rule admitting `POST` on a port other than the plain-HTTP port, naming the rule to add. |

Invariant:

| Inv | Invariant |
|---|---|
| `FW-INV20` **Source non-disclosure** | For every source kind on both backends, no byte of a credential the Gateway read from a source or captured at a token endpoint appears in a confined process's environment, in a file, service or process argument list it can read, in any Gateway response to it, in a log record or operator line, or in the FidelityReport. The source and OAuth form of [FW-INV13](../formwork.md#fw-inv13), tested to falsify. |

---

## 6. Verification plan

The run-level tests use the fixtures of [FW-E2E-099](../formwork.md#fw-e2e-099) (`127.0.0.1` and
`localhost` TLS fixtures with a fixture root in `SSL_CERT_FILE`), the host-opener fixture of
[FW-E2E-090](../formwork.md#fw-e2e-090) (`FORMWORK_HOST_OPENER`), and three new fixtures (§6.3.3):
fake source programs, a token endpoint, and a test keyring (a session `gnome-keyring` under
`dbus-run-session` on Linux CI; a `security create-keychain` keychain on macOS, as
[FW-E2E-081](../formwork.md#fw-e2e-081) does). Blueprints are passed with `--blueprint`, except
where discovery is the subject.

### 6.1 End-to-end tests (draft)

`FW-E2E-145` **Every source kind through `run` (both).** One session brokers six inline bindings to
the fixture: `file://`, `keyring://` (test keyring), `env://`, `op://` and `bw://` (fake programs in
an ungranted directory) and, on macOS, `apple-password://`. The workload's first command, issued
without delay, is one `curl` per binding; then it reads the `file://` path and a sibling file in the
same directory, and asks the keyring for the item (`secret-tool lookup` on Linux, `security
find-generic-password` on macOS), each with an unconfined control. Harness
`crates/formwork-cli/tests/fep10_run.rs`. **Pass:** the fixture receives each secret in its scheme
header; the confined environment holds only `fwcred-` values; the source file is denied and its
sibling read; the keyring lookup fails inside and succeeds in the control. **Fail:** any header
lacks its secret, any secret is readable in the session, or a control fails. Derived from nono
`test_load_secret_by_ref_dispatches_file_uri` (keystore.rs:4306) and the dispatch tests (:3361,
:3634), made hermetic.

`FW-E2E-146` **Fail loud before spawn (both).** Seven runs whose workload creates a marker file:
a missing `file://`, an absent keyring item, an `op` fake that fails "not signed in", a `bw` fake that
prints nothing, `op` absent from `PATH`, only a write-granted `op` on `PATH`, and a 65,537-byte
`file://`. Harness `fep10_run.rs`. **Pass:** each exits non-zero, the marker is absent, stderr has
one line naming the binding, the source and `not-found`, `not-found`, `locked`, `locked`,
`program-missing`, `program-untrusted` and `too-large` respectively; each fixed variant (a
65,536-byte file in the last case) runs and creates the marker. **Fail:** any marker appears, or a
cause differs. `timed-out` is covered in §6.3, since **source-timeout** is two minutes. Derived from
nono `test_load_missing_env_credential_records_credential_not_found` (credential.rs:993), inverted:
nono starts the session.

`FW-E2E-147` **Program trust (both).** `PATH` lists a workspace directory granted `readwrite:` and
holding a fake `op`, then an ungranted directory with another; a second case grants the second fake
`modify:` (directory untouched); a third leaves only the granted one. Harness `fep10_run.rs`.
**Pass:** case one runs the ungranted fake (its call log has one entry, the planted one's none); cases
two and three refuse with `program-untrusted` and neither call log has an entry. **Fail:** a
candidate under a grant runs, or any candidate runs during resolution. Derived from nono
`broker_command_skips_trojan_in_writable_path_dir` (keystore.rs:2152),
`broker_command_errors_when_sanitized_path_is_empty` (:2204),
`load_secrets_sanitizes_path_against_known_outer_caps` (:2244).

`FW-E2E-148` **Store floor (both).** `formwork` runs with `OP_SESSION_fixture`,
`OP_SERVICE_ACCOUNT_TOKEN`, `BW_SESSION` and `BW_CLIENTSECRET` set, `~/.config/op/config` and the
platform's Bitwarden CLI data file present, and an `op://` binding. The workload prints `env` and
reads both files and `~/.config/other/file`. Repeated under the default profile with nothing
brokered. Harness `fep10_run.rs`. **Pass:** in both runs the four variables are absent and both
files denied while `~/.config/other/file` is read; the `op` fake's call log shows it received
`OP_SESSION_fixture`. **Fail:** any variable or file reaches the session, or the fake did not get its
session. Derived from nono `test_env_sanitization.sh:110-114`.

`FW-E2E-149` **Blueprints the compiler refuses (both).** `formwork compile` on: sources
`op://v//f`, `cmd://github`, `keyring://a/b?decode=x`, `file://rel`, `file:///a/../b`; a `file://`
source under `readwrite:` and under `modify:`; `os-keyring` bare, and `claude` bare, with a `keyring://`
source; `1password` bare with an `op://` source; an inline `env = "ld_preload"`; `apple-password://` (Linux
runner); an OAuth binding with an `op://` source; OAuth token endpoints under `tunnel:`, under a
port-80 rule and under `get:` only. Harness `py/harness/test_credential_sources.py`. **Pass:** each
fails naming the entry or the rule to add; each corrected variant compiles. **Fail:** any case
compiles or names the wrong entry. Derived from nono `test_validate_op_uri_empty_vault`
(keystore.rs:2822), `test_validate_keyring_uri_unknown_decode_value_rejected` (:2582),
`test_validate_file_uri_rejects_traversal` (:4181), `test_validate_destination_env_var_dangerous_case_insensitive` (:3935).

`FW-E2E-150` **Sources come from chosen layers (both).** In a user-owned directory a
`FORMWORK.toml` carries, in turn: a `{ broker = "anthropic", source = … }` entry; an inline
binding with no source; an `extends` to a sibling file holding an inline binding; `broker:anthropic`
alone. Harness `test_credential_sources.py`. **Pass:** the first three runs refuse before any source
program runs (fake call logs empty), naming the file and `--blueprint`; the same files given with
`--blueprint` run; the fourth runs auto-discovered. **Fail:** a source is read for an auto-discovered
layer, or the explicit door refuses.

`FW-E2E-151` **Report per source kind (both).** `formwork compile` of one blueprint holding every
kind the host accepts, one with `oauth`. Harness `test_credential_sources.py`. **Pass:** each
`broker-sources` entry carries the §3.10 verdict for the host OS; `per_capability.credential-source`
is the weakest; the section's key set equals `crates/formwork-compile/tests/fixtures/broker-sources-v1.json`;
every `Enforced` row is matched by a denied probe in `FW-E2E-145` or `FW-E2E-148`
([FW-INV5](../formwork.md#fw-inv5)). **Fail:** a verdict, key or probe disagrees.

`FW-E2E-152` **OAuth refresh at expiry (both).** The test writes a slot whose access token `at-0`
expires 45 s later; the token fixture issues tokens with `expires_in: 31` and rotates refresh
tokens (a reused one gets `invalid_grant`). The workload sends one API request at once, two
concurrent requests at 20 s, and, after the test has made the fixture revoke `rt-1`, a fourth at
22 s. Harness `fep10_run.rs`. **Pass:** the API fixture sees `at-0`, then `at-1` twice; the token
fixture sees exactly two grants, carrying `rt-0` and then `rt-1`; the fourth request is refused with
`credential-unavailable` and reaches no fixture; no `fwcred-` value is presented upstream.
**Fail:** a third grant, an expired token presented, or a request forwarded without a valid token.
Derived from nono `test_token_cache_detects_expiry` (oauth2.rs:863), inverted.

`FW-E2E-153` **Write-back and the next session (both).** A session set up as in `FW-E2E-152`
performs one refresh (`rt-0` to `rt-1`) and exits; a second `formwork run` with the same blueprint
sends one API request. Harness `fep10_run.rs`. **Pass:** after session one the source holds `rt-1`,
`at-1` and the original placeholders, and the `secret-tool`/`security` fake's argument log contains
neither token; session two presents `at-1` or a token granted from `rt-1`, and its placeholder
equals session one's. **Fail:** the source still holds `rt-0`, a token appears in an argument, or
session two cannot present. Derived from nono `persisted_capture_store_resolves_phantom_after_reload`
(oauth_capture/mod.rs:618), with the store moved into the operator's source.

`FW-E2E-154` **Login under the opener channel (both).** Empty source; `channels = ["open-url"]`; the
host opener fixture plays the browser, calling the URL's `redirect_uri` with a code from outside the
session. The confined fixture CLI (`python3`) first calls the API with the env placeholder, then
runs `login` (loopback listener, opener, code exchange through the Gateway, response saved to
`~/.fixture-cli/auth.json`), then calls the API with the saved access value. Harness `fep10_run.rs`.
**Pass:** the first call is refused `credential-unavailable` and reaches no fixture; `auth.json`
holds only the binding's placeholders; the last call reaches the API with `at-1`; the source holds
`rt-1`; `lsopen` (macOS) and the session bus (Linux) stay denied. **Fail:** any token value reaches
the CLI, or the callback is refused on either platform. Derived from nono
`response_rewrite_mints_phantoms_and_resolves_only_admitted_consumers` (oauth_capture/mod.rs:339)
and the manual QA it replaces (oauth-capture-manual-qa.mdx:20-40).

`FW-E2E-155` **Token request substitution and host backstop (both).** After a login, the fixture CLI
refreshes with the refresh placeholder in a form body and then a JSON body, and sends one form
request with it in `client_secret`; the token host also answers `/oauth/token/`, `/userinfo` and a
400 with a token member. Harness `fep10_run.rs`. **Pass:** the fixture receives the held refresh
token in `refresh_token` both times; the `client_secret` request is refused `placeholder` and
reaches no fixture; the three responses end as `reflection` with no token byte at the client.
**Fail:** any of these differs. Derived from nono `request_rewrite_resolves_form_refresh_phantom`
(oauth_capture/mod.rs:516), `request_rewrite_resolves_refresh_phantom` (:468),
`capture_host_response_fails_closed_on_token_fields` (:543).

`FW-E2E-156` **Replaced credentials leave the Gateway's memory (Linux, root in the CI
container).** In `FW-E2E-152`'s session, between the first refresh and the fourth request, the
harness stops `formwork` with `SIGSTOP`, reads every private readable mapping through
`/proc/<pid>/mem`, and resumes it. Gate:
`not_exercised("not root")`, a failure on CI. Harness `fep10_run.rs`. **Pass:** `at-0` and `rt-0`
occur zero times; `at-1` occurs at least once, so the scan is not vacuous. **Fail:** a replaced value
occurs. macOS: §3.13.

### 6.2 Adversarial tests (draft)

`FW-ADV-039` **Source non-disclosure sweep (`FW-INV20`, both).** Property: no credential from any
source kind, nor an OAuth token, reaches any surface a confined process can observe, or the
operator's records. Probe classes, run while fake source programs hold the read and the write-back
open for 500 ms: every confined-readable environment and argument list of every visible process
(`/proc/*/environ`, `/proc/*/cmdline`; `kern.procargs2` on macOS); files under `$HOME` and the
session scratch; every response, the fixture's reflection paths included; the run's stderr at
`RUST_LOG=trace`; the compile JSON. Harness `fep10_run.rs`. **Pass:** no 8-byte run of any value
appears. **Fail:** one does. Derived from nono `test_loaded_credential_debug_redacts_secrets`
(credential.rs:911) and `test_keystore_error_detail_redacts_credential_ref_in_message` (:1043).

`FW-ADV-040` **A blueprint the operator did not choose cannot pick a secret or its destination
(both).** Property: no layer outside §3.7 causes a source read or binds hosts. Probes: an
auto-discovered file with a keyring source bound to `collector.test`, one with an inline `env`
binding, one whose `extends` reaches such a file, and the discovered layer carrying an entry. Harness
`test_credential_sources.py`. **Pass:** each refuses before any program runs or listener opens.
**Fail:** a source program's call log has an entry.

`FW-ADV-041` **No agent-triggerable source access (both).** Property: after spawn, no confined
action causes a source read or a prompt, and the source is written only when the slot changes.
Probes: 1,000 requests with placeholders, requests the fixture answers 401, unknown placeholders,
and refresh requests for an unexpired slot. Harness `fep10_run.rs`. **Pass:** each source program's
log has exactly one read, at session start, and one write per slot change. **Fail:** more.

`FW-ADV-042` **Reflection over every source and token (both).** Property:
[FW-CRED17](../formwork.md#fw-cred17) holds for each source kind and for OAuth. Probes: for a
binding of each kind and an OAuth binding, the fixture echoes the presented value split across two
writes 50 ms apart, in a header, and gzip-coded; the token fixture echoes the sent refresh token in
an `error_description` and returns an extra `session_token` member. Harness
`crates/formwork-gateway/tests/oauth.rs`. **Pass:** no 8-byte run reaches the client, and each case
records `reflection`. **Fail:** one does. Extends [FW-ADV-021](../formwork.md#fw-adv-021); nono has
no counterpart (§2.3).

### 6.3 Unit and property tests

#### 6.3.1 Where the tests live

| Module | Layer and why |
|---|---|
| `crates/formwork-blueprint/src/credential.rs` `mod tests` | pure: source grammar, `resolve_brokers` conflicts and layer checks; no filesystem, no programs |
| `crates/formwork-blueprint/src/catalog.rs` `mod tests`, `src/launcher.rs` `mod tests` | pure: env prefix form; `construct_env` takes the environment as its `vars` argument |
| `crates/formwork-cli/tests/profiles.rs` | the Catalog canary: the shipped types exist and are floored |
| `crates/formwork-compile/tests/broker_sources.rs` (new) | pure compiler on synthesized `HostProfile`s, golden fixture, determinism |
| `crates/formwork-gateway/src/source.rs` `mod tests` (new) | `Secret`, program resolution and execution against fake programs in a test directory; no network |
| `crates/formwork-gateway/src/oauth.rs` `mod tests` (new) | pure byte-level capture, substitution, marker scan and slot timing with an injected `now` |
| `crates/formwork-gateway/tests/oauth.rs` (new) | Gateway behavior over sockets with `tests/support/mod.rs` (`Session::new(rules, resolver)`, `fixture_tls`, `upstream`, `violation_for`) plus the new `token_endpoint` |
| `crates/formwork-cli/tests/fep10_run.rs` (new) | `FW-E2E-145`..148, 152..156, `FW-ADV-039`, 041, using `support::{formwork_env, not_exercised, egress_host}` and the new fixtures |
| `py/harness/test_credential_sources.py` (new) | `FW-E2E-149`..151, `FW-ADV-040`, marked `@pytest.mark.fw_e2e(...)` / `@pytest.mark.fw_adv(...)` |

No new test touches `formwork-confine`: the denials are existing Confiner rules fed new paths, and
the run-level tests probe them through the kernel.

#### 6.3.2 The test list

**`formwork-blueprint/src/credential.rs`.** nono's `keystore.rs` carries 199 tests, about 90 on
validation; this module plans 24, because one table-driven test replaces nono's per-character tests
and no CLI list-mapping syntax exists to test.

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `env_source_parses_its_variable_name` | `FW-CRED23` | — | `CredentialSource::parse("env://ANTHROPIC_API_KEY", HOME)` → `assert_eq!(.., Ok(CredentialSource::Env("ANTHROPIC_API_KEY".into())))` | keystore.rs:3688 |
| `env_source_rejects_an_empty_or_non_word_name` | `FW-CRED23` | — | `"env://"`, `"env://A-B"` → `matches!(e, SourceParseError::Name { .. })` | :3696, :3706 |
| `file_source_expands_the_home_sigil` | `FW-CRED23` | `const HOME: &str = "/home/u"` | `"file://~/.config/t"` → `File("/home/u/.config/t")` | :4161 |
| `file_source_rejects_a_relative_path` | `FW-CRED23` | — | `"file://rel"` → `SourceParseError::Relative` | :4174 |
| `file_source_rejects_a_parent_component` | `FW-CRED23` | — | `"file:///a/../b"` → `Traversal` | :4181 |
| `file_source_rejects_an_empty_path` | `FW-CRED23` | — | `"file://"`, `"file:///"` → `Empty` | :4168 |
| `keyring_source_splits_service_and_account` | `FW-CRED23` | — | `"keyring://gh:github.com/octocat"` → `Keyring { service: "gh:github.com", account: "octocat", decode: Decode::None }` | :2523 |
| `keyring_source_accepts_only_the_go_keyring_decode_query` | `FW-CRED23` | — | `?decode=go-keyring` → `Decode::GoKeyring`; `?decode=x`, `?foo=1`, `?decode` → `Query` | :2571, :2582, :2600, :2605 |
| `keyring_source_rejects_a_third_segment_and_a_fragment` | `FW-CRED23` | — | `"keyring://a/b/c"` → `Shape`; `"keyring://a/b#f"` → `Shape` | :2612, :2593 |
| `keyring_source_is_bounded_at_1024_bytes` | `FW-CRED23` | `fn keyring_of_len(n: usize) -> String` | 1,024 → `Ok`; 1,025 → `TooLong` | :2755 |
| `op_source_accepts_three_or_four_segments_with_spaces` | `FW-CRED23` | — | `"op://Private/Anthropic API/credential"`, `"op://v/i/s/f"` → `Ok(Op(..))` | :2771, :2777, :2784 |
| `op_source_rejects_empty_and_missing_segments` | `FW-CRED23` | — | `"op://v//f"`, `"op://v/i"` → `Shape` | :2800, :2822-2843 |
| `every_kind_rejects_each_forbidden_character` | `FW-CRED23` | `const FORBIDDEN: &[char]` | for each kind × char, insert into a segment → `Forbidden { ch }` with that `ch`; 6 × 19 cases | :2860-2907, :3041-3091 |
| `bw_source_accepts_an_item_and_an_optional_field` | `FW-CRED23` | — | `"bw://abc"`, `"bw://abc/totp"` → `Ok` | :2977, :2982 |
| `bw_source_rejects_a_segment_starting_with_a_dash` | `FW-CRED23` | — | `"bw://-x"`, `"bw://x/-f"` → `LeadingDash` | :3121, :3131 |
| `apple_password_source_requires_server_and_account` | `FW-CRED23` | — | `"apple-password://github.com/alice@example.com"` → `Ok`; `".../github.com"` → `Shape` | :2431, :2456 |
| `an_unknown_scheme_or_bare_name_is_not_a_keyring_lookup` | `FW-CRED23` | — | `"my-account"`, `"vault://x"`, `"cmd://github"` → `UnknownScheme` | keystore.rs:306-309 (designed out) |
| `the_display_form_parses_back_to_the_same_source` | `FW-CRED23` | `fn every_kind() -> Vec<&'static str>` | `parse(&s.to_string()) == Ok(s)` for each | — ([FW-FID4](../formwork.md#fw-fid4)) |
| `a_control_variable_is_refused_as_a_destination` | `FW-CRED28` | `fn inline(env: &str) -> CredentialEntry` | `resolve_brokers(&[inline("ld_preload")], ..)` → `BrokerError::ControlVariable { .. }`; `"GHE_TOKEN"` → `Ok` | :3929, :3935 |
| `a_file_source_under_a_write_or_modify_grant_is_refused` | `FW-CRED28` | `fn grants(writes: &[&str], modify: &[&str]) -> FsGrants` | `/home/u/p/t` under `writes = ["/home/u/p/**"]` → `SourceWritable`; under `modify = ["/home/u/p/t"]` → same; `/home/u/q/t` → `Ok` | — |
| `a_source_whose_store_is_exposed_is_refused` | `FW-CRED28` | `fn entries(raw: &str) -> Vec<CredentialEntry>` | `["os-keyring", {broker="anthropic", source="keyring://a/b"}]` → `StoreExposed { store: "os-keyring", by: "os-keyring" }`; `"claude"` with the same source → `StoreExposed { by: "claude", .. }`; `"1password"` with `op://` likewise; `"aws"` → `Ok` | — |
| `an_oauth_binding_needs_a_writable_kind` | `FW-CRED28` | `fn oauth(source: &str) -> CredentialEntry` | `op://`, `bw://`, `env://` → `OAuthSourceNotWritable`; `keyring://`, `file://` → `Ok` | — |
| `a_source_from_an_auto_discovered_layer_is_refused` | `FW-CRED29` | `fn origin(o: LayerOrigin) -> Provenance` | entry with source at `Discovered` → `FromUnchosenLayer`; at `Flag` → `Ok`; `broker:anthropic` at `Discovered` → `Ok` | — |
| `an_inline_binding_through_a_discovered_extends_chain_is_refused` | `FW-CRED29` | same | `LayerOrigin::ExtendsOf(Discovered)` → `FromUnchosenLayer` | — |

**`catalog.rs`, `launcher.rs`, `profiles.rs`** (6 tests).

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `an_env_prefix_matches_names_that_start_with_it` | `FW-CRED27` | `Catalog::from_toml` | `envs = ["OP_SESSION_*"]`; `matches("OP_SESSION_my")` true, `"OP_SESSIONS"` false | — |
| `a_star_before_the_end_of_an_env_name_is_refused` | `FW-CRED27` | same | `"OP_*_X"` → `CatalogError::EnvPattern { .. }` | — |
| `construct_env_strips_password_manager_sessions_in_passthrough` | `FW-CRED27` | `vars(&[(&str, &str)])` (existing) | `construct_env(&EnvPosture::Passthrough, &builtin, &[], &channels, vars(&[("OP_SESSION_my","x"),("BW_SESSION","y"),("PATH","/usr/bin")]))` → `strip` has both with types `1password`, `bitwarden`; `kept` has `PATH` | test_env_sanitization.sh:110-114 |
| `an_op_source_puts_the_placeholder_on_every_env_of_the_type` | `FW-CRED27` | same | `broker:github` with `op://` source → `GITHUB_TOKEN` and `GH_TOKEN` both `fwcred-github-` | — |
| `the_password_manager_types_ship_floored` | `FW-CRED27` | `ResolvedCatalog::builtin_for_home("/h")` | both types present; `enforced_types(&[])` contains both | — |
| `the_catalog_version_is_three` | `FW-CRED27` | same | `assert_eq!(catalog.version, 3)` | — |

**`formwork-compile/tests/broker_sources.rs`** (9 tests; nono has no compile-time report to compare).

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `each_kind_reports_its_verdict_per_platform` | [FW-FID8](../formwork.md#fw-fid8) (amended) | `fn host(os: Os, bus: bool) -> HostProfile` | table of (kind, os) → `matches!` on `Fidelity::{Enforced, Partial}` and `Backend` per §3.10 | — |
| `an_env_source_on_macos_is_partial_from_the_launcher` | [FW-FID8](../formwork.md#fw-fid8) | same | `(Env, Os::MacOs)` → `matches!(v, Fidelity::Partial { backend: Backend::Launcher, .. })`; `(Env, Os::Linux)` with `process-environment` `Enforced` → `Enforced` | — |
| `an_oauth_binding_is_at_most_partial` | [FW-FID8](../formwork.md#fw-fid8) | same | `file://` + `oauth` → `Partial` | — |
| `credential_source_is_the_weakest_binding` | [FW-FID8](../formwork.md#fw-fid8) | same | `file://` + `env://` on macOS → `per_capability[CredentialSource]` is `Partial` | — |
| `apple_password_for_linux_is_refused` | `FW-CRED28` | `compile(&bp, &host(Os::Linux, true))` | `Err(CompileError::Broker(BrokerError::Unsupported { kind: SourceKind::ApplePassword, .. }))` | keystore.rs:3649 (designed out) |
| `keyring_without_a_session_bus_is_refused_on_linux` | `FW-CRED28` | `host(Os::Linux, false)` | `Unsupported { kind: Keyring, .. }`; with bus → `Ok` | — |
| `a_token_endpoint_without_a_tls_post_rule_is_refused` | `FW-EGR30` | `fn oauth_bp(rule: &str) -> Blueprint` | `tunnel:`, port-80 `post:`, `get:` → `TokenEndpointNotInspected { rule_to_add }`; `post:auth.test/oauth/token` → `Ok` | — |
| `broker_sources_has_exactly_these_keys` | [FW-FID8](../formwork.md#fw-fid8) | golden `tests/fixtures/broker-sources-v1.json` | `BTreeSet` of keys at `/credentials/broker-sources/*` == `{kind, oauth, verdict}` | schema_shape.rs:11-40 |
| `broker_sources_compile_byte_identically` | [FW-FID4](../formwork.md#fw-fid4) | same blueprint | two `serde_json::to_vec` equal | — |

**`formwork-gateway/src/source.rs`** (21 tests; nono's dispatch, classification, file and timeout tests number about 60).

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `secret_debug_prints_no_byte_of_the_value` | `FW-CRED25` | `Secret::from_slice(b"sk-fixture-5f3a")` | `format!("{s:?}") == "Secret([redacted])"` | credential.rs:911 |
| `secret_is_not_clone` | `FW-CRED25` | rustdoc `compile_fail` block on `Secret` | `let _ = s.clone();` fails to compile | — |
| `replacing_a_secret_zeroes_the_old_buffer` | `FW-CRED25` | `Secret::with_probe()` (`#[cfg(test)]` constructor recording the buffer's bytes at drop) | `slot.replace(new)` → probe of old buffer all `0` | — |
| `resolution_skips_a_directory_under_a_write_grant` | `FW-CRED26` | `fake_program`, `WriteGrants::from_patterns` | §6.3.5 | keystore.rs:2152 |
| `resolution_skips_a_modify_granted_file` | `FW-CRED26` | same | grant `modify` on `ro/op` only → `ProgramUntrusted` | — |
| `resolution_refuses_when_no_entry_is_safe` | `FW-CRED26` | same | `PATH` = granted dir only → `SourceError::ProgramUntrusted { program: "op" }` | :2204 |
| `resolution_ignores_relative_entries` | `FW-CRED26` | same | `PATH = ".:ro"`, fake in `.` and `ro` → `ro/op` | :2204 (cwd case) |
| `security_resolves_only_to_usr_bin_security` | `FW-CRED26` | `#[cfg(target_os = "macos")]`; fake `security` first on `PATH` | → `Ok("/usr/bin/security")`; the fake's call log is empty | — |
| `op_receives_the_uri_after_a_double_dash` | `FW-CRED23` | `fake_program(.., Answers("sk"))`, `calls()` | argv == `["read", "--", "op://v/i/f"]` | keystore.rs:1260-1262 |
| `a_program_gets_exactly_its_own_session_variables` | `FW-INV20` | `LaunchEnv(vec![..])` with `ANTHROPIC_API_KEY`, `OP_SESSION_my`, `BW_SESSION` | recorded env names == `{HOME, OP_SESSION_my, PATH}` | — (nono passes all) |
| `a_trailing_newline_is_trimmed_and_inner_space_kept` | `FW-CRED24` | `Answers("  sk x  \n")` | `secret.expose() == b"  sk x  "` | :4257, :4267 |
| `an_empty_answer_is_malformed` | `FW-CRED24` | `op` fake, `Answers("\n")` | `Malformed` | :4277 |
| `an_answer_over_the_limit_is_too_large` | `FW-CRED24` | `Answers` of 65,536 and 65,537 bytes | `Ok`; `TooLarge` | — |
| `a_program_past_the_timeout_is_killed_and_timed_out` | `FW-CRED24` | `Slow { secs: 10, .. }`, `read_with_timeout(.., Duration::from_millis(50))` | `TimedOut`; `waitpid(pid, WNOHANG)` then fails with `ECHILD` (the child was killed and reaped) | :4128 |
| `stderr_classifies_into_typed_causes` | `FW-CRED24` | `Fails { stderr, code: 1 }`, a table | op `"not signed in"` → `Locked`; op `"isn't an item"` → `NotFound`; bw `"Vault is locked."` → `Locked`; bw empty stdout and stderr → `Locked`; security `"could not be found"` → `NotFound`; `"User interaction is not allowed"` → `Locked`; unknown → `Malformed`; no variant holds the stderr text | :3183-3264, :3543-3593 |
| `a_missing_program_is_program_missing` | `FW-CRED24` | `PATH` with no `op` | `ProgramMissing` | :3634 (made hermetic) |
| `bw_field_prefers_login_fields_then_custom_fields` | `FW-CRED23` | item JSON literals | `password`, `username`, custom `api-key`, absent → `NotFound` | :3394-3461 |
| `go_keyring_values_are_unwrapped` | `FW-CRED23` | `Answers("go-keyring-base64:c2stZml4")` | `b"sk-fix"`; missing prefix → `Malformed` | :2666, :2676, :2688 |
| `a_file_source_symlink_is_not_followed` | `FW-CRED28` | `TestDir`, `symlink(target, path)` | `Malformed`; the target's bytes are never read | — |
| `a_slot_write_puts_the_slot_on_stdin_only` | `FW-CRED31` | fake `secret-tool` recording argv and stdin | argv lacks every slot byte; stdin == slot document | :4288 (file store, contrasted) |
| `an_env_source_reads_the_captured_launch_environment` | `FW-CRED24` | `LaunchEnv(vec![("X", "v")])` | `read(&Env("X"), &launch)` → `b"v"`; `"Y"` → `NotFound` | :3775 (process env, designed out) |

**`formwork-gateway/src/oauth.rs`** (17 tests; nono's `oauth_capture` and `oauth2` carry 34).

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `token_values_are_replaced_by_the_binding_placeholders` | `FW-EGR27` | `fn placeholders() -> Placeholders` | `capture_response(br#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":60}"#, &p)` → body has `p.access`/`p.refresh`; `Captured { expires_in: 60, .. }` | oauth_capture/mod.rs:339 |
| `the_same_placeholders_survive_a_rotation` | `FW-EGR27` | same | two captures → identical placeholder bytes | — |
| `an_unreplaced_token_member_refuses_the_response` | `FW-EGR27` | same | `id_token` top-level, `{"data":{"session_token":"x"}}` → `CaptureError::UnreplacedToken { member }`; `token_type` → `Ok` | :450 |
| `a_body_over_the_token_limit_is_refused` | `FW-EGR27` | `fn body_of_len(n)` | 65,536 → `Ok`; 65,537 → `CaptureError::Limit` | oauth2.rs:39 |
| `a_non_object_body_is_refused` | `FW-EGR27` | — | `b"[]"`, `b"not json"` → `Malformed` | oauth2.rs:789 |
| `a_missing_expires_in_takes_the_default_lifetime` | `FW-CRED30` | — | → `Duration::from_secs(3_600)` | oauth2.rs:769 |
| `the_form_refresh_placeholder_is_substituted` | `FW-EGR28` | `held = Secret::from_slice(b"rt/1 x")` | `grant_type=refresh_token&refresh_token=<p.refresh>` → form-decoded `refresh_token == "rt/1 x"` | :516 |
| `the_json_refresh_placeholder_is_substituted` | `FW-EGR28` | same | JSON → `refresh_token == "rt/1 x"` | :468 |
| `a_body_without_the_placeholder_passes_unchanged` | `FW-EGR28` | same | device-code form body → byte-equal | :502 |
| `the_refresh_placeholder_elsewhere_refuses_the_request` | `FW-EGR28` | same | `client_secret=<p.refresh>`; `refresh_token=x<p.refresh>` → `PlaceholderOutOfPlace` | — |
| `a_token_marker_split_across_chunks_ends_the_response` | `FW-EGR29` | `MarkerScan::new()` | feed `b"{\"refresh_to"`, `b"ken\": \"x"` → second `feed` returns `Verdict::End`; no byte of the second chunk released | :543; [FW-ADV-021](../formwork.md#fw-adv-021) split shape |
| `a_marker_without_a_string_value_passes` | `FW-EGR29` | same | `{"refresh_token_ttl": 60}`, `{"access_token": null}` → `Verdict::Release` | — |
| `a_slot_inside_the_margin_needs_refresh` | `FW-CRED30` | `Slot::new(expires_at)`, `now: Instant` param | remaining 31 s → `false`; 30 s → `true`; 29 s → `true` | oauth2.rs:855, :863 |
| `an_expired_slot_whose_grant_fails_is_not_presented` | `FW-CRED30` | `present_or_refuse(&slot, now, Err(GrantError::Status(400)))` | `Decision::Refuse(RefusalReason::CredentialUnavailable)` | oauth2.rs:863 (inverted) |
| `an_empty_slot_is_refused` | `FW-CRED30` | `Slot::empty()` | `Refuse(CredentialUnavailable)` | — |
| `the_refresh_grant_body_is_form_encoded` | `FW-CRED30` | — | `refresh_grant_body(&held, "cli")` == `b"grant_type=refresh_token&refresh_token=rt-0&client_id=cli"` | oauth2.rs:802 |
| `the_slot_document_has_exactly_these_keys` | `FW-CRED31` | golden `crates/formwork-gateway/tests/fixtures/oauth-slot-v1.json` | key `BTreeSet` equality; version 2 → `SlotError::Version` | schema_shape.rs:11-40 |

**`formwork-gateway/tests/oauth.rs`** (7 tests).

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `concurrent_requests_at_expiry_share_one_grant` | `FW-CRED30` | `Session::new` with a slot already expired, `token_endpoint(TokenFixture { lifetime_s: 3_600, rotate: true, .. })` | two concurrent `request`s → `grants().len() == 1`; both upstream heads carry `at-1` | — |
| `a_chunked_token_response_is_decoded` | `FW-CRED30` | `TokenFixture { chunked: true, .. }` | grant succeeds; `at-1` presented | oauth2.rs:725 (#1976) |
| `a_rotating_refresh_token_is_used_once` | `FW-CRED30` | `rotate: true, lifetime_s: 29` (inside the margin, so every request refreshes) | two sequential requests → grants carry `rt-0` then `rt-1`; both succeed | — |
| `a_gateway_refresh_emits_a_grant_record` | `FW-CRED30` | — | `proxy.grants()` has one `POST` to the endpoint path | [FW-FID13](../formwork.md#fw-fid13) |
| `a_token_response_echoing_the_refresh_token_is_ended` | [FW-CRED17](../formwork.md#fw-cred17) | `TokenFixture { echo: true, .. }` | `reasons(&proxy)` contains `RefusalReason::Reflection`; client output has no 8-byte run of `rt-0` | inspect.rs `fw_adv_021_credential_reflection` |
| `write_back_precedes_the_response` | `FW-CRED31` | `file://` source in `TestDir` | when the client reads the response, the file already holds `rt-1` | — |
| `a_write_back_failure_still_forwards_the_response` | `FW-CRED31` | read-only source directory | client gets `200`; one operator record names the binding | — |

#### 6.3.3 Fixtures and helpers to add

- **`TestDir::new(tag: &str) -> TestDir`** in `source.rs`/`oauth.rs` tests: `std::env::temp_dir()/fw-<tag>-<pid>`,
  removed on drop; `fn path(&self) -> &Path`. The unit tests use no Landlock, so `/tmp` is safe
  here. Mirrors nono's `tempfile::tempdir()` use without adding `tempfile`.
- **`fake_program(dir: &Path, name: &str, behavior: FakeProgram) -> PathBuf`** (in `source.rs`
  `#[cfg(test)] mod fake`, copied into `crates/formwork-cli/tests/support/mod.rs`): writes a mode-0755
  `/bin/sh` script that appends its argv (one per line), its environment variable names, and its
  stdin to `<dir>/<name>.calls`, then behaves per `enum FakeProgram<'a> { Answers(&'a str), Fails {
  stderr: &'a str, code: i32 }, Slow { secs: u32, stdout: &'a str } }`; `fn calls(program: &Path) ->
  Vec<Call>` reads the log. Mirrors the marker scripts of keystore.rs:2165-2172, but takes `PATH` as a
  `resolve_program(name, path_var: &str, grants: &WriteGrants)` argument instead of nono's
  thread-local override (:1209-1240).
- **`token_endpoint(tls: FixtureTls, cfg: TokenFixture) -> TokenEndpoint`** in
  `crates/formwork-gateway/tests/support/mod.rs`, beside `upstream`: answers `POST /oauth/token`
  with `{"access_token":"at-<n>","refresh_token":"rt-<n>","expires_in":<lifetime_s>,"token_type":"Bearer"}`;
  `TokenFixture { lifetime_s: u64, rotate: bool, chunked: bool, echo: bool, revoke: Arc<AtomicBool> }`;
  `fn grants(&self) -> Vec<Grant { grant_type: String, refresh_token: String }>`; `/api` records its
  `Authorization`. Mirrors `exchange_mock_token_response` (oauth2.rs:881-925), over TLS.
- **`Scratch::isolated(tag: &str) -> Scratch`** in `crates/formwork-cli/tests/support/mod.rs`, with
  `home()`, `state()` and `workspace()` as siblings under `env!("CARGO_TARGET_TMPDIR")/fw-<tag>-<pid>/`.
  Two reasons: a launcher directory under `/tmp` splits its ancestors under Landlock
  (`crates/formwork-confine/src/linux/landlock.rs:125-160`), and a tmpfs or FUSE bind mount can
  accept Landlock grants without enforcing them (nono@9edf3ea:crates/nono-test-support/src/lib.rs:31-38).
  State is a sibling of home so a test granting `$HOME` never grants it (lib.rs:43-47).
- **`TestKeyring::new(scratch: &Scratch) -> Option<TestKeyring>`** in the CLI support: Linux needs
  `secret-tool` and a session bus with a Secret Service, else `None` and the caller calls
  `not_exercised("no Secret Service on the session bus")`; macOS creates `<state>/fw.keychain-db`,
  unlocks it, prepends it to the user search list, and restores the list on drop.
  `fn store(&self, service, account, value)` for arranging.
- **py:** `fake_program(tmp_path, name, stdout) -> Path`, `calls(path) -> list[list[str]]` and
  `require_egress_host(cli, dir)` (the `support::egress_host` gate: `pytest.fail` under
  `FW_REQUIRE_EXERCISED=1`, otherwise a skip that names the gate) in `py/harness/helpers.py`.

#### 6.3.4 Patterns adopted from nono, and the ones designed out

1. **Irreversible kernel calls in a forked child.** Not needed: no test installs a new kernel
   mechanism; the denials are probed through `formwork run`'s confined child, which reports through
   its exit status and output (the `fep6_run.rs` shape).
2. **Silent host-capability gating — designed out.** Every gated test names its gate through
   `support::not_exercised`, which fails under `FW_REQUIRE_EXERCISED=1`: `egress_host`,
   `TestKeyring::new` (no Secret Service), `python3` for the fixture CLI, root for `FW-E2E-156`.
   The Linux CI job installs `gnome-keyring`, `libsecret-tools` and `dbus` and runs the keyring tests
   under `dbus-run-session`, so none of these skip on CI.
3. **Environment mutation — designed out.** No test sets a process variable. `construct_env` takes
   `vars`, the reader takes a `LaunchEnv` captured once in `main`, program resolution takes
   `path_var`, the timeout is a `read_with_timeout` argument, and slot timing takes `now`. nono's
   `ENV_LOCK`/`EnvGuard` (keystore.rs:4040-4085; nono@9edf3ea:crates/nono-cli/src/test_env.rs:5-40) and its timeout
   variable have no counterpart.
4. **Contract shape tests.** Two new Data-model surfaces, each with an exact key-set test and a
   golden file: `crates/formwork-compile/tests/fixtures/broker-sources-v1.json` and
   `crates/formwork-gateway/tests/fixtures/oauth-slot-v1.json`; the first also gets a
   byte-determinism check ([FW-FID4](../formwork.md#fw-fid4)).
5. **Property tests.** One property is wanted: `parse(display(s)) == s` for every source. It needs
   `proptest`, which `docs/STATUS.md` already owes; until it lands,
   `the_display_form_parses_back_to_the_same_source` over a fixed corpus stands in, and the stand-in
   is registered as a tracked test-method exception (strategy when it lands: segments from
   `[A-Za-z0-9 ._@:-]{1,32}`, `ProptestConfig::with_cases(64)`).
6. **Regression tests named for the defect.** `resolution_skips_a_directory_under_a_write_grant`
   (nono #1733, #1895), `a_chunked_token_response_is_decoded` (nono #1976),
   `an_expired_slot_whose_grant_fails_is_not_presented` (nono's stale token),
   `construct_env_strips_password_manager_sessions_in_passthrough` (§1, verified by reading
   `lib.rs:389-410`), `a_source_from_an_auto_discovered_layer_is_refused` (the review's
   auto-discovery finding), each with a doc comment citing it. The GHSA advisories in nono's
   CHANGELOG name no subject there; the one whose tests cite it (GHSA-8r33-hr9m-69wh, endpoint-path
   ambiguity, nono@9edf3ea:crates/nono-proxy/src/config.rs:2097) is an egress-path matter, not a source one.
7. **Shell integration suites — designed out.** `test_env_sanitization.sh`'s 1Password cases become
   `FW-E2E-148`; `test_tls_intercept.sh`'s wiring checks are already
   [FW-E2E-097](../formwork.md#fw-e2e-097) and [FW-E2E-099](../formwork.md#fw-e2e-099). No case is skipped silently.

#### 6.3.5 Worked example

```rust
/// FW-CRED26. A program in a directory the session can write is never run for a
/// source: resolution skips it and takes the next entry (nono #1733, #1895;
/// modelled on keystore.rs:2152 broker_command_skips_trojan_in_writable_path_dir).
#[test]
fn resolution_skips_a_directory_under_a_write_grant() {
    let root = TestDir::new("op-trust");
    let (rw, ro) = (root.path().join("rw"), root.path().join("ro"));
    let planted = fake_program(&rw, "op", FakeProgram::Answers("planted"));
    let trusted = fake_program(&ro, "op", FakeProgram::Answers("sk-fixture"));
    let grants = WriteGrants::from_patterns(&[format!("{}/**", rw.display())]);

    let path_var = format!("{}:{}", rw.display(), ro.display());
    let resolved = resolve_program("op", &path_var, &grants).unwrap();
    assert_eq!(resolved, trusted);

    let only_rw = rw.display().to_string();
    let err = resolve_program("op", &only_rw, &grants).unwrap_err();
    assert!(matches!(err, SourceError::ProgramUntrusted { ref program } if program == "op"));
    assert!(calls(&planted).is_empty() && calls(&trusted).is_empty());
}
```

```python
@pytest.mark.fw_e2e("FW-E2E-150")
def test_a_discovered_source_is_refused_before_any_program_runs(cli, tmp_path):
    require_egress_host(cli, tmp_path)  # fails under FW_REQUIRE_EXERCISED=1, else skips
    op = fake_program(tmp_path / "bin", "op", stdout="sk-fixture")
    (tmp_path / "FORMWORK.toml").write_text(
        'rules = ["allow:api.anthropic.com"]\n'
        'allow-credentials = [{ broker = "anthropic", source = "op://v/i/f" }]\n'
    )
    env = {"PATH": f"{op.parent}:/usr/bin:/bin"}
    refused = cli("run", "--", "true", cwd=tmp_path, env=env)
    assert refused.code != 0
    assert "--blueprint" in refused.stderr and "FORMWORK.toml" in refused.stderr
    assert calls(op) == []
    chosen = cli("run", "--blueprint", tmp_path / "FORMWORK.toml", "--", "true",
                 cwd=tmp_path, env=env)
    assert chosen.code == 0, chosen.stderr
    assert len(calls(op)) == 1
```

### 6.4 Traceability (draft rows for formwork.md §10)

| Requirement | Primary test | Also |
|---|---|---|
| `FW-CRED23` Source grammar | `FW-E2E-149` | 145, unit `credential.rs` |
| `FW-CRED24` Resolved before spawn | `FW-E2E-146` | 145, `FW-ADV-041` |
| `FW-CRED25` Zeroized custody | `FW-E2E-156` (Linux) | `FW-ADV-039`, unit `source.rs` |
| `FW-CRED26` Source program trust | `FW-E2E-147` | 146 |
| `FW-CRED27` Source stores floored | `FW-E2E-148` | 145, 151 |
| `FW-CRED28` Source conflicts refused | `FW-E2E-149` | unit `broker_sources.rs` |
| `FW-CRED29` Sources from chosen layers | `FW-E2E-150` | `FW-ADV-040` |
| `FW-CRED30` OAuth presentation | `FW-E2E-152` | 154, unit `oauth.rs` |
| `FW-CRED31` OAuth write-back | `FW-E2E-153` | 152, 154 |
| `FW-EGR27` Token response capture | `FW-E2E-154` | `FW-ADV-042` |
| `FW-EGR28` Token request substitution | `FW-E2E-155` | 154 |
| `FW-EGR29` Token host backstop | `FW-E2E-155` | `FW-ADV-042` |
| `FW-EGR30` Token endpoint closure | `FW-E2E-149` | — |
| `FW-INV20` Source non-disclosure | `FW-ADV-039` | 145, 153, 156, `FW-ADV-042` |
| [FW-FID8](../formwork.md#fw-fid8) (amended) | `FW-E2E-151` | — |
| [FW-CRED17](../formwork.md#fw-cred17) (extended coverage) | `FW-ADV-042` | — |

### 6.5 Phasing

- **Phase A, static sources:** `FW-CRED23`, 24, 26–29, `FW-INV20`, the Catalog types, the report
  section, the `Secret` type with its unit tests; `FW-E2E-145`..151, `FW-ADV-039`..041 (static
  arms), the CI keyring setup. `op://` lands `Partial` on macOS until its characterization row closes.
- **Phase B, OAuth refresh:** `FW-CRED25` (anchored once `FW-E2E-156` runs), 30, 31, `FW-EGR30`;
  `FW-E2E-152`, 153, 156; the OAuth arms of `FW-ADV-039` and `FW-ADV-041`. Slots arrive by the operator
  storing a token, or from Phase C.
- **Phase C, login capture:** `FW-EGR27`–29; `FW-E2E-154`, 155; `FW-ADV-042`; the `security -i`
  characterization.

---

## 7. Amendments to the landed docs (apply on landing)

**(a) `formwork.md` §5.9.** Replace the brokering sentence of the preamble: "Brokering … is a third
treatment of a type beside deny and exclude: the floor stays, the Gateway reads the credential
from its source — the launcher environment by default, or a keychain, password manager or file
named by URI (FEP-10) — and presents it on the type's bound hosts." Amend
[FW-CRED15](../formwork.md#fw-cred15): "The Gateway shall hold each brokered credential outside the
sandbox, reading its source once before the workload is spawned (`FW-CRED24`); an OAuth binding's
access token is renewed by the Gateway (`FW-CRED30`)." Amend [FW-BP12](../formwork.md#fw-bp12) to
list the `{ broker, source }` form and the `source` and `oauth` keys. Add rows `FW-CRED23`–31.

**(b) `formwork.md` §5.11.** Add `FW-EGR27`–30; note that FEP-5 §9's "bodies are not scanned" now
excepts the token endpoints of OAuth bindings.

**(c) `formwork.md` §5.6.** [FW-FID8](../formwork.md#fw-fid8): add the key `credential-source` and the
section `credentials.broker-sources` (`{ kind, oauth, verdict }` per binding, verdicts per §3.10).
[FW-FID12](../formwork.md#fw-fid12): the brokering reasons become `placeholder`, `reflection` or
`credential-unavailable`. [FW-FID11](../formwork.md#fw-fid11): `explain --hosts` prints each binding's
source kind.

**(d) `formwork.md` §6.** Add `FW-INV20`; [FW-INV13](../formwork.md#fw-inv13) gains "(see `FW-INV20`
for sources and OAuth tokens)".

**(e) `formwork.md` §7, §10, §7.12.** Add the tests of §6.1–6.2 and the rows of §6.4. Tests that write
an inline binding into an auto-discovered `FORMWORK.toml` ([FW-E2E-099](../formwork.md#fw-e2e-099),
the §7.12 scenario forms) pass it with `--blueprint`.

**(f) `profiles/credential-catalog.toml`.** `version = 3`; rewrite the header's last sentence (lines
14-16) to name sources; add `[types.1password]` and `[types.bitwarden]` (§3.5); document the
trailing-`*` env form.

**(g) `constitution.md`.** Vocabulary, after **placeholder**: "**source** = where the Gateway reads a
brokered credential, named by a URI on the broker entry; never the agent's copy." Concepts, the
Blueprint bullet: "credential exclusions and brokered sources (`allow-credentials`, …)". Data model:
the OAuth slot document is a reviewed surface, written only into the operator's store.

**(h) `docs/macos-characterization.md`.** Two new rows, numbered on landing: whether `security -i`
accepts `add-generic-password -U … -w` on a non-tty stdin without the value in any argument list;
which Mach service the `op` CLI reaches the 1Password app through, and whether a Seatbelt deny of
it leaves `op` with service-account tokens working.

**(i) `docs/STATUS.md`.** A FEP-10 row; owed-work rows for Phases B and C; the property stand-in of
§6.3.4 in the tracked test-method exceptions.

---

## 8. Decisions (recorded per constitution Precedence & Conflicts)

- **Programs, not crates.** The `keyring`, `security-framework`, `secret-service` and `spiffe`
  crates were each searched and declined under Growth; a program at a resolved, grant-checked
  absolute path adds nothing to the build. If the `security -i` characterization fails, the
  fallback is `security-framework` on macOS only, brought to review as a dependency.
- **Read once, before spawn.** First-use resolution and `cmd://` are declined: both run store
  access at a time the agent's traffic chooses, and `cmd://` lets a blueprint string run a command
  outside the sandbox. A failed read stops the run (nono starts it with an unavailable route).
- **Static secrets do not rotate in a session.** Re-reading on an interval or on a 401 would be
  agent-triggerable; only OAuth renews, from a token the Gateway already holds.
- **No stale tokens.** A failed refresh refuses the request; nono presents the expired token.
- **The operator's store holds the OAuth slot.** nono's 90-day plaintext capture file is declined;
  OAuth sources are restricted to the two kinds Formwork can write: the OS keyring, which encrypts
  at rest, and a file the operator named, written at mode 0600.
- **Inline bindings narrow.** [FW-BP12](../formwork.md#fw-bp12) as landed accepts an inline binding
  from any layer; `FW-CRED29` refuses it from auto-discovered layers, because its `hosts` choose
  where an operator secret goes. This narrows landed behavior; the affected tests move to
  `--blueprint` (§7 e). No exception is needed: nothing is widened.
- **URIs are printed as written on the operator channel.** nono redacts them; Formwork accepts a
  source only from a layer the operator chose, and the report carries the kind only.
- **Sources broker, never expose.** nono's `--env-credential` mode writes a store's secret into the
  child's environment with a warning (nono@9edf3ea:crates/nono-cli/src/credential_runtime.rs:108-114); exposure in
  Formwork remains the typed exclude ([FW-CRED5](../formwork.md#fw-cred5)) of a location.
- **No cross-store hints.** nono's miss hint looks the name up in another store
  (credential.rs:779-835), which can prompt; Formwork's line names the cause and nothing else.
- **SPIFFE declined.** A workload-identity source needs the SPIFFE Workload API, a gRPC client
  (nono uses the `spiffe` crate), and the `jwt-bearer` grant; the dependency fails Growth for a CI-
  and cluster-only use. It stays an open question.
- **SigV4 declined.** Signing is a presentation scheme, not a source; FEP-5 §3.2 put signing schemes
  out of scope, and an AWS key brokered from any source still needs it. A static AWS key pair is not
  brokerable after this FEP.

---

## 9. Open questions

- **The 1Password app integration on macOS.** Which Mach service, and can the `1password` type deny
  it (`services`) so `op://` reaches `Enforced`? Owner: macOS backend maintainer; closes with the
  §7 (h) row, before Phase A anchors `FW-CRED27`.
- **`security -i` as the write path.** Owner: macOS backend maintainer; closes in Phase C, with the
  `security-framework` fallback decided there.
- **Catalog OAuth blocks for shipped agents.** For `claude` and `codex`: token endpoint, client id,
  whether the tool accepts a bearer from its environment, and where it stores tokens when the
  keychain is floored. Owner: Catalog maintainer; closes at Phase C landing, with an
  `agent-examples` characterization in place of nono's manual QA.
- **`id_token`.** Codex may parse one locally (sandboxed-oauth-logins.mdx:404); a synthetic
  JWT-shaped placeholder is nono's answer.
  Owner: Gateway maintainer; after Phase C.
- **Operator-triggered re-read.** A signal to `formwork` (never a confined action) to re-read static
  sources. Owner: CLI maintainer; FEP-10 adoption review.
- **Linux stores beyond Secret Service.** KWallet without its Secret Service bridge, and headless
  hosts without `secret-tool`. Owner: Linux backend maintainer; Phase A.
- **The login residual.** Whether the Gateway could own the redirect and the PKCE exchange, removing
  the code from the confined tool. Owner: Gateway maintainer; Phase C review.
- **default-lifetime.** 3,600 s follows nono; a shorter value costs more grants and narrows the
  window an unannounced expiry leaves. Owner: Gateway maintainer; Phase B.
- **SPIFFE and SigV4.** Owner: Gateway maintainer; the next egress FEP.
