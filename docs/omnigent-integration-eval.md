# Evaluation: integrating Formwork into Omnigent

Status: research note, 2026-09-25. Omnigent at `omnigent-ai/omnigent@8ff455b` (2026-09-24);
Formwork at `8a340c4`. Claims are from reading both codebases, plus live probes on a Linux 6.18 host
(Landlock ABI 7, bubblewrap 0.x). macOS claims come from the code only and were not run.

**What the Linux host did not have.** The probe host was a headless container: no session D-Bus,
no `systemd --user`, no X11 or Wayland socket, no Secret Service. Those are the services through
which a confined process can ask something *outside* the sandbox to run a command, open a URL, or
hand over a secret. Omnigent closes them structurally (bwrap does not mount `$XDG_RUNTIME_DIR`,
and it strips `DBUS_*`). Formwork does not mediate pathname-socket `connect()` on Linux, so on a
developer desktop they are reachable. That finding is from code reading and did not show up in the
probes here, because there was nothing to reach. §5 items 7–8 record it, and [FEP-5](fep-5.md)
§4.1 makes the test suite start a session of its own so CI (also headless) exercises it, and adds a
`detect` line so an operator sees which of these facilities their own host has.

## TL;DR

- **Don't replace Omnibox with Formwork. Stack them.** Omnigent's sandbox is built around mount,
  PID and net namespaces (bwrap) plus a kernel-forced L7 egress proxy. Formwork is built around
  Landlock, seccomp and Seatbelt path policy, a credential catalog, and MCP shading. Each covers
  most of what the other lacks.
  - On Linux, `formwork run --confine-self` runs cleanly *inside* Omnigent's bwrap wrap. I verified
    this: both layers enforce at the same time, and Omnigent's seccomp denylist does not block
    `landlock_*`, `seccomp` or `prctl`.
- **Replacing Omnibox with Formwork would be a net security loss today, mostly on network.**
  Omnigent's egress proxy gives host, method and path rules, credential injection, and blocking of
  private IPs and cloud metadata. The proxy can't be bypassed because the sandbox has no network
  except the relay. Formwork only has TCP port rules, and UDP is left open in port mode. Landlock
  can't restrict by destination IP, so Formwork alone can't force traffic through a local relay.
- **The cheapest real gain is Formwork's MCP gateway.** Omnigent does not OS-sandbox MCP servers
  (only env filtering). Wrapping each stdio MCP server command in `formwork gateway` confines the
  server process and shades its tools, with no Omnigent core changes.
- **Formwork has blockers of its own to fix first**, most importantly that `builtin:default`
  fails to launch on Linux (§5).

## 1. What each system actually enforces

### Omnigent ("OmniBox", `omnigent/inner/*sandbox*.py`, pure Python)

| Area | Linux `linux_bwrap` | macOS `darwin_seatbelt` | Windows `windows_jobobject` |
|---|---|---|---|
| FS read | Closed. Only `/usr`, `/lib*`, `/bin`, selected `/etc`, the cwd and `read_paths` are bind-mounted. `$HOME` does not exist in the sandbox. | `(deny default)` plus system paths, cwd and `read_paths` | none |
| FS write | cwd only if granted, plus `write_paths`/`write_files`, a private scratch dir and a tmpfs `/tmp` | same shape | none |
| Hiding | Top-level cwd dotfiles are masked (tmpfs or `/dev/null` bind; default allows only `.venv`), as are `mask_paths` and escaping symlinks. Non-granted paths return ENOENT. | access deny; `file-read-metadata` is global, so any path can be stat'ed | none |
| Exec | unrestricted (anything visible) | unrestricted | none |
| Namespaces | pid, ipc and uts, plus net when there is no network or egress rules are set | n/a | Job Object kill-on-close only |
| seccomp | k8s-style denylist, `CLONE_NEW*` denied, `clone3` returns ENOSYS, `socket()` allowed only for UNIX, INET and INET6 | n/a | n/a |
| Landlock | **none** (the docs mention it; the module doesn't exist) | n/a | n/a |
| Network | on/off, or netns plus the L7 proxy | on/off, or only `localhost:<relay>` | not enforced |
| Egress proxy | MITM with default deny. Rules look like `"GET,POST host/path/**"`. Private IPs and metadata endpoints are blocked, DNS is resolved in the parent and pinned. Credentials are injected by swap-on-access or `oa_cred_*` placeholders, so the agent never sees the real token. | same | rejected |
| Env | allowlist (PATH, HOME, LANG…) plus `env_passthrough` | same | same |
| Missing mechanism | fails closed (`OSError` without bwrap or libseccomp) | fails closed | silently degrades |

Where each harness sits relative to the sandbox:
- **Claude Code (SDK):** the CLI is wrapped by `create_exec_launcher` → `run_launcher`, which
  re-execs under bwrap or sandbox-exec. If the wrap can't be built, the CLI runs *unwrapped with
  native tools disabled*, so file and shell access still goes through the sandboxed `sys_os_*`
  helper (`claude_sdk_executor.py:1337`).
- **Codex:** not wrapped. The spec is mapped onto Codex's own `read-only`, `workspace-write` or
  `danger-full-access` modes (`codex_executor.py:2189`).
- **Native tmux harnesses:** `os_env: inherit`, meaning they run in the same sandbox.
- **Policies** (`ALLOW`/`DENY`/`ASK` on request, tool_call and tool_result) run at the application
  level, in the server or runner, through harness hooks. They are not kernel-enforced.

### Formwork (Rust; Landlock + seccomp + NO_NEW_PRIVS on Linux, Seatbelt on macOS)

- **FS read and write:**
  - Landlock is a hard requirement: if it isn't fully enforced, the spawn aborts.
  - Two read modes: `closed`, or `ambient-minus-subtract` (grant `/` minus the holes).
  - Writes are closed by default, with a split between create and modify.
- **Credential floor.** A compiled-in catalog of 22+ typed entries (aws, gcp, ssh, github,
  anthropic, dotenv…) plus a filename backstop.
  - It stays denied even under broad grants, and a deny beats an allow from any layer.
  - For env vars that point at a file (`KUBECONFIG`), the target file is denied too.
  - Catalog env vars are stripped, and a scrub heuristic removes vars by name or value shape.
- **Tamper vectors.** `.git/hooks`, `.git/config`, `.mcp.json` and IDE dirs stay readable but not
  writable. This is enforced on macOS; Linux support is broken, see §5.
- **Exec allowlist:** Landlock `Execute`, or Seatbelt `process-exec`.
- **Network:**
  - `deny`: seccomp blocks INET, INET6, PACKET and netlink socket creation.
  - `ports`: Landlock `ConnectTcp` per port (ABI ≥ 4). UDP stays open.
  - There is no proxy, no host rules and no credential injection.
- **Namespaces:** none. Landlock ABI 6 scoping covers abstract unix sockets and signals.
- **Observability and authoring:**
  - A `FidelityReport` rates each capability enforced, partial or unenforceable, and
    `compile --report-only` emits it as JSON.
  - `explain [--json]` gives the verdict for a path, with the deciding rule and the layer it came
    from.
  - `learn` turns denials into a reviewable proposal of grants.
- **MCP gateway:** `formwork gateway`.
  - Filters stdio JSON-RPC `*/list`.
  - Refuses ungranted `tools/call`, `resources/read` and `prompts/get`.
  - Gates sampling and elicitation.
  - Runs the backend server confined by the same blueprint.
- **Windows:** out of scope.

## 2. Integration options

### Option A: Formwork replaces bwrap/Seatbelt as an Omnigent `SandboxBackend` (not recommended)

Omnigent has a backend ABC with `resolve`, `activate`, `wrap_launcher_argv` and `post_spawn`, and a
`register_backend()` registry (`inner/sandbox.py:340-442`). A `formwork` backend would:
- implement `wrap_launcher_argv` as `["formwork", "run", "--blueprint", <generated>, "--", *argv]`;
- translate `SandboxPolicy` into a blueprint:
  - `read_paths` → closed-mode `reads`;
  - `write_paths`/`write_files` → `writes`;
  - `mask_paths` plus the enumerated cwd dotfiles → `subtract`;
  - `allow_network` → `net`.

Core edits needed: `_SPAWN_WRAP_BACKENDS` is hardcoded to `{"linux_bwrap", "darwin_seatbelt"}`
(`sandbox.py:52`), and the egress and credential-proxy gates are also hardcoded to those two types
(`loader.py:793,815`, `sandbox.py:526`). There is no entry-point plugin group for OS backends.

The bigger problem is **egress**. Omnigent forces traffic through its proxy by removing every
other route (netns on Linux, SBPL `localhost:<relay>` on macOS). With Formwork as the only layer:
- **Linux:** Landlock `ConnectTcp` is port-only. Allowing the relay port allows *any IP* on that
  port. An agent that reads `HTTP_PROXY` learns the port and can exfiltrate to an attacker host
  listening on it. UDP (DNS tunnelling, QUIC) is unrestricted in port mode. The proxy becomes
  advisory.
- **macOS:** Formwork's SBPL emits `(remote tcp "*:port")`, so the same hole exists. It's fixable
  in Formwork by emitting `localhost:port`.

### Option B: stack Formwork inside Omnibox on Linux (recommended)

Keep bwrap as the outer layer: namespaces, netns, the egress proxy, tmpfs `/tmp`, and ENOENT
invisibility. In `run_launcher` (`sandbox.py:998`), run the target as
`formwork run --confine-self --blueprint <generated> -- <target>` instead of the bare target.

Verified on this host. bwrap ran with Omnigent's flags (`--unshare-pid/ipc/uts/net`, tmpfs `/tmp`,
`--die-with-parent`), with Formwork inside it using an `ambient-minus-subtract` blueprint:

| Probe | Formwork alone | Formwork inside bwrap |
|---|---|---|
| read a subtracted `.env` in the project | EACCES | EACCES |
| read a `.aws/credentials` in a granted tree | EACCES | EACCES |
| write outside `writes` | EACCES | EACCES |
| `socket(AF_INET)` with `net = "deny"` | EPERM | EPERM |
| create a file in a project subdir | ok | ok |
| create a file in the project root (holds a hole) | **EACCES** (§5 item 3) | **EACCES** |
| numeric PIDs visible in `/proc` | 78 | 4 |

On the network side:
- **Inside Omnigent's egress netns,** Formwork should use `net = { ports = [<relay>] }`. The netns
  already limits the reachable IPs to loopback, which closes the any-IP hole above.
- **When the netns is present,** Formwork's net layer is mostly redundant. Leave it at `ports`,
  or omit it.

On macOS, stacking is probably not possible. A process that is already sandboxed generally can't
apply a second Seatbelt profile; this needs verification. There the choice is either Omnigent's
Seatbelt (deny-default, egress-aware) or Formwork's (allow-default base, but with credential
floor, any-depth regex denies, tamper vectors and an exec allowlist). A practical middle ground is
to feed Formwork's credential catalog and tamper rules into Omnigent's SBPL generator as extra
denies.

### Option C: `formwork gateway` for Omnigent's MCP servers (recommended, no core change)

Omnigent's OS sandbox covers the `sys_os_*` helper and the harness CLIs, but not MCP servers.
Wrapping an MCP server's stdio command as `formwork gateway --server <name> -- <cmd>` gives:
- a kernel-confined server process;
- per-tool, resource and prompt allow/deny, where refused items look nonexistent;
- sampling and elicitation gating.

This overlaps with Omnigent's app-level `tool_call` policies, but it's enforced one hop lower and
also covers `*/list` shading.

## 3. Capabilities gained by integrating Formwork

Gains from stacking (Option B), or from replacement (Option A) except where noted:

1. **Credential floor that survives broad grants.** Omnigent protects `$HOME` secrets only by not
   mounting them. Once a user adds `read_paths: ["~"]` or a parent dir, `~/.aws` and `~/.ssh` are
   readable. Formwork's typed catalog still denies them, and also denies files that credential env
   vars point to.
2. **Exec allowlist.** Omnigent has none on any platform.
3. **Tamper-vector protection for the repo.** Omnigent's default masks `.git` entirely, which also
   stops `git` from working in cwd. If the user allows `.git` and cwd is writable, hooks can be
   planted. Formwork keeps `.git/config` readable but not writable (once §5 item 1 is fixed on
   Linux).
4. **Create-vs-modify write split** (`writes-no-create`).
5. **Masking at any depth.** Omnigent masks top-level dotfiles only by default, and past a 50k-entry
   cap it just warns. Formwork expresses `$CWD/**/x` declaratively; this is fully enforced only on
   macOS today.
6. **Value-shape env scrubbing.** On top of Omnigent's name allowlist, Formwork catches `ghp_`,
   `sk-`, `AKIA` and PEM values in passthrough vars.
7. **Honest fidelity reporting, `explain` and `learn`.** Omnigent has no equivalent for asking
   "why was this denied, and by which rule", and no denial-driven grant proposals. The closest it
   has is the `OMNIGENT_SANDBOX_STRACE` debug switch.
8. **Works without user namespaces (replacement only).** bwrap needs unprivileged userns or
   setuid. It often fails inside Docker's default seccomp profile, and on distros that restrict
   userns through AppArmor. Omnigent already has a Lakebox `/proc` downgrade for one such
   environment. Landlock and seccomp need neither. This is the strongest argument for offering
   Formwork as a *fallback* backend where bwrap can't run, instead of Omnigent's current behaviour
   there (fail closed, or run the Claude CLI unwrapped with native tools off).
9. **Kernel-confined MCP servers** (Option C).
10. **Rust, no runtime dependencies.** No libseccomp `ctypes` load and no Python in the enforcement
    path. The blueprint is compiled, then applied in `pre_exec` without allocation.

## 4. Capabilities lost if Formwork *replaces* Omnibox

1. **L7 egress control.** Host, method and path rules, credential injection (the agent never holds
   the token), private-IP and metadata blocking, and DNS pinning. This is the headline Omnigent
   feature, and Formwork has no equivalent (host-scoped egress is deferred, formwork.md §11).
   Omnigent's path matching does not normalize, so a `/repos/acme/**` rule also admits
   `/repos/acme/../other/x` and `/repos/acme/%2e%2e/other/x` (verified against `rules.py`).
2. **Proxy that can't be bypassed.** Only the netns makes the proxy mandatory, and Landlock can't
   filter by destination IP.
3. **UDP control.** Formwork's port mode leaves all UDP open.
4. **PID, IPC and UTS isolation.** Other processes stay visible: their `cmdline` (which often holds
   tokens), their `environ` for same-uid processes (verified: a confined process read a sibling's
   `FW_CANARY` variable — `ptrace_may_access` decides this, and Landlock does not govern it), and
   pids that can be signalled below Landlock ABI 6. Measured on this host: 78 vs 4 visible PIDs.
4a. **Host-service channels.** Under bwrap the session bus, `systemd --user`, display-server and
   keyring sockets do not exist in the sandbox. Under Formwork on Linux they are reachable if
   present on the host (code reading; the probe host had none — see the status note at the top).
5. **Invisibility.** bwrap makes unmounted paths not exist (ENOENT). Formwork returns EACCES, and
   `stat` still works on Linux, which leaks that the path exists.
6. **Private `/tmp` and scratch.** Formwork grants the host `/tmp`, which is shared across sessions.
7. **Pathname unix sockets.** Under bwrap a socket that isn't mounted can't be reached. Formwork on
   Linux does not mediate AF_UNIX `connect()`, even in `closed` read mode, so a known path such as
   `/var/run/docker.sock` can be reached. Omnigent's tmux-socket `/dev/null` bind has no Formwork
   equivalent on Linux.
8. **macOS deny-default posture.** Omnigent's SBPL starts from `(deny default)`. Formwork starts
   from `(allow default)`, leaving mach, sysctl, IPC and process-info open apart from its specific
   rules.
9. **Windows.** Omnigent's Job Object is weak, but Formwork has nothing.
10. **Older kernels.** Formwork port rules need Landlock ABI 4 (Linux 6.7+) and scoping needs ABI 6
    (6.12+). bwrap works on much older kernels, including enterprise LTS.
11. **Packaging.** Omnigent is `pip install`. Formwork would ship as a separate native binary
    (release tarballs today), or would need a wheel or bindings. Its loader (extends, builtin
    profiles, sigils) is private to the CLI crate, so embedding means shelling out to the CLI.

## 5. Formwork issues found during this evaluation (fix before integrating)

1. **`builtin:default` fails to launch on Linux.**
   - Repro: the README quickstart with `formwork run -- /bin/echo hi` fails with
     `any-depth pattern **/.git/config cannot be a rooted Landlock rule`.
   - Cause: `profiles/default.toml` ships `**/` `write-subtract` rows. The compiler filters `**/`
     only from the credential floor (`formwork-compile/src/lib.rs:432` vs `:440`), not from
     `write_subtract`.
   - It fails closed, but `explain`/`compile` still report fs-write as enforced. Layer merge is
     additive, so a downstream layer can't remove the inherited rows.
   - `examples/blueprints/agent-session.toml` has the same problem.
2. **Linux: any-depth credential rows are not enforced.** `formwork explain $CWD/.env` says
   "denied" without a platform caveat, but a nested `sub/.env` is readable. The JSON report does
   mark `dotenv` as partial.
3. **Linux: new files can't be created in a "split" directory.** Reproduced above.
   - Any directory that contains a hole only has its *existing* children granted.
   - `protect_policy_inputs` write-denies `FORMWORK.toml` in the project root, so the root itself
     is always split.
   - For Omnigent that means an agent can't create files at the top level of its workspace.
4. **Linux port mode leaves UDP open.** The report still says `net-default-deny enforced`.
5. **Linux AF_UNIX pathname `connect()` is unmediated.** The CrossDomainSocket "partial" reason
   understates this.
6. **Gateway passthrough frames.** Non-JSON frames, JSON-RPC batch arrays, and `tools/call` without
   an `id` are forwarded unfiltered (`formwork-gateway/src/lib.rs:84-139`). This needs a test
   against real MCP SDKs before Option C is trusted.

7. **Same-uid process environments are readable on Linux.** Verified. The FidelityReport has no
   line for it. Landlock cannot express "every `/proc/<pid>` but the caller's" because each
   descendant's `/proc/self` is a different inode; only a PID namespace closes it.
8. **Desktop-session sockets are unmediated on Linux** (item 4a above). Not probed here — no
   session existed on the host. This is the kind of gap a headless evaluation cannot see, and the
   test suite has to bring its own session (FEP-5 `FW-E2E-082`) rather than hope the runner has one.

## 6. Recommended plan

The Formwork-side work to close the gaps in §4 is proposed in [FEP-5](fep-5.md).

1. **Formwork-side fixes.**
   - Make the Linux compiler drop or downgrade `**/` rows to partial with a warning (§5.1).
   - Allow creation of new siblings in split directories, or document the limitation in the report
     (§5.3).
   - Emit `localhost:<port>` rules on macOS.
   - Close the gateway passthrough cases (§5.6).
   - Add a stable `--blueprint-json` / stdin blueprint input, so an orchestrator can pass a
     generated policy without temp files.
2. **Option C first.** Add a documented Omnigent MCP recipe that wraps servers in
   `formwork gateway`. This needs zero Omnigent core changes.
3. **Option B on Linux.**
   - Add an opt-in `os_env.sandbox.formwork` block (blueprint path, or inline rules and
     `allow_credentials`).
   - When it's set and the backend is `linux_bwrap`, `run_launcher` prefixes the target with
     `formwork run --confine-self --blueprint <gen>`.
   - Generate the blueprint from the resolved `SandboxPolicy`, in `ambient-minus-subtract` mode.
     bwrap already enforces the closed view, so Formwork contributes the credential floor, exec
     allowlist and tamper rules.
   - Fail closed if the fidelity report says anything requested is unenforceable.
4. **Optional: Formwork as a fallback `linux_landlock` backend** for hosts where bwrap can't
   create namespaces. Omnigent's own docs already reserve that name.
   - With `egress_rules` set, it must refuse to run: no netns means no mandatory proxy.
   - Needs the `_SPAWN_WRAP_BACKENDS` and egress-gate edits noted in Option A.
5. **macOS:** keep Omnigent's Seatbelt. Port Formwork's credential catalog and tamper rules into it
   as generated denies, rather than swapping profiles.
