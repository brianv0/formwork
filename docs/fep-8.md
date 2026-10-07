# FEP-8 (proposal): command sandboxes — per-tool grants brokered outside the agent's session

**Formwork Enhancement Proposal 8 — proposal, not landed.** Companion to `formwork.md` (design +
end-to-end spec) and `constitution.md` (doctrine).

**Status: nothing in this document mutates the landed spec or the constitution yet.** A draft lives
in its FEP until adoption (constitution, Requirements & identifiers; Precedence & Conflicts). New
identifiers are draft numbering, written as inline code, which the requirements canary and the
linking rule skip, until they are anchored on landing. This FEP holds the reserved blocks
`FW-ISO19`..`FW-ISO27`, `FW-GW10`..`FW-GW14`, `FW-CRED20`..`FW-CRED22`, `FW-BP23`..`FW-BP25`,
`FW-INV17`..`FW-INV18`, `FW-E2E-117`..`FW-E2E-132` and `FW-ADV-030`..`FW-ADV-035`, and uses all of
them. The FEP proposes amendments to [FW-CAP2](../formwork.md#fw-cap2),
[FW-XR5](../formwork.md#fw-xr5) and [FW-XR8](../formwork.md#fw-xr8) and to the Concepts text of
**Session** and **Seam** (§7); no mechanism lands before they do (§8). nono is cited as
`nono@9edf3ea:<path>:<line>` in plain text, Formwork paths as inline code; nono's files were read,
never built or run. After the first full citation, `tool-sandbox.mdx` abbreviates
`docs/cli/features/tool-sandbox.mdx`; `linux.rs`, `macos.rs`, `policy.rs`, `protocol.rs`, `shim.rs`
and `token_broker.rs` abbreviate files under `crates/nono-cli/src/tool-sandbox/` (`platform/` for
the first two); `command_policy.rs` and `test_env.rs` are under `crates/nono-cli/src/`;
`schema_shape.rs`, `manifest_roundtrip.rs`, `why_deny.rs` and `tool_sandbox_shim_env.rs` under
`crates/nono-cli/tests/`; `sandbox/linux.rs` and `snapshot.rs` under `crates/nono/src/` (`undo/` for
the latter); `test_*.sh` under `tests/integration/`; plain `README.md` and `CHANGELOG.md` are
nono's.

---

## 1. Problem

Formwork gives one grant to a whole process tree. The exec allow-list is session-wide
([FW-ISO4](../formwork.md#fw-iso4), [FW-ISO9](../formwork.md#fw-iso9); one `ExecPlan` per
`LinuxPolicy`, `crates/formwork-confine/src/linux/landlock.rs:174`). A brokered credential is bound
to hosts for the whole session
([FW-CRED10](../formwork.md#fw-cred10)–[FW-CRED19](../formwork.md#fw-cred19)): any session process
that sends the placeholder to a bound host gets it presented, with whatever methods and paths that
host's rules admit. A nested sandbox only removes authority ([FW-CAP2](../formwork.md#fw-cap2),
[FW-XR4](../formwork.md#fw-xr4)). So a tool cannot hold a credential or a path that the agent lacks,
and an operator who wants the agent to run `git push` has three choices, all wider than the task:
expose `ssh` to the whole session ([FW-CRED5](../formwork.md#fw-cred5)), so the agent can read the
key; broker a GitHub token, so any code the agent writes can call `api.github.com` with it; or run
the push outside Formwork.

Two Formwork mechanisms already act on a session's behalf with authority the session lacks. The
opener shim is a read-only directory first in `PATH` whose scripts write to a socket the session
inherits; the `formwork` process, outside the sandbox, decides and acts
([FW-ISO17](../formwork.md#fw-iso17), [FW-ISO18](../formwork.md#fw-iso18);
`crates/formwork-gateway/src/opener.rs:1-9`, `crates/formwork-cli/src/main.rs:1174-1209`). The MCP
gateway spawns each stdio backend under the blueprint it was given, which can grant paths the agent
does not hold ([FW-GW5](../formwork.md#fw-gw5), [FW-E2E-019](../formwork.md#fw-e2e-019);
`crates/formwork-gateway/src/lib.rs:631-643`, `crates/formwork-cli/src/main.rs:2216-2244`). Neither
runs a command-line tool with its own grant on the agent's request. The people hurt are operators of
agents that drive `gh`, `git`, `kubectl` and package managers: they over-grant the session, and a
prompt-injected instruction stream inherits the over-grant.

### 1.1 Constraints this FEP holds to

- **No new concept.** A command sandbox is a Session the Gateway spawns, as it spawns a stdio MCP
  backend; the request travels on a Seam that is an inherited descriptor
  ([FW-XR7](../formwork.md#fw-xr7)); the Gateway stays the single privileged broker
  ([FW-XR5](../formwork.md#fw-xr5)). Only the Concepts text of Session and Seam changes (§7 d).
- **Authority fixed before the run.** Every command grant is compiled, and every program pinned,
  before the workload spawns, from layers the operator chose ([FW-XR8](../formwork.md#fw-xr8)). The
  agent's request selects a pre-compiled command; it never shapes a grant (`FW-INV17`).
- **Honesty per backend.** Each new property has a FidelityReport line on Linux and macOS (§3.9);
  what a backend cannot enforce is reported `Partial` or `Unenforceable`, never claimed
  ([FW-INV5](../formwork.md#fw-inv5)).
- **Growth.** One new Blueprint field (`commands`), no new subcommand, no new flag, no new
  dependency, no new requirement family. A command's grant is an ordinary Blueprint file.
- **Transparency** ([FW-TRA2](../formwork.md#fw-tra2)). `gh pr view`, `sh -c 'gh pr view'` and a
  Makefile that runs `gh` reach the same policy through `PATH`; tools run unmodified.

---

## 2. Prior art: nono

### 2.1 Mechanism and behavior

nono puts delegated tools in "their own isolated command sandboxes, outside the agent's control":
the session runs the agent, and when it calls a controlled tool, nono's broker "launches that tool
under a command policy with its own filesystem policy, network policy, and credentials"
(nono@9edf3ea:README.md:128). "The agent can ask for a tool, but it cannot widen that tool's
sandbox, mint new keys, or bypass endpoint policy from inside the session" (README.md:137); the `gh`
example binds a keyring token to `api.github.com` behind a credential proxy, admits only `GET` on
one repository's issues, and admits only `issue list` and `issue view` argv prefixes
(README.md:139-182). The broker is the unsandboxed supervisor parent
(docs/cli/features/supervisor.mdx:20-24, execution-modes.mdx:21).

- **Fresh grant per invocation.** "Each command sandbox starts from a minimal runtime baseline. It
  does not inherit the session sandbox's `--allow` grants, CWD access, broad profile groups, raw
  credential paths, or network policy" (docs/cli/features/tool-sandbox.mdx:24).
- **Shims and broker discovery.** Shims are copies of the nono executable in a per-session runtime
  directory; a shim finds its broker by the socket path `supervisor.sock` beside its own directory
  (crates/nono-cli/src/tool-sandbox/shim.rs:1-4, :34-52). The request carries command, argv, env,
  cwd and three tty flags (tool-sandbox/protocol.rs:43-50), bounded at 4096 arguments of 128 KiB and
  a 1 MiB frame (protocol.rs:36-41, validated at :161-196); the shim then passes its own stdin,
  stdout and stderr by `SCM_RIGHTS` (protocol.rs:288-293).
- **Pinned identity.** `executable` binds a command "by path, inode, and digest"
  (tool-sandbox.mdx:263); the launch spec carries dev, ino, size, mtime and SHA-256
  (protocol.rs:82-100). Linux executes the verified object by descriptor
  (tool-sandbox/platform/linux.rs:912-1010); macOS verifies and then calls `execve` by path
  (tool-sandbox/platform/macos.rs:750-789). Targets writable by the session are rejected unless the
  profile opts into a "trust downgrade" (tool-sandbox.mdx:265-303).
- **Direct execution.** Linux checks the initial program's (dev, ino) against controlled binaries
  (linux.rs:528-570, `check_exec_gate` :5298-5340) and stacks a Landlock layer that handles only
  Execute and grants it on trusted `PATH` executables and on session-writable directories
  (linux.rs:3316-3410; ABI V3 required at :3338-3343). macOS denies `file-read-data`,
  `file-map-executable` and `process-exec*` on each controlled binary's literal path
  (macos.rs:3463-3487).
- **Chaining.** `can_use` on the caller plus `from.<caller>` on the callee; each edge carries its
  own grant, never merged (tool-sandbox.mdx:14-20, :233-240). Callers are attributed by process
  ancestry, with a per-command cgroup on Linux and a daemon-pid helper plus a `setsid` per launch on
  macOS (tool-sandbox.mdx:309-347).
- **Argv policy and intercepts.** `invocation_policy` decides `deny`, `approve` or `allow` on argv
  and env predicates (tool-sandbox.mdx:244); `intercept` rules can `respond`, `capture`,
  `capture_credential`, `approve` or `exec` a helper (tool-sandbox.mdx:153-166).
- **Command-scoped egress.** A command with `allow_domain` gets "a dedicated loopback proxy and
  fresh proxy credential" whose policy does not inherit the session's (tool-sandbox.mdx:223-231).
- **Stdio and audit.** With `sandbox.stdio`, the broker relays output through its own pipes with
  byte limits (tool-sandbox.mdx:767-795); every decision is an audit event written by the broker,
  not the tool (tool-sandbox.mdx:816-822).

### 2.2 Its tests

`crates/nono-cli/src/command_policy.rs` carries 129 unit tests from :3599 (validation findings by
stable code, merge, resolution, intercepts, approval backends); `tool-sandbox/policy.rs` carries 24
(intercept matching, `invocation_policy_denies_before_broader_allow` :1229); `platform/linux.rs` 51
(identity :6389-6425, exec gate :6489-6575 and :6894-6973, chaining caps :7432) and
`platform/macos.rs` 107. Binary tests: `crates/nono-cli/tests/tool_sandbox_shim_env.rs` (fail-closed
shims :202, :224; nested mediation after env sanitization :255). Shell suites:
`tests/integration/test_child_tool_boundaries.sh` (scoped grants and credentials :303-325, no
inheritance :342-350, fire-and-forget chains :388-461), `test_commands.sh` (blocking, with the
startup-only limitation at :104-107) and `test_binary_exec.sh` (binaries run under the sandbox,
:34-206). §6 names the Formwork test derived from each.

### 2.3 Defects and documented limitations

1. **Argv match is lexical.** `match` "does not perform command-specific semantic normalization such
   as `--flag=value` versus `--flag value`, short versus long aliases" (tool-sandbox.mdx:151); a
   non-UTF-8 argv falls through every predicate (policy.rs:1113).
2. **Overrides are not narrowing.** A per-intercept `sandbox` "completely replaces the selected
   command sandbox ... it is not restricted to narrowing" (tool-sandbox.mdx:111); an `exec` helper
   "runs with the matched command's real credentials" and pointing it at a shell defeats the sandbox
   (:166).
3. **Path-based exec on macOS and writable targets.** "macOS ... must still call `execve()` by path,
   so a sandbox-writable executable or parent directory remains replaceable before launch"
   (tool-sandbox.mdx:305); the `kubernetes` example ships with that downgrade
   (tool-sandbox-examples/kubernetes/README.md:210-215).
4. **Broker found by socket path.** The shim derives `supervisor.sock` from its location
   (shim.rs:34-52); CHANGELOG.md:19 (#2002) fixed discovery after environment sanitization broke it.
5. **Attribution by lineage.** A double-forked daemon "severs that chain" (tool-sandbox.mdx:311); on
   macOS a redirected stdio means "membership proves nothing" (:320). Fixes #1417 and #1274
   (CHANGELOG.md:747; test_child_tool_boundaries.sh:452-461).
6. **Exec gate gaps.** Execute is granted in session-writable directories (linux.rs:3384-3399;
   #1391, CHANGELOG.md:751), and identity is by inode, so a copy is an unknown executable that runs
   (`unknown_inode_is_allowed_as_non_controlled_executable`, linux.rs:6954). Startup-only command
   blocking was bypassed by a child shell (test_commands.sh:104-107).
7. **Shebang chains.** The `npm` and `aws-cli` examples abandon command sandboxes because the nested
   exec gate cannot run `#!/usr/bin/env node` or a Python interpreter chain
   (tool-sandbox-examples/npm/README.md:35-39, aws-cli/README.md:34-43).
8. **Network scope.** A command's proxy policy shared the session's domain allowlist until #1981
   (CHANGELOG.md:27); on macOS, port rules are rejected for command sandboxes (tool-sandbox.mdx:391,
   :915) and the `kubernetes` example falls back to `allow_all` (kubernetes/README.md:216-218).
9. **Host-side helpers on an agent-writable `PATH`.** #1733 and #1895 (CHANGELOG.md:429, :15);
   `load_command_credential_source_skips_trojan_in_writable_path_dir` (policy.rs:1412).
10. **Silent skips.** Two no-inheritance cases skip on macOS as "host-dependent"
    (test_child_tool_boundaries.sh:338-341); the binary suite skips absent runtimes
    (test_binary_exec.sh:157-206).
11. **Widening at run time.** Capability expansion grants paths on a terminal prompt
    (supervisor.mdx:29-58), and NEP-0002 proposes invocation-scoped filesystem approvals requested
    by the sandboxed command (neps/0002-invocation-scoped-commands.md:15-25, :127-147).

CHANGELOG.md:7 and :116-120 list six GHSA advisories by identifier only; none is attributable to
command sandboxes from the text there, so none is mapped to a test.

### 2.4 What Formwork adopts and declines

| nono quality | Formwork |
|---|---|
| Broker outside the session launches the tool into a fresh grant that inherits nothing | **Adopt**: the Gateway spawns each command sandbox from its own compiled grant (`FW-ISO19`) |
| Policy in the profile, not the prompt | **Adopt, strengthened**: grants compiled before the run and only from `flag` or `builtin` layers (`FW-BP24`, `FW-INV17`) |
| Pinned program, inode-verified, exec by descriptor on Linux | **Adopt**; writable targets refused, no downgrade (`FW-ISO22`, `FW-ISO23`) |
| Direct execution of a controlled program denied | **Adopt** with Seatbelt literals and a Landlock read hole; reported, not overclaimed (`FW-ISO21`) |
| Command-scoped egress with fresh proxy credentials | **Adopt** through the existing engine, one listener and placeholder per launch (`FW-CRED20`) |
| Argv allow/deny before launch | **Adopt** with [FW-GW9](../formwork.md#fw-gw9) tokens and terminal deny; non-UTF-8 refused (`FW-GW13`) |
| Broker discovered by socket path | **Decline**: inherited descriptor ([FW-XR7](../formwork.md#fw-xr7), `FW-GW10`) |
| Caller attribution by ancestry, cgroup, daemon helper | **Decline**: attribution by the descriptor a request arrives on (`FW-GW10`) |
| Stdio descriptors passed to the tool | **Decline**: Gateway-owned pipes, exact descriptor set (`FW-ISO24`) |
| Per-caller grants, intercept overrides, `exec`/`respond`/`capture` actions, `export_env`, `unsafe_macos_seatbelt_rules`, dynamic `@git:` tokens | **Decline** in v1 (§8) |
| Approval prompts, capability expansion, NEP-0002 approvals | **Decline**: live widening on the agent's request ([FW-XR8](../formwork.md#fw-xr8)) |

---

## 3. Design

### 3.1 Concepts and layers

| Piece | Concept | Crate |
|---|---|---|
| `commands` field; argv token-glob; caller graph; merge | Blueprint | `formwork-blueprint` (new `command.rs`, pure) |
| each command's grant compiled from its grant file; report lines | CompiledPolicy, FidelityReport | `formwork-compile` (pure; program facts are an input, like `SessionSpec`) |
| direct-execution denial in the session; command sandbox confinement | Confiner | `formwork-confine` (two macOS SBPL rows; no new Linux code, §3.6) |
| rendezvous, admission, spawn, relay, per-launch egress | Gateway, Seam | `formwork-gateway` (new `command.rs`, beside `opener.rs`) |
| shim placement, program resolution, provenance gate, shim stage | Launcher | `formwork-cli` |

A **command sandbox** is a confined process tree the Gateway spawns from a pre-compiled command
entry on a request it receives over the Seam. It is a Session in the existing sense — a process tree
under the Confiner — with its own CompiledPolicy, exactly as a stdio MCP backend is. No concept is
added; §7 (d) amends the Session and Seam definitions to name it.

### 3.2 Blueprint: `commands`

```toml
[commands.gh]
program = "/usr/bin/gh"                  # absolute; pinned at session start (FW-ISO22)
grant   = "commands/gh.toml"             # a Blueprint file, resolved like an `extends` entry
argv    = { allow = [["pr", "view", "**"], ["pr", "list", "**"]],
            deny  = [["**", "/--web(=.*)?|-w/", "**"]] }
callers = ["session"]                    # default ["session"]

[commands.ssh]
program = "/usr/bin/ssh"
grant   = "commands/ssh.toml"
argv    = { allow = [["**"]] }
callers = ["git"]                        # only the `git` command sandbox may run it
```

`commands/gh.toml` is an ordinary Blueprint: `extends = ["builtin:default"]`,
`rules = ["read:$CWD/**", "get:api.github.com/repos/acme/widget/**"]`,
`allow-credentials = ["broker:github"]`. It merges over the fail-closed baseline and the credential
floor ([FW-BP2](../formwork.md#fw-bp2)) and never over the session's layers, so a command grant
holds nothing the operator did not write into it; `$CWD` is the launch directory, fixed at the CLI
edge ([FW-BP5](../formwork.md#fw-bp5)). An argv pattern is a list of tokens: `"**"` matches zero or
more whole arguments; any other entry matches exactly one argument, exactly or as an anchored `/…/`
regex with the [FW-GW9](../formwork.md#fw-gw9) semantics. A request is admitted when some allow
pattern matches the arguments after `argv[0]` and no deny pattern does; deny is terminal
([FW-CAP8](../formwork.md#fw-cap8)). `argv` has no default: an entry without it fails at parse, and
`allow = [["**"]]` is how an operator admits everything. A name is `[A-Za-z0-9._+-]{1,64}`, never
`session`, a channel or group name, or `formwork`. Across layers, entries merge by name: allow and
deny lists and `callers` union, `commands.<name> = "deny"` is terminal, and a second layer that
names a different `program` or `grant` for an existing name is a compile error naming both layers.

A `commands` table, and every grant file it names, is accepted only from a layer whose provenance is
`flag` or `builtin` ([FW-FID7](../formwork.md#fw-fid7); `BlueprintSource`,
`crates/formwork-cli/src/blueprint_load.rs:35-44`). An auto-discovered `FORMWORK.toml`, or a file it
extends, that carries `commands` fails loud before spawn and names `--blueprint`. A committed
`FORMWORK.toml` is applied today with one INFO line and can already lift the floor
(`blueprint_load.rs:86-171`); a command grant is the one place a grant exceeds the session's, so it
is not accepted from a file a cloned repository supplies.

### 3.3 Seam and attribution

For each Session that may call commands — the workload, and each command sandbox named in another
command's `callers` — the Gateway creates an `AF_UNIX SOCK_DGRAM` socketpair, keeps one end and
passes the other, named by `FORMWORK_COMMAND_FD`, together with a read-only shim directory first in
`PATH`. Each shim entry is a symlink named for the command and pointing at the `formwork` binary;
`formwork` dispatches to the shim stage when `FORMWORK_COMMAND_FD` is set and its `argv[0]` basename
is not `formwork`, the way the isolation stage dispatches on `FORMWORK_ISOLATE_STAGE`
(`crates/formwork-cli/src/main.rs:452-458`). The shim creates a fresh `SOCK_STREAM` socketpair and
sends one end to the Gateway in a single datagram with `SCM_RIGHTS`; all framing then runs on that
per-request stream. A datagram is atomic, so concurrent shims cannot interleave (nono's EMSGSIZE
race, CHANGELOG.md:888, does not arise).

The Gateway attributes a request to the Session whose datagram socket it arrived on. A daemonized
descendant of a tool still holds the tool's descriptor and is attributed to the tool; a session
process holds no command sandbox's descriptor (`FW-ISO24`, `FW-ISO25`), so it cannot be attributed
to one. No ancestry walk, cgroup, helper or `setsid` is needed. The shim is untrusted: every
decision is the Gateway's.

### 3.4 Admission

The request frame carries the command name, the arguments (each UTF-8, no NUL), and the working
directory; nothing else. It is parsed once at the Gateway edge into domain types and bounded by the
limits in §3.10; a malformed or oversized frame closes the stream and starts nothing. Admission, in
order: the name is a compiled command; its `callers` names the attributed caller; the chain depth
stays within **command-depth** and the Session's live launches within **command-concurrency**; the
argv is admitted (§3.2); the canonical working directory lies within the command grant's read scope.
A refusal exits the shim 126 with the single stderr line `formwork: <name>: refused`, the same for
every reason, and writes one operator line naming the command, the caller, a reason from the closed
set
`unknown-command | caller | argv-denied | argv-not-allowed | cwd | identity | malformed | limit`,
the deciding rule with its layer, and `formwork explain <name>` ([FW-FID9](../formwork.md#fw-fid9),
[FW-CRED7](../formwork.md#fw-cred7)). The environment of the request is not read: a command's
environment is built by the Launcher's `construct_env` from the operator's environment under the
command grant's `env` posture, the floor strip, and its placeholders
([FW-CRED14](../formwork.md#fw-cred14)). `GIT_SSH_COMMAND`, `LD_PRELOAD` and their kind therefore
never travel from the agent to a tool.

### 3.5 Launch

The Launcher resolves each `program` at session start: canonical path, (dev, ino, size, mtime),
`st_nlink`, and for a script its interpreter. It refuses the session, naming the path and the
granting rule, when the program, any ancestor directory of it, its interpreter, or any directory on
the command's `PATH` is writable under the session's grant or any command grant. The Gateway, per
launch: re-checks the identity (refusing `identity` on mismatch); compiles the command's policy with
a per-launch `SessionSpec` holding only its listener endpoint and marker (blueprint input
unchanged); creates a private 0700 temporary directory granted read-write to that launch only
([FW-TRA10](../formwork.md#fw-tra10)); starts the tool as `argv[0]` = the command name in a new
process group, without a controlling terminal, with exactly three Gateway-owned pipes on 0–2 plus
its own rendezvous descriptor if it has callees; and execs the verified object — by descriptor on
Linux for an ELF program, by path after re-verification in the pre-exec child otherwise. Read and
execute of the program and interpreter are added to the command grant as Launcher-owned grants
([FW-TRA9](../formwork.md#fw-tra9)); nothing else is inferred. Because the command grant has no
outer exec gate, `#!/usr/bin/env node` resolves through the command's own `PATH` (2.3 item 7 does
not arise).

Egress: a command grant's host rules start one Gateway egress listener and one connect supervisor
(Linux, [FW-EGR7](../formwork.md#fw-egr7)) or one marker (macOS, [FW-EGR8](../formwork.md#fw-egr8),
[FW-EGR9](../formwork.md#fw-egr9)) per launch, holding that command's host table only. Each launch
gets a fresh placeholder per brokered credential, honored only on that launch's listener; presented
on any other listener it is refused with reason `placeholder`. The session's own host rules and
placeholders are a different listener. [FW-EGR14](../formwork.md#fw-egr14) is amended to host the
Gateway when any command grant carries a host rule.

### 3.6 Direct execution of the pinned program

The grant of a command sandbox is reachable only through the Gateway by construction: no session
process holds it. Denying the session direct execution of the program protects something narrower —
that every run of that program file passes the argv policy and the operator record. A copy of the
program, or a download of the same bytes, runs with the session's authority, which the session
already has; the report says so and does not claim more.

- **Linux.** The Launcher adds each pinned program to the session's `subtract` set, which `expand`
  already carves out of every read grant (`landlock.rs:125-160`). Landlock requires `READ_FILE` for
  the file `execve` opens, so the hole denies execution, a loader-run (`ld.so <program>`) and a copy
  alike **(characterize: a test pins this before `FW-ISO21` is anchored; if it fails, the session
  governs Execute with a subtractive execute grant around the same holes)**. No execute grant is
  added anywhere (2.3 item 6 does not arise).
- **macOS.** The same `subtract` compiles to `file-read*` and metadata denies
  ([FW-CAP7](../formwork.md#fw-cap7)); the compiler adds `(deny process-exec* (literal P))` and
  `(deny file-map-executable (literal P))`, as nono does (macos.rs:3463-3487).
- **Both.** Every command sandbox gets the same holes for every pinned program but its own. A path
  is not an inode: when `st_nlink > 1` the other links are not denied, and bind mounts are not
  detected; the verdict is `Partial` with that reason. On a Linux host without Landlock the line is
  `Unenforceable`, as every fs line is.

### 3.7 Relay, exit status, signals and lifetime

The shim relays its stdin to the tool and the tool's stdout and stderr to its own, in order, as
frames on the per-request stream; the Gateway holds at most **relay-buffer** bytes per direction and
stops reading from the other side when full. No session descriptor reaches the tool, and the tool
sees pipes, never a terminal: `isatty` is false and `/dev/tty` fails, as for nono's macOS launches
(tool-sandbox.mdx:344-347). The shim exits with the tool's status, or 128 + n when the tool died of
signal n ([FW-XR10](../formwork.md#fw-xr10)'s convention, `main.rs` `exit_code`); a Formwork failure
after the request was sent exits 125 with one `formwork:` line ([FW-XR11](../formwork.md#fw-xr11)).
The shim forwards exactly SIGINT, SIGQUIT, SIGTERM, SIGHUP, SIGUSR1, SIGUSR2, SIGTSTP and SIGCONT to
the tool's process group. When the request stream closes before the tool exits (the shim was
killed), or when the session's workload exits, the Gateway sends SIGKILL to the process group within
**reap-window**. A descendant that leaves the process group (`setsid`) outlives this; `lifetime` is
`Partial` on both backends and the residual is named (§9).

### 3.8 Nesting

A tool calls another tool the way the session does: its `PATH` starts with a shim directory holding
the commands whose `callers` name it, and its descriptor attributes the request. The callee runs
under its own grant, not intersected with the caller's: both are operator-authored, and the callee's
grant is what the operator wrote for it. Depth counts launches from the session; a cycle
(`git → ssh → git`) is bounded by **command-depth**. A `formwork run` started inside a Session can
only produce command sandboxes inside that Session's own wall: its Gateway is confined, and Landlock
domains and Seatbelt profiles stack ([FW-XR4](../formwork.md#fw-xr4)).

### 3.9 FidelityReport and `explain`

The report gains a `commands` map beside `channels`, and a `command-<name>` row in `per_capability`
carrying the weakest member verdict. Each entry has exactly the keys `program`, `callers`,
`direct-exec`, `identity`, `argv`, `lifetime`, `inspection`, `credentials` and `grant` (the
command's own FidelityReport without `host`). `formwork compile`, `explain` and `run` resolve
program facts at the CLI edge in the same way, so all three print the same verdict on one host
([FW-XR1](../formwork.md#fw-xr1)); a compile for another host reports `direct-exec` and `identity`
`Unenforceable` with reason `program not resolved`. `formwork explain <name>` prints the program and
its identity, the grant file and its layer, each argv rule with its layer, `callers`, and every
verdict ([FW-FID11](../formwork.md#fw-fid11) amended).

| Line | Linux | macOS |
|---|---|---|
| `grant` | the command's own lines | the command's own lines |
| `direct-exec` | `Enforced` (read hole, characterized); `Partial` when `st_nlink > 1`; `Unenforceable` without Landlock | `Enforced` (literal denies); `Partial` when `st_nlink > 1` |
| `identity` | `Enforced` (ELF by descriptor; script re-verified, writers refused) | `Enforced` (re-verified, then by path; every writer inside any grant refused) |
| `argv` | `Partial`: tokens are matched, not the program's option grammar; a program that runs caller-chosen code runs it with the grant | same |
| `lifetime` | `Partial`: a descendant leaving the process group outlives the request | same |
| `inspection` (session → command processes) | `Enforced` unprivileged (separate Landlock domains refuse ptrace-class access); `Partial` with `CAP_SYS_ADMIN`/`CAP_PERFMON`/`CAP_SYS_PTRACE` | `Partial`: task ports denied ([FW-ISO14](../formwork.md#fw-iso14)); arguments and exec-time environment readable through `kern.procargs2` (C5) |
| custody `brokered` | as `credential-broker` (`Partial`, [FW-CRED17](../formwork.md#fw-cred17)) | same |
| custody `held-file` | `Enforced` against the session (its floor); residual: the tool's output, streams and shared writable paths | same |
| custody `held-env` | follows `inspection` | `Unenforceable` (`kern.procargs2`, C5) |

### 3.10 Limits

Defined once here and implemented as named constants in `formwork-gateway`, as FEP-6 §4.9 defines
the egress limits: **command-frame** 1 MiB per request frame, at most 4096 arguments of at most 128
KiB each (nono's bounds, protocol.rs:36-41); **request-timeout** 10 s from the rendezvous datagram
to a complete request frame; **relay-buffer** 64 KiB per direction per stream; **command-depth** 8;
**command-concurrency** 64 live launches per Session; **reap-window** 1 s.

### 3.11 Postures and asymmetries

Commands need a process outside the sandbox, so only `formwork run` in the spawn posture serves
them. `run --confine-self`, `formwork gateway` and `learn` refuse a blueprint with `commands` before
the workload runs ([FW-XR9](../formwork.md#fw-xr9), [FW-DISC11](../formwork.md#fw-disc11)). The
asymmetries that remain are those of the table in §3.9: macOS exposes a command's arguments and
exec-time environment to same-uid readers; Linux depends on a characterized Landlock behavior for
`direct-exec`.

---

## 4. Surface changes (each measured against Growth)

- **Blueprint field `commands` (new).** Searched first: `exec` is a session-wide allowlist that
  narrows only; `mcp.<server>` is protocol visibility for a backend the MCP host launches, not a
  program the session invokes; `channels` lifts a host service and carries no grant;
  `allow-credentials` is session-wide. None names a program with its own grant. The value reuses
  existing surfaces: the grant is a Blueprint file resolved like `extends`
  ([FW-BP3](../formwork.md#fw-bp3)); argv tokens are [FW-GW9](../formwork.md#fw-gw9) patterns;
  `"deny"` is the channel posture keyword. Data-model surface, expand-only, pre-release.
- **CLI.** No subcommand, no flag. `explain` accepts a command name positionally
  ([FW-FID11](../formwork.md#fw-fid11)). The shim stage is the one binary dispatched by an
  environment variable naming an inherited descriptor, the isolation-stage precedent; a second
  shipped binary would break the self-contained release (constitution, Growth).
- **FidelityReport.** The `commands` map and `command-<name>` rows (§3.9); a Data-model change,
  versioned with the report. **Operator channel.** Refusal lines ([FW-FID9](../formwork.md#fw-fid9))
  and one launch record per command run: command, caller, argv with each token escaped and cut at
  256 bytes, cwd, status, duration and bytes per stream ([FW-FID13](../formwork.md#fw-fid13)
  amended).
- **Typed errors.** `CommandError` in `formwork-blueprint` (parse, merge, provenance) and a
  `CommandRefusal` enum in `formwork-gateway` (the closed reason set); API surface, each with a
  consumer.
- **Dependencies.** None. `SCM_RIGHTS`, `execveat` and process groups use `libc`, already a
  dependency; the Gateway's tokio runtime stays in `formwork-gateway`. `proptest` is named in §6.3.4
  as a dev-dependency gated on the owed property-test infrastructure, not added by this FEP.
- **HostProfile, Catalog, profiles.** Unchanged.

---

## 5. Proposed requirements (draft numbering — anchored on landing)

| Req | Requirement |
|---|---|
| `FW-ISO19` **Command grant** | The Confiner shall confine each command sandbox to the CompiledPolicy compiled from its grant file over the baseline and the credential floor, with no grant taken from the session or from the calling command. |
| `FW-ISO20` **Command shim** | In every spawned session whose blueprint names a command with `session` among its callers, the Launcher shall place a Formwork-owned, write-denied shim directory first in `PATH` holding exactly one entry per such command. |
| `FW-ISO21` **Direct-execution denial** | The Confiner shall deny every session process, and every command sandbox other than the program's own, reading and executing each pinned program file at its canonical path. |
| `FW-ISO22` **Program identity** | The Gateway shall launch a command only from the file whose canonical path, device, inode, size and modification time the Launcher recorded at session start, and shall refuse the request with reason `identity` when they differ. |
| `FW-ISO23` **Unwritable program** | The Launcher shall refuse to start a session in which a command's program, an ancestor directory of it, its interpreter, or a directory on its `PATH` is writable under the session's grant or any command grant, naming the path and the granting rule. |
| `FW-ISO24` **Descriptor set** | The Gateway shall start each command sandbox with exactly three standard descriptors, each a Gateway-owned pipe, plus its own rendezvous descriptor when another command names it as a caller, and no other open descriptor. |
| `FW-ISO25` **Command inspection** | The Confiner shall deny every session process ptrace-class access to the processes of a command sandbox where the platform provides a mechanism (Linux: Landlock domain separation; macOS: the task-port deny of [FW-ISO14](../formwork.md#fw-iso14)). |
| `FW-ISO26` **Command lifetime** | Within **reap-window** after a request stream closes before its tool exits, or after the session's workload exits, the Gateway shall send SIGKILL to the command sandbox's process group. |
| `FW-ISO27` **Command report** | For each command the FidelityReport shall carry a `commands.<name>` entry with exactly the keys of §3.9 and a `command-<name>` row whose verdict is the weakest of the entry's verdicts. |
| `FW-GW10` **Rendezvous attribution** | The Gateway shall accept a command request only on a rendezvous socket it created and shall attribute it to the Session that socket was created for. |
| `FW-GW11` **Caller admission** | The Gateway shall launch a command only when its `callers` names the attributed caller, the launch depth from the session is at most **command-depth**, and the caller has fewer than **command-concurrency** live launches. |
| `FW-GW12` **Request bounds** | The Gateway shall close the request stream without launching when a request frame exceeds **command-frame**, carries more than 4096 arguments, an argument over 128 KiB, a non-UTF-8 or NUL-bearing argument, or does not complete within **request-timeout** of its rendezvous datagram. |
| `FW-GW13` **Invocation admission** | The Gateway shall launch a request only when an allow pattern of the command's `argv` matches its arguments, no deny pattern matches them, and its canonical working directory lies within the command grant's read scope. |
| `FW-GW14` **Shim transparency** | The command shim shall relay its standard input to the tool and the tool's standard output and error to its own in order, forward exactly the eight signals of §3.7 to the tool's process group, and exit with the tool's status or 128 + n for signal n. |
| `FW-CRED20` **Launch-bound placeholder** | The Gateway shall present a credential brokered by a command grant only on the egress listener of the launch it issued that placeholder to, and refuse it with reason `placeholder` on every other listener. |
| `FW-CRED21` **Session floor precondition** | The Launcher shall refuse to start a session in which a credential type that a command grant exposes or brokers is reported other than `Enforced` in the session's own floor. |
| `FW-CRED22` **Command custody** | For each credential a command grant lists, the FidelityReport shall state its custody — `brokered`, `held-file` or `held-env` — and the verdict §3.9 gives that custody on the current backend. |
| `FW-BP23` **Commands shape** | The Blueprint parser shall accept `commands` as a table of names matching `[A-Za-z0-9._+-]{1,64}`, other than `session`, `formwork` and every channel and group name, each holding exactly `program` (absolute), `grant`, `argv` and optional `callers`, or the keyword `"deny"`, and fail at parse otherwise. |
| `FW-BP24` **Command provenance** | The CLI shall refuse, before spawn and naming `--blueprint`, a `commands` entry or grant file reached from a blueprint whose source is `auto-discovered`. |
| `FW-BP25` **Command layering** | Across layers, command entries shall merge by name with `argv` lists and `callers` unioned and `"deny"` terminal, and a layer that names a different `program` or `grant` for an existing command shall be a compile error naming both layers. |

Invariants:

| Inv | Invariant |
|---|---|
| `FW-INV17` **Pre-compiled command authority** | Every command sandbox runs under a CompiledPolicy whose blueprint input was fixed before the session's workload spawned; no byte a Session sends the Gateway adds a path, host, credential, program or caller to any grant. Per-launch inputs are limited to the listener endpoint, marker, placeholder and private temporary directory. Tested to falsify. |
| `FW-INV18` **Command custody** | On a backend reporting the custody `Enforced`, no session process obtains a credential a command sandbox holds through the filesystem, the environment, or process inspection; the tool's own output — its standard streams and the files it writes where the session can read them — is the one remaining route, and the report names it. |

---

## 6. Verification plan

Fixtures: `fw-tool-probe`, a new probe binary in `crates/formwork-confine/src/bin/` beside the
`fw-*-probe` set, with subcommands `read P`, `write P`, `cat`, `exit N`, `raise SIG`, `env NAME`,
`cwd`, `fds`, `trap SIG MARKER`, `daemonize ARGS…`, `exec ARGS…`, `call NAME ARGS…`, `tty`. Where a
boundary is involved, each test pairs allow and deny probes at the kernel or the Gateway, runs the
least convenient realistic shape (the fastest-failing request, the largest stream, the daemonizing
tool), and never skips silently.

### 6.1 End-to-end tests (draft)

**`FW-E2E-117` Grant separation (both; `py/harness/test_command_sandbox.py`).** Session grant reads
`session-only/`; command `probe` (program `fw-tool-probe`, grant `read:$CWD/tool-only/**`). From the
session: `probe read tool-only/f`; `cat tool-only/f`; `probe read session-only/f`; the session's own
`read session-only/f`. **Pass:** the first and last return the file bytes; the second and third fail
EACCES-class. **Fail:** the session reads `tool-only/`, or the tool reads `session-only/`. Derived
from test_child_tool_boundaries.sh:303-325 and :342-345, run on macOS too (2.3 item 10).

**`FW-E2E-118` Shim placement and fail-closed shim (both; py).** **Pass:** `PATH`'s first entry is
the shim directory; writing into it fails EACCES-class; `command -v probe` names it; with
`FORMWORK_COMMAND_FD` closed in a subshell, `probe exit 0` exits 125 with one `formwork:` line and
the fixture records no start; a blueprint whose only command has `callers = ["git"]` yields no shim
directory. **Fail:** a shim runs anything without the Gateway, or `PATH` lacks the shim. Derived
from tool_sandbox_shim_env.rs:202 and :224.

**`FW-E2E-119` Direct execution denied (both; py).** The session tries the pinned program by
absolute path, through `command -p`, through a symlink it creates in `$TMPDIR`, by copying it into
`$TMPDIR`, and on Linux through the dynamic loader, each in a grandchild shell. **Pass:** each
attempt fails EACCES-class or the copy cannot be read, `probe exit 0` through the shim succeeds, and
`direct-exec` is `Enforced`; with a second hard link planted beside the fixture program, the link
runs and the report says `Partial` naming the link count. **Fail:** any attempt runs the pinned
program while the report says `Enforced`. Derived from tool-sandbox.mdx:893-902 and
test_commands.sh:104-107.

**`FW-E2E-120` Argv admission (both; py).**
`argv = { allow = [["read", "**"]], deny = [["**", "--secret", "**"]] }`. **Pass:** `probe read f`
runs; `probe write f`, `probe read --secret f` and `probe read f --secret` exit 126 with exactly
`formwork: probe: refused` and no fixture start, and each writes one operator line with reason
`argv-not-allowed` or `argv-denied`, the rule, its layer and `formwork explain probe`. **Fail:** a
refused request starts the tool, or the agent-side message names the rule. Derived from
policy.rs:1229 and README.md:169-176.

**`FW-E2E-121` Stdio and status (both; `crates/formwork-cli/tests/command_run.rs`).** **Pass:** 8
MiB piped through `probe cat` returns byte-identical; stdout and stderr arrive separately; exits 0,
3 and 255 are the shim's status; `probe raise SEGV` gives 139; `probe tty` reports stdin, stdout and
stderr not terminals and `/dev/tty` unopenable; `probe fds` lists 0, 1, 2 only; the formwork
process's resident memory grows by less than 4 MiB during the 8 MiB transfer. **Fail:** any byte
differs, a status differs, or a fourth descriptor is open.

**`FW-E2E-122` Signals and lifetime (both; cli tests).** **Pass:** SIGINT to the shim makes
`probe trap INT m` write its marker and exit 130, and the shim exits 130; after SIGKILL to the shim,
no process of the tool's group exists 1 s later; after the workload exits, none remains; a
`probe daemonize` child survives and `lifetime` reads `Partial`. **Fail:** a group member outlives
the window, or the report says `Enforced`.

**`FW-E2E-123` Working directory (both; py).** **Pass:** from `tool-only/sub`, `probe cwd` prints
that directory; from `session-only/`, the request is refused with reason `cwd` and no start.
**Fail:** the tool starts outside its read scope.

**`FW-E2E-124` Placeholder bound to a launch (both; py, egress fixtures of FEP-6 §7.1).** The
command grant brokers
`{ name = "tool-key", env = "FIXTURE_TOOL_KEY", hosts = ["cred.test"], scheme = "header:x-api-key" }`
with `allow:cred.test`; the session has `allow:cred.test` and no broker. **Pass:** a request by the
tool reaches the fixture with the harness value; `printenv FIXTURE_TOOL_KEY` in the session prints
nothing; the tool's placeholder, printed by `probe env` and sent by the session through its own
proxy and by a second launch, is refused with `placeholder` and the fixture logs no credential.
**Fail:** the credential reaches the fixture on any route but the issuing launch. Derived from
README.md:139-182 and tool-sandbox.mdx:223-231.

**`FW-E2E-125` Held file credential (both; py).** `$HOME` is the scratch with a planted fake
`.ssh/id_ed25519`; the command grant has `allow-credentials = ["ssh"]`. **Pass:**
`probe read ~/.ssh/id_ed25519` returns it; the session's read fails EACCES-class; the report shows
custody `held-file`, `Enforced`. **Fail:** the session reads the key. Derived from
test_child_tool_boundaries.sh:303 and :347-350.

**`FW-E2E-126` Nesting (both; cli tests).** `outer` (callers session) and `inner` (callers
`["outer"]`, grant reading `inner-only/`, which `outer` cannot). **Pass:**
`outer call inner read inner-only/f` returns bytes; the session's `inner …` is refused `caller`; a
self-calling chain is refused `limit` at launch 9; a `daemonize`d grandchild of `outer`, its parent
gone, still calls `inner`. **Fail:** any branch differs. Derived from tool-sandbox.mdx:438-493 and
test_child_tool_boundaries.sh:388-461.

**`FW-E2E-127` Provenance gate (both; py).** **Pass:** an auto-discovered `FORMWORK.toml` carrying
`commands` fails before spawn naming `--blueprint`; the same file via `--blueprint` runs; an
auto-discovered file that extends a file carrying `commands` also fails. **Fail:** a command runs
from an auto-discovered layer.

**`FW-E2E-128` Writable program refused (both; py).** **Pass:** a program under the session's write
grant, a program whose parent a command grant writes, a script whose interpreter sits in a
session-writable directory, and a command `PATH` entry under `$TMPDIR` each fail before spawn naming
the path and the rule. **Fail:** any starts. Derived from policy.rs:1412 and CHANGELOG.md:429.

**`FW-E2E-129` Identity swap (both; cli tests).** After the session starts, a process outside the
session renames a different file over the program. **Pass:** the next request is refused `identity`;
restoring the file does not restore admission unless dev and ino match. **Fail:** the new file runs.
Derived from `verify_binary_identity_rejects_swapped_binary` (linux.rs:6404).

**`FW-E2E-130` Report, explain, determinism (both; py).** **Pass:** `formwork compile` JSON carries
`commands.probe` with exactly the §3.9 key set and `command-probe`; two compiles are byte-identical
([FW-FID4](../formwork.md#fw-fid4)); `explain probe` prints program, grant layer, each argv rule
with its layer, callers and verdicts; a second layer redefining `program` fails naming both layers.
**Fail:** a key differs or a compile is non-deterministic.

**`FW-E2E-131` Toolchain through a command (both; py).** `git` as a command with grant
`readwrite:$CWD/**`, session read-only on the project. **Pass:** `git init`, `git add`, `git commit`
and `sh -c 'git log -1'` succeed through the shim; the session's own write into `.git/` fails
EACCES-class. **Fail:** git fails under its grant, or the session writes `.git/`. Derived from
test_binary_exec.sh:34-206 and tool-sandbox.mdx:441-443.

**`FW-E2E-132` Unsupported postures (both; py).** **Pass:** `run --confine-self`, `gateway` and
`learn` with a blueprint carrying `commands` each fail before the workload runs, naming
`formwork run`. **Fail:** any runs the workload.

### 6.2 Adversarial tests (draft)

**`FW-ADV-030` Grant shaping through the request (both;
`crates/formwork-gateway/tests/command.rs`).** Property: no request content changes a grant
(`FW-INV17`). Probe classes: unknown and look-alike names (case, Unicode, `../`), argv tokens shaped
like Formwork flags or environment assignments, a working directory reached through a symlink
swapped after the request, NUL and non-UTF-8 arguments, 4097 arguments, an oversized frame, a frame
that never completes. **Pass:** each is refused with the expected reason or runs with exactly the
compiled grant, confirmed by paired reads. **Fail:** any probe reads outside the compiled grant.
From protocol.rs:161-196 and command_policy.rs:3702.

**`FW-ADV-031` Reaching a held credential (both; confine tests).** Property: `FW-INV18`. A session
process tries every non-output route to a running tool's held credential: the path, the tool's
`environ`, `fd`, `mem` and `cwd` entries (Linux), ptrace attach, `kern.procargs2` (macOS), the
launch's private temporary directory, and the tool's rendezvous descriptor. **Pass:** every route on
a line reported `Enforced` is denied, and the macOS `procargs2` route yields the environment exactly
when the report says `Unenforceable`. **Fail:** a route succeeds against an `Enforced` line.

**`FW-ADV-032` Placeholder replay (both; gateway tests).** Property: `FW-CRED20`. The session, a
second launch and a sibling command each present one launch's placeholder on their own listeners,
also after that launch exits. **Pass:** all refused `placeholder`; the fixture sees no credential.
**Fail:** any presentation.

**`FW-ADV-033` Caller forgery (both; gateway tests).** Property: `FW-GW10`. A session process tries
to be attributed to `outer`: a frame claiming a caller, descriptor numbers guessed under
`/proc/self/fd`, and a request relayed through `outer`'s standard input. **Pass:** each is
attributed to the session and `inner` is refused `caller`. **Fail:** any reaches `inner`.

**`FW-ADV-034` Program substitution (both; cli tests).** Property: `FW-ISO22`/`FW-ISO23`. Attempts
to shadow or replace the program from inside the session and from a command sandbox: writes to its
path and directory, an earlier same-named entry on the command's `PATH`, a replaced interpreter.
**Pass:** each is denied or refused before launch; the tool's identity equals the pinned one.
**Fail:** another file runs.

**`FW-ADV-035` Tool as a code relay (both; py).** Property: report honesty for `argv`. With
`allow = [["**"]]`, `probe exec` runs caller-chosen code. **Pass:** `argv` is `Partial` with the
caller-chosen-code reason; the code reads `tool-only/` and is denied `session-only/` and the floor;
adding `deny = [["exec", "**"]]` refuses it. **Fail:** the report claims `Enforced`, or the code
exceeds the command grant. From tool-sandbox.mdx:151 and :166.

### 6.3 Unit and property tests

#### 6.3.1 Where the tests live

| Module | Layer and reason |
|---|---|
| `crates/formwork-blueprint/src/command.rs` `mod tests` | pure: parse, names, token-glob, merge, caller graph; no kernel, tempdir only for grant files |
| `crates/formwork-compile/src/lib.rs` and `report.rs` `mod tests` | pure: command policies, holes, report keys, determinism, over a synthesized `HostProfile` and `ProgramFacts` ([FW-E2E-026](../formwork.md#fw-e2e-026) precedent) |
| `crates/formwork-gateway/src/command.rs` `mod tests` | pure decisions: frame parse, admission, refusal set, status and signal mapping; no spawn |
| `crates/formwork-cli/src/command_shim.rs` `mod tests` | pure: stage dispatch from `argv[0]` and a passed environment |
| `crates/formwork-confine/tests/linux_command.rs`, `macos_command.rs` | kernel: confined children probe holes and inspection, never mocked |
| `crates/formwork-gateway/tests/command.rs` | Gateway over a socketpair spawning `fw-tool-probe` under the Confiner, with `tests/support/mod.rs` (`Session::new(rules, resolver)`, `fixture_tls`, `Upstream`, `violation_for`) |
| `crates/formwork-cli/tests/command_run.rs` | the built binary through `tests/support/mod.rs` (`Scratch`, `formwork`, `formwork_env`, `host_profile`, `not_exercised`) |
| `py/harness/test_command_sandbox.py` | black-box, `@pytest.mark.fw_e2e`/`fw_adv`; a both-OS test carries neither `linux` nor `macos` (conftest skips a test marked with either off that OS) |

#### 6.3.2 The tests

nono's `command_policy.rs` carries 129 tests and `tool-sandbox/policy.rs` 24; this FEP plans 52 unit
and integration tests. The difference is surface Formwork declines (intercept actions, approval
backends, capture credentials, daemon helpers, raw Seatbelt rules, dynamic providers: about 70 of
nono's), not density per kept behavior. Every row asserts a typed variant, a closed reason or a
value, never prose.

`formwork-blueprint/src/command.rs` (17):

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `minimal_entry_parses` | `FW-BP23` | `gh_entry()` | `CommandTable::parse(GH_TOML)` → `assert_eq!(t["gh"], gh_entry())` | `active_policy_validates_references` command_policy.rs:3691 |
| `entry_without_argv_is_an_error` | `FW-BP23` | `commands_layer(&str)` | drop `argv` → `matches!(err, CommandError::MissingArgv { .. })` | `inactive_non_empty_policy_is_invalid` :3672 |
| `relative_program_is_an_error` | `FW-BP23` | `commands_layer` | `program = "gh"` → `CommandError::RelativeProgram` | `direct_bypass_paths_must_be_absolute` :4757 |
| `unknown_field_is_an_error` | `FW-BP23` | `commands_layer` | add `sandbox = {}` → `CommandError::Toml` naming `sandbox` | `command_sandbox_rejects_unknown_field` :3896 |
| `reserved_names_are_rejected_case_insensitively` | `FW-BP23` | `commands_layer` | `Session`, `FORMWORK`, `clipboard`, `desktop`, a 65-char name, `a/b` → each `CommandError::BadName` | `session_identifier_is_reserved_case_insensitively` :3702 |
| `name_of_64_chars_is_accepted` | `FW-BP23` | `commands_layer` | boundary 64 → `Ok` | — |
| `double_star_alone_admits_every_argv` | `FW-GW13` | `argv(&[&str])` | `[["**"]]` vs `[]`, `["x"]`, 4096 tokens → `ArgvVerdict::Allow` | `resolve_intercept_action_labels_catch_all_rule` policy.rs:1153 |
| `token_matches_whole_argument` | `FW-GW13` | `argv` | allow `[["pr","**"]]`, deny `["**","--web","**"]`; `--webhook` → `Allow` | `resolve_intercept_action_exact_predicate_rejects_extra_args` :879 |
| `deny_is_terminal_over_broader_allow` | `FW-GW13` | `argv` | §6.3.5 | `invocation_policy_denies_before_broader_allow` :1229 |
| `deny_matches_after_leading_global_args` | `FW-GW13` | `argv` | deny `["**","push","**","--force","**"]`; `-c x push o --force` → `Deny { rule: 0 }` | `resolve_intercept_action_matches_after_leading_global_args` :755 |
| `no_allow_match_is_not_allowed` | `FW-GW13` | `argv` | `repo delete x` → `NotAllowed` | `resolve_intercept_action_falls_through_when_rule_sequence_is_absent` :784 |
| `bad_regex_token_fails_at_parse` | `FW-GW13` | `commands_layer` | `"/(/"` → `CommandError::BadPattern` | [FW-GW9](../formwork.md#fw-gw9) parse tests |
| `merge_unions_argv_and_callers` | `FW-BP25` | `gh_entry()` | base + child adding a deny and `callers` → both lists unioned, order base-first | `merge_preserves_inherited_policy_and_appends_child_grants` :4419 |
| `deny_keyword_is_terminal_across_layers` | `FW-BP25` | two layers | `"deny"` then a full entry → merged entry absent | `command_sandbox_open_urls_merge_child_replaces` :4047 |
| `program_redefinition_is_an_error_naming_both_layers` | `FW-BP25` | two layers | different `program` → `CommandError::Redefined { first, second }` | `writable_executable_override_merges_monotonically` :4850 |
| `caller_naming_unknown_command_is_an_error` | `FW-GW11` | `commands_layer` | `callers = ["nope"]` → `CommandError::UnknownCaller` | `active_policy_validates_references` :3691 |
| `cyclic_callers_parse_and_depth_bounds_them` | `FW-GW11` | `commands_layer` | `git→ssh→git` → `Ok`; `depth_limit()` is 8 | — |

`formwork-compile` (7):

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `command_grant_inherits_no_session_grant` | `FW-ISO19` | `synthetic_facts(1)` | session reads `/s/**`, grant reads `/t/**` → command policy has `/t`, not `/s` | test_child_tool_boundaries.sh:342 |
| `session_subtracts_every_pinned_program` | `FW-ISO21` | `synthetic_facts(1)` | two commands → session `subtract` holds both; `gh`'s policy holds only `ssh`'s | `policy_command_without_bypass_is_blocked` linux.rs:6916 |
| `macos_profile_denies_exec_and_map_of_program` | `FW-ISO21` | macOS `HostProfile` | compile → SBPL contains both literal rows for `/usr/bin/gh` | `process_exec_gate_denies_by_default_and_allows_exact_paths` macos.rs:6377 |
| `link_count_above_one_is_partial` | `FW-ISO21` | `synthetic_facts(2)` | → `direct-exec` is `Fidelity::Partial` with reason containing the count token `nlink=2` | `outer_exec_gate_rejects_partial_enforcement` linux.rs:6489 |
| `unresolved_program_is_unenforceable` | `FW-ISO27` | no facts | Linux policy compiled on macOS → `direct-exec`, `identity` `Unenforceable` | — |
| `command_entry_has_exactly_the_contract_keys` | `FW-ISO27` | golden `report-command-v1.json` | `BTreeSet` of entry keys == §3.9 set; equals golden | `assert_properties_at` schema_shape.rs:11-40 |
| `command_report_is_byte_deterministic` | `FW-ISO27` | `gh_entry()` | compile twice → identical bytes | [FW-FID4](../formwork.md#fw-fid4) tests |

`formwork-gateway/src/command.rs` (12):

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `frame_at_limit_parses_and_one_byte_over_closes` | `FW-GW12` | `frame(argc, len)` | 1 MiB → `Ok`; 1 MiB + 1 → `Err(CommandRefusal::Limit)` | `validate_ipc_request` protocol.rs:161 |
| `argc_4096_parses_and_4097_is_limit` | `FW-GW12` | `frame` | → `Ok` / `Limit` | protocol.rs:36-41 |
| `nul_or_non_utf8_argument_is_malformed` | `FW-GW12` | `frame` | `b"a\0b"`, `[0xff]` → `Malformed` | `resolve_intercept_action_non_utf8_argv_predicate_falls_through` policy.rs:1113 (designed out) |
| `unknown_command_is_refused` | `FW-GW11` | `policy_with(gh)` | `decide(Caller::Session, "gl")` → `UnknownCommand` | `command_resolution_skips_missing_command_with_warning` :4648 |
| `caller_not_listed_is_refused` | `FW-GW11` | `policy_with(git, ssh)` | session → `ssh` → `Caller` | tool-sandbox.mdx:475 `"session": "deny"` |
| `depth_eight_admits_and_nine_is_limit` | `FW-GW11` | chain fixture | depth 8 → `Launch`; 9 → `Limit` | — |
| `concurrency_64_admits_and_65_is_limit` | `FW-GW11` | live count | → `Launch` / `Limit` | — |
| `cwd_outside_read_scope_is_refused` | `FW-GW13` | tempdir grant | `/tmp/other` → `Cwd` | `interpreted_script_read_grants_nothing_for_an_uncovered_script` linux.rs:6277 |
| `refusal_message_is_one_constant_line` | `FW-GW13` | each `CommandRefusal` | `agent_message(r)` == `"formwork: gh: refused\n"` for all eight | `shim_error_message_sanitizes_and_bounds_backend_reason` policy.rs:1335 |
| `operator_record_escapes_and_bounds_tokens` | `FW-GW13` | 5000-byte token with ESC | record token has no control char, ≤ 256 bytes | same |
| `signal_and_exit_mapping` | `FW-GW14` | `WaitStatus` values | exit 3 → 3; signal 11 → 139; the forwarded set is exactly eight signals | — (Formwork's `exit_code`, `crates/formwork-cli/src/main.rs:1571`) |
| `placeholder_is_fresh_per_launch` | `FW-CRED20` | `Broker::issue` twice | two placeholders differ and differ from the session's | `store_named_always_issues_fresh_nonce_without_caching_invocation` token_broker.rs:928 |

`formwork-cli/src/command_shim.rs` (2): `shim_stage_requires_fd_variable_and_non_formwork_name`
(`FW-ISO20`; `stage(argv0, env: &[(&str, &str)])` → `None` for `formwork` or without the variable,
`Some("gh")` otherwise; from `ordinary_cli_ignores_shim_discovery_variables`,
tool_sandbox_shim_env.rs:242) and `shim_reports_125_when_rendezvous_is_closed` (`FW-GW14`; closed fd
→ `ShimExit::FormworkFailure(125)`; from :202).

Integration (14): `crates/formwork-confine/tests/linux_command.rs` and `macos_command.rs` —
`session_cannot_read_or_exec_pinned_program` (`FW-ISO21`; `run(&policy, sh(..))` exit codes: 126 for
running the program from `/bin/sh`, 1 for `cat` of it, 0 for `cat` of a sibling; from
`deny_only_command_is_blocked` linux.rs:6935), `landlock_execve_requires_read_file` (`FW-ISO21`
characterization, Linux), `regression_direct_exec_denial_binds_grandchildren` (`FW-ISO21`; from
test_commands.sh:104-107), `regression_pinned_programs_add_no_execute_grant` (`FW-ISO21`; a file
written into `$TMPDIR` executes with and without `commands` alike, nono #1391, linux.rs:3384-3399),
`session_cannot_inspect_command_process` (`FW-ISO25`, `FW-INV18`; Linux `environ`/`fd`/ptrace
EACCES/EPERM, macOS task port refused). `crates/formwork-gateway/tests/command.rs` —
`broker_runs_probe_under_command_grant_only` (`FW-ISO19`), `tool_holds_exactly_three_pipes`
(`FW-ISO24`), `request_on_foreign_socket_is_never_read` (`FW-GW10`),
`regression_command_egress_does_not_inherit_session_host_rules` (`FW-CRED20`; nono #1981),
`regression_rendezvous_survives_64_concurrent_shims` (`FW-GW10`; nono #1325).
`crates/formwork-cli/tests/command_run.rs` —
`regression_auto_discovered_layer_cannot_declare_commands` (`FW-BP24`; the
`blueprint_load.rs:86-171` finding), `regression_command_path_rejects_session_writable_dir`
(`FW-ISO23`; nono #1733/#1895, policy.rs:1412), `regression_shim_works_under_empty_env_allowlist`
(`FW-ISO20`; nono #2002), `regression_grant_file_split_is_announced` (`FW-ISO19`; the split warning
skipped at `main.rs:1634`: a grant file inside a writable grant is write-protected, and `run` names
the split directory).

#### 6.3.3 Fixtures and helpers to add

- `fn gh_entry() -> CommandEntry` and `const GH_TOML: &str` — the §3.2 `gh` entry, the base every
  blueprint test mutates (mirrors `active_git_config`, command_policy.rs:3605-3622).
- `fn commands_layer(toml: &str) -> Result<CommandTable, CommandError>` parses one layer for
  parse-only tests;
  `fn commands_layer_dir(toml: &str) -> (TempDir, Result<CommandTable, CommandError>)` also writes
  each named grant file and returns the `TempDir` so the directory lives for the test (the
  `setup_test_dir() -> (TempDir, PathBuf)` shape of snapshot.rs:1147-1171).
- `fn argv(tokens: &[&str]) -> Vec<String>`.
- `fn write_program(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf` — writes mode 0o755 and
  returns the canonical path (mirrors `write_executable`, command_policy.rs:3625-3631).
- `fn synthetic_facts(nlink: u64) -> ProgramFacts` (pure) and
  `fn program_facts(path: &Path) -> ProgramFacts` (fstat at the edge).
- `fn probe_bin() -> PathBuf` — `fw-tool-probe` beside `CARGO_BIN_EXE_formwork`, the
  `fixture_path()` pattern of `crates/formwork-cli/tests/gateway_cli.rs:40-44`; a missing probe is a
  failure, not a skip.
- `struct BrokerFixture { scratch: Scratch, session: OwnedFd, broker: CommandBroker }` with
  `fn new(blueprint: &str) -> BrokerFixture` and
  `fn request(&self, name: &str, argv: &[&str], stdin: &[u8]) -> ShimOutcome { code: i32, stdout: Vec<u8>, stderr: Vec<u8> }`.
- `Scratch::isolated(tag: &str) -> Scratch` with `home()`, `state()` and `work()`, rooted at
  `env!("CARGO_TARGET_TMPDIR")/formwork-<tag>-<pid>`, and
  `formwork_in(&Scratch, args, env) -> Output`, which sets `HOME` to `home()`, `TMPDIR` to
  `state()/tmp` and the working directory to `work()`. nono roots each test under
  `target/test-artifacts` because a tempdir on a FUSE bind mount accepts Landlock grants without
  enforcing them (crates/nono-test-support/src/lib.rs:20-70, `nono_test!` :156); rooting under the
  target directory also keeps the session's sibling directories (shim directory, per-launch
  temporary directories) inside the test root, so drop removes them.
- `tool_probe` — a session-scoped pytest fixture in `py/harness/conftest.py` that runs
  `cargo build -q -p formwork-confine --bin fw-tool-probe` beside `formwork_bin` and returns the
  canonical path of `target/debug/fw-tool-probe`; a failed build fails the session, never skips it.
- `fn not_exercised(reason: &str)` copied into `crates/formwork-confine/tests/support/mod.rs` and
  `crates/formwork-gateway/tests/support/mod.rs` from
  `crates/formwork-cli/tests/support/mod.rs:127-133`.

#### 6.3.4 Patterns adopted from nono, and those designed out

1. **Kernel calls in a child.** Confine tests spawn through the existing `run(&policy, cmd)` helper
   (`crates/formwork-confine/tests/linux_confine.rs:60-64`) and assert the exit code, as nono
   asserts `WIFEXITED`/`WEXITSTATUS` (sandbox/linux.rs:5993-6030).
2. **Host gating — designed out.** nono returns early when the ABI lacks a feature
   (sandbox/linux.rs:5994-6003; linux.rs:6499-6505). Every gated test here calls
   `not_exercised("<gate>")`: Landlock absent, Seatbelt absent, connect supervision absent
   (`FW-E2E-124` on Linux), each failing under `FW_REQUIRE_EXERCISED=1`.
3. **Environment mutation.** No test sets process environment. `construct_env` already takes the
   variables as a parameter; the shim's `stage(argv0, env)` and the Launcher's command environment
   builder take them the same way. nono's `ENV_LOCK`/`EnvVarGuard` (test_env.rs:15-33) is not
   needed.
4. **Contract shape.** The `commands` report entry is pinned by an exact `BTreeSet` key test and the
   golden `crates/formwork-compile/tests/fixtures/report-command-v1.json`; the schema by
   `crates/formwork-blueprint/tests/fixtures/commands-v1.toml` parsed with `deny_unknown_fields`;
   both with a byte-determinism check ([FW-FID4](../formwork.md#fw-fid4)).
5. **Property tests.** Property: for every argv and pattern set, `decide` is `Deny` whenever any
   deny pattern matches, and `[["**"]]` alone admits every argv. Strategy: `arb_token()` from a
   12-token alphabet including `--`, `-c`, `=`-forms and `**`; `arb_pattern()` 0–4 tokens; argv 0–16
   tokens; `ProptestConfig::with_cases(64)`, as manifest_roundtrip.rs:867. `proptest` is the owed
   property-infrastructure dev-dependency (`docs/STATUS.md`); until it lands the stand-in is the
   five argv rows above, registered as a tracked test-method exception for `FW-INV17` (§7 h).
6. **Regression names.** Each `regression_*` test carries a doc comment citing the nono issue or the
   Formwork finding it pins (the `why_deny.rs` module-doc style).
7. **Shell suites — designed out.** Each adopted nono shell case is a pytest in
   `test_command_sandbox.py` with markers; the macOS-skipped no-inheritance cases
   (test_child_tool_boundaries.sh:338-341) run on macOS as `FW-E2E-117`.

#### 6.3.5 Worked example

```rust
/// FW-GW13: a deny pattern is terminal over a broader allow, and tokens match whole arguments.
/// Modelled on nono@9edf3ea:crates/nono-cli/src/tool-sandbox/policy.rs:1229
/// (`invocation_policy_denies_before_broader_allow`).
#[test]
fn deny_is_terminal_over_broader_allow() -> Result<(), CommandError> {
    let policy = ArgvPolicy::compile(
        &[vec!["pr", "**"], vec!["issue", "list", "**"]],
        &[vec!["**", "/--web(=.*)?|-w/", "**"]],
    )?;

    assert_eq!(policy.decide(&argv(&["pr", "view", "12"])), ArgvVerdict::Allow);
    assert_eq!(
        policy.decide(&argv(&["pr", "view", "12", "--web=1"])),
        ArgvVerdict::Deny { rule: 0 }
    );
    assert_eq!(policy.decide(&argv(&["pr", "-w"])), ArgvVerdict::Deny { rule: 0 });
    // Whole-argument match: `--webhook` is neither `--web` nor `--web=…`.
    assert_eq!(policy.decide(&argv(&["pr", "--webhook"])), ArgvVerdict::Allow);
    assert_eq!(policy.decide(&argv(&["repo", "delete", "x"])), ArgvVerdict::NotAllowed);
    assert_eq!(policy.decide(&argv(&[])), ArgvVerdict::NotAllowed);
    Ok(())
}
```

```python
import json

@pytest.mark.fw_e2e("FW-E2E-119")
def test_direct_execution_of_pinned_program_is_denied(cli, tmp_path, tool_probe):
    (tmp_path / "probe.toml").write_text('extends = ["builtin:default"]\n')
    bp = tmp_path / "session.toml"
    bp.write_text('extends = ["builtin:default"]\n'
                  f'[commands.probe]\nprogram = "{tool_probe}"\ngrant = "probe.toml"\n'
                  'argv = { allow = [["**"]] }\n')
    attempts = (f'"{tool_probe}" exit 0; echo "abs=$?"; '
                f'cp "{tool_probe}" "$TMPDIR/p" 2>/dev/null; echo "copy=$?"; '
                'probe exit 0; echo "shim=$?"')
    r = cli("run", "--blueprint", bp, "--", "/bin/sh", "-c", f"sh -c '{attempts}'", cwd=tmp_path)
    assert ("abs=126", "copy=1", "shim=0") == tuple(
        line for line in r.stdout.split() if line[:4] in ("abs=", "copy", "shim"))
    report = json.loads(cli("compile", "--blueprint", bp, "--report-only").stdout)
    assert report["commands"]["probe"]["direct-exec"]["status"] == "enforced"
```

### 6.4 Traceability (draft rows for formwork.md §10)

| Requirement | Primary test | Also |
|---|---|---|
| `FW-ISO19` Command grant | `FW-E2E-117` | `FW-E2E-131`, `FW-ADV-035` |
| `FW-ISO20` Command shim | `FW-E2E-118` | `FW-E2E-131` |
| `FW-ISO21` Direct-execution denial | `FW-E2E-119` | unit `session_subtracts_every_pinned_program` |
| `FW-ISO22` Program identity | `FW-E2E-129` | `FW-ADV-034` |
| `FW-ISO23` Unwritable program | `FW-E2E-128` | `FW-ADV-034` |
| `FW-ISO24` Descriptor set | `FW-E2E-121` | `FW-ADV-031` |
| `FW-ISO25` Command inspection | `FW-ADV-031` | `FW-E2E-125` |
| `FW-ISO26` Command lifetime | `FW-E2E-122` | — |
| `FW-ISO27` Command report | `FW-E2E-130` | `FW-E2E-119`, `FW-ADV-035` |
| `FW-GW10` Rendezvous attribution | `FW-ADV-033` | `FW-E2E-126` |
| `FW-GW11` Caller admission | `FW-E2E-126` | `FW-ADV-033` |
| `FW-GW12` Request bounds | `FW-ADV-030` | `FW-E2E-118` |
| `FW-GW13` Invocation admission | `FW-E2E-120` | `FW-E2E-123`, `FW-ADV-035` |
| `FW-GW14` Shim transparency | `FW-E2E-121` | `FW-E2E-122` |
| `FW-CRED20` Launch-bound placeholder | `FW-E2E-124` | `FW-ADV-032` |
| `FW-CRED21` Session floor precondition | `FW-E2E-125` | unit (Linux any-depth type refused) |
| `FW-CRED22` Command custody | `FW-E2E-125` | `FW-ADV-031` |
| `FW-BP23` Commands shape | `FW-E2E-130` | unit (17) |
| `FW-BP24` Command provenance | `FW-E2E-127` | — |
| `FW-BP25` Command layering | `FW-E2E-130` | unit |
| `FW-INV17` Pre-compiled command authority | `FW-ADV-030` | `FW-E2E-127`, `FW-ADV-033` |
| `FW-INV18` Command custody | `FW-ADV-031` | `FW-E2E-124`, `FW-E2E-125` |

### 6.5 Phasing

- **A — pure core (non-deviating).** `commands` parse, merge and argv matcher; command compile and
  report lines; `explain <name>`; `run` refuses a blueprint with `commands` ("compiled, not yet
  run"). Grants nothing anyone lacks, so it needs no amendment and opens no exception. Tests: 6.3.2
  pure rows, `FW-E2E-130`, `FW-E2E-132`.
- **B — mechanism, both backends.** After the §7 amendments land: shim stage, rendezvous, admission,
  spawn, relay, lifetime, direct-execution holes with the Landlock characterization first.
  `FW-E2E-117`..123, 126..129, 131; `FW-ADV-030`, 031, 033..035.
- **C — command-scoped egress.** Per-launch listeners and placeholders. `FW-E2E-124`, 125;
  `FW-ADV-032`.
- **D — open questions** of §9 that close inside this FEP.

---

## 7. Amendments to the landed docs (apply on landing)

**(a) [FW-CAP2](../formwork.md#fw-cap2)**, replacement text:

> **FW-CAP2** Monotonic narrowing. A session may narrow its own grant but never widen it. A child's
> grant is a subset of its parent's. A process the Gateway spawns on a session's request — a stdio
> MCP backend or a command sandbox — is not the session's child: it runs under a grant compiled
> before the session's workload started, from operator-authored blueprint layers, which the
> session's requests select but cannot change (`FW-INV17`).

**(b) [FW-XR8](../formwork.md#fw-xr8)**, appended sentence:

> A command sandbox is not an escalation in this sense: its grant is compiled and its program pinned
> before the workload runs, from layers whose provenance is `flag` or `builtin` (`FW-BP24`); a
> request names a pre-compiled command and supplies only argv its invocation policy admits, a
> working directory inside its grant, and standard input, and nothing in it reaches a grant, a
> program or a credential.

**(c) [FW-XR5](../formwork.md#fw-xr5)**, replacement of the second sentence: "The agent, every stdio
MCP backend and every command sandbox are confined by the same confiner, each to its own compiled
grant."

**(d) Constitution — Concepts.** Session: "a confined process tree: the agent and its descendants,
and the stdio MCP backends and command sandboxes the Gateway spawns, each under the Confiner with
its own CompiledPolicy." Seam: add "and, for the opener shim and command shims, a socket the session
inherits". Vocabulary: **command sandbox** = a Session the Gateway spawns from a pre-compiled
`commands` entry on a request it receives over the Seam; **pin** = record a program's identity at
session start so that only that file runs.

**(e) [FW-FID8](../formwork.md#fw-fid8)**: add the `commands` map and `command-<name>` rows (§3.9).
**[FW-FID9](../formwork.md#fw-fid9)**: add "each command-shim refusal".
**[FW-FID13](../formwork.md#fw-fid13)**: add "and for each command launch, a record with command,
caller, escaped argv, working directory, status, duration and byte counts".
**[FW-FID11](../formwork.md#fw-fid11)**: `explain` also accepts a command name.
**[FW-EGR14](../formwork.md#fw-egr14)**: "whenever the blueprint or any command grant carries a host
rule".

**(f) `formwork.md` §3**, in scope: "A confined process causing a command sandbox to act outside its
compiled grant or invocation policy." §9: the §3.9 rows in the fidelity summary and the asymmetry
table.

**(g) Traceability**: the §6.4 rows. Defining site: add `docs/fep-8.md` to the canary's `DEFINING`
list or fold §5 into `formwork.md` §5.3, §5.4, §5.8, §5.9 and §6.

**(h) `docs/STATUS.md`**: a tracked test-method exception for `FW-INV17` (property over argv and
pattern sets; example-based stand-in; expiry: the property-infrastructure FEP).

---

## 8. Decisions (recorded per constitution Precedence & Conflicts)

- **The tension with [FW-CAP2](../formwork.md#fw-cap2), [FW-XR5](../formwork.md#fw-xr5) and
  [FW-XR8](../formwork.md#fw-xr8) is resolved by amendment, not exception.** A command sandbox holds
  grants the session lacks, which the plain reading of "a child's grant is a subset of its parent's"
  forbids. STOP, stated: the rule and the task conflict. The command sandbox is not the session's
  child in the process tree (the Gateway spawns it) or in authority (the operator wrote its grant
  before the run). The structure already exists twice in landed Formwork: a stdio MCP backend runs
  under the blueprint `formwork gateway` was given, and a brokered credential is presented by the
  Gateway on a session's request. What CAP2 and XR8 protect is that nothing the agent emits shapes
  authority; `FW-INV17`, `FW-BP24` and the request's three inputs (argv inside policy, cwd inside
  grant, stdin) preserve it. XR5 holds because the Gateway stays the only unconfined component. The
  amendment text is §7 (a)–(c); no mechanism lands before it (phase B).
- **Operator-authored means `flag` or `builtin`.** An auto-discovered file is authored by whoever
  committed it; refusing `commands` there costs one `--blueprint` and closes the review finding for
  this feature (`FW-BP24`).
- **The grant is a Blueprint file.** An inline nono-style `sandbox` object would be a second grant
  vocabulary; reusing the Blueprint reuses verbs, host rules, `allow-credentials`, the floor and
  every report line.
- **One grant per command, not per caller.** nono's `from.<caller>` gives each edge its own grant;
  Growth says no until an operator needs two grants for one program, which two command names give.
- **Attribution by descriptor.** It removes lineage walks, cgroup markers, daemon helpers and
  per-launch `setsid` (2.3 item 5) and is unforgeable from the session (`FW-ADV-033`).
- **Inherited descriptor, not a socket path** ([FW-XR7](../formwork.md#fw-xr7)).
- **Relay through the shim, not descriptors to the tool.** Passing session descriptors would let a
  session hand the tool a directory or socket; Gateway-owned pipes make the descriptor set exact.
  The cost is no terminal for tools (§9).
- **No caller environment.** `export_env` exists in nono because tools need some variables, and it
  forwards loader and tool-control variables when misconfigured (tool-sandbox.mdx:607-621). v1
  builds a command's environment from the operator's only.
- **`argv` required, lexical, `Partial`.** A program's option grammar is not modelled; the report
  says so on every backend instead of claiming the deny list covers spellings it cannot see.
  Non-UTF-8 arguments are refused rather than left unmatched.
- **No approval, intercepts, capture, `exec` helpers or invocation-scoped approvals.** Each is a
  decision taken during the run on the agent's request; [FW-XR8](../formwork.md#fw-xr8) leaves such
  escalation to a host's out-of-band action, and [FW-FID5](fep-1.md#fw-fid5)'s stream is where an
  embedder would build it.
- **Writable targets refused, no downgrade.** nono's own examples ship with the downgrade enabled
  (2.3 item 3).
- **Direct-execution denial is reported as what it is.** It protects the invocation policy and the
  record, not the grant; copies and extra links are named.
- **Family placement.** The report line is `FW-ISO27` because no FID block was reserved; on landing
  it may be renumbered into FID before anchoring, as an unlanded draft.
- **No pty, spawn posture only, `learn` refused.** Each keeps v1 inside mechanisms Formwork already
  verifies; §9 holds the follow-ups.

---

## 9. Open questions

- **Landlock and `execve` without `READ_FILE`** — whether the read hole alone denies execution.
  Owner: Linux backend maintainer. Closes: phase B, before `FW-ISO21` is anchored.
- **Lifetime beyond the process group** — subreaper, per-launch cgroup or PID namespace on Linux;
  nothing comparable on macOS. Owner: Linux backend maintainer. Closes: phase D, or the report stays
  `Partial`.
- **Terminal for interactive tools** — a Gateway-allocated pty when the shim's three descriptors are
  terminals, as nono does (linux.rs:5336-5342). Owner: CLI maintainer. Closes: phase D.
- **Caller environment forwarding** — a closed list of names a command may accept from its caller,
  excluding loader and tool-control variables. Owner: blueprint schema owner. Closes: adoption
  review, after two operator requests.
- **Per-caller grants** — nono's `from.<caller>`. Owner: blueprint schema owner. Closes: adoption
  review.
- **`learn` with commands** — whether argv refusals become proposals; they would be agent-initiated
  widenings. Owner: discovery maintainer. Closes: with FEP-4's mechanism.
- **Other paths to a pinned file** — bind mounts are not detected. Owner: Confiner maintainer.
  Closes: adoption review.
- **Nested `formwork run`** — whether a nested Launcher closes the outer session's rendezvous and
  opener descriptors before its workload. Owner: CLI maintainer. Closes: phase B.
- **Commands for MCP backends** — shims inside `formwork gateway` backends. Owner: Gateway
  maintainer. Closes: after [FW-GW7](../formwork.md#fw-gw7) self-confinement.
- **Worktrees and dynamic paths** — nono's `@git:` tokens run git at prepare time
  (tool-sandbox.mdx:168-208); sigils are a closed set ([FW-BP5](../formwork.md#fw-bp5)). Owner:
  blueprint schema owner. Closes: on a second operator request.
