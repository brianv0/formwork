# FEP-9 (proposal): denial diagnostics — a session record, an end-of-run account, and `explain` that matches the run

**Formwork Enhancement Proposal 9 — proposal, not landed.** Companion to `formwork.md`
(design + end-to-end spec) and `constitution.md` (doctrine).

**Status.** Nothing in this document mutates the landed spec or the constitution. The §7
amendments are apply-on-landing blocks for review; until they are applied, every identifier this
FEP mints is draft numbering, written as inline code so the requirements canary skips it. This
FEP holds the reserved blocks `FW-FID16`..`FW-FID24`, `FW-DISC13`..`FW-DISC14`, `FW-INV19`,
`FW-E2E-133`..`FW-E2E-144` and `FW-ADV-036`..`FW-ADV-038`, and uses every number in them. On
landing it supersedes the deferred remainder of FEP-1, [FW-FID5](fep-1.md#fw-fid5) and
[FW-E2E-040](fep-1.md#fw-e2e-040) (§7 i). The prior art is nono at commit `9edf3ea`
(2026-10-05), cited as nono@9edf3ea:path:line on first use in a paragraph and path:line after
it; short paths in §6 and §8 are basenames, unique in nono's tree except `audit.rs` (meaning
`crates/nono/src/audit.rs`) and `audit_ledger.rs` (the `crates/nono-cli/src/` module; the
integration test is written `tests/audit_ledger.rs`). Its files were read, never built or run.
The Linux findings in §1 were reproduced on Linux 6.18 with Landlock ABI 7.

---

## 1. Problem

A denied operation reaches the confined process as a bare `EACCES`, by design
([FW-CRED7](../formwork.md#fw-cred7)). The operator learns more only for some denials and only in
some commands:

- **Filesystem denials during `run` are recorded nowhere.** `spawn_confined_child` logs the exit
  status and nothing the kernel refused (`crates/formwork-cli/src/main.rs:1650-1760`). On macOS
  every deny of a spawned session already carries a per-session tag into the unified log
  (`main.rs:1270-1278`, `crates/formwork-compile/src/sbpl.rs:70-74`), but only `learn` reads it.
  On Linux the only feed is `learn`'s ptrace tap, which needs `strace` on `PATH` (`main.rs:1897-1917`).
- **Egress, socket and opener refusals are emitted, then dropped.** The Gateway keeps up to 1,024
  violations in memory (`crates/formwork-gateway/src/egress.rs:48`) and writes one operator line
  per refusal ([FW-FID9](../formwork.md#fw-fid9)); at session end only a `learn` run collects them
  (`main.rs:1785-1860`).
- **Learning is a second run.** To find what a failed run needed, the operator reruns it under
  `learn`, which on Linux adds an `strace` ancestor and on macOS waits at least six seconds for the
  log to settle (`crates/formwork-cli/src/learn.rs:175-178`).
- **`explain` disagrees with the run.** [FW-FID6](../formwork.md#fw-fid6) scopes `explain` to the
  merged blueprint, "not the session-only denies `run` adds" (`main.rs:600-612`). Those denies
  change verdicts. The verified case: `run` write-protects the blueprint inside a writable grant
  ([FW-XR8](../formwork.md#fw-xr8), `crates/formwork-cli/src/blueprint_load.rs:760-786`);
  Landlock has no deny rule, so the subtractive expansion splits every directory between the hole
  and the grant root, and a split directory admits no new entries
  (`crates/formwork-confine/src/linux/landlock.rs:107-158`). `touch $CWD/new.txt` fails with
  `EACCES` while `explain $CWD/new.txt` answers `write: granted`. FEP-5 D3's remedy, moving the
  blueprint to `.formwork/blueprint.toml`, does not help: the hole is still strictly under the
  project root, and `announce_split_root` stops warning for that layout (`main.rs:1634`). The
  Launcher's write-protected directories under the temporary root ([FW-TRA9](../formwork.md#fw-tra9))
  split it the same way, and [FW-CRED3](../formwork.md#fw-cred3)'s env-file denies come from the
  launching environment, which `explain` never consults.
- **[FW-FID5](fep-1.md#fw-fid5) is deferred.** `docs/fep-1.md` holds a violation stream with a
  test, [FW-E2E-040](fep-1.md#fw-e2e-040), and no mechanism; `docs/STATUS.md` lists "no runtime
  record of fs denials" as owed.

Who is hurt: the operator of a failing agent run reads `Permission denied` in the agent's output
with no account of which rule refused what, and on Linux `explain` tells them the opposite; an
embedding host (FEP-5 §3.5's SDK harness) has no structured record to show its user; the agent
spends turns retrying operations the sandbox will never allow.

### 1.1 Constraints this FEP holds to

- **No new concept, no new family.** The record is the Session's, written by the Launcher; the
  Linux feed is a Confiner flag; the query and the proposal are `explain` and `learn`.
  Requirements continue FID, DISC and INV.
- **Channel split** ([FW-CRED7](../formwork.md#fw-cred7), [FW-FID9](../formwork.md#fw-fid9)).
  Everything added is operator-side: the account on `run`'s stderr, the record outside every
  session's grant. The confined process sees nothing it does not see today.
- **Wrapper transparency** ([FW-XR10](../formwork.md#fw-xr10), [FW-XR11](../formwork.md#fw-xr11)).
  Nothing on stdout; diagnostics never change the workload's exit status; nothing is printed for a
  session with zero denials ([FW-TRA2](../formwork.md#fw-tra2)'s common case).
- **Observation never widens** ([FW-INV10](../formwork.md#fw-inv10), [FW-XR8](../formwork.md#fw-xr8)).
  A record is never a policy input; it reaches a grant only through `learn` and per-entry accept.
- **Evidence, not inference.** An entry exists because the kernel or a Formwork component refused
  an operation of this session, never because the workload printed something shaped like a refusal.
- **Honesty** ([FW-INV5](../formwork.md#fw-inv5)). Each backend's feed carries a report verdict; a
  host without a feed says so before the workload runs ([FW-XR9](../formwork.md#fw-xr9)).
- **Growth.** No new subcommand, no new dependency (§4).

---

## 2. Prior art: nono

### 2.1 The end-of-run footer and its feeds

After a supervised run nono prints a diagnostic block to stderr
(nono@9edf3ea:crates/nono-cli/src/output.rs:857-860, 1011-1025) whenever the exit code is non-zero
or it holds any evidence: kernel-attributed denials, IPC denials, Seatbelt violations, or findings
parsed from the command's own output (crates/nono-cli/src/exec_strategy.rs:1927-1941). The block
lists up to ten denied paths, collapses the rest into "… and N more", and ends with one line of
flags that would grant them (crates/nono-cli/src/diagnostic/formatter.rs:4455-4482;
docs/cli/usage/troubleshooting.mdx:353-364). It says "may be due to" rather than "was caused by",
because a non-zero exit need not be the sandbox's doing (formatter.rs:13-18). With a profile, nono
then offers, in an interactive prompt, to save the missing grants as a profile patch
(exec_strategy.rs:1736-1772; crates/nono-cli/src/profile_save_runtime.rs).

The feeds differ by platform. On **macOS**, a `log stream` started at spawn, filtered to the child
by PID or by process name, stops reading at 50 violations, with a `log show --last 10s` fallback
when the stream caught nothing (nono@9edf3ea:crates/nono-cli/src/sandbox_log.rs:19-21, 29-36, 136-143, 187-200,
208-230). On **Linux**, kernel-attributed filesystem denials exist only under capability
elevation, a seccomp interception of `openat` that prompts the user and injects a descriptor on
approval (docs/cli/features/supervisor.mdx:29-56; exec_strategy.rs:222-245). It is off by default;
without it "a sandboxed process … will receive `EPERM` as normal" (supervisor.mdx:45), and the log
collector is a no-op (sandbox_log.rs:204-207, 280-286). What remains is a heuristic over the
command's terminal output: lines containing "permission denied" or "operation not permitted"
become path hints (exec_strategy.rs:1589-1601; formatter.rs:147-258).

### 2.2 `nono why`

`nono why --path P --op read|write` answers allowed or denied with a reason code
(`filesystem_deny`, `path_not_granted`, `insufficient_access`), the policy source and a suggested
flag (nono@9edf3ea:crates/nono-cli/src/query_ext.rs:45-103; tests/integration/test_policy_queries.sh:30-58).
`nono profile show --format manifest` emits the effective rules "using the same extends + group
resolution that `nono run` uses" (docs/cli/features/profile-introspection.mdx:319), and #1556 made
`why` report an explicit deny before a covering allow (CHANGELOG.md:602;
crates/nono-cli/tests/why_deny.rs:1-4). `why --self` answers from inside the sandbox: nono writes
the session's capability state to a file and passes its path in `NONO_CAP_FILE`, which the
sandboxed process reads (crates/nono-cli/src/sandbox_state.rs:1-5; troubleshooting.mdx:272-300).

### 2.3 The session audit record

Every `nono run` writes a session directory under `$XDG_STATE_HOME/nono/audit/` with
`session.json` and an append-only `audit-events.ndjson` (nono@9edf3ea:docs/cli/features/audit.mdx:6, 415). It
holds the command and its arguments "with best-effort redaction" (audit.mdx:39-50, 168),
timestamps, exit code, supervisor events and proxy network events, and by default a hash chain and
Merkle root entered into a global ledger, with optional signing (audit.mdx:106-170). `nono audit
list|show|verify|cleanup` query it; retention is manual (audit.mdx:323-341). nono refuses any grant
that overlaps its state roots, a parent such as `~` included (crates/nono-cli/src/protected_paths.rs:1-40).

### 2.4 Why nono removed `learn`

nono's macOS `learn` traced the command with `fs_usage` (nono@9edf3ea:CHANGELOG.md:3449), a root-only tracer
whose pipe buffering and process-name matching needed fixes (CHANGELOG.md:3026), and `nettop` for
the network (CHANGELOG.md:3212). It was deprecated with the note "Deprecate 'nono learn' and
improve diagnostics" (CHANGELOG.md:1873), the diagnostic's pointer to it was replaced by `nono run`
(#1170, CHANGELOG.md:1117), and it was removed (#1543, CHANGELOG.md:652). The entries state no
rationale; the page that replaced it shows the effect: "run the command under `nono run`. nono
reports denied paths at exit with suggested fix flags", and with a profile prompts to save a patch
(troubleshooting.mdx:339-369). The question moved into the run the user was already making, and
the root-only tracer went with it.

### 2.5 nono's tests in this area

Unit, under nono@9edf3ea:crates/nono-cli/src/: `diagnostic/formatter.rs` 92 (dedup :4390, the ten-entry cap :4455, "may not was" :2811,
stderr parsing :2991-3171); `why_runtime.rs` 30 (unresolvable network policy is an error :959, deny
covers a missing leaf :1004, sibling prefix :1218); `sandbox_log.rs` 11 (PID and name attribution
:505-546); `query_ext.rs` 27; `profile_save_runtime.rs` 54; `audit_session.rs` 8 (traversing id
:587, symlink out of the root :601); `audit_event_reader.rs` 7 (half-written final record :290,
damage before it :315); `audit_ledger.rs` 5; `audit_commands.rs` 18 (size-budget pruning
:1309-1333); `crates/nono/src/audit.rs` 18 (argument scrub :1615, golden vectors :2292).
Integration: `tests/why_deny.rs:36, 70`; `tests/audit_ledger.rs:47, 73`;
`tests/integration/test_audit.sh:71-266`; `test_policy_queries.sh:30-78`;
`test_silent_output.sh:54-73`; the golden fixture `tests/fixtures/audit-session-metadata-v1.json`
(asserted at crates/nono-cli/src/audit_client.rs:779-786). §6 names the Formwork test each feeds.

### 2.6 Defects and documented limitations

- **The Linux account rests on what the command printed.** The heuristic misses a tool that fails
  quietly and invents a denial for any path the workload names in a refusal-shaped line
  (nono@9edf3ea:crates/nono-cli/src/diagnostic/formatter.rs:147-258); such a hint alone qualifies the run for the save prompt
  (exec_strategy.rs:1961-1975).
- **The save prompt can lift protection.** A `sensitive_path` denial becomes a patch with
  `bypass_protection` for the file (profile_save_runtime.rs:2066-2096): one keypress from a
  credential grant.
- **Kernel attribution on Linux needs live widening**: capability elevation intercepts `openat`
  before Landlock and opens files on approval (supervisor.mdx:49-56).
- **macOS attribution by PID or name** admits a same-named process and drops a child with another
  name (sandbox_log.rs:29-36, tested :528, :538); the stream stops at 50 without saying so
  (:136-143); the fallback window is a fixed ten seconds (:229).
- **`why --self` hands the sandboxed process its whole capability set** (sandbox_state.rs:1-5).
- **Recording failures change the exit status**: an unrecorded run that exited 0 exits 1
  (audit.mdx:398; tests/audit_ledger.rs:45-70); #1804 stopped save-prompt failures overriding the
  child's code (CHANGELOG.md:132).
- **Arguments are recorded with best-effort redaction** (audit.mdx:168; crates/nono/src/audit.rs:1615-1636).
- **Records accumulate** until the user runs cleanup (audit.mdx:323-341).
- Fixed regressions in the area: #1556 (above), #1554 `why` fails on an unresolvable policy instead
  of degrading (CHANGELOG.md:562), #1873 `--self` tolerates process-relative aliases (:130), #1596
  errors after an unparseable ledger (:465), #1603 per-variant golden vectors (:546), #1862
  directory sizing against symlink cycles (:134). The GHSA identifiers carry no description in the
  changelog (CHANGELOG.md:5-7, 114-120), and none of the fixes released with them is in
  diagnostics, `why` or audit.

### 2.7 What Formwork adopts and declines

| nono | Formwork | Basis |
|---|---|---|
| Account at the end of every run, ten entries then "N more" | Adopted on stderr; nothing when nothing was denied (`FW-FID21`) | §2.1 |
| Session record by default under `$XDG_STATE_HOME` | Adopted: JSON Lines, operator-side, bounded (`FW-FID16`, `FW-FID24`) | §2.3 |
| Query by session id | `explain --session` (`FW-FID23`) | §2.3 |
| Query uses `run`'s resolution (#1556, `--format manifest`) | `explain` applies the session-only denies (`FW-FID22`) | §2.2 |
| Half-written tail reported, damage before it an error; golden fixtures | Adopted for the record reader and format (§6.3) | §2.5 |
| State directory unreachable from sessions | Adopted as a subtract, not a refused grant (`FW-INV19`) | [FW-TRA2](../formwork.md#fw-tra2) |
| Terminal-output heuristics | Declined: entries only from kernel or Formwork records | §1.1 |
| Interactive save prompt; `bypass_protection` patch | Declined: `learn --session`, per-entry accept, floor withheld (`FW-DISC13`) | [FW-INV8](../formwork.md#fw-inv8), [FW-ADV-012](../formwork.md#fw-adv-012) |
| Capability elevation (live `openat` approval) | Declined | [FW-INV10](../formwork.md#fw-inv10), [FW-XR8](../formwork.md#fw-xr8) |
| `why --self` capability file | Declined (§3.8) | [FW-CRED7](../formwork.md#fw-cred7), [FW-FID9](../formwork.md#fw-fid9) |
| Arguments with best-effort redaction | Program path only (`FW-FID17`) | §2.6 |
| Exit status downgraded on a recording failure | Workload's status kept, one stderr line | [FW-XR10](../formwork.md#fw-xr10) |
| Hash chain, ledger, signing | Declined (§8) | Growth; `formwork.md` §3 |
| Manual retention | Automatic bounds (`FW-FID24`) | §2.6 |
| Removing `learn` | Declined: unprivileged Linux has no other feed (§3.2) | [FW-XR9](../formwork.md#fw-xr9) |
| Live sessions (`ps`, `attach`, `inspect`) | Out of scope | — |

---

## 3. Design

### 3.1 Where each piece lives

| Piece | Concept | Crate |
|---|---|---|
| Record line types, session id, bounds, prune plan, record parser | Session (the Launcher's artifact) | `formwork-blueprint` (`record.rs`, pure) |
| Session-only denies, one function for `run` and `explain`, environment passed in | Launcher | `formwork-blueprint` (`launcher.rs`, pure) |
| Split-directory predicate, shared by the expansion and `explain` | CompiledPolicy (Linux) | `formwork-compile` (`linux.rs`, pure) |
| `denial-record` report line | FidelityReport | `formwork-compile` |
| Whether a denial feed is readable here | HostProfile | `formwork-detect` |
| `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`; the audit reader | Confiner | `formwork-confine` (`linux/landlock.rs`, `linux/audit.rs`) |
| Record writer, pruning, feed parsers, account, `--session` | Launcher, CLI shell | `formwork-cli` (`record.rs`, `feed.rs`, `render.rs`) |

### 3.2 A filesystem denial feed during `run`

| Feed | Cost | Privilege | Attribution to this session | Used by |
|---|---|---|---|---|
| Landlock audit (Linux 6.15+, ABI 7) | one kernel record per denial, none per allowed operation; one reader thread | `CAP_AUDIT_READ`, audit enabled | exact: the Landlock domain the session's child created | `run` (§3.3) |
| ptrace (`strace`, `learn`'s tap) | a stop on every traced file syscall; an extra ancestor; the workload cannot be traced by its own debugger | none (ancestor) | exact: the traced tree | `learn` only |
| seccomp user notification on file syscalls | a supervisor round trip per open | none | sees the request, not Landlock's verdict | rejected |
| fanotify, eBPF LSM | per-event delivery | `CAP_SYS_ADMIN` / `CAP_BPF` | no Landlock verdict | rejected |
| unified log by deny tag (macOS) | one `log stream` child for the session; no attach wait | what `learn` already uses | exact: the tag every session deny carries | `run` and `learn` |
| `fs_usage`, Endpoint Security (macOS) | system-wide capture | root; entitlement | reconstructed | rejected (FEP-4 §7) |

The ptrace feed stays `learn`'s: its per-syscall cost breaks [FW-TRA6](../formwork.md#fw-tra6)
for an ordinary run. On a Linux host without readable audit, `run` records non-filesystem refusals
only, the report says so before the workload starts, and `learn` remains the way to observe
filesystem denials. That is why this FEP keeps `learn` where nono removed it.

On macOS `run` starts `log stream` without waiting for it to attach, because the attach probe
that `learn` waits on costs up to five seconds per spawn (`learn.rs:198`). A denial before attach
is recovered post-hoc by tag: at exit, when the workload exited non-zero or the stream saw a
record, `run` polls `log show` for the tag for at most **settle-budget**; records that persist later
are added by `explain --session` (`FW-FID23`), which can query by tag for as long as the unified
log retains them. The verdict is `Partial` for that reason.

### 3.3 Linux: Landlock audit

From ABI 7 (Linux 6.15) Landlock writes denials to the kernel audit stream as two record types:
`LANDLOCK_ACCESS` (domain id, `blockers`, `path`, `dev`, `ino`) and `LANDLOCK_DOMAIN` (`allocated`,
with the pid and executable that called `landlock_restrict_self`, emitted after the domain's first
access record; `deallocated`, with `denials=N`). By default only the restricting executable's own
denials are logged; `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON` logs them after `execve` too, and the
kernel documentation warns that it can flood the audit log. The pinned `landlock` 0.4.5 crate
exposes the flag as `log_new_exec`, so no dependency changes. The flag travels as a
`SessionSpec` field into the Linux policy, as the macOS deny tag does
(`crates/formwork-compile/src/lib.rs:193-216`), so compile stays pure.

The flow: `detect` records whether the host can feed a session (ABI ≥ 7, a bind to the audit
multicast group succeeds, audit enabled; the exact probe is characterization L5). Before spawn the
Launcher opens the reader; only then does the Confiner set the flag (`FW-FID19`), so a session never
adds audit records nobody consumes. The `allocated` record names the spawned child (or the
isolation stage, [FW-ISO10](../formwork.md#fw-iso10)) as creator, which maps the domain to the
session; access records that arrive before it are held, by domain, for at most **settle-budget**.
`blockers` map to the record's access: `fs.read_file`, `fs.read_dir` → `read`; `fs.write_file`,
`fs.truncate`, `fs.refer` → `write`; `fs.make_*` → `create`; `fs.remove_*` → `remove`;
`fs.execute` → `exec`. For `create` and `remove` Landlock names the directory it checked, so the
line says "a new entry in `<dir>`". Paths the audit layer hex-encodes are decoded; `dev` and `ino`
are dropped (`FW-FID17`). At exit the Launcher waits at most **settle-budget** for the
`deallocated` record; `denials=N` minus the access records it attributed is written as `fs-lost`.
A denial raised by a Landlock domain the workload created for itself names that domain and is not
the session's. While Formwork consumes the records, any other audit reader on the host (auditd)
receives them too; §9 holds that question.

### 3.4 The session record

**Location.** `<state>/formwork/sessions/<id>.jsonl`, where `<state>` is `$XDG_STATE_HOME` when it
is set and absolute, otherwise `$HOME/.local/state`, on both platforms. The directory is created
0700; a directory that is a symbolic link or is owned by another user is refused. The file is
created before the spawn with `O_CREAT | O_EXCL | O_NOFOLLOW`, mode 0600. The id is
`<unix-seconds>-<16 hex>` from the session nonce (`main.rs:1070-1078`); the macOS deny tag carries
the same 16 hex, so a record and its log entries correlate.

**Shape (format 1).** JSON Lines, one object per line, discriminated by `kind`, with exactly these
keys (`?` marks a key present only when known):

| `kind` | Keys |
|---|---|
| `session` (first line) | `format` (1), `id`, `started-ms`, `formwork` (version), `os`, `posture`, `program` (argv[0] as given), `cwd`, `blueprint` `{path, source}` ([FW-FID7](../formwork.md#fw-fid7)), `feed` `{fs, verdict, gap?}` |
| `fs` | `t-ms`, `access` (`read`, `write`, `create`, `remove`, `exec`), `path`, `rule`, `layer`, `floor?` (credential type) |
| `egress` | `t-ms` and the [FW-FID12](../formwork.md#fw-fid12) fields: `capability`, `reason`, `host`, `port`, `method?`, `path?` (canonical, no query), `rule?` |
| `socket` | `t-ms`, `path`, `channel?` ([FW-ISO12](../formwork.md#fw-iso12) refusals, mapped as `learn` maps them) |
| `channel` | `t-ms`, `channel`, `scheme?`, `host?` (an opener refusal, URL reduced to scheme and host) |
| `end` (last line) | `ended-ms`, `exit` `{code}` or `{signal}`, `denials` (all, repeats included), `distinct`, `dropped`, `fs-complete` (true, false or null), `fs-lost` (count or null) |

A line is appended once per distinct (`kind`, access, target); repeats only increment `denials`.
`rule` and `layer` are computed from the session's effective blueprint, launcher denies included,
when the line is appended, so a later edit to the blueprint does not rewrite history. A record
without an `end` line is an interrupted session; a reader reports it as interrupted and counts its
complete lines, and treats damage before the final line as an error (nono's
audit_event_reader.rs:290-337 rule).

**Bounds**, defined once here and implemented as named constants in `formwork_blueprint::record`:

| Parameter | Value | Bounds |
|---|---|---|
| **record-entries** | 1,024 | distinct entry lines per record (the Gateway's `MAX_KEPT_RECORDS`) |
| **record-bytes** | 256 KiB | bytes per record file |
| **record-sessions** | 200 | records kept, newest first |
| **record-age** | 30 days | age of the oldest record kept |
| **append-latency** | 1 s | from a refusal reaching Formwork to its line on disk |
| **settle-budget** | 2 s (TBD, §9) | the wait at exit for late feed records |
| **account-lines** | 10 | denial entries listed in the account |

Disk use is therefore at most 50 MiB per user. Past **record-entries** or **record-bytes** the
writer appends nothing but the `end` line, whose `dropped` counts the distinct denials not written.

**Failure.** If the directory or file cannot be created, `run` proceeds: one stderr line names the
directory and the error before the spawn, and the record's absence is the `denial-record`
verdict's reason. Observation is not containment; refusing the run would turn an unwritable state
directory into an outage. An append failure after spawn is stated in the account. Neither changes
the exit status.

**Not recorded** (`FW-FID17`): environment values, arguments, header values, bodies, query strings,
opener URL paths, placeholders, credential bytes, inode and device numbers. Paths, hosts, methods
and canonical paths are recorded verbatim, as the operator channel prints them today.

### 3.5 The end-of-run account

```text
formwork: session 1791391353-3f9a0c12d4e5b678: 4 denied (record ~/.local/state/formwork/sessions/1791391353-3f9a0c12d4e5b678.jsonl)
formwork:   read    /home/u/proj/secret/a.env     deny:$CWD/secret/**  [file FORMWORK.toml]
formwork:   create  new entry in /home/u/proj     split by /home/u/proj/FORMWORK.toml  [launcher]
formwork:   read    /home/u/.aws/credentials      credential floor (aws)  lift: allow-credentials = ["aws"]
formwork:   egress  GET blocked.test:443/x        host-not-listed  explain https://blocked.test/x
formwork: propose grants for the next run: formwork learn --session 1791391353-3f9a0c12d4e5b678
```

`run` writes the account after the workload exits and before it exits itself, directly to stderr
and not as a tracing event, so `RUST_LOG=warn` does not remove it; it precedes any
[FW-XR11](../formwork.md#fw-xr11) line, which stays last. It lists at most **account-lines**
entries and folds the rest, dropped ones included, into "and N more". With no denial and exit 0 it
prints nothing. With no denial, a non-zero exit and a `denial-record` verdict other than
`Enforced`, it prints one line naming the gap and `formwork learn -- <cmd>`, and asserts no cause;
the macOS settling case adds one line pointing at `explain --session`. Entries say "denied", not
nono's "may be due to": each is a kernel or Formwork refusal, not an inference.

### 3.6 `explain` matches the run

One pure function, `launcher_denies`, returns every deny `run` adds before compile: the
[FW-CRED3](../formwork.md#fw-cred3) env-file references, read from an environment snapshot passed
in; the policy-input write-subtracts ([FW-XR8](../formwork.md#fw-xr8)); the Launcher-owned
directories under the temporary root ([FW-TRA9](../formwork.md#fw-tra9)), modelled by their parent;
and the record directory (`FW-INV19`). `prepare_session` and `explain` both call it with the
snapshot the CLI captures once at its edge, and the provenance side table tags each deny with a new
origin, `launcher`. On a Linux host `explain` then asks `splitting_hole(writes, holes, dir)`, the
predicate the expansion uses, moved from `Hole::strictly_under` (`landlock.rs:107-115`) into
`formwork-compile` so the Confiner and `explain` share one definition. For a path whose parent is
split, `explain --json` carries `split: {dir, hole, source}` and the prose says existing entries keep
their grants and new ones cannot be created. `announce_split_root` uses the same predicate, names
every split directory, and no longer recommends `.formwork/` on Linux. This FEP reports splits; it
does not remove them (§9).

### 3.7 From a record to a proposal

`formwork learn --session <id|last>` reads a record (checks: `FW-DISC14`), converts `fs` lines into
`DenialRecord`s (`create` and `remove` as write, `exec` as read, as the existing parsers do,
`learn.rs:140-163, 582-628`), `egress` lines into `EgressObservation`s and `socket`/`channel` lines
into channels, then runs the feed-agnostic half of `conclude_learning_run` (`learn.rs:634-787`)
with the session id as the run id. Lines whose deciding rule is in the `launcher` layer are
withheld with their remedy: a proposal cannot undo [FW-XR8](../formwork.md#fw-xr8), and a split is
not fixed by a grant. `reverse_compile` re-applies the credential floor whatever the line's `floor`
says ([FW-DISC3](../formwork.md#fw-disc3)). Candidates in the auto-widen zone reach the discovered
layer for the next run ([FW-DISC4](../formwork.md#fw-disc4)); nothing reaches a running session
([FW-INV10](../formwork.md#fw-inv10)). `learn -- cmd` keeps its feeds; in Phase 3 its observing run
writes a session record and concludes through this path.

### 3.8 Querying from inside a session

A confined process may run `formwork explain` against what it can already read: the blueprint
file and the compiled-in catalog, which is public. `explain` performs no filesystem access on the
path it is asked about, so its answer does not depend on whether a floored path exists. A confined
process may not read session records, its own included (`FW-INV19`); `explain --session` inside a
session fails with the same refusal whether or not records exist. The record holds operator-channel
material: credential types ([FW-CRED7](../formwork.md#fw-cred7)), deciding rules that
[FW-FID9](../formwork.md#fw-fid9) keeps from the confined process, withheld itemizations, denials of
other session members (stdio MCP backends are members), and other projects' paths from earlier
sessions. Residuals: in-session `explain` cannot see [FW-CRED3](../formwork.md#fw-cred3) references,
whose variables are stripped, and under-reports them; on Linux `stat` of a record path answers
([FW-CAP7](../formwork.md#fw-cap7)'s residual), with 64 random bits in each name. A host that wants
its agent to see the account relays it out of band, the host-offered action
[FW-XR8](../formwork.md#fw-xr8) allows.

### 3.9 Report line and asymmetries that remain

| Host | `denial-record` | Reason |
|---|---|---|
| Linux, ABI ≥ 7, audit readable | `Enforced` | every denial of the session's domain is recorded or counted in `fs-lost` |
| Linux otherwise | `Unenforceable` | names the gap (ABI, audit disabled, `CAP_AUDIT_READ`) and `formwork learn` |
| macOS | `Partial` | records persisting after **settle-budget** are added by `explain --session` |
| any, `run --confine-self` | `Unenforceable` | no Launcher remains; no record |

Non-filesystem refusals are recorded on every host that serves them, because Formwork makes them.

| Property | Linux | macOS | Why |
|---|---|---|---|
| Filesystem feed | Landlock audit, privileged | unified log, unprivileged | kernel interfaces |
| Latency | as the kernel emits each record | stream, or post-hoc by tag | Seatbelt has no notification channel |
| Completeness signal | `denials=N` at deallocation | none | Landlock counts per domain |
| `create` target | the directory checked | the new path | each backend's record |
| Split directories | yes, under write-protection inside a write grant | no | Landlock has no deny rule |

---

## 4. Surface changes (each measured against Growth)

- **CLI: `--session <id|last>` on `explain` and on `learn`.** Searched first: `explain`'s
  positional arguments are typed by shape and a bare relative name resolves as a path
  (`main.rs:164-167`), so an id or `last` would collide with a file of that name; `learn --list`,
  `--accept` and `--proposal` operate on a proposal, not a record. No `why`, `audit` or `session`
  subcommand, and no flag to silence the account or disable the record (§9).
- **Report key `denial-record`** (`Capability::DenialRecord`, appended per `report.rs:12-14`). No
  existing key reports observation; [FW-FID8](../formwork.md#fw-fid8) lines report enforcement.
- **HostProfile `denial-feed`: `{ fs: "landlock-audit" | "unified-log" | "none", gap? }`.** The
  usability review's P3 asked for exactly this line (`docs/usability-review.md:53-56`); FEP-4's
  `trace-feed` is the open-feed sibling. `render::host_summary` already prints the `learn` feed in
  prose (`render.rs:14-43`); this makes it data.
- **`explain --json`**: an optional `split` object per explanation and the origin `launcher` in
  `RuleSource`. Additive.
- **The session record, format 1, and its directory**: a new Data-model surface (§7 j).
- **Types**: `RecordError` and `LauncherError` variants in `formwork-blueprint` are API surface.
- **Blueprint schema, profiles, Catalog**: unchanged. **Dependencies**: none; the netlink reader
  uses `libc`, ids are epoch-based so no date crate is needed.

---

## 5. Proposed requirements (draft numbering — anchored on landing)

| Req | Requirement |
|---|---|
| `FW-FID16` **Session record** | For every `formwork run` in the spawn posture, the Launcher shall create the session record of §3.4 (file 0600 in a 0700 directory) before it spawns the workload, write only lines of the format-1 kinds with exactly their keys, append a line for each Gateway violation, connect-supervisor socket refusal and opener-shim refusal of the session within **append-latency** (1 s) of the refusal, and append no entry line beyond **record-entries** (1,024) distinct entries or **record-bytes** (256 KiB). |
| `FW-FID17` **Record exclusions** | The session record and the end-of-run account shall contain no environment-variable value, no command argument other than the program, no HTTP header value, body byte or query string, no opener URL path, no placeholder or brokered credential byte, and no inode or device number. |
| `FW-FID18` **Filesystem denial feed in `run`** | Where the HostProfile reports a filesystem denial feed, `formwork run` shall append one `fs` line per distinct access and path the feed attributes to the session (Linux: Landlock audit records of the domain the session's child created; macOS: unified-log Sandbox records carrying the session's deny tag) within **append-latency** of the feed delivering it to Formwork. |
| `FW-FID19` **Audit logging only when consumed** | On Linux, the Confiner shall request Landlock logging after `execve` (`LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`) for a session exactly when the Launcher holds an open audit reader for that session. |
| `FW-FID20` **Denial-record report line** | The FidelityReport shall carry a `denial-record` line that is `Enforced` only where every filesystem denial the session's policy causes is recorded or counted in the record's `fs-lost`, `Partial` with the reason where records can persist after **settle-budget**, and `Unenforceable` naming the missing precondition and `formwork learn` where no filesystem feed exists. |
| `FW-FID21` **End-of-run account** | After the workload exits and before it exits itself, `formwork run` shall write to stderr, and to no other stream, an account of at most **account-lines** (10) entries plus 4 lines exactly when the session recorded a denial or exited non-zero under a `denial-record` verdict other than `Enforced`; each entry names the access, target, deciding rule and layer, and the `explain` invocation or lift that addresses it, and the account names the record path and the `learn --session` invocation. |
| `FW-FID22` **Explain matches the run** | For each path, `formwork explain` shall report the verdict `formwork run` from the same directory and environment would enforce on the current host: it shall apply every session-only deny of §3.6 with the origin `launcher` and, on a Linux host, report a path whose parent directory the Landlock expansion splits as not creatable, naming the directory and a hole that splits it. |
| `FW-FID23` **Session query** | `formwork explain --session <id\|last>` shall print every denial of the named record with the rule and layer recorded for it, including denials the host feed attributes to the session after it ended, and report a record without an `end` line as interrupted; with `--json` it shall print the lines in the record's own shape. |
| `FW-FID24` **Record retention** | At each session start, the Launcher shall delete each regular file in the record directory whose name is a session id older than **record-age** (30 days), then the oldest such files beyond the newest **record-sessions** (200), excluding the current session's record and never following a symbolic link. |
| `FW-DISC13` **Proposal from a session record** | `formwork learn --session <id\|last>` shall reverse-compile the record's `fs`, `egress`, `socket` and `channel` lines into the blueprint's proposal under [FW-DISC2](../formwork.md#fw-disc2)–[FW-DISC4](../formwork.md#fw-disc4) and [FW-DISC12](../formwork.md#fw-disc12), with the session id as the run id, without spawning a workload, withholding and itemizing every line whose deciding rule is in the `launcher` layer. |
| `FW-DISC14` **Record as untrusted input** | `learn --session` and `explain --session` shall refuse a record whose name is not a session id, that is not a regular file directly in the record directory, whose `format` they do not know, or (for `learn`) whose header names a blueprint other than the one resolved. |

Invariant:

| Inv | Invariant |
|---|---|
| `FW-INV19` **Record isolation** | No confined process, in any posture, can read the contents of, list, create, modify, rename or delete an entry of the session-record directory, its own session's record included. The Launcher subtracts the directory from every blueprint, and deny is terminal ([FW-CAP8](../formwork.md#fw-cap8)). |

---

## 6. Verification plan

FEP-5 §6.1's rules hold: control run first, a positive assertion of each denial, fixtures that are
subprocesses. Every Linux filesystem-feed test runs on a new `linux-audit` CI job: a Lima VM with a
6.15+ kernel, audit enabled in setup (`auditctl -e 1`), the harness as root, and `setpriv` for the
unprivileged arms. Every gated test names its gate through `support::not_exercised` or
`require_exercised`, which fail under `FW_REQUIRE_EXERCISED=1` (§6.3.4).

### 6.1 End-to-end tests (draft)

- `FW-E2E-133` **A millisecond denial reaches the account and the record (both).** Under
  `extends = ["builtin:default"]`, `rules = ["readwrite:$CWD/**", "deny:$CWD/secret/**"]`, the
  workload is `sh -c 'cat ok.txt && cat secret/a.env'`, which dies on its first denial in about a
  millisecond. Linux on `linux-audit`; py harness. **Pass:** exit 1; stdout is `ok.txt`'s bytes only;
  stderr's account names `read`, `secret/a.env`, `deny:$CWD/secret/**` and layer `file`; the record
  holds that one `fs` line, none for `ok.txt`, and `end.exit.code == 1`; on macOS, if the account
  carries the settling line instead, `explain --session last` lists the denial within 30 s.
  **Fail:** the denial is in neither; the granted read is recorded; any Formwork byte on stdout.
  From nono's test_audit.sh:71-111 (a record for zero and non-zero exits) and troubleshooting.mdx:353-364.
- `FW-E2E-134` **Nothing denied, nothing said (both).** `readwrite:$CWD/**`; the workload prints
  `out` to stdout, `err` to stderr and exits 0, then a second run exits 3; `RUST_LOG=warn`; py.
  **Pass:** stdout is `out\n` and stderr exactly `err\n` in both runs (where the verdict is not
  `Enforced`, macOS and Linux without audit, the exit-3 run adds exactly the one gap or settling line), exit codes 0 and 3, each record has zero entry lines
  and `end.denials == 0`. **Fail:** any other Formwork byte on either stream. From nono's
  test_silent_output.sh:71-73 and formatter.rs:3518.
- `FW-E2E-135` **Explain matches the run in a split project root (Linux; macOS parity).** Regression
  for §1's verified finding. `FORMWORK.toml` in the project with `extends = ["builtin:default"]`,
  `rules = ["readwrite:$CWD/**"]` and an existing `notes.txt`; py. **Pass on Linux:**
  `explain --json $CWD/new.txt` carries `split.dir == $CWD` with origin `launcher`; `run -- touch
  new.txt` exits non-zero, `new.txt` is absent and the account lists `create` in `$CWD` as
  `launcher`; `run -- sh -c 'echo x >> notes.txt'` succeeds and `explain` says write granted with no
  `split`; the same holds with the blueprint at `.formwork/blueprint.toml`; with `--blueprint` naming
  a file outside the project, `explain` reports no split and `touch` succeeds. **Pass on macOS:** no
  `split` key and `touch` succeeds in every layout. **Fail:** any `explain` verdict that the paired
  `run` contradicts. From nono's why_deny.rs:36 (#1556).
- `FW-E2E-136` **Launcher-only denies are explained (both).** `GOOGLE_APPLICATION_CREDENTIALS`
  names an existing `$HOME/srv/gcp.json` for both commands; `rules = ["read:$HOME/srv/**"]`; py.
  **Pass:** `explain` reports `$HOME/srv/gcp.json` read denied with origin `launcher` and `run --
  cat` of it fails with `EACCES`, listed as `launcher` in the account; `$HOME/srv/other.json` is
  granted by `file` in `explain` and readable in `run`; `explain` of the record directory reports
  read and write denied, origin `launcher`. **Fail:** any verdict differs from the run. From nono's
  test_policy_queries.sh:30-49.
- `FW-E2E-137` **Session query (both).** After an `FW-E2E-133` run; py. **Pass:** `explain --session
  last` and `explain --session <id from the account>` print the denial with the recorded rule;
  `--json` lines have exactly the format-1 keys; an absent id exits non-zero naming the directory;
  after the harness appends a half line to a copy, that record prints "interrupted" and its complete
  lines; a record with a damaged middle line exits non-zero. **Fail:** any of these differs. From
  nono's test_audit.sh:256-266 and audit_event_reader.rs:290-337.
- `FW-E2E-138` **From a record to a proposal, with no run (both).** `mode = "unveil"`,
  `rules = ["readwrite:$CWD/**"]`; the workload reads `~/data/in.csv` and `~/.aws/credentials`
  (both present) and writes `FORMWORK.toml`; then `learn --session last`; py. **Pass:** the proposal
  holds a read candidate for `~/data/in.csv` with run id equal to the session id; the credential is
  itemized as withheld (`aws`) on stderr and absent from the proposal; the `FORMWORK.toml` write is
  withheld as `launcher`; `learn --session` creates no record and spawns nothing; the original run's
  read of `in.csv` failed; after `learn --accept 1` a new run reads it. **Fail:** a credential or
  launcher line is proposed, or the first run read `in.csv`. From nono's troubleshooting.mdx:339-369,
  with profile_save_runtime.rs:2066 designed out.
- `FW-E2E-139` **Refusals beyond the filesystem (both).** Under `rules = ["allow:allowed.test"]`
  with `support::TlsFixture`, the workload requests `blocked.test`, connects to an out-of-session
  pathname socket (Linux), and opens `https://evil.test/p` with `open-url` unlifted;
  `crates/formwork-cli/tests/session_record.rs`. **Pass:** the record holds
  `egress{reason: host-not-listed, host: blocked.test}`, `socket` (Linux) and
  `channel{channel: open-url, scheme: https, host: evil.test}`, and the account lists them.
  **Fail:** one is missing or appears only as a log line.
- `FW-E2E-140` **Nothing secret in the record (both).** One nonce appears in an argument, an
  environment variable, a query string, a request header and an inline brokered credential
  ([FW-BP12](../formwork.md#fw-bp12)) bound to `allowed.test`, and the run includes a denied read
  and a refused request; `session_record.rs`. **Pass:** the nonce occurs in no byte under the record
  directory and in no stderr byte; no line has an `ino` or `dev` key; `session.program` is the
  program alone. **Fail:** any occurrence. From nono's audit.rs:1615 (redaction there; absence here).
- `FW-E2E-141` **The report line matches the record (both).** Arms: `linux-audit` as root; the same
  host as an unprivileged user; macOS; `run --confine-self` on each; a state directory set 0500
  (unprivileged). py. **Pass:** root reports `Enforced`, a denial yields an `fs` line and `end.fs-complete == true`;
  unprivileged reports `Unenforceable` with the `CAP_AUDIT_READ` gap, its non-zero run prints the one
  gap line, and egress lines are still recorded; macOS reports `Partial`; `--confine-self` writes no
  record; the 0500 arm runs, keeps exit codes 0 and 7, and prints one line naming the directory.
  **Fail:** a verdict claims more than its record shows, or an exit code changes. From nono's
  test_audit.sh:235-245, with tests/audit_ledger.rs:47 designed out (#1804).
- `FW-E2E-142` **Audit logging only when consumed (Linux).** A root watcher on the audit multicast
  group; `session_record.rs` on `linux-audit`. **Pass:** an unprivileged `formwork run` whose
  workload is denied a read produces no `LANDLOCK_ACCESS` record after `execve` for the domain its
  child created; the same run as root produces them. **Fail:** the unprivileged run adds records.
- `FW-E2E-143` **Retention and caps (both).** The state directory holds 205 records (10 started 31
  days ago), `notes.txt`, and a session-id-named symbolic link to a file outside it; one run, then a
  run whose workload is denied 1,100 distinct paths; py. **Pass:** after the first run at most 200
  records remain, none older than 30 days, the current record among them, `notes.txt` and the link
  target unchanged; the second record holds at most 1,024 `fs` lines in at most 256 KiB, with
  `end.distinct + end.dropped == 1100`, and its account ends "and 1,090 more". **Fail:** any bound exceeded, an old record kept, or a
  non-record file touched. From nono's audit_commands.rs:1316, with audit.mdx:323-341 designed out.
- `FW-E2E-144` **A consumable record within the run (both; supersedes
  [FW-E2E-040](fep-1.md#fw-e2e-040)).** Under `allow:allowed.test`, the workload is denied a read,
  reads a granted file, requests `blocked.test`, then sleeps 5 s; the harness tails the one record
  in an isolated state directory; py. **Pass:** the egress line, and on `linux-audit` the `fs` line,
  appear within 1 s of the refusal while the workload sleeps; on macOS the `fs` line appears before
  exit or the account carries the settling line; no line names the granted read. **Fail:** a denial
  surfaces only after exit where the feed is `Enforced`, or a grant is recorded as a denial.

### 6.2 Adversarial tests (draft)

- `FW-ADV-036` **Record isolation (both).** Property: no process in a session reaches the record
  directory. Probe class: every filesystem operation family on the directory, on the session's own
  record (its path passed in from outside), on another session's record, and through a symbolic
  link planted in a writable directory; under `builtin:default`, under a blueprint granting
  `readwrite:~/**` and `readwrite:` of the state directory itself, under `run --confine-self`, and
  from a nested `formwork run`. **Pass:** every attempt is denied, every record hashes the same
  before and after (hashed outside the session), and the session's own record ends with an `end`
  line. **Fail:** any byte read, listed or changed. py. Derived from nono's protected_paths.rs:1-40
  and audit_session.rs:601.
- `FW-ADV-037` **Workload output is not evidence (both).** Property: nothing the workload writes
  becomes an entry or a candidate. Probe class: refusal-shaped lines on stdout and stderr naming a
  credential path and a path outside every grant that the workload never opens; a forged record file
  in its writable project; a flood of 5,000 distinct denials after one denial of interest; then the
  operator runs `learn --session last` and `learn --session` on the forged file. **Pass:** no line
  names a printed path; the forged file is refused (`FW-DISC14`); the first denial is in the record,
  `end.dropped > 0` and the account says so; the proposal holds none of the printed paths. **Fail:**
  any printed path is recorded or proposed. py. Designs out nono's formatter.rs:147-258 with
  exec_strategy.rs:1961-1975.
- `FW-ADV-038` **No oracle through diagnostics (both).** Property: the confined process learns
  nothing from Formwork's diagnostic surfaces that separates an existing floored path from an absent
  one, and reaches no operator-channel material. Probe class: in-session `formwork explain
  ~/.aws/credentials` and `explain --session last` with and without the file present, and the errno
  of a read of it. **Pass:** each output is byte-identical across the two states; `--session` is
  refused identically; the type name appears only in the operator-side account and record.
  **Fail:** any difference. py. Extends [FW-ADV-012](../formwork.md#fw-adv-012); designs out nono's
  why_deny.rs:70 and sandbox_state.rs:1-5.

### 6.3 Unit and property tests

#### 6.3.1 Where the tests live

| Path | Layer and why |
|---|---|
| `crates/formwork-blueprint/src/record.rs` `#[cfg(test)] mod tests` | pure: record types, ids, bounds, parser, prune plan; strings only |
| `crates/formwork-blueprint/src/launcher.rs` `mod tests` (extended) | pure: `launcher_denies` with the environment as data; provenance with the `launcher` origin |
| `crates/formwork-compile/src/linux.rs` and `lib.rs` `mod tests` | pure: `splitting_hole`; the `denial-record` line from a synthesized HostProfile (the one allowed substitution, constitution Testing) |
| `crates/formwork-cli/src/feed.rs` and `render.rs` `mod tests` | parse edge: audit and unified-log text into typed lines; the account as typed lines before rendering |
| `crates/formwork-confine/tests/linux_audit.rs` (new) | kernel: confined children against Landlock ABI 7 audit, never mocked; characterization L1–L5 |
| `crates/formwork-cli/tests/session_record.rs` (new) | CLI shell with `tests/support/mod.rs`: `FW-E2E-139`, 140, 142 |
| `py/harness/test_session_record.py` (new) | black box: the other E2E and ADV tests, `@pytest.mark.fw_e2e`/`fw_adv` plus `linux`/`macos` |

#### 6.3.2 The test list

`record.rs` — nono's audit_session.rs, audit_event_reader.rs and audit_ledger.rs carry 20 tests
between them; this module plans 14, because ledger and digest tests have no counterpart here.

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `session_id_round_trips_its_canonical_form` | `FW-DISC14` | — | `"1791391353-3f9a0c12d4e5b678"` → `SessionId::parse` → `Ok`, `to_string()` equal | audit_ledger.rs:210 `ledger_rejects_malformed_session_id` |
| `session_id_rejects_traversal_and_malformed_names` | `FW-DISC14` | — | `""`, `"../x"`, uppercase hex, 15 hex, `"last"` → `parse` → each `Err(RecordError::BadSessionId { .. })` | audit_session.rs:587 `session_dir_rejects_a_traversing_id` |
| `state_dir_prefers_an_absolute_xdg_state_home` | `FW-FID16` | — | `state_dir(Some("/s"), Some("/h"))` → `/s/formwork/sessions`; `Some("rel")` → `/h/.local/state/…`; `(None, None)` → `Err(RecordError::NoStateDir)` | audit_session.rs:374 (env as data, not `EnvVarGuard`) |
| `book_appends_once_per_distinct_entry` | `FW-FID16` | `fs_line`, `limits` | admit one `fs` line twice → `Admit::Append`, `Admit::Repeat`; `end()` → `denials == 2`, `distinct == 1` | formatter.rs:4390 `test_supervised_deduplicates_paths` |
| `book_stops_at_record_entries` | `FW-FID16` | `limits(3, usize::MAX)` | admit 2, 3, 4 distinct → `Append`×3 then `Dropped`; `end().dropped == 1` | audit.rs:1936 `summary_bounds_distinct_commands` |
| `book_stops_at_record_bytes` | `FW-FID16` | `limits(usize::MAX, header + 2 lines)` | third line → `Dropped`; serialized size ≤ limit | sandbox_log.rs:21 (cap there is silent) |
| `lines_have_exactly_the_format_1_keys` | `FW-FID16` | `sample_lines()` | serialize each kind → key `BTreeSet` == the §3.4 list | schema_shape.rs:19 `assert_properties_at` |
| `lines_match_the_golden_fixture` | `FW-FID16` | `tests/fixtures/session-record-v1.jsonl` | fixed-time lines → `to_string` → byte-equal to the fixture, line per kind | audit.rs:2292 `audit_event_payload_golden_vectors` |
| `half_written_final_line_is_interrupted_not_counted` | `FW-FID23` | `record_text` | header, `fs`, `{"kind":"fs","t-ms":` → `parse_record` → `interrupted == true`, 2 lines | audit_event_reader.rs:290 |
| `damage_before_the_final_line_is_an_error` | `FW-FID23` | `record_text` | corrupt line 2 of 4 → `Err(RecordError::Malformed { line: 2 })` | audit_event_reader.rs:315 |
| `unknown_format_is_refused` | `FW-DISC14` | `record_text` | header `format: 2` → `Err(RecordError::UnknownFormat { format: 2 })` | why_runtime.rs:959 (#1554) |
| `prune_plan_removes_records_older_than_record_age` | `FW-FID24` | `id_at` | ages 31 d, 29 d, 0 d → `prune_plan` → only the 31-day id | audit_commands.rs:1316 |
| `prune_plan_keeps_the_newest_record_sessions` | `FW-FID24` | `id_at` | 199, 200, 201 records → plan lengths 0, 0, 1; the removed one is oldest | audit_commands.rs:1324 |
| `prune_plan_skips_non_ids_links_and_the_current_session` | `FW-FID24` | `id_at` | `notes.txt`, `<id>.jsonl.tmp`, a symlink named `<id>.jsonl`, the current id oldest and over count → none planned | audit_session.rs:601 `session_dir_rejects_a_symlink_out_of_the_audit_root` |

`launcher.rs` and provenance — nono's why_runtime.rs carries 30, most for network and command
policy, which `explain`'s existing tests and [FW-E2E-059](../formwork.md#fw-e2e-059)-class probes cover; this plans 7.

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `env_file_reference_is_denied_from_the_given_environment` | `FW-FID22` | `inputs` | env `GOOGLE_APPLICATION_CREDENTIALS=/srv/gcp.json` → `launcher_denies` → one subtract, `LauncherReason::EnvFileRef`; with `allow = ["gcp"]` → none | why_runtime.rs:1004 |
| `relative_env_file_reference_resolves_against_cwd` | `FW-FID22` | `inputs` | value `creds.json`, cwd `/w` → pattern `/w/creds.json` | formatter.rs:3146 |
| `non_utf8_env_file_reference_fails_loud` | `FW-FID22` | `inputs` | `OsString` from invalid UTF-8 → `Err(LauncherError::NotRenderable { .. })` | audit_ledger.rs:358 |
| `policy_inputs_are_write_subtracted` | `FW-FID22` | `inputs` | blueprint `/w/p/FORMWORK.toml` → three write-subtracts, `LauncherReason::PolicyInput` | — |
| `record_directory_is_subtracted_read_and_write` | `FW-INV19` | `inputs` | state dir → one subtree subtract, `LauncherReason::RecordDir`; nothing else under `/h/.local/state` | protected_paths.rs:34-40 |
| `launcher_deny_wins_over_a_covering_file_grant` | `FW-FID22` | `inputs` | `readwrite:/w/p/**` → `explain(/w/p/FORMWORK.toml).write` → `Verdict::Denied { source: RuleSource::Launcher, .. }`; read `Granted` from `File` | why_deny.rs:36 (#1556) |
| `path_without_a_launcher_deny_keeps_the_model_verdict` | `FW-FID22` | `inputs` | `/w/p/src/main.rs` → write `Granted` from `File` | why_runtime.rs:1218 |

`formwork-compile` — plans 8; nono has no split-directory test, and its `why_deny.rs` regression
runs on macOS only (why_deny.rs:6).

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `policy_input_hole_splits_the_project_root` | `FW-FID22` | `pp` | §6.3.5 | why_deny.rs:36 |
| `launcher_dir_splits_the_temp_root` | `FW-FID22` | `pp` | writes `/tmp/**`, hole `/tmp/fw-s-opener/**` → `splitting_hole(…, /tmp)` → `Some` | — |
| `directory_outside_write_grants_is_never_split` | `FW-FID22` | `pp` | dir `/w` → `None` | why_runtime.rs:1218 |
| `expansion_and_explain_share_the_predicate` | `FW-FID22` | `pp` | 6 (writes, holes, dir) triples → `splitting_hole` agrees with the expansion's split set | — |
| `denial_record_is_enforced_with_a_readable_audit_feed` | `FW-FID20` | `linux_host(DenialFeed::LandlockAudit)` | `compile` → `per_capability[DenialRecord]` is `Fidelity::Enforced { .. }` | — |
| `denial_record_is_partial_on_macos` | `FW-FID20` | `macos_host()` | → `Fidelity::Partial { .. }` | — |
| `denial_record_is_unenforceable_below_abi_7` | `FW-FID20` | `linux_host(DenialFeed::None { gap: FeedGap::AbiBelow7 })` | → `Fidelity::Unenforceable { .. }` | — |
| `denial_record_line_is_byte_deterministic` | [FW-FID4](../formwork.md#fw-fid4) | `linux_host` | compile twice → equal JSON bytes | — |

`feed.rs` and `render.rs` — nono's sandbox_log.rs carries 11 and formatter.rs 92, most of the
latter for terminal-output heuristics, exit-code stories and approval modes this FEP declines; this
plans 15.

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `parses_a_landlock_access_record` | `FW-FID18` | `ACCESS_LINE` | `domain=1a6fdc66f blockers=fs.read_file path="/w/a.env" dev="vda2" ino=351` → `LandlockAccess { domain, access: Read, path }`; the type has no `ino` field | sandbox_log.rs:451 |
| `maps_landlock_blockers_to_record_access` | `FW-FID18` | — | each §3.3 blocker → its access; `net.connect_tcp` → `None` | sandbox_log.rs:459 |
| `decodes_hex_encoded_audit_paths` | `FW-FID18` | — | `path=2F772F6120622E747874` → `/w/a b.txt` | formatter.rs:3008 |
| `attributes_by_the_domain_the_session_child_created` | `FW-FID18` | `domain_line` | allocated pid 4242, child 4242 → kept; pid 999 → dropped | sandbox_log.rs:505, 538 |
| `holds_access_records_until_their_domain_record` | `FW-FID18` | `domain_line` | access then allocated → one line, after the domain record | — |
| `deallocation_count_reports_lost_records` | `FW-FID20` | `domain_line` | 3 seen, `denials=5` → `fs-lost: 2`, `fs-complete: false`; `denials=3` → 0, `true` | — |
| `unified_log_keeps_only_the_session_tag` | `FW-FID18` | existing | moved from `learn.rs:1165` | sandbox_log.rs:528 (name match, designed out) |
| `workload_text_is_never_parsed_as_a_denial` | `FW-ADV-037` | — | `cat: /w/x: Permission denied` → both feed parsers → `None` | formatter.rs:2991 (designed out) |
| `egress_violation_maps_to_a_line_without_prose` | `FW-FID17` | `Violation` literal | `detail` and `explain` set → line keys exactly the §3.4 `egress` set | — |
| `opener_refusal_keeps_scheme_and_host_only` | `FW-FID17` | — | `https://evil.test/p/a?token=n0nce` → `scheme: https`, `host: evil.test`; JSON lacks `n0nce` and `/p/a` | audit.rs:1615 |
| `account_is_empty_for_a_clean_session` | `FW-FID21` | `account_input` | 0 entries, exit 0, `Enforced` → `account()` → empty `Vec<AccountLine>` | formatter.rs:3518 |
| `account_lists_account_lines_entries_then_folds` | `FW-FID21` | `account_input` | 10, 11, 15 entries → 10 `Denied` + `More { n: 0, 1, 5 }`; total ≤ 14 | formatter.rs:4455 |
| `account_states_the_gap_only_on_a_failed_run` | `FW-FID21` | `account_input` | 0 entries, `Unenforceable`: exit 1 → one `NoFeed { gap }`; exit 0 → empty | formatter.rs:2811 |
| `floor_entry_carries_its_lift_not_a_grant` | `FW-FID21` | `account_input` | `floor: aws` → `Denied { lift: Some(Lift::AllowCredential("aws")), .. }`, no `LearnHint` for it | profile_save_runtime.rs:2066 (designed out) |
| `record_failure_never_changes_the_exit_status` | [FW-XR10](../formwork.md#fw-xr10) | — | `final_exit(0, Err(..))` → 0; `final_exit(7, Err(..))` → 7 | exec_strategy.rs:5002 (#1804) |

`linux_audit.rs` (kernel; gate: `not_exercised("Landlock ABI < 7 or no CAP_AUDIT_READ")`):
`l1_post_exec_denial_is_logged_with_new_exec_on` (`FW-FID18`: one `LANDLOCK_ACCESS` naming the
secret path, its domain created by the child; the paired granted read logs nothing),
`l2_post_exec_denial_is_silent_without_new_exec` (`FW-FID19`), `l3_deallocation_counts_denials`
(`FW-FID20`: three denials → `denials=3` within **settle-budget**),
`l4_workload_domain_denial_names_the_workload_domain` (`FW-FID20`'s reason), and
`l5_detect_matches_the_reader` (`FW-FID20`: `denial-feed` is `landlock-audit` exactly when
`AuditReader::open` succeeds). Each compiles with `SessionSpec { audit: true, .. }` (false
for L2) and spawns through `formwork_confine::spawn_confined` (`linux_confine.rs:60-64`). `session_record.rs` holds `egress_socket_and_opener_refusals_are_recorded`
(`FW-E2E-139`), `no_nonce_reaches_the_record_or_stderr` (`FW-E2E-140`) and
`unprivileged_run_adds_no_audit_records` (`FW-E2E-142`).

#### 6.3.3 Fixtures and helpers to add

- `record.rs` tests: `fn limits(entries: usize, bytes: usize) -> RecordLimits`;
  `fn fs_line(path: &str, access: RecordAccess) -> RecordLine`; `fn id_at(secs: u64) -> SessionId`
  (nonce `0123456789abcdef`); `fn record_text(lines: &[&str]) -> String`;
  `fn sample_lines() -> Vec<RecordLine>` (one per kind, fixed times, the fixture's source).
- `launcher.rs` tests: `fn inputs<'a>(blueprint: &'a str, env: &'a [(OsString, OsString)]) ->
  LauncherInputs<'a>` with cwd `/w`, state dir `/h/.local/state/formwork/sessions` and
  `ResolvedCatalog::builtin_for_home("/h")` (nono's `active_git_config` builder shape).
- `formwork-compile` tests: `fn pp(s: &str) -> PathPattern`; `fn linux_host(feed: DenialFeed) ->
  HostProfile` (ABI 7); `fn macos_host() -> HostProfile`.
- `feed.rs`/`render.rs` tests: `const ACCESS_LINE: &str`; `fn domain_line(domain: &str, status:
  &str, pid: u32) -> String`; `fn account_input(entries: usize, exit: i32, verdict: Fidelity) ->
  AccountInput`.
- `crates/formwork-cli/tests/support/mod.rs` gains `pub struct Isolated { pub home: PathBuf,
  pub state: PathBuf, pub project: PathBuf, _scratch: Scratch }` with `Isolated::new(tag)`,
  `fn record(&self) -> Vec<serde_json::Value>` (the one record in `state`), and
  `pub fn formwork_in(iso: &Isolated, args: &[&str], env: &[(&str, &str)]) -> Output` setting `HOME`,
  `XDG_STATE_HOME` and the project as cwd; plus `pub fn audit_feed_host(dir: &Path) -> bool`. State
  is a sibling of home, as in nono's `NonoTest` (crates/nono-test-support/src/lib.rs:48-52), so a test
  granting `readwrite:~/**` exercises the record subtract only when it means to. The root stays
  `std::env::temp_dir()`: nono relocates to `target/test-artifacts` because a FUSE bind mount accepts
  Landlock grants without enforcing them (lib.rs:32-37); Formwork's scratch is never on the bind-mounted
  checkout, and `FW-E2E-135`'s paired `run` arm would fail if it were.
- `crates/formwork-confine/tests/support/mod.rs` (new): `not_exercised` with the CLI body, and
  `pub struct AuditCapture` over the product's `AuditReader`, with `fn records_for(&self, child:
  u32, within: Duration) -> Vec<String>`.
- `py/harness/helpers.py`: `require_exercised(reason)` (fails under `FW_REQUIRE_EXERCISED=1`, else
  skips), `Isolated(home, state, project)` with `.env()`, and `read_record(state) -> list[dict]`;
  `conftest.py` gains the `isolated` fixture.

#### 6.3.4 Patterns adopted from nono, and the ones designed out

1. **Kernel calls in a spawned child.** `linux_audit.rs` never calls `restrict_self` in the test
   process; it spawns through the Confiner and asserts the child's status, as nono's
   sandbox/linux.rs:5993-6030 and Formwork's `linux_confine.rs:60-64` do.
2. **Silent capability gating, designed out.** nono returns early when the kernel lacks a feature
   (sandbox/linux.rs:5994-6003), and `linux_confine.rs:114-118` does the same. Every test here gates through
   `not_exercised` or `require_exercised`; the `linux-audit` and macOS jobs set
   `FW_REQUIRE_EXERCISED=1`.
3. **No environment mutation.** nono serializes on `ENV_LOCK` and `EnvVarGuard`
   (crates/nono-cli/src/test_env.rs:5-30). `state_dir` and `launcher_denies` take the environment as
   parameters, and `env_file_ref_denies` (`blueprint_load.rs:788-826`) moves behind
   `launcher_denies`, so no unit test sets a variable.
4. **Contract shapes.** Exact key sets and golden fixtures: `crates/formwork-blueprint/tests/fixtures/
   session-record-v1.jsonl` (one line per kind) and `crates/formwork-compile/tests/fixtures/
   denial-record-report-v1.json` (the report key and the HostProfile field), each with a byte-equality
   test and, for the report, [FW-FID4](../formwork.md#fw-fid4) determinism.
5. **Property tests: an example stand-in.** The property is: for every sequence of 0–5,000 admits
   over 0–2,000 distinct keys, `distinct ≤ record-entries`, `distinct + dropped == keys` and
   `denials == admits`; strategy: a key-index vector; 64 cases (nono's `with_cases(64)`,
   manifest_roundtrip.rs:867). No requirement here names a property method, so the boundary examples
   stand in and no exception is registered; the property lands with the owed fuzz infrastructure.
6. **Regression names.** `policy_input_hole_splits_the_project_root` cites §1's verified finding;
   `launcher_deny_wins_over_a_covering_file_grant` cites nono #1556; `unknown_format_is_refused`
   cites #1554; `record_failure_never_changes_the_exit_status` cites #1804.
7. **Shell suites, designed out.** nono's `expect_*` helpers and `require_working_sandbox`
   (tests/lib/test_helpers.sh:78-170, 322) become pytest: test_audit.sh Tests 1 and 3 map to
   `FW-E2E-133`, Test 9 to `FW-E2E-141` and Test 10 to `FW-E2E-137`; test_policy_queries.sh:30-49 to `FW-E2E-136`; test_silent_output.sh:71
   to `FW-E2E-134`.

#### 6.3.5 Worked example

```rust
// crates/formwork-compile/src/linux.rs, #[cfg(test)] mod tests
use std::path::Path;

use formwork_blueprint::PathPattern;

use super::splitting_hole;

fn pp(s: &str) -> PathPattern {
    PathPattern::parse(s).expect("test patterns are absolute")
}

/// Regression for the finding FEP-9 §1 reproduced on Linux 6.18 (Landlock ABI 7): a
/// write-protected policy input splits every ancestor inside the write grant, so `explain` must
/// report a create in the project root as denied. Modelled on nono's
/// `why_reports_profile_deny_before_covering_allow` (crates/nono-cli/tests/why_deny.rs:36).
#[test]
fn policy_input_hole_splits_the_project_root() {
    let writes = [pp("/w/proj/**")];
    // FW-FID22: both layouts split the root, so FEP-5 D3's `.formwork/` remedy does not hold.
    for input in ["/w/proj/FORMWORK.toml", "/w/proj/.formwork/blueprint.toml"] {
        let holes = [pp(input)];
        let hole = splitting_hole(&writes, &holes, Path::new("/w/proj"));
        assert_eq!(hole.map(ToString::to_string).as_deref(), Some(input));
    }
    // Negative controls: a directory outside every write grant, and a hole that is the directory.
    assert!(splitting_hole(&writes, &[pp("/w/proj/FORMWORK.toml")], Path::new("/w")).is_none());
    assert!(splitting_hole(&writes, &[pp("/w/proj/**")], Path::new("/w/proj")).is_none());
}
```

```python
@pytest.mark.linux
@pytest.mark.fw_e2e("FW-E2E-135")
def test_explain_matches_run_in_a_split_project_root(cli, isolated):
    """Regression: explain said `write: granted` for a create the kernel denied."""
    project, env = isolated.project, isolated.env()
    (project / "FORMWORK.toml").write_text(
        'extends = ["builtin:default"]\nrules = ["readwrite:$CWD/**"]\n')
    out = cli("explain", "--json", "new.txt", cwd=project, env=env)
    split = json.loads(out.stdout)["explanations"][0]["split"]
    assert split["dir"] == str(project) and split["source"] == {"origin": "launcher"}
    ran = cli("run", "--", "touch", "new.txt", cwd=project, env=env)
    assert ran.code != 0 and not (project / "new.txt").exists()
    host = json.loads(cli("explain", "--json", cwd=project, env=env).stdout)["host"]
    if host["denial-feed"]["fs"] != "landlock-audit":
        require_exercised("the record arm needs the linux-audit job")
    entry = [l for l in read_record(isolated.state) if l["kind"] == "fs"][0]
    assert (entry["access"], entry["layer"]) == ("create", "launcher")
```

### 6.4 Traceability (draft rows for formwork.md §10)

| Requirement | Primary test | Also |
|---|---|---|
| `FW-FID16` Session record | `FW-E2E-133` | 139, 143, 144 |
| `FW-FID17` Record exclusions | `FW-E2E-140` | 139 |
| `FW-FID18` Filesystem denial feed in `run` | `FW-E2E-133` | 141, 144; L1 |
| `FW-FID19` Audit logging only when consumed | `FW-E2E-142` | L2 |
| `FW-FID20` Denial-record report line | `FW-E2E-141` | L3–L5 |
| `FW-FID21` End-of-run account | `FW-E2E-133` | 134, 141, 143 |
| `FW-FID22` Explain matches the run | `FW-E2E-135` | 136 |
| `FW-FID23` Session query | `FW-E2E-137` | 133 |
| `FW-FID24` Record retention | `FW-E2E-143` | — |
| `FW-DISC13` Proposal from a session record | `FW-E2E-138` | `FW-ADV-037` |
| `FW-DISC14` Record as untrusted input | `FW-ADV-037` | 137 |
| `FW-INV19` Record isolation | `FW-ADV-036` | `FW-ADV-038` |

Amended rows: [FW-FID3](../formwork.md#fw-fid3) gains `FW-E2E-133` and `FW-E2E-144`;
[FW-FID6](../formwork.md#fw-fid6) gains `FW-E2E-135`; [FW-DISC1](../formwork.md#fw-disc1) gains
`FW-E2E-138`.

### 6.5 Phasing

0. **Characterize.** `linux_audit.rs` L1–L5 on the `linux-audit` job, and the macOS delay from a
   millisecond denial to its tagged record with the stream started unawaited; the two results fix
   **settle-budget**. No requirement relying on them is anchored before they pass.
1. **`explain` matches the run, both OSes** (`FW-FID22`): `launcher_denies`, `splitting_hole`,
   `announce_split_root`, the `launcher` origin, the record-directory subtract; `FW-E2E-135`, 136. Independent of any feed; it fixes
   the verified defect first.
2. **Record and account without a Linux filesystem feed** (`FW-FID16`, 17, 21, 23, 24, `FW-INV19`,
   `FW-DISC14`, and `FW-FID18` on macOS through the unified log): `FW-E2E-133` (macOS), 134, 137, 139,
   140, 143, `FW-ADV-036`, 038. Linux reports `denial-record` `Unenforceable`.
3. **Landlock audit and the proposal path** (`FW-FID18`–20, `FW-DISC13`): `FW-E2E-133` (Linux),
   138, 141, 142, 144, `FW-ADV-037`; `learn`'s conclusion moves onto the record; the §7 i
   supersession of FEP-1 applies.

---

## 7. Amendments to the landed docs (apply on landing)

- **(a) `formwork.md` §5.6.** Add `FW-FID16`–`FW-FID24`. Replace [FW-FID6](../formwork.md#fw-fid6)'s
  sentence "It reflects the merged Blueprint (like `compile`), not the session-only denies `run`
  adds" with "It reports the verdict `run` would enforce on the current host (`FW-FID22`)", and add
  `launcher` to its layer list. Add the `denial-record` key to the report-line paragraph.
- **(b) §5.10.** Add `FW-DISC13` and `FW-DISC14`; note in [FW-DISC11](../formwork.md#fw-disc11)
  that `--session` is part of the `learn` surface.
- **(c) §6.** Add `FW-INV19`.
- **(d) §7.6, §7.9, §7.10.** Add `FW-E2E-133`–144 and `FW-ADV-036`–038.
- **(e) §8.** Rows: denial-record setup added to spawn, < 10 ms; added to exit with no denial,
  < 10 ms; measured with the owed §8 harness.
- **(f) §9.** Fidelity summary row "`run` denial record": Linux `Enforced` with Landlock audit (6.15+,
  `CAP_AUDIT_READ`), else `Unenforceable` (`learn`'s ptrace feed remains); macOS `Partial`. Add the
  §3.9 asymmetry rows; correct the FEP-5 D3 note that `.formwork/` keeps the root whole on Linux.
- **(g) §10.** The §6.4 rows; [FW-FID5](fep-1.md#fw-fid5) and [FW-E2E-040](fep-1.md#fw-e2e-040)
  rows read "superseded by FEP-9".
- **(h) §11.** Close "Violation streaming": the session record is the consumable stream (`FW-FID16`,
  `FW-FID18`); a push channel stays open (§9).
- **(i) `docs/fep-1.md`.** Mark [FW-FID5](fep-1.md#fw-fid5) and [FW-E2E-040](fep-1.md#fw-e2e-040)
  superseded by `FW-FID16`/`FW-FID18` and `FW-E2E-144`; both stay anchored there and their numbers
  are never reused.
- **(j) `constitution.md`.** Data model: add "the **session record** (`<state>/formwork/sessions/
  *.jsonl`, format 1) and the HostProfile `denial-feed` field". Observability: "a wrapper's product
  output, the end-of-run account and the [FW-XR11](../formwork.md#fw-xr11) line, goes to stderr,
  because the wrapper's stdout is the workload's ([FW-XR10](../formwork.md#fw-xr10)); it is written
  directly, not as a tracing event, so quiet telemetry does not remove it". Vocabulary: **session
  record** = the operator-side per-session file of refusals (`FW-FID16`); **account** = its
  end-of-run stderr summary (`FW-FID21`). Concepts: unchanged.
- **(k) `docs/STATUS.md`.** The "Violation stream" owed row points at this FEP; add the
  `linux-audit` job to the CI description.

---

## 8. Decisions (recorded per constitution Precedence & Conflicts)

- **No new subcommand.** `why`, `audit` and `session` verbs were rejected: `explain` already answers
  "why" for a path, and `--session` gives it the session; `learn` already owns proposals.
- **`learn` stays.** nono could drop it because its account replaced the root-only tracer. On an
  unprivileged Linux host Formwork's only filesystem feed is ptrace, which an ordinary run cannot
  afford (§3.2); removing `learn` would leave those hosts with no way to observe.
- **Declined nono behaviors** (§2.7): the save prompt reads a terminal an SDK harness does not
  have ([FW-XR10](../formwork.md#fw-xr10)) and can emit a `bypass_protection` patch an injected
  payload shapes ([FW-ADV-012](../formwork.md#fw-adv-012)); output heuristics trade silence on
  hosts without audit for invented denials, and the report states the silence; capability elevation
  is the live widening [FW-INV10](../formwork.md#fw-inv10) rules out; the capability file hands the
  confined process the rules [FW-FID9](../formwork.md#fw-fid9) withholds; refusing a grant that
  covers the state root would break the default profile's broad `$HOME` read
  ([FW-CAP3](../formwork.md#fw-cap3)), so the directory is a terminal deny instead.
- **No hash chain, ledger or signing.** Each would add crates (Growth's hardest no). The record is
  protected from the session by the Confiner (`FW-INV19`); an unconfined same-user process can
  rewrite anything that user owns, and a key that user holds would not change that
  (`formwork.md` §3).
- **Denials only.** Grant records ([FW-FID13](../formwork.md#fw-fid13)) stay debug-level tracing:
  recording every admitted request would make the record an activity log of every host contacted.
- **Program only; the workload's exit status.** Redaction is a secret detector, which
  `formwork.md` §3 declines, and absence is checkable where redaction is not. nono's downgrade
  makes a clean run look failed; the missing record is stated on stderr and in the report line.
- **A run proceeds without a record.** [FW-XR9](../formwork.md#fw-xr9) is met by saying so before
  the spawn; refusing confinement because observation is unavailable would trade the boundary for a
  log.
- **macOS does not wait for the stream.** Up to five seconds per spawn breaks
  [FW-TRA6](../formwork.md#fw-tra6); the deny tag makes late records recoverable, so the verdict is
  `Partial` rather than the run slower.
- **Epoch-second ids.** They sort as text until 2286 and need no date crate.
- **The account precedes the [FW-XR11](../formwork.md#fw-xr11) line**, so an embedder reading the
  last stderr line of a 125 exit still finds the attribution.

---

## 9. Open questions

- **settle-budget** (2 s provisional). Owner: Linux and macOS backend maintainers. Closes at Phase 0.
- **Detecting audit enabled without `CAP_AUDIT_CONTROL`** (`AUDIT_GET` may need it; L5). Owner:
  Linux backend maintainer. Closes at Phase 0.
- **The host audit trail.** While Formwork reads Landlock records, auditd also logs them; whether
  `run` should install an exclusion rule (it would need `CAP_AUDIT_CONTROL`) or only disclose it.
  Owner: Linux backend maintainer. Closes at Phase 3.
- **A push channel for embedders**, the part of [FW-FID5](fep-1.md#fw-fid5) a tailed file does not
  give, and how an embedder learns the session id before exit (a structured field on the spawn event
  is the candidate). Owner: embedder-integration maintainer. Closes at Phase 3.
- **Silencing the account.** Whether an embedder needs `run`'s stderr byte-identical to the
  workload's when denials occur. Owner: CLI surface reviewer. Closes at Phase 2 review.
- **Removing splits.** Placing policy inputs and Launcher directories outside every write grant, or
  Landlock `Make*` rights on split directories (FEP-5 §9's D3 alternatives, reopened by §1). Owner:
  Linux backend maintainer. Closes with a follow-up FEP before the next release.
- **Records for `formwork gateway` backends.** Owner: Gateway maintainer. After Phase 3.
- **Vocabulary.** FEP-4 §5c proposes **record** for a permissive recording run; this FEP uses
  **session record**. Owner: constitution reviewer. Closes when the second of the two lands.
