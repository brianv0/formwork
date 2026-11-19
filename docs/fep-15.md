# FEP-15 (proposal): Launcher session state — where it lives, who can write it, and when it goes away

**Formwork Enhancement Proposal 15 — proposal, not landed.** §1's first item is a cross-session
fail-open found in a security review of `main` at `e6e4572`, not yet fixed; the other two are
issues #49 and #50. Companion to `formwork.md` and `constitution.md`.

**Status.** Nothing here mutates the landed spec. New identifiers are draft numbering in inline
code. This FEP holds `FW-TRA18`..`FW-TRA21`, `FW-XR12`..`FW-XR13`, `FW-INV23`,
`FW-E2E-191`..`FW-E2E-196` and `FW-ADV-053`, above FEP-11's `FW-TRA17`, FEP-12's `FW-INV22` and
FEP-14's test block.

---

## 1. Problem

For each session the Launcher creates three directories under `std::env::temp_dir()`
(`crates/formwork-cli/src/main.rs:1082-1133`): the private temporary directory
(`formwork-session-<pid>-<nanos>`, [FW-TRA10](../formwork.md#fw-tra10)), the opener shim
directory (`-opener`, first on the session's `PATH` and its `$BROWSER`) and the trust bundle
directory (`-trust`, holding the session CA the confined clients verify against). Three defects
share that placement and lifetime.

1. **Another session can rewrite them.** [FW-TRA9](../formwork.md#fw-tra9) makes the shim and
   bundle read-only by adding them to the *owning* session's policy
   (`grant_launcher_dir`, `main.rs:1150-1172`). `profiles/default.toml:35` and every agent example
   grant `/tmp/**` for writing. A second session of the same user under the default profile
   replaced the first session's `xdg-open`; the first session then ran the planted program with
   its own grants. The same reach covers the CA bundle (a session that trusts a planted CA
   accepts a forged upstream) and the other session's `TMPDIR`. Verified on Linux as root; for an
   unprivileged user the 0700 directories are owned by the same uid, so the unlink is permitted.
2. **A signal to `formwork` orphans the workload** (#49). `run` waits with default dispositions.
   `SIGTERM` or `SIGINT` ends the launcher; the workload is reparented and keeps running,
   confined, with no Gateway.
3. **The directories outlive the session** (#50) on every refusal path, under `--confine-self`,
   on every Linux `learn`, and after a signal. `SessionTmp` has no `Drop`.

The second and third compound the first: leaked shim directories from dead sessions accumulate in
a directory every session can write.

### 1.1 Constraints

- The private temporary directory must stay writable by its own session and must be on a
  filesystem that supports what toolchains do in `TMPDIR` (exec, large files, Unix sockets).
- Landlock has no deny rule: a hole in a writable grant splits its ancestors. Placement must not
  split `/tmp` for sessions that grant it.
- `--confine-self` leaves no Formwork process alive to clean up.

## 2. Design

### 2.1 One session root, outside every commonly granted tree

The Launcher creates one directory per session, the **session root**, and puts the three
directories inside it:

```
<runtime>/formwork/<session-id>/           0700, owner = invoking uid
    tmp/        the session's TMPDIR         (read-write for the session)
    opener/     shim scripts                 (read + exec for the session)
    trust/      ca-bundle.pem                (read for the session)
```

`<runtime>` is `$XDG_RUNTIME_DIR` when it is set, absolute, owned by the invoking uid and mode
0700 (the conditions the XDG specification gives it); otherwise `~/.local/state`, created 0700.
On macOS it is the per-user `$TMPDIR` under `/var/folders`, which already has these properties.
`/tmp` is never used. If none of these can be created with the stated owner and mode, `run`
refuses to start and names the directory ([FW-INV6](../formwork.md#fw-inv6)).

`<session-id>` is 128 bits from the OS random source, not a pid and a clock value.

### 2.2 Every session is denied every other session's root

Each compiled policy carries a subtract on `<runtime>/formwork/**` and re-grants only its own
session root. On Seatbelt that is a deny followed by an allow. On Landlock the parent
`<runtime>/formwork` is split, which costs nothing: sessions do not create entries there, and the
Launcher creates the root before confinement.

A blueprint grant that covers `<runtime>/formwork` (for example `readwrite:~/**` when the
fallback location is used) does not lift the subtract: it is a Launcher deny, applied after the
merge, in the manner of the policy-input denies ([FW-XR8](../formwork.md#fw-xr8)).

This is the property §1's first item lacks, and placement alone does not give it: a blueprint can
grant any directory.

### 2.3 The Launcher forwards signals and reports the workload's status

While the workload runs, the Launcher forwards `SIGINT`, `SIGTERM`, `SIGHUP` and `SIGQUIT` to the
workload's process group and keeps waiting. It exits with the workload's status
([FW-XR10](../formwork.md#fw-xr10)). If the workload has not exited **term-grace** (10 s) after a
forwarded `SIGTERM`, the Launcher sends `SIGKILL` to the group, and where the session has a PID
namespace ([FW-ISO10](../formwork.md#fw-iso10)) the namespace ends with it. A second `SIGINT`
from a terminal within the grace period escalates at once.

The isolation stage already relays this way
(`crates/formwork-confine/src/linux/isolate.rs:257-300`); the Launcher reuses that code.

Without a PID namespace, descendants that left the process group survive. The report's existing
process-isolation row says so; this FEP adds no claim.

### 2.4 The session root is removed when the session ends

The Launcher removes the session root on every exit path it controls: normal exit, a refusal
after creation, a forwarded signal. Refusing checks move ahead of creation so most refusals
create nothing.

Two paths leave no Launcher alive:

- **`--confine-self`** replaces the process. The Launcher creates only what the posture uses (no
  Gateway means no trust bundle) and the session root is removed by whoever invoked it: `learn`
  removes its shim's root; a direct `run --confine-self` leaves `tmp/` and says so once on the
  operator channel.
- **`SIGKILL` of the Launcher.** At start, the Launcher removes any session root under
  `<runtime>/formwork` whose lock file (`<root>/.lock`, held with `flock` for the session's life)
  it can acquire. A dead session's root is gone by the next `run`.

## 3. Surface changes (each measured against Growth)

| Change | Note |
|---|---|
| Session directories move from `temp_dir()` to `<runtime>/formwork/<id>/` | the `TMPDIR` a session sees changes; nothing reads the old path |
| Parameter **term-grace** = 10 s | named once here; no flag until someone needs a different value |
| A Launcher deny on `<runtime>/formwork/**` in every policy | a report line names it, as for policy inputs |
| `flock`-held lock file per session root | no new dependency (`libc`) |

No blueprint field, flag, concept or dependency.

## 4. Proposed requirements (draft numbering)

| ID | Statement |
|---|---|
| `FW-TRA18` Session root | The Launcher shall create every per-session path inside one directory it creates with mode 0700 under the invoking user's runtime directory (FEP-15 §2.1), and shall refuse to start where that directory cannot be created with the invoking uid as owner. |
| `FW-TRA19` Session roots are disjoint | Every compiled policy shall deny read and write on every session root other than its own, whatever the blueprint grants. |
| `FW-TRA20` Session root removal | The Launcher shall remove the session root before it exits, on every exit path in which a Launcher process outlives the workload. |
| `FW-TRA21` Stale roots | At start, the Launcher shall remove every session root whose session lock it can acquire. |
| `FW-XR12` Signal forwarding | The Launcher shall forward `SIGINT`, `SIGTERM`, `SIGHUP` and `SIGQUIT` it receives after spawn to the workload's process group, and shall exit only after the workload has. |
| `FW-XR13` Termination bound | The Launcher shall send `SIGKILL` to the workload's process group if the workload has not exited **term-grace** after the Launcher forwarded `SIGTERM`. |
| `FW-INV23` No cross-session write | A confined process shall not be able to create, modify, replace or remove any path inside another session's session root. |

## 5. Verification plan

| ID | Test |
|---|---|
| `FW-E2E-191` | Two concurrent sessions under `builtin:default`: session B attempts to replace A's `opener/xdg-open`, to overwrite `trust/ca-bundle.pem` and to create a file in A's `tmp/`; each is refused; A then runs its shim and gets the Launcher's. Both backends. |
| `FW-E2E-192` | With `readwrite:~/**` and no `XDG_RUNTIME_DIR` (the fallback location inside a granted tree), the same attempts are refused, and the report names the Launcher deny. |
| `FW-E2E-193` | `SIGTERM` to the Launcher: the workload receives it, the Launcher exits with the workload's status, no process of the session remains, and `<runtime>/formwork` is empty. Repeated for `SIGINT` against a workload that handles it and continues: the Launcher keeps waiting. |
| `FW-E2E-194` | A workload that ignores `SIGTERM` is killed **term-grace** after the forward (measured from the forward, tolerance 2 s) and the Launcher exits 137. |
| `FW-E2E-195` | The table of #50, one row each (refused `--confine-self`, refused `gateway`, refused broker, a `learn` run): `<runtime>/formwork` is empty afterwards. |
| `FW-E2E-196` | `SIGKILL` the Launcher mid-session, then start another `run`: the first session's root is gone and the second runs. A live session's root survives a concurrent `run`. |
| `FW-ADV-053` | `FW-INV23` by rename and link: session B tries `rename` of A's root, a hard link into it, a symlink at a predictable next session id, and `O_TMPFILE` + `linkat` into it. Every attempt fails; A's `PATH` head and bundle are byte-identical before and after. |

## 6. Amendments (apply on landing)

- `formwork.md` §5: the rows of §4. [FW-TRA9](../formwork.md#fw-tra9) and
  [FW-TRA10](../formwork.md#fw-tra10): name the session root. §10: rows for the new tests, and
  FW-XR10 gains `FW-E2E-193`.
- `docs/linux-backend.md`: the split of `<runtime>/formwork`.
- `profiles/default.toml` and `examples/blueprints/agent-base.toml`: decide whether `/tmp/**`
  stays granted now that every session has a private `TMPDIR` (§8).
- Draft FEP-7, FEP-9 and FEP-11 each propose a state directory under `~/.local/state/formwork`
  (see #61). Their stores are durable and this root is per-session, so they do not merge, but the
  fallback location and the Launcher-deny provenance label should be one decision.

## 7. Decisions

- **Deny by rule, not only by placement.** A location outside `/tmp` protects the default
  profile; `FW-TRA19` protects every blueprint.
- **Random session ids.** A pid and a nanosecond value are guessable, and a guessable name lets
  another session pre-create the path.
- **Escalate after a stated interval.** A Launcher that waits forever on a workload that ignores
  `SIGTERM` makes `timeout formwork run …` and CI cancellation useless.
- **Clean up stale roots at start, not with a daemon.** There is no long-lived Formwork process
  to do it otherwise.

## 8. Open questions

| Question | Owner | Closes at |
|---|---|---|
| Should the default profile stop granting `/tmp/**` for writing once `TMPDIR` is private? It removes a shared writable tree between sessions; it may break tools that hardcode `/tmp`. Measure with the agent examples (`FW-E2E-084`). | reviewer | adoption |
| Is `$XDG_RUNTIME_DIR` (often a size-limited tmpfs) acceptable for `tmp/`, or should `tmp/` alone live under `~/.cache` with the same deny? | implementer | phase 1 measurement |
| On macOS, does Seatbelt refuse a rename of the session root's parent by another session when the deny is on the children? Characterize (the same question FEP-7 raises as C10). | implementer | before anchoring `FW-TRA19` as `Enforced` on macOS |
| Does **term-grace** need a flag for interactive agents that save state on `SIGTERM`? | reviewer | after first use |
