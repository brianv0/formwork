# FEP-11 (proposal): session rollback — snapshot the writable working set and restore it

**Formwork Enhancement Proposal 11 — proposal, not landed.** Companion to `formwork.md` (design +
end-to-end spec) and `constitution.md` (doctrine).

**Status: nothing in this document mutates the landed spec or the constitution.** Per the
constitution (Requirements & identifiers; Precedence & Conflicts) a draft lives in its FEP until
adoption; the amendments in §7 are apply-on-landing blocks. New identifiers are draft numbering,
written as inline code until anchored. This FEP holds the reserved blocks `FW-TRA11`..`FW-TRA17`,
`FW-FID25`..`FW-FID26`, `FW-INV21`, `FW-E2E-157`..`FW-E2E-168` and `FW-ADV-043`..`FW-ADV-045`, and
uses every number in them. nono (release 0.79.0, 2026-10-05) is read as data and never built or run.
It is cited as `nono@9edf3ea:<path>:<line>`, where `undo/` abbreviates `crates/nono/src/undo/` and
`cli/` abbreviates `crates/nono-cli/src/`; a bare `:<line>` continues the file cited immediately
before it. Formwork paths are repository-relative and carry no prefix.

---

## 1. Problem

Formwork grants a writable working set ([FW-TRA5](../formwork.md#fw-tra5)) and, inside it, the
agent's writes are unconstrained by design: the minimal blueprint `formwork` suggests is
`readwrite:$CWD/**` (`crates/formwork-cli/src/main.rs:578-588`), and only the tamper-vector
write-subtract set ([FW-TRA7](../formwork.md#fw-tra7)) and the write-protected policy inputs
([FW-XR8](../formwork.md#fw-xr8), `crates/formwork-cli/src/blueprint_load.rs:760-786`) narrow it.
Nothing records what a session changed and nothing can put it back. `run` spawns the child, waits,
removes the private temporary directory and exits with the workload's status (`main.rs:1741-1742`,
`1862-1874`); `learn` observes denials, which are the writes that did not happen.

The operator's version control is the only recovery, and it covers less than it appears to:
untracked and ignored files (`.env`, local databases, generated fixtures), uncommitted edits lost to
`git checkout -- .` or `git clean -fdx`, and `.git` itself (a reset branch, a `git gc --prune=now`
after it) are outside what git can restore. A prompt-injected or careless agent that runs one
destructive command inside its grant has not breached the boundary
([FW-XR2](../formwork.md#fw-xr2)), so the threat model (`formwork.md` §3) is silent about it, and
the operator has no undo. The operators hurt are the solo operator with uncommitted work under
`readwrite:$CWD/**`, the team member whose project carries ignored local state, and the embedder
(FEP-5's Omnigent case) that wants "undo this session" and today snapshots the tree itself, without
Formwork's knowledge of what the session could write.

### 1.1 Constraints this FEP holds to

- **No new concept, no new family.** Capture and restore are the Launcher's (§7 a); requirements
  continue TRA under [FW-TRA5](../formwork.md#fw-tra5) and FID under
  [FW-FID7](../formwork.md#fw-fid7)/[FW-FID8](../formwork.md#fw-fid8).
- **The store is unreachable from every session**, on both backends, whether or not the session
  asked for a snapshot.
- **Capture scope comes from the compiled policy and operator-typed flags only.** Nothing the agent
  can write — a `.gitignore`, a marker file — changes it.
- **Fail loud before spawn.** A capture that cannot be complete within its limits refuses the run
  ([FW-XR9](../formwork.md#fw-xr9)); nothing is left out silently.
- **Restore never writes outside what was captured, never follows a symlink, and never overwrites a
  change the operator made after the session.**
- **Honesty.** Every gap in restorability is a named code in the report, per backend (§3.7).
- **Growth.** One subcommand, two `run` flags, no Blueprint field, no new crate (§4).

## 2. Prior art: nono

### 2.1 Mechanism and behavior

`nono run --rollback` takes a baseline snapshot of every user-granted writable directory before the
child starts and a final snapshot after it exits, then offers an interactive restore
(`nono@9edf3ea:docs/cli/features/atomic-rollbacks.mdx:10-22`,
`nono@9edf3ea:cli/rollback_runtime.rs:390-487`, `:505-596`). Tracked roots are the capability set's
user-intent directories with write access (`nono@9edf3ea:cli/rollback_runtime.rs:323-340`). Files
are stored content-addressed by SHA-256 under `objects/<2 hex>/<62 hex>`, deduplicated within a
session, cloned with `clonefile()` on APFS and copied elsewhere
(`nono@9edf3ea:undo/object_store.rs:41-75`, `:330-364`); restore writes a temporary file beside the
target, re-hashes it and renames it into place (`nono@9edf3ea:undo/object_store.rs:102-155`). A
Merkle tree with RFC 6962 domain separation commits to each manifest
(`nono@9edf3ea:undo/merkle.rs:19-94`). Each `FileState` holds hash, size, mtime and mode; symlinks
are recorded by path only (`nono@9edf3ea:undo/types.rs:120-131`, `:537-553`). A walk budget of
300,000 entries and 2 GiB fails the snapshot (`nono@9edf3ea:undo/snapshot.rs:21-42`, `:918-939`); a
preflight auto-excludes "heavy" directories by name and by a time-capped file count
(`nono@9edf3ea:cli/rollback_preflight.rs:18-47`, `:142-255`). Restore validates manifest paths
lexically (`nono@9edf3ea:undo/snapshot.rs:586-611`) and checks each existing parent with `lstat`
before writing (`nono@9edf3ea:undo/snapshot.rs:621-713`). The default store
(`$XDG_STATE_HOME/nono/rollbacks`, `nono@9edf3ea:cli/state_paths.rs:74-76`) is protected by refusing
any grant that overlaps it (`nono@9edf3ea:cli/protected_paths.rs:74-111`). The CLI has five verbs —
`list`, `show`, `restore`, `verify`, `cleanup` (`nono@9edf3ea:cli/rollback_commands.rs:66-80`);
retention keeps 10 sessions and 5 GB
(`nono@9edf3ea:docs/cli/features/atomic-rollbacks.mdx:185-192`).

### 2.2 Its tests

Unit tests sit beside the code. In `nono@9edf3ea:undo/`: `snapshot.rs` 31, `object_store.rs` 10,
`exclusion.rs` 9, `merkle.rs` 8, `types.rs` 8. In `nono@9edf3ea:cli/`: `rollback_commands.rs` 19
(formatting and grouping), `rollback_runtime.rs` 12, `rollback_preflight.rs` 10,
`rollback_session.rs` 8. The snapshot tests share three fixtures, `setup_test_dir`, `make_manager`
and `make_manager_with_budget` (`nono@9edf3ea:undo/snapshot.rs:1147-1171`, `:1827-1846`). Black-box
coverage is `nono@9edf3ea:crates/nono-cli/tests/rollback_run.rs` (3 tests) and two shell suites,
`nono@9edf3ea:tests/integration/test_rollback.sh` and `test_rollback_dest_edge_cases.sh` beside it.
§6 names the test each Formwork test derives from.

### 2.3 Defects and limitations (each designed out below)

| # | Defect | Citation | Formwork |
|---|---|---|---|
| N1 | A custom store is refused unless a sandbox **write** grant covers it; the suites assert this and accept the store equal to the workdir, so the agent can rewrite its own snapshots | `nono@9edf3ea:cli/launch_runtime.rs:631-667`; `nono@9edf3ea:tests/integration/test_rollback_dest_edge_cases.sh:57-89`, `:219-232`; `nono@9edf3ea:crates/nono-cli/tests/rollback_run.rs:26-38` | no store flag; store denied to every session (`FW-TRA14`) |
| N2 | Restore is two-way: every file absent from the manifest is deleted, including files the operator created after the session | `nono@9edf3ea:undo/snapshot.rs:351-366` | three-way change set (`FW-TRA15`, `FW-TRA16`) |
| N3 | Restore rebuilds exclusions from the base list, without `.gitignore`, rooted at the first tracked path only, so files excluded at capture are deleted at restore | `nono@9edf3ea:cli/rollback_commands.rs:635-652` vs `nono@9edf3ea:cli/rollback_runtime.rs:86-96`, `:428-472` | exclusions recorded in the manifest; restore acts on the change set only |
| N4 | The default restore target is the final snapshot, while the documentation says baseline | `nono@9edf3ea:cli/rollback_commands.rs:621-624`; `nono@9edf3ea:docs/cli/features/atomic-rollbacks.mdx:135-139` | the baseline is the only target |
| N5 | `.git` is always excluded, so a restore leaves HEAD, index and refs at the session's state over a reverted working tree | `nono@9edf3ea:cli/launch_runtime.rs:16-30`; `nono@9edf3ea:cli/rollback_runtime.rs:67-84` | `.git` is captured (§3.2) |
| N6 | Capture scope depends on the wall clock: a directory whose count times out is treated as large and excluded, announced in one stderr line | `nono@9edf3ea:cli/rollback_preflight.rs:228-255`, `:271-288`; `nono@9edf3ea:cli/rollback_runtime.rs:435-466` | no auto-exclusion; limits fail loud |
| N7 | Silent capture gaps: unreadable files are skipped with a warning, walk errors dropped, and a source changed between hash and clone is not stored while its hash is recorded | `nono@9edf3ea:undo/snapshot.rs:777-779`, `:789`, `:826-828`; `nono@9edf3ea:undo/object_store.rs:290-300` | the object name is the digest of the stored bytes; gaps are listed |
| N8 | A symlink the session deleted is not recreated: manifests hold no link targets | `nono@9edf3ea:undo/snapshot.rs:283-284`; `nono@9edf3ea:undo/types.rs:548-550` | targets recorded and recreated |
| N9 | Restore through a symlinked parent is refused by an `lstat` pre-check: the session blocks its own undo by planting a link, and the check-then-use window stays open | `nono@9edf3ea:undo/snapshot.rs:621-713`; `nono@9edf3ea:CHANGELOG.md:1732` | kernel no-follow opens (§3.6) |
| N10 | Atomic per file only; mode restore masks setuid, setgid and sticky and only warns on failure; unlink failures warn | `nono@9edf3ea:docs/cli/features/atomic-rollbacks.mdx:145`; `nono@9edf3ea:undo/snapshot.rs:325-333`, `:354-356` | journalled all-or-nothing (`FW-TRA17`) |
| N11 | No tracked roots returns no snapshot silently; retention and 0700 failures warn and continue | `nono@9edf3ea:cli/rollback_runtime.rs:422-426`, `:115-131`, `:211-219` | fail loud |
| N12 | The Merkle root sits beside the manifest it commits to: it detects corruption, not a writer of the store (which N1 permits) | `nono@9edf3ea:undo/types.rs:551-552`; `nono@9edf3ea:cli/rollback_commands.rs:726-739` | integrity by digest; tamper resistance by denial |
| N13 | Tests named for restore do not restore: `rollback_restores_file_after_write` asserts only that the list is a JSON array, `dry_run_does_not_modify_workspace` never runs `restore --dry-run`, and the shell suite never restores and skips `show`/`verify` when no id parses | `nono@9edf3ea:crates/nono-cli/tests/rollback_run.rs:19`, `:62-69`, `:75`; `nono@9edf3ea:tests/integration/test_rollback.sh:84-91`, `:100-105` | every restore test restores and compares digests |

### 2.4 What Formwork adopts and declines

Adopted: content-addressed objects named by SHA-256 and re-hashed before rename
(`nono@9edf3ea:undo/object_store.rs:102-155`); copy-on-write cloning, extended from `clonefile()` to
Linux `FICLONE`; roots derived from write grants (`nono@9edf3ea:cli/rollback_runtime.rs:323-340`);
entry and byte limits that fail the capture, at nono's values
(`nono@9edf3ea:undo/snapshot.rs:35-42`); a walk that never follows a symlink or a symlinked root
(`nono@9edf3ea:undo/snapshot.rs:743-749`, `:794-799`; `nono@9edf3ea:CHANGELOG.md:658`); manifest
path validation (`nono@9edf3ea:undo/snapshot.rs:586-611`; `nono@9edf3ea:CHANGELOG.md:3523`); a state
root outside every grant (`nono@9edf3ea:cli/protected_paths.rs:9-111`); 0700 store directories
(`nono@9edf3ea:cli/rollback_runtime.rs:211-219`), enforced rather than warned; a dry run.

Declined, each for the N-row named: the store-location flag (N1), ignore-file and auto-exclusion
(N3, N6), the `.git` exclusion (N5), the Merkle tree (N12), final-snapshot content and per-session
object stores (`nono@9edf3ea:undo/object_store.rs:29-38`), five verbs, and the post-exit prompt
(`nono@9edf3ea:cli/rollback_ui.rs:16-66`), since `run` stays a wrapper ([FW-XR10](../formwork.md#fw-xr10)).

## 3. Design

### 3.1 Concepts and layers

A **snapshot** is the Launcher's record of a session's **capture set**: the baseline, taken before
spawn, and the final record, taken when the workload's direct child exits. The **change set** is the
entries whose baseline and final records differ. **Restore** returns the change set to its baseline;
a **conflict** is a change-set entry whose current state differs from its final record. A snapshot
belongs to one Session; the Launcher writes it; `formwork restore` reads it outside any session.
This extends the Launcher concept (§7 a) — it already owns pre-spawn transforms and policy-input
protection — and adds a Data-model artifact (§7 b), not a concept.

| Piece | Crate | Note |
|---|---|---|
| capture-set computation, limits, change set, restore plan, manifest types, `SnapshotError` | `formwork-blueprint` (`src/snapshot.rs`, pure) | beside the Launcher's other pure decisions (`construct_env`); takes digests and `lstat` tuples as data |
| `snapshot-store` and `snapshot` rows | `formwork-compile` (pure) | the `private-tmp` precedent (`crates/formwork-compile/src/lib.rs:821-849`); the store root arrives with the catalog's home, the snapshot id in `SessionSpec` (`lib.rs:193-201`) |
| walk, clone or copy, hashing, no-follow restore, journal, store lock | `formwork-cli` (`src/snapshot.rs`) | impure fs work in the shell, the `learn.rs` and `SessionTmp` precedent; no confinement code changes |
| store denial | `formwork-cli` passes the root; `formwork-compile` renders the denies | the `protect_policy_inputs` precedent (`blueprint_load.rs:760-786`); a compile input, not Blueprint rows, because the Linux and macOS forms differ (§3.5) |

### 3.2 What is captured

The capture roots are the roots of the session's `writes` and `writes-no-create` grants
([FW-CAP9](../formwork.md#fw-cap9)): `modify` cannot create but can unlink, so both grades are
captured. Within the roots an entry is captured when the compiled policy leaves it writable **on
this host**: installed `subtract`, `write-subtract`, floor and policy-input denies remove it; a row
the backend withheld does not. On Linux the any-depth rows (`**/.git/hooks/**`, `**/.env`) are
withheld ([FW-CRED9](../formwork.md#fw-cred9)), so those paths are writable and captured; on macOS
they are denied and need no capture. The store can therefore hold copies of credential-shaped files
a Linux host could not floor-deny; it is denied to every session (§3.5).

Excluded whole, with source `builtin`: a grant whose root is a host temp root (`/tmp`,
`/private/tmp`, `/var/tmp`, `/private/var/tmp`, and on macOS the `confstr(_CS_DARWIN_USER_TEMP_DIR)`
directory), because other processes share it and a restore would undo their work; and every
Launcher-owned path ([FW-TRA9](../formwork.md#fw-tra9)), the private temporary directory
([FW-TRA10](../formwork.md#fw-tra10)) included, which is removed at exit. The rule is per grant: the
default profile's `/tmp/**` is excluded, but a project at `/tmp/proj` under `readwrite:/tmp/proj/**`
is captured. Excluded with source `flag`: each `--snapshot-exclude <pattern>`, parsed as a
[FW-CAP6](../formwork.md#fw-cap6) path pattern after sigil expansion
([FW-BP5](../formwork.md#fw-bp5)). A write grant in the any-depth form has no enumerable root and
makes `--snapshot` fail loud. No other input changes the set: `.gitignore` and `CACHEDIR.TAG` are
agent-writable, and honoring `.gitignore` would need a parser (a dependency) or running `git` in the
Launcher, which executes repository-controlled configuration (`core.fsmonitor`) outside the sandbox.

`.git` is captured like any directory. Restoring HEAD, index, refs and objects together keeps the
repository consistent with its working tree; objects the session added are session-created files and
are removed. Per entry kind:

| Kind | Recorded | Restored |
|---|---|---|
| regular file | content object, mode (all 12 bits), uid, gid, size, mtime, `(dev, ino, ctime, nlink)` | content, mode, mtime |
| directory | mode, owner, mtime | created or removed; mode and mtime |
| symlink | target bytes (`readlink`), never followed | recreated with the same target |
| FIFO | mode | recreated with `mkfifoat` |
| socket, device | kind and mode | not restorable (code `not-restorable`) |
| hardlink group inside the set | one object, every name | one file plus `linkat` for the other names |
| file with links outside the set (`nlink` above the names found) | as a file | rename-replace splits the link; the outside name is never written; listed `hardlink-outside` |
| unreadable file or directory at baseline | tuple only | never removed or rewritten; listed `unreadable` |
| extended attributes, ACLs | count of files carrying them | not captured (code `xattrs`) |

Paths are recorded as UTF-8; a non-UTF-8 name under a root fails the capture naming its parent
([FW-INV6](../formwork.md#fw-inv6): no lossy rendering).

### 3.3 When and how

**Baseline, before spawn.** `prepare_session` computes the capture set after compilation; the
Launcher walks it with `lstat`, checks the limits on that inventory (§3.4) before copying anything,
then stores each regular file: `FICLONE` (Linux: btrfs, XFS with reflink, bcachefs) or `clonefile`
with `CLONE_NOFOLLOW` (macOS: APFS) into a temporary object, falling back to a streamed copy on
`EOPNOTSUPP`/`EXDEV`/`EINVAL`. The digest is computed over the stored bytes, so an object always
matches its name (N7). The source's `(dev, ino, size, mtime, ctime)` is compared before and after; a
change retries the file once and then fails the capture naming it. The workload spawns only after
the manifest is written and `fsync`ed.

**Final record, at the direct child's exit.** An `lstat` walk under the roots records each entry's
tuple; no content is stored, since restore targets the baseline only. `ctime` cannot be set by an
unprivileged process, so an unchanged `(dev, ino, size, mtime, ctime)` means unchanged content; on a
filesystem with one-second timestamps, files whose `ctime` falls in the capture second are
re-hashed. A directory the session made unreadable is recorded **opaque**. Processes that outlive
the direct child can write after the final record; their writes are conflicts or are left in place
(gap `descendants`), except where the session's PID namespace ends with the workload (Linux,
`isolate = ["processes"]`, [FW-ISO10](../formwork.md#fw-iso10); **(characterize)** by `FW-E2E-167`).
A final-record failure exits `125` with the attribution line ([FW-XR11](../formwork.md#fw-xr11)) and
leaves a snapshot that `restore` refuses.

**Incremental capture was weighed and declined.** Copying a file only before its first write needs a
blocking pre-write event: fanotify permission events need `CAP_SYS_ADMIN`, Endpoint Security
`AUTH_OPEN` an Apple entitlement, and unprivileged fanotify reports after the write, when the
baseline is gone. An overlayfs upper directory gives copy-up for free but needs unprivileged user
namespaces, which Ubuntu 24.04 restricts ([FW-ISO10](../formwork.md#fw-iso10)), has no macOS
counterpart ([FW-XR6](../formwork.md#fw-xr6)), and changes what the operator sees in the tree during
the session. The full baseline costs a walk plus clones or copies, which is why `--snapshot` is
opt-in per run ([FW-TRA6](../formwork.md#fw-tra6)).

`--snapshot` requires the spawn posture: under `--confine-self` no Launcher remains to take the
final record, so the combination is refused before work, naming the spawn posture
([FW-XR9](../formwork.md#fw-xr9); `refuse_unavailable_isolation`, `main.rs:1587-1617`, is the
precedent). `--snapshot` with no capture root (a read-only blueprint) fails loud (N11).

### 3.4 Limits

Values are nono's (§2.1), defined once here and implemented as named constants in
`formwork_blueprint::snapshot`.

| Parameter | Value | Bounds | Exceeded |
|---|---|---|---|
| **snapshot-max-entries** | 300,000 entries | files, directories, symlinks and special files in the capture set | `run` refuses before spawn and before any copy, naming the limit, the count and the three largest subtrees |
| **snapshot-max-bytes** | 2 GiB (2,147,483,648) | apparent size of the regular files in the capture set, reflinked or not, so the verdict is the same on every host | as above |
| **snapshot-retain** | 10 snapshots | snapshots in the store, the new one included | the oldest without a restore journal are removed before the capture; their ids go to the operator channel |
| **snapshot-store-max-bytes** | 5 GiB (5,368,709,120) | apparent size of all stored objects after the new capture | oldest removed as above; if the capture still does not fit, `run` refuses before spawn |

There is no wall-clock limit: a timeout would make the outcome depend on disk speed (N6). The final
record has no limit; its cost is linear in what the session wrote. The time the capture adds is an
open question (§9).

### 3.5 The store

**Location.** `~/.local/state/formwork/snapshots` on both platforms, `~` being the `$HOME` every
other Formwork path uses; `--snapshot` with `HOME` unset or relative fails loud (the `/` fallback in
`main.rs:408-410` is never used for the store). `XDG_STATE_HOME` is not consulted (§8).

**Layout.** `store.json` (`{"version": 1}`), `lock` (exclusive `flock` for capture, prune and
restore), `objects/<2 hex>/<62 hex>` (shared by every snapshot, so dedup spans sessions;
unreferenced objects are swept under the lock after a prune), and per snapshot `<id>/manifest.json`
(baseline), `<id>/final.json`, and `<id>/journal.json` only while a restore runs. The id is 16
lowercase hex digits from `/dev/urandom` (the `session_nonce` precedent, `main.rs:1070-1077`).

**Denied to every session.** `prepare_session` passes the store root to the compiler in every
session (`run`, `learn`, `gateway` backends), whether or not the root exists, beside the
[FW-XR8](../formwork.md#fw-xr8) policy inputs; the compiler adds read and write denies for `<store>`
and `<store>/**`, terminal like every deny ([FW-CAP8](../formwork.md#fw-cap8)). On macOS Seatbelt
denies the subpath whether or not it exists, so the root cannot be created from inside, and the
compiler also write-denies the literal entry of each ancestor below `$HOME` (`~/.local`,
`~/.local/state`, `~/.local/state/formwork`), so no session can rename a directory that holds the
store; creating entries beside them stays allowed. On Linux the hole is left out of every expanded
grant and each existing ancestor under a grant is split
(`crates/formwork-confine/src/linux/landlock.rs:121-158`): Landlock gives a split directory no rights
of its own, so nothing can be created in it and none of its entries can be renamed or removed, which
covers the ancestors without a literal deny (one would drop the whole ancestor subtree from the
grant). The Linux cost: a write grant covering an ancestor (`readwrite:~/**`) loses create rights
directly in each split directory; `run` names them on the operator channel (the
`announce_split_root` precedent, `main.rs:1619-1648`) and lists the grant under the report's
`withheld`. A confined `formwork restore` therefore cannot read the store and fails.

**Root validation.** Before a capture or restore, the store root is opened component by component
from `$HOME` with `O_NOFOLLOW | O_DIRECTORY`; each component must be a directory owned by the
invoking uid, the root mode 0700. Missing components are created 0700; a non-empty root without
`store.json` is refused as not Formwork's. This closes planting by a session launched before this
feature, when the root was not yet denied.

### 3.6 Restore

`formwork restore` loads the manifest and final record, validates every path (absolute, no `..`,
under a recorded root), and refuses a snapshot without a final record. The change set is computed
from the two records. The selection is the change set, narrowed to the subtrees of any positional
paths, minus not-restorable entries. Every selected entry's current state is read and compared with
its final record; any difference refuses the whole restore, writing nothing, listing every conflict.
Entries beneath an opaque directory have no final record: restore first returns the directory's
mode, then plans them against the baseline alone and marks them `unverified`.

Before the first write, restore verifies every needed object's digest, stores the current content of
every selected entry as pre-restore objects, and writes the journal (`fsync`). It then applies, in
order: remove session-created non-directories, deepest first; remove session-created directories
once empty; create baseline directories, shallowest first; write files, symlinks and FIFOs through a
temporary name and `renameat`; set modes and mtimes, deepest first. Every path is reached by opening
each component relative to its parent's descriptor with `O_NOFOLLOW | O_DIRECTORY`, starting from
`/`, so a symlink anywhere fails with `ELOOP` at the kernel, with no check-then-use window (N9); a
session-created symlink is removed with `unlinkat`, which never follows it, before a baseline
directory takes its name. A failed operation reverts the applied ones from the journal and exits
non-zero; an interrupted invocation is reverted by the next `formwork restore` before anything else.
Once the journal is removed, either every selected entry is at its baseline or every one is at its
pre-restore state. A second restore of the same snapshot conflicts everywhere and is refused.
Restore checks conflicts once, before its first write: a write by another process during the restore
is overwritten or reverted with it.

### 3.7 Report and disclosure

| Key | Where | Linux | macOS |
|---|---|---|---|
| `snapshot-store` | every report: `compile`, `explain`, and each session's | `Enforced` (Landlock); `Unenforceable` without Landlock, and `--snapshot` is then refused | `Enforced` (Seatbelt) |
| `snapshot` | sessions spawned with `--snapshot` | `Enforced` (backend `launcher`) with no gap; else `Partial` | same |

Beside the verdict, a `snapshot` section (the `channels` precedent,
`crates/formwork-compile/src/report.rs:135-146`) carries `{ id, store, roots, excluded, gaps }`.
Gaps are a closed set: `host-temp-grant`, `flag-exclusion` and `descendants` are known at compile
time; `not-restorable` and `xattrs` are known after the capture and appear in the copy of the row
the manifest stores. `descendants` is absent only under the Linux namespace case of §3.3. The
default profile's `/tmp/**` grant makes the row `Partial` with `host-temp-grant`.

Disclosure follows [FW-FID7](../formwork.md#fw-fid7). `run --snapshot` emits one operator-channel
line naming the id, the store root (`builtin`), the roots, entry and byte counts (reflinked and
copied), each exclusion with its source (`builtin` or `flag`), and the restore command; stdout stays
the workload's. The manifest's `inputs` section names the blueprint path, its source
(`flag | auto-discovered`) and SHA-256, the store root and the exclusions. Every `restore` output
starts with the id, the capture time and the blueprint it was captured under, so a snapshot taken
under an auto-discovered `FORMWORK.toml` says so wherever it is used. `explain` names the store root
and reports paths beneath it denied by a `built-in` rule (§7 f).

### 3.8 Asymmetries that remain

| Property | Linux | macOS | Why |
|---|---|---|---|
| Copy-on-write capture | `FICLONE` on btrfs, XFS (reflink), bcachefs; ext4 copies | `clonefile` on APFS; HFS+ copies | filesystem |
| Store denial under a grant covering an ancestor | `Enforced`; ancestors split, no new entries directly in them | `Enforced`; only the ancestors' own entries are write-denied | Landlock is allow-list only |
| Writes after the final record | none under `isolate = ["processes"]` (characterize); else gap `descendants` | gap `descendants` | no PID namespace on macOS |
| Withheld any-depth rows (`.git/hooks`, `.env`) | writable, captured | denied, not captured | [FW-CRED9](../formwork.md#fw-cred9) |

## 4. Surface changes (each measured against Growth)

- **`run --snapshot`** (flag). Searched: a Blueprint posture (`snapshot = true`) would let an
  auto-discovered `FORMWORK.toml` decide whether the operator's run pays the capture; `learn`
  observes denials, not writes. A flag on the one subcommand that spawns a workload is the smallest
  surface, and the operator types it.
- **`run --snapshot-exclude <pattern>`** (repeatable flag). Searched: `--subtract` and
  `--write-subtract` would deny the agent writing the cache, which is not the intent; `.gitignore`
  and `CACHEDIR.TAG` are agent-writable inputs (§3.2); a Blueprint `[snapshot]` table is a
  non-capability field, and therefore a Concepts amendment, deferred (§9). Without exclusions a Rust
  `target/` or `node_modules/` trips **snapshot-max-bytes**, so v1 needs one.
- **`formwork restore [<id> [<path>…]] [--dry-run] [--json]`** (subcommand). Searched:
  `run --restore <id>` breaks `run`'s contract — it requires a command and exits with its status
  ([FW-XR10](../formwork.md#fw-xr10)); `explain` never mutates; the `learn --list`/`--accept` review
  mode is the precedent for listing and acting in one place. One subcommand replaces nono's five
  verbs: no id lists the store's snapshots for the launch directory, `--dry-run` shows the change
  set, conflicts and gaps, every restore verifies digests first, and retention is automatic.
  `--json` is the machine door for embedders; the prose listing is not contract.
- **Report keys** `snapshot-store`, `snapshot`, and the `snapshot` section
  ([FW-FID8](../formwork.md#fw-fid8) precedent).
- **Typed errors** in `formwork-blueprint`: `SnapshotError` (`NoCaptureRoots`, `AnyDepthWriteGrant`,
  `NonUtf8Name`, `LimitExceeded { limit, observed, largest }`, `ChangedDuringCapture`,
  `Conflict { paths }`, `OutsideCaptureSet`, `DigestMismatch`, `NoFinalRecord`,
  `InterruptedRestore`, `ManifestInvalid(ManifestDefect)`), `Limit`, `ManifestDefect`. API surface;
  nothing is added in `formwork-confine`.
- **Data model:** the store layout and the manifest, final and journal records, `version: 1`.
- **Dependencies:** none new. SHA-256 comes from `ring`, already in the binary through `rustls`
  (`Cargo.toml:38-43`); `formwork-cli` gains a direct edge to it. `FICLONE`, `clonefile`, `openat`,
  `mkfifoat` and `linkat` come through `libc`, already a `formwork-cli` dependency. No `walkdir`,
  `ignore`, `globset`, `sha2` or `tempfile`.
- **Blueprint schema:** unchanged. **Concepts:** the Launcher amendment (§7 a).

## 5. Proposed requirements (draft numbering — anchored on landing)

| Req | Requirement |
|---|---|
| `FW-TRA11` **Snapshot capture** | When `formwork run` is given `--snapshot`, the Launcher shall record the baseline of every entry in the capture set (content, kind, mode, owner, size, mtime and symlink target) in the snapshot store before it spawns the workload, and shall record the final state of every entry in the capture set when the workload's direct child exits, before `run` exits. |
| `FW-TRA12` **Capture set** | The capture set shall be exactly the entries beneath the roots of the session's `writes` and `writes-no-create` grants that the compiled policy leaves writable on the host, minus each grant rooted at a host temp root or a Launcher-owned path and minus each `--snapshot-exclude` pattern; no file inside the roots shall change it. |
| `FW-TRA13` **Capture limits** | `formwork run --snapshot` shall refuse to spawn the workload, writing no snapshot, when the capture set exceeds **snapshot-max-entries** entries or **snapshot-max-bytes** bytes, naming the limit, the observed value and the three largest subtrees; before each capture it shall remove the oldest snapshots that carry no restore journal until at most **snapshot-retain** snapshots, the new one included, and at most **snapshot-store-max-bytes** remain. |
| `FW-TRA14` **Store protection** | In every session it spawns, the Launcher shall deny the confined process tree reading or writing the snapshot store root and every entry beneath it, whether or not the root exists, and renaming or removing each ancestor of the root below `$HOME`; `formwork run --snapshot` and `formwork restore` shall use a store root only when it and each ancestor below `$HOME` is a directory, not a symlink, owned by the invoking user, with the root at mode 0700. |
| `FW-TRA15` **Restore scope** | `formwork restore` shall change only entries of the snapshot's change set that lie in its recorded capture set, return each to its baseline from an object whose SHA-256 digest matches the manifest, and open every component of each path it changes relative to its parent's descriptor without following a symlink. |
| `FW-TRA16` **Conflict refusal** | `formwork restore` shall write nothing when any selected entry's current state differs from its final record, and shall list every such entry. |
| `FW-TRA17` **All-or-nothing restore** | When any operation of a restore fails, `formwork restore` shall return every selected entry to its pre-restore state before it exits non-zero; when an invocation is interrupted, the next `formwork restore` invocation shall do so before any other work. |
| `FW-FID25` **Snapshot report rows** | The FidelityReport shall carry the store denial's verdict under the key `snapshot-store` in every report, and, for a session spawned with `--snapshot`, a `snapshot` verdict with the snapshot id, store root, capture roots and each gap from the closed set of §3.7. |
| `FW-FID26` **Snapshot disclosure** | The operator channel of `formwork run --snapshot`, the snapshot manifest and every `formwork restore` output shall name the snapshot id, the store root with source `builtin`, the blueprint path with its `flag \| auto-discovered` source, and each exclusion with its `flag \| builtin` source. |

| Invariant | Statement |
|---|---|
| `FW-INV21` **Rollback confinement** | No `formwork restore` creates, modifies or removes a directory entry outside the capture set recorded in the snapshot it applies, or resolves a symlink in a path it changes, and no process in any session reads or writes a byte of the snapshot store. Falsified adversarially (`FW-ADV-043`, `FW-ADV-044`) and by the restore round-trip property (§6.3.4). |

## 6. Verification plan

Every test follows the constitution's Testing section and FEP-5 §6.1: a control run first where a
boundary is probed, positive assertion of each denial, the fastest-failing workload, and
`FW_REQUIRE_EXERCISED=1` turning a skip into a failure in CI. Tree comparisons use `tree_digest`
(§6.3.3): kind, mode, mtime, SHA-256 or link target per entry. "Both" means Linux (Landlock) and
macOS.

### 6.1 End-to-end tests (draft)

`FW-E2E-157`: **Round trip (both).** `py/harness/test_snapshot.py`. A project with files, an empty
directory, a nested tree, a mode-0750 script and a symlink. The session modifies, creates, deletes,
renames, `chmod`s, creates and removes directories, and replaces a file with a symlink, then
`restore <id>` runs. Pass: `tree_digest` equals the pre-run digest, the restore listing names every
change, and a second restore is refused as conflicting. Fail: any entry differs, or the second
restore writes. Derived from `restore_reverts_to_baseline` (`nono@9edf3ea:undo/snapshot.rs:1257`);
designs out N13 (`nono@9edf3ea:crates/nono-cli/tests/rollback_run.rs:19`).

`FW-E2E-158`: **Capture precedes spawn (both).** `py/harness/test_snapshot.py`. The least convenient
shape: the workload's first and only act is `rm -rf` of the project's `src/` and `.git/`, exiting
within milliseconds. Pass: `restore` returns the tree to its pre-run digest;
`run --snapshot --confine-self` is refused before the workload runs (its marker file never appears),
naming the spawn posture; `run --snapshot` under a read-only blueprint fails loud. Fail: any entry
unrecoverable, or the workload ran under `--confine-self`. No nono counterpart.

`FW-E2E-159`: **Capture-set boundaries (both).** `py/harness/test_snapshot.py`. Blueprint:
`readwrite:$CWD/**`, `modify:$CWD/data/**`, `readwrite:/tmp/**`, a read-only sibling, and
`--snapshot-exclude '$CWD/build/**'`. The session writes in each. Pass: project and `data/` writes
are reverted; the `/tmp` write and `build/` output survive, and the operator line lists both
exclusions with sources `builtin` and `flag`; the private `TMPDIR` is absent from the manifest; the
sibling write is denied (paired probe). On Linux a write to `.git/hooks/pre-commit` succeeds and is
reverted; on macOS it is denied and absent from the manifest. Fail: any other outcome, including an
excluded path removed by restore (N3). Derived from
`derive_snapshot_tracked_paths_include_only_writable_user_directories`
(`nono@9edf3ea:cli/rollback_runtime.rs:813`).

`FW-E2E-160`: **Limits fail loud (both).** `crates/formwork-cli/tests/snapshot_run.rs`. A tree of
**snapshot-max-entries** + 1 empty files; separately a sparse file of **snapshot-max-bytes** + 1
apparent bytes. Pass: `run --snapshot` exits non-zero before spawn (marker absent), names the limit,
the count and the largest subtree; the store holds no new snapshot and no new object; with the
excess file removed, the run succeeds. Fail: the workload runs, a partial snapshot is written, or a
subtree is excluded silently. Derived from `walk_budget_entry_limit_exceeded`,
`walk_budget_byte_limit_exceeded` (`nono@9edf3ea:undo/snapshot.rs:1849`, `:1876`); designs out N6.

`FW-E2E-161`: **Store unreachable (both).** Kernel half in
`crates/formwork-confine/tests/snapshot_store.rs`, CLI half in `py/harness/test_snapshot.py`. Probe
classes at the session's first syscall, under ambient reads and under `readwrite:~/**`: read an
object, list the store, create, modify, rename into or out of it, create the root when absent,
rename an ancestor. Pass: the unconfined control succeeds for each probe; confined, each fails with
`EACCES`/`EPERM`, and the store's digest is unchanged after the run; a confined `formwork restore`
fails; on Linux under `readwrite:~/**` the split directories are named on the operator channel.
Fail: any confined probe succeeds. Inverts
`nono@9edf3ea:tests/integration/test_rollback_dest_edge_cases.sh:57-89`.

`FW-E2E-162`: **Conflicts and operator files (both).** `py/harness/test_snapshot.py`. The session
modifies `a.txt` and `b.txt`; after it exits the operator edits `b.txt` and creates `mine.txt`.
Pass: `restore <id> --dry-run` lists both changes and the `b.txt` conflict and writes nothing;
`restore <id>` exits non-zero, writes nothing and lists `b.txt`; `restore <id> a.txt` restores
`a.txt`; `b.txt` and `mine.txt` keep the operator's bytes throughout. Fail: any operator byte lost.
Derived from `compute_restore_diff_shows_changes_without_modifying_disk`
(`nono@9edf3ea:undo/snapshot.rs:1597`); designs out N2 and N13
(`nono@9edf3ea:crates/nono-cli/tests/rollback_run.rs:75`).

`FW-E2E-163`: **All-or-nothing (both).** `crates/formwork-cli/tests/snapshot_run.rs`. A change set
of 50 files across directories; after the session the operator sets mode 0555 on `zz/`, a directory
the session did not change, which holds the last file in apply order. Pass: restore fails at that
file, exits non-zero, and all 50 entries hold their pre-restore digests. Second case, no gate:
restore is killed with `SIGKILL` once `journal.json` exists; the next `formwork restore` reports the
reverted journal first, every entry holds its pre-restore digest, and the restore then succeeds.
Fail: a mixed tree after either case. Gate: the first case runs as a non-root user (euid 0 ignores
directory modes) and calls `not_exercised` otherwise. No nono counterpart (N10).

`FW-E2E-164`: **Links, special files, modes (both).** `py/harness/test_snapshot.py`. Baseline: a
symlink to an outside target, a dangling symlink, a FIFO, a hardlink pair, a file linked from
outside the set, a 4755 file, a 2775 directory, a socket. The session deletes both symlinks,
replaces `sub/` with a symlink to an outside directory, removes the FIFO, rewrites both linked
files. Pass: the symlinks are recreated with their target bytes; `sub/` is a directory again and the
outside directory's digest is unchanged; the FIFO and the pair are back; the outside-linked file is
split and its outside name keeps the session's bytes; modes match all 12 bits; the socket is listed
`not-restorable`. Fail: any target written, a link not recreated, or a mode masked. Derived from
`restore_removes_symlinks_created_during_session`, `restore_keeps_symlinks_present_at_baseline`,
`restore_rejects_symlinked_parent_directory` (`nono@9edf3ea:undo/snapshot.rs:1351`, `:1390`,
`:1288`); designs out N8, N9, N10.

`FW-E2E-165`: **Git working tree (both).** `py/harness/test_snapshot.py`, needs `git`. A repository
with three commits, a branch, a stash and an ignored `.env`. The session commits, creates a branch,
`reset --hard HEAD~2`, `gc --prune=now` and deletes `.env`. Pass: after restore
`git rev-parse HEAD`, `git branch`, `git stash list` and `git status --porcelain` equal the
baseline, `git fsck --full` is clean, `.env` is back. Fail: any differs. Designs out N5.

`FW-E2E-166`: **Report and disclosure (both).** `py/harness/test_snapshot.py`. Pass:
`explain --json` carries `snapshot-store` `Enforced` with backend `landlock` or `seatbelt`, and
`explain <store>/x` reports read and write denied by a `built-in` rule; under `readwrite:$CWD/**`
alone the `snapshot` row is `Partial` with exactly `descendants` (`Enforced` on `ubuntu-22.04` with
`isolate = ["processes"]`), and adding `/tmp/**` adds `host-temp-grant`; the operator line names id,
store (`builtin`), roots, counts and each exclusion with its source; `manifest.json` matches the
golden key set and names the blueprint with source `auto-discovered` when run from a directory
holding `FORMWORK.toml`; `restore --json` starts with the id and that blueprint; `run`'s stdout is
empty. Fail: any field missing or wrong.

`FW-E2E-167`: **Final record and surviving descendants (both).**
`crates/formwork-cli/tests/snapshot_run.rs`. The workload starts a background child that writes
`late.txt` and rewrites `a.txt` 500 ms after the direct child exits. Pass: the run's `snapshot` row
carries `descendants`; `restore` refuses with `a.txt` as a conflict and leaves `late.txt`; on
`ubuntu-22.04` under `isolate = ["processes"]` the late writes never happen and the gap is absent.
Fail: a late write reverted without a conflict, or the gap absent where descendants survive. Settles
the §3.3 **(characterize)** mark.

`FW-E2E-168`: **Store root and retention (both).** `py/harness/test_snapshot.py`. Pass: the first
capture creates the root 0700 owned by the user with `store.json`; a root that is a symlink, a root
at mode 0755, and a non-empty root without `store.json` each refuse `run --snapshot` before spawn
naming the path; after **snapshot-retain** + 1 captures the oldest id is removed and named, its
unshared objects swept; a snapshot with a journal survives pruning. Fail: any refusal missing or any
wrong snapshot removed. Derived from `ensure_session_dir_sets_0700_permissions`
(`nono@9edf3ea:cli/rollback_runtime.rs:746`) and
`nono@9edf3ea:tests/integration/test_rollback_dest_edge_cases.sh:176-217`; designs out N11.

### 6.2 Adversarial tests (draft)

`FW-ADV-043`: **Store tampering from a session (both).** `py/harness/test_snapshot.py` and
`crates/formwork-confine/tests/snapshot_store.rs`. Property: no confined process, in a session with
or without `--snapshot`, under ambient reads and under a write grant covering `$HOME`, can read,
forge, alter, plant or relocate any part of the store. Probe classes: pre-creating the root while
absent, replacing an ancestor with a symlink or a renamed directory, hardlinking into or out of the
store, writing a forged snapshot directory. Pass: each is denied; the next `restore` lists only
Formwork-created snapshots and verifies their digests. Fail: any probe changes, discloses or plants
a store byte. Inverts `nono@9edf3ea:tests/integration/test_rollback_dest_edge_cases.sh:219-232`.

`FW-ADV-044`: **Restore redirection (both).** `crates/formwork-cli/tests/snapshot_run.rs`. Property:
whatever state the session leaves, restore writes nothing outside the recorded capture set
(`FW-INV21`). Probe classes: a symlinked directory at a restore parent, a symlink where a file will
be restored, a symlink swapped in by a surviving descendant during the restore (the
[FW-ADV-002](../formwork.md#fw-adv-002) race class), a forged manifest path with `..` or outside the
roots. Pass: the digest of an outside canary tree is unchanged, and restore completes inside the set
or refuses. Fail: any outside byte changes. Derived from
`restore_rejects_symlink_before_create_dir_all`, `validate_manifest_rejects_parent_dir_traversal`
(`nono@9edf3ea:undo/snapshot.rs:1323`, `:1709`) and `nono@9edf3ea:CHANGELOG.md:1732`, `:3523`.

`FW-ADV-045`: **Capture-scope and record manipulation (both).** `py/harness/test_snapshot.py`.
Property: an earlier session cannot shrink the next capture, and a session cannot defeat its own
final record. Probe classes: marker files (`.gitignore` entries, `CACHEDIR.TAG`, `.formwork/`
content) planted under the roots; a tree grown past a limit; directories made unreadable before
exit. Pass: the capture set is identical with and without the markers; the grown tree refuses the
next run rather than excluding anything; restore returns the unreadable directories and their
contents to baseline, listed `unverified`. Fail: any marker changes the set, or any entry is left
out silently. Designs out N6 (`nono@9edf3ea:cli/rollback_preflight.rs:18-31`;
`nono@9edf3ea:CHANGELOG.md:3511`).

### 6.3 Unit and property tests

#### 6.3.1 Where the tests live

| Module | Layer | Why there |
|---|---|---|
| `crates/formwork-blueprint/src/snapshot.rs` `#[cfg(test)] mod tests` | pure | capture set, limits, change set, restore plan and manifest are functions of records and patterns: no kernel, no filesystem |
| `crates/formwork-blueprint/tests/fixtures/snapshot-{manifest,final,journal}-v1.json` | pure (golden) | Data-model shapes (§6.3.4 pattern 4) |
| `crates/formwork-compile/src/report.rs` and `lib.rs` tests | pure | the two report rows and the `snapshot` section; byte determinism ([FW-FID4](../formwork.md#fw-fid4)) |
| `crates/formwork-cli/src/snapshot.rs` `#[cfg(test)] mod tests` | impure, tempdir only | clone or copy, digests, no-follow opens, journal; `formwork-cli` is a binary crate, so its internals are tested in-module |
| `crates/formwork-confine/tests/snapshot_store.rs` | kernel | the store denial against Landlock and Seatbelt, paired probes |
| `crates/formwork-cli/tests/snapshot_run.rs` | CLI shell | `FW-E2E-160`, 163, 167 and `FW-ADV-044`, which need 300,001 files, `SIGKILL`, timed descendants and a racing thread |
| `py/harness/test_snapshot.py` | black box | the remaining E2E and ADV tests, each with `@pytest.mark.fw_e2e` or `fw_adv`; tests for both platforms carry no platform marker (the conftest skips a test carrying both, `py/harness/conftest.py:46-60`) and gate on the `confiner` fixture |

#### 6.3.2 The test list

`crates/formwork-blueprint/src/snapshot.rs` — nono's `undo/snapshot.rs` carries 31 tests and
`undo/types.rs` 8; this module plans 33. Fixtures are §6.3.3's; `p(s)` is `PathBuf::from(s)`. In the
last column a bare `:<line>` is in `nono@9edf3ea:undo/snapshot.rs`.

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `capture_roots_are_write_grant_roots_of_both_grades` | `FW-TRA12` | `write_view`, `ctx` | writes `/w/proj/**`, no-create `/w/data/**` → `capture_spec(&view, &ctx())` → `assert_eq!(spec.roots, [p("/w/data"), p("/w/proj")])` | `derive_snapshot_tracked_paths_include_only_writable_user_directories` (`nono@9edf3ea:cli/rollback_runtime.rs:813`) |
| `read_only_blueprint_has_no_capture_roots` | `FW-TRA12` | same | reads only → `matches!(err, SnapshotError::NoCaptureRoots)` | regression N11 (`nono@9edf3ea:cli/rollback_runtime.rs:422-426`) |
| `host_temp_root_grant_is_excluded_but_grant_below_it_is_captured` | `FW-TRA12` | same | writes `/tmp/**`, `/tmp/proj/**` → roots `[p("/tmp/proj")]`; `excluded[0] == Exclusion { pattern: "/tmp/**", source: Source::Builtin, reason: Reason::HostTempRoot }` | — |
| `launcher_owned_tmp_is_excluded` | `FW-TRA12` | same | `ctx().launcher_owned = [p("/t/fw-session-1")]`, granted → not a root, reason `LauncherOwned` | [FW-E2E-089](../formwork.md#fw-e2e-089) |
| `any_depth_write_grant_fails_loud` | `FW-TRA12` | same | writes `**/cache/**` → `matches!(err, SnapshotError::AnyDepthWriteGrant { .. })` | — |
| `installed_deny_removes_entry_withheld_row_keeps_it` | `FW-TRA12` | `write_view_withheld` | same tree, write-subtract `**/.git/hooks/**` installed vs withheld → `.git/hooks/pre-commit` absent vs present in `spec.select(&inventory)` | — |
| `flag_exclusion_prunes_subtree_and_is_recorded` | `FW-TRA12` | `write_view`, `inventory` | `--snapshot-exclude /w/proj/target/**` → no entry under `target`; exclusion source `Source::Flag` | `collect_atomic_temp_prunes_excluded_dirs` (`nono@9edf3ea:undo/snapshot.rs:1972`) |
| `planted_markers_do_not_change_the_capture_set` | `FW-TRA12` | `inventory` | inventory with and without `.gitignore` = `"*"`, `src/CACHEDIR.TAG` → `assert_eq!` selected sets minus the marker files | regression N6 |
| `entries_at_limit_pass_and_one_more_fails` | `FW-TRA13` | `inventory_of(n)` | `Limits { entries: 3, bytes: 0 }`, n = 3 then 4 → `Ok`, then `LimitExceeded { limit: Limit::Entries, observed: 4, .. }` | `walk_budget_entry_limit_exceeded` (`nono@9edf3ea:undo/snapshot.rs:1849`) |
| `bytes_at_limit_pass_and_one_more_fails` | `FW-TRA13` | `inventory` | 10 bytes at limit 10, then 11 → `Ok`, then `Limit::Bytes, observed: 11` | `walk_budget_byte_limit_exceeded`, `budget_checked_for_tracked_files` (`:1876`, `:1903`) |
| `empty_capture_set_is_within_limits` | `FW-TRA13` | `inventory_of(0)` | → `assert_eq!(totals, Totals::default())` | — |
| `symlink_target_size_is_not_counted` | `FW-TRA13` | `inventory` | link to a 64 KiB file, limit 4,096 bytes → `Ok`, link recorded as `Kind::Symlink` | `symlink_to_large_file_not_counted_against_budget` (`:1943`) |
| `limit_error_names_three_largest_subtrees` | `FW-TRA13` | `inventory` | five subtrees of 5..1 bytes, limit 1 → `largest == [a, b, c]` by bytes | — |
| `prune_plan_keeps_retain_newest_and_journalled` | `FW-TRA13` | `store_index` | 11 snapshots, oldest journalled, retain 10 → removes the second-oldest only | — |
| `changed_tuple_during_capture_is_an_error` | `FW-TRA11` | `tuple` | before ≠ after `ctime` → `matches!(err, SnapshotError::ChangedDuringCapture { .. })` | regression N7 (`nono@9edf3ea:undo/object_store.rs:290-300`) |
| `non_utf8_name_fails_loud` | `FW-TRA11` | raw `OsString` name | → `NonUtf8Name { parent: p("/w/proj") }` | — |
| `change_set_detects_create_modify_delete_mode_link` | `FW-TRA11` | `record`, `with` | one of each → `assert_eq!(kinds, [Created, Modified, Deleted, Mode, LinkTarget])` | `incremental_detects_{modification,creation,deletion}` (`:1190`, `:1215`, `:1236`) |
| `unchanged_tuple_is_not_a_change` | `FW-TRA11` | `record` | identical records → `change_set(..).is_empty()` | `merkle_root_differs_between_snapshots` (`:1479`, inverse) |
| `directory_created_and_removed_are_changes` | `FW-TRA11` | `record`, `dir()` | → `Created` for the new dir, `Deleted` for the removed one | — |
| `restore_plan_applied_to_final_yields_baseline` | `FW-TRA15` | `record`, `apply` | B, F from `baseline_two_files` → `apply(&f, &plan_restore(&b, &f, &f, &[])?) == b` | `restore_reverts_to_baseline` (`:1257`); regression N4 |
| `restore_plan_leaves_operator_files_and_refuses_conflicts` | `FW-TRA15`, `FW-TRA16` | §6.3.5 | §6.3.5 | regression N2 (`nono@9edf3ea:undo/snapshot.rs:351-366`) |
| `excluded_entry_is_never_in_plan` | `FW-TRA15` | `record`, `ctx` | current holds `/w/proj/build/x` under a flag exclusion → absent from `plan.paths()` | regression N3 (`nono@9edf3ea:cli/rollback_commands.rs:635-652`) |
| `selection_narrows_plan_to_subtree` | `FW-TRA15` | `record` | changes in `a/` and `b/`, selection `[p("/w/proj/a")]` → only `a/` paths | — |
| `not_restorable_entries_are_listed_and_never_removed` | `FW-TRA15` | `record`, `socket()`, `unreadable()` | → `plan.not_restorable == [..]`, no op names them | regression N7 (`nono@9edf3ea:undo/snapshot.rs:777-779`) |
| `session_symlink_removed_before_baseline_dir_created` | `FW-TRA15` | `record`, `link`, `dir` | B: `sub/` dir; F: `sub` link → ops `[Unlink(sub), Mkdir(sub), ..]` in that order | `restore_rejects_symlinked_parent_directory` (`:1288`) |
| `opaque_directory_entries_are_planned_unverified` | `FW-TRA15` | `record`, `opaque()` | F marks `x/` opaque → entries beneath carry `Verify::Unverified` | — |
| `conflict_lists_every_conflicting_path` | `FW-TRA16` | `record`, `with` | 3 changed, 2 edited after F → `Conflict { paths }` with exactly those 2, sorted | — |
| `second_restore_conflicts_everywhere` | `FW-TRA16` | `record`, `apply` | `c = apply(f, plan)`, plan again → `Conflict` naming every change | — |
| `snapshot_without_final_record_is_refused` | `FW-TRA16` | `record` | final `None` → `matches!(err, SnapshotError::NoFinalRecord)` | — |
| `manifest_rejects_parent_dir_component` | `FW-INV21` | `manifest_with` | `/w/proj/sub/../../etc/passwd` → `ManifestInvalid(ManifestDefect::ParentComponent)` | `validate_manifest_rejects_parent_dir_traversal` (`:1709`) |
| `manifest_rejects_path_outside_roots` | `FW-INV21` | `manifest_with` | `/tmp/not-tracked/secret.txt` → `ManifestDefect::OutsideRoots` | `validate_manifest_rejects_path_outside_tracked` (`:1754`) |
| `manifest_round_trips_byte_identically` | `FW-FID26` | `baseline_two_files` | `to_json` → `from_json` → `to_json` equal bytes; unknown `version: 2` → `ManifestDefect::Version(2)` | `manifest_roundtrip_via_disk` (`:1547`), `snapshot_manifest_serde_roundtrip` (`nono@9edf3ea:undo/types.rs:616`) |
| `golden_manifest_v1_parses_with_exact_keys` | `FW-FID26` | golden file | parse fixture; `BTreeSet` of top-level and entry keys equals the documented set | `assert_properties_at` (`nono@9edf3ea:crates/nono-cli/tests/schema_shape.rs:11-40`) |

`crates/formwork-compile` (`src/lib.rs` tests) — nono has no report; 7 tests, each on the existing
`HostProfile::synthetic_linux` / `synthetic_macos` constructors and a `snapshot_spec()` fixture
(`SessionSpec` with id `00000000000000aa` and store `/h/.local/state/formwork/snapshots`):

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `snapshot_keys_round_trip` | `FW-FID25` | — | `Capability::from_key(&c.as_key()) == Some(c)` for both new variants | — |
| `snapshot_store_enforced_on_both_synthetic_hosts` | `FW-FID25` | synthetic hosts | compile any blueprint → `Fidelity::Enforced { backend: Backend::Landlock }`, then `Backend::Seatbelt` | — |
| `store_ancestor_literals_rendered_on_seatbelt_only` | `FW-TRA14` | `snapshot_spec()`, synthetic hosts | macOS profile contains a literal write deny for each of the three ancestors; the Linux plan holds the subtree hole and no ancestor hole | `emit_protected_root_deny_rules_adds_platform_rules` (`nono@9edf3ea:cli/protected_paths.rs:437`) |
| `snapshot_store_unenforceable_without_landlock` | `FW-FID25` | `synthetic_linux(None)` | → `matches!(f, Fidelity::Unenforceable { .. })` | — |
| `snapshot_row_gaps_name_host_temp_grant` | `FW-FID25` | `snapshot_spec()` | `builtin:default` → `gaps == [Gap::HostTempGrant, Gap::Descendants]`, verdict `Partial` | — |
| `snapshot_row_enforced_under_isolate_processes` | `FW-FID25` | `snapshot_spec()` | Linux, `isolate = ["processes"]`, writes `/w/proj/**` only → `Enforced { backend: Backend::Launcher }` | — |
| `session_with_snapshot_compiles_byte_identically` | `FW-FID25` | golden `report-snapshot-v1.json` | two compiles → `assert_eq!` on serialized bytes and on the golden | [FW-E2E-027](../formwork.md#fw-e2e-027) |

`crates/formwork-cli/src/snapshot.rs` — nono's `undo/object_store.rs` carries 10 tests; this module
plans 14. In the last column a bare `:<line>` is in `nono@9edf3ea:undo/object_store.rs`. The two
tests that rely on a 0555 directory run as a non-root user and call `not_exercised` under euid 0.

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `object_is_named_by_digest_of_stored_bytes` | `FW-TRA11` | `make_store` | store `file1.txt` → object path `objects/<2>/<62>` of `ring::digest::SHA256` over the object's bytes | `store_file_roundtrip` (`nono@9edf3ea:undo/object_store.rs:387`) |
| `identical_content_is_stored_once_across_snapshots` | `FW-TRA13` | `make_store` | two captures of one file → one object, two manifests referencing it | `deduplication` (`:398`) |
| `clone_or_copy_produces_identical_bytes` | `FW-TRA11` | `make_store` | → bytes equal; `mode` is `CopyMode::Reflink` or `CopyMode::Copy`, both accepted | `clone_or_copy_produces_identical_content` (`:455`) |
| `large_file_is_streamed` | `FW-TRA11` | `make_store` | 3 × 64 KiB + 7 bytes → round trip equal | `store_file_streams_without_full_buffer` (`:470`) |
| `corrupted_object_fails_before_any_write` | `FW-TRA15` | `make_store` | overwrite an object, restore → `DigestMismatch` downcast; target tree digest unchanged | `verify_detects_corruption` (`:417`) |
| `inventory_records_link_target_without_following` | `FW-TRA11` | `setup_test_dir` | link to `../outside.txt` → `target == "../outside.txt"`, no object for the target | `restore_keeps_symlinks_present_at_baseline` (`nono@9edf3ea:undo/snapshot.rs:1390`) |
| `inventory_never_descends_a_symlinked_root` | `FW-TRA12` | `setup_test_dir` | root is a link → inventory empty, error `SymlinkedRoot` | `restore_never_removes_a_symlinked_tracked_root` (`nono@9edf3ea:undo/snapshot.rs:1448`) |
| `open_beneath_refuses_symlink_in_any_component` | `FW-INV21` | `setup_test_dir` | `sub` → outside dir, `open_beneath(root, "sub/f")` → `raw_os_error() == Some(libc::ELOOP)`; outside untouched | `restore_rejects_symlink_before_create_dir_all` (`nono@9edf3ea:undo/snapshot.rs:1323`) |
| `restore_unlinks_session_symlink_without_touching_target` | `FW-INV21` | `make_store` | planted and dangling links → both gone, target bytes unchanged | `restore_removes_symlinks_created_during_session` (`nono@9edf3ea:undo/snapshot.rs:1351`) |
| `fifo_recreated_socket_listed` | `FW-TRA15` | `make_store` | → `S_ISFIFO` restored; socket in `not_restorable` | — |
| `modes_restore_all_twelve_bits_and_failure_is_an_error` | `FW-TRA15` | `make_store` | baseline 4755 → `mode & 0o7777 == 0o4755`; on a target whose parent is 0555 → error, not a warning | regression N10 (`nono@9edf3ea:undo/snapshot.rs:325-333`) |
| `apply_failure_reverts_every_applied_operation` | `FW-TRA17` | `make_store` | 5 ops, parent of the 4th made 0555 after planning → `Err`; all 5 entries at pre-restore digests | — |
| `recover_reverts_a_hand_built_partial_journal` | `FW-TRA17` | `make_store` | journal + tree with 2 of 4 ops applied → `recover()` → pre-restore digests, journal removed | — |
| `store_root_symlink_or_loose_mode_is_refused` | `FW-TRA14` | `setup_test_dir` | root link → `StoreRoot::Symlink`; mode 0755 → `StoreRoot::Mode(0o755)` | `ensure_session_dir_sets_0700_permissions` (`nono@9edf3ea:cli/rollback_runtime.rs:746`) |

`crates/formwork-confine/tests/snapshot_store.rs` — nono tests its state root at the grant level
(`nono@9edf3ea:cli/protected_paths.rs`, 12 tests), never against the kernel; 4 tests here. Each
compiles a Blueprint carrying the Launcher's store rows, runs `sh -c` probes through
`spawn_confined` (the `run` and `sh` helpers, `linux_confine.rs:60-76`), asserts the unconfined
control exits 0 and the confined probe non-zero, and compares the store's digest before and after.

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `store_subtree_denied_under_ambient_reads` | `FW-TRA14`, `FW-INV21` | `StoreFixture::new(tag)` | `read-mode = "ambient-minus-subtract"` → `cat`, `ls`, append on an object each exit non-zero | `inside_protected_root_always_blocked` (`nono@9edf3ea:cli/protected_paths.rs:278`) |
| `absent_store_root_cannot_be_created` | `FW-TRA14` | same, root removed | `mkdir -p <store>` → non-zero; root still absent | `requested_path_blocks_nonexistent_child_under_protected_root` (`:347`) |
| `store_ancestor_cannot_be_renamed` | `FW-TRA14` | same | `readwrite:<home>/**`, `mv <home>/.local/state/formwork …` → non-zero | `emit_protected_root_deny_rules_adds_platform_rules` (`:437`) |
| `store_denied_under_write_grant_covering_home` | `FW-TRA14`, `FW-INV21` | same | `readwrite:<home>/**` → write and create beneath the store non-zero; a sibling of `.local` writable (paired) | `parent_directory_capability_blocked_even_with_opt_in_on_linux` (`:257`), which Formwork replaces with a split |

#### 6.3.3 Fixtures and helpers to add

- **Pure records** (`formwork-blueprint`, test-only): `fn record(entries: &[(&str, E)]) -> Record`;
  `fn file(bytes: &[u8]) -> E`, `fn dir() -> E`, `fn link(target: &str) -> E`, `fn socket() -> E`,
  `fn unreadable() -> E`, `fn opaque() -> E`; `Record::with(&self, &[(&str, E)]) -> Record`, which
  gives every replaced or added entry a fresh synthetic tuple (`ctime` from a per-record counter,
  digest the SHA-256 of the bytes), so a change is always visible to the tuple comparison;
  `fn baseline_two_files() -> Record` holds `/w/proj/file1.txt` = `hello world` and
  `/w/proj/file2.txt` = `goodbye world`, nono's `setup_test_dir` contents
  (`nono@9edf3ea:undo/snapshot.rs:1147-1154`); `fn apply(r: &Record, plan: &RestorePlan) -> Record`,
  the in-memory interpreter of a plan.
- **Capture inputs:**
  `fn write_view(writes: &[&str], no_create: &[&str], denies: &[&str]) -> WriteView`,
  `fn write_view_withheld(..)` with a withheld list, `fn ctx() -> CaptureContext` (host temp roots
  `/tmp`, `/private/tmp`, `/var/tmp`, `/private/var/tmp`; no Launcher-owned paths),
  `fn inventory(entries: &[(&str, u64)]) -> Vec<Entry>`, `fn inventory_of(n: usize) -> Vec<Entry>`,
  `fn store_index(ids: &[(&str, bool)]) -> StoreIndex`,
  `fn manifest_with(paths: &[&str]) -> String`. These mirror
  `make_manager`/`make_manager_with_budget` (`nono@9edf3ea:undo/snapshot.rs:1156-1171`,
  `:1827-1846`): limits are a `Limits` parameter, so no test builds 300,000 files.
- **Tempdir** (`formwork-cli`, in-module): `fn setup_test_dir(tag: &str) -> (TestDir, PathBuf)`
  returns an RAII `TestDir` under `std::env::temp_dir()/formwork-snap-<tag>-<pid>` with `project/`
  holding nono's two files, plus `fn make_store(dir: &TestDir) -> Store` (root `dir/store`, 0700)
  and `fn make_store_with_limits(dir: &TestDir, limits: Limits) -> Store`. No `tempfile` dependency;
  the `Scratch` shape (`crates/formwork-cli/tests/support/mod.rs:15-34`).
- **Isolated home for binary-driven tests:**
  `support::Scratch::snapshot_home(tag) -> SnapshotHome { home, project, outside, store }` with
  `HOME = <scratch>/home`, the project at `<scratch>/work/project` (a sibling of `home`, so a
  project grant does not cover the store unless a test grants `<scratch>/**` on purpose), an
  `outside` canary tree, and `store = home/.local/state/formwork/snapshots`. The scratch stays under
  `std::env::temp_dir()`, never a bind mount: nono's `NonoTest` records that a FUSE bind mount
  accepts Landlock rules without enforcing them
  (`nono@9edf3ea:crates/nono-test-support/src/lib.rs:20-70`, `nono_test!` at `:156`).
- **py harness:** a `snap` fixture returning
  `SnapEnv(home, project, outside, store, blueprint, env)` with `env = {"HOME": str(home)}`;
  `tree_digest(root) -> dict[str, tuple]` (kind, mode, mtime, SHA-256 or link target, `lstat` only);
  `latest_snapshot(cli, snap) -> str` from `restore --json` (never parsed from prose); and a
  `confiner` fixture that skips locally and fails under `FW_REQUIRE_EXERCISED=1` when
  `explain --json` reports neither Landlock nor Seatbelt.
- **Kernel fixture:** `StoreFixture::new(tag: &str) -> StoreFixture` in `snapshot_store.rs` builds
  `<tmp>/home/.local/state/formwork/snapshots` with one object and a sibling `<tmp>/home/notes`, on
  the `Fixture` pattern of `linux_confine.rs:79-110`, and removes it on drop.
- **Confine gating:** `crates/formwork-confine/tests/snapshot_store.rs` gains a
  `not_exercised(reason)` copy of `support::not_exercised`
  (`crates/formwork-cli/tests/support/mod.rs:126-133`) in place of the `eprintln!` and `return` at
  `linux_confine.rs:136-140`.

#### 6.3.4 Patterns adopted from nono, and the ones designed out

1. **Irreversible kernel calls in a child.** The store-denial tests install the policy in a spawned
   child through `formwork_confine::spawn_confined`, never in the test process; the parent asserts
   the exit status, as nono's fork tests assert `WIFEXITED`/`WEXITSTATUS`
   (`nono@9edf3ea:crates/nono/src/sandbox/linux.rs:5993-6030`). Restore itself is not irreversible
   and runs in-process.
2. **Host-capability gating — designed out.** nono returns early and passes on a kernel without the
   feature (`nono@9edf3ea:crates/nono/src/sandbox/linux.rs:5994-6003`). Every gated test here calls
   `not_exercised(reason)` or the `confiner` fixture, naming its gate: Landlock or Seatbelt
   (`FW-E2E-161`, `FW-ADV-043`); `git` on `PATH` (`FW-E2E-165`); `ubuntu-22.04` user namespaces
   (`FW-E2E-167`'s isolate case). Reflink support is not a gate: both copy modes pass.
3. **Environment as a parameter.** nono serializes env-mutating tests behind `ENV_LOCK` and
   `EnvVarGuard` (`nono@9edf3ea:cli/test_env.rs:15-18`). Here `store_root(home: &Path)`,
   `capture_spec(&WriteView, &CaptureContext)` (host temp roots and Launcher-owned paths passed in)
   and the `confstr` temp root (read once by the CLI and passed in) take their environment as input;
   no test mutates the process environment.
4. **Contract shapes.** The manifest, final record, journal, the `snapshot` report section and
   `restore --json` each get a `BTreeSet` key-set test in nono's `assert_properties_at` style
   (`nono@9edf3ea:crates/nono-cli/tests/schema_shape.rs:11-40`) and a golden file:
   `crates/formwork-blueprint/tests/fixtures/snapshot-manifest-v1.json`, `snapshot-final-v1.json`,
   `snapshot-journal-v1.json`, `crates/formwork-compile/tests/fixtures/report-snapshot-v1.json`,
   `crates/formwork-cli/tests/fixtures/restore-list-v1.json`. The report fixture is also compiled
   twice for [FW-FID4](../formwork.md#fw-fid4).
5. **Property test.** The property: for any baseline tree of at most 32 entries and depth 4, and any
   sequence of at most 16 operations from {create, modify, delete, chmod, mkdir, rmdir, symlink,
   replace-directory-with-symlink, hardlink}, `apply(&f, &plan_restore(&b, &f, &f, &[])?) == b`, and
   no plan op names a path outside `b`'s roots. Strategies `arb_tree()` and `arb_ops(&tree)`, 64
   cases (`ProptestConfig::with_cases(64)`, as in
   `nono@9edf3ea:crates/nono-cli/tests/manifest_roundtrip.rs:710-870`). Formwork has no `proptest`
   and `docs/STATUS.md` owes the property infrastructure, so the stand-in is
   `restore_round_trip_examples`, a table of 12 hand-written sequences (one per operation, plus
   three mixed); it is registered as a tracked test-method exception for `FW-INV21` (§7 h) beside
   [FW-INV1](../formwork.md#fw-inv1), [FW-INV2](../formwork.md#fw-inv2) and
   [FW-INV4](../formwork.md#fw-inv4).
6. **Regressions named for the defect.** Each N-row of §2.3 that has a unit test carries a doc
   comment naming the nono path and line it pins, in the style of the module doc of
   `nono@9edf3ea:crates/nono-cli/tests/why_deny.rs:1-4`, and the test name states the corrected
   behavior.
7. **Typed assertions, not prose.** nono asserts `err_msg.contains("budget exceeded")`
   (`nono@9edf3ea:undo/snapshot.rs:1868-1872`); these tests use `matches!` on `SnapshotError`
   variants, `Limit`, `ManifestDefect` and `Gap`, and `raw_os_error()` for kernel refusals.
8. **Shell suites — designed out.** nono's
   `expect_success`/`expect_failure`/`expect_output_contains`
   (`nono@9edf3ea:tests/lib/test_helpers.sh:78-170`) and `require_working_sandbox` (`:322-330`)
   become pytest functions with markers. `nono@9edf3ea:tests/integration/test_rollback.sh:46-53`
   maps to `FW-E2E-157`, `:118-137` and the edge-case suite to `FW-E2E-161`, `FW-E2E-168` and
   `FW-ADV-043`; no case skips silently.

#### 6.3.5 Worked example

```rust
/// Regression: nono@9edf3ea:crates/nono/src/undo/snapshot.rs:351-366 deletes every file the
/// baseline lacks, so restore removes a file the operator created after the session ended.
#[test]
fn restore_plan_leaves_operator_files_and_refuses_conflicts() {
    // FW-TRA15, FW-TRA16
    let baseline = baseline_two_files();
    let last = baseline.with(&[
        ("/w/proj/file1.txt", file(b"modified")),
        ("/w/proj/new.txt", file(b"new file")),
    ]);
    let current = last.with(&[("/w/proj/operator.txt", file(b"mine"))]);

    let plan = plan_restore(&baseline, &last, &current, &[]).expect("no conflict");
    assert_eq!(plan.paths(), vec![p("/w/proj/file1.txt"), p("/w/proj/new.txt")]);
    let restored = apply(&current, &plan);
    assert_eq!(restored.get(&p("/w/proj/file1.txt")), baseline.get(&p("/w/proj/file1.txt")));
    assert!(restored.get(&p("/w/proj/new.txt")).is_none());
    assert_eq!(restored.get(&p("/w/proj/operator.txt")), current.get(&p("/w/proj/operator.txt")));

    let edited = current.with(&[("/w/proj/file1.txt", file(b"operator edit"))]);
    let err = plan_restore(&baseline, &last, &edited, &[]).unwrap_err();
    assert!(matches!(&err, SnapshotError::Conflict { paths }
        if paths == &vec![p("/w/proj/file1.txt")]));
}
```

```python
@pytest.mark.fw_e2e("FW-E2E-158")
def test_snapshot_precedes_a_millisecond_destructive_workload(cli, snap, confiner):
    """The workload deletes src/ and .git/ as its only act and exits within milliseconds."""
    before = tree_digest(snap.project)
    run = cli("run", "--snapshot", "--blueprint", snap.blueprint, "--",
              "/bin/rm", "-rf", snap.project / "src", snap.project / ".git",
              cwd=snap.project, env=snap.env)
    assert run.code == 0, run.stderr
    assert run.stdout == ""  # FW-XR10: run writes nothing of its own to stdout
    restored = cli("restore", latest_snapshot(cli, snap), cwd=snap.project, env=snap.env)
    assert restored.code == 0, restored.stderr
    assert tree_digest(snap.project) == before
```

### 6.4 Traceability (draft rows for formwork.md §10)

| Requirement | Primary test | Also |
|---|---|---|
| `FW-TRA11` Snapshot capture | `FW-E2E-158` | `FW-E2E-157`, `FW-E2E-167` |
| `FW-TRA12` Capture set | `FW-E2E-159` | `FW-E2E-165`, `FW-ADV-045` |
| `FW-TRA13` Capture limits | `FW-E2E-160` | `FW-E2E-168`, `FW-ADV-045` |
| `FW-TRA14` Store protection | `FW-E2E-161` | `FW-E2E-168`, `FW-ADV-043` |
| `FW-TRA15` Restore scope | `FW-E2E-157` | `FW-E2E-164`, `FW-E2E-165`, `FW-ADV-044` |
| `FW-TRA16` Conflict refusal | `FW-E2E-162` | `FW-E2E-167` |
| `FW-TRA17` All-or-nothing restore | `FW-E2E-163` | — |
| `FW-FID25` Snapshot report rows | `FW-E2E-166` | `FW-E2E-159`, `FW-E2E-167` |
| `FW-FID26` Snapshot disclosure | `FW-E2E-166` | `FW-E2E-159` |
| `FW-INV21` Rollback confinement | `FW-ADV-044` | `FW-ADV-043`, `FW-E2E-161`, `FW-E2E-164`; property stand-in (§6.3.4) |

### 6.5 Phasing

- **Phase 0** — the pure core in `formwork-blueprint` and its 33 unit tests. Nothing runs
  differently.
- **Phase 1** — the store denial in every session (`FW-TRA14`) with the `snapshot-store` row,
  `FW-E2E-161` and `FW-ADV-043`. It lands before any capture code, so no release ever writes a
  snapshot a session could reach.
- **Phase 2** — capture, final record, limits, retention, `run --snapshot` and `--snapshot-exclude`,
  the `snapshot` row and the disclosure line.
- **Phase 3** — `formwork restore` (listing, `--dry-run`, `--json`, apply, journal, recovery).
- **Phase 4** — the characterization of `FW-E2E-167` and the §9 time measurement; then anchoring.

## 7. Amendments to the landed docs (apply on landing)

**(a) Constitution — Concepts, Launcher.** Append: "On request it also takes a **snapshot** of the
session's writable set — a baseline before spawn and a final record when the workload's direct child
exits — keeps it in a store it denies to every session, and `formwork restore` returns the session's
changes to the baseline (FEP-11)." No new concept: the snapshot is the Launcher's artifact, as the
environment it builds is.

**(b) Constitution — Data model.** Add: "the **snapshot store** — its layout and the manifest, final
and journal records (`version: 1`), machine-written, read back by `formwork restore` across
releases."

**(c) Constitution — Vocabulary.** Add: **snapshot** = the Launcher's record of a session's capture
set, baseline and final · **capture set** = what a snapshot covers (`FW-TRA12`) · **change set** =
entries whose baseline and final records differ · **conflict** = a change-set entry whose current
state differs from its final record · **restore** = return a change set to its baseline. "Rollback"
and "undo" are not terms.

**(d) `formwork.md` §3.** Under out of scope add: "Undoing effects outside the capture set — egress,
other processes, the host temp roots — and durability against loss of the disk the store shares with
the project. A snapshot is a record of in-grant writes, not a backup."

**(e) `formwork.md` §5–§10.** The §5 rows go to §5.5 (TRA) and §5.6 (FID) with the §3.4 parameter
table beside them, `FW-INV21` to §6, §6.1–§6.2's tests to a new §7.13, a TBD capture-time row to
§8, the fidelity rows `snapshot store` (Enforced / Enforced) and `session snapshot` (Partial, or
Enforced under `isolate = ["processes"]` / Partial) and the §3.8 rows to §9, and §6.4's rows to §10.

**(f) [FW-FID6](../formwork.md#fw-fid6).** After "not the session-only denies `run` adds": "except
the snapshot-store denial, which applies in every session and is reported as `built-in`".

**(g) [FW-TRA9](../formwork.md#fw-tra9).** Add: "The snapshot store is a Launcher-owned path that is
denied, not granted (`FW-TRA14`), and is named in the same disclosure."

**(h) `docs/STATUS.md`.** A phase row for FEP-11, owed-work rows for each unbuilt phase, and a
tracked test-method exception: `FW-INV21`, spec method "property test over generated trees and
operation sequences", standing in `restore_round_trip_examples`, reason "property infrastructure not
built", expiry "the fuzz-infra FEP".

**(i) `README.md`.** One sentence and one example line for `run --snapshot` and `formwork restore`,
without requirement IDs (document audience rule).

## 8. Decisions (recorded per constitution Precedence & Conflicts)

- **The Launcher concept is amended, not a concept added.** The constitution's Launcher starts the
  child; restore runs in a later invocation. The conflict is stated (§7 a): a snapshot is an
  artifact the Launcher produces for one Session, and restore consumes only that artifact, never a
  policy. A separate "Snapshotter" concept would duplicate the Launcher's pre-spawn position.
- **The store is denied in every session, not only in `--snapshot` sessions.** A session without a
  snapshot could otherwise read earlier snapshots (copies of files from other projects) or plant a
  forged one for a later restore. nono refuses overlapping grants
  (`nono@9edf3ea:cli/protected_paths.rs:74-111`); Formwork's default read mode is ambient, so it
  subtracts instead.
- **No store-location flag, no `XDG_STATE_HOME`, no Merkle tree, no prompt.** A movable store is the
  source of N1; one fixed root disclosed as `builtin` keeps the protection rule one line. Per-object
  digests detect corruption and denial prevents tampering (N12). `run` stays a wrapper
  ([FW-XR10](../formwork.md#fw-xr10)).
- **Three-way restore, baseline target only.** N2–N4 all follow from comparing only the current tree
  with a stored manifest. The final record holds tuples, not content, so there is nothing to restore
  to but the baseline.
- **Opt-in per run.** A full baseline cannot meet [FW-TRA6](../formwork.md#fw-tra6)'s 50 ms setup
  target on a large tree; incremental capture needs privileges Formwork does not take (§3.3).
- **Restore does not chase descendants.** Waiting for every orphan (a Linux subreaper) would make
  `run` block on a dev server the agent left running; the gap is reported instead.

## 9. Open questions

- **Capture and restore time target.** Owner: CLI maintainer. Closure: measured on the CI runners
  with a 10,000-file, 100 MiB tree in the `FW-E2E-157` harness, on reflink and copy filesystems,
  and entered in `formwork.md` §8 before `FW-TRA11` is anchored.
- **Persistent exclusions.** A Blueprint `[snapshot] exclude` table would spare operators retyping
  `--snapshot-exclude`, but it is a non-capability field (a Concepts amendment) and lets an
  auto-discovered `FORMWORK.toml` shrink the capture. Owner: Blueprint schema reviewer. Closure:
  FEP-11 landing review, with operator feedback from Phase 2.
- **A higher byte limit where reflink works.** Reflinked bytes cost no disk; a host-dependent limit
  costs parity. Owner: Launcher maintainer. Closure: after the time measurement above.
- **Extended attributes and ACLs.** Capturing `user.*` (Linux) and non-system attributes (macOS).
  Owner: Launcher maintainer. Closure: before a 1.0 release.
- **The namespace claim of §3.3.** Owner: Linux backend maintainer. Closure: `FW-E2E-167` on
  `ubuntu-22.04` before `FW-FID25` is anchored; if processes survive, the gap stays on Linux too.
- **Overlay-based capture on Linux.** Owner: Linux backend maintainer. Closure: a spike recorded in
  `docs/spikes.md`, reopened only if Ubuntu lifts its user-namespace restriction by default.
- **Explicit discard.** Retention is automatic; an operator who wants a snapshot gone sooner has no
  command. Owner: CLI maintainer. Closure: FEP-11 landing review, Growth default no.
