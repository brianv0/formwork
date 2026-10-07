# FEP-7 (proposal): blueprint trust and policy provenance

**Formwork Enhancement Proposal 7 — proposal, not landed.** Companion to `formwork.md`
(design + end-to-end spec) and `constitution.md` (doctrine).

**Status: nothing in this document mutates the landed spec or the constitution.** The amendments in
§7 are apply-on-landing blocks. New identifiers are draft numbering, written as inline code so the
requirements canary skips them, until they are anchored on landing. This FEP holds the reserved
blocks `FW-BP17`..`FW-BP22`, `FW-FID14`..`FW-FID15`, `FW-INV16`, `FW-E2E-107`..`FW-E2E-116` and
`FW-ADV-026`..`FW-ADV-029`, all above the highest landed numbers (`FW-BP16`, `FW-FID13`,
`FW-INV15`, [FW-E2E-106](../formwork.md#fw-e2e-106), [FW-ADV-025](../formwork.md#fw-adv-025)) and
clear of FEP-4's drafts. It adopts one quality of nono (nono@9edf3ea, 2026-10-05): policy is applied
only with verified provenance and an explicit operator choice.

---

## 1. Problem

Formwork applies a blueprint it finds without asking anyone. With no `--blueprint`, the CLI walks
from the launch directory up to `$HOME` and takes the first `FORMWORK.toml` or
`.formwork/blueprint.toml` the invoking user owns (`crates/formwork-cli/src/blueprint_load.rs:86-171`,
[FW-BP8](../formwork.md#fw-bp8)). The only notice is one INFO line (`:76-81`) and the
`blueprint: {path, source}` stamp on `compile`/`explain` ([FW-FID7](../formwork.md#fw-fid7)). A
cloned repository is owned by the user who cloned it, so the ownership check passes, and its
committed blueprint governs the session. Verified on Linux 6.18 (Landlock ABI 7): a cloned
`FORMWORK.toml` with `allow-credentials = ["aws"]` and a port tier lifted the credential floor
([FW-CRED5](../formwork.md#fw-cred5)) and opened direct egress on those ports, and the run printed
only the resolution line. The same holds for a `git pull` that changes a committed blueprint, for an edit to a local
`extends` base, and for an explicit `--blueprint` naming a file the operator never read.

The second defect is the in-session protection of the policy inputs. To keep a confined agent from
shaping its next run ([FW-XR8](../formwork.md#fw-xr8)), the Launcher write-denies the blueprint, its
discovered layer and its proposal (`protect_policy_inputs`, `blueprint_load.rs:764-786`, called at
`crates/formwork-cli/src/main.rs:1231`). On Linux each such row is a hole below a write grant, and
the Landlock subtractive expansion splits every directory above a hole
(`crates/formwork-confine/src/linux/landlock.rs:106-157`): existing entries stay writable, new files
cannot be created directly in the project root. FEP-5 D3 moved the blueprint to `.formwork/` to
confine the hole to one directory; it does not, because `.formwork/blueprint.toml` is strictly below
the root and splits it too. The notice that should say so returns early for any `.formwork`
directory (`main.rs:1634`), and `explain` reports the root writable
([FW-FID6](../formwork.md#fw-fid6) reflects the merged blueprint, not the run). Verified: under
`readwrite:$CWD/**`, `touch $CWD/new` fails with EACCES in both layouts. Two further gaps sit in the
same code: `protect_policy_inputs` protects the top file only, so a local `extends` base stays
writable from the session, and the proposal the operator reviews with `learn --list` sits in the
project tree, where the session can write it.

Who is hurt: an operator who runs an agent in a repository they did not author gets the
repository's grants, including credential lifts, with no decision of their own; an operator on Linux
cannot create files in the project root of any session; a CI pipeline cannot pin the policy it was
reviewed with.

### 1.1 Constraints this FEP holds to

- **No new concept.** The gate is a Launcher responsibility, the reference is a Blueprint, the record
  is a machine-written, human-accepted Data-model artifact like the discovered layer. No new family.
- **No new dependency.** SHA-256 comes from `ring`, already linked through `formwork-gateway`
  (`Cargo.lock:522`, the only hash crate in the tree); `formwork-cli` takes it as a direct dependency
  on the precedent of `base64` (`Cargo.toml:45-47`). Sigstore and signing stacks are declined (§3.7).
- **Narrowing never asks.** An input set whose effective blueprint narrows its reference runs with no
  prompt ([FW-CAP2](../formwork.md#fw-cap2)); only an excess asks.
- **Fail before the work.** Every refusal happens before the workload or backend spawns
  ([FW-XR9](../formwork.md#fw-xr9)); the dry-run doors (`compile`, `explain`) report and never
  prompt, refuse or write.
- **Parity.** Both backends get the same gate and the same store protection; where macOS cannot be
  shown to enforce the store, the report says `Partial` ([FW-XR6](../formwork.md#fw-xr6),
  [FW-INV5](../formwork.md#fw-inv5)).
- **Vocabulary.** "Widen" is reserved ([FW-CAP2](../formwork.md#fw-cap2)); this FEP says a candidate
  **exceeds** its reference and lists **excess** items.

## 2. Prior art: nono

### 2.1 Mechanism and behavior

- **No implicit profile.** nono loads a profile only by registry reference, explicit path, user
  profile name or built-in name (nono@9edf3ea:crates/nono-cli/src/profile/mod.rs:3048-3096,
  `load_profile_inner`); nothing is read from the working directory. A name that matches nothing
  fails rather than falling back (nono@9edf3ea:tests/integration/test_pack_resolution.sh:83-87).
- **Verified registry packs.** A pull verifies a Sigstore bundle per artifact, requires keyless
  signing whose repository owner equals the pack namespace (`enforce_namespace_assertion`,
  nono@9edf3ea:crates/nono-cli/src/package_cmd.rs:1072-1095), and pins the signer identity in the
  lockfile: a changed repository or workflow is refused unless `--force`
  (`enforce_signer_pinning`, package_cmd.rs:1097-1120; the per-release `@ref` is stripped first,
  :1127-1131). Short-name execution of an installed pack re-verifies lockfile and bundle
  (test_pack_resolution.sh:13-24).
- **First use asks.** A profile served by a pack the user lacks prompts `Continue? [y/N]` naming
  publisher and provenance (nono@9edf3ea:crates/nono-cli/src/migration.rs:182-228,
  docs/cli/clients/claude.mdx:369-384); only `y`/`yes` approves (:230-232); with no terminal it skips
  with a hint (:141-151) unless `NONO_AUTO_MIGRATE` is set (:24, :141).
- **User policy anchors project policy.** Trust policies merge embedded, user and project levels;
  enforcement takes the strictest and a project file cannot weaken the user's
  (nono@9edf3ea:docs/cli/features/trust.mdx:447-467; nono@9edf3ea:crates/nono/src/trust/policy.rs:647).
- **Instruction-file attestation.** Files matching `includes` (CLAUDE.md, AGENTS.md) are scanned
  before exec, digested, checked against a blocklist, verified against a bundle and a trusted
  publisher; `deny` enforcement refuses to start (trust.mdx:511-527; nono@9edf3ea:crates/nono/src/trust/mod.rs:3-28).
  Verified files are write-protected by a literal Seatbelt deny on macOS
  (nono@9edf3ea:crates/nono-cli/src/instruction_deny.rs:41-49).
- **Own state outside the sandbox.** nono refuses a grant inside `$XDG_STATE_HOME/nono` on every
  platform and a grant on its parent on Linux, where Landlock cannot express a deny inside an allow
  (nono@9edf3ea:crates/nono-cli/src/protected_paths.rs:35-40, :68-105); the state root is
  `$XDG_STATE_HOME/nono`, default `~/.local/state/nono`, on every platform
  (nono@9edf3ea:crates/nono-cli/src/state_paths.rs:22-46).

### 2.2 Tests and fixes in this area

Unit tests sit beside the code: digest vectors (nono@9edf3ea:crates/nono/src/trust/digest.rs, 10
tests), policy merge and evaluation (trust/policy.rs, 37), policy types and serde (trust/types.rs,
35), the pre-exec scan (nono@9edf3ea:crates/nono-cli/src/trust_scan.rs, 34), protected state roots
(protected_paths.rs, 12), install wiring (nono@9edf3ea:crates/nono-cli/src/wiring.rs, 31) and
consent parsing (migration.rs, 6); §6.3.2 cites each one Formwork's tests are modelled on.
`enforce_signer_pinning` has no unit test. Integration suites:
nono@9edf3ea:tests/integration/test_trust_cli.sh (tampered file :285, relocated signing key
:483-496, 0600 key file :436-438, missing-literal asymmetry :354-397) and test_pack_resolution.sh
(:76-114, a hand-installed fixture pack, nono@9edf3ea:tests/fixtures/synthetic-pack).

CHANGELOG fixes in the area, each a regression candidate: reject `.`/`..` in pack names
(nono@9edf3ea:CHANGELOG.md:136); a predicate field so a trust policy is not confused with foreign
JSON (:880); skip pack verification on dry runs (:1248); profile names that shadow built-ins or packs
refused (:1563, :1577); pack signer identities verified, source pack always in the verification set
(:1670-1672); symlink escape and traversal in bundle subject names rejected (:1931-1935); env-lock
guards for test isolation (:2972). The GHSA entries (:7, :116-120) carry no description; the one the
source cites, GHSA-8r33-hr9m-69wh, is in the proxy (nono@9edf3ea:crates/nono-proxy/src/config.rs:1465),
and no trust or pack code cites any.

### 2.3 Defects and limitations

1. `nono update` re-pulls and prints only `updating <pack> <old> → <new>`; the operator never sees
   which grants changed (`run_update`, package_cmd.rs:224-361, the line at :323).
2. Signing proves who published and that bytes are unchanged, not that grants are narrow; nono's own
   documentation says so (trust.mdx:382-389). A pinned signer can publish a profile that grants `~`.
3. Install-time wiring writes symlinks, files and JSON/TOML/YAML merges into `$HOME` from the
   unconfined CLI (wiring.rs:1-22, directive set :35-95).
4. `NONO_AUTO_MIGRATE=1` approves any pack without naming it (migration.rs:141-151); `--force`
   bypasses signer pinning wholesale (package_cmd.rs:1102-1104).
5. Verified-file write protection is a no-op on Linux (instruction_deny.rs:52-62), and instruction
   verification is startup-only on macOS (trust.mdx:541-550); missing literal patterns block on macOS
   and pass on Linux (test_trust_cli.sh:354-397).
6. Tests that mutate the environment serialize on a process-global lock
   (nono@9edf3ea:crates/nono-cli/src/test_env.rs:15) and some kernel tests return early, passing, on
   a host without the feature (nono@9edf3ea:crates/nono/src/sandbox/linux.rs:5994-6003).

### 2.4 What Formwork adopts / declines

| nono quality | Formwork |
|---|---|
| No profile from the working directory | Adapted. Discovery stays ([FW-BP8](../formwork.md#fw-bp8)); a discovered or named file that exceeds its reference needs an operator approval (`FW-BP17`) |
| First use asks y/N; explicit yes only | Adopted for the interactive gate, with the excess listed (`FW-FID14`) |
| Signer pinning refuses a change without `--force` | Adopted as content pinning. The approval is bound to the input digest and the blueprint path; a change is shown as an excess diff; there is no force (`FW-BP18`, `FW-BP21`) |
| User policy anchors project policy | Adopted. The reference lives in the user's state directory; an in-tree file can only narrow it without approval |
| Own state outside every grant | Adopted, by split not refusal. Formwork's subtractive expansion can carve the state directory out of a broad grant, so no grant is refused (`FW-BP22`) |
| Update with no diff; blanket env approval; `--force` | Designed out. Every change that exceeds the reference shows its excess; approval names a digest |
| Sigstore pack signing | Declined for now, §3.7 |
| Instruction-file signing and read-deny | Declined, §3.7 |
| Install-time wiring | Designed out. Approval writes one record file and nothing else (`FW-BP20`) |

## 3. Design

### 3.1 Inputs and the input digest

An **input** is a file the loader parses into a layer: the blueprint file, each `extends` base
resolved from a file (authored, from `--extends`, or from a `--set` fragment), and the discovered
layer. `builtin:` profiles are not inputs: they are compiled into the release binary
(`blueprint_load.rs:28-29`) and carry the binary's provenance. `--set` fragments and sugar flags are
not inputs either: the operator typed them. The loader reads each input once into memory and parses
that buffer; the **input digest** is SHA-256 over the inputs in resolution order, each framed as a
role byte, a big-endian `u64` length and the bytes, rendered `sha256:<64 lowercase hex>`
(`FW-BP19`). Paths are not hashed, so two checkouts of one commit share a digest; records are keyed
by path instead (§3.3). A changed `extends` base changes the digest, so bases are pinned through the
digest and no per-entry pin syntax is needed.

The **file-sourced blueprint** is the merge of every layer except `--set` fragments and sugar flags,
the existing [FW-BP2](../formwork.md#fw-bp2) merge over a subset of its layers. For the approval
decision it is expanded with `~` → `$HOME` and `$CWD` held symbolic: the loader parses the same
buffers a second time with `$CWD` bound to a reserved sentinel prefix the CLI edge refuses in
authored paths, so the decision does not depend on the launch directory. Enforcement uses the
ordinary expansion ([FW-BP5](../formwork.md#fw-bp5)).

### 3.2 The reference and the gate

Every blueprint path has a **reference**: the blueprint held by its approval record, or, with no
record, the **default reference** — the file-sourced blueprint of `extends = ["builtin:default"]`
plus `rules = ["readwrite:$CWD/**"]`, which is the minimal blueprint the CLI already suggests
(`main.rs:578-586`). Grants inside the reference's own auto-widen zone
([FW-DISC4](../formwork.md#fw-disc4)) count as inside the reference, so in-zone discovery never
asks. The candidate **exceeds** the reference when the itemized difference below is non-empty. It
reuses `Blueprint::narrow` (`crates/formwork-blueprint/src/narrow.rs:37-83`), which is
conservative: `n = reference.narrow(candidate)` is a subset of both, so every item it drops from the
candidate is an excess, never a false narrowing. Items, in Blueprint field order:

| Axis (`excess[].axis`) | Excess item |
|---|---|
| `read`, `write`, `modify` | a grant in the candidate that `n` drops (reads only under the closed read mode; ambient reads are inert) |
| `read-mode` | candidate ambient where `n` is closed |
| `deny-removed`, `write-deny-removed` | a `subtract` / `write-subtract` row of `n` the candidate lacks (dropping the [FW-TRA7](../formwork.md#fw-tra7) rows counts) |
| `net` | a port or host rule the candidate holds and `n` drops, or a host `deny` it lacks |
| `exec` | candidate unrestricted where `n` holds an allow-list |
| `env` | `n.env` differs from the candidate's posture |
| `mcp` | a server, or an allow entry, `n` drops; a deny entry the candidate lacks |
| `credential` | an `allow-credentials` entry of any form, bare, `broker:` or inline |
| `auto-widen` | a zone path `n` drops |
| `channel` | a channel lift `n` drops |
| `isolate-removed` | an `isolate` member of `n` the candidate lacks |

The axis set is exactly these fourteen values.

The exec axis cannot exceed the default reference, whose exec is unrestricted
(`profiles/default.toml`); it exceeds a record that holds an allow-list. Where `narrow` under-
approximates (anchored-regex MCP allow lists, mixed write grades) the result is an extra prompt, not
a missed excess.

The **gate** (`FW-BP17`) runs in `run` (both postures), `learn` in observe mode and `gateway`,
after the layer stack loads and before any session state is created:

| Record | Candidate vs reference | `--approve` | Terminal | Outcome |
|---|---|---|---|---|
| none | within default reference | absent | any | run; write a first-use record |
| present | within record | absent | any | run; write nothing |
| any | any | equals the digest | any | run; write the record |
| any | any | differs from the digest | any | refuse, naming both digests |
| any | exceeds | absent | attached | list the excess, ask; `y`/`yes` runs and records, anything else refuses |
| any | exceeds | absent | none | refuse, listing the excess and the `--approve` argument |

A mismatched `--approve` refuses even a narrowing: a CI pin means exactly these inputs. A record
that fails validation (§3.4) refuses, naming the record; it is never read as "no record", which would
fall back to the default reference and could admit what a tighter record excluded.

### 3.3 Approving

**Interactive.** When stderr is a terminal and a controlling terminal is available (nono's condition,
migration.rs:142-143), the Launcher prints the excess list (`FW-FID14`) and the digest and reads one
line; only `y` or `yes`, case-insensitive and trimmed, approves (migration.rs:230-232).

**Non-interactive and CI.** `--approve sha256:<hex>` on `run`, `learn` and `gateway` names the one
digest the operator approves for this invocation (`FW-BP21`). A CI workflow commits the digest
beside the blueprint; a pull request that changes `FORMWORK.toml` or a base must change the digest
in the workflow file, so the change and its approval are reviewed together. `compile` and `explain`
refuse `--approve`, as a flag a mode would ignore ([FW-DISC11](../formwork.md#fw-disc11)). An
environment variable was rejected (§8).

**Records.** A record is `<state>/approvals/<hex SHA-256 of the canonical blueprint path>.toml`
holding `kind = "formwork-approval"`, `version = 1`, the canonical `blueprint` path, the `digest`,
`recorded-by` (`prompt` | `approve-flag` | `first-use` | `accept`) and the approved file-sourced
blueprint as a `BlueprintLayer` (`BlueprintLayer::from_blueprint`,
`crates/formwork-blueprint/src/layer.rs:176`). It is created 0600 in a 0700 directory, written to a
fresh temporary name opened with `O_CREAT|O_EXCL|O_NOFOLLOW` and renamed into place; the file name is
fixed-width hex, so no path component of the blueprint reaches the store's namespace. A record
larger than **record-limit** (1 MiB) is refused. An approval replaces the record: the approved
candidate becomes the new reference.

**Accept.** `learn --accept` records the new input set (`recorded-by = "accept"`) when the
file-sourced blueprint before the accept was within the record (in-zone self-grants keep it so);
otherwise it writes the discovered layer, records nothing, and says the next run will ask. Accept
is per-entry and listed ([FW-DISC5](../formwork.md#fw-disc5)), so it is an operator approval of
exactly those entries.

Linux `learn` runs a `run --confine-self` shim under `strace` ([FW-E2E-071](../formwork.md#fw-e2e-071));
the parent forwards `--approve <digest>` for the inputs it checked, and the shim refuses when its own
digest differs, so a file changed between the two loads is caught.

### 3.4 The state directory

The **state directory** is `$XDG_STATE_HOME/formwork` when `XDG_STATE_HOME` is absolute, else
`$HOME/.local/state/formwork`, on both platforms (nono's rule, state_paths.rs:22-46). With neither
resolvable, an enforcing command refuses: falling back to `/` is the FEP-1 defect `docs/STATUS.md`
already owes. It holds `approvals/` and `proposals/`: `learn` writes the proposal to
`proposals/<hex>.proposal.toml`, which [FW-DISC11](../formwork.md#fw-disc11) already permits (the
file names are conventions surfaced in output); `--proposal` stays the fallback. The discovered layer
stays beside the blueprint, where FEP-5's team workflow commits it (`docs/fep-5.md` §8), and is
covered by the digest. The Launcher creates the state directory with mode 0700 before the first
session when it is absent, so the deny row always names an existing directory.

In every session the Launcher adds the state directory to the write-subtract set
([FW-TRA7](../formwork.md#fw-tra7) semantics: readable, not writable), and adds no row for the
blueprint, its bases, the discovered layer or the proposal (`FW-BP22`). Readable, because a
Formwork invocation nested in a session (an MCP host launching `formwork gateway` from a confined
agent) then honors the operator's records; it cannot write one, and its sessions are bounded by the
outer one ([FW-XR4](../formwork.md#fw-xr4)). A record parse validates `kind`, `version`, the path
binding, owner equal to the effective uid, mode no wider than 0600, not a symlink, and record-limit.

With the in-tree rows gone, a project root under `readwrite:$CWD/**` has no hole and is granted
whole. The state directory splits its ancestors on Linux only when a write grant covers its parent
(`readwrite:~/**`, or `XDG_STATE_HOME` under a writable tree); those ancestors are already split by
the credential floor's holes under `$HOME`, and the report names them (`FW-FID15`).
`announce_split_root` (`main.rs:1619-1648`) is deleted with `protect_policy_inputs`.

### 3.5 What FW-XR8 means without in-tree write protection

[FW-XR8](../formwork.md#fw-xr8) forbids any mechanism by which a confined process reconfigures its
own confinement. Today it is realized for policy inputs by prevention: the session cannot write
them. Under this FEP the session can edit `FORMWORK.toml`, a base or the discovered layer, and the
edit takes effect at the next launch only if it narrows the reference; anything else needs an
approval that only an unconfined invocation can give and record, because the session cannot write
the state directory. `FW-INV16` states the result.

The trade. Lost: an absolute bar becomes an operator decision, and an operator who
approves without reading admits the excess; the diff lists only excess items, attributed to the
input that wrote them, to keep the decision small. An agent can also narrow its next run without
asking, which can make that run less useful but grants nothing. Gained: the project root is whole on
Linux ([FW-TRA1](../formwork.md#fw-tra1); `npm init`, `cargo new`, `git init` create files there);
`extends` bases and the discovered layer are covered, which they are not today; edits from outside
any session (`git pull`, a cloned repository, an operator's own edit) are gated, which write
protection never addressed; and a CI run can pin its policy. Keeping write protection on macOS only,
where it costs no split, was rejected: the agent would see EACCES on one backend and success on the
other for one blueprint ([FW-XR6](../formwork.md#fw-xr6)), and the gate is the control on both.

Out of scope, as for [FW-TRA7](../formwork.md#fw-tra7): a wrapper script the operator runs
unconfined from a writable directory can be edited to pass `--approve`; shell rc files are already
write-subtracted.

### 3.6 Reporting

- `compile` and `explain --json` extend the [FW-FID7](../formwork.md#fw-fid7) stamp to
  `blueprint: {path, source, digest, approval, reference, inputs, excess}`: `approval` is
  `approved` | `within-reference` | `unapproved`; `reference` is `record` | `default`; `inputs` lists
  `{role, path, sha256}` in resolution order; `excess` lists `{axis, grant, input}`. Human `explain`
  prints the same in one block. The `policy` and `report` subtrees are unchanged
  ([FW-FID4](../formwork.md#fw-fid4)).
- The FidelityReport gains `approval-store` (`FW-FID15`). Linux: `Enforced` (Landlock write-deny; a
  split directory grants no entry creation or removal, so no ancestor can be renamed); the reason
  names split directories when a write grant covers the state directory's parent. macOS: `Enforced`
  when no write grant covers a strict ancestor of the state directory; otherwise `Partial` naming the
  grant, until characterization C10 (§6.3.2, `FW-ADV-026`) shows Seatbelt refuses a rename of an
  ancestor of a denied subpath. A host without Landlock: `Unenforceable`, and `FW-INV16` is reported
  as not held against a session that writes records.

### 3.7 Signing and instruction files

**Blueprint signing (Sigstore, keyed or keyless) is declined for this FEP and deferred.** Growth
gives dependencies the hardest no, and nono's verification stack is four Sigstore crates bumped
repeatedly (nono@9edf3ea:CHANGELOG.md:582, :799, :805, :817) plus X.509, DSSE and in-toto parsing
(nono@9edf3ea:crates/nono/src/trust/bundle.rs, dsse.rs, 2,284 lines). It answers who published a
blueprint; the operator's question is what the blueprint grants, which the excess diff answers
without a key. Formwork has no registry: blueprints are repository files and `builtin:` profiles
ship inside the signed release binary. Integrity across machines comes from the digest pinned in
reviewed CI configuration. Signing is revisited if a blueprint distribution channel is proposed, and
then as provenance shown beside the diff, never in place of it (§9).

**Instruction-file signing (CLAUDE.md, AGENTS.md) is declined.** It protects the integrity of the
model's input, not the boundary: Formwork's boundary holds whatever the agent reads
(`formwork.md` §3, prompt-injected streams are in scope because the OS enforces). Denying reads of
unsigned files is a content judgment outside the closed vocabulary
([FW-CAP1](../formwork.md#fw-cap1)), needs the same signing stack, and nono itself enforces it only
at startup on macOS and leaves verified files writable on Linux (§2.3 item 5). An operator who wants
those files unwritable writes a `write-subtract` row, as the default does for `.claude/settings.json`.

### 3.8 Asymmetries that remain

1. macOS ancestor rename of the state directory under a broad home write grant: `Partial` until C10.
2. Linux split of the state directory's ancestors when a write grant covers its parent: reported.
3. Linux without Landlock: the store is unprotected; `approval-store` is `Unenforceable`.
4. The Launcher-owned directories under `/tmp` still split `/tmp` on Linux
   (`grant_launcher_dir`, `main.rs:1147-1172`); that is [FW-TRA9](../formwork.md#fw-tra9)'s defect,
   not this FEP's (§9).

## 4. Surface changes (each measured against Growth)

- **CLI flag `--approve <sha256:hex>`** on the shared blueprint arguments, accepted by `run`, `learn`
  and `gateway`, refused by `compile` and `explain`. Searched: `--blueprint` chooses a file, not its
  content; `--set`/`--rule` add layers; `learn --accept` moves proposal entries;
  `--observe-anyway` is `learn`-only. None names a content digest, and an interactive prompt cannot
  serve an MCP host's stdio launch or CI. No subcommand: approving without a workload is
  `formwork run --approve <digest> -- true`. No environment variable (§8).
- **Blueprint schema:** unchanged. Digest-pinned `extends` entries (`{path, sha256}`) were declined:
  the input digest pins every base.
- **Stamp keys** `digest`, `approval`, `reference`, `inputs`, `excess` under the existing
  `blueprint` object ([FW-FID7](../formwork.md#fw-fid7) is the surface built for this disclosure).
- **Report key** `approval-store` in `per_capability`, the [FW-FID8](../formwork.md#fw-fid8) map.
- **On-disk:** approval records (new Data-model surface); the proposal moves to the state directory
  (location only; the shape is unchanged).
- **Code:** `crates/formwork-blueprint/src/approval.rs` (pure: excess, decision, record types) and
  `crates/formwork-cli/src/approval.rs` (digest, store, prompt). One typed error enum in the pure
  crate, `RecordError` (`MalformedDigest`, `Malformed`, `ForeignKind`, `UnsupportedVersion`,
  `PathMismatch`), because the record is parsed at a boundary. Deleted: `protect_policy_inputs`,
  `announce_split_root`.
- **Dependency:** `ring` becomes a direct `formwork-cli` dependency; the lockfile gains no crate.
  `sha2` was rejected (a new crate for what `ring` already provides).

## 5. Proposed requirements (draft numbering — anchored on landing)

| Req | Requirement |
|---|---|
| `FW-BP17` **Approval gate** | `formwork run`, `formwork learn` in observe mode and `formwork gateway` shall not spawn the workload or backend when the file-sourced blueprint exceeds its reference, unless the operator answers yes at the prompt of that invocation or `--approve` names the input digest. |
| `FW-BP18` **Reference** | The reference for a blueprint path shall be the blueprint of the valid approval record for its canonical path, else the default reference, with grants inside the reference's auto-widen zone counted within it and `$CWD` held symbolic in both; a record that fails validation shall make the command refuse to spawn, naming the record. |
| `FW-BP19` **Input digest** | The loader shall compute the input digest over exactly the non-builtin inputs it parses — the blueprint file, every file-resolved `extends` base, and the discovered layer — in resolution order, each framed by role and length, from the same bytes it parses. |
| `FW-BP20` **Approval records** | Formwork shall write an approval record exactly when the operator answers yes at the prompt, when `--approve` names the input digest, when a path with no record runs within the default reference, or when `learn --accept` changes the discovered layer of inputs whose file-sourced blueprint was within the record before the accept, and shall write no other file when approving. |
| `FW-BP21` **Named approval** | `run`, `learn` and `gateway` shall exit with status 1 before spawning when `--approve` names a digest other than the input digest, and when approval is required, `--approve` is absent and no terminal is attached, printing the excess list, the input digest, and the `--approve` argument that admits it. |
| `FW-BP22` **State directory** | The Launcher shall add the state directory, and no blueprint, base, discovered-layer or proposal path, to the write-subtract set of every session, refusing to spawn when the state directory does not resolve to an absolute path. |
| `FW-FID14` **Excess listing** | Before prompting or refusing under `FW-BP17`, the Launcher shall print on stderr one line per excess item with its axis and grant, and for fs, exec, host-rule and channel items the input that wrote it, followed by the input digest and the reference kind. |
| `FW-FID15` **Store report line** | The FidelityReport shall carry `approval-store`, `Enforced` when the backend denies writes to the state directory and the rename of each of its ancestors that a write grant covers, and `Partial` naming the covering grant otherwise. |

Invariant:

- `FW-INV16` **Approval provenance.** No session runs with a file-sourced grant outside its
  reference unless an unconfined Formwork invocation approved that input digest; no confined process
  can create, change, rename or remove an approval record. The policy-input form of
  [FW-XR8](../formwork.md#fw-xr8), falsified by `FW-E2E-108` and `FW-ADV-026`/028.

## 6. Verification plan

Every scenario takes its least convenient realistic shape: the workload is a millisecond process
that writes a marker file as its first act, so "did not spawn" is observable; each boundary has an
allow and a deny probe. Rust binary-driven tests sit in `crates/formwork-cli/tests/approval_run.rs`,
black-box tests in `py/harness/test_approval.py`, kernel tests in `crates/formwork-confine/tests/`.

### 6.1 End-to-end tests (draft)

`FW-E2E-107` **A cloned blueprint that lifts a credential does not run (both).** An isolated home
holding a fake `~/.aws/credentials`; a project whose `FORMWORK.toml` extends `builtin:default`, adds
`allow-credentials = ["aws"]` and `allow:egress.example`; `formwork run -- touch marker; cat
~/.aws/credentials` with no terminal. **Pass:** exit 1, no marker, stderr lists exactly two excess
items (`net` attributed to the file, `credential`), the digest and the `--approve` argument; the same
run with that argument creates the marker and reads the file (allow probe); a sibling project whose
blueprint only narrows runs with no prompt. **Fail:** the marker exists without approval, an item is
missing, or the narrowing project is refused. Py harness (Rust arm in `approval_run.rs`). From
nono's no-cwd loading (profile/mod.rs:3048) and test_pack_resolution.sh:83-87.

`FW-E2E-108` **An in-session edit takes effect only by narrowing (both).** Session N, under an
approved blueprint with `mode = "unveil"`, appends `readwrite:~/other/**` to its own
`FORMWORK.toml`; a second blueprint's session flips its own `mode` to subtractive; a third deletes a
grant. Next launch of each, no terminal. **Pass:** the first two refuse, listing `write` and
`read-mode` items; the third runs; the session's write to the blueprint succeeded (no in-tree
deny). **Fail:** an exceeding edit runs, or a narrowing edit asks. Py harness. From
`write_file_refuses_to_overwrite_edited_file_on_repull` (wiring.rs:2329) and signer pinning
(package_cmd.rs:1097-1120).

`FW-E2E-109` **The project root stays whole (Linux primary, macOS).** Blueprint at `$CWD/FORMWORK.toml`,
then at `$CWD/.formwork/blueprint.toml`, granting `readwrite:$CWD/**`; the workload creates
`$CWD/new` and `$CWD/.formwork/new`, appends to the blueprint, and creates a file beside the project.
**Pass:** the three writes in the project succeed; the create beside it fails with EACCES; `explain`
agrees with each probe. **Fail:** EACCES in the root or on the blueprint, or the outside create
succeeds. Kernel arm in `crates/formwork-confine/tests/linux_confine.rs`; black-box arm in the py
harness. Regression for the verified split (landlock.rs:106-157, main.rs:1634); contrast nono's
Linux no-op (instruction_deny.rs:52-62).

`FW-E2E-110` **A changed base is a changed input (both).** `FORMWORK.toml` extends `./base.toml`;
approved by `--approve`; `base.toml` then gains `readwrite:/srv/data/**`. **Pass:** the next run with
the old digest refuses naming the old and new digests; with no flag it lists one `write` item
attributed to `base.toml`. **Fail:** the run proceeds, or the item names the wrong input. Rust arm.
From `scan_unsigned_file_deny_enforcement_blocks` (trust_scan.rs:1285) and test_trust_cli.sh:285.

`FW-E2E-111` **CI pinning (both).** The same repository checked out at two paths; `explain --json`
in each; `run --approve` with the reported digest, with a digest differing in one hex digit, and
with `sha256:` plus 63 digits. **Pass:** both checkouts report one digest; the match runs; the
mismatch refuses naming both; the malformed value fails at argument parsing; no prompt appears.
**Fail:** a path-dependent digest, or a near-miss accepted. Py harness. Contrast
test_trust_cli.sh:483-496 (nono's identity is path-dependent; Formwork's digest is not, its records
are).

`FW-E2E-112` **Records are written exactly when stated (both).** Fresh state directory: a
within-default run; an `--approve` run of an exceeding blueprint; a run whose candidate is within
its record; a nested `formwork run` inside a session. **Pass:** the first writes a `first-use`
record, 0600 in a 0700 directory; the second replaces it with `approve-flag`; the third leaves the
record byte-identical; the nested run reads the record, cannot write, and prints one line saying so;
no other file appears under the state directory or the project. **Fail:** any extra write, a missing
record, or a nested write. Rust arm. From wiring.rs:2020 and test_trust_cli.sh:436-438.

`FW-E2E-113` **Discovery under the gate (macOS; Linux with strace).** A blueprint with an auto-widen
zone `$CWD/.cache/**`; a learning run that is denied an in-zone and an out-of-zone path; `learn
--accept` of the out-of-zone entry; then the same with an out-of-zone grant written into the
discovered layer out of band before the accept. **Pass:** the proposal is under
`<state>/proposals/`, not beside the blueprint; the next run after the in-zone self-grant runs with
no prompt; after the accept it runs with no prompt and the record says `accept`; after the
out-of-band grant, accept records nothing and the next run lists that grant. **Fail:** a proposal in the tree, a prompt for in-zone grants, or a recorded unreviewed
edit. Py harness (extends `test_discovery.py`'s fixture).

`FW-E2E-114` **Dry-run doors report and never act (any host).** `compile` and `explain --json` over
the `FW-E2E-107` project, with no record, with a record, and with `--approve`. **Pass:** the stamp
carries exactly the v1 key set with `approval` `unapproved` then `within-reference`; `excess`
matches `FW-E2E-107`; `per_capability` carries `approval-store`; no file is written; `--approve`
is refused; the `policy` and `report` subtrees are byte-identical across the three runs. **Fail:** a
key drift, a write, or a prompt. Rust arm with golden fixture. From nono's dry-run verification skip
(CHANGELOG.md:1248) and schema_shape.rs:19-30.

`FW-E2E-115` **An MCP host's gateway launch (both).** `formwork gateway --blueprint mcp-gateway.toml
--server files -- <fixture server>` with stdio pipes, as `examples/claude-code/mcp.json` launches it.
**Pass:** with no record, exit 1 before the backend spawns (the fixture server writes a marker on
start; absent), stderr names the `--approve` argument; after `formwork run --approve <digest> --
true` from a shell, the same launch serves `tools/list`. **Fail:** the backend starts unapproved.
Rust arm (`gateway_cli.rs` fixture server).

`FW-E2E-116` **Operator-typed layers are outside the gate; builtins cannot be shadowed (both).** A
within-default file plus `--allow-cred aws --rule allow:egress.example`; a file plus `--extends
./extra.toml` that grants `/srv/**`; a directory holding a file literally named `builtin:default`
with `net = "ports:22"`. **Pass:** the first runs with no prompt; the second asks for one `write` item
from `extra.toml`; the third resolves the compiled-in profile and the file is not an input.
**Fail:** a prompt for typed flags, an unhashed `--extends` file, or a shadowed builtin. Rust arm.
From CHANGELOG.md:1563, :1577.

### 6.2 Adversarial tests (draft)

`FW-ADV-026` **The session cannot touch the store (both).** Under `readwrite:~/**` and under
`readwrite:~/.local/state/**`, a confined process attempts each write class against the state directory:
create, modify, remove a record, replace a record by rename, and rename the state directory and each
ancestor a write grant covers. **Pass:** every attempt is denied on Linux; on macOS every attempt is
denied, or the ancestor-rename arm succeeds and `approval-store` is `Partial` naming the grant
(C10 records which). **Fail:** a record changes while the report says `Enforced`. Kernel arms in
`linux_confine.rs` and `macos_characterize.rs`; run arm in the py harness. From protected_paths.rs:257,
:278, :347.

`FW-ADV-027` **Untrusted record files fail closed (both).** Record files, placed outside any session,
that are a symlink, group-writable, foreign-owned (injected predicate, as
[FW-E2E-070](../formwork.md#fw-e2e-070) does), of another `kind`, of `version = 2`, bound to another
path, one byte over record-limit, or truncated. **Pass:** each makes `run` refuse naming the record;
none is read as absent; a record of exactly record-limit that is valid is accepted. **Fail:** a
fallback to the default reference, or a parse past the limit. Rust arm. From
`legacy_version_field_is_rejected` (types.rs:1050), CHANGELOG.md:880, wiring.rs:2161.

`FW-ADV-028` **Planted inputs (both).** During session N the agent writes a nearer
`sub/FORMWORK.toml` that lifts `aws`, a second nearer file that only narrows, and an out-of-zone entry
in the discovered layer with forged provenance. **Pass:** a launch from `sub/` refuses the first and
runs the second, announcing its path ([FW-FID7](../formwork.md#fw-fid7)); the forged entry is listed
as an excess on the next launch. **Fail:** a planted excess runs. Py harness. From
`merge_project_cannot_weaken` (policy.rs:647).

`FW-ADV-029` **The digest covers what is parsed (both).** `extends = ["base.toml"]` with
`base.toml` a symlink re-pointed between runs; a process rewriting `FORMWORK.toml` in a loop while
`run` and the Linux `learn` shim load it. **Pass:** the re-pointed base changes the digest; no
session's grants differ from those of the digest it reported; a shim whose digest differs from the
parent's refuses. **Fail:** a session built from bytes other than the hashed ones. Rust arm. From
`multi_subject_bundle_detects_tampered_file` (trust_scan.rs:1509), CHANGELOG.md:1931-1935.

### 6.3 Unit and property tests

#### 6.3.1 Where the tests live

| Module | Layer and reason |
|---|---|
| `crates/formwork-blueprint/src/approval.rs` `mod tests` | pure: excess classification, reference choice, the decision table, record serde and validation, digest parsing; no filesystem |
| `crates/formwork-cli/src/approval.rs` `mod tests` | shell edge: digest framing and hashing (`ring`), state-directory resolution with the environment passed in, record store against a `Scratch`, answer parsing |
| `crates/formwork-cli/src/blueprint_load.rs` `mod tests` (extended) | input collection and the single read, with an injected reader |
| `crates/formwork-cli/src/learn.rs` `mod tests` (extended) | proposal location, accept recording |
| `crates/formwork-confine/tests/linux_confine.rs`, `macos_characterize.rs` | kernel: the state-directory row and ancestor rename, spawned children, never mocked |
| `crates/formwork-cli/tests/approval_run.rs` (new), `tests/support/mod.rs` | the built binary under an isolated home, state and workspace; golden shapes in `tests/fixtures/` |
| `py/harness/test_approval.py` (new) | black-box E2E with `@pytest.mark.fw_e2e(...)` / `fw_adv(...)`, `linux`/`macos` where platform-bound |

#### 6.3.2 The test list

In the **Modelled on** column a bare file name is nono@9edf3ea at the path §2 gives it (`trust/` under
`crates/nono/src/`, `.sh` under `tests/integration/`, `CHANGELOG.md` at the root, the rest under
`crates/nono-cli/src/`);
Formwork files carry the prefix `fw:`.

`formwork-blueprint/src/approval.rs` — nono's trust/policy.rs carries 37 tests and types.rs 35; this
module plans 24, with no publisher matching or cryptography to cover.

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `identical_candidate_is_within_reference` | `FW-BP18` | `default_reference()` | c = r → `excess_over(&r,&c)` → `is_empty()` | `narrowing_is_idempotent` (fw:narrow.rs:443); policy.rs:542 |
| `credential_lift_and_host_rule_exceed_the_default` | `FW-BP17`, `FW-BP18` | §6.3.5 | §6.3.5 | policy.rs:647 |
| `brokered_and_inline_credentials_exceed_like_exposed` | `FW-BP18` | `default_reference()` | `Broker("github")`, inline entry → 2 × `Excess::Credential(_)` | types.rs:673 |
| `write_inside_cwd_is_within_and_outside_exceeds` | `FW-BP18` | `cwd(p)` | `$CWD/src/**` → `[]`; `~/.claude/**` → `[Excess::Write(_)]` | protected_paths.rs:319, :333 |
| `dropping_a_write_subtract_row_exceeds` | `FW-BP18` | `default_reference()` minus `**/.git/hooks/**` | → `[Excess::WriteDenyRemoved(p)]`, `p` equals the row | policy.rs:647 |
| `ambient_read_mode_exceeds_a_closed_record` | `FW-BP18` | `record_reference(closed)` | candidate ambient → `Excess::ReadMode { .. }`; extra ambient reads → no item | types.rs:941 |
| `exec_unrestricted_exceeds_only_an_allowlist_record` | `FW-BP18` | both references | default → `[]`; allow-list record → `[Excess::Exec]` | policy.rs:638 |
| `dropping_an_isolate_member_exceeds` | `FW-BP18` | record with `processes` | candidate `[]` → `[Excess::IsolateRemoved(IsolateMember::Processes)]` | — |
| `channel_lift_mcp_server_and_env_passthrough_exceed` | `FW-BP18` | `default_reference()` | 3 items, axes `== ["env","mcp","channel"]` | fw:narrow.rs:413 |
| `auto_widen_zone_in_the_candidate_exceeds` | `FW-BP18` | `default_reference()` | zone `$CWD/.cache/**` → `[Excess::AutoWiden(_)]` | — |
| `grants_inside_the_reference_zone_are_within` | `FW-BP18` | record with zone | read + write `$CWD/.cache/x/**` → `[]`; `$CWD/y/**` → 1 item | [FW-E2E-052](../formwork.md#fw-e2e-052) |
| `cwd_sentinel_and_absolute_launch_path_differ` | `FW-BP18` | `cwd(p)` | `$CWD/**` → `[]`; `/work/p/**` → `[Excess::Write(_)]` (conservative) | — |
| `excess_items_follow_blueprint_field_order` | `FW-FID14` | 4-axis candidate | axes `== ["write","net","credential","channel"]` | — |
| `decide_runs_first_use_within_the_default` | `FW-BP20` | `digest_fixture(1)` | no record, narrower → `Decision::RunFirstUse` | migration.rs:302 |
| `decide_writes_nothing_within_a_record` | `FW-BP20` | `record_reference(..)` | → `Decision::Run` | wiring.rs:2020 |
| `decide_refuses_without_terminal_or_flag` | `FW-BP21` | — | → `Refuse(Refusal::Unapproved { excess })`, `excess.len() == 2` | migration.rs:141-151 |
| `decide_asks_when_a_terminal_is_attached` | `FW-BP17` | — | terminal → `Decision::Ask { excess }` | migration.rs:350 |
| `decide_runs_a_matching_flag_and_records` | `FW-BP21` | — | flag = digest → `RunApproved` | package_cmd.rs:1097-1120 |
| `decide_refuses_a_mismatched_flag_even_when_narrowing` | `FW-BP21` | — | → `Refusal::DigestMismatch { named, actual }`, both `assert_eq!` | package_cmd.rs:1108-1118 |
| `record_round_trips_through_toml` | `FW-BP20` | `record_fixture()` | `toml::to_string` → `from_str` → `assert_eq!` | types.rs:1063 |
| `record_with_an_unknown_key_is_refused` | `FW-BP18` | `record_toml()` + `extra = 1` | → `RecordError::Malformed { .. }` | types.rs:1050 |
| `record_of_a_foreign_kind_is_refused` | `FW-BP18` | `kind = "trust-policy"` | → `RecordError::ForeignKind { .. }` | CHANGELOG.md:880 |
| `record_of_a_newer_version_is_refused` | `FW-BP18` | `version = 2` | → `RecordError::UnsupportedVersion { found: 2 }` | types.rs:1050 |
| `digest_parse_accepts_only_sha256_with_64_lowercase_hex` | `FW-BP21` | literals | 64 → `Ok`; 63, 65, uppercase, `sha1:`, `""` → `MalformedDigest` | digest.rs:90 |

`formwork-cli/src/approval.rs` — nono's digest.rs carries 10 tests, wiring.rs 31 (file-write
discipline), protected_paths.rs 12; this module plans 17, since Formwork writes one file kind.

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `input_digest_of_a_fixed_set_matches_its_pinned_vector` | `FW-BP19` | `inputs(&[(Role::File, b"net = \"deny\"\n")])` | `input_digest` → `assert_eq!` a literal pinned when first computed | digest.rs:57, :67 |
| `input_digest_is_deterministic` | `FW-BP19` | same set twice | equal | digest.rs:76 |
| `input_digest_changes_with_one_byte` | `FW-BP19` | flip one byte | `assert_ne!` | digest.rs:83 |
| `input_digest_is_order_and_role_sensitive` | `FW-BP19` | swap two inputs; same bytes as `File` vs `Extends` | both `assert_ne!` | — |
| `input_digest_framing_resists_boundary_shift` | `FW-BP19` | `["ab","c"]` vs `["a","bc"]` | `assert_ne!` | — |
| `input_digest_ignores_the_path` | `FW-BP19` | same bytes at two paths | `assert_eq!` | test_trust_cli.sh:483-496 (contrast) |
| `state_dir_prefers_an_absolute_xdg_state_home` | `FW-BP22` | `env(&[("XDG_STATE_HOME","/s"),("HOME","/h")])` | → `/s/formwork` | state_paths.rs:27-41 |
| `state_dir_ignores_a_relative_xdg_state_home` | `FW-BP22` | `XDG_STATE_HOME=rel` | → `/h/.local/state/formwork` | state_paths.rs:33-36 |
| `state_dir_without_home_is_an_error` | `FW-BP22` | `env(&[])` | `is_err()` | — |
| `record_path_is_fixed_width_hex` | `FW-BP20` | blueprint path with `..` text and non-ASCII | file stem 64 hex chars, parent `= state/approvals` | package.rs:419 |
| `write_record_creates_0700_dir_and_0600_file` | `FW-BP20` | `Scratch::new` | mode bits `assert_eq!(0o700)`, `(0o600)` | test_trust_cli.sh:436-438 |
| `write_record_does_not_follow_a_planted_temp_symlink` | `FW-BP20` | symlink at the temp name → victim | victim unchanged, record written | wiring.rs:2123 |
| `write_record_refuses_a_symlinked_approvals_dir` | `FW-BP20` | `approvals` → elsewhere | `is_err()`, target empty | wiring.rs:2161 |
| `read_record_refuses_a_group_writable_file` | `FW-BP18` | mode 0620 | `is_err()` | — |
| `read_record_refuses_a_record_bound_to_another_path` | `FW-BP18` | `blueprint` field differs | `RecordError::PathMismatch` (via `downcast_ref`) | trust_scan.rs:1835 |
| `read_record_accepts_the_limit_and_refuses_one_byte_more` | `FW-BP18` | padded valid record of record-limit, +1 | `Ok`, `is_err()` | — |
| `approval_answer_requires_explicit_yes` | `FW-BP17` | `"y"`, `" YES \n"`, `""`, `"n"`, `"yes please"` | true, true, false, false, false | migration.rs:350 |

Extended modules (existing tests keep their names):

| Test fn | Discharges | Fixture | Arrange → Act → Assert | Modelled on |
|---|---|---|---|---|
| `inputs_are_listed_in_resolution_order` (blueprint_load) | `FW-BP19` | `Scratch` with base, file, discovered | roles `== [Extends, File, Discovered]`, canonical paths | fw:blueprint_load.rs:1161 |
| `builtin_bases_and_set_fragments_are_not_inputs` | `FW-BP19` | `builtin:default` + `--set` | `inputs.len() == 1` | fw:blueprint_load.rs:1287 |
| `cli_extends_file_is_an_input` | `FW-BP19` | `--extends ./extra.toml` | role `CliExtends` present | — |
| `each_input_is_read_once` | `FW-BP19` | counting reader closure | `assert_eq!(count(path), 1)` per input | trust_scan.rs:1509 |
| `builtin_reference_cannot_be_shadowed_by_a_file` | `FW-BP19` | file named `builtin:default` | merged `net == Deny`; not an input | CHANGELOG.md:1563 |
| `default_reference_fixture_matches_the_loaded_builtin` | `FW-BP18` | `default_reference()` | `assert_eq!` against the CLI's load of the minimal blueprint | — |
| `proposal_path_lives_under_the_state_dir` (learn) | `FW-BP22` | state `/s` | `/s/proposals/<64 hex>.proposal.toml` | — |
| `accept_records_when_the_pre_accept_inputs_are_within_the_record` | `FW-BP20` | `Scratch` + `record_fixture()` | record digest = post-accept digest, `recorded-by = accept` | wiring.rs:2329 (inverse) |
| `accept_records_nothing_after_an_exceeding_edit` | `FW-BP20` | discovered layer given an out-of-zone grant first | record bytes unchanged | wiring.rs:2329 |
| `state_dir_row_denies_store_writes_under_a_home_grant` (linux_confine) | `FW-BP22`, `FW-INV16` | `Fixture` with home/state/project | write in state ≠ 0; create in project = 0 | protected_paths.rs:257 |
| `split_ancestor_of_the_state_dir_cannot_be_renamed` | `FW-FID15` | same | `mv` of `.local/state` ≠ 0 | — |
| `project_root_without_policy_rows_is_whole` | `FW-BP22` | `readwrite:<root>/**` only | `touch <root>/new` = 0 | fw:landlock.rs:106-157 |
| `c10_rename_of_an_ancestor_of_a_denied_subpath` (macos_characterize) | `FW-FID15` | `ambient(dir)` + deny row | records the observed answer for `docs/macos-characterization.md` | FEP-5 C1–C9 |

Shape tests in `approval_run.rs`: `explain_stamp_has_exactly_the_v1_key_set` and
`approval_record_has_exactly_the_v1_key_set` (`BTreeSet` equality against the goldens, modelled on
`assert_properties_at`, nono@9edf3ea:crates/nono-cli/tests/schema_shape.rs:19-30), and
`policy_and_report_are_byte_identical_with_and_without_a_record` ([FW-FID4](../formwork.md#fw-fid4)).

#### 6.3.3 Fixtures and helpers to add

- Pure (`approval.rs` tests): `fn default_reference() -> Blueprint` (a literal mirror of
  `profiles/default.toml` plus `$CWD` sentinel write, checked equal to the CLI's loaded default by one
  `blueprint_load` test); `fn record_reference(bp: Blueprint) -> Reference`; `fn cwd(rel: &str) ->
  PathPattern`; `fn digest_fixture(byte: u8) -> InputDigest`; `fn record_fixture() -> ApprovalRecord`;
  `fn record_toml() -> String`. They follow nono's `make_policy` and `keyed_publisher`
  (nono@9edf3ea:crates/nono/src/trust/policy.rs:397-424): one builder per input, every field named.
- Shell (`formwork-cli/src/approval.rs` tests): `fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl
  Fn(&str) -> Option<OsString> + 'a`, fed to `state_dir(env: &dyn Fn(&str) -> Option<OsString>)`;
  `fn inputs(set: &[(Role, &[u8])]) -> Vec<ResolvedInput>`. No `tempfile` dependency: the repo's
  `Scratch` (`blueprint_load.rs:1141`) returns its guard, as nono's `setup_test_dir` returns its
  `TempDir`.
- Existing binary-driven tests: `formwork_command` sets `XDG_STATE_HOME` to a sibling of the
  scratch directory, and `pub fn approved(dir: &Path, args: &[&str]) -> Vec<String>` inserts
  `--approve` with the digest from `explain --json`, the CI recipe, for tests whose blueprints exceed
  the default reference but do not test the gate; py `run_cli` gains `approve=True` for the same.
- Binary-driven (`tests/support/mod.rs`): `pub struct Isolated { root, home, state, workspace }`,
  `Isolated::new(tag)` rooted at `env!("CARGO_TARGET_TMPDIR")`, and `pub fn formwork_isolated(iso:
  &Isolated, args: &[&str], env: &[(&str, &str)]) -> Output` setting `HOME`, `XDG_STATE_HOME`
  and the working directory. It mirrors `NonoTest` (nono@9edf3ea:crates/nono-test-support/src/lib.rs:20-70):
  state is a sibling of home and workspace, because `Scratch` makes `$HOME` the launch directory,
  which would put the state directory inside the project grant, and the root is outside `/tmp`,
  because `builtin:default` grants `/tmp/**` and a state row there would split it. Py:
  an `isolated` fixture in `conftest.py` with the same layout under `target/test-artifacts/py/`.
- Goldens: `crates/formwork-cli/tests/fixtures/explain-stamp-v1.json`,
  `crates/formwork-cli/tests/fixtures/approval-record-v1.toml`.

#### 6.3.4 Patterns adopted from nono, and the ones designed out

1. **Forked child reports by exit status.** Kernel tests use `linux_confine.rs`'s `run(policy, cmd)`
   (`spawn_confined` then the exit code), the pattern of nono@9edf3ea:crates/nono/src/sandbox/linux.rs:5993-6030.
2. **Silent capability gating, designed out.** New kernel and binary tests call `not_exercised(reason)`
   (`crates/formwork-cli/tests/support/mod.rs:127-133`), which fails under `FW_REQUIRE_EXERCISED=1`;
   `linux_confine.rs` gains the helper `macos_characterize.rs:40` already has. Gates: Landlock ABI ≥ 1
   for `FW-E2E-109`/`FW-ADV-026`; `strace` for `FW-E2E-113` on Linux.
3. **Environment as a parameter.** `state_dir` and the terminal check take their inputs as arguments,
   following `formwork_blueprint::construct_env`; no test mutates process environment, so nono's
   `ENV_LOCK`/`EnvVarGuard` (test_env.rs:15-18) is not needed.
4. **Contract shape tests.** The stamp and the record get exact-key-set tests and v1 goldens (§6.3.2);
   the report key joins the existing per-capability shape checks.
5. **Property tests.** `excess_over(r, c).is_empty()` iff `r.narrow(&c)` keeps every grant of `c`,
   and `excess_over(b, b)` is empty for all `b`. With no `proptest` in the tree, the stand-in is the
   example tests above plus a table of 12 blueprint pairs, registered in `docs/STATUS.md` beside
   [FW-INV1](../formwork.md#fw-inv1)'s row; the property lands with the fuzz-infra FEP
   (`ProptestConfig::with_cases(64)`, strategies over `Blueprint` fields, as
   nono@9edf3ea:crates/nono-cli/tests/manifest_roundtrip.rs:710-720, :867).
6. **Regression tests named for the defect,** with a doc comment citing the finding:
   `credential_lift_and_host_rule_exceed_the_default` (the cloned-blueprint finding, §1),
   `project_root_without_policy_rows_is_whole` (landlock.rs:106-157, main.rs:1634),
   `inputs_are_listed_in_resolution_order` (`protect_policy_inputs` left bases writable), and the
   rows citing CHANGELOG entries above.
7. **Shell suites, designed out.** nono's `expect_success`/`expect_failure`
   (nono@9edf3ea:tests/lib/test_helpers.sh:47-170) and `require_working_sandbox` (:322) become pytest
   cases with markers; none skips silently.

#### 6.3.5 Worked example

```rust
/// FW-BP17, FW-BP18. Verified finding: a cloned FORMWORK.toml lifted the credential floor and
/// opened the network with one INFO line (crates/formwork-cli/src/blueprint_load.rs:86-171).
/// Modelled on nono@9edf3ea:crates/nono/src/trust/policy.rs:647 `merge_project_cannot_weaken`.
#[test]
fn credential_lift_and_host_rule_exceed_the_default() {
    let reference = Reference::Default(default_reference());
    let candidate = Blueprint {
        net: NetPosture::AllowHosts(HostTable::new(vec![
            HostRule::parse("allow", "egress.example").expect("host rule"),
        ])),
        allow_credentials: vec![CredentialEntry::Expose("aws".into())],
        ..default_reference()
    };

    let excess = excess_over(reference.blueprint(), &candidate);
    assert_eq!(excess.len(), 2);
    assert!(matches!(excess[0], Excess::Net(_)));
    assert!(matches!(&excess[1], Excess::Credential(CredentialEntry::Expose(t)) if t == "aws"));

    let digest = digest_fixture(0x11);
    let refused = decide(&reference, &candidate, &digest, None, false);
    assert!(matches!(
        refused,
        Decision::Refuse(Refusal::Unapproved { ref excess }) if excess.len() == 2
    ));
    let admitted = decide(&reference, &candidate, &digest, Some(&digest), false);
    assert!(matches!(admitted, Decision::RunApproved));
}
```

```python
@pytest.mark.fw_e2e("FW-E2E-107")
def test_cloned_blueprint_that_lifts_a_credential_does_not_spawn(cli, isolated):
    repo = isolated.project("FORMWORK.toml", EXCEEDING)  # aws lift + allow:egress.example
    marker = repo / "spawned"
    refused = cli("run", "--", "/usr/bin/touch", marker, cwd=repo, env=isolated.env)
    assert refused.code == 1 and not marker.exists()
    stamp = json.loads(cli("explain", "--json", cwd=repo, env=isolated.env).stdout)["blueprint"]
    assert (stamp["approval"], stamp["reference"]) == ("unapproved", "default")
    assert [e["axis"] for e in stamp["excess"]] == ["net", "credential"]
    admitted = cli("run", "--approve", stamp["digest"], "--", "/usr/bin/touch", marker,
                   cwd=repo, env=isolated.env)
    assert admitted.code == 0 and marker.exists()
```

### 6.4 Traceability (draft rows for formwork.md §10)

| Requirement | Primary test | Also |
|---|---|---|
| `FW-BP17` Approval gate | `FW-E2E-107` | `FW-E2E-115`, `FW-E2E-116` |
| `FW-BP18` Reference | `FW-E2E-108` | `FW-E2E-113`, `FW-ADV-027`, `FW-ADV-028` |
| `FW-BP19` Input digest | `FW-E2E-110` | `FW-E2E-111`, `FW-E2E-116`, `FW-ADV-029` |
| `FW-BP20` Approval records | `FW-E2E-112` | `FW-E2E-113` |
| `FW-BP21` Named approval | `FW-E2E-111` | `FW-E2E-107`, `FW-E2E-115` |
| `FW-BP22` State directory | `FW-E2E-109` | `FW-E2E-112`, `FW-ADV-026` |
| `FW-FID14` Excess listing | `FW-E2E-107` | `FW-E2E-110`, `FW-E2E-114` |
| `FW-FID15` Store report line | `FW-E2E-114` | `FW-ADV-026` |
| `FW-INV16` Approval provenance | `FW-E2E-108` | `FW-ADV-026`, `FW-ADV-028` |
| [FW-FID7](../formwork.md#fw-fid7) (amended stamp) | `FW-E2E-114` | `FW-E2E-111` |

### 6.5 Phasing

1. **Pure core.** `formwork-blueprint/src/approval.rs` and its 24 tests; no behavior change.
2. **Gate, digest, store, in one change.** Single-read loader with inputs, `formwork-cli/src/approval.rs`,
   the gate in `prepare_session` and the `learn` shim forwarding, `--approve`, the proposal move, the
   state-directory row, and the deletion of `protect_policy_inputs` and `announce_split_root`. No
   release carries the deletion without the gate. Existing tests move to `approved(..)` (§6.3.3);
   `py/harness/test_learn_review.py`,
   `test_discovery.py`, `test_learn_linux.py` and `crates/formwork-cli/tests/{cli_surface,fep5_run}.rs`
   update their proposal paths. Tests: `FW-E2E-107`, 108, 110–113, 115, 116; `FW-ADV-027`–029.
3. **Reporting and kernel tests.** Stamp keys, `approval-store`, goldens; `FW-E2E-109`, 114; the
   Linux arms of `FW-ADV-026`.
4. **macOS characterization C10** on `macos-14` and `macos-15`, then `FW-FID15` and `FW-INV16` anchor.

## 7. Amendments to the landed docs (apply on landing)

- **(a) Constitution, Concepts, Launcher.** Replace "write-protects the blueprint/proposal files the
  session was launched from ([FW-XR8](../formwork.md#fw-xr8))" with "gates a launch whose
  file-sourced blueprint exceeds its reference on the operator's approval of the input digest, and
  write-denies its own state directory in every session ([FW-XR8](../formwork.md#fw-xr8),
  `FW-BP17`, `FW-BP22`)".
- **(b) Constitution, Data model.** Add the approval record (`<state>/approvals/*.toml`) to the
  discovery artifacts' bullet as a machine-written, operator-approved surface; the proposal's
  location moves to `<state>/proposals/`.
- **(c) Constitution, Vocabulary.** **approve** = the operator's acceptance of an input digest whose
  file-sourced blueprint exceeds its reference (`FW-BP17`), distinct from **accept** (per discovery
  entry); **reference**, **default reference**, **exceed**/**excess**, **input digest** and **state
  directory** as defined in §3.
- **(d) `formwork.md` §2.** The Launcher paragraph and the diagram line
  `policy-input write-protect (FW-XR8)` become `approval gate; state-dir write-deny (FW-XR8)`.
- **(e) Requirement text.** [FW-FID6](../formwork.md#fw-fid6) "the session-only denies `run` adds
  ([FW-CRED3](../formwork.md#fw-cred3), [FW-XR8](../formwork.md#fw-xr8))" becomes
  "([FW-CRED3](../formwork.md#fw-cred3), `FW-BP22`)". [FW-FID7](../formwork.md#fw-fid7) gains: "the
  `blueprint` stamp carries the input digest, each input with its role and SHA-256, the approval
  state, the reference kind and the excess list". [FW-FID8](../formwork.md#fw-fid8)'s key list
  gains `approval-store`. [FW-DISC11](../formwork.md#fw-disc11): the proposal convention is
  `<state>/proposals/<hex>.proposal.toml`. [FW-BP8](../formwork.md#fw-bp8) is unchanged; its
  discussion cites `FW-BP17` for files the walk trusts by owner but the operator has not approved.
- **(f) `docs/fep-5.md` §2 D3** gains: "superseded by FEP-7: the `.formwork/` layout did not keep
  the root whole; `.formwork/blueprint.toml` stays a discovery location".
- **(g) `formwork.md` §10** gains the rows of §6.4; `docs/STATUS.md` gains the FEP-7 row, the
  property-test exception (§6.3.4 item 5), and the C10 characterization.
- **(h) README and `examples/`.** User-facing, no IDs: "the first run of a blueprint that grants more
  than the default asks once"; `examples/claude-code/README.md` and the CI recipe show
  `formwork run --approve <digest> -- true` before an MCP host launches `formwork gateway`.

## 8. Decisions (recorded per constitution Precedence & Conflicts)

- **The approval gate replaces in-tree write protection on both backends** (§3.5). This changes how
  [FW-XR8](../formwork.md#fw-xr8) is realized, not its statement; the constitution's Launcher text
  is amended (§7 a) rather than deviated from.
- **Narrowing never asks; excess is relative to the reference, not only to `builtin:default`.** A
  tight blueprint's own loosening asks, which a default-only comparison would miss; the first-use
  record makes the operator's file the reference without a prompt.
- **Flag, no environment variable.** One spelling per surface (Growth); an inherited variable would
  also approve nested invocations silently, nono's `NONO_AUTO_MIGRATE` shape.
- **Digest independent of path; records bound to path.** CI pins survive checkout location; an
  approval of `aws` for one repository does not transfer to a byte-identical file elsewhere.
- **Store readable, not writable.** Nested invocations honor records; reading reveals paths a session
  under the default profile can already list.
- **Split, not refuse.** nono refuses a grant over its state root on Linux (protected_paths.rs:68-105);
  Formwork's subtractive expansion carves the hole, so `readwrite:~/**` keeps working.
- **A corrupt record refuses.** Reading it as absent would fall back to a wider reference.
- **Signing and instruction-file attestation declined** (§3.7). **No new concept, family, crate or
  subcommand.**

## 9. Open questions

| Question | Owner | Closes at |
|---|---|---|
| Does Seatbelt refuse renaming an ancestor of a write-denied subpath (C10)? Decides `approval-store` on macOS under broad home grants | macOS backend maintainer | Phase 4, before `FW-FID15` anchors |
| The default reference inherits `profiles/default.toml`'s placeholder `~/project/**` write; drop it from the reference or from the profile | default-profile maintainer | Phase 1 |
| Retention of records for moved or deleted projects (a `--forget` or an age bound) | CLI maintainer | Phase 2 |
| Keep or deprecate `.formwork/blueprint.toml`, whose reason (D3) is gone | CLI surface maintainer | the next release pruning event |
| Signing as provenance beside the diff, if a blueprint distribution channel is proposed | author of that FEP | that FEP |
| The `/tmp` split from Launcher-owned directories (`grant_launcher_dir`) | [FW-TRA9](../formwork.md#fw-tra9) maintainer | a `docs/STATUS.md` owed row, Phase 2 |
