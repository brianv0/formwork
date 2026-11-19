# FEP-13 (proposal): one meaning for a path pattern on Linux, on macOS and in `explain`

**Formwork Enhancement Proposal 13 — proposal, not landed.** This draft describes fail-opens found
in a security review of `main` at `e6e4572`; none is fixed yet. Companion to `formwork.md` and
`constitution.md`.

**Status.** Nothing here mutates the landed spec. New identifiers are draft numbering in inline
code. This FEP holds `FW-BP27`..`FW-BP31`, `FW-FID31`, `FW-E2E-178`..`FW-E2E-184` and
`FW-ADV-048`..`FW-ADV-049`, above FEP-12's blocks.

---

## 1. Problem

A path pattern is the unit of every filesystem grant and deny. The same pattern means different
things to the three components that read it.

| Pattern | Pattern model and `explain` (`formwork-blueprint/src/path.rs`) | Landlock (`formwork-confine/src/linux/landlock.rs`) | Seatbelt (`formwork-compile/src/sbpl.rs`) |
|---|---|---|---|
| literal on a directory, as a grant: `read:/a/data` | matches `/a/data` only | the directory and everything beneath it (`root_of`, `:327-332`) | `(literal "/a/data")`: the entry only |
| literal on a directory, as a deny: `deny:/a/secrets` | matches `/a/secrets` only | the whole subtree is dropped from the expansion (`:90-104`) | `(deny … (literal "/a/secrets"))`: files beneath stay open |
| any-depth grant: `read:/srv/**/data/**` | every `data/` under `/srv` | `./data` under the launcher's cwd, wherever that is | a regex; correct |
| any-depth deny from the operator: `deny:**/secrets.yaml` | every match | refused at enforce, after `compile` said `enforced` (#57) | a regex; correct |
| `deny:/srv/keys/*.pem` | the file named `*.pem` | the same | `(literal "/srv/keys/*.pem")` |
| `deny:secrets.json` | not a path: a host rule for the host `secrets.json` (FW-BP16) | — | — |

Verified on Linux 6.18 with Landlock ABI 7: a literal directory grant
reads the subtree while `explain` answers "not granted"; an anchored any-depth write grant under
`/srv/elsewhere` wrote into the launch directory; `deny:$CWD/secrets`, the recipe in
`examples/README.md`, denies the files on Linux, leaves them readable in the macOS profile, and
`explain` calls them granted on both.

Each row is a place where [FW-XR6](../formwork.md#fw-xr6) (parity) or
[FW-INV5](../formwork.md#fw-inv5) (report soundness) does not hold, and three of them widen a
grant or void a deny without a message ([FW-INV6](../formwork.md#fw-inv6)).

### 1.1 Constraints

- The grammar stays closed ([FW-BP4](../formwork.md#fw-bp4): "no general glob"). This FEP removes
  ambiguity; it adds no pattern form.
- Landlock has no deny rule and no pattern rule. What it cannot express is refused or reported,
  never approximated.
- `compile` stays pure: it cannot stat a path to learn whether it is a directory.

## 2. Design

### 2.1 A literal names one filesystem object and, when that object is a directory, nothing beneath it

The pattern model is right and the backends move to it.

- **Linux, grants.** For a literal grant the confiner opens the path and checks its type. A
  regular file gets a file rule, as today. A directory gets a rule carrying only the rights that
  apply to the directory itself (`ReadDir` for a read grant; no `ReadFile`, `WriteFile` or
  `Make*`), which Landlock expresses by adding the rule with a rights mask that excludes the
  per-file rights. Entries beneath are not granted.
- **Linux, denies.** A literal hole on a directory removes that directory from the expansion and
  keeps its children governed by the rules that cover them. Since a child of an unlisted
  directory cannot be reached by path, the observable result on Linux is still that the subtree
  is unreachable; the report states this as a `Partial` divergence for a literal directory deny
  (wider than asked), and `explain` on a Linux host says "unreachable: parent denied".
- **macOS.** Unchanged: `(literal …)` already means this.
- **`run` warns once** when a literal deny names an existing directory: "`deny:/a/secrets` names
  a directory and covers only the directory entry; write `deny:/a/secrets/**` to cover its
  contents". The three shipped recipes change to the `/**` form (§5).

The alternative, making a bare directory pattern mean its subtree everywhere, was rejected: it
changes the meaning of every existing literal grant on macOS, and it makes `readwrite:$SSH_AUTH_SOCK`
(a literal on a socket, the documented way to grant one) a special case.

### 2.2 Any-depth grants are refused for a Linux target

`compile` for a Linux host refuses a blueprint whose `reads`, `writes`, `writes-no-create` or
exec paths contain an any-depth pattern, naming the row. The confiner's `root_of` refuses the
same input independently, so a policy that reaches it by another route fails closed.

Expanding the pattern by walking the tree at enforce time was rejected: the set is unbounded, it
is stale the moment a matching directory is created, and Landlock cannot follow it.

### 2.3 Any-depth operator denies are refused for a Linux target

Same rule, same error shape (resolves #57). The floor's own any-depth rows stay withheld and
reported ([FW-CRED9](../formwork.md#fw-cred9)): the operator did not write those and cannot
remove them, so refusing would make the default profile unusable on Linux. An operator row is a
statement the operator can rewrite.

### 2.4 Glob characters are refused at parse

`PathPattern::parse` refuses a component containing `*`, `?` or `[` outside the two `**` forms,
with an error that shows the nearest valid spelling. A file whose name contains one of these
characters is written with a backslash escape (`/srv/odd\*name`).

### 2.5 A path target is spelled as a path

[FW-BP16](../formwork.md#fw-bp16) reads a rule target as a path when it begins with `/`, `~`, `$`
or `**`, and otherwise as a host. Two additions:

- `./name` is accepted as a path relative to the launch directory (it expands like `$CWD/name`).
- A host target with no port and no path whose text names an existing entry in the launch
  directory is refused, with both spellings shown: "`deny:secrets.json` is a host rule; for the
  file write `deny:./secrets.json`, for the host write `deny:secrets.json:443`".

### 2.6 Discovery never parses an observed path

`reverse_compile` builds a candidate from an observed path with a constructor that cannot produce
a subtree or any-depth pattern. A record whose path has a `**` component is withheld and
itemized.

### 2.7 `explain` answers from the compiled policy for the host

For a Linux host `explain` reports a path beneath a literal directory grant as not granted, a
path beneath a literal directory deny as unreachable, and refuses the same blueprints `run`
refuses, with the same message.

## 3. Surface changes (each measured against Growth)

| Change | Why no existing surface serves |
|---|---|
| `./` as a path prefix | `$CWD/` exists and stays; `./` is what an operator types after reading an error about a relative name |
| `\` escape for `*`, `?`, `[` in a path component | none exists; without it the refusal in §2.4 makes such files unnameable |
| Two new load errors, one new `run` warning | the current behavior is silence |

No blueprint field, flag, concept or dependency.

## 4. Proposed requirements (draft numbering)

| ID | Statement |
|---|---|
| `FW-BP27` Literal extent | A literal path pattern shall confer or deny access to exactly the filesystem object it names and to no entry beneath it, on both backends. |
| `FW-BP28` Any-depth rows on Linux | For a Linux host the compiler shall refuse a blueprint whose operator-authored grant or deny contains an any-depth pattern, naming the row and the reason. |
| `FW-BP29` Glob characters | The Blueprint parser shall refuse a path pattern containing an unescaped `*`, `?` or `[` outside the `/**` and `**/` forms. |
| `FW-BP30` Path spelling | The Blueprint parser shall read a target beginning with `./` as a path under the launch directory, and the CLI shall refuse a host target with no port and no path that names an existing entry of the launch directory. |
| `FW-BP31` Observed paths are literals | Discovery shall construct each filesystem candidate as a literal pattern of the observed path, and shall withhold a record whose path contains a `**` component. |
| `FW-FID31` Explain follows the host | For every path, `explain` shall report the access the compiled policy for the named host confers, including the reduced extent of a literal directory row. |

## 5. Verification plan

| ID | Test |
|---|---|
| `FW-E2E-178` | Literal directory grant, paired, both backends: the directory lists; a file beneath it is refused; `explain` says not granted. Kernel arms in `linux_confine.rs` and `macos_confine.rs`. |
| `FW-E2E-179` | Literal directory deny, both backends: the report names the Linux divergence; `explain` matches the probe on each. |
| `FW-E2E-180` | Any-depth grant and any-depth operator deny for `--target linux-v6`: `compile`, `explain` and `run` each refuse with the same message; the macOS target compiles and enforces both. |
| `FW-E2E-181` | `deny:/srv/keys/*.pem` is a parse error; the escaped form denies the file named `*.pem`. |
| `FW-E2E-182` | `deny:secrets.json` with that file present is refused naming both spellings; `deny:./secrets.json` denies the file under enforcement. |
| `FW-E2E-183` | Every `rules` line in `README.md`, `examples/README.md` and `examples/blueprints/*.toml` that names a directory in a deny uses `/**` (a harness canary). |
| `FW-E2E-184` | `learn` on a workload that opens a file literally named `**` proposes nothing for it and itemizes the withheld record. |
| `FW-ADV-048` | The anchored any-depth escape of §1: with the fix reverted the write outside the anchor succeeds; with it, `run` refuses to start. |
| `FW-ADV-049` | A confined process creates and opens names containing `**`, `*` and `?` inside the auto-widen zone; no candidate wider than one path reaches the discovered layer. |

## 6. Amendments (apply on landing)

- `formwork.md` §5: the rows of §4; a sentence under [FW-CAP6](../formwork.md#fw-cap6) on literal
  extent; §9 matrix: literal directory deny, Linux, `Partial`.
- `docs/linux-backend.md`: replace "Landlock governs the path and everything beneath it either
  way" with the directory-rights rule of §2.1; add operator any-depth rows to the refused list.
- `examples/README.md:100`, `:138`, `formwork.md:132`, `examples/blueprints/rules-demo.toml:19`
  and the `--rule` help text: `deny:<dir>/**`.

## 7. Decisions

- **Literal means the object.** Chosen over "bare directory means subtree" (§2.1).
- **Refuse, do not approximate.** An any-depth row Landlock cannot root is an error for a Linux
  target, for grants and for operator denies alike (constitution Boundaries).
- **This breaks blueprints** that relied on a literal directory grant covering its subtree on
  Linux. No release has shipped; the change is made outright and the error names the fix.

## 8. Open questions

| Question | Owner | Closes at |
|---|---|---|
| Does a Landlock rule with only directory rights on a directory behave as §2.1 states on ABI 1 through 7? Characterize before anchoring `FW-BP27`. | implementer | spike, before phase 1 |
| Should the literal-directory-deny warning be an error when the directory exists and has entries? | reviewer | adoption |
| Is a backslash the right escape, given TOML basic strings already use it? A literal string (`'…'`) avoids doubling. | reviewer | adoption |
