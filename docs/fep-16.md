# FEP-16 (proposal): the credential floor follows the environment — relocated stores, list-valued references, and discovery

**Formwork Enhancement Proposal 16 — proposal, not landed.** This draft describes credential-floor
bypasses found in a security review of `main` at `e6e4572`; none is fixed yet. Companion to
`formwork.md`, `constitution.md` and `profiles/credential-catalog.toml`.

**Status.** Nothing here mutates the landed spec. New identifiers are draft numbering in inline
code. This FEP holds `FW-CRED32`..`FW-CRED35`, `FW-DISC15`..`FW-DISC16`, `FW-E2E-197`..`FW-E2E-202`
and `FW-ADV-054`..`FW-ADV-055`, above FEP-10's `FW-CRED31`, FEP-9's `FW-DISC14` and FEP-15's test
block.

---

## 1. Problem

The Catalog locates credentials two ways ([FW-CRED2](../formwork.md#fw-cred2)): path patterns
under `$HOME`, and environment variable names. A third form,
`env-file-refs` ([FW-CRED3](../formwork.md#fw-cred3)), names a variable whose value is a file to
deny. The launching environment can move a credential out from under all three.

1. **A variable relocates a whole store.** `GNUPGHOME`, `DOCKER_CONFIG`, `CARGO_HOME`,
   `XDG_CONFIG_HOME`, `KUBECONFIG`'s directory and their kin tell a tool where its credentials
   are. The Catalog's paths stay `$HOME`-relative (`crates/formwork-blueprint/src/catalog.rs:90-100`).
   With `GNUPGHOME=/secure/gnupg`, `explain` reports `/secure/gnupg/private-keys-v1.d/k.key` as
   "allowed by default" under `builtin:default`, the report shows `gpg` path `enforced`, and the
   child inherits the variable, because its name is not scrub-shaped.
2. **A list-valued reference is read as one path.** `KUBECONFIG=a.yaml:b.yaml` is ordinary
   `kubectl` usage. The loader builds a single deny for the nonexistent path `a.yaml:b.yaml`
   (`crates/formwork-cli/src/blueprint_load.rs:794-828`); both files stay readable and the report
   shows `kube` path `enforced`.
3. **Discovery does not know what the Launcher denied.** The env-file-ref denies go into the
   session's `subtract` only (`crates/formwork-cli/src/main.rs:1218-1226`). `learn` floors by
   catalog path shape (`crates/formwork-cli/src/learn.rs:643-648`), so the denial of the file
   `GOOGLE_APPLICATION_CREDENTIALS` names is an ordinary candidate, and inside the auto-widen zone
   it is self-granted. A later run without the variable exported reads the key
   ([FW-DISC3](../formwork.md#fw-disc3) and [FW-INV8](../formwork.md#fw-inv8) say it cannot).

All three were reproduced on Linux 6.18. In each the report says
`enforced` for a credential the session can read.

### 1.1 Constraints

- The Catalog stays a closed, versioned, compiled-in enumeration
  ([FW-CRED1](../formwork.md#fw-cred1)). This FEP adds one field form and entries; it adds no
  general environment interpolation (constitution Vocabulary, **sigil**).
- `compile` stays pure: environment values enter at the CLI edge, as `env-file-refs` values do
  today.
- A reference the Launcher cannot render into a deny fails loud
  ([FW-INV6](../formwork.md#fw-inv6)); the loader already says so for non-UTF-8 values.

## 2. Design

### 2.1 `env-dir-refs`: a variable that relocates a type's store

A Catalog type may list variables whose value is a directory that replaces one of the type's
`$HOME`-relative roots:

```toml
[types.gpg]
paths = ["~/.gnupg/**"]
env-dir-refs = [{ var = "GNUPGHOME", replaces = "~/.gnupg" }]

[types.docker]
paths = ["~/.docker/**"]
env-dir-refs = [{ var = "DOCKER_CONFIG", replaces = "~/.docker" }]

[types.github]
paths = ["~/.config/gh/**"]
env-dir-refs = [{ var = "GH_CONFIG_DIR", replaces = "~/.config/gh" },
                { var = "XDG_CONFIG_HOME", replaces = "~/.config" }]
```

When the variable is set in the launching environment, the Launcher adds, for each of the type's
paths under `replaces`, the same pattern rebased onto the variable's value, and denies it with
the type's floor. The `$HOME`-relative rows stay: a tool that ignores the variable still finds
nothing.

`XDG_CONFIG_HOME`, `XDG_DATA_HOME` and `XDG_STATE_HOME` apply to every type with a path under the
corresponding default directory; the Catalog states them once in a `[relocations]` table and
`ResolvedCatalog` applies them to each type.

`allow-credentials` lifts the rebased rows with the type, as it lifts the others
([FW-CRED5](../formwork.md#fw-cred5)).

### 2.2 List-valued references

A Catalog `env-file-refs` entry may be marked as a list:

```toml
[types.kube]
env-file-refs = [{ var = "KUBECONFIG", list = true }]
```

The Launcher splits the value on `:` and denies each non-empty element. The plain string form
stays for single-file variables. An element that is not an absolute path resolves against the
launch directory, as today.

### 2.3 The proposal records what the Launcher withheld

Two changes, one at each end of discovery.

- **Propose.** `learn` passes the session's Launcher denies (env-file refs, rebased store rows)
  to `reverse_compile` beside the catalog floor. A denial matching one is **withheld** and
  itemized with its type, never a candidate ([FW-DISC3](../formwork.md#fw-disc3)).
- **Accept.** The variable may be unset when `--accept` runs, so the path alone does not say the
  file is a credential. The proposal file gains a `withheld` table: each entry holds the pattern,
  the type and the reason (`env-file-ref` or `env-dir-ref`), written at propose time. `accept`
  refuses any selected candidate a `withheld` entry covers, and the discovered-layer loader
  refuses a grant a `withheld` entry of the sibling proposal covers.

The proposal is a file the session cannot write ([FW-XR8](../formwork.md#fw-xr8)), so the table
is as trustworthy as the candidates beside it.

### 2.4 The report states which locations were resolved

The per-type credential rows gain, for each `env-dir-ref` and `env-file-ref` variable that was
set, the variable's name (never its value) and the count of rows it added. A type whose store
was relocated by a variable the Catalog does not model cannot be detected; the Catalog version
bump and its tests are the control for that, and §5's canary keeps the list honest against the
tools the examples ship.

## 3. Surface changes (each measured against Growth)

| Change | Existing surface searched first |
|---|---|
| Catalog field `env-dir-refs`; `[relocations]` table; `list = true` on `env-file-refs` | `env-file-refs` denies one file per variable and cannot express a directory or a list |
| Catalog version 3, with entries for at least: `GNUPGHOME`, `DOCKER_CONFIG`, `CARGO_HOME`, `GH_CONFIG_DIR`, `AWS_CONFIG_FILE`, `NPM_CONFIG_USERCONFIG`, `PIP_CONFIG_FILE`, `NETRC`, `GIT_CONFIG_GLOBAL`, `SSH_AUTH_SOCK` (already a service), `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME` | — |
| Proposal file: `withheld` table | the proposal has candidates only |
| Report: resolved-reference names per type | the per-type rows say `enforced` with no account of what was resolved |

Draft FEP-10 also proposes a Catalog version 3 with two new types; the two changes compose, and
whichever lands second takes version 4.

No flag, concept or dependency.

## 4. Proposed requirements (draft numbering)

| ID | Statement |
|---|---|
| `FW-CRED32` Relocated stores | For each Catalog `env-dir-refs` variable set in the launching environment, the Launcher shall deny, under the type's floor, every path pattern of the type rebased from the replaced root onto the variable's value. |
| `FW-CRED33` List-valued references | For an `env-file-refs` variable the Catalog marks as a list, the Launcher shall deny each `:`-separated element of its value. |
| `FW-CRED34` Unrenderable references | The Launcher shall refuse to start, naming the variable, when the value of a set `env-file-refs` or `env-dir-refs` variable cannot be rendered into a path pattern. |
| `FW-CRED35` Resolved references are reported | The report shall name, per credential type, each `env-file-refs` and `env-dir-refs` variable that was set and the number of deny rows it added, and no value of any such variable. |
| `FW-DISC15` Launcher denies are floored | Discovery shall withhold, and never propose, a denial that matches a deny the Launcher added for a credential type in the observed session. |
| `FW-DISC16` Withheld entries persist | The proposal shall record each withheld pattern with its credential type, and `accept` and the discovered-layer loader shall refuse a grant that a recorded withheld pattern covers. |

## 5. Verification plan

| ID | Test |
|---|---|
| `FW-E2E-197` | For each `env-dir-refs` entry in the Catalog (table-driven from the embedded file): with the variable pointing at a scratch directory holding a fake credential, the file is denied under enforcement and `explain` names the type; with the variable unset the scratch file is readable. Both backends. |
| `FW-E2E-198` | `KUBECONFIG` with one, two and three elements, an empty element and a relative element: every named file is denied; the report names the variable and the row count. |
| `FW-E2E-199` | The `learn` sequence of §1 item 3: learn with `GOOGLE_APPLICATION_CREDENTIALS` set and the key inside the auto-widen zone; the denial is withheld with type `gcp`, nothing is auto-accepted, and a later run without the variable is still denied. |
| `FW-E2E-200` | `--accept` of a hand-edited proposal that moves a withheld path into the candidates is refused; a discovered layer carrying that grant fails to load. |
| `FW-E2E-201` | A value containing a NUL-free but non-UTF-8 byte, and a `KUBECONFIG` element that is not a renderable pattern: `run` refuses and names the variable. |
| `FW-E2E-202` | Catalog canary (the `profiles.rs` pattern): for each tool the agent examples document (`gh`, `git`, `docker`, `kubectl`, `aws`, `gcloud`, `npm`, `cargo`, `pip`, `gpg`, `ssh`), a fixture list of that tool's documented relocation variables must each appear in the Catalog or in an explicit `not-modelled` list with a reason. |
| `FW-ADV-054` | Under `builtin:default` with every modelled relocation variable set to a directory inside a `readwrite` grant, a confined process sweeps those directories for the planted credential files; none is readable, and no variable's value appears in the report or logs. |
| `FW-ADV-055` | A confined process cannot cause a withheld entry to be dropped: it cannot write the proposal, and a second learning run that does not observe the denial keeps the first run's `withheld` entry. |

**Phasing.** A: `FW-CRED33`, `FW-CRED34` and `FW-DISC15` (small; they close §1 item 3 at
propose time, and item 2). B: `FW-CRED32`, `FW-CRED35` and Catalog version 3 (§1 item 1). C:
`FW-DISC16`.

## 6. Amendments (apply on landing)

- `formwork.md` §5: the rows of §4. [FW-CRED3](../formwork.md#fw-cred3): "and, for a variable
  that names a directory or a list, every location it names". §10 rows.
- `profiles/credential-catalog.toml`: header comment, `version = 3`, the new entries.
- `constitution.md` Data model: the proposal's `withheld` table is part of the discovery
  artifact.

## 7. Decisions

- **Keep the `$HOME` rows when a store is relocated.** A relocation variable is advice to the
  tool; the floor covers both places.
- **Record withheld entries in the proposal** over re-deriving them at accept time: the
  environment at accept time is a different environment.
- **Enumerate variables in the Catalog** over a heuristic on variable names ending in `_HOME` or
  `_CONFIG`: a heuristic would deny build directories (`JAVA_HOME`, `GOPATH`) and still miss
  `NETRC`.

## 8. Open questions

| Question | Owner | Closes at |
|---|---|---|
| Should a set relocation variable also be stripped from the child's environment when its type is floored? Stripping hides the pointer; it also changes tool behavior for a store the session could not read anyway. | reviewer | adoption |
| `XDG_CONFIG_HOME` rebasing denies `<value>/gh/**` and the like. Is there a type whose XDG path is shared with non-credential files a session needs? Check each Catalog type. | implementer | phase B |
| Two smaller defects in the same area are fixes with no design question: a literal write grant admits a UNIX socket that the credential floor or a `deny` covers (`unix_socket_grants` in `crates/formwork-compile/src/lib.rs:125-136` is not filtered by either), and the env scrub tests `allow` before an explicit `deny` (`crates/formwork-blueprint/src/lib.rs:365-373`). Land them with phase A, or separately? | reviewer | now |
