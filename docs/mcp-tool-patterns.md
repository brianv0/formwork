# MCP tool patterns — requirement clarification & design record

Status: adopted. Mints [`FW-GW9`](../formwork.md#fw-gw9) and the end-to-end tests
[`FW-E2E-065`](../formwork.md#fw-e2e-065)–[`FW-E2E-069`](../formwork.md#fw-e2e-069). This note
records *why* the feature is shaped the way it is; the normative statements live in `formwork.md`.

## The gap this closes

Before this change, a `[mcp.<server>]` axis (`tools`, `resources`, `prompts`) was an exact-name
allowlist: `AllowAll | Allow([names]) | Deny`. Two limits fell out of that:

1. **No patterns.** A real server exposes dozens of tools with shared prefixes (`get_*`, `list_*`,
   `delete_*`). Naming each one to allow (or to keep denied as the server grows) is toil, and a tool
   added by a server update is silently *ungranted* — safe, but it means an allowlist drifts out of
   date against a moving backend.
2. **No deny axis.** You could only enumerate what to allow. You could not say "expose everything
   this server offers *except* the destructive handful" — the single most common shaping intent for
   a broadly-useful server.

`FW-GW9` adds both: each axis becomes an **allow scope** minus a **terminal deny list**, and entries
may be anchored regex.

## Decisions

### Regex, not glob

The task and the shape of tool names (prefixes, alternations, optional segments) both point at
regex. We use the `regex` crate: it matches in guaranteed linear time, so a hostile blueprint
pattern cannot ReDoS the gateway — a property a hand-rolled or backtracking matcher would not give a
*security* tool. Globs were considered and rejected: friendlier to type, but strictly less
expressive, and the audience authoring a sandbox policy is comfortable with regex.

### This does **not** reopen the filesystem "no general glob" rule

[`FW-BP4`](../formwork.md#fw-bp4) forbids a general glob on the **filesystem** axis, because a path
pattern has to be lowered into a *kernel* rule (Landlock paths, a Seatbelt regex) and a pattern the
kernel cannot faithfully root is a silent fail-open of a deny. MCP shading is different in kind: it
is a **userspace string match inside the privileged gateway**, evaluated in Rust against a protocol
identifier. A mismatch shades one JSON-RPC frame; it never unroots a kernel boundary. So a full
regex is sound here precisely where it is not on the fs axis. `formwork.md` §4 states this
distinction so the two axes are not confused.

### Deny is terminal (same bias as the fs model)

`permits(name)` holds iff the allow scope admits `name` **and** no deny pattern matches it. A deny
always wins over any allow, at every layer — the MCP-surface form of the deny-terminal fs model
([`FW-CAP8`](../formwork.md#fw-cap8)/[`FW-BP4`](../formwork.md#fw-bp4)). Under narrowing
([`FW-CAP2`](../formwork.md#fw-cap2)) the deny lists **union** (a child cannot un-deny what a parent
denied) and the allow scopes intersect — a conservative, never-widening subset.

### Whole-name anchoring

Every pattern is compiled as `\A(?:…)\z`, so it must match the *entire* identifier. `/get_.*/`
covers `get_issue` but not the substring hit `forget_me`. This is the safe default for an
allow/deny: an allow pattern that matched substrings could expose an unintended tool, and it keeps
allow and deny symmetric. The cost is that habitual `^…$` anchors are redundant and a bare `/get_/`
matches only the literal `get_` — documented in the examples, which use `.*` for prefixes.

### Deny-only means "all except"

Authoring is one shape on every axis: the keyword `"allow-all"`/`"deny"`, `{ allow = [...] }`,
`{ allow = [...], deny = [...] }`, or a deny-only `{ deny = [...] }`. In the deny-only form an
absent `allow` means **all** (so it reads as all-except-deny — the headline use case). An explicit
`allow = []` means **none**. An empty `{}` is ambiguous between those two and is a **loud error**,
never silently resolved.

### Fail loud, stay deterministic, stay oracle-free

- A `/…/` that will not compile, and the empty `{}` table, fail at parse
  ([`FW-INV6`](../formwork.md#fw-inv6)) — never a silent deny-all or allow-all. A misspelled table
  key (`alow`) is rejected (`deny_unknown_fields`), not read as a deny-only (allow-all) table.
- Pattern sets canonicalize (sort + dedup by authoring form), so equal policies compile
  byte-identically ([`FW-FID4`](../formwork.md#fw-fid4)).
- Refusals are unchanged, so a deny-hidden name refuses exactly as a nonexistent one does — deny
  never becomes an existence oracle ([`FW-ADV-004`](../formwork.md#fw-adv-004)).

## Authoring grammar

```toml
[mcp.github]
tools     = { allow = ["/^(get|list|search)_.*/"], deny = ["/^delete_.*/", "merge_pull_request"] }
resources = { deny = ["/^secret_.*/"] }   # all resources except the secret_* ones
prompts   = "deny"                          # keywords still work
```

An entry wrapped in single slashes (`/re/`) is a regex; anything else is an exact identifier —
including a name that itself contains slashes (a resource `uri`), which is treated literally.

## Test matrix

| ID | Level | What it pins |
|---|---|---|
| unit (`formwork-blueprint`) | pure | parse/permits/deny-terminal/anchoring/canonicalize/serde round-trip/bad-regex + empty-table rejection |
| [`FW-E2E-065`](../formwork.md#fw-e2e-065) | gateway + fixture | regex allow shades `tools/list` to the matching set |
| [`FW-E2E-066`](../formwork.md#fw-e2e-066) | gateway + fixture | deny terminal over allow — on list and on the overlapping call |
| [`FW-E2E-067`](../formwork.md#fw-e2e-067) | gateway + fixture | deny stays oracle-free (deny-hidden ≡ nonexistent) |
| [`FW-E2E-069`](../formwork.md#fw-e2e-069) | CLI compile (any host) | patterns round-trip into compiled policy, deterministically; bad pattern / empty table fail loud |
| [`FW-E2E-066`](../formwork.md#fw-e2e-066) | **real `formwork gateway` binary** | CLI → compile → confine backend → shade: pattern policy holds end-to-end where a confiner exists |
| [`FW-E2E-068`](../formwork.md#fw-e2e-068) | real server, Linux CI | shading against `@modelcontextprotocol/server-everything` driven through the gateway |

Where each level runs (be honest about it):

- **`FW-E2E-068`** runs in the `mcp-integration` CI job (and `just test-integration-mcp`): it fetches
  the pinned reference server and drives it through the production shading path (`Gateway::run`). It
  isolates the shading so it needs no host confiner.
- **Binary-level `FW-E2E-066`** exists twice. `crates/formwork-cli/tests/gateway_cli.rs` drives the
  real `formwork gateway` binary and **runs in GitHub CI** on macOS (Seatbelt) and on Linux when the
  runner carries Landlock — it skips, never fails, where no confiner is available.
  `test_examples_gateway.py::test_example_gateway_shades_by_pattern` covers the same through the
  black-box CLI, but the Python harness is a **local / `just test-e2e` gate — it is not wired into
  GitHub CI** (only `cargo test --workspace` is), so the Rust CLI test is the one that gives CI
  coverage of the binary path.
- The orthogonal backend-confinement arm ([`FW-GW5`](../formwork.md#fw-gw5)) stays covered by the
  host-gated [`FW-E2E-019`](../formwork.md#fw-e2e-019).

## Open questions

- **Case-insensitive / inline flags.** The engine supports `(?i)`; we neither block nor document it
  yet. If it proves a footgun on case-sensitive tool names we may pin flags off.
- **Resource URI patterns.** Regex over a `uri`/`uriTemplate` works today but is unexercised beyond
  unit level; a real resource-heavy server would be the next integration target.
