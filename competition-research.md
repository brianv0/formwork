# Formwork vs. the 2026 agentic-sandboxing landscape

*Competitive research, compiled 2026-07-06. Findings are grounded in actual source
(fetched from upstream repos on `main`), vendor docs, and disclosed advisories.
Formwork claims are traced to this repo's code with `file:line` citations.*

## TL;DR

Formwork's **defaults and credential posture are stronger than every shipping
competitor**. We are the only tool with a schema-level default-deny on filesystem
reads, and the only one that ships a curated, CI-tested credential deny-list.
Anthropic's `sandbox-runtime` explicitly documents that it has "no built-in
credential deny list"; Cursor leaks `~/.npmrc` by default (demonstrated token
exfiltration); OpenAI Codex returns full-disk-read `true` in every mode. Only
VS Code approaches us, by denying `$HOME` reads by default.

Our three real gaps:

1. **No domain-level network egress** — table stakes everywhere else and the #1
   exfiltration control. We do TCP-port granularity only.
2. **No write-protection for code-execution vectors** (`.git/hooks`, shell rc,
   agent config dirs) — every competitor hardcodes these.
3. **No Linux enforcement** — everyone ships Linux; ours is an honest stub.

---

## The landscape at a glance

| Tool | Mechanism (macOS / Linux / Win) | On by default? | FS reads default | FS writes default | Net default | Domain allowlist? |
|---|---|---|---|---|---|---|
| **Formwork** | Seatbelt / *stub (Landlock+seccomp compiled, unenforced)* / — | n/a (CLI wrapper) | **Deny-all** (schema); ambient-minus-subtract in shipped profile | **Deny-all, always** | Deny-all | **No — TCP port only** |
| **Anthropic srt / Claude Code** | Seatbelt / bwrap+socat+seccomp / WSL2 | **Off** (`sandbox.enabled: false`) | **Allow-all** | Deny-all (CC: cwd+tmp) | Deny-all → per-domain prompt | Yes (host-side HTTP CONNECT + SOCKS5 proxy) |
| **OpenAI Codex CLI** | Seatbelt / bwrap+seccomp (Landlock legacy) / **native Windows** | **Yes** (workspace-write preset) | **Allow-all, unconditionally** | cwd+`/tmp`+`$TMPDIR`; `.git`/`.codex`/`.agents` carved out | Off in workspace-write | Yes (network-proxy crate) |
| **Google Gemini CLI** | Seatbelt profiles / Docker-only (legacy) / Docker | **Off** | Allow-all (default `permissive-open`) | cwd+caches | **Open** in default profile | Only via a proxy you supply |
| **Cursor 2.x–3.0** | Seatbelt / **Landlock+seccomp direct** / WSL2 | **Yes** (Pro, 2.0+) | Allow-all minus `.cursorignore` | Workspace+`/tmp` | Deny; RFC-1918 + `169.254.169.254` hard-blocked | Yes (`sandbox.json`, enterprise-enforced) |
| **VS Code / Copilot (v1.127)** | Seatbelt / bwrap+socat / MXC runtime | Rolling out as default | **`$HOME` denied by default**; workspace allowed | cwd only | Deny-all | Yes (org-manageable) |
| **Zed** | Seatbelt / non-setuid bwrap / WSL | Yes | Allow-all except git metadata | Project dirs+tmp | Deny → per-host approval | macOS only (proxy) |

Also relevant: **Docker Sandboxes** (GA Jan 2026, microVM-per-sandbox; credentials
never enter the sandbox — a host-side proxy injects OAuth tokens) and **GitHub
Copilot** local sandboxes (Microsoft MXC runtime, cross-platform). **Amp,
OpenCode, Goose, Windsurf, and JetBrains Junie** have **no** real OS-level sandbox
— approval prompts and allowlists only.

---

## Credential files — the focus area

The single most important industry fact is the **read/write asymmetry**.
`sandbox-runtime`, Claude Code, Codex, Gemini (default profile), Cursor, and Zed
all leave credential *reads* open by default and rely on default-deny **network**
to prevent exfiltration. Claude Code's docs say it outright:

> "this default still allows reading credential files such as `~/.aws/credentials`
> and `~/.ssh/` … There is no built-in credential deny list."

- Codex's `SandboxPolicy::has_full_disk_read_access()` returns `true`
  unconditionally for read-only, workspace-write, *and* danger-full-access.
- A published Cursor analysis (Nov 2025) demonstrated an `~/.npmrc` npm-token
  leak into model context — `.cursorignore` protects direct file reads, not shell
  stdout, and everything on stdout goes to the model.
- The only hardcoded protected-path lists in `sandbox-runtime` (`DANGEROUS_FILES`,
  `DANGEROUS_DIRECTORIES`) are **write-only** protections for shell rc / `.gitconfig`
  / `.mcp.json` / IDE dirs / `.claude/{commands,agents}` — code-execution and
  policy-tampering vectors, **not** secrets.

### Where Formwork stands

Genuinely differentiated:

- Schema-default `read-mode = "closed"` denies `$HOME` entirely by omission
  (`crates/formwork-compile/src/sbpl.rs:46-49` documents the rationale:
  "secrets live under `$HOME`, which stays denied").
- The shipped ambient profile subtracts a curated `profiles/sensitive-set.toml`
  (ssh, gnupg, aws, gcloud, azure, kube, netrc, npmrc, pypirc, gh,
  git-credentials, keychains, browser profiles, `/etc/shadow`) with a CI drift
  test asserting `default.toml.subtract ⊇ sensitive-set.toml`
  (`crates/formwork-cli/tests/profiles.rs:507-517`). **No competitor ships this.**

### Holes in our credential coverage (things the research surfaced)

1. **Agent-tool state dirs are absent** — `~/.claude`, `~/.claude.json`, `~/.codex`,
   `~/.gemini`, `~/.cursor` (OAuth creds, session transcripts). Ironic given our
   examples wrap exactly these agents. `sandbox-runtime` hard-denies *writes* to
   Claude settings at every scope for the tampering half of this.
2. **`.env` files are unprotected** — and currently *inexpressible*, because our
   `PathPattern` is absolute-only (`crates/formwork-blueprint/src/path.rs:27-48`).
   Gemini's per-tool sandbox masks `.env`/`.env.*`; OpenCode deny-reads `*.env` by
   default; Codex documents `"**/*.env" = "deny"` profiles.
3. **Env-var secrets — zero scrubbing.** The confined child inherits
   `AWS_ACCESS_KEY_ID` etc.; there is no `env_clear`/`env_remove` anywhere in the
   codebase. `sandbox-runtime` has `credentials.envVars` (deny/mask), Claude Code
   has `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`, Gemini strips by regex
   (`/TOKEN|SECRET|PASSWORD|KEY|.../i` plus PEM/`ghp_`/`AKIA`/JWT value patterns).
   Our blueprint schema has no env vocabulary at all.
4. **Cloud metadata endpoints** — `net = { ports = [443] }` permits
   `169.254.169.254` (IMDS credential theft). Cursor hard-blocks metadata IPs and
   RFC-1918 by default as anti-SSRF; we can't express it.
5. **Existence/metadata leak** — broad `(allow file-read-metadata)`
   (`crates/formwork-compile/src/sbpl.rs:99`) means `stat(~/.aws/credentials)`
   succeeds. Honest and reported (`FsInvisibility: Unenforceable`,
   `crates/formwork-compile/src/lib.rs:78-85`), but `sandbox-runtime`'s Linux
   `--tmpfs`-overlay approach actually achieves ENOENT-style invisibility.

---

## Gaps (prioritized)

**1. No domain-level egress — the biggest functional gap.** Every real competitor
converged on the same architecture: the kernel denies all egress; a host-side
proxy (outside the sandbox) enforces a domain allowlist, reached via unix
socket/loopback. Formwork offers only `NetPosture::Ports`
(`crates/formwork-blueprint/src/lib.rs:52-60`) — ":443 to anywhere" — and the
gateway is an MCP stdio shader, not an egress filter (FW-GW7 deferred to Phase 7,
`IMPLEMENTATION_PLAN.md:158-162`; `reqwest` not in the lockfile). Since the whole
industry's credential story is "reads open, egress gated," and *our* story is
"reads closed," adding domain egress would make us strictly stronger than everyone.

**2. No write-protection for code-execution / policy-tampering vectors.** The one
hardcoded list *everyone* has and we don't: `sandbox-runtime`'s `DANGEROUS_FILES`/
`DANGEROUS_DIRECTORIES` (shell rc, `.gitconfig`, `.mcp.json`, `.git/hooks`,
`.vscode`, `.idea`, `.claude/{commands,agents}`), Codex's forced-read-only
`.git`/`.agents`/`.codex` inside every writable root, Cursor's protected
`.cursor/*.json`/`.git/hooks`/`.cursorignore`, Zed's git-metadata protection.
With our `agent-session.toml`, `.git/hooks/**` inside the granted workspace is
writable — an agent can plant a hook the user later runs *unsandboxed*. Our
subtract mechanism can express this today; the sensitive set just omits it.

**3. Linux enforcement unbuilt.** All major competitors ship Linux (bwrap or
direct Landlock+seccomp). Cursor validates our exact direct-Landlock design choice
at production scale. Being macOS-only is the main "not production-comparable" mark
against us. Our confiner is an honest stub
(`crates/formwork-confine/src/linux/mod.rs:9-18`).

**4. No violation observability.** `sandbox-runtime` tails the unified log
(`sandbox-exec` predicate with an embedded log-tag) and Claude Code turns
violations into prompts; Cursor/VS Code surface the specific constraint that
failed so the agent can request escalation. We deny with EACCES and give embedders
nothing to build that UX on.

**5. Smaller items:**
- cwd isn't defaulted into the grant (`docs/spikes.md` Spike 2; breaks interpreters).
- `$HOME` unset silently falls back to `/`, making `~/.ssh` subtracts miss
  (`crates/formwork-cli/src/main.rs:109-111` — should be a hard error).
- No credential masking/injection story (srt's mask mode; Docker's host-side token
  injection) — advanced, arguably later.
- The fd-seam is not wired into production (`crates/formwork-seam/src/lib.rs:10-13`).

---

## Strengths (verified differentiators)

1. **Defaults.** The only tool whose *schema* default is deny-all reads, deny-all
   writes, deny-all net. The empty blueprint exposes only system runtime dirs,
   curated `/dev` literals (deliberately no `subpath /dev` — avoids the `rdisk`
   whole-disk bypass, `crates/formwork-compile/src/sbpl.rs:64-66`), and `stat`.
   Even VS Code — the strictest competitor — allows workspace+system reads and only
   denies `$HOME`.
2. **A shipped, tested credential deny-list**, with a superset drift test in CI.
   `sandbox-runtime`'s docs literally disclaim having one.
3. **Fidelity honesty.** `Enforced/Partial/Unenforceable` reporting; Linux refuses
   to run rather than degrade; net falls back to *full deny* when a port tier can't
   be honored (`crates/formwork-compile/src/linux.rs:82-101`). Contrast: Claude
   Code's default is `failIfUnavailable: false` — **warn and run unsandboxed**; srt
   shipped CVE-2025-66479 where deny-all silently became allow-all. Our fail-closed
   posture is a marketable trust story.
4. **Deterministic, auditable compilation.** Byte-identical
   `Blueprint × HostProfile → policy`, diffable in review
   (`crates/formwork-compile/src/lib.rs:53-113`). Everyone else generates profiles
   dynamically at runtime from mutable settings — exactly what Cursor's
   CVE-2026-50548/9 (sandbox helper binary overwritten; model-controlled
   `working_directory`) and Codex's CVE-2025-59532 (model-supplied cwd became the
   writable root) exploited. Our canonicalize-then-compile-from-declared-paths
   design structurally avoids the "model input flows into policy synthesis" bug class.
5. **No self-escape hatch.** The Ona writeup and `sandbox-runtime` issue #97
   document Claude Code auto-retrying with `dangerouslyDisableSandbox` — the agent
   reasons its way out. Formwork-the-enforcer has no such path; escalation is the
   embedder's problem by design.
6. **MCP-layer policy** — gateway shading with oracle-free refusals (denied vs.
   nonexistent tools produce byte-identical errors,
   `crates/formwork-gateway/tests/gateway.rs`) — plus a monotonic parent-clamp
   narrowing algebra for embedders (`crates/formwork-blueprint/src/narrow.rs`).
   Closest competitor: VS Code's per-MCP-server sandboxing.
7. **Exec allowlisting** (path-based, kernel-enforced on macOS,
   `crates/formwork-compile/src/sbpl.rs:140-148`). Codex's seatbelt base emits
   `(allow process-exec)` broadly; no competitor offers exec-path confinement.

---

## Recommended changes, priced by their CVEs

1. **Build the egress proxy (accelerate FW-GW7)** with the published failure modes
   as the test plan:
   - empty-allowlist must mean deny (CVE-2025-66479);
   - hostname validation must reject null bytes / percent-encoding / CRLF / IPv6
     zone-IDs *before* matching (the SOCKS5 `\x00.google.com` bypass);
   - require per-session proxy auth (srt does);
   - block RFC-1918 + metadata IPs by default (Cursor);
   - document domain-fronting / no-TLS-inspection limits honestly (fits our
     fidelity-report ethos — "domain allowlist: Partial").
2. **Add an "execution-vectors" write-deny set** alongside `sensitive-set.toml`:
   `.git/hooks`, `.git/config`, shell rc files, `.mcp.json`, `.claude/**`,
   `.cursor/**`, `.vscode/**`, `.idea/**`, `.codex/**`. Consider making the
   in-workspace git subset compiler-enforced rather than profile-optional, like
   Codex does.
3. **Extend the sensitive set**: `~/.claude*`, `~/.codex`, `~/.gemini`, `~/.cursor`,
   `~/.docker/**`; add relative/glob path support (or a documented convention) so
   `.env` becomes expressible; fix the `$HOME`-unset fallback to fail loud.
4. **Add env-var vocabulary to the blueprint** (allowlist or scrub-list) — cheap,
   and its absence is our most conspicuous credential hole given every competitor
   grew one.
5. **Ship Linux** — Cursor proves direct Landlock+seccomp works in production at
   scale, de-risking our exact design.

---

## Cross-cutting themes

1. **The read/write asymmetry is the core industry weakness.** Reads are
   unrestricted by default nearly everywhere; only writes and (sometimes) network
   are confined. Restricting reads is opt-in and easy to get wrong. Formwork
   inverts this — reads-closed by default is our headline advantage.
2. **Network egress is the exfiltration channel, and OS sandboxes can't express
   domain rules.** Seatbelt/Landlock/seccomp operate at the syscall boundary and
   cannot say "permit HTTPS to api.anthropic.com" — hence the proxy layers. Those
   proxies are where the bypasses keep landing (null-byte, domain-fronting, DNS
   rebinding).
3. **`.git` protection is a recognized escalation vector** and a concrete, copyable
   pattern (Codex hard-codes read-only `.git`/`.agents`/`.codex`).
4. **`sandbox-exec` is technically deprecated** (Apple, ~2016) yet every macOS
   sandbox here — including ours — depends on it. Shared long-term maintenance risk.
5. **Sandboxes contain the host, not prompt injection.** Both OpenAI and Anthropic
   concede any allowed network path can exfiltrate anything the agent can read. The
   "lethal trifecta" (private data + untrusted content + egress) is the persistent gap.
6. **Defaults are the real security posture.** Amp doesn't prompt; Goose is
   Autonomous; OpenCode allows most things; Gemini's sandbox is off — and both
   Gemini CVEs (incl. the CVSS 10.0 CI RCE) landed on users running defaults. Codex
   is the outlier with a sandbox-first default; Formwork is stricter still.

---

## Citation index

### Formwork (this repo)
`Cargo.toml`; `crates/formwork-blueprint/src/{lib,path,narrow}.rs`;
`crates/formwork-detect/src/lib.rs`; `crates/formwork-compile/src/{lib,linux,policy,sbpl,report}.rs`;
`crates/formwork-confine/src/{lib,macos/mod,linux/mod}.rs`; `crates/formwork-seam/src/lib.rs`;
`crates/formwork-gateway/src/lib.rs`; `crates/formwork-cli/src/{main,blueprint_load}.rs`;
`profiles/{default,sensitive-set}.toml`; `examples/blueprints/agent-session.toml`;
tests under `crates/*/tests/` and `py/harness/`; `formwork.md`, `constitution.md`,
`IMPLEMENTATION_PLAN.md`, `docs/{spikes,linux-backend}.md`.

### Anthropic sandbox-runtime / Claude Code
- Repo: https://github.com/anthropic-experimental/sandbox-runtime
  (`README.md`, `src/cli.ts`, `src/sandbox/{sandbox-config,sandbox-schemas,sandbox-utils,http-proxy,request-filter,domain-pattern}.ts`)
- npm: https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime
- Docs: https://code.claude.com/docs/en/sandboxing · https://code.claude.com/docs/en/settings#sandbox-settings
- Engineering: https://www.anthropic.com/engineering/claude-code-sandboxing · https://www.anthropic.com/engineering/claude-code-auto-mode
- CVE-2025-66479: https://www.securityweek.com/anthropic-silently-patches-claude-code-sandbox-bypass/
- SOCKS5 null-byte bypass: https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/
- Agent self-escape: https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox
- Auto-disable sandbox: https://github.com/anthropic-experimental/sandbox-runtime/issues/97
- Cowork escape: https://threat-modeling.com/anthropic-claude-cowork-sandbox-escape-root-access/

### OpenAI Codex CLI
- Repo (`main`): `codex-rs/sandboxing/src/{seatbelt.rs,seatbelt_base_policy.sbpl}`;
  `codex-rs/linux-sandbox/src/{bwrap,landlock,linux_run_main}.rs`;
  `codex-rs/protocol/src/{protocol,permissions,config_types}.rs`;
  `codex-rs/config/src/types.rs`; `codex-rs/network-proxy/src/config.rs`;
  `codex-rs/windows-sandbox-rs/`
- Docs: https://developers.openai.com/codex/concepts/sandboxing ·
  https://developers.openai.com/codex/permissions ·
  https://developers.openai.com/codex/agent-approvals-security ·
  https://developers.openai.com/codex/windows ·
  https://openai.com/index/building-codex-windows-sandbox/
- CVE-2025-59532: https://www.miggo.io/vulnerability-database/cve/CVE-2025-59532
- CVE-2025-61260: https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/
- Cymulate escapes: https://cymulate.com/blog/the-race-to-ship-ai-tools-left-security-behind-part-1-sandbox-escape/ ·
  https://cymulate.com/blog/codex-cli-rce-prompt-injection-mitigations/

### Google Gemini CLI
- Repo (`main`): `packages/cli/src/utils/{sandbox.ts,sandboxUtils.ts,sandbox-macos-*.sb}`;
  `packages/cli/src/config/{sandboxConfig,settingsSchema}.ts`;
  `packages/core/src/sandbox/{linux/bwrapArgsBuilder,macos/*,windows/WindowsSandboxManager}.ts`;
  `packages/core/src/services/{sandboxManager,environmentSanitization}.ts`;
  `docs/cli/sandbox.md`
- Tracebit RCE: https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack
- CVSS 10.0 CI RCE (GHSA-wpqr-6v78-jr5g): https://github.com/advisories/GHSA-wpqr-6v78-jr5g ·
  https://thehackernews.com/2026/04/google-fixes-cvss-10-gemini-cli-ci-rce.html

### Cursor
- Blog: https://cursor.com/blog/agent-sandboxing
- Docs: https://cursor.com/docs/reference/sandbox · https://cursor.com/docs/agent/security/run-modes
- Changelogs: https://cursor.com/changelog/{1-7,2-0,2-5}
- Secret leak: https://luca-becker.me/blog/cursor-sandboxing-leaks-secrets/
- CVE-2026-50548 / -50549: https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html

### VS Code / GitHub Copilot
- Release notes: https://code.visualstudio.com/updates/{v1_104,v1_109,v1_127}
- Docs: https://code.visualstudio.com/docs/agents/concepts/trust-and-safety ·
  https://code.visualstudio.com/docs/agents/security
- Test-plan issue: https://github.com/microsoft/vscode/issues/290620
- Copilot sandboxes: https://github.blog/changelog/2026-06-02-cloud-and-local-sandboxes-for-github-copilot-now-in-public-preview/ ·
  https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/overview ·
  https://bartwullems.blogspot.com/2026/06/local-sandboxing-in-github-copilot-cli.html

### Other tools
- Zed: https://zed.dev/docs/ai/sandboxing · https://github.com/zed-industries/zed/discussions/40482
- JetBrains Junie/Air: https://junie.jetbrains.com/docs/action-allowlist-junie-cli.html ·
  https://blog.jetbrains.com/junie/2026/04/junie-cli-inside-your-jb-ide/
- Windsurf: https://docs.windsurf.com/windsurf/cascade/cascade
- Docker Sandboxes: https://www.docker.com/blog/docker-sandboxes-run-claude-code-and-other-coding-agents-unsupervised-but-safely/ ·
  https://docs.docker.com/ai/sandboxes/
- Amp: https://ampcode.com/manual · https://ampcode.com/security ·
  https://embracethered.com/blog/posts/2025/amp-agents-that-modify-system-configuration-and-escape/
- OpenCode: https://opencode.ai/docs/permissions/ · https://github.com/anomalyco/opencode/pull/21538
- Goose: https://block.github.io/goose/docs/guides/sandbox/ · https://github.com/block/goose/issues/5943
- Community catalog: https://github.com/dloss/awesome-agent-sandboxes
