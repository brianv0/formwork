# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, not in public issues or pull requests.

Use GitHub's private vulnerability reporting: on the repository's **Security** tab, choose
**Report a vulnerability**. Include the affected version or commit, a description, and a reproduction
if you have one. We'll acknowledge the report and work with you on a fix and coordinated disclosure.

## What is in scope

Formwork targets **good isolation, not perfect isolation**: a hard wall against accidental, careless,
and prompt-injected overreach, and against untrusted code the agent runs — *not* against kernel
exploitation. Every enforcement claim is meant to be backed by a real mechanism on the host or
reported as a gap; the tool is designed to fail closed, never to silently claim containment it cannot
deliver.

In scope — a bug where Formwork's own logic is what fails:

- A compiled policy that grants more than the blueprint asked for, or a merge/narrowing bug where a
  deny fails to beat an allow.
- A confinement bypass that reaches a resource the policy denied (filesystem, network, exec) through
  a path Formwork was supposed to close.
- The gateway leaking a tool/resource/prompt its shading policy denied, or egress the policy denied.
- A credential-floor bypass, or `learn` proposing a grant that should have been withheld.
- Any case where the fidelity report claims enforcement the host is not actually delivering (a
  silent fail-open).

Out of scope — by design, not because they don't matter:

- Kernel or hypervisor exploitation, and side channels below the mechanisms Formwork drives
  (Landlock, seccomp, Seatbelt). Formwork is not a defense against a kernel 0-day.
- Escapes that require the confining policy to have been configured to allow the thing in question.
- Weaknesses in software Formwork sandboxes but does not ship.

If you're unsure whether something is in scope, report it — a borderline honesty gap in the fidelity
report is exactly the kind of thing we want to hear about.

## Supported versions

Formwork is pre-1.0. Fixes land on `main` and flow to the rolling
[`canary`](https://github.com/brianv0/formwork/releases/tag/canary) prerelease; tagged `v*` releases
cut stable builds. Please test against the latest `main` or `canary` before reporting.
