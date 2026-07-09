# FEP-2 by example: real CLI sessions

Every transcript below is captured verbatim from a real run of the `formwork` binary on macOS
(real Seatbelt enforcement, real unified-log denial feed) against a **fake `$HOME`** with planted
fake credentials — the same fixture style the E2E harness uses, so no real secret is ever in
play. Timestamps are real; nothing is mocked. Telemetry goes to stderr and is uncolored here
because stderr was a pipe (`formwork` only emits ANSI at a terminal).

The playground:

```console
$ export HOME=/tmp/fw-doc/home        # planted: ~/.aws/credentials, ~/.ssh/id_ed25519 (both fake)
$ cat session.toml
extends = ["base.toml"]               # base.toml: net = "deny", ambient reads, project writable
```

## 1. Ordinary work just works; the floor announces itself once, compactly

```console
$ formwork run --blueprint session.toml -- /bin/cat project/src/main.py
2026-07-09T22:22:17Z  INFO formwork{run_id=35497 cmd="run"}: credential floor active (RUST_LOG=debug itemizes per type) path_types=21 env_types=11 catalog_version=1 allowed=[]
2026-07-09T22:22:17Z  INFO formwork{run_id=35497 cmd="run"}: configuring confinement posture="spawn" backend="seatbelt"
2026-07-09T22:22:17Z  INFO formwork{run_id=35497 cmd="run"}: spawning confined command program=/bin/cat
print("hello from the project")
2026-07-09T22:22:17Z  INFO formwork{run_id=35497 cmd="run"}: confined command exited exit_code=0
```

The summary's one varying field is `allowed=` — the deliberate exclusions are the news, the
21-type roll-call is not. `RUST_LOG=warn` silences telemetry entirely; `RUST_LOG=debug` itemizes:

```console
$ RUST_LOG=debug formwork run --blueprint session.toml -- /usr/bin/true 2>&1 | grep itemized
2026-07-09T22:22:17Z DEBUG formwork{run_id=35511 cmd="run"}: credential catalog floor, itemized denied_path_types=["anthropic", "aws", "azure", "browser", "cargo", "claude", "codex", "cursor", "docker", "dotenv", "gcp", "gemini", "github", "gpg", "keychain", "kube", "netrc", "npm", "pypi", "ssh", "system"] stripped_env_types=["anthropic", "aws", "azure", "cargo", "gcp", "github", "kube", "npm", "openai", "pypi", "slack"]
```

## 2. A credential path under a broad grant: the agent sees only the kernel's errno

```console
$ formwork run --blueprint session.toml -- /bin/cat ~/.aws/credentials
cat: /tmp/fw-doc/home/.aws/credentials: Operation not permitted
2026-07-09T22:22:17Z  INFO formwork{run_id=35499 cmd="run"}: confined command exited exit_code=1
```

No type name, no "catalog", no oracle — indistinguishable from any other denial (FW-INV9,
verified adversarially by FW-ADV-012).

## 3. An env credential: absent, not empty, through the whole tree

```console
$ AWS_SECRET_ACCESS_KEY=super-secret formwork run --blueprint session.toml -- \
    /bin/sh -c 'echo "child sees: ${AWS_SECRET_ACCESS_KEY-<unset>}"; \
                /bin/sh -c "echo \"grandchild sees: \${AWS_SECRET_ACCESS_KEY-<unset>}\""'
2026-07-09T22:22:17Z  INFO formwork{run_id=35501 cmd="run"}: credential catalog: env vars stripped by the launcher stripped=[("AWS_SECRET_ACCESS_KEY", "aws")]
child sees: <unset>
grandchild sees: <unset>
```

The strip is per-run news, so it itemizes at default level — names and types only, never values
(FW-CRED7). `${VAR-<unset>}` prints `<unset>` only when the variable is genuinely absent
(FW-INV7): the launcher never passed it, so no descendant can inherit it.

## 4. `--allow-cred aws` un-blocks exactly one type

```console
$ AWS_SECRET_ACCESS_KEY=super-secret formwork run --blueprint session.toml --allow-cred aws -- \
    /bin/sh -c 'echo "aws env: $AWS_SECRET_ACCESS_KEY"; head -1 ~/.aws/credentials; cat ~/.ssh/id_ed25519'
2026-07-09T22:22:17Z  INFO formwork{...}: credential floor active (...) path_types=20 env_types=10 catalog_version=1 allowed=["aws"]
aws env: super-secret
[default]
cat: /tmp/fw-doc/home/.ssh/id_ed25519: Operation not permitted
```

The summary shows the lift (`allowed=["aws"]`, one fewer type on each arm). This is the only
un-deny that exists: no path grant at any layer can shadow the floor (FW-BP4/FW-INV8). A typo is
a loud config error, never a silent no-op:

```console
$ formwork run --blueprint session.toml --allow-cred awss -- /usr/bin/true
Error: unknown credential type "awss" in allow-credentials (known: ["anthropic", "aws", "azure",
"browser", "cargo", "claude", "codex", "cursor", "docker", "dotenv", "gcp", "gemini", "github",
"gpg", "keychain", "kube", "netrc", "npm", "openai", "pypi", "slack", "ssh", "system", "backstop"])
```

## 5. The generic backstop covers uncatalogued shapes

```console
$ formwork run --blueprint session.toml -- /bin/cat project/.env.production
cat: project/.env.production: Operation not permitted
```

No curated type names `.env.production`; the backstop's shape rules do (FW-CRED6).

## 6. The report labels each arm and discloses the launcher contingency

```console
$ formwork compile --blueprint session.toml --target macos --report-only | jq .credentials
{
  "aws": {
    "path": { "status": "enforced", "backend": "seatbelt" },
    "env":  { "status": "enforced", "backend": "launcher" }
  },
  "slack": {
    "env":  { "status": "enforced", "backend": "launcher" }
  },
  "backstop": { "status": "enforced", "backend": "seatbelt" },
  "allowed": [],
  "launcher-contingency": "env-var shading is applied by the launcher at spawn; it holds only while Formwork is the launching process and is not a kernel guarantee (FW-CRED8)"
}
```

Env-only types claim no path arm; path-only types claim no env arm; on a `--target linux-v6`
compile the path backend reads `landlock` and any-depth rows report `partial` (FW-INV5). The
contingency note is FW-ADV-014's subject: started *without* formwork, the variable is present —
and the report never claimed otherwise.

## 7. A learning run: enforced, observed, reverse-compiled

`tight.toml` grants only `project/src/**` (closed reads) and draws an auto-widen zone over
`project/**`. The workload needs a toolchain dir, an in-zone cache file, and — because this is
the adversarial case discovery is bounded against — pokes at an ssh key:

```console
$ formwork learn --blueprint tight.toml -- \
    /bin/sh -c 'cat /tmp/fw-doc/toolchain/helper.py /tmp/fw-doc/toolchain/util.py \
                    /tmp/fw-doc/project/.cache-data /tmp/fw-doc/home/.ssh/id_ed25519'
2026-07-09T22:22:17Z  INFO formwork{run_id=35516 cmd="learn"}: LEARNING MODE (observe-then-widen): the policy below is enforced unchanged; denials are recorded and proposed, never granted live (FW-DISC1/FW-INV10)
cat: /tmp/fw-doc/toolchain/helper.py: Operation not permitted
cat: /tmp/fw-doc/toolchain/util.py: Operation not permitted
cat: /tmp/fw-doc/project/.cache-data: Operation not permitted
cat: /tmp/fw-doc/home/.ssh/id_ed25519: Operation not permitted
2026-07-09T22:22:17Z  INFO formwork{run_id=35516 cmd="learn"}: confined command exited exit_code=1
2026-07-09T22:22:18Z  INFO formwork{run_id=35516 cmd="learn"}: learning: denial withheld by the credential floor (FW-DISC3); lift only via --allow-cred path=/private/tmp/fw-doc/home/.aws/credentials credential_type=aws
2026-07-09T22:22:18Z  INFO formwork{run_id=35516 cmd="learn"}: learning: denial withheld by the credential floor (FW-DISC3); lift only via --allow-cred path=/private/tmp/fw-doc/home/.ssh/id_ed25519 credential_type=ssh
2026-07-09T22:22:18Z  INFO formwork{run_id=35516 cmd="learn"}: learning: denial withheld by the credential floor (FW-DISC3); lift only via --allow-cred path=/private/tmp/fw-doc/project/.env.production credential_type=backstop
2026-07-09T22:22:18Z  INFO formwork{run_id=35516 cmd="learn"}: learning: in-zone candidates self-granted for the NEXT run (FW-DISC4) file=tight.toml.discovered.toml grants=1
2026-07-09T22:22:18Z  INFO formwork{run_id=35516 cmd="learn"}: learning run complete (proposal written regardless of workload exit) workload_exit=1 proposal=tight.toml.proposal.toml candidates=2 needs_review=1 withheld=3
```

Worth noticing in that transcript:

- The workload failed (`workload_exit=1`) — a first learning run usually fails on exactly the
  denials it exists to observe. `learn` exits with the workload's status; the artifacts are
  written regardless.
- **Three** withheld entries, though this run only touched one credential: the collection window
  also caught the `~/.aws` and `.env.production` denials from the sessions above. Attribution is
  run-window plus dedup, deliberately tolerant of over-capture — a withheld entry is never
  proposable and everything else waits for review (FW-INV10), so over-capture costs an extra
  line, never an extra grant.
- The two toolchain siblings folded into one `toolchain/**` candidate.

The proposal is a reviewable file; the credential matches are *not in it* (the operator channel
above is where they are named — writing them into a file inside the grant would hand the agent
an oracle):

```console
$ cat tight.toml.proposal.toml
# formwork learn proposal -- review with `formwork accept --proposal tight.toml.proposal.toml` (no selection
# lists entries by number), then accept per entry (--entry <N> or --entry <pattern>).
# Paths are kernel-resolved (macOS: /tmp appears as /private/tmp). Nothing here has any
# effect until accepted (FW-INV10).
blueprint = "/private/tmp/fw-doc/tight.toml"

[[candidates]]
pattern = "/private/tmp/fw-doc/project/.cache-data"
access = "read"
tag = "auto-accepted"
run-id = "learn-35516-1783635737"

[[candidates]]
pattern = "/private/tmp/fw-doc/toolchain/**"
access = "read"
tag = "needs-review"
run-id = "learn-35516-1783635737"
```

Unreviewed candidates accumulate across learning runs (each stamped with the run that observed
it); a re-observed entry is refreshed in place.

## 8. The zone self-grants; everything else waits for a human

```console
$ formwork run --blueprint tight.toml -- /bin/cat /tmp/fw-doc/project/.cache-data
2026-07-09T22:22:18Z  INFO formwork{run_id=35521 cmd="run"}: discovered layer loaded (grants carry discovery provenance) file=tight.toml.discovered.toml reads=1 writes=0
cached artifact
```

`formwork accept` with no selection lists the entries by number:

```console
$ formwork accept --proposal tight.toml.proposal.toml
2026-07-09T22:22:18Z  INFO formwork{run_id=35523 cmd="accept"}: candidate entry=1 pattern=/private/tmp/fw-doc/project/.cache-data access=Read tag=AutoAccepted observed_by=learn-35516-1783635737
2026-07-09T22:22:18Z  INFO formwork{run_id=35523 cmd="accept"}: candidate entry=2 pattern=/private/tmp/fw-doc/toolchain/** access=Read tag=NeedsReview observed_by=learn-35516-1783635737
2026-07-09T22:22:18Z  INFO formwork{run_id=35523 cmd="accept"}: select with --entry <number|pattern> (repeatable) or --all; auto-accepted entries are already in the discovered layer and are listed for audit only

$ formwork accept --proposal tight.toml.proposal.toml --entry 2
2026-07-09T22:22:42Z  INFO formwork{run_id=35535 cmd="accept"}: accepted discovered grants; they apply from the next run accepted=1 into=/private/tmp/fw-doc/tight.toml.discovered.toml

$ formwork run --blueprint tight.toml -- /bin/cat /tmp/fw-doc/toolchain/helper.py
helper one
```

The discovered layer keeps learned grants forever distinguishable from authored ones (FW-DISC6):

```console
$ cat tight.toml.discovered.toml
# Discovered grants (formwork learn/accept). Every grant carries provenance (FW-DISC6);
# authored grants belong in the blueprint, not here.
[fs]
reads = [
    "/private/tmp/fw-doc/project/.cache-data",
    "/private/tmp/fw-doc/toolchain/**",
]

[discovery.provenance."/private/tmp/fw-doc/project/.cache-data"]
added-via = "discovery-auto"
run-id = "learn-35516-1783635737"

[discovery.provenance."/private/tmp/fw-doc/toolchain/**"]
added-via = "discovery"
run-id = "learn-35516-1783635737"
```

## 9. The confused-deputy door stays shut

A hand-forged proposal naming a credential — bypassing `learn` entirely — is refused at the
floor, which `accept` re-checks with no exclusions at all:

```console
$ formwork accept --proposal forged.toml --all
Error: refusing to accept /private/tmp/fw-doc/home/.ssh/id_ed25519: it matches the credential
floor (type: backstop); the only lift is the explicit typed exclude, --allow-cred (FW-INV8)
```

## Reproducing

The fixture layout and every command above are exactly what the E2E harness drives
(`py/harness/test_credential_catalog.py`, `test_adv_credentials.py`, `test_discovery.py` —
FW-E2E-041..054, FW-ADV-012..014). `cd py && uv run pytest -v` runs the lot against your own
machine's kernel.
