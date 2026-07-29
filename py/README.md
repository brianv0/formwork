# Formwork test harness (Python)

The black-box end-to-end / adversarial harness. It drives the `formwork` **CLI binary** exactly as
a real embedder would — it never links the Rust crates — so it tests the shipped interface honestly.
Dev-only; never shipped. Managed by `uv` (the system Python is 3.9 and is not used).

## Run

```sh
cd py
uv run pytest -v
```

`uv` creates the venv and installs `pytest` on first run, and the `formwork_bin` fixture builds the
CLI once per session (`cargo build -p formwork-cli`). Every run ends with a generated
requirements↔tests traceability section (from the markers), printed by the conftest
`pytest_terminal_summary` hook.

## Markers

Each scenario carries its design-doc ID and its platform requirement:

- `@pytest.mark.fw_e2e("FW-E2E-001")` / `@pytest.mark.fw_adv("FW-ADV-001")` — the design test ID,
  used to generate the §10 traceability table rather than hand-maintaining it.
- `@pytest.mark.macos` / `@pytest.mark.linux` — a platform backend requirement. Tests are
  skipped-with-reason off their platform (never silently passed), matching Formwork's
  "report, don't pretend" philosophy.

## Coverage today

The suite tracks the design-doc IDs it exercises via the `fw_e2e`/`fw_adv` markers; the generated
traceability section (printed at the end of every run) is the authoritative map. By area:

- **Enforcement** — `test_fs_confinement.py` (granted vs. ungranted reads, write scope,
  sensitive-set subtraction), `test_net_egress.py` (egress denied at `connect()`). macOS-gated.
- **Compile / dry-run** — `test_compile.py` (cross-platform compile, degraded-host honesty,
  deterministic byte-identical output), `test_blueprint_model.py`, `test_examples_blueprints.py`
  (the shipped `examples/` blueprints compile and behave). Any host.
- **Credentials** — `test_credential_catalog.py`, `test_adv_credentials.py` (catalog floor holds
  under broad grants; operator/agent channel separation).
- **Gateway (MCP shading)** — `test_examples_gateway.py` drives a real `fw-mcp-fixture` backend
  through the gateway ([FW-E2E-013](../formwork.md#fw-e2e-013)/018/066).
- **Discovery / `learn`** — `test_discovery.py`, `test_learn_review.py`, `test_learn_linux.py`
  (the enforced-run → proposal → accept loop, both feeds).
- **Meta** — `test_requirements.py` is the requirement-identifier canary: every cited `FW-*` ID
  resolves to exactly one anchored definition, and every markdown requirement link lands on it.
