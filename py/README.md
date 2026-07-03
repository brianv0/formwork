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
requirements↔tests traceability section (from the markers). Standalone form:

```sh
uv run python harness/traceability.py
```

## Markers

Each scenario carries its design-doc ID and its platform requirement:

- `@pytest.mark.fw_e2e("FW-E2E-001")` / `@pytest.mark.fw_adv("FW-ADV-001")` — the design test ID,
  used to generate the §10 traceability table rather than hand-maintaining it.
- `@pytest.mark.macos` / `@pytest.mark.linux` — a platform backend requirement. Tests are
  skipped-with-reason off their platform (never silently passed), matching Formwork's
  "report, don't pretend" philosophy.

## Coverage today

- `test_fs_confinement.py` — FW-E2E-001/002/003 (macOS): granted vs. ungranted reads, write scope,
  sensitive-set subtraction under a broad grant.
- `test_net_egress.py` — FW-E2E-006 (macOS): direct egress denied at `connect()` (not a startup
  artifact — the interpreter runs and the syscall is what fails).
- `test_compile.py` — FW-E2E-026/027 (any host): cross-platform dry-run compile, degraded-host
  honesty, deterministic byte-identical compile, and `formwork detect`.

MCP fixture servers and the gateway shading tests (FW-E2E-013..019) land with Phase 6.
