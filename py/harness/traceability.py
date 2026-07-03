#!/usr/bin/env python3
"""Generate the requirements<->tests traceability from pytest markers rather than hand-maintaining
the §10 table. Run: `uv run python harness/traceability.py`. The live table is also printed at the
end of every `uv run pytest` run by the conftest `pytest_terminal_summary` hook."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HARNESS = Path(__file__).resolve().parent


def main() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", str(HARNESS)],
        capture_output=True,
        text=True,
        cwd=HARNESS,
    )
    if proc.returncode not in (0, 5):  # 5 == no tests collected
        sys.stderr.write(proc.stdout + proc.stderr)
        return proc.returncode
    print("Collected harness tests (run `uv run pytest` for the FW-ID traceability table):\n")
    for line in proc.stdout.splitlines():
        if "::test_" in line:
            print(f"  {line.strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
