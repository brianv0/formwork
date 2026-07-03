"""Fixtures and hooks for the Formwork harness: build the CLI once, provide a scratch workspace,
skip platform-backend tests off-platform (never a silent pass), and emit a generated FW-ID -> tests
traceability table at the end of the run."""

from __future__ import annotations

import subprocess
import sys

import pytest

from helpers import REPO_ROOT, Workspace, make_workspace, run_cli


@pytest.fixture(scope="session")
def formwork_bin():
    subprocess.run(["cargo", "build", "-q", "-p", "formwork-cli"], cwd=REPO_ROOT, check=True)
    binary = REPO_ROOT / "target" / "debug" / "formwork"
    assert binary.exists(), f"formwork binary not found at {binary}"
    return binary


@pytest.fixture
def cli(formwork_bin):
    def _run(*args, cwd=None, timeout=60):
        return run_cli(formwork_bin, *args, cwd=cwd, timeout=timeout)

    return _run


@pytest.fixture
def workspace(tmp_path) -> Workspace:
    return make_workspace(tmp_path)


def _fw_id(item) -> str | None:
    for name in ("fw_e2e", "fw_adv"):
        marker = item.get_closest_marker(name)
        if marker and marker.args:
            return marker.args[0]
    return None


def pytest_collection_modifyitems(config, items):
    """Skip platform-backend tests off their platform; stash FW IDs for the traceability report."""
    is_macos = sys.platform == "darwin"
    is_linux = sys.platform.startswith("linux")
    skip_macos = pytest.mark.skip(reason="needs the macOS Seatbelt backend (Phase 3)")
    skip_linux = pytest.mark.skip(reason="needs the Linux Landlock/seccomp backend (Phase 2)")

    traceability = {}
    for item in items:
        if item.get_closest_marker("macos") and not is_macos:
            item.add_marker(skip_macos)
        if item.get_closest_marker("linux") and not is_linux:
            item.add_marker(skip_linux)
        fw_id = _fw_id(item)
        if fw_id:
            traceability.setdefault(fw_id, []).append(item.nodeid)
    config._fw_traceability = traceability


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    table = getattr(config, "_fw_traceability", None)
    if not table:
        return
    terminalreporter.write_sep("=", "Formwork traceability (generated from markers)")
    for fw_id in sorted(table):
        for nodeid in table[fw_id]:
            terminalreporter.write_line(f"  {fw_id:<14} {nodeid}")
