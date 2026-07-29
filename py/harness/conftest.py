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
    def _run(*args, cwd=None, timeout=60, env=None):
        return run_cli(formwork_bin, *args, cwd=cwd, timeout=timeout, env=env)

    return _run


@pytest.fixture
def workspace(tmp_path) -> Workspace:
    return make_workspace(tmp_path)


def _fw_ids(item) -> list[str]:
    """Every FW-E2E/FW-ADV id on a test. A test may carry several (one scenario that discharges
    two requirements, e.g. FW-E2E-071 + FW-E2E-051); get_closest_marker would silently drop all
    but one, defeating the point of a generated table."""
    ids = []
    for name in ("fw_e2e", "fw_adv"):
        for marker in item.iter_markers(name):
            if marker.args:
                ids.append(marker.args[0])
    return ids


def pytest_collection_modifyitems(config, items):
    """Skip platform-backend tests off their platform; stash FW IDs for the traceability report."""
    is_macos = sys.platform == "darwin"
    is_linux = sys.platform.startswith("linux")
    skip_macos = pytest.mark.skip(reason="needs the macOS Seatbelt backend")
    skip_linux = pytest.mark.skip(reason="needs the Linux Landlock/seccomp backend")

    traceability = {}
    for item in items:
        if item.get_closest_marker("macos") and not is_macos:
            item.add_marker(skip_macos)
        if item.get_closest_marker("linux") and not is_linux:
            item.add_marker(skip_linux)
        for fw_id in _fw_ids(item):
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
