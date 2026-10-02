"""Fixtures and hooks for the Formwork harness: build the CLI once, provide a scratch workspace,
skip platform-backend tests off-platform (never a silent pass), and emit a generated FW-ID -> tests
traceability table at the end of the run. With `FW_E2E_RESULTS` set, each test's outcome and FW
IDs are also written there as JSON for the cross-platform verdict (`py/e2e_matrix.py`)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

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


_RESULTS = pytest.StashKey[dict]()


def _marker_skip_reasons(item) -> set[str]:
    reasons = set()
    for name in ("skip", "skipif"):
        for marker in item.iter_markers(name):
            reason = marker.kwargs.get("reason")
            if reason is None and name == "skip" and marker.args:
                reason = marker.args[0]
            if reason:
                reasons.add(reason)
    return reasons


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Record one outcome per test. A skip a marker declared (the platform markers, a platform
    `skipif`) means the test does not apply here; any other skip happened at runtime -- a missing
    tool or mechanism -- which the verdict counts as a run that did not exercise its test."""
    report = (yield).get_result()
    results = item.config.stash.setdefault(_RESULTS, {})
    entry = results.setdefault(
        report.nodeid, {"nodeid": report.nodeid, "ids": _fw_ids(item), "outcome": "passed"}
    )
    if report.failed:
        entry["outcome"] = "failed"
    elif report.skipped and entry["outcome"] != "failed":
        reason = report.longrepr[2] if isinstance(report.longrepr, tuple) else str(report.longrepr)
        reason = reason.removeprefix("Skipped: ")
        entry["outcome"] = "not-applicable" if reason in _marker_skip_reasons(item) else "skipped"
        entry["reason"] = reason


def pytest_sessionfinish(session, exitstatus):
    path = os.environ.get("FW_E2E_RESULTS")
    if not path:
        return
    results = session.config.stash.get(_RESULTS, {})
    tests = sorted(results.values(), key=lambda r: r["nodeid"])
    Path(path).write_text(json.dumps({"tool": "pytest", "tests": tests}, indent=1))


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    table = getattr(config, "_fw_traceability", None)
    if not table:
        return
    terminalreporter.write_sep("=", "Formwork traceability (generated from markers)")
    for fw_id in sorted(table):
        for nodeid in table[fw_id]:
            terminalreporter.write_line(f"  {fw_id:<14} {nodeid}")
