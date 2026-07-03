"""Filesystem confinement E2E (design §7.1), driven through the `formwork` CLI. macOS-only for now."""

import pytest

from helpers import write_spec

pytestmark = pytest.mark.macos


def _denied(result):
    """Nonzero exit with an EPERM-ish message (a confinement denial, not a crash)."""
    return result.code != 0 and (
        "Operation not permitted" in result.stderr
        or "not permitted" in result.stderr.lower()
        or "denied" in result.stderr.lower()
    )


@pytest.mark.fw_e2e("FW-E2E-001")
def test_granted_read_succeeds_ungranted_denied(cli, workspace, tmp_path):
    spec = write_spec(
        tmp_path / "spec.toml",
        reads=[f"{workspace.granted}/**"],
        writes=[f"{workspace.granted}/**"],
    )
    ok = cli("run", "--spec", spec, "--", "/bin/cat", workspace.granted_file, cwd=workspace.granted)
    assert ok.code == 0, ok.stderr
    assert "in-scope contents" in ok.stdout

    denied = cli("run", "--spec", spec, "--", "/bin/cat", workspace.secret_file, cwd=workspace.granted)
    assert _denied(denied), f"expected denial, got code={denied.code} stderr={denied.stderr!r}"


@pytest.mark.fw_e2e("FW-E2E-002")
def test_write_scope_and_readonly(cli, workspace, tmp_path):
    # Read the whole tree; write only under granted/.
    spec = write_spec(
        tmp_path / "spec.toml",
        reads=[f"{workspace.root}/**"],
        writes=[f"{workspace.granted}/**"],
    )
    wrote = cli(
        "run", "--spec", spec, "--", "/bin/sh", "-c",
        f"echo x > {workspace.granted}/new.txt", cwd=workspace.granted,
    )
    assert wrote.code == 0, wrote.stderr
    assert (workspace.granted / "new.txt").exists()

    ro = cli(
        "run", "--spec", spec, "--", "/bin/sh", "-c",
        f"echo x > {workspace.secret}/injected.txt", cwd=workspace.granted,
    )
    assert ro.code != 0, "write to a read-only-granted path must be denied"

    etc = cli(
        "run", "--spec", spec, "--", "/bin/sh", "-c",
        "echo x > /etc/formwork-should-not-exist", cwd=workspace.granted,
    )
    assert etc.code != 0, "write to /etc must be denied"


@pytest.mark.fw_e2e("FW-E2E-003")
def test_sensitive_subtraction_under_broad_grant(cli, workspace, tmp_path):
    spec = write_spec(
        tmp_path / "spec.toml",
        reads=[f"{workspace.root}/**"],
        subtract=[f"{workspace.secret}/**"],
    )
    ok = cli("run", "--spec", spec, "--", "/bin/cat", workspace.granted_file, cwd=workspace.granted)
    assert ok.code == 0, ok.stderr
    assert "in-scope contents" in ok.stdout

    denied = cli("run", "--spec", spec, "--", "/bin/cat", workspace.secret_file, cwd=workspace.granted)
    assert _denied(denied), "subtracted path must be denied even under a broad read grant"
