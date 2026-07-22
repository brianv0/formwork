"""Linux observation E2E (FW-E2E-071): the ptrace denial feed, against the real chain -- an
unconfined `strace` tracing a `run --confine-self` shim that enforces with real Landlock. The
Linux sibling of test_discovery.py's macOS suite: same properties, different tap. Gated on the
chain actually existing here (Landlock kernel, strace installed, ptrace permitted) -- skips are
loud, never silent passes."""

import json
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.linux


@pytest.fixture
def ptrace_feed(cli):
    """Skip unless this host carries the whole Linux feed chain."""
    if shutil.which("strace") is None:
        pytest.skip("strace not installed")
    if json.loads(cli("detect").stdout).get("landlock-abi") is None:
        pytest.skip("no Landlock on this kernel (nothing enforces, so nothing denies)")
    probe = subprocess.run(
        ["strace", "-qq", "-o", "/dev/null", "/bin/true"], capture_output=True
    )
    if probe.returncode != 0:
        pytest.skip("ptrace is blocked in this environment (container seccomp?)")


@pytest.mark.fw_e2e("FW-E2E-071")
def test_millisecond_workload_denial_is_captured(ptrace_feed, cli, tmp_path):
    """The canonical discovery shape (FW-E2E-064's property, Linux realization): a `cat` that
    dies on its first denied read in about a millisecond still lands in the proposal. The trace
    is complete when the tracee exits, so unlike the macOS window there is no latency to poll."""
    denied = tmp_path / "denied.txt"
    denied.write_text("nope\n")
    blueprint = tmp_path / "bp.toml"
    blueprint.write_text(
        'net = "deny"\n[fs]\nread-mode = "ambient-minus-subtract"\n'
        f'subtract = ["{denied}"]\n'
    )

    result = cli(
        "learn", "--blueprint", blueprint, "--", "/bin/cat", denied,
        cwd=tmp_path, env={"HOME": str(tmp_path)},
    )
    assert result.code != 0, "cat failing on the subtracted file IS the scenario"
    proposal = tmp_path / "bp.toml.proposal.toml"
    assert proposal.exists(), result.stderr
    assert str(denied) in proposal.read_text(), (
        f"the denied read must be a candidate:\n{proposal.read_text()}\n{result.stderr}"
    )
    # The proposal pointer is a stdout result (survives quiet telemetry), not a log line.
    assert "proposal:" in result.stdout, result.stdout


@pytest.mark.fw_e2e("FW-E2E-071")
@pytest.mark.fw_e2e("FW-E2E-051")
def test_credential_denial_is_withheld_not_proposed(ptrace_feed, cli, tmp_path):
    """FW-E2E-051's floor property through the Linux tap: a credential the workload hit is
    withheld from the proposal (FW-DISC3), while an ordinary denied path is proposed."""
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    key = home / ".ssh" / "id_ed25519"
    key.write_text("FAKE KEY\n")
    plain = tmp_path / "data.txt"
    plain.write_text("data\n")
    blueprint = tmp_path / "bp.toml"
    blueprint.write_text(
        'net = "deny"\n[fs]\nread-mode = "ambient-minus-subtract"\n'
        f'subtract = ["{plain}"]\n'
    )

    result = cli(
        "learn", "--blueprint", blueprint,
        "--", "/bin/sh", "-c", f"cat {key}; cat {plain}",
        cwd=tmp_path, env={"HOME": str(home)},
    )
    proposal = tmp_path / "bp.toml.proposal.toml"
    assert proposal.exists(), result.stderr
    text = proposal.read_text()
    assert str(plain) in text, f"the ordinary denial must be proposed:\n{text}\n{result.stderr}"
    assert ".ssh" not in text, f"a credential must never be a candidate (FW-DISC3):\n{text}"
    # The withheld itemization is operator-channel material (FW-CRED7).
    assert "withheld" in result.stderr, result.stderr
