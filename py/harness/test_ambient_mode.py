"""Ambient-read-mode parity E2E (FW-E2E-072): the same no-explicit-reads ambient blueprint must
mean the same thing on every backend -- reads default-allow, holes and floor deny. Runs wherever a
native confiner exists (macOS Seatbelt always; Linux with Landlock), because the divergence this
pins was exactly per-platform: Seatbelt's `(allow default)` vs Landlock's governed-but-ungranted."""

import json
import sys

import pytest


@pytest.fixture
def enforceable(cli):
    """Skip unless this host can natively enforce (the property under test is enforcement)."""
    if sys.platform == "darwin":
        return
    if sys.platform.startswith("linux"):
        if json.loads(cli("detect").stdout).get("landlock-abi") is None:
            pytest.skip("no Landlock on this kernel")
        return
    pytest.skip("no native confiner on this platform")


@pytest.mark.fw_e2e("FW-E2E-072")
def test_ambient_mode_is_ambient_with_no_explicit_reads(enforceable, cli, tmp_path):
    root = tmp_path.resolve()  # kernel coordinates (macOS /var -> /private/var)
    ordinary = root / "ordinary.txt"
    ordinary.write_text("ambient-readable\n")
    hole = root / "carved-out.txt"
    hole.write_text("never\n")
    home = root / "home"
    (home / ".ssh").mkdir(parents=True)
    key = home / ".ssh" / "id_ed25519"
    key.write_text("FAKE KEY\n")
    blueprint = root / "bp.toml"
    blueprint.write_text(
        'net = "deny"\n[fs]\nread-mode = "ambient-minus-subtract"\n'
        f'subtract = ["{hole}"]\n'
    )

    def run(target):
        return cli(
            "run", "--blueprint", blueprint, "--", "/bin/cat", target,
            cwd=root, env={"HOME": str(home)},
        )

    # Ambient means ambient: an ungranted ordinary path reads (and the workload binary exec'd,
    # which on Linux also needs the ambient ReadFile grant for execve's internal open).
    ok = run(ordinary)
    assert ok.code == 0, f"ambient read failed -- the mode is not ambient here: {ok.stderr}"
    assert "ambient-readable" in ok.stdout

    # The holes still carve: an operator subtract, and the credential floor.
    carved = run(hole)
    assert carved.code != 0, "a subtract hole must deny under ambient"
    floored = run(key)
    assert floored.code != 0, "the credential floor must deny under ambient"
