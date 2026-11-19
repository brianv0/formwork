"""FW-E2E-199: the file a credential variable names is floored in learning (FW-DISC15), against
the real kernel and the real denial feed on either backend. The Launcher denies that file
(FW-CRED3), but its path has no Catalog shape, so only the Launcher's own deny marks the observed
denial as a credential's. Without that, the denial was an ordinary candidate, and inside the
auto-widen zone the learning run granted the key to every later run."""

import json
import shutil
import subprocess
import sys

import pytest

# Closed mode needs the toolchain's own files granted on Linux; Seatbelt's closed mode carries
# them (the shape test_discovery.py runs `/bin/cat` under).
SYSTEM_READS = (
    [] if sys.platform == "darwin" else ["/usr/**", "/bin/**", "/lib/**", "/lib64/**", "/etc/**"]
)


@pytest.fixture
def denial_feed(cli):
    """Skip unless this host carries a denial feed: the unified log on macOS, or the whole
    Linux chain (Landlock, strace, ptrace permitted)."""
    if sys.platform == "darwin":
        return
    if shutil.which("strace") is None:
        pytest.skip("strace not installed")
    if json.loads(cli("explain", "--json").stdout)["host"].get("landlock-abi") is None:
        pytest.skip("no Landlock on this kernel (nothing enforces, so nothing denies)")
    probe = subprocess.run(["strace", "-qq", "-o", "/dev/null", "/bin/true"], capture_output=True)
    if probe.returncode != 0:
        pytest.skip("ptrace is blocked in this environment (container seccomp?)")


@pytest.mark.fw_e2e("FW-E2E-199")
def test_the_file_a_credential_variable_names_is_withheld_not_self_granted(
    denial_feed, cli, tmp_path
):
    root = tmp_path.resolve()
    home = root / "home"
    home.mkdir()
    keys = root / "keys"
    keys.mkdir()
    key = keys / "sa.json"
    key.write_text('{"private_key": "FAKE"}\n')
    ok = root / "ok.txt"
    ok.write_text("ok\n")
    blueprint = root / "bp.toml"
    reads = ", ".join(f'"{p}"' for p in [ok, *SYSTEM_READS])
    # The zone is drawn over the key's directory: whatever is proposed there is self-granted.
    blueprint.write_text(
        f'net = "deny"\n[fs]\nread-mode = "closed"\nreads = [{reads}]\n'
        f'[discovery]\nauto-widen = ["{keys}/**"]\n'
    )
    discovered = root / "bp.toml.discovered.toml"
    proposal = root / "bp.toml.proposal.toml"

    learned = cli(
        "learn", "--blueprint", blueprint, "--", "/bin/cat", key,
        cwd=root, env={"HOME": str(home), "GOOGLE_APPLICATION_CREDENTIALS": str(key)},
        timeout=120,
    )
    assert learned.code != 0, "the Launcher denies the key during the learning run"
    assert "FAKE" not in learned.stdout

    # Withheld, itemized with the type whose variable named the file...
    withheld = [
        l for l in learned.stderr.splitlines()
        if "withheld by the credential floor" in l and "sa.json" in l
    ]
    assert withheld, learned.stderr
    assert all("gcp" in l for l in withheld), withheld
    # ...and neither proposed nor self-granted, zone or not.
    assert proposal.exists(), learned.stderr
    assert "sa.json" not in proposal.read_text(), proposal.read_text()
    assert not discovered.exists() or "sa.json" not in discovered.read_text(), (
        discovered.read_text()
    )

    # A later run launched without the variable: no Launcher deny now, and still no grant.
    later = cli(
        "run", "--blueprint", blueprint, "--", "/bin/cat", key,
        cwd=root, env={"HOME": str(home), "GOOGLE_APPLICATION_CREDENTIALS": ""},
    )
    assert later.code != 0, "the key must not have been granted by the learning run"
    assert "FAKE" not in later.stdout, later.stdout
