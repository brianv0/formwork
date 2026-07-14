"""Filesystem confinement E2E (design §7.1), driven through the `formwork` CLI. macOS-only for now."""

import textwrap

import pytest

from helpers import write_blueprint

pytestmark = pytest.mark.macos


# A genuine TOCTOU attempt: one thread flips a symlink in the WRITABLE area between an in-scope file
# and the out-of-scope secret while the main thread reads through it in a tight loop. If enforcement
# were a userspace pre-check, a symlink swapped in after the check would leak the secret. Because the
# kernel matches on the RESOLVED path at every access, the read of the secret target always denies.
# Exit 3 = the secret was observed at least once (leak); exit 0 = never (enforcement held).
_SYMLINK_RACE_PROBE = textwrap.dedent(
    """
    import os, sys, threading
    granted, secret, safe = sys.argv[1], sys.argv[2], sys.argv[3]
    link = os.path.join(granted, "race-link")
    stop = threading.Event()

    def flip():
        while not stop.is_set():
            for target in (safe, secret):
                try: os.unlink(link)
                except FileNotFoundError: pass
                try: os.symlink(target, link)
                except OSError: pass

    t = threading.Thread(target=flip, daemon=True); t.start()
    leaked = False
    try:
        for _ in range(20000):
            try:
                with open(link) as f:
                    if "TOP SECRET" in f.read():
                        leaked = True; break
            except OSError:
                pass
    finally:
        stop.set(); t.join(1)
    sys.exit(3 if leaked else 0)
    """
)


def _denied(result):
    """Nonzero exit with an EPERM-ish message (a confinement denial, not a crash)."""
    return result.code != 0 and (
        "Operation not permitted" in result.stderr
        or "not permitted" in result.stderr.lower()
        or "denied" in result.stderr.lower()
    )


@pytest.mark.fw_e2e("FW-E2E-001")
def test_granted_read_succeeds_ungranted_denied(cli, workspace, tmp_path):
    blueprint = write_blueprint(
        tmp_path / "blueprint.toml",
        reads=[f"{workspace.granted}/**"],
        writes=[f"{workspace.granted}/**"],
    )
    ok = cli("run", "--blueprint", blueprint, "--", "/bin/cat", workspace.granted_file, cwd=workspace.granted)
    assert ok.code == 0, ok.stderr
    assert "in-scope contents" in ok.stdout

    denied = cli("run", "--blueprint", blueprint, "--", "/bin/cat", workspace.secret_file, cwd=workspace.granted)
    assert _denied(denied), f"expected denial, got code={denied.code} stderr={denied.stderr!r}"


@pytest.mark.fw_e2e("FW-E2E-002")
def test_write_scope_and_readonly(cli, workspace, tmp_path):
    # Read the whole tree; write only under granted/.
    blueprint = write_blueprint(
        tmp_path / "blueprint.toml",
        reads=[f"{workspace.root}/**"],
        writes=[f"{workspace.granted}/**"],
    )
    wrote = cli(
        "run", "--blueprint", blueprint, "--", "/bin/sh", "-c",
        f"echo x > {workspace.granted}/new.txt", cwd=workspace.granted,
    )
    assert wrote.code == 0, wrote.stderr
    assert (workspace.granted / "new.txt").exists()

    ro = cli(
        "run", "--blueprint", blueprint, "--", "/bin/sh", "-c",
        f"echo x > {workspace.secret}/injected.txt", cwd=workspace.granted,
    )
    assert ro.code != 0, "write to a read-only-granted path must be denied"

    etc = cli(
        "run", "--blueprint", blueprint, "--", "/bin/sh", "-c",
        "echo x > /etc/formwork-should-not-exist", cwd=workspace.granted,
    )
    assert etc.code != 0, "write to /etc must be denied"


@pytest.mark.fw_e2e("FW-E2E-003")
def test_sensitive_subtraction_under_broad_grant(cli, workspace, tmp_path):
    blueprint = write_blueprint(
        tmp_path / "blueprint.toml",
        reads=[f"{workspace.root}/**"],
        subtract=[f"{workspace.secret}/**"],
    )
    ok = cli("run", "--blueprint", blueprint, "--", "/bin/cat", workspace.granted_file, cwd=workspace.granted)
    assert ok.code == 0, ok.stderr
    assert "in-scope contents" in ok.stdout

    denied = cli("run", "--blueprint", blueprint, "--", "/bin/cat", workspace.secret_file, cwd=workspace.granted)
    assert _denied(denied), "subtracted path must be denied even under a broad read grant"


@pytest.mark.fw_adv("FW-ADV-002")
def test_toctou_symlink_race_never_leaks_sensitive_target(cli, workspace, tmp_path):
    """A symlink race from a writable path to a sensitive target cannot win: enforcement is at the
    kernel access on the resolved path, not a userspace pre-check, so no access to the secret ever
    succeeds however the symlink is flipped between check and use (FW-ADV-002)."""
    # secret/ is out of the read scope (only granted/ is granted), so a link into it is the attack.
    blueprint = write_blueprint(
        tmp_path / "blueprint.toml",
        reads=[f"{workspace.granted}/**"],
        writes=[f"{workspace.granted}/**"],
    )
    result = cli(
        "run", "--blueprint", blueprint, "--", "/usr/bin/python3", "-c", _SYMLINK_RACE_PROBE,
        str(workspace.granted), str(workspace.secret_file), str(workspace.granted_file),
        cwd=workspace.granted,
    )
    assert result.code == 0, (
        f"symlink race leaked the sensitive target (exit {result.code}); enforcement must hold at "
        f"the kernel access. stderr={result.stderr!r}"
    )
