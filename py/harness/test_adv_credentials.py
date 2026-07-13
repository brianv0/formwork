"""Adversarial credential scenarios (FEP-2 §9.4): the oracle probe (FW-ADV-012) and
launcher-bypass honesty (FW-ADV-014). FW-ADV-013 (discovery confused-deputy) lives with the
discovery suite. Timing side channels are out of asserting scope (flaky by nature); the design
property is that both arms are decided pre-spawn, so no per-access timing difference exists to
measure."""

import json
import subprocess

import pytest

BROAD_BLUEPRINT = """\
net = "deny"

[fs]
read-mode = "ambient-minus-subtract"
reads = ["/**"]
writes = ["{writes}/**"]
subtract = ["{operator_deny}/**"]
"""


@pytest.fixture
def fake_home(tmp_path):
    home = tmp_path / "home"
    for rel, content in [
        (".aws/credentials", "[default]\nfake\n"),
        ("operator-denied/file.txt", "operator secret\n"),
        ("project/ok.txt", "ok\n"),
    ]:
        p = home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return home.resolve()


def _blueprint(fake_home, tmp_path):
    bp = tmp_path / "blueprint.toml"
    bp.write_text(
        BROAD_BLUEPRINT.format(
            writes=fake_home / "project", operator_deny=fake_home / "operator-denied"
        )
    )
    return bp


def _agent_view(result, *paths):
    """What the confined agent could observe: exit code + stdout + its own stderr lines, with
    formwork's operator telemetry excluded and the probed path normalized away."""
    lines = [
        l
        for l in result.stderr.splitlines()
        if "credential catalog" not in l and "formwork" not in l
    ]
    text = "\n".join(lines)
    for p in paths:
        text = text.replace(str(p), "<path>")
    return (result.code, result.stdout, text)


@pytest.mark.fw_adv("FW-ADV-012")
@pytest.mark.macos
def test_credential_oracle_probe_path_and_env(cli, fake_home, tmp_path):
    bp = _blueprint(fake_home, tmp_path)
    env = {"HOME": str(fake_home)}

    # Path arm: a catalog denial must be indistinguishable from an ordinary (operator-subtracted)
    # denial -- same errno, same message shape, no type annotation.
    catalog_path = fake_home / ".aws/credentials"
    ordinary_path = fake_home / "operator-denied/file.txt"
    catalog_denial = cli("run", "--blueprint", bp, "--", "/bin/cat", catalog_path,
                         cwd=fake_home, env=env)
    ordinary_denial = cli("run", "--blueprint", bp, "--", "/bin/cat", ordinary_path,
                          cwd=fake_home, env=env)
    assert catalog_denial.code != 0 and ordinary_denial.code != 0
    assert _agent_view(catalog_denial, catalog_path) == _agent_view(
        ordinary_denial, ordinary_path
    ), "a catalog denial must not be distinguishable from a plain denial"

    # Env arm: a stripped variable must be indistinguishable from one never set (FW-INV9).
    probe = 'echo "probe=${AWS_SECRET_ACCESS_KEY+set}${AWS_SECRET_ACCESS_KEY-unset}"'
    with_var = cli("run", "--blueprint", bp, "--", "/bin/sh", "-c", probe,
                   cwd=fake_home, env={**env, "AWS_SECRET_ACCESS_KEY": "s3cr3t"})
    never_set = cli("run", "--blueprint", bp, "--", "/bin/sh", "-c", probe,
                    cwd=fake_home, env=env)
    assert "probe=unset" in with_var.stdout
    assert _agent_view(with_var) == _agent_view(never_set), (
        "a stripped variable must look exactly like a never-set one"
    )

    # No arm ever surfaces an interactive prompt a social-engineering payload could target
    # (extends FW-ADV-004): every run above completed without operator interaction.
    for r in (catalog_denial, ordinary_denial, with_var, never_set):
        assert "?" not in r.stdout.lower() or "probe=" in r.stdout, r.stdout


@pytest.mark.fw_adv("FW-ADV-014")
def test_launcher_bypass_honesty(cli, fake_home, tmp_path):
    """Started WITHOUT formwork, the variable is present -- and the report had already disclosed
    env-shading as launcher-contingent, so the guarantee was never overclaimed (FW-CRED8)."""
    direct = subprocess.run(
        ["/bin/sh", "-c", 'echo "direct=${AWS_SECRET_ACCESS_KEY-UNSET}"'],
        env={"AWS_SECRET_ACCESS_KEY": "present", "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert "direct=present" in direct.stdout

    bp = _blueprint(fake_home, tmp_path)
    report = cli("compile", "--blueprint", bp, "--target", "macos", "--report-only",
                 env={"HOME": str(fake_home)})
    creds = json.loads(report.stdout)["credentials"]
    note = creds["launcher-contingency"]
    assert "launching process" in note and "not a kernel guarantee" in note, note
    # The env rows themselves carry the launcher backend, never an OS-sandbox claim.
    assert creds["per-type"]["aws"]["env"]["backend"] == "launcher"
