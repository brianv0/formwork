"""Credential catalog and launcher E2E (FEP-2 §9.2). Enforcement tests run against real Seatbelt
with $HOME pointed at a fake home full of planted fake credentials, so the developer's real
secrets are never in play. The operator channel is formwork's stderr telemetry; the agent channel
is the confined child's own view -- the tests keep the two apart."""

import json
import os

import pytest

BROAD_BLUEPRINT = """\
net = "deny"

[fs]
read-mode = "ambient-minus-subtract"
reads = ["/**"]
writes = ["{writes}/**"]
"""


@pytest.fixture
def fake_home(tmp_path):
    """A realpath'd home with planted fake credentials and ordinary files."""
    home = tmp_path / "home"
    for rel, content in [
        (".aws/credentials", "[default]\naws_secret_access_key = FAKE\n"),
        (".ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY----- FAKE\n"),
        (".someprovider/credentials", "novel-provider-secret\n"),
        ("project/.env.production", "DB_PASSWORD=fake\n"),
        ("project/ok.txt", "ordinary project file\n"),
        ("notes.txt", "ordinary home file\n"),
    ]:
        p = home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return home.resolve()


def _blueprint_for(fake_home, tmp_path):
    bp = tmp_path / "blueprint.toml"
    bp.write_text(BROAD_BLUEPRINT.format(writes=fake_home / "project"))
    return bp


def _operator_lines(stderr: str) -> str:
    """Formwork's own telemetry (the tracing span prefix marks it)."""
    return "\n".join(l for l in stderr.splitlines() if "formwork{" in l)


def _agent_lines(stderr: str) -> str:
    """What the confined child itself wrote to the shared stderr."""
    return "\n".join(l for l in stderr.splitlines() if "formwork{" not in l)


@pytest.mark.fw_e2e("FW-E2E-045")
@pytest.mark.macos
def test_path_credential_denied_and_itemized(cli, fake_home, tmp_path):
    bp = _blueprint_for(fake_home, tmp_path)
    # The per-type itemization is the debug tier (the default info line is a stable summary);
    # FW-CRED7 requires the operator CAN get the naming, so the denial run asks for it.
    env = {"HOME": str(fake_home), "RUST_LOG": "debug"}

    # Ordinary reads under the same broad grant succeed -- the floor is a hole, not a wall.
    ok = cli("run", "--blueprint", bp, "--", "/bin/cat", fake_home / "notes.txt",
             cwd=fake_home, env=env)
    assert ok.code == 0, ok.stderr
    assert "ordinary home file" in ok.stdout

    denied = cli("run", "--blueprint", bp, "--", "/bin/cat", fake_home / ".aws/credentials",
                 cwd=fake_home, env=env)
    assert denied.code != 0, "catalog path must be denied under a broad grant"
    assert "FAKE" not in denied.stdout

    # Operator channel names the type (FW-CRED7)...
    operator = _operator_lines(denied.stderr)
    assert '"aws"' in operator, f"operator channel must name type aws: {operator!r}"
    # ...while the agent-facing denial is the kernel's plain errno, no catalog annotation. The
    # path the agent itself asked for legitimately echoes back (cat prints it), so it is removed
    # before scanning for annotation words.
    agent = _agent_lines(denied.stderr).replace(str(fake_home / ".aws/credentials"), "<path>")
    assert "not permitted" in agent.lower() or "denied" in agent.lower(), agent
    for oracle in ("catalog", "credential", "aws", "type:"):
        assert oracle not in agent.lower(), f"agent channel leaks {oracle!r}: {agent!r}"


@pytest.mark.fw_e2e("FW-E2E-046")
@pytest.mark.macos
def test_env_credential_stripped_and_absent_in_tree(cli, fake_home, tmp_path):
    bp = _blueprint_for(fake_home, tmp_path)
    probe = (
        'echo "child=${AWS_SECRET_ACCESS_KEY-UNSET}";'
        ' /bin/sh -c \'echo "grandchild=${AWS_SECRET_ACCESS_KEY-UNSET}"\';'
        ' echo "ordinary=${ORDINARY_VAR-UNSET}"'
    )
    res = cli(
        "run", "--blueprint", bp, "--", "/bin/sh", "-c", probe,
        cwd=fake_home,
        env={"HOME": str(fake_home), "AWS_SECRET_ACCESS_KEY": "sekrit-value",
             "ORDINARY_VAR": "survives"},
    )
    assert res.code == 0, res.stderr
    # Absent -- not empty -- at both depths (FW-INV7): ${VAR-UNSET} prints UNSET only when unset.
    assert "child=UNSET" in res.stdout, res.stdout
    assert "grandchild=UNSET" in res.stdout, res.stdout
    assert "ordinary=survives" in res.stdout, res.stdout
    # The value never appears anywhere -- not even in the operator channel (names only).
    assert "sekrit-value" not in res.stdout + res.stderr
    operator = _operator_lines(res.stderr)
    assert "AWS_SECRET_ACCESS_KEY" in operator and '"aws"' in operator, operator


@pytest.mark.fw_e2e("FW-E2E-047")
@pytest.mark.macos
def test_env_points_to_file_dual_arm(cli, fake_home, tmp_path):
    """GOOGLE_APPLICATION_CREDENTIALS under the default deny: the variable is stripped AND the
    file its value names is denied -- even though the file sits inside the readable grant, so the
    deny is FW-CRED3's, not the grant's."""
    bp = _blueprint_for(fake_home, tmp_path)
    sa = fake_home / "project" / "sa.json"
    sa.write_text('{"type": "service_account", "private_key": "FAKE"}\n')
    env = {"HOME": str(fake_home), "GOOGLE_APPLICATION_CREDENTIALS": str(sa)}

    # Control: without the env var pointing at it, the file is an ordinary in-grant read.
    control = cli("run", "--blueprint", bp, "--", "/bin/cat", sa,
                  cwd=fake_home, env={"HOME": str(fake_home)})
    assert control.code == 0, control.stderr

    stripped = cli("run", "--blueprint", bp, "--", "/bin/sh", "-c",
                   'echo "gac=${GOOGLE_APPLICATION_CREDENTIALS-UNSET}"',
                   cwd=fake_home, env=env)
    assert "gac=UNSET" in stripped.stdout, stripped.stdout

    denied = cli("run", "--blueprint", bp, "--", "/bin/cat", sa, cwd=fake_home, env=env)
    assert denied.code != 0, "the referenced file must be denied while the var is set"
    assert "FAKE" not in denied.stdout


@pytest.mark.fw_e2e("FW-E2E-048")
@pytest.mark.macos
def test_exclude_by_type_unblocks_exactly_one(cli, fake_home, tmp_path):
    bp = _blueprint_for(fake_home, tmp_path)
    env = {
        "HOME": str(fake_home),
        "AWS_SECRET_ACCESS_KEY": "aws-value",
        "SLACK_BOT_TOKEN": "xoxb-fake",
    }

    # aws path becomes readable and its env var present...
    path_ok = cli("run", "--blueprint", bp, "--allow-cred", "aws", "--",
                  "/bin/cat", fake_home / ".aws/credentials", cwd=fake_home, env=env)
    assert path_ok.code == 0, f"--allow-cred aws must un-block the aws path: {path_ok.stderr}"

    probe = 'echo "aws=${AWS_SECRET_ACCESS_KEY-UNSET} slack=${SLACK_BOT_TOKEN-UNSET}"'
    env_ok = cli("run", "--blueprint", bp, "--allow-cred", "aws", "--",
                 "/bin/sh", "-c", probe, cwd=fake_home, env=env)
    assert "aws=aws-value" in env_ok.stdout, env_ok.stdout
    # ...while adjacent types stay put: slack still stripped, ssh still denied.
    assert "slack=UNSET" in env_ok.stdout, env_ok.stdout
    ssh = cli("run", "--blueprint", bp, "--allow-cred", "aws", "--",
              "/bin/cat", fake_home / ".ssh/id_ed25519", cwd=fake_home, env=env)
    assert ssh.code != 0, "ssh must stay denied when only aws is excluded"

    # A typo'd type is a loud config error, not a silent no-op.
    typo = cli("run", "--blueprint", bp, "--allow-cred", "awss", "--",
               "/bin/true", cwd=fake_home, env=env)
    assert typo.code != 0 and "unknown credential type" in typo.stderr


@pytest.mark.fw_e2e("FW-E2E-049")
@pytest.mark.macos
def test_generic_backstop_covers_uncatalogued_shapes(cli, fake_home, tmp_path):
    bp = _blueprint_for(fake_home, tmp_path)
    env = {"HOME": str(fake_home)}

    novel = cli("run", "--blueprint", bp, "--", "/bin/cat",
                fake_home / ".someprovider/credentials", cwd=fake_home, env=env)
    assert novel.code != 0, "a novel ~/.someprovider/credentials must hit the backstop"

    dotenv_variant = cli("run", "--blueprint", bp, "--", "/bin/cat",
                         fake_home / "project/.env.production", cwd=fake_home, env=env)
    assert dotenv_variant.code != 0, "an unusual .env variant must hit the backstop"

    # The sibling non-secret file in the same tree stays readable (the backstop is a hole, not a wall).
    ok = cli("run", "--blueprint", bp, "--", "/bin/cat",
             fake_home / "project/ok.txt", cwd=fake_home, env=env)
    assert ok.code == 0, ok.stderr


@pytest.mark.fw_e2e("FW-E2E-050")
def test_report_labels_mechanism_per_type(cli, fake_home, tmp_path):
    bp = _blueprint_for(fake_home, tmp_path)
    env = {"HOME": str(fake_home)}

    res = cli("compile", "--blueprint", bp, "--target", "macos", "--report-only", env=env)
    assert res.code == 0, res.stderr
    report = json.loads(res.stdout)
    creds = report["credentials"]

    # Dual-kind type: path -> OS sandbox, env -> launcher (FW-CRED2/8).
    aws = creds["per-type"]["aws"]
    assert aws["path"]["backend"] == "seatbelt"
    assert aws["path"]["status"] == "enforced"
    assert aws["env"]["backend"] == "launcher"
    # Env-only and path-only types claim exactly their kinds -- nothing more (FW-INV5).
    assert "path" not in creds["per-type"]["slack"]
    assert creds["per-type"]["slack"]["env"]["backend"] == "launcher"
    assert "env" not in creds["per-type"]["ssh"]
    assert creds["per-type"]["ssh"]["path"]["backend"] == "seatbelt"
    # The launcher contingency is disclosed with the report itself (FW-CRED8 / FW-ADV-014).
    assert "launching process" in creds["launcher-contingency"]

    # On Linux the path arm rides Landlock and says so.
    linux = cli("compile", "--blueprint", bp, "--target", "linux-v6", "--report-only", env=env)
    linux_creds = json.loads(linux.stdout)["credentials"]
    assert linux_creds["per-type"]["aws"]["path"]["backend"] == "landlock"
    assert linux_creds["per-type"]["aws"]["env"]["backend"] == "launcher"
