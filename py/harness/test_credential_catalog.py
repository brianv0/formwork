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
    # ...and announces the active backstop, the one floor row that also denies inside a granted
    # tree (FW-CRED6), so its otherwise-invisible EACCES has a named cause.
    assert "credential backstop active" in operator, (
        f"operator channel must announce the active backstop: {operator!r}"
    )
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

    # FW-CRED9: Seatbelt carries any-depth floor rows as a regex, Landlock cannot root them. The
    # all-any-depth backstop and dotenv are Partial on Linux, with a reason that cites FW-CRED9 and
    # claims no absolute rows they do not have; a type with absolute rows stays Enforced.
    assert creds["backstop"]["status"] == "enforced"
    assert creds["per-type"]["dotenv"]["path"]["status"] == "enforced"
    assert linux_creds["per-type"]["ssh"]["path"]["status"] == "enforced"
    for partial in (linux_creds["backstop"], linux_creds["per-type"]["dotenv"]["path"]):
        assert partial["status"] == "partial", partial
        assert "withheld on Linux" in partial["reason"], partial
        assert "FW-CRED9" in partial["reason"], partial
        assert "absolute rows" not in partial["reason"], partial
    assert "credential-floor **/credentials" in json.loads(linux.stdout)["withheld"]


@pytest.mark.fw_e2e("FW-E2E-050")
@pytest.mark.linux
def test_withheld_backstop_is_readable_and_never_claimed_denied(cli, fake_home, tmp_path):
    """FW-CRED9's Linux half at the real boundary: the report's Partial backstop matches what the
    kernel does -- a backstop-shaped file under a broad grant is readable while an absolute floor
    row still denies -- and no human surface claims the withheld denial (FW-INV5/FW-XR1). If Linux
    ever roots any-depth rows, this fails until the report and the wording catch up."""
    bp = _blueprint_for(fake_home, tmp_path)
    env = {"HOME": str(fake_home)}
    novel = fake_home / ".someprovider/credentials"

    summary_json = cli("explain", "--blueprint", bp, "--json", env=env)
    assert summary_json.code == 0, summary_json.stderr
    report = json.loads(summary_json.stdout)["report"]
    if report["credentials"]["backstop"]["status"] != "partial":
        pytest.skip(f"backstop is {report['credentials']['backstop']['status']} on this host")

    # The paired probe: the absolute aws row is denied, the any-depth backstop row is not.
    aws = cli("run", "--blueprint", bp, "--", "/bin/cat", fake_home / ".aws/credentials",
              cwd=fake_home, env=env)
    assert aws.code != 0, "an absolute floor row must still deny on Linux"
    withheld = cli("run", "--blueprint", bp, "--", "/bin/cat", novel, cwd=fake_home, env=env)
    assert withheld.code == 0, withheld.stderr
    assert "novel-provider-secret" in withheld.stdout
    operator = _operator_lines(withheld.stderr)
    assert "credential backstop not enforced on this host" in operator, operator
    assert "credential backstop active" not in operator, operator

    # The summary: the backstop line carries the report's verdict, and the denied total counts
    # only the types this host enforces.
    summary = cli("explain", "--blueprint", bp, env=env)
    assert summary.code == 0, summary.stderr
    lines = summary.stdout.splitlines()
    backstop = next(l for l in lines if l.startswith("backstop: "))
    assert "denied" not in backstop and "withheld on Linux" in backstop, backstop
    floor = next(l for l in lines if l.startswith("credential floor: "))
    per_type = report["credentials"]["per-type"].values()
    enforced = sum(1 for t in per_type if t.get("path", {}).get("status") == "enforced")
    assert f"-- {enforced} path types denied, " in floor, floor
    assert "partial on this host (dotenv)" in floor, floor

    # The per-path verdict: the model's deny, the host note, and a hint that claims no denial.
    path = cli("explain", "--blueprint", bp, novel, env=env)
    assert path.code == 0, path.stderr
    assert "withheld on this host" in path.stdout, path.stdout
    hint = next(l for l in path.stdout.splitlines() if l.strip().startswith("hint: "))
    assert "no denial here to lift" in hint and "-- fires at any depth" not in hint, hint
