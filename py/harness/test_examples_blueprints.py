"""The shipped example blueprints (examples/blueprints/) compile and report honestly, driven through the
`formwork` CLI. Cross-platform: compilation is pure, so no platform marker."""

import json

import pytest

from helpers import REPO_ROOT

BLUEPRINTS = REPO_ROOT / "examples" / "blueprints"


@pytest.mark.fw_e2e("FW-E2E-026")
def test_agent_blueprint_compiles_and_accounts_for_net(cli):
    """The Axis-A Claude Code blueprint compiles, and its host-scoped egress is a real,
    accounted-for posture on any host -- never silently open (FW-INV6)."""
    result = cli("compile", "--blueprint", BLUEPRINTS / "claude-code.toml", "--report-only")
    assert result.code == 0, result.stderr
    report = json.loads(result.stdout)
    caps = report["per-capability"]
    assert "fs-read" in caps and "fs-write" in caps
    # Host rules -> both the default-deny floor and the host scope are accounted for.
    assert "net-default-deny" in caps
    assert "net-host-scope" in caps
    assert caps["net-host-scope"]["status"] in ("enforced", "partial", "unenforceable")


@pytest.mark.fw_e2e("FW-E2E-026")
def test_mcp_gateway_blueprint_compiles(cli):
    """The Axis-B gateway blueprint (backend fs/net + [mcp.files] shading) is a well-formed blueprint."""
    result = cli("compile", "--blueprint", BLUEPRINTS / "mcp-gateway.toml", "--report-only")
    assert result.code == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["per-capability"]["net-default-deny"]["status"]


@pytest.mark.fw_e2e("FW-E2E-014")
def test_gateway_unknown_server_is_a_loud_config_error(cli):
    """A `--server` with no matching `[mcp.<name>]` policy is a config error surfaced loudly (with
    the known servers), never a silent deny that would let a typo masquerade as an empty toolset
    (Errors invariant). Cross-platform: it fails at the lookup, before any confiner runs."""
    result = cli("gateway", "--blueprint", BLUEPRINTS / "mcp-gateway.toml", "--server", "bogus", "--", "/bin/true")
    assert result.code != 0, "unknown server must fail, not silently expose nothing"
    assert "bogus" in result.stderr and "files" in result.stderr


@pytest.mark.fw_e2e("FW-E2E-061")
def test_rules_demo_compiles(cli):
    """The verb-rule example (flat `rules` + `mode`, FEP-3) is a well-formed blueprint that compiles
    like any other -- verbs desugar into the one model (FW-BP1)."""
    result = cli("compile", "--blueprint", BLUEPRINTS / "rules-demo.toml", "--target", "macos", "--report-only")
    assert result.code == 0, result.stderr
    caps = json.loads(result.stdout)["per-capability"]
    assert caps["fs-read"]["status"] == "enforced"
    assert caps["exec"]["status"] == "enforced"  # readexec:/bin/** governs exec
    assert caps["net-default-deny"]["status"] == "partial"  # the loopback-callback listener (FW-EGR15, C1)


@pytest.mark.linux
@pytest.mark.fw_e2e("FW-E2E-024")
def test_exec_allowlist_starts_dynamic_binaries_on_linux(cli, tmp_path):
    """An exec allow-list on Linux runs the dynamically linked binaries it lists -- the confiner
    grants the loader they name -- for a listed file over the agent base and for rules-demo's
    listed directory, and an unlisted program fails naming the grant it lacks."""
    if json.loads(cli("explain", "--json").stdout)["host"].get("landlock-abi") is None:
        pytest.skip("no Landlock on this kernel (the allow-list is not enforced)")
    base = BLUEPRINTS / "agent-base.toml"
    listed = cli("run", "--blueprint", base, "--rule", "exec:/bin/true", "--", "/bin/true", cwd=tmp_path)
    assert listed.code == 0, listed.stderr
    demo = cli("run", "--blueprint", BLUEPRINTS / "rules-demo.toml", "--", "/bin/true", cwd=tmp_path)
    assert demo.code == 0, demo.stderr

    unlisted = cli("run", "--blueprint", base, "--rule", "exec:/bin/true", "--", "/bin/ls", cwd=tmp_path)
    assert unlisted.code != 0, "an unlisted program must not run"
    assert "/bin/ls is not on the exec allow-list" in unlisted.stderr, unlisted.stderr

    report = json.loads(cli("compile", "--blueprint", base, "--rule", "exec:/bin/true", "--report-only").stdout)
    assert report["per-capability"]["exec"]["status"] == "partial"
    assert "loader" in report["per-capability"]["exec"]["reason"]


@pytest.mark.macos
@pytest.mark.fw_e2e("FW-E2E-024")
def test_agent_port_fallback_enforced_on_macos(cli):
    """On macOS the port-tier fallback the examples document (the shared agent base plus
    `--net ports:443`) is genuinely kernel-enforced, so the 'confine the agent, then skip the
    prompts' claim is backed, not aspirational, even where host rules are not used."""
    result = cli(
        "compile", "--blueprint", BLUEPRINTS / "agent-base.toml",
        "--net", "ports:443", "--allow-cred", "claude", "--report-only",
    )
    assert result.code == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["per-capability"]["net-port-tier"]["status"] == "enforced"
    assert report["per-capability"]["fs-write"]["status"] == "enforced"
