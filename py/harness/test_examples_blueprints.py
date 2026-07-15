"""The shipped example blueprints (examples/blueprints/) compile and report honestly, driven through the
`formwork` CLI. Cross-platform: compilation is pure, so no platform marker."""

import json

import pytest

from helpers import REPO_ROOT

BLUEPRINTS = REPO_ROOT / "examples" / "blueprints"


@pytest.mark.fw_e2e("FW-E2E-026")
def test_agent_session_blueprint_compiles_and_accounts_for_net(cli):
    """The Axis-A confinement blueprint compiles, and its HTTPS-only egress is a real, accounted-for
    posture — never silently open (FW-INV6)."""
    result = cli("compile", "--blueprint", BLUEPRINTS / "agent-session.toml", "--report-only")
    assert result.code == 0, result.stderr
    report = json.loads(result.stdout)
    caps = report["per-capability"]
    assert "fs-read" in caps and "fs-write" in caps
    # net = { ports = [443] } -> both the default-deny floor and the port tier are accounted for.
    assert "net-default-deny" in caps
    assert "net-port-tier" in caps
    assert caps["net-default-deny"]["status"] in ("enforced", "partial", "unenforceable")


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
def test_rules_demo_verb_surface_compiles(cli):
    """The verb-surface example (flat `rules` + `mode`, FEP-3) is a well-formed blueprint that
    compiles like any other -- verbs are a surface onto the one model (FW-BP1)."""
    result = cli("compile", "--blueprint", BLUEPRINTS / "rules-demo.toml", "--target", "macos", "--report-only")
    assert result.code == 0, result.stderr
    caps = json.loads(result.stdout)["per-capability"]
    assert caps["fs-read"]["status"] == "enforced"
    assert caps["exec"]["status"] == "enforced"  # readexec:/bin/** governs exec
    assert caps["net-default-deny"]["status"] == "enforced"


@pytest.mark.macos
@pytest.mark.fw_e2e("FW-E2E-024")
def test_agent_session_net_port_tier_enforced_on_macos(cli):
    """On macOS the HTTPS egress tier is genuinely kernel-enforced, so the flagship 'confine the
    agent, then skip the prompts' claim is backed, not aspirational."""
    result = cli("compile", "--blueprint", BLUEPRINTS / "agent-session.toml", "--report-only")
    report = json.loads(result.stdout)
    assert report["per-capability"]["net-port-tier"]["status"] == "enforced"
    assert report["per-capability"]["fs-write"]["status"] == "enforced"
