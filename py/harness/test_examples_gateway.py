"""`formwork gateway` shading E2E, driven as an MCP host would: launch it as a stdio server in front
of the built-in fixture backend, using the shipped example blueprint (examples/blueprints/mcp-gateway.toml).

macOS-only: the gateway confines the spawned backend (FW-GW5), which needs the Seatbelt backend here.
Driven interactively (Popen, not a one-shot pipe) because the gateway tears the connection down the
moment either side hangs up — a real host keeps stdin open for the whole session, so the test does too.
"""

import json
import subprocess
import threading

import pytest

from helpers import REPO_ROOT

pytestmark = pytest.mark.macos

EXAMPLE_BLUEPRINT = REPO_ROOT / "examples" / "blueprints" / "mcp-gateway.toml"


@pytest.fixture(scope="session")
def fixture_bin():
    subprocess.run(
        ["cargo", "build", "-q", "-p", "formwork-gateway", "--bin", "fw-mcp-fixture"],
        cwd=REPO_ROOT,
        check=True,
    )
    binary = REPO_ROOT / "target" / "debug" / "fw-mcp-fixture"
    assert binary.exists(), f"fixture backend not found at {binary}"
    return binary


def _req(msg_id, method, params):
    return {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params}


def _drive(formwork_bin, backend, requests, expect, timeout=20,
           blueprint=EXAMPLE_BLUEPRINT, server="files"):
    """Send `requests` to a `formwork gateway` fronting `backend`; collect `expect` id-bearing
    replies keyed by id. Keeps stdin open until the replies are in, so backend round-trips finish
    before the connection closes."""
    proc = subprocess.Popen(
        [str(formwork_bin), "gateway", "--blueprint", str(blueprint),
         "--server", server, "--", str(backend)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    responses = {}

    def reader():
        while len(responses) < expect:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line:
                msg = json.loads(line)
                if "id" in msg:
                    responses[msg["id"]] = msg

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    for req in requests:
        proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()
    thread.join(timeout)

    proc.stdin.close()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    return responses, proc.stderr.read()


@pytest.mark.fw_e2e("FW-E2E-013")
def test_example_gateway_hides_ungranted_tools(formwork_bin, fixture_bin):
    responses, stderr = _drive(formwork_bin, fixture_bin, [_req(1, "tools/list", {})], expect=1)
    assert 1 in responses, f"no tools/list reply; stderr={stderr!r}"
    names = [t["name"] for t in responses[1]["result"]["tools"]]
    assert names == ["read_file"], f"only the granted tool should be visible, got {names}"


@pytest.mark.fw_e2e("FW-ADV-004")
def test_example_gateway_refuses_ungranted_call_without_oracle(formwork_bin, fixture_bin):
    responses, stderr = _drive(
        formwork_bin,
        fixture_bin,
        [
            _req(1, "tools/call", {"name": "http_fetch", "arguments": {}}),
            _req(2, "tools/call", {"name": "does_not_exist", "arguments": {}}),
        ],
        expect=2,
    )
    assert 1 in responses and 2 in responses, f"missing replies {responses}; stderr={stderr!r}"
    hidden_real, nonexistent = responses[1], responses[2]
    assert "error" in hidden_real, "a hidden-but-real tool must be refused, not executed"
    # A hidden tool and a nonexistent one refuse the same way, so nothing reveals the hidden one exists.
    assert hidden_real["error"]["code"] == nonexistent["error"]["code"]
    assert "denied" not in hidden_real["error"]["message"].lower()


@pytest.mark.fw_e2e("FW-E2E-018")
def test_example_gateway_passes_granted_call_through(formwork_bin, fixture_bin):
    responses, stderr = _drive(
        formwork_bin,
        fixture_bin,
        [_req(1, "tools/call", {"name": "read_file", "arguments": {"path": "/x"}})],
        expect=1,
    )
    assert 1 in responses, f"no read_file reply; stderr={stderr!r}"
    assert responses[1]["result"]["content"][0]["text"] == "ok:read_file"
    assert responses[1]["result"]["isError"] is False


PATTERN_BLUEPRINT = """\
net = "deny"
[fs]
read-mode = "ambient-minus-subtract"
reads = ["/**"]
writes = []
[mcp.patterns]
tools = { allow = ["/.*_file/", "list_dir"], deny = ["/delete_.*/"] }
resources = "deny"
prompts = "deny"
"""


@pytest.mark.fw_e2e("FW-E2E-066")
def test_example_gateway_shades_by_pattern(formwork_bin, fixture_bin, tmp_path):
    """The real `formwork gateway` binary shades by a regex allow/deny policy (FW-GW9): allow
    `/.*_file/` + `list_dir`, deny `/delete_.*/`. delete_file matches both, so the deny wins."""
    bp = tmp_path / "patterns.toml"
    bp.write_text(PATTERN_BLUEPRINT)
    responses, stderr = _drive(
        formwork_bin,
        fixture_bin,
        [
            _req(1, "tools/list", {}),
            _req(2, "tools/call", {"name": "delete_file", "arguments": {}}),
            _req(3, "tools/call", {"name": "read_file", "arguments": {}}),
        ],
        expect=3,
        blueprint=bp,
        server="patterns",
    )
    assert {1, 2, 3} <= responses.keys(), f"missing replies {responses}; stderr={stderr!r}"

    visible = sorted(t["name"] for t in responses[1]["result"]["tools"])
    assert visible == ["list_dir", "read_file", "write_file"], visible

    assert "error" in responses[2], "delete_file matches the deny pattern; deny is terminal"
    assert responses[3]["result"]["content"][0]["text"] == "ok:read_file"
