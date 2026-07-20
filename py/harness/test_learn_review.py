"""Learn review-loop E2E (FW-E2E-062/063) -- cross-platform, dry-run: the proposal file is the
input, so no kernel mechanism is needed and these run on every host, unlike the macOS-only
observation tests in test_discovery.py. The proposal here is fabricated the way FW-DISC3 assumes
an attacker could fabricate one -- it is untrusted input, which is exactly why accept re-checks
the floor (FW-INV8)."""

import json
import sys

import pytest


BLUEPRINT = 'net = "deny"\n[fs]\nread-mode = "closed"\n'

PROPOSAL = """\
blueprint = "{blueprint}"

[[candidates]]
pattern = "/opt/toolchain/**"
access = "read"
tag = "needs-review"
run-id = "learn-1"

[[candidates]]
pattern = "/srv/data/out.log"
access = "write"
tag = "needs-review"
run-id = "learn-2"

[[candidates]]
pattern = "/srv/app/credentials"
access = "read"
tag = "needs-review"
run-id = "learn-2"
"""


@pytest.fixture
def review(tmp_path, cli):
    blueprint = tmp_path / "bp.toml"
    blueprint.write_text(BLUEPRINT)
    proposal = tmp_path / "bp.toml.proposal.toml"
    proposal.write_text(PROPOSAL.format(blueprint=blueprint))
    def run(*args, extra_env=None):
        env = {"HOME": str(tmp_path), **(extra_env or {})}
        return cli("learn", "--blueprint", "bp.toml", *args, cwd=tmp_path, env=env)

    run.blueprint = blueprint
    run.proposal = proposal
    run.discovered = tmp_path / "bp.toml.discovered.toml"
    return run


@pytest.mark.fw_e2e("FW-E2E-063")
def test_listing_is_a_numbered_stdout_result(review):
    listed = review("--list")
    assert listed.code == 0, listed.stderr
    # The listing is the RESULT stream: stdout, intact even under quiet telemetry.
    quiet = review("--list", extra_env={"RUST_LOG": "warn"})
    assert quiet.code == 0, quiet.stderr
    for out in (listed.stdout, quiet.stdout):
        assert "1. /opt/toolchain/**" in out, out
        assert "2. /srv/data/out.log" in out, out
        assert "needs-review" in out, out


@pytest.mark.fw_e2e("FW-E2E-063")
def test_accept_by_number_and_pattern_moves_exactly_the_selection(review):
    accepted = review("--accept", "2", "--accept", "/opt/toolchain/**")
    assert accepted.code == 0, accepted.stderr
    assert "accepted 2 grants" in accepted.stdout, accepted.stdout

    # The discovered layer holds exactly the selection, each grant with provenance (FW-DISC6).
    discovered = review.discovered.read_text()
    assert "/opt/toolchain/**" in discovered
    assert "/srv/data/out.log" in discovered
    assert "added-via" in discovered and "discovery" in discovered
    assert "learn-1" in discovered and "learn-2" in discovered

    # The proposal is visibly consumed: only the unselected (floored) entry remains.
    remaining = review.proposal.read_text()
    assert "/opt/toolchain/**" not in remaining
    assert "/srv/data/out.log" not in remaining
    assert "/srv/app/credentials" in remaining


@pytest.mark.fw_e2e("FW-E2E-063")
def test_accept_refuses_a_credential_floor_match(review):
    # The backstop shape (`**/credentials`) floors the entry wherever it sits -- a forged
    # proposal cannot walk a credential into the discovered layer through accept (FW-INV8).
    refused = review("--accept", "/srv/app/credentials")
    assert refused.code != 0
    assert "credential floor" in refused.stderr, refused.stderr
    assert not review.discovered.exists(), "a refused accept must write nothing"

    # --accept-all skips nothing silently: it also trips over the floored entry.
    refused_all = review("--accept-all")
    assert refused_all.code != 0
    assert "credential floor" in refused_all.stderr, refused_all.stderr


@pytest.mark.fw_e2e("FW-E2E-063")
def test_accepted_grants_load_into_the_next_run(review, cli, tmp_path):
    assert review("--accept", "1").code == 0
    # The discovered layer stacks under the blueprint on the next invocation: the accepted read
    # is now granted, attributed to the discovered layer -- distinguishable from authored grants.
    explained = cli(
        "explain", "--blueprint", "bp.toml", "--json", "/opt/toolchain/lib.py",
        cwd=tmp_path, env={"HOME": str(tmp_path)},
    )
    assert explained.code == 0, explained.stderr
    verdict = json.loads(explained.stdout)["explanations"][0]["read"]
    assert verdict["decision"] == "granted"
    assert verdict["source"]["origin"] == "discovered"


@pytest.mark.fw_e2e("FW-E2E-062")
@pytest.mark.skipif(sys.platform == "darwin", reason="macOS has a wired denial feed")
def test_learn_without_a_denial_feed_fails_before_the_workload(review, tmp_path):
    marker = tmp_path / "ran"
    result = review("--", "/bin/touch", str(marker))
    assert result.code != 0
    assert "denial feed" in result.stderr, result.stderr
    assert "--observe-anyway" in result.stderr, result.stderr
    assert not marker.exists(), "the workload must not have run"
    # And no proposal beyond the fabricated fixture: observation was refused, not pretended.
    assert "/bin/touch" not in review.proposal.read_text()


@pytest.mark.fw_e2e("FW-E2E-062")
@pytest.mark.skipif(sys.platform == "darwin", reason="macOS has a wired denial feed")
def test_observe_anyway_runs_enforced_but_writes_no_proposal(cli, tmp_path):
    detect = cli("detect")
    if json.loads(detect.stdout).get("landlock-abi") is None:
        pytest.skip("host cannot enforce (no Landlock); the enforced-run half needs a real confiner")
    blueprint = tmp_path / "bp.toml"
    blueprint.write_text(
        'net = "deny"\n[fs]\nread-mode = "closed"\n'
        f'reads = ["/usr/**", "/bin/**", "/lib/**", "/lib64/**"]\n'
    )
    result = cli(
        "learn", "--blueprint", blueprint, "--observe-anyway", "--", "/bin/true",
        cwd=tmp_path, env={"HOME": str(tmp_path)},
    )
    assert result.code == 0, result.stderr
    assert "no denial feed" in result.stderr, result.stderr
    assert not (tmp_path / "bp.toml.proposal.toml").exists(), "no proposal may be pretended"
