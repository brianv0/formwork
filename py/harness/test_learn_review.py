"""Learn review-loop E2E (FW-E2E-062/063) -- cross-platform, dry-run: the proposal file is the
input, so no kernel mechanism is needed and these run on every host, unlike the macOS-only
observation tests in test_discovery.py. The proposal here is fabricated the way FW-DISC3 assumes
an attacker could fabricate one -- it is untrusted input, which is exactly why accept re-checks
the floor (FW-INV8)."""

import json
import shutil
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


@pytest.mark.fw_e2e("FW-E2E-211")
def test_list_and_accept_name_the_layer_and_each_entry(review):
    # The listing says where an accept will write before anything is accepted...
    listed = review("--list")
    assert listed.code == 0, listed.stderr
    assert str(review.discovered) in listed.stdout.splitlines()[0], listed.stdout

    # ...and the accept prints each entry it wrote, not a count alone (FW-DISC19).
    accepted = review("--accept", "2", "--accept", "/opt/toolchain/**")
    assert accepted.code == 0, accepted.stderr
    lines = accepted.stdout.splitlines()
    assert any(l.startswith("accepted /opt/toolchain/** (read") for l in lines), accepted.stdout
    assert any(l.startswith("accepted /srv/data/out.log (write") for l in lines), accepted.stdout
    assert not any("/srv/app/credentials" in l for l in lines), accepted.stdout
    assert str(review.discovered) in lines[-1], accepted.stdout


@pytest.mark.fw_e2e("FW-E2E-211")
def test_a_selector_that_matches_nothing_refuses_the_whole_accept(review):
    """Public issue #54: beside a valid selector, one that names no entry used to be dropped
    and the accept exited 0 -- `--accept 2 --accept 12` read as two grants accepted."""
    before = review.proposal.read_text()
    for stray in ("99", "0", "/opt/toolchain", "allow:nowhere.test"):
        refused = review("--accept", "1", "--accept", stray)
        assert refused.code != 0, f"{stray}: {refused.stdout}"
        assert stray in refused.stderr, refused.stderr
        assert "accepted" not in refused.stdout, refused.stdout
        assert not review.discovered.exists(), "a refused accept must write nothing"
        assert review.proposal.read_text() == before, "a refused accept consumes nothing"
    # --accept-all does not excuse a selector either.
    assert review("--accept-all", "--accept", "99").code != 0
    assert not review.discovered.exists()


@pytest.mark.fw_e2e("FW-E2E-211")
def test_a_selector_naming_an_auto_accepted_entry_is_refused(review):
    """An auto-accepted entry is listed for audit and already in the discovered layer; naming
    it accepts nothing, so the selector is refused rather than passed over."""
    review.proposal.write_text(
        review.proposal.read_text().replace(
            'access = "write"\ntag = "needs-review"', 'access = "write"\ntag = "auto-accepted"'
        )
    )
    refused = review("--accept", "1", "--accept", "2")
    assert refused.code != 0, refused.stdout
    assert "2" in refused.stderr and "needs-review" in refused.stderr, refused.stderr
    assert not review.discovered.exists()


@pytest.mark.fw_e2e("FW-E2E-211")
def test_accept_refuses_a_proposal_learned_against_another_blueprint(tmp_path, cli):
    """Public issue #54: the destination used to be the path string inside the proposal. A
    proposal that names another project's blueprint -- a copied or moved project, or a file
    reviewed with --proposal -- wrote grants into a layer the invocation never resolved."""
    env = {"HOME": str(tmp_path)}
    projects = {}
    for name in ("here", "elsewhere"):
        root = tmp_path / name
        root.mkdir()
        (root / "bp.toml").write_text(BLUEPRINT)
        projects[name] = root
    here, elsewhere = projects["here"], projects["elsewhere"]
    stale = PROPOSAL.format(blueprint=elsewhere / "bp.toml")

    # A proposal beside this blueprint that names the other one (the copied-project shape).
    (here / "bp.toml.proposal.toml").write_text(stale)
    # The other project's own proposal, reviewed from here with --proposal.
    (elsewhere / "bp.toml.proposal.toml").write_text(stale)
    for extra in ([], ["--proposal", elsewhere / "bp.toml.proposal.toml"]):
        for review_flags in (["--list"], ["--accept", "1"], ["--accept-all"]):
            refused = cli(
                "learn", "--blueprint", "bp.toml", *extra, *review_flags, cwd=here, env=env
            )
            assert refused.code != 0, refused.stdout
            assert str(elsewhere / "bp.toml") in refused.stderr, refused.stderr
            assert str(here / "bp.toml") in refused.stderr, refused.stderr
    for root in (here, elsewhere):
        assert not (root / "bp.toml.discovered.toml").exists(), f"{root} was written to"
    assert (here / "bp.toml.proposal.toml").read_text() == stale


@pytest.mark.fw_e2e("FW-E2E-211")
def test_accept_writes_to_the_resolved_blueprint_when_the_proposal_sits_elsewhere(tmp_path, cli):
    """--proposal names where the proposal file is; the layer written is still the resolved
    blueprint's own."""
    blueprint = tmp_path / "bp.toml"
    blueprint.write_text(BLUEPRINT)
    moved = tmp_path / "review" / "pending.toml"
    moved.parent.mkdir()
    moved.write_text(PROPOSAL.format(blueprint=blueprint))
    accepted = cli(
        "learn", "--blueprint", "bp.toml", "--proposal", moved, "--accept", "1",
        cwd=tmp_path, env={"HOME": str(tmp_path)},
    )
    assert accepted.code == 0, accepted.stderr
    assert "/opt/toolchain/**" in (tmp_path / "bp.toml.discovered.toml").read_text()
    assert not (moved.parent / "bp.toml.discovered.toml").exists()


FORGED_KINDS = """\
blueprint = "{blueprint}"

[[candidates]]
pattern = "/srv/**/config"
access = "write"
tag = "needs-review"
run-id = "learn-1"

[[candidates]]
pattern = "**/notes.txt"
access = "read"
tag = "needs-review"
run-id = "learn-1"

[[hosts]]
rule = "tunnel:git.corp.example"
run-id = "learn-1"

[[hosts]]
rule = "deny:wiki.corp.example"
run-id = "learn-1"

[[hosts]]
rule = "allow:*.corp.example"
run-id = "learn-1"

[[hosts]]
rule = "allow:169.254.169.254"
run-id = "learn-1"

[[hosts]]
rule = "get:api.corp.example/v1/**"
run-id = "learn-1"

[[hosts]]
rule = "allow:blocked.test"
run-id = "learn-1"
"""


@pytest.mark.fw_e2e("FW-E2E-211")
def test_accept_refuses_entry_kinds_discovery_never_proposes(review):
    """The proposal is untrusted input (FW-DISC3). A learning run proposes a denied path or its
    directory's subtree, `allow:` on an exact public host, or one method on one literal path
    (FW-DISC12) -- never a tunnel grade, a deny, a wildcard, a restricted destination or a
    pattern. A proposal carrying one of those does not pass it through accept."""
    review.proposal.write_text(FORGED_KINDS.format(blueprint=review.blueprint))
    for number, why in (
        (1, "any-depth"),
        (2, "any-depth"),
        (3, "tunnel"),
        (4, "deny"),
        (5, "wildcard"),
        (6, "FW-EGR19"),
        (7, "glob"),
    ):
        refused = review("--accept", str(number))
        assert refused.code != 0, f"{number}: {refused.stdout}"
        assert "refusing to accept" in refused.stderr and why in refused.stderr, refused.stderr
        assert not review.discovered.exists(), "a refused accept must write nothing"
    assert review("--accept-all").code != 0
    assert not review.discovered.exists()

    # The one entry of a proposable kind still goes through.
    accepted = review("--accept", "8")
    assert accepted.code == 0, accepted.stderr
    assert "allow:blocked.test" in review.discovered.read_text()


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


@pytest.mark.fw_e2e("FW-E2E-063")
def test_accept_through_a_symlinked_blueprint_reaches_the_next_run(tmp_path, cli):
    """Both discovery artifacts derive from the CANONICAL blueprint path: accept reaches the
    blueprint through the proposal's recorded string, the loader through the CLI-given path.
    With a symlinked blueprint those used to diverge -- the accepted grant landed in a discovered
    layer no run ever loaded (a silent no-op of the whole review loop)."""
    policies = tmp_path / "policies"
    policies.mkdir()
    target = policies / "real.toml"
    target.write_text(BLUEPRINT)
    link = tmp_path / "bp.toml"
    link.symlink_to(target)
    env = {"HOME": str(tmp_path)}

    # The proposal sits beside the canonical blueprint, as a learning run would have written it.
    canonical = target.resolve()
    proposal = canonical.parent / (canonical.name + ".proposal.toml")
    proposal.write_text(PROPOSAL.format(blueprint=canonical))

    accepted = cli("learn", "--blueprint", link, "--accept", "1", cwd=tmp_path, env=env)
    assert accepted.code == 0, accepted.stderr

    explained = cli(
        "explain", "--blueprint", link, "--json", "/opt/toolchain/lib.py",
        cwd=tmp_path, env=env,
    )
    assert explained.code == 0, explained.stderr
    verdict = json.loads(explained.stdout)["explanations"][0]["read"]
    assert verdict["decision"] == "granted", explained.stdout
    assert verdict["source"]["origin"] == "discovered", explained.stdout


@pytest.mark.fw_e2e("FW-E2E-062")
@pytest.mark.skipif(sys.platform == "darwin", reason="macOS's feed needs no userspace tool")
def test_learn_without_a_denial_feed_fails_before_the_workload(review, tmp_path):
    # The Linux feed requires `strace` on PATH (FW-E2E-071), so an empty PATH makes the feed
    # reliably unavailable whatever the kernel carries; no Landlock is the other unavailable arm.
    marker = tmp_path / "ran"
    result = review("--", "/bin/touch", str(marker), extra_env={"PATH": ""})
    assert result.code != 0
    assert "denial feed" in result.stderr, result.stderr
    assert "--observe-anyway" in result.stderr, result.stderr
    assert not marker.exists(), "the workload must not have run"
    # And no proposal beyond the fabricated fixture: observation was refused, not pretended.
    assert "/bin/touch" not in review.proposal.read_text()


@pytest.mark.fw_e2e("FW-E2E-062")
@pytest.mark.skipif(sys.platform == "darwin", reason="macOS's feed needs no userspace tool")
def test_observe_anyway_runs_enforced_but_writes_no_proposal(cli, tmp_path):
    host = json.loads(cli("explain", "--json").stdout)["host"]
    if host.get("landlock-abi") is None:
        pytest.skip("host cannot enforce (no Landlock); the enforced-run half needs a real confiner")
    blueprint = tmp_path / "bp.toml"
    blueprint.write_text(
        'net = "deny"\n[fs]\nread-mode = "closed"\n'
        f'reads = ["/usr/**", "/bin/**", "/lib/**", "/lib64/**"]\n'
    )
    # PATH emptied so the feed is genuinely absent: with one available, --observe-anyway is
    # refused instead (it would silently change nothing -- FW-DISC11).
    result = cli(
        "learn", "--blueprint", blueprint, "--observe-anyway", "--", "/bin/true",
        cwd=tmp_path, env={"HOME": str(tmp_path), "PATH": ""},
    )
    assert result.code == 0, result.stderr
    assert "no denial feed" in result.stderr, result.stderr
    assert not (tmp_path / "bp.toml.proposal.toml").exists(), "no proposal may be pretended"


@pytest.mark.fw_e2e("FW-E2E-062")
def test_observe_anyway_is_refused_where_a_feed_exists(review, cli):
    """With a working feed, --observe-anyway would silently change nothing: refused, never
    silently dropped (FW-DISC11)."""
    if sys.platform != "darwin":
        if shutil.which("strace") is None:
            pytest.skip("no feed on this host (Linux without strace)")
        if json.loads(cli("explain", "--json").stdout)["host"].get("landlock-abi") is None:
            pytest.skip("no feed on this host (no Landlock, so nothing is enforced or denied)")
    result = review("--observe-anyway", "--", "/bin/true")
    assert result.code != 0
    assert "--observe-anyway" in result.stderr, result.stderr
    assert "this host has one" in result.stderr, result.stderr
