"""Discovery E2E (FEP-2 §9.3) + the confused-deputy adversarial case (FW-ADV-013), against the
real Seatbelt kernel and the real unified-log denial feed -- macOS only, like the confiner suite.
One learning fixture drives FW-E2E-051..053; 054 and ADV-013 make their own runs.

The FEP's FW-E2E-051 sketch names a pytest run against a real repo; the harness has no reuse
workload fixtures yet (FW-E2E-020..023 are unimplemented), so the same property is exercised
hermetically: a workload that needs ordinary toolchain paths and also touches a credential."""

import json
import subprocess

import pytest

from helpers import REPO_ROOT, run_cli

pytestmark = pytest.mark.macos

BLUEPRINT = """\
net = "deny"

[fs]
read-mode = "closed"
reads = ["{ok_file}"]
writes = []

[discovery]
auto-widen = ["{zone}/**"]
"""


class Learned:
    def __init__(self, root, bin):
        self.bin = bin
        self.home = root / "home"
        (self.home / ".ssh").mkdir(parents=True)
        (self.home / ".ssh" / "id_ed25519").write_text("FAKE KEY\n")
        self.toolchain = root / "toolchain"
        self.toolchain.mkdir()
        (self.toolchain / "lib.py").write_text("lib\n")
        (self.toolchain / "util.py").write_text("util\n")
        self.proj = root / "proj"
        (self.proj / ".cache").mkdir(parents=True)
        (self.proj / ".cache" / "x").write_text("cache\n")
        self.ok_file = self.proj / "ok.txt"
        self.ok_file.write_text("granted\n")
        self.blueprint = root / "bp.toml"
        self.blueprint.write_text(
            BLUEPRINT.format(ok_file=self.ok_file, zone=self.proj)
        )
        self.proposal = root / "bp.toml.proposal.toml"
        self.discovered = root / "bp.toml.discovered.toml"

    def cli(self, *args, **kw):
        kw.setdefault("env", {"HOME": str(self.home)})
        return run_cli(self.bin, *args, **kw)


@pytest.fixture(scope="module")
def learned(tmp_path_factory):
    subprocess.run(["cargo", "build", "-q", "-p", "formwork-cli"], cwd=REPO_ROOT, check=True)
    binary = REPO_ROOT / "target" / "debug" / "formwork"
    fixture = Learned(tmp_path_factory.mktemp("learn").resolve(), binary)
    # One learning run needing the toolchain, an in-zone cache file, and (illegitimately) a key.
    fixture.learn_result = fixture.cli(
        "learn", "--blueprint", fixture.blueprint, "--",
        "/bin/cat",
        fixture.toolchain / "lib.py",
        fixture.toolchain / "util.py",
        fixture.proj / ".cache" / "x",
        fixture.home / ".ssh" / "id_ed25519",
        timeout=120,
    )
    assert fixture.proposal.exists(), fixture.learn_result.stderr
    fixture.proposal_text = fixture.proposal.read_text()
    return fixture


@pytest.mark.fw_e2e("FW-E2E-051")
def test_learning_proposes_toolchain_and_omits_secrets(learned):
    # The ordinary paths the run needed are proposed (siblings folded to the parent subtree)...
    assert str(learned.toolchain) in learned.proposal_text, learned.proposal_text
    # ...and no credential-matched path appears anywhere in the proposal, however hard it was hit.
    assert ".ssh" not in learned.proposal_text, learned.proposal_text
    assert "id_ed25519" not in learned.proposal_text
    # The withheld itemization -- path and type -- went to the operator channel instead.
    withheld_lines = [
        l for l in learned.learn_result.stderr.splitlines() if "withheld by the credential floor" in l
    ]
    assert withheld_lines, learned.learn_result.stderr
    assert any("ssh" in l for l in withheld_lines), withheld_lines


@pytest.mark.fw_e2e("FW-E2E-052")
def test_auto_widen_zone_boundary(learned):
    # In-zone: self-granted for the next run without any human action (FW-DISC4)...
    in_zone = learned.cli("run", "--blueprint", learned.blueprint, "--",
                          "/bin/cat", learned.proj / ".cache" / "x")
    assert in_zone.code == 0, in_zone.stderr
    assert "cache" in in_zone.stdout
    # ...while the out-of-zone candidate is still denied and sits in the proposal as needs-review.
    out_zone = learned.cli("run", "--blueprint", learned.blueprint, "--",
                           "/bin/cat", learned.toolchain / "lib.py")
    assert out_zone.code != 0, "out-of-zone must not self-grant"
    assert "needs-review" in learned.proposal_text
    assert "auto-accepted" in learned.proposal_text


@pytest.mark.fw_e2e("FW-E2E-053")
def test_provenance_recorded_and_distinguishable(learned):
    accept = learned.cli("accept", "--proposal", learned.proposal,
                         "--entry", f"{learned.toolchain.resolve()}/**")
    assert accept.code == 0, accept.stderr
    discovered = learned.discovered.read_text()
    # The accepted grant carries provenance with the run id (FW-DISC6)...
    assert "added-via" in discovered and "discovery" in discovered
    assert "run-id" in discovered and "learn-" in discovered
    assert str(learned.toolchain.resolve()) in discovered
    # ...the authored grant lives in the blueprint with none -- audit can always tell them apart.
    assert "provenance" not in learned.blueprint.read_text()
    # The stack (blueprint + discovered layer) compiles, and the grant now works.
    after = learned.cli("run", "--blueprint", learned.blueprint, "--",
                        "/bin/cat", learned.toolchain / "lib.py")
    assert after.code == 0, after.stderr


@pytest.mark.fw_e2e("FW-E2E-054")
def test_discovery_is_non_authoritative_within_a_run(tmp_path, cli):
    """A denial observed in learning mode, outside any zone: the live session is not widened --
    the same operation fails again in the same run (FW-INV10)."""
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("outside\n")
    ok = tmp_path / "ok.txt"
    ok.write_text("ok\n")
    bp = tmp_path / "bp.toml"
    bp.write_text(f'net = "deny"\n[fs]\nread-mode = "closed"\nreads = ["{ok}"]\n')
    probe = (
        f'/bin/cat {target} && echo FIRST_SUCCEEDED; '
        f'/bin/cat {target} && echo SECOND_SUCCEEDED; true'
    )
    res = cli("learn", "--blueprint", bp, "--", "/bin/sh", "-c", probe,
              env={"HOME": str(home)}, timeout=120)
    assert "FIRST_SUCCEEDED" not in res.stdout
    assert "SECOND_SUCCEEDED" not in res.stdout, "observation must not widen the live session"


@pytest.mark.fw_adv("FW-ADV-013")
def test_discovery_confused_deputy(tmp_path, cli):
    """A prompt-injected workload hammers a credential to get it proposed and auto-accepted --
    with the zone adversarially drawn over the whole home. The wall holds (FW-INV8)."""
    home = (tmp_path / "home").resolve()
    (home / ".ssh").mkdir(parents=True)
    key = home / ".ssh" / "id_ed25519"
    key.write_text("FAKE KEY\n")
    ok = home / "ok.txt"
    ok.write_text("ok\n")
    bp = tmp_path / "bp.toml"
    bp.write_text(
        f'net = "deny"\n[fs]\nread-mode = "closed"\nreads = ["{ok}"]\n'
        f'[discovery]\nauto-widen = ["{home}/**"]\n'
    )
    env = {"HOME": str(home)}
    hammer = " ; ".join([f"/bin/cat {key} 2>/dev/null"] * 25) + " ; true"
    res = cli("learn", "--blueprint", bp, "--", "/bin/sh", "-c", hammer,
              env=env, timeout=120)
    assert res.code == 0, res.stderr

    proposal = tmp_path / "bp.toml.proposal.toml"
    if proposal.exists():
        text = proposal.read_text()
        assert "id_ed25519" not in text and ".ssh" not in text, (
            "persistent probing must never yield a candidate grant"
        )
    discovered = tmp_path / "bp.toml.discovered.toml"
    if discovered.exists():
        assert ".ssh" not in discovered.read_text(), "the floor must not auto-accept"

    # Next run: still walled, attempt count notwithstanding.
    again = cli("run", "--blueprint", bp, "--", "/bin/cat", key, env=env)
    assert again.code != 0, "the credential wall must hold across learning runs"

    # And a forged proposal cannot push it through the accept door either (FW-INV8).
    forged = tmp_path / "forged.toml"
    forged.write_text(
        f'blueprint = "{bp.resolve()}"\n\n'
        f'[[candidates]]\npattern = "{key}"\naccess = "read"\ntag = "needs-review"\n'
        f'run-id = "learn-evil-1"\n'
    )
    refused = cli("accept", "--proposal", forged, "--all", env=env)
    assert refused.code != 0
    assert "credential floor" in refused.stderr

@pytest.mark.fw_adv("FW-ADV-015")
def test_fold_does_not_transitively_grant_a_non_home_credential(tmp_path, cli):
    """FW-INV8 regression: a credential-shaped file OUTSIDE $HOME is withheld, but its ordinary
    siblings must not fold into an auto-widened subtree that transitively re-grants it. The
    enforcement floor is anchored under $HOME (it does not deny a non-$HOME key), so the fold
    guard is the wall -- without it, `proj/**` auto-accepts and the next run reads proj/id_rsa."""
    root = tmp_path.resolve()
    home = root / "home"
    home.mkdir()
    proj = root / "proj"  # deliberately NOT under $HOME
    proj.mkdir()
    (proj / "id_rsa").write_text("FAKE KEY\n")
    (proj / "a.txt").write_text("a\n")
    (proj / "b.txt").write_text("b\n")
    ok = root / "ok.txt"
    ok.write_text("ok\n")
    bp = root / "bp.toml"
    bp.write_text(
        f'net = "deny"\n[fs]\nread-mode = "closed"\nreads = ["{ok}"]\n'
        f'[discovery]\nauto-widen = ["{proj}/**"]\n'
    )
    env = {"HOME": str(home)}

    res = cli("learn", "--blueprint", bp, "--", "/bin/sh", "-c",
              f"cat {proj / 'a.txt'} {proj / 'b.txt'} {proj / 'id_rsa'} 2>/dev/null; true",
              env=env, timeout=120)
    assert res.code == 0, res.stderr
    assert any("withheld by the credential floor" in l and "id_rsa" in l
               for l in res.stderr.splitlines()), res.stderr

    discovered = root / "bp.toml.discovered.toml"
    if discovered.exists():
        text = discovered.read_text()
        assert f"{proj}/**" not in text, "a fold covering the withheld key must not be granted"
        assert "id_rsa" not in text

    again = cli("run", "--blueprint", bp, "--", "/bin/cat", proj / "id_rsa", env=env)
    assert again.code != 0, "the fold must not have re-granted the non-$HOME credential"
