"""The shipped profiles (profiles/*.toml) compile and enforce as advertised, driven through the
`formwork` CLI. The default profile is subtractive (ambient-minus-subtract); strict is its
closed-read counterpart (FW-CAP3). Compile checks are cross-platform (the compiler is pure);
the closed-read enforcement check needs the real Seatbelt backend, so it is macOS-marked."""

import json

import pytest

from helpers import REPO_ROOT

PROFILES = REPO_ROOT / "profiles"


@pytest.mark.parametrize("profile", ["default.toml", "strict.toml"])
def test_shipped_profile_compiles_and_accounts_for_net(cli, profile):
    """Every shipped profile compiles on every target and never leaves egress silently open
    (FW-INV6): the default-deny floor is always an accounted-for capability."""
    for target in ("macos", "linux-v6", "linux-v1"):
        result = cli("compile", "--blueprint", PROFILES / profile, "--target", target, "--report-only")
        assert result.code == 0, f"{profile} on {target}: {result.stderr}"
        caps = json.loads(result.stdout)["per-capability"]
        assert "fs-read" in caps and "fs-write" in caps
        assert caps["net-default-deny"]["status"] in ("enforced", "partial", "unenforceable")


@pytest.mark.macos
def test_strict_profile_closes_reads_outside_the_grants(cli, tmp_path):
    """strict.toml is closed-read (FW-CAP3): only the explicit grants (OS runtime + the `$CWD`
    project) are readable. A file under the launch directory reads; a file outside every grant --
    here in $HOME, which strict does not grant -- is denied. This is the shipped preset that
    exercises `read-mode = "closed"` end to end, the gap the profile set previously had."""
    root = tmp_path.resolve()
    home = root / "home"
    home.mkdir()
    proj = root / "proj"
    proj.mkdir()
    (proj / "in.txt").write_text("in-scope\n")
    (home / "secret.txt").write_text("out-of-scope\n")
    strict = PROFILES / "strict.toml"
    env = {"HOME": str(home)}

    # In-scope: a project file under $CWD is readable, and /bin/cat itself loads (OS runtime granted).
    ok = cli("run", "--blueprint", strict, "--", "/bin/cat", "in.txt", cwd=proj, env=env)
    assert ok.code == 0, ok.stderr
    assert "in-scope" in ok.stdout

    # Out-of-scope: a $HOME file is under no grant, so closed reads deny it.
    denied = cli("run", "--blueprint", strict, "--", "/bin/cat", str(home / "secret.txt"),
                 cwd=proj, env=env)
    assert denied.code != 0, "closed reads must deny a path outside every explicit grant"
    assert "out-of-scope" not in denied.stdout
