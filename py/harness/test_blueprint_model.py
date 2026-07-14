"""Blueprint model and format E2E (FEP-2 §9.1): layering, extends, CLI/file parity, rename
regression -- all black-box through the `formwork` CLI. Compile-level tests pin the host with
--target so byte-comparisons are meaningful on any machine."""

from pathlib import Path

import pytest

from helpers import write_blueprint

RICH_BLUEPRINT = """\
net = { ports = [443] }
exec = "unrestricted"
env = { scrub = { allow = ["ANTHROPIC_API_KEY"] } }

[fs]
read-mode = "closed"
reads = ["/work/**"]
writes = ["/work/project/**"]
subtract = ["/work/.ssh/**"]
write-subtract = ["**/.git/config"]

[mcp.files]
tools = { allow = ["read_file"] }
resources = "allow-all"
"""


@pytest.mark.fw_e2e("FW-E2E-041")
def test_rename_regression_spec_alias_and_stability(cli, tmp_path):
    """The renamed surface (--blueprint) and the back-compat --spec alias compile a pre-FEP-2
    single-file blueprint to byte-identical output, deterministically (FW-FID4)."""
    bp = tmp_path / "session.toml"
    bp.write_text(RICH_BLUEPRINT)

    via_blueprint = cli("compile", "--blueprint", bp, "--target", "macos")
    via_spec = cli("compile", "--spec", bp, "--target", "macos")
    assert via_blueprint.code == 0, via_blueprint.stderr
    assert via_spec.code == 0, via_spec.stderr
    assert via_blueprint.stdout == via_spec.stdout, "rename must not change compilation"

    again = cli("compile", "--blueprint", bp, "--target", "macos")
    assert again.stdout == via_blueprint.stdout, "compile must be byte-deterministic"


@pytest.mark.fw_e2e("FW-E2E-042")
@pytest.mark.macos
def test_override_precedence_cli_subtract_beats_file_allow(cli, workspace, tmp_path):
    """A path allowed by the file is denied when a CLI --subtract layers over it; a deny and an
    allow at equal precedence (same file) resolve to deny."""
    blueprint = write_blueprint(
        tmp_path / "blueprint.toml",
        reads=[f"{workspace.root}/**"],
        writes=[f"{workspace.granted}/**"],
    )
    # Baseline: the file grants the read.
    ok = cli("run", "--blueprint", blueprint, "--", "/bin/cat", workspace.secret_file,
             cwd=workspace.granted)
    assert ok.code == 0, ok.stderr

    # CLI --subtract is a higher layer: deny lands even though the file allows.
    denied = cli("run", "--blueprint", blueprint, "--subtract", f"{workspace.secret}/**",
                 "--", "/bin/cat", workspace.secret_file, cwd=workspace.granted)
    assert denied.code != 0, "CLI --subtract must deny a file-allowed path"

    # Equal precedence: the same file both allows and subtracts -> deny wins.
    tied = write_blueprint(
        tmp_path / "tied.toml",
        reads=[f"{workspace.root}/**"],
        writes=[f"{workspace.granted}/**"],
        subtract=[f"{workspace.secret}/**"],
    )
    tied_run = cli("run", "--blueprint", tied, "--", "/bin/cat", workspace.secret_file,
                   cwd=workspace.granted)
    assert tied_run.code != 0, "deny must beat allow at equal precedence"


@pytest.mark.fw_e2e("FW-E2E-043")
def test_cli_file_parity_byte_identical_policy(cli, tmp_path):
    """The same grants authored in the file, via --set fragments, and via sugar flags compile to
    byte-identical policy (FW-BP1: one model, many surfaces)."""
    authored = tmp_path / "authored.toml"
    authored.write_text(
        """\
net = { ports = [443] }

[fs]
reads = ["/work/**"]
writes = ["/work/project/**"]
subtract = ["/work/.ssh/**"]
"""
    )
    empty = tmp_path / "empty.toml"
    empty.write_text("")

    from_file = cli("compile", "--blueprint", authored, "--target", "macos")
    assert from_file.code == 0, from_file.stderr

    from_set = cli(
        "compile", "--blueprint", empty, "--target", "macos",
        "--set", 'net = { ports = [443] }',
        "--set", '[fs]\nreads = ["/work/**"]\nwrites = ["/work/project/**"]\nsubtract = ["/work/.ssh/**"]',
    )
    assert from_set.code == 0, from_set.stderr
    assert from_set.stdout == from_file.stdout, "--set surface diverged from the file surface"

    from_sugar = cli(
        "compile", "--blueprint", empty, "--target", "macos",
        "--net", "ports:443",
        "--read", "/work/**",
        "--write", "/work/project/**",
        "--subtract", "/work/.ssh/**",
    )
    assert from_sugar.code == 0, from_sugar.stderr
    assert from_sugar.stdout == from_file.stdout, "sugar flags diverged from the file surface"


@pytest.mark.fw_e2e("FW-E2E-044")
def test_extends_composition_deterministic_and_cycles_error(cli, tmp_path):
    """A Blueprint extending bases merges deterministically (diamond included); an extends cycle
    fails loud, naming the cycle."""
    (tmp_path / "d.toml").write_text('[fs]\nsubtract = ["/etc/shadow"]\n')
    (tmp_path / "b.toml").write_text('extends = ["d.toml"]\nnet = { ports = [443] }\n')
    (tmp_path / "c.toml").write_text('extends = ["d.toml"]\n[fs]\nreads = ["/data/**"]\n')
    (tmp_path / "child.toml").write_text(
        'extends = ["b.toml", "c.toml"]\nnet = "deny"\n[fs]\nwrites = ["/work/project/**"]\n'
    )

    first = cli("compile", "--blueprint", tmp_path / "child.toml", "--target", "macos")
    second = cli("compile", "--blueprint", tmp_path / "child.toml", "--target", "macos")
    assert first.code == 0, first.stderr
    assert first.stdout == second.stdout, "extends merge must be deterministic"
    # The child's own posture wins over its bases: b.toml's port tier must not survive net="deny".
    assert "443" not in first.stdout, "base's port tier leaked past the child's net=deny"
    # The diamond base's subtract survives the merge.
    assert "/etc/shadow" in first.stdout

    (tmp_path / "x.toml").write_text('extends = ["y.toml"]\n')
    (tmp_path / "y.toml").write_text('extends = ["x.toml"]\n')
    cycle = cli("compile", "--blueprint", tmp_path / "x.toml", "--target", "macos")
    assert cycle.code != 0, "an extends cycle must be an error"
    assert "cycle" in cycle.stderr.lower()
    assert "x.toml" in cycle.stderr and "y.toml" in cycle.stderr


@pytest.mark.fw_e2e("FW-E2E-055")
@pytest.mark.macos
def test_cwd_sigil_scopes_a_grant_to_the_launch_directory(cli, tmp_path):
    """`$CWD` is a CLI-edge sigil (like `~`): it expands to the launch directory before patterns
    reach the compiler, so a grant written `$CWD/**` scopes to the project you run from. Enforced
    by the real kernel -- a file under the launch dir is readable, a sibling outside it is not --
    and the broad-cwd guardrail warns (not refuses) when `$CWD` is the filesystem root."""
    root = tmp_path.resolve()
    home = root / "home"
    home.mkdir()
    proj = root / "proj"
    proj.mkdir()
    (proj / "in.txt").write_text("in-scope\n")
    outside = root / "outside.txt"
    outside.write_text("out-of-scope\n")
    bp = root / "bp.toml"
    bp.write_text('net = "deny"\n[fs]\nread-mode = "closed"\nreads = ["$CWD/**"]\n')
    env = {"HOME": str(home)}

    # In-scope: a file under the launch directory is granted via $CWD/**, and a real project
    # directory trips no guardrail.
    inside = cli("run", "--blueprint", bp, "--", "/bin/cat", "in.txt", cwd=proj, env=env)
    assert inside.code == 0, inside.stderr
    assert "in-scope" in inside.stdout
    assert "$CWD resolves to" not in inside.stderr

    # Out-of-scope: a sibling outside the launch directory is not granted by $CWD/**.
    out = cli("run", "--blueprint", bp, "--", "/bin/cat", str(outside), cwd=proj, env=env)
    assert out.code != 0, "a path outside $CWD must not be granted by $CWD/**"

    # Guardrail: from '/', $CWD/** would cover the whole filesystem -- a warning, not a refusal.
    from_root = cli("run", "--blueprint", bp, "--", "/bin/echo", "ok", cwd=Path("/"), env=env)
    assert "$CWD resolves to" in from_root.stderr


@pytest.mark.macos
def test_cwd_outside_read_scope_warns_not_silently_widens(cli, tmp_path):
    """FW-CAP1: grants are authored, never inferred -- the launch directory is not folded into the
    read grant. Rather than silently widen (or silently break), formwork warns loudly when cwd is
    unreadable under the policy, so a workload whose interpreter scans its cwd gets a diagnosis
    instead of a mystery EACCES. The complement of FW-E2E-055's broad-cwd guardrail."""
    root = tmp_path.resolve()
    proj = root / "proj"
    proj.mkdir()
    env = {"HOME": str(root)}

    # cwd carved out of an otherwise-broad grant: the warning must fire, and a workload that does
    # NOT touch cwd (echo) still runs -- the warning is a nudge, not a refusal.
    carved = root / "carved.toml"
    carved.write_text(
        f'net = "deny"\n[fs]\nread-mode = "ambient-minus-subtract"\n'
        f'reads = ["/**"]\nsubtract = ["{proj}/**"]\n'
    )
    warned = cli("run", "--blueprint", carved, "--", "/bin/echo", "ok", cwd=proj, env=env)
    assert "launch directory is not readable" in warned.stderr, warned.stderr
    assert "ok" in warned.stdout

    # Control: when cwd is readable, no such warning appears.
    open_bp = root / "open.toml"
    open_bp.write_text('net = "deny"\n[fs]\nread-mode = "ambient-minus-subtract"\nreads = ["/**"]\n')
    quiet = cli("run", "--blueprint", open_bp, "--", "/bin/echo", "ok", cwd=proj, env=env)
    assert "launch directory is not readable" not in quiet.stderr, quiet.stderr
