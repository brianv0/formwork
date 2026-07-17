"""Blueprint model and format E2E (FEP-2 §9.1): layering, extends, CLI/file parity, rename
regression -- all black-box through the `formwork` CLI. Compile-level tests pin the host with
--target so byte-comparisons are meaningful on any machine."""

import json
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


# --- FEP-3: filesystem capability rules (compile-level; enforcement is macOS/Landlock-gated) ---


@pytest.mark.fw_e2e("FW-E2E-056")
def test_modify_verb_splits_create_from_modify(cli, tmp_path):
    """FW-CAP9: the `modify` verb grants modify/unlink/chmod on a path but never create."""
    bp = tmp_path / "s.toml"
    bp.write_text('net = "deny"\nmode = "unveil"\nrules = ["readonly:/usr/**", "modify:/data/logs"]\n')
    r = cli("compile", "--blueprint", bp, "--target", "macos")
    assert r.code == 0, r.stderr
    sbpl = json.loads(r.stdout)["confiner"]["sbpl"]
    assert '(allow file-write-data (literal "/data/logs"))' in sbpl
    assert '(allow file-write-unlink (literal "/data/logs"))' in sbpl
    # Create is never granted; no blanket file-write* that would re-admit it.
    assert 'file-write-create (literal "/data/logs")' not in sbpl
    assert '(allow file-write* (literal "/data/logs"))' not in sbpl


@pytest.mark.fw_e2e("FW-E2E-057")
def test_mode_posture_aliases_read_mode(cli, tmp_path):
    """FW-BP7: `mode` is a friendlier spelling of `[fs] read-mode`; both values compile identically."""
    for mode, read_mode in (("unveil", "closed"), ("subtractive", "ambient-minus-subtract")):
        flat = tmp_path / f"flat-{mode}.toml"
        flat.write_text(f'net = "deny"\nmode = "{mode}"\nrules = ["readonly:/usr/**"]\n')
        nested = tmp_path / f"nested-{mode}.toml"
        nested.write_text(f'net = "deny"\n[fs]\nread-mode = "{read_mode}"\nreads = ["/usr/**"]\n')
        a = cli("compile", "--blueprint", flat, "--target", "linux-v6")
        b = cli("compile", "--blueprint", nested, "--target", "linux-v6")
        assert a.code == 0 and b.code == 0, (a.stderr, b.stderr)
        assert a.stdout == b.stdout, f"mode {mode} must equal read-mode {read_mode}"


@pytest.mark.fw_e2e("FW-E2E-058")
def test_rules_are_order_independent_and_deny_terminal(cli, tmp_path):
    """FW-BP6/FW-CAP8: rule sets union order-independently and deny beats allow regardless of order."""
    base = tmp_path / "base.toml"
    base.write_text('net = "deny"\n')
    order1 = cli("compile", "--blueprint", base, "--target", "macos", "--mode", "subtractive",
                 "--rule", "readwrite:/work/**", "--rule", "deny:/work/secret")
    order2 = cli("compile", "--blueprint", base, "--target", "macos", "--mode", "subtractive",
                 "--rule", "deny:/work/secret", "--rule", "readwrite:/work/**")
    assert order1.code == 0 and order2.code == 0, (order1.stderr, order2.stderr)
    assert order1.stdout == order2.stdout, "rule order must not change the compiled policy"


@pytest.mark.fw_e2e("FW-E2E-061")
def test_flat_rules_equal_nested_fs(cli, tmp_path):
    """FW-BP1: flat verb rules and the nested [fs] table are one model (byte-identical)."""
    flat = tmp_path / "flat.toml"
    flat.write_text(
        'net = "deny"\nmode = "unveil"\n'
        'rules = ["readonly:/usr/**", "readwrite:/work/p/**", "deny:/work/p/secret"]\n'
    )
    nested = tmp_path / "nested.toml"
    nested.write_text(
        'net = "deny"\n[fs]\nread-mode = "closed"\n'
        'reads = ["/usr/**"]\nwrites = ["/work/p/**"]\nsubtract = ["/work/p/secret"]\n'
    )
    a = cli("compile", "--blueprint", flat, "--target", "linux-v6")
    b = cli("compile", "--blueprint", nested, "--target", "linux-v6")
    assert a.code == 0 and b.code == 0, (a.stderr, b.stderr)
    assert a.stdout == b.stdout, "flat rules must compile identically to the nested [fs] form"


@pytest.mark.fw_e2e("FW-E2E-057")
def test_mode_and_read_mode_compose_across_extends(cli, tmp_path):
    """FW-BP7 + FW-BP2: `mode` and `[fs] read-mode` are two spellings of one posture. Across
    layers they compose by last-wins (a child's `mode` overrides a base's `read-mode`, no error);
    only both-in-ONE-layer is the loud conflict. Guards that the conflict check does not break
    `extends`."""
    (tmp_path / "base.toml").write_text('net = "deny"\n[fs]\nread-mode = "ambient-minus-subtract"\nreads = ["/usr/**"]\n')
    child = tmp_path / "child.toml"
    child.write_text('extends = ["base.toml"]\nmode = "unveil"\nrules = ["readonly:/work/**"]\n')
    r = cli("compile", "--blueprint", child, "--target", "linux-v6")
    assert r.code == 0, r.stderr
    policy = json.loads(r.stdout)["confiner"]
    # The child's mode (unveil -> closed) wins over the base's ambient read-mode.
    assert policy["read-mode"] == "closed", "child `mode` must override base `read-mode` via last-wins"

    # But both in the SAME layer is a loud conflict, not a silent pick.
    same = tmp_path / "same.toml"
    same.write_text('net = "deny"\nmode = "unveil"\n[fs]\nread-mode = "closed"\n')
    bad = cli("compile", "--blueprint", same, "--target", "linux-v6")
    assert bad.code != 0 and "not both" in bad.stderr


@pytest.mark.fw_e2e("FW-E2E-060")
def test_cli_flags_compose_with_an_unveil_blueprint(cli, tmp_path):
    """FW-BP1/FW-BP2 + FW-BP7 + FW-ISO9: the CLI override surface composes with an `unveil`
    (empty-universe) blueprint the way an operator expects. Sugar flags populate the closed
    universe; `--rule exec:` closes exec to an allow-list on a separate axis; the `--mode unveil`
    flag flips a subtractive file to closed by last-wins; and the credential floor stays
    un-liftable underneath all of it. All dry-run via `explain`, so it runs on any host."""
    env = {"HOME": str(tmp_path)}

    def explain(bp, path, *flags):
        r = cli("explain", "--blueprint", bp, path, *flags, env=env)
        assert r.code == 0, r.stderr
        return json.loads(r.stdout)

    unveil = tmp_path / "unveil.toml"
    unveil.write_text('net = "deny"\nmode = "unveil"\n')

    # 1. Empty universe: an unlisted path is hidden; a CLI `--read` grant fills it in (origin cli).
    assert explain(unveil, "/opt/data/x")["read"]["decision"] == "hidden"
    granted = explain(unveil, "/opt/data/x", "--read", "/opt/data/**")
    assert granted["read"]["decision"] == "granted"
    assert granted["read"]["source"] == {"origin": "cli"}

    # 2. A CLI `--write` grant implies read under unveil (FW-TRA3: write implies read).
    w = explain(unveil, "/work/f", "--write", "/work/**")
    assert w["write"]["decision"] == "granted"
    assert w["read"]["decision"] == "granted"

    # 3. `--rule exec:` closes exec to an allow-list over unveil (FW-ISO9). Exec is a separate axis:
    #    the listed binary runs (origin cli) but stays unreadable; an unlisted one does not run.
    listed = explain(unveil, "/bin/ls", "--rule", "exec:/bin/ls")
    assert listed["exec"]["decision"] == "granted"
    assert listed["exec"]["source"] == {"origin": "cli"}
    assert listed["read"]["decision"] == "hidden", "exec confers execute only, not read"
    assert explain(unveil, "/bin/bash", "--rule", "exec:/bin/ls")["exec"]["decision"] != "granted"

    # 4. The `--mode unveil` FLAG flips a subtractive file to a closed universe by last-wins
    #    (FW-BP2/FW-BP7): an ambient-only path goes hidden, an explicitly-granted one stays granted.
    sub = tmp_path / "sub.toml"
    sub.write_text('net = "deny"\n[fs]\nread-mode = "ambient-minus-subtract"\nreads = ["/usr/**"]\n')
    assert explain(sub, "/etc/hosts")["read"]["decision"] == "ambient"
    assert explain(sub, "/etc/hosts", "--mode", "unveil")["read"]["decision"] == "hidden"
    assert explain(sub, "/usr/lib/x", "--mode", "unveil")["read"]["decision"] == "granted"

    # 5. The credential floor is un-liftable (FW-INV8): a broad CLI `--read ~/**` cannot expose
    #    ~/.ssh (origin built-in), while a non-sensitive sibling under the same grant is readable.
    floored = explain(unveil, "~/.ssh/id_rsa", "--read", "~/**")
    assert floored["read"]["decision"] == "denied"
    assert floored["read"]["source"] == {"origin": "built-in"}
    assert explain(unveil, "~/notes.txt", "--read", "~/**")["read"]["decision"] == "granted"


@pytest.mark.fw_e2e("FW-E2E-059")
def test_explain_names_winning_rule_and_provenance(cli, tmp_path):
    """FW-FID6: `explain <path>` reports the read/write verdict, the rule that decides each under
    the deny-terminal model (FW-CAP8), and the layer that rule came from -- without enforcing."""
    bp = tmp_path / "s.toml"
    bp.write_text(
        'net = "deny"\nmode = "unveil"\n'
        'rules = ["readwrite:/work/**", "modify:/var/log/app.log"]\n'
    )

    # A granted path names the file rule and its origin.
    granted = json.loads(cli("explain", "--blueprint", bp, "/work/src/main.rs").stdout)
    assert granted["read"]["decision"] == "granted"
    assert granted["read"]["rule"] == "/work/**"
    assert granted["read"]["source"] == {"origin": "file", "name": str(bp)}

    # A `--rule` deny is terminal (deny beats the file's readwrite) and is attributed to the CLI.
    denied = json.loads(
        cli("explain", "--blueprint", bp, "/work/src/secret", "--rule", "deny:/work/src/secret").stdout
    )
    assert denied["read"]["decision"] == "denied"
    assert denied["read"]["source"] == {"origin": "cli"}
    assert denied["write"]["decision"] == "denied"

    # The credential floor is a built-in, un-liftable deny (the backstop shape `**/credentials`).
    floored = json.loads(cli("explain", "--blueprint", bp, "/work/vault/credentials").stdout)
    assert floored["read"]["decision"] == "denied"
    assert floored["read"]["source"] == {"origin": "built-in"}
    assert "credential floor" in floored["read"]["rule"]

    # An unlisted path under `unveil` (empty universe) is hidden, not ambient.
    hidden = json.loads(cli("explain", "--blueprint", bp, "/etc/hosts").stdout)
    assert hidden["read"]["decision"] == "hidden"

    # Exec is a separate axis (FW-ISO9): an `exec:` grant shows execute even where read is closed.
    execd = json.loads(
        cli("explain", "--blueprint", bp, "/usr/bin/git", "--rule", "exec:/usr/bin/git").stdout
    )
    assert execd["exec"]["decision"] == "granted"
    assert execd["exec"]["source"] == {"origin": "cli"}
    assert execd["read"]["decision"] == "hidden", "exec confers execute only, not read"
