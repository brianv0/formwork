"""One meaning for a path pattern (FW-BP27..FW-BP30, FW-FID31), black-box through the CLI: what
`compile`, `explain` and `run` do with a literal row, an any-depth row, a glob character and a
dotted relative name. Compile-level tests pin the host with --target and run anywhere; the
enforcement halves need Landlock and are marked `linux`. The Seatbelt half of each pair is the
rendered profile, which the compiler produces on any host."""

import json
import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from helpers import REPO_ROOT

DEFAULT = 'extends = ["builtin:default"]\nrules = ["readwrite:$CWD/**"]\n'
SYSTEM = '"readexec:/usr/**", "readexec:/bin/**", "readexec:/lib/**", "readexec:/lib64/**"'


def project(tmp_path: Path) -> Path:
    """A launch directory with a tree to probe, symlink-resolved like the kernel sees it."""
    root = Path(os.path.realpath(tmp_path)) / "proj"
    (root / "data" / "sub").mkdir(parents=True)
    (root / "secrets" / "deep").mkdir(parents=True)
    (root / "data" / "top.txt").write_text("top-contents\n")
    (root / "data" / "sub" / "inner.txt").write_text("inner-contents\n")
    (root / "secrets" / "key").write_text("key-contents\n")
    (root / "secrets" / "deep" / "key").write_text("deep-key-contents\n")
    (root / "plain.txt").write_text("plain-contents\n")
    (root / "bp.toml").write_text(DEFAULT)
    return root


def unveil(root: Path, *rules: str) -> Path:
    """A closed-universe blueprint: the system directories, and the rules under test."""
    quoted = ", ".join(f'"{rule}"' for rule in rules)
    path = root / "unveil.toml"
    path.write_text(f'mode = "unveil"\nnet = "deny"\nrules = [{SYSTEM}, {quoted}]\n')
    return path


def refused_by_kernel(result) -> bool:
    """The workload ran and the kernel refused it: a denial, not a blueprint that failed to load."""
    return result.code != 0 and "Permission denied" in result.stderr and "Error: " not in result.stderr


def error_line(result) -> str:
    """The refusal itself, without the telemetry around it."""
    lines = [line for line in result.stderr.splitlines() if line.startswith("Error: ")]
    assert lines, f"no refusal on stderr:\n{result.stderr}"
    return lines[0]


def sbpl(cli, root: Path, blueprint: Path, *args: str) -> str:
    result = cli("compile", "--blueprint", blueprint, "--target", "macos", *args, cwd=root)
    assert result.code == 0, result.stderr
    return json.loads(result.stdout)["confiner"]["sbpl"]


@pytest.fixture
def landlock(cli):
    if json.loads(cli("explain", "--json").stdout)["host"].get("landlock-abi") is None:
        pytest.skip("no Landlock on this kernel (nothing enforces, so nothing denies)")


# --- FW-BP27: a literal names one object -------------------------------------------------


@pytest.mark.fw_e2e("FW-E2E-178")
def test_literal_directory_grant_is_a_seatbelt_literal(cli, tmp_path):
    root = project(tmp_path)
    profile = sbpl(cli, root, unveil(root, f"read:{root}/data"))
    assert f'(allow file-read* (literal "{root}/data"))' in profile
    assert f'(subpath "{root}/data")' not in profile


@pytest.mark.linux
@pytest.mark.fw_e2e("FW-E2E-178")
def test_literal_directory_grant_confers_nothing_beneath_it(landlock, cli, tmp_path):
    """The paired probe: the literal reads nothing beneath the directory, `explain` says so for
    the file and for the directory, `run` names the row, and the `/**` spelling reads."""
    root = project(tmp_path)
    inner = root / "data" / "sub" / "inner.txt"
    literal = unveil(root, f"read:{root}/data", f"read:{root}/plain.txt")

    live = cli("run", "--blueprint", literal, "--", "/bin/cat", root / "plain.txt", cwd=root)
    assert live.code == 0 and "plain-contents" in live.stdout, live.stderr
    denied = cli("run", "--blueprint", literal, "--", "/bin/cat", inner, cwd=root)
    assert denied.code != 0 and "inner-contents" not in denied.stdout
    assert "Permission denied" in denied.stderr, denied.stderr
    assert f"`{root}/data/**`" in denied.stderr, "run must name the spelling that grants the contents"
    listing = cli("run", "--blueprint", literal, "--", "/bin/ls", root / "data", cwd=root)
    assert refused_by_kernel(listing) and "top.txt" not in listing.stdout, listing.stderr

    explained = json.loads(
        cli("explain", "--blueprint", literal, "--json", inner, root / "data", cwd=root).stdout
    )["explanations"]
    beneath, directory = explained
    assert beneath["read"]["decision"] == "hidden", beneath
    assert directory["read"]["decision"] == "granted", directory
    assert "not granted on this host" in directory["host_note"], directory
    assert f"{root}/data/**" in directory["host_note"]

    subtree = unveil(root, f"read:{root}/data/**")
    read = cli("run", "--blueprint", subtree, "--", "/bin/cat", inner, cwd=root)
    assert read.code == 0 and "inner-contents" in read.stdout, read.stderr
    assert "names a directory" not in read.stderr
    explained = json.loads(
        cli("explain", "--blueprint", subtree, "--json", inner, cwd=root).stdout
    )["explanations"][0]
    assert explained["read"]["decision"] == "granted" and "host_note" not in explained


@pytest.mark.fw_e2e("FW-E2E-179")
def test_literal_directory_deny_is_a_seatbelt_literal(cli, tmp_path):
    root = project(tmp_path)
    literal = sbpl(cli, root, root / "bp.toml", "--rule", "deny:$CWD/secrets")
    assert f'(deny file-read* (literal "{root}/secrets"))' in literal
    assert f'(subpath "{root}/secrets")' not in literal
    contents = sbpl(cli, root, root / "bp.toml", "--rule", "deny:$CWD/secrets/**")
    assert f'(deny file-read* (subpath "{root}/secrets"))' in contents


@pytest.mark.linux
@pytest.mark.fw_e2e("FW-E2E-179")
def test_literal_directory_deny_and_explain_agree_with_the_probe(landlock, cli, tmp_path):
    """Landlock drops what lies beneath a denied directory. `explain` says so for the path, and
    `run` names the row and the spelling that denies the contents on both hosts."""
    root = project(tmp_path)
    key = root / "secrets" / "deep" / "key"
    rule = ("--rule", "deny:$CWD/secrets")

    denied = cli("run", "--blueprint", "bp.toml", *rule, "--", "/bin/cat", key, cwd=root)
    assert refused_by_kernel(denied) and "deep-key-contents" not in denied.stdout, denied.stderr
    assert f"`deny:{root}/secrets/**`" in denied.stderr, denied.stderr
    sibling = cli("run", "--blueprint", "bp.toml", *rule, "--", "/bin/cat", "plain.txt", cwd=root)
    assert sibling.code == 0 and "plain-contents" in sibling.stdout, sibling.stderr

    explained = json.loads(
        cli("explain", "--blueprint", "bp.toml", *rule, "--json", key, "plain.txt", cwd=root).stdout
    )["explanations"]
    beneath, plain = explained
    # The model's verdict is the rule's own extent; the host note is what this kernel does.
    assert beneath["read"]["decision"] == "granted", beneath
    assert "read and write denied on this host" in beneath["host_note"], beneath
    assert f"{root}/secrets/**" in beneath["host_note"]
    assert "host_note" not in plain, plain

    contents = ("--rule", "deny:$CWD/secrets/**")
    explained = json.loads(
        cli("explain", "--blueprint", "bp.toml", *contents, "--json", key, cwd=root).stdout
    )["explanations"][0]
    assert explained["read"]["decision"] == "denied" and "host_note" not in explained
    quiet = cli("run", "--blueprint", "bp.toml", *contents, "--", "/bin/cat", key, cwd=root)
    assert refused_by_kernel(quiet) and "names a directory" not in quiet.stderr, quiet.stderr


# --- FW-BP28: any-depth operator rows and Linux -------------------------------------------

ANY_DEPTH = [
    ("readwrite:{root}/elsewhere/**/data/**", "`write:{root}/elsewhere/**/data/**`"),
    ("read:**/data/**", "`read:**/data/**`"),
    ("deny:**/secrets.yaml", "`deny:**/secrets.yaml`"),
]


@pytest.mark.fw_e2e("FW-E2E-180")
@pytest.mark.parametrize("rule,named", ANY_DEPTH)
def test_any_depth_operator_row_is_refused_for_linux_and_compiles_for_macos(
    cli, tmp_path, rule, named
):
    root = project(tmp_path)
    rule, named = rule.format(root=root), named.format(root=root)
    # A closed universe: under the default profile's `/tmp/**` a row anchored in the scratch
    # tree is covered by a subtree grant, canonicalizes away, and is no longer a row to refuse.
    blueprint = unveil(root, rule)
    for target in ("linux-v1", "linux-v6"):
        for extra in ((), ("--report-only",)):
            refused = cli("compile", "--blueprint", blueprint, "--target", target, *extra, cwd=root)
            assert refused.code != 0 and refused.stdout == "", refused.stdout
            assert named in error_line(refused) and "Landlock" in error_line(refused)
    assert '(regex #"' in sbpl(cli, root, blueprint)


@pytest.mark.linux
@pytest.mark.fw_e2e("FW-E2E-180")
@pytest.mark.parametrize("rule,named", ANY_DEPTH)
def test_compile_explain_and_run_refuse_with_one_message(landlock, cli, tmp_path, rule, named):
    root = project(tmp_path)
    args = ("--blueprint", unveil(root, rule.format(root=root)))
    doors = {
        "compile": cli("compile", *args, cwd=root),
        "explain <path>": cli("explain", *args, root / "plain.txt", cwd=root),
        "explain": cli("explain", *args, cwd=root),
        "run": cli("run", *args, "--", "/bin/cat", "plain.txt", cwd=root),
    }
    messages = {door: error_line(result) for door, result in doors.items()}
    assert len(set(messages.values())) == 1, messages
    assert named.format(root=root) in messages["run"]
    for door, result in doors.items():
        assert result.code != 0 and "plain-contents" not in result.stdout, door


@pytest.mark.linux
@pytest.mark.fw_adv("FW-ADV-048")
def test_anchored_any_depth_grant_cannot_reach_the_launch_directory(landlock, cli, tmp_path):
    """The escape: an any-depth grant anchored elsewhere used to bind to `./data` of the launch
    directory. The session must not start, so nothing is read and nothing is planted."""
    root = project(tmp_path)
    elsewhere = root.parent / "elsewhere"
    elsewhere.mkdir()
    blueprint = unveil(root, f"readwrite:{elsewhere}/**/data/**")
    planted = root / "data" / "sub" / "planted.txt"
    result = cli(
        "run", "--blueprint", blueprint, "--", "/bin/sh", "-c",
        f"cat {root}/data/sub/inner.txt; echo x > {planted}; echo RAN",
        cwd=root,
    )
    assert result.code != 0, result.stdout
    assert "RAN" not in result.stdout and "inner-contents" not in result.stdout
    assert not planted.exists(), "the workload wrote outside the grant's anchor"
    assert "cannot be enforced on Linux" in error_line(result)


# --- FW-BP29: glob characters --------------------------------------------------------------


@pytest.mark.fw_e2e("FW-E2E-181")
@pytest.mark.parametrize(
    "rule,subtree,escaped",
    [
        ("deny:/srv/keys/*.pem", "`/srv/keys/**`", r"`/srv/keys/\*.pem`"),
        ("read:/srv/keys/prod?.pem", "`/srv/keys/**`", r"`/srv/keys/prod\?.pem`"),
        ("readwrite:/srv/[a-z]/**", "`/srv/**`", r"`/srv/\[a-z]/**`"),
    ],
)
def test_glob_character_is_a_load_error_naming_the_valid_spellings(
    cli, tmp_path, rule, subtree, escaped
):
    root = project(tmp_path)
    for surface in (("--rule", rule), ("--set", f'rules = ["{rule}"]')):
        refused = cli("compile", "--blueprint", "bp.toml", *surface, "--target", "macos", cwd=root)
        assert refused.code != 0 and refused.stdout == ""
        assert "not a wildcard" in refused.stderr, refused.stderr
        assert subtree in refused.stderr and escaped in refused.stderr, refused.stderr
    pattern = rule.split(":", 1)[1]
    for flag in ("--read", "--subtract"):
        refused = cli("compile", "--blueprint", "bp.toml", flag, pattern, cwd=root)
        assert refused.code != 0 and "not a wildcard" in refused.stderr, refused.stderr


@pytest.mark.fw_e2e("FW-E2E-181")
def test_escaped_glob_character_is_the_file_name_in_both_policies(cli, tmp_path):
    root = project(tmp_path)
    rule = ("--rule", r"deny:/srv/keys/\*.pem")
    assert '(deny file-read* (literal "/srv/keys/*.pem"))' in sbpl(cli, root, root / "bp.toml", *rule)
    linux = cli("compile", "--blueprint", "bp.toml", *rule, "--target", "linux-v6", cwd=root)
    assert linux.code == 0, linux.stderr
    # The policy keeps the pattern's spelling, so reading it back names the same one file.
    assert r"/srv/keys/\*.pem" in json.loads(linux.stdout)["confiner"]["subtract"]


@pytest.mark.linux
@pytest.mark.fw_e2e("FW-E2E-181")
def test_escaped_glob_character_denies_the_file_of_that_name(landlock, cli, tmp_path):
    root = project(tmp_path)
    (root / "keys").mkdir()
    (root / "keys" / "*.pem").write_text("star-contents\n")
    (root / "keys" / "prod.pem").write_text("prod-contents\n")
    rule = ("--rule", r"deny:$CWD/keys/\*.pem")
    star = cli("run", "--blueprint", "bp.toml", *rule, "--", "/bin/cat", "keys/*.pem", cwd=root)
    assert refused_by_kernel(star) and "star-contents" not in star.stdout, star.stderr
    prod = cli("run", "--blueprint", "bp.toml", *rule, "--", "/bin/cat", "keys/prod.pem", cwd=root)
    assert prod.code == 0 and "prod-contents" in prod.stdout, prod.stderr
    explained = json.loads(
        cli("explain", "--blueprint", "bp.toml", *rule, "--json", "keys/*.pem", "keys/prod.pem",
            cwd=root).stdout
    )["explanations"]
    assert [e["read"]["decision"] for e in explained] == ["denied", "granted"], explained


@pytest.mark.linux
@pytest.mark.fw_e2e("FW-E2E-181")
def test_launch_directory_and_launcher_paths_with_glob_characters_enforce(landlock, cli, tmp_path):
    """Paths the Launcher builds are concrete: a launch directory and a credential file whose
    names carry glob characters are granted and denied as themselves."""
    root = Path(os.path.realpath(tmp_path)) / "app[v2] *"
    root.mkdir()
    (root / "bp.toml").write_text(DEFAULT)
    (root / "sa[1]*.json").write_text("service-account\n")
    (root / "sa1.json").write_text("neighbour\n")
    # Not the launch directory itself: write-protecting bp.toml splits it, and Landlock cannot
    # grant create in a split directory.
    (root / "out").mkdir()
    env = {"GOOGLE_APPLICATION_CREDENTIALS": str(root / "sa[1]*.json")}
    wrote = cli(
        "run", "--blueprint", "bp.toml", "--", "/bin/sh", "-c", "echo made > out/new.txt && cat sa1.json",
        cwd=root, env=env,
    )
    assert wrote.code == 0 and "neighbour" in wrote.stdout, wrote.stderr
    assert (root / "out" / "new.txt").read_text() == "made\n"
    denied = cli("run", "--blueprint", "bp.toml", "--", "/bin/cat", "sa[1]*.json", cwd=root, env=env)
    assert refused_by_kernel(denied) and "service-account" not in denied.stdout, denied.stderr
    # The blueprint itself stays write-protected under its odd path (FW-XR8).
    tamper = cli(
        "run", "--blueprint", "bp.toml", "--", "/bin/sh", "-c", "echo x >> bp.toml", cwd=root, env=env
    )
    assert refused_by_kernel(tamper) and (root / "bp.toml").read_text() == DEFAULT, tamper.stderr


# --- FW-BP30: a path target is spelled as a path -------------------------------------------


@pytest.mark.fw_e2e("FW-E2E-182")
@pytest.mark.parametrize("verb", ["deny", "allow"])
def test_host_rule_naming_a_launch_directory_entry_is_refused(cli, tmp_path, verb):
    root = project(tmp_path)
    (root / "secrets.json").write_text("{}\n")
    rule = f"{verb}:secrets.json"
    for door in (("compile", "--target", "macos"), ("explain", "--hosts")):
        refused = cli(door[0], "--blueprint", "bp.toml", "--rule", rule, *door[1:], cwd=root)
        assert refused.code != 0 and "secrets.json" not in refused.stdout, refused.stdout
        message = error_line(refused)
        assert f"`{verb}:./secrets.json`" in message and f"`{verb}:secrets.json:443`" in message

    # With no such entry the name can only be a host, and the rule loads as one.
    (root / "secrets.json").unlink()
    hosts = cli("explain", "--blueprint", "bp.toml", "--rule", rule, "--hosts", cwd=root)
    assert hosts.code == 0 and "host rules" in hosts.stdout, hosts.stderr


@pytest.mark.fw_e2e("FW-E2E-182")
def test_dot_slash_target_is_a_path_rule_in_both_policies(cli, tmp_path):
    root = project(tmp_path)
    (root / "secrets.json").write_text("{}\n")
    rule = ("--rule", "deny:./secrets.json")
    assert f'(deny file-read* (literal "{root}/secrets.json"))' in sbpl(cli, root, root / "bp.toml", *rule)
    linux = json.loads(
        cli("compile", "--blueprint", "bp.toml", *rule, "--target", "linux-v6", cwd=root).stdout
    )
    assert f"{root}/secrets.json" in linux["confiner"]["subtract"]
    # A path rule leaves the net posture alone: no host table, no Gateway.
    assert linux["gateway"].get("egress") is None, linux["gateway"]


@pytest.mark.linux
@pytest.mark.fw_e2e("FW-E2E-182")
def test_dot_slash_deny_denies_the_file(landlock, cli, tmp_path):
    root = project(tmp_path)
    (root / "secrets.json").write_text("secret-contents\n")
    rule = ("--rule", "deny:./secrets.json")
    denied = cli("run", "--blueprint", "bp.toml", *rule, "--", "/bin/cat", "secrets.json", cwd=root)
    assert refused_by_kernel(denied) and "secret-contents" not in denied.stdout, denied.stderr
    control = cli("run", "--blueprint", "bp.toml", "--", "/bin/cat", "secrets.json", cwd=root)
    assert control.code == 0 and "secret-contents" in control.stdout, control.stderr


# --- FW-E2E-183: the shipped recipes -------------------------------------------------------

# Dotfiles the shipped documents deny as files. A literal deny target otherwise passes only with
# a file extension; anything else a shipped `deny:` names is a directory and must be spelled with
# `/**` (FW-BP27).
DENIED_FILES = {".env", ".npmrc"}
EXTENSION_RE = re.compile(r"[^./][^/]*\.[A-Za-z0-9]+$|^\.[^./]+\.[A-Za-z0-9]+$")
DENY_RE = re.compile(r"""deny:((?:/|~|\$|\./)[^\s"'`,|)]*)""")


@pytest.mark.fw_e2e("FW-E2E-183")
def test_shipped_deny_recipes_cover_a_directory_with_its_contents():
    documents = [REPO_ROOT / "README.md", REPO_ROOT / "examples" / "README.md", REPO_ROOT / "formwork.md"]
    documents += sorted((REPO_ROOT / "examples").rglob("*.toml"))
    documents += sorted((REPO_ROOT / "examples").rglob("*.md"))
    documents += sorted((REPO_ROOT / "profiles").glob("*.toml"))
    seen, bare = 0, []
    for document in dict.fromkeys(documents):
        for target in DENY_RE.findall(document.read_text()):
            seen += 1
            literal = not target.endswith("/**") and "**/" not in target
            name = target.rsplit("/", 1)[-1]
            if literal and name not in DENIED_FILES and not EXTENSION_RE.match(name):
                bare.append(f"{document.relative_to(REPO_ROOT)}: deny:{target}")
    assert seen >= 5, "the canary found no deny recipes to check; its pattern has drifted"
    assert not bare, (
        "a literal deny covers one entry, not a directory's contents; write `/**`, or list the "
        "dotfile in DENIED_FILES:\n" + "\n".join(bare)
    )


# --- FW-BP31: an observed path is a literal ------------------------------------------------


@pytest.mark.linux
@pytest.mark.fw_adv("FW-ADV-049")
def test_learn_grants_a_hostile_name_as_one_file(landlock, cli, tmp_path):
    """The real chain: a confined workload opens files whose names spell pattern grammar inside
    the auto-widen zone. Whatever reaches the discovered layer names one observed file, and the
    next run reads that file and not the neighbour a wildcard reading would have reached."""
    if shutil.which("strace") is None:
        pytest.skip("strace not installed")
    if subprocess.run(["strace", "-qq", "-o", "/dev/null", "/bin/true"]).returncode != 0:
        pytest.skip("ptrace is blocked in this environment (container seccomp?)")
    root = Path(os.path.realpath(tmp_path))
    zone = root / "zone"
    # One hostile name per directory, each beside the neighbour it would match as a pattern.
    hostile = {
        zone / "a" / "**": zone / "a" / "other",
        zone / "b" / "**" / "config": zone / "b" / "deep" / "config",
        zone / "c" / "x*y": zone / "c" / "xzy",
        zone / "d" / "k?y": zone / "d" / "key",
        zone / "e" / "[id]": zone / "e" / "i",
    }
    for path in [*hostile, *hostile.values()]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"contents of {path.name}\n")
    blueprint = root / "bp.toml"
    blueprint.write_text(
        f'mode = "unveil"\nnet = "deny"\nrules = [{SYSTEM}]\n'
        f'[discovery]\nauto-widen = ["{zone}/**"]\n'
    )
    script = "; ".join(f"cat '{path}'" for path in hostile)
    env = {"HOME": str(root)}
    learned = cli("learn", "--blueprint", blueprint, "--", "/bin/sh", "-c", script, cwd=root, env=env)
    discovered = root / "bp.toml.discovered.toml"
    assert discovered.exists(), learned.stderr

    def unescaped(grant: str) -> str:
        return re.sub(r"\\(.)", r"\1", grant)

    grants = tomllib.loads(discovered.read_text())["fs"]["reads"]
    observed = {str(path) for path in hostile}
    for grant in grants:
        # Every `*`, `?` and `[` is escaped, so the pattern is a literal; unescaped, it is a
        # path the workload opened.
        assert not re.search(r"[*?\[]", re.sub(r"\\.", "", grant)), grant
        assert unescaped(grant) in observed, grant
    granted = {unescaped(grant) for grant in grants}
    assert str(zone / "c" / "x*y") in granted, f"a hostile name is still proposed, as itself: {grants}"

    # The next run, under the discovered layer: each granted file reads, its neighbour does not.
    for path, neighbour in hostile.items():
        if str(path) not in granted:
            continue
        read = cli("run", "--blueprint", blueprint, "--", "/bin/cat", path, cwd=root, env=env)
        assert read.code == 0 and f"contents of {path.name}" in read.stdout, read.stderr
        wide = cli("run", "--blueprint", blueprint, "--", "/bin/cat", neighbour, cwd=root, env=env)
        assert refused_by_kernel(wide) and "contents of" not in wide.stdout, f"{path} reached {neighbour}"
