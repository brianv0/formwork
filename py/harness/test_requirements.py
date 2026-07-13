"""Requirement-identifier canaries (constitution: Requirements & identifiers). Every FW-* ID
cited anywhere in the repo must resolve to exactly one anchored definition in a defining
document, and every markdown requirement link must land on that anchor. Same pattern as the
catalog canaries in crates/formwork-cli/tests/profiles.rs: drift fails loud in CI, silently
dangling identifiers are the docs' fail-open."""

import re
import subprocess
from pathlib import Path

from helpers import REPO_ROOT

# The defining documents, in precedence order: an ID must be defined in exactly one.
DEFINING = ("formwork.md", "fep-1.md")

ID_RE = re.compile(
    r"FW-(?:E2E|ADV)-\d{3}"
    r"|FW-(?:XR|CAP|ISO|GW|TRA|FID|ENV|BP|CRED|DISC|INV|EGR)\d+"
)
ANCHOR_RE = re.compile(r'<a id="(fw-[a-z0-9-]+)"></a>')
# A definition site: the bold ID token at the start of a table row, bullet, or paragraph.
DEF_RE = re.compile(
    r"^(?:\|\s*|-\s+)?(?:<a id=\"[a-z0-9-]+\"></a>)?\*\*("
    + ID_RE.pattern
    + r")\b(?!\]\()",
    re.MULTILINE,
)
LINK_RE = re.compile(r"\]\(([^)#]*)#(fw-[a-z0-9-]+)\)")


def tracked(*patterns: str) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", *patterns], cwd=REPO_ROOT, capture_output=True, text=True
    )
    return [REPO_ROOT / line for line in out.stdout.splitlines()]


def strip_code(markdown: str) -> str:
    """Drop fenced blocks and inline code spans: quoted IDs are exempt by convention
    (historical/draft numbering is written as inline code so it neither links nor resolves)."""
    lines, out, fenced = markdown.split("\n"), [], False
    for line in lines:
        if line.strip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            out.append(re.sub(r"`[^`]*`", "", line))
    return "\n".join(out)


def definitions() -> dict[str, str]:
    """id (lowercase) -> defining file. Fails on duplicates across or within files."""
    defs: dict[str, str] = {}
    for name in DEFINING:
        text = (REPO_ROOT / name).read_text()
        for anchor in ANCHOR_RE.findall(text):
            assert anchor not in defs, f"{anchor} anchored in both {defs[anchor]} and {name}"
            defs[anchor] = name
    return defs


def test_every_definition_is_anchored_exactly_once():
    for name in DEFINING:
        text = (REPO_ROOT / name).read_text()
        anchors = ANCHOR_RE.findall(text)
        assert len(anchors) == len(set(anchors)), f"duplicate anchors in {name}"
        for ident in DEF_RE.findall(strip_code(text)):
            assert ident.lower() in anchors, f"{name}: definition {ident} has no anchor"


def test_every_cited_id_resolves_to_a_definition():
    defs = definitions()
    dangling = []
    for path in tracked("*.md", "*.rs", "*.py", "*.toml", "*.yml"):
        text = path.read_text()
        if path.suffix == ".md":
            text = strip_code(text)
        for ident in set(ID_RE.findall(text)):
            if ident.lower() not in defs:
                dangling.append(f"{path.relative_to(REPO_ROOT)}: {ident}")
    assert not dangling, "cited IDs with no definition:\n" + "\n".join(sorted(dangling))


def test_markdown_requirement_links_land():
    defs = definitions()
    broken = []
    for path in tracked("*.md"):
        for target, anchor in LINK_RE.findall(path.read_text()):
            where = f"{path.relative_to(REPO_ROOT)} -> {target}#{anchor}"
            if anchor not in defs:
                broken.append(f"{where} (no such anchor)")
                continue
            expected = REPO_ROOT / defs[anchor]
            actual = (path.parent / target).resolve() if target else path.resolve()
            if actual != expected.resolve():
                broken.append(f"{where} (defined in {defs[anchor]})")
    assert not broken, "requirement links that do not land:\n" + "\n".join(sorted(broken))
