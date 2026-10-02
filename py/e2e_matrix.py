"""Cross-platform end-to-end verdict for `main` (.github/workflows/e2e-verify.yml).

Each platform job leaves a results directory: `host.json` (`formwork explain --json`), one or more
`cargo-*.log` files (`cargo test ... -- --show-output`), and `pytest.json` (the harness with
`FW_E2E_RESULTS` set). This script maps every executed test to the FW-E2E/FW-ADV tests of
formwork.md section 7 and decides, from formwork.md alone, whether each test the spec claims is
implemented passed on every OS family its title names. Standard library only: the verdict job
runs it with the runner's own python3.

A test discharges the IDs in its name (`fw_e2e_075_...`, `fw_cred16_...`) and the IDs that lead
its first doc line (`/// FW-E2E-001 (Linux/Landlock): ...`); an ID cited later in the comment is a
cross-reference, not a claim. Harness tests discharge their `fw_e2e`/`fw_adv` markers.

Blocking, in the order reported:
  1. an expected platform left no results;
  2. a test failed;
  3. a test that discharges an FW ID skipped at runtime (a Rust `skipping:` line, a harness skip
     no marker declared) -- the run did not exercise it, which `FW_REQUIRE_EXERCISED` promises
     never happens; a test with no ID that skips (a deliberate per-host arm, such as the
     isolation tier on an image without user namespaces) is listed as a note;
  4. a section 7 test that is neither retired nor on the section 10 not-yet-implemented list has
     no passing test on an OS family its title names (`(both)` = Linux and macOS; no marker = at
     least one platform).
A test on the section 10 list that passes is reported as spec drift, not a failure.

Exit status: 0 verdict pass, 1 verdict fail, 2 the spec or a results file could not be parsed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FAMILIES = ("linux", "macos")

TEST_ID = r"FW-(?:E2E|ADV)-\d{3}"
REQ_ID = r"FW-(?:XR|CAP|ISO|GW|TRA|FID|ENV|BP|CRED|DISC|INV|EGR)\d+"
ANY_ID = re.compile(rf"{TEST_ID}|{REQ_ID}")
NAME_TEST_ID = re.compile(r"fw_(e2e|adv)_(\d{3})")
NAME_REQ_ID = re.compile(r"fw_(xr|cap|iso|gw|tra|fid|env|bp|cred|disc|inv|egr)(\d+)(?=_|$)")
LEAD_SEP = re.compile(r"\s*(?:/|,|\+|&|and)\s*")


class SpecError(Exception):
    """formwork.md no longer has the shape this verdict reads; fail loud rather than pass."""


# --- the spec -----------------------------------------------------------------------------------


@dataclass
class SpecTest:
    id: str
    title: str
    scope: frozenset[str] | None  # None: no platform marker, so any one platform suffices
    retired: bool


@dataclass
class Spec:
    tests: dict[str, SpecTest]
    owed: set[str]
    partial: set[str]
    requirements: dict[str, list[str]]  # requirement -> primary tests (section 10)
    retired_requirements: set[str]


def _section(text: str, start: str, end: str) -> str:
    try:
        return text.split(start, 1)[1].split(end, 1)[0]
    except IndexError as exc:
        raise SpecError(f"formwork.md has no section between {start!r} and {end!r}") from exc


def _unlink(text: str) -> str:
    return re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)


def title_scope(title: str) -> frozenset[str] | None:
    """The OS families a section 7 title names in its parentheticals: `(both)`, `(both OSes)` and
    `(S1; both OSes)` name both; `(Linux, ABI-gated)` and `(Linux, both runners)` name Linux --
    "both runners" is the two Ubuntu images, not the two OSes; `(macOS)` names macOS."""
    families: set[str] = set()
    for group in re.findall(r"\(([^()]*)\)", _unlink(title)):
        for token in re.split(r"[;,]", group.lower()):
            token = token.strip()
            if token in ("both", "both oses"):
                families.update(FAMILIES)
            elif token in ("linux", "linux first"):
                families.add("linux")
            elif token == "macos":
                families.add("macos")
    return frozenset(families) or None


def _expand(text: str) -> list[str]:
    """Test IDs in a section 10 cell, in order. Links and `–nnn` ranges as written; a bare number
    takes the kind of the explicit ID before it, as a reader takes `ADV-013, 015`."""
    ids: list[str] = []
    kind = "E2E"
    token = re.compile(
        r"FW-(E2E|ADV)-(\d{3})\]\([^)]*\)(?:[–-](\d{3}))?"  # [FW-E2E-020](#...)–023
        r"|(?<![\w-])(E2E|ADV)-(\d{3})(?:\.\.(\d{3}))?"  # ADV-001..006
        r"|(?<![\w#-])(\d{3})(?:\.\.(\d{3}))?(?![\d)])"  # 025, 012..015
    )
    for m in token.finditer(text):
        if m.group(1):
            kind, lo, hi = m.group(1), m.group(2), m.group(3)
        elif m.group(4):
            kind, lo, hi = m.group(4), m.group(5), m.group(6)
        else:
            lo, hi = m.group(7), m.group(8)
        for n in range(int(lo), int(hi or lo) + 1):
            ids.append(f"FW-{kind}-{n:03d}")
    return ids


def load_spec(repo: Path = REPO_ROOT) -> Spec:
    text = (repo / "formwork.md").read_text()
    sec7 = _section(text, "## 7. End-to-end tests", "\n## 8.")
    sec10 = _section(text, "## 10. Requirements", "\n## 11.")

    tests: dict[str, SpecTest] = {}
    head = re.compile(rf'<a id="fw-(?:e2e|adv)-\d{{3}}"></a>\*\*({TEST_ID}): (.+?)\*\*(.{{0,40}})')
    for m in head.finditer(sec7):
        tests[m.group(1)] = SpecTest(
            id=m.group(1),
            title=_unlink(m.group(2)).rstrip("."),
            scope=title_scope(m.group(2)),
            retired=m.group(3).lstrip().startswith("*(Retired"),
        )
    if len(tests) < 50:
        raise SpecError(f"found only {len(tests)} section 7 tests; the heading shape changed")

    intro = sec10.split("| Requirement |", 1)[0]
    lead = "Tests defined in §7 but not yet implemented"
    if lead not in intro:
        raise SpecError(f"section 10 no longer opens its not-yet-implemented list with {lead!r}")
    after = intro.split(lead, 1)[1]
    stop = re.search(r"\)\.\s", after)
    if stop is None:
        raise SpecError("section 10's not-yet-implemented list has no end")
    owed = set(_expand(after[: stop.end()]))
    partial = set(_expand(after[stop.end() :])) - owed
    if not owed:
        raise SpecError("section 10's not-yet-implemented list parsed empty")

    requirements: dict[str, list[str]] = {}
    retired_requirements = set()
    for line in sec10.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        req = re.match(rf"\[({REQ_ID})\]", cells[0]) if len(cells) >= 3 else None
        if req:
            requirements[req.group(1)] = _expand(cells[1])
            if cells[1].startswith("retired"):
                retired_requirements.add(req.group(1))
    unknown = {t for ts in requirements.values() for t in ts} | owed | partial
    unknown -= set(tests)
    if unknown:
        raise SpecError(f"section 10 names tests section 7 does not define: {sorted(unknown)}")
    return Spec(tests, owed, partial, requirements, retired_requirements)


# --- what each Rust test claims -----------------------------------------------------------------


@dataclass
class RustTest:
    file: str
    fn: str
    ids: frozenset[str]


def lead_ids(line: str) -> list[str]:
    """The IDs a doc line opens with: `FW-GW3 / FW-INV4: ...` -> both; `FW-ADV-020, the opener
    route: ...` -> FW-ADV-020; `Pattern shading (FW-GW9): ...` -> none."""
    ids, pos, line = [], 0, line.strip()
    while (m := ANY_ID.match(line, pos)) is not None:
        ids.append(m.group(0))
        pos = m.end()
        sep = LEAD_SEP.match(line, pos)
        if sep is None or ANY_ID.match(line, sep.end()) is None:
            break
        pos = sep.end()
    return ids


def name_ids(fn: str) -> list[str]:
    ids = [f"FW-{k.upper()}-{n}" for k, n in NAME_TEST_ID.findall(fn)]
    ids += [f"FW-{k.upper()}{n}" for k, n in NAME_REQ_ID.findall(fn)]
    return ids


def scan_rust(repo: Path = REPO_ROOT) -> list[RustTest]:
    found = []
    for path in sorted(repo.glob("crates/*/**/*.rs")):
        lines = path.read_text().splitlines()
        for i, line in enumerate(lines):
            if not re.match(r"\s*#\[(?:tokio::)?test\b", line):
                continue
            j = i
            while j < len(lines) and not re.match(r"\s*(?:pub\s+)?(?:async\s+)?fn\s", lines[j]):
                j += 1
            fn = re.search(r"fn\s+(\w+)", lines[j]).group(1)
            k, first_doc = i - 1, ""
            while k >= 0 and lines[k].strip().startswith(("///", "#[")):
                if lines[k].strip().startswith("///"):
                    first_doc = lines[k].strip()[3:]
                k -= 1
            ids = frozenset(name_ids(fn) + lead_ids(first_doc))
            found.append(RustTest(str(path.relative_to(repo)), fn, ids))
    return found


# --- results ------------------------------------------------------------------------------------


@dataclass
class Outcome:
    tool: str  # cargo | pytest
    test: str
    ids: frozenset[str]
    outcome: str  # passed | failed | skipped | ignored | not-applicable
    reason: str = ""


ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")  # CARGO_TERM_COLOR=always colours cargo's own lines
RUNNING = re.compile(r"^\s+Running (?:unittests )?(\S+) \((\S+)\)")
SAME_LINE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\b")
OUTPUT_HEAD = re.compile(r"^---- (\S+) stdout ----$")
LISTED = re.compile(r"^    (\S+)$")
# `skip:`, `skipping:` and `skip fw_e2e_068:` end a test early; `skipping capable-kernel arm:`
# notes a branch the test replaced with its other arm, which is still a pass.
SKIP_LINE = re.compile(r"^(?:skip|skipping)(?: fw_\w+)?:\s*(.*)$")


def parse_cargo_log(text: str) -> list[tuple[str, str, str, str]]:
    """(binary, source, test path, outcome[, skip reason]) per test from `cargo test` run with
    `--show-output`. The `successes:`/`failures:` lists libtest prints at the end of each binary
    decide the outcome, because under `--test-threads=1` a child process's uncaptured output can
    land between `test name ...` and its `ok`."""
    results: dict[tuple[str, str, str], list[str]] = {}
    output: dict[tuple[str, str, str], list[str]] = {}
    binary = source = None
    mode = None  # None | "await" | "output" | "list"
    kind = capture = None
    for raw in ANSI.sub("", text).splitlines():
        line = raw.rstrip("\n")
        if m := RUNNING.match(line):
            source, binary = m.group(1), Path(m.group(2)).name.rsplit("-", 1)[0]
            mode = None
            continue
        if line.lstrip().startswith("Doc-tests "):
            binary = source = None
            continue
        if binary is None:
            continue
        if line in ("successes:", "failures:"):
            kind, mode = line[:-1], "await"
            continue
        if line.startswith("test result:"):
            mode = None
            continue
        if mode == "await":
            if not line.strip():
                continue
            mode = "output" if OUTPUT_HEAD.match(line) else "list"
        if mode == "output":
            if m := OUTPUT_HEAD.match(line):
                capture = (binary, source, m.group(1))
                output.setdefault(capture, [])
            elif capture is not None:
                output[capture].append(line)
            continue
        if mode == "list":
            if m := LISTED.match(line):
                results[(binary, source, m.group(1))] = [
                    "passed" if kind == "successes" else "failed"
                ]
            elif not line.strip():
                mode = None
            continue
        if m := SAME_LINE.match(line):
            key = (binary, source, m.group(1))
            verdict = {"ok": "passed", "FAILED": "failed", "ignored": "ignored"}[m.group(2)]
            results.setdefault(key, [verdict])
    rows = []
    for key, (verdict,) in results.items():
        reason = ""
        if verdict == "passed":
            skips = [m for ln in output.get(key, []) if (m := SKIP_LINE.match(ln.strip()))]
            if skips:
                verdict, reason = "skipped", skips[0].group(1)
        rows.append((*key, verdict, reason))
    return rows


def attribute(binary: str, source: str, test: str, index: list[RustTest]) -> frozenset[str]:
    fn = test.rsplit("::", 1)[-1]
    same_fn = [t for t in index if t.fn == fn]
    if source.startswith("tests/"):
        narrowed = [t for t in same_fn if Path(t.file).stem == Path(source).stem]
    else:
        crate = {"formwork": "formwork-cli"}.get(binary, binary.replace("_", "-"))
        narrowed = [t for t in same_fn if t.file.startswith(f"crates/{crate}/")]
    return frozenset().union(*(t.ids for t in (narrowed or same_fn)))


@dataclass
class Platform:
    name: str
    family: str | None
    host: dict = field(default_factory=dict)
    outcomes: list[Outcome] = field(default_factory=list)
    cargo_logs: int = 0
    pytest_ran: bool = False


def load_platform(directory: Path, index: list[RustTest]) -> Platform:
    host = {}
    if (directory / "host.json").is_file():
        try:
            host = json.loads((directory / "host.json").read_text()).get("host", {})
        except json.JSONDecodeError as exc:
            raise SpecError(f"{directory}/host.json: {exc}") from exc
    family = host.get("os") or next((f for f in FAMILIES if directory.name.startswith(f)), None)
    platform = Platform(directory.name, family, host)
    for log in sorted(directory.glob("cargo-*.log")):
        platform.cargo_logs += 1
        for binary, source, test, verdict, reason in parse_cargo_log(log.read_text()):
            ids = attribute(binary, source, test, index)
            name = f"{binary}::{test}"
            platform.outcomes.append(Outcome("cargo", name, ids, verdict, reason))
    if (directory / "pytest.json").is_file():
        platform.pytest_ran = True
        for row in json.loads((directory / "pytest.json").read_text())["tests"]:
            platform.outcomes.append(
                Outcome(
                    "pytest",
                    row["nodeid"],
                    frozenset(row["ids"]),
                    row["outcome"],
                    row.get("reason", ""),
                )
            )
    return platform


# --- the verdict --------------------------------------------------------------------------------


def _merge_outcomes(outcomes: list[Outcome]) -> list[Outcome]:
    """One row per test per platform: a test that ran in two cargo invocations (the default run
    lists an `#[ignore]` test as ignored; the `--ignored` run executes it) keeps its strongest
    result -- failed over passed over skipped over ignored."""
    rank = {"failed": 4, "passed": 3, "skipped": 2, "ignored": 1, "not-applicable": 0}
    best: dict[tuple[str, str], Outcome] = {}
    for o in outcomes:
        key = (o.tool, o.test)
        if key not in best or rank[o.outcome] > rank[best[key].outcome]:
            best[key] = o
    return list(best.values())


def cell(outcomes: list[Outcome]) -> str:
    seen = {o.outcome for o in outcomes}
    for verdict in ("failed", "passed", "skipped", "ignored"):
        if verdict in seen:
            return verdict
    return "absent"


@dataclass
class Verdict:
    platforms: list[Platform]
    spec: Spec
    missing: list[str]
    failures: list[tuple[str, Outcome]]
    skips: list[tuple[str, Outcome]]
    unclaimed_skips: list[tuple[str, Outcome]]
    uncovered: list[tuple[str, list[str]]]  # (test id, families with no pass)
    drift: list[str]
    matrix: dict[str, dict[str, str]]  # test id -> platform -> cell
    status: dict[str, str]  # test id -> verified | owed | retired | unverified
    requirement_status: dict[str, str]

    @property
    def passed(self) -> bool:
        return not (self.missing or self.failures or self.skips or self.uncovered)


def decide(spec: Spec, platforms: list[Platform], expected: list[str]) -> Verdict:
    order = {name: i for i, name in enumerate(expected)}
    platforms = sorted(platforms, key=lambda p: (order.get(p.name, len(order)), p.name))
    by_name = {p.name: p for p in platforms}
    missing = [
        n
        for n in expected
        if n not in by_name or not any(o.tool == "cargo" for o in by_name[n].outcomes)
    ]
    missing += [p.name for p in platforms if not p.pytest_ran and p.name not in missing]
    for p in platforms:
        p.outcomes = _merge_outcomes(p.outcomes)

    failures = [(p.name, o) for p in platforms for o in p.outcomes if o.outcome == "failed"]
    skipped = [(p.name, o) for p in platforms for o in p.outcomes if o.outcome == "skipped"]
    skips = [(n, o) for n, o in skipped if o.ids]
    unclaimed_skips = [(n, o) for n, o in skipped if not o.ids]

    matrix: dict[str, dict[str, str]] = {}
    status: dict[str, str] = {}
    uncovered, drift = [], []
    for tid, test in sorted(spec.tests.items()):
        matrix[tid] = {p.name: cell([o for o in p.outcomes if tid in o.ids]) for p in platforms}
        passed_in = {p.family for p in platforms if matrix[tid][p.name] == "passed"}
        if test.retired:
            status[tid] = "retired"
        elif tid in spec.owed:
            status[tid] = "owed"
            if passed_in:
                drift.append(tid)
        else:
            lacking = sorted((test.scope or set()) - passed_in) or ([] if passed_in else ["any"])
            status[tid] = "unverified" if lacking else "verified"
            if lacking:
                uncovered.append((tid, lacking))

    requirement_status = {}
    for req, primary in spec.requirements.items():
        if req in spec.retired_requirements:
            requirement_status[req] = "retired"
            continue
        direct = any(req in o.ids and o.outcome == "passed" for p in platforms for o in p.outcomes)
        states = [status.get(t, "unverified") for t in primary if status.get(t) != "retired"]
        if (states and all(s == "verified" for s in states)) or (not states and direct):
            requirement_status[req] = "verified"
        elif "verified" in states or direct:
            requirement_status[req] = "partial"
        else:
            requirement_status[req] = "unverified"
    return Verdict(
        platforms,
        spec,
        missing,
        failures,
        skips,
        unclaimed_skips,
        uncovered,
        drift,
        matrix,
        status,
        requirement_status,
    )


# --- rendering ----------------------------------------------------------------------------------

GLYPH = {
    "passed": "pass",
    "failed": "**FAIL**",
    "skipped": "skip",
    "ignored": "ign",
    "absent": "·",
}


def render_markdown(v: Verdict, title: str) -> str:
    names = [p.name for p in v.platforms]
    out = [f"# {title}: {'PASS' if v.passed else 'FAIL'}", ""]
    out += [
        "| Platform | OS | Landlock ABI | Seatbelt | Rust tests | Harness tests |",
        "|---|---|---|---|---|---|",
    ]
    for p in v.platforms:
        cargo = [o for o in p.outcomes if o.tool == "cargo"]
        py = [o for o in p.outcomes if o.tool == "pytest"]
        out.append(
            f"| {p.name} | {p.host.get('os', '?')} {p.host.get('os-version', '')} "
            f"| {p.host.get('landlock-abi', '—')} | {p.host.get('seatbelt', '—')} "
            f"| {_counts(cargo)} | {_counts(py)} |"
        )
    out.append("")

    blocking = [
        f"- `{n}` left no results (a cargo log with parsable tests, and `pytest.json`)"
        for n in v.missing
    ]
    blocking += [f"- **failed** on `{n}`: `{o.test}` {_ids(o)}" for n, o in v.failures]
    blocking += [
        f"- **skipped at runtime** on `{n}`: `{o.test}` {_ids(o)}: {o.reason}" for n, o in v.skips
    ]
    for tid, fams in v.uncovered:
        where = "platform" if fams == ["any"] else f"{' or '.join(fams)} platform"
        blocking.append(
            f"- `{tid}` ({v.spec.tests[tid].title}) is not on the §10 not-yet-implemented "
            f"list but passed on no {where}"
        )
    out += ["## Blocking", ""] + (blocking or ["None."]) + [""]

    notes = [
        f"- `{tid}` is on the §10 not-yet-implemented list but passed; update §10 and "
        "docs/STATUS.md"
        for tid in v.drift
    ]
    notes += [
        f"- skipped at runtime on `{n}` (no FW ID, not blocking): `{o.test}`: {o.reason}"
        for n, o in v.unclaimed_skips
    ]
    partial = sorted(v.spec.partial)
    notes += [f"- `{t}` is partial per §10 ({v.spec.tests[t].title})" for t in partial]
    out += ["## Notes", ""] + (notes or ["None."]) + [""]

    out += ["## Section 7 tests", ""]
    out += ["| Test | Scope | " + " | ".join(names) + " | Status |"]
    out += ["|---|---|" + "---|" * len(names) + "---|"]
    for tid, row in v.matrix.items():
        test = v.spec.tests[tid]
        scope = " + ".join(sorted(test.scope)) if test.scope else "any"
        cells = " | ".join(GLYPH[row[n]] for n in names)
        out.append(f"| {tid} {test.title} | {scope} | {cells} | {v.status[tid]} |")
    legend = (
        "pass: ran and passed. skip: ran and skipped at runtime. ign: `#[ignore]`, not run. "
        "·: no test carrying the ID ran there. A test carries the IDs in its name and the IDs "
        "leading its first doc line, or its harness markers."
    )
    out += ["", legend, ""]

    states = ("verified", "partial", "unverified", "retired")
    counts = {s: sum(1 for x in v.requirement_status.values() if x == s) for s in states}
    out += [
        "## Requirements (§10 primary tests; informational)",
        "",
        ", ".join(f"{counts[s]} {s}" for s in states) + ".",
        "",
    ]
    for req, state in v.requirement_status.items():
        if state in ("partial", "unverified"):
            primary = ", ".join(v.spec.requirements[req]) or "none named"
            out.append(f"- `{req}` {state}: primary tests {primary}")
    out.append("")
    return "\n".join(out)


def _counts(outcomes: list[Outcome]) -> str:
    tally = {k: sum(1 for o in outcomes if o.outcome == k) for k in ("passed", "failed", "skipped")}
    return f"{tally['passed']} passed, {tally['failed']} failed, {tally['skipped']} skipped"


def _ids(o: Outcome) -> str:
    return "(" + ", ".join(sorted(o.ids)) + ")" if o.ids else ""


def to_json(v: Verdict) -> dict:
    evidence: dict[str, list[dict]] = {}
    for p in v.platforms:
        for o in p.outcomes:
            for tid in sorted(o.ids & set(v.spec.tests)):
                evidence.setdefault(tid, []).append(
                    {"platform": p.name, "tool": o.tool, "test": o.test, "outcome": o.outcome}
                )
    return {
        "passed": v.passed,
        "platforms": [{"name": p.name, "family": p.family, "host": p.host} for p in v.platforms],
        "missing": v.missing,
        "failures": [{"platform": n, "test": o.test, "ids": sorted(o.ids)} for n, o in v.failures],
        "skips": [
            {"platform": n, "test": o.test, "ids": sorted(o.ids), "reason": o.reason}
            for n, o in v.skips
        ],
        "unclaimed_skips": [
            {"platform": n, "test": o.test, "reason": o.reason} for n, o in v.unclaimed_skips
        ],
        "uncovered": [{"test": t, "families": f} for t, f in v.uncovered],
        "drift": v.drift,
        "matrix": v.matrix,
        "status": v.status,
        "evidence": evidence,
        "requirements": v.requirement_status,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--results", type=Path, required=True, help="one subdirectory per platform")
    parser.add_argument(
        "--expect", default="", help="comma-separated platform names, in column order"
    )
    parser.add_argument("--markdown", type=Path, help="write the summary here")
    parser.add_argument("--json", type=Path, help="write the full matrix here")
    parser.add_argument("--title", default="End-to-end verification")
    args = parser.parse_args(argv)
    try:
        spec = load_spec()
        index = scan_rust()
        dirs = sorted(d for d in args.results.iterdir() if d.is_dir())
        platforms = [load_platform(d, index) for d in dirs]
    except (SpecError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"e2e_matrix: {exc}", file=sys.stderr)
        return 2
    expected = [n for n in args.expect.split(",") if n]
    if expected:
        stray = [p.name for p in platforms if p.name not in expected]
        for name in stray:
            print(f"e2e_matrix: ignoring {name}: not an expected platform", file=sys.stderr)
        platforms = [p for p in platforms if p.name in expected]
    verdict = decide(spec, platforms, expected)
    markdown = render_markdown(verdict, args.title)
    if args.markdown:
        args.markdown.write_text(markdown)
    else:
        print(markdown)
    if args.json:
        args.json.write_text(json.dumps(to_json(verdict), indent=1))
    return 0 if verdict.passed else 1


if __name__ == "__main__":
    sys.exit(main())
