"""Canaries for the cross-platform verdict (py/e2e_matrix.py, run by e2e-verify.yml on main). It
reads formwork.md sections 7 and 10 and libtest's text output, so a reworded heading or a changed
libtest layout must fail here, on every pull request, rather than turn main's verdict vacuous."""

import sys

from helpers import REPO_ROOT

sys.path.insert(0, str(REPO_ROOT / "py"))

import e2e_matrix as m  # noqa: E402


def test_spec_parses_every_section_7_test():
    spec = m.load_spec()
    assert len(spec.tests) >= 100
    assert {"FW-E2E-010", "FW-E2E-011", "FW-E2E-012", "FW-E2E-041"} <= {
        t for t, s in spec.tests.items() if s.retired
    }
    assert "FW-E2E-008" in spec.owed and "FW-ADV-025" in spec.owed
    assert {"FW-E2E-021", "FW-E2E-022"} <= spec.owed, "an en-dash range expands"
    assert spec.partial == {"FW-E2E-028", "FW-E2E-092"}
    assert not spec.owed & {t for t, s in spec.tests.items() if s.retired}


def test_titles_name_their_os_families():
    spec = m.load_spec()
    both = frozenset(m.FAMILIES)
    assert spec.tests["FW-E2E-075"].scope == both  # (both)
    assert spec.tests["FW-E2E-098"].scope == both  # (S1; both OSes)
    assert spec.tests["FW-E2E-079"].scope == {"linux"}  # (Linux, both runners)
    assert spec.tests["FW-E2E-009"].scope == {"linux"}  # (Linux, ABI-gated)
    assert spec.tests["FW-ADV-019"].scope == {"macos"}
    assert spec.tests["FW-E2E-001"].scope is None
    assert spec.tests["FW-E2E-055"].scope is None, "a linked ID in parentheses is not a scope"


def test_section_10_shorthand_inherits_the_kind_before_it():
    assert m._expand("[FW-ADV-013](#fw-adv-013), 015") == ["FW-ADV-013", "FW-ADV-015"]
    assert m._expand("[FW-E2E-024](#fw-e2e-024), 025") == ["FW-E2E-024", "FW-E2E-025"]
    assert m._expand("[FW-E2E-020](#fw-e2e-020)–023") == [f"FW-E2E-0{n}" for n in (20, 21, 22, 23)]
    assert m._expand("ADV-001..003") == ["FW-ADV-001", "FW-ADV-002", "FW-ADV-003"]
    spec = m.load_spec()
    assert spec.requirements["FW-DISC3"] == ["FW-ADV-013", "FW-ADV-015"]
    assert "FW-GW6" in spec.retired_requirements


def test_a_test_claims_its_name_and_leading_doc_ids_only():
    assert m.lead_ids(" FW-E2E-001 (Linux/Landlock): an in-scope read") == ["FW-E2E-001"]
    assert m.lead_ids(" FW-GW3 / FW-INV4: `resources/subscribe`") == ["FW-GW3", "FW-INV4"]
    assert m.lead_ids(" FW-ADV-020, the opener route (Linux): see FW-E2E-075") == ["FW-ADV-020"]
    assert m.lead_ids(" Pattern shading (FW-GW9): the regex") == []
    assert m.name_ids("fw_e2e_075_gateway_is_the_sole_egress_path") == ["FW-E2E-075"]
    assert m.name_ids("fw_cred16_the_gateway_is_not_dumpable") == ["FW-CRED16"]
    index = m.scan_rust()
    sole = [t for t in index if t.fn == "fw_e2e_075_gateway_is_the_sole_egress_path"]
    assert sole and all(t.ids == {"FW-E2E-075"} for t in sole)


CARGO_LOG = """\
     Running tests/linux_confine.rs (target/debug/deps/linux_confine-12f5fde0d6f54f9c)

running 4 tests
test landlock_granted_read_ok_ungranted_denied ... ok
test fw_adv_006_cross_domain_unix_socket_reach_around ... ok
test fw_e2e_045_credential_floor_denies_catalog_path_linux ... FAILED
test later_test ... ignored, needs a network

successes:

---- landlock_granted_read_ok_ungranted_denied stdout ----
skipping: no Landlock on this host

---- fw_adv_006_cross_domain_unix_socket_reach_around stdout ----
skipping capable-kernel arm: no Landlock ABI v6 on this host


successes:
    fw_adv_006_cross_domain_unix_socket_reach_around
    landlock_granted_read_ok_ungranted_denied

failures:

---- fw_e2e_045_credential_floor_denies_catalog_path_linux stdout ----
thread 'x' panicked at tests/linux_confine.rs:9:5:
    indented panic text

failures:
    fw_e2e_045_credential_floor_denies_catalog_path_linux

test result: FAILED. 2 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out
     Running tests/latency.rs (target/release/deps/latency-0123456789abcdef)

running 1 test
test fw_e2e_096_latency_budget ... child process noise
ok

successes:
    fw_e2e_096_latency_budget

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
   Doc-tests formwork_blueprint

running 1 test
test crates/formwork-blueprint/src/lib.rs - doc (line 3) ... ok
"""


def test_cargo_log_outcomes_come_from_libtest_lists():
    rows = {(r[0], r[2]): (r[3], r[4]) for r in m.parse_cargo_log(CARGO_LOG)}
    assert rows[("linux_confine", "landlock_granted_read_ok_ungranted_denied")] == (
        "skipped",
        "no Landlock on this host",
    )
    assert rows[("linux_confine", "fw_adv_006_cross_domain_unix_socket_reach_around")] == (
        "passed",
        "",
    ), "a skipped arm is still a pass"
    assert rows[("linux_confine", "fw_e2e_045_credential_floor_denies_catalog_path_linux")][0] == (
        "failed"
    )
    assert rows[("linux_confine", "later_test")][0] == "ignored"
    assert rows[("latency", "fw_e2e_096_latency_budget")][0] == "passed", "output between name and ok"
    assert not any(binary is None or "doc" in test for binary, test in rows)


def _platform(name, family, outcomes):
    p = m.Platform(name, family, {"os": family})
    p.outcomes = [m.Outcome("cargo", t, frozenset(ids), o) for t, ids, o in outcomes]
    p.cargo_logs, p.pytest_ran = 1, True
    return p


def test_verdict_demands_each_named_family():
    spec = m.load_spec()
    linux = _platform("linux-x", "linux", [("a", {"FW-E2E-075"}, "passed")])
    macos = _platform("macos-x", "macos", [("b", {"FW-E2E-001"}, "passed")])
    v = m.decide(spec, [linux, macos], ["linux-x", "macos-x"])
    uncovered = dict(v.uncovered)
    assert uncovered["FW-E2E-075"] == ["macos"], "(both) needs a macOS pass too"
    assert "FW-E2E-001" not in uncovered, "an unmarked test needs one platform"
    assert "FW-E2E-008" not in uncovered, "owed tests are not demanded"
    assert v.status["FW-E2E-010"] == "retired"


def test_verdict_blocks_on_missing_platforms_failures_and_runtime_skips():
    spec = m.load_spec()
    ran = _platform(
        "linux-x",
        "linux",
        [("a", {"FW-E2E-001"}, "failed"), ("b", set(), "skipped"), ("c", {"FW-E2E-008"}, "passed")],
    )
    v = m.decide(spec, [ran], ["linux-x", "macos-x"])
    assert v.missing == ["macos-x"]
    assert [o.test for _, o in v.failures] == ["a"]
    assert [o.test for _, o in v.skips] == ["b"]
    assert v.drift == ["FW-E2E-008"], "an owed test that passes is drift, not a failure"
    assert not v.passed


def test_a_test_rerun_with_ignored_keeps_its_executed_result():
    merged = m._merge_outcomes(
        [
            m.Outcome("cargo", "latency::t", frozenset(), "ignored"),
            m.Outcome("cargo", "latency::t", frozenset(), "passed"),
        ]
    )
    assert [o.outcome for o in merged] == ["passed"]
