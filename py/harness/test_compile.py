"""Compiler E2E (design §7.6) via the `formwork` CLI. Cross-platform: the compiler is pure, so these
carry no platform marker and run on every host."""

import json

import pytest

from helpers import write_blueprint


@pytest.mark.fw_e2e("FW-E2E-026")
def test_dry_run_cross_platform_compile(cli, tmp_path):
    blueprint = write_blueprint(tmp_path / "blueprint.toml", reads=["/work/project/**"], writes=["/work/project/**"])
    for target in ("macos", "linux-v6", "linux-v1"):
        result = cli("compile", "--blueprint", blueprint, "--target", target, "--report-only")
        assert result.code == 0, result.stderr
        report = json.loads(result.stdout)
        assert "per-capability" in report
        assert "fs-read" in report["per-capability"]
        assert "net-default-deny" in report["per-capability"]  # net always accounted for (FW-INV6)


@pytest.mark.fw_e2e("FW-E2E-026")
def test_degraded_host_reports_unenforceable(cli, tmp_path):
    blueprint = write_blueprint(tmp_path / "blueprint.toml", reads=["/work/project/**"])
    result = cli("compile", "--blueprint", blueprint, "--target", "linux-v1", "--report-only")
    report = json.loads(result.stdout)
    net = report["per-capability"]["net-default-deny"]
    assert net["status"] in ("enforced", "partial"), "net must never be silently open"


@pytest.mark.fw_e2e("FW-E2E-027")
def test_deterministic_compile_byte_identical(cli, tmp_path):
    blueprint = write_blueprint(
        tmp_path / "blueprint.toml",
        reads=["/work/**"],
        writes=["/work/project/**"],
        subtract=["/work/.ssh/**"],
    )
    a = cli("compile", "--blueprint", blueprint, "--target", "linux-v4")
    b = cli("compile", "--blueprint", blueprint, "--target", "linux-v4")
    assert a.code == 0 and b.code == 0
    assert a.stdout == b.stdout, "same blueprint + target must compile byte-identically"


@pytest.mark.fw_e2e("FW-E2E-026")
def test_detect_runs_on_this_host(cli):
    result = cli("detect")
    assert result.code == 0, result.stderr
    profile = json.loads(result.stdout)
    assert profile["os"] in ("macos", "linux")
    assert "seccomp" in profile and "seatbelt" in profile
