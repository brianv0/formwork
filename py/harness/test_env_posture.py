"""Environment-posture E2E (FW-ENV1/2), driven through the `formwork` CLI. The FW-ENV2 heuristic
scrub is unit-tested in the Rust crate; this is its end-to-end scenario -- launch a confined child
under the shipped default profile's scrub and inspect the environment it actually receives.

Distinct from the credential-catalog env strip (FW-E2E-046): that drops a KNOWN type by name; this
is the heuristic that drops anything secret-shaped by NAME or VALUE, minus a blueprint allowlist.
macOS-marked because it launches a confined child via `formwork run`."""

from pathlib import Path

import pytest

from helpers import REPO_ROOT

pytestmark = pytest.mark.macos

DEFAULT_PROFILE = REPO_ROOT / "profiles" / "default.toml"

_PEM_VALUE = "-----BEGIN RSA PRIVATE KEY-----\\nMIIFAKE\\n-----END RSA PRIVATE KEY-----"


@pytest.mark.fw_e2e("FW-E2E-036")
def test_secret_shaped_env_scrubbed_allowlist_survives(cli, tmp_path):
    """Under the default profile's scrub, a confined child's environment has the secret-shaped vars
    removed -- by name (AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN) and by value (a PEM-valued var whose
    NAME is innocuous, so only the FW-ENV2 value heuristic catches it) -- while the model API key
    survives so the workload still reaches its API, and an ordinary var is untouched.

    The model key is allowlisted at the blueprint level with `--allow-cred anthropic`: ANTHROPIC is a
    *catalogued* credential type, so its lift is FW-CRED5's typed exclude (which also exempts it from
    the FW-ENV2 shape heuristic, launcher.rs), not the scrub's `allow` list -- that list is for
    non-catalogued false positives. The pure heuristic drops (the PEM value here) are the FW-ENV2
    crux this test exists to pin end to end."""
    home = (tmp_path / "home")
    home.mkdir()
    probe = (
        'echo "aws=${AWS_SECRET_ACCESS_KEY-UNSET}";'
        ' echo "ghtok=${GITHUB_TOKEN-UNSET}";'
        ' echo "pem=${SERVICE_BLOB-UNSET}";'
        ' echo "anthropic=${ANTHROPIC_API_KEY-UNSET}";'
        ' echo "ordinary=${ORDINARY_VAR-UNSET}"'
    )
    res = cli(
        "run", "--blueprint", DEFAULT_PROFILE, "--allow-cred", "anthropic",
        "--", "/bin/sh", "-c", probe,
        cwd=home,
        env={
            "HOME": str(home),
            "AWS_SECRET_ACCESS_KEY": "aws-secret-value",   # name-shape (SECRET/ACCESS_KEY)
            "GITHUB_TOKEN": "ghp_fakefakefakefake",        # name-shape (TOKEN)
            "SERVICE_BLOB": _PEM_VALUE,                    # value-shape only: name is innocuous
            "ANTHROPIC_API_KEY": "sk-ant-allowlisted",     # catalogued model key, lifted by --allow-cred
            "ORDINARY_VAR": "survives",
        },
    )
    assert res.code == 0, res.stderr
    # Secret-shaped vars absent -- not empty -- in the child (FW-INV7): ${VAR-UNSET} prints UNSET.
    assert "aws=UNSET" in res.stdout, res.stdout
    assert "ghtok=UNSET" in res.stdout, res.stdout
    assert "pem=UNSET" in res.stdout, res.stdout
    # The allowlisted model API key survives; the ordinary var is untouched.
    assert "anthropic=sk-ant-allowlisted" in res.stdout, res.stdout
    assert "ordinary=survives" in res.stdout, res.stdout
    # No secret value ever appears anywhere -- not even in formwork's own telemetry (names only).
    assert "aws-secret-value" not in res.stdout + res.stderr
    assert "BEGIN RSA PRIVATE KEY" not in res.stdout + res.stderr


@pytest.mark.fw_e2e("FW-E2E-036")
def test_env_scrub_reported_partial_not_overclaimed(cli, tmp_path):
    """The heuristic scrub is honest about its own fidelity: the env capability is reported Partial
    (never enforced), because a shape heuristic cannot promise it caught every secret (FW-INV5)."""
    import json

    bp = tmp_path / "bp.toml"
    bp.write_text('env = { scrub = { allow = ["ANTHROPIC_API_KEY"] } }\n[fs]\nread-mode = "closed"\nreads = ["/work/**"]\n')
    res = cli("compile", "--blueprint", bp, "--target", "macos", "--report-only",
              env={"HOME": str(tmp_path)})
    assert res.code == 0, res.stderr
    caps = json.loads(res.stdout)["per-capability"]
    env_cap = next((v for k, v in caps.items() if "env" in k.lower()), None)
    assert env_cap is not None, f"no env capability in report: {sorted(caps)}"
    assert env_cap["status"] == "partial", f"heuristic scrub must report Partial, got {env_cap}"
