"""Network egress E2E (design §7.2), driven through the `formwork` CLI. macOS-only for now."""

import textwrap

import pytest

from helpers import write_spec

pytestmark = pytest.mark.macos

# Exit 0 = connected (LEAK); 7 = denied at connect(); 8 = other failure. Require 7 so a startup
# failure can't masquerade as a denial.
_CONNECT_PROBE = textwrap.dedent(
    """
    import socket, sys
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect(('93.184.216.34', 80)); sys.exit(0)
    except PermissionError:
        sys.exit(7)
    except Exception:
        sys.exit(8)
    """
)


@pytest.mark.fw_e2e("FW-E2E-006")
def test_direct_egress_denied(cli, workspace, tmp_path):
    spec = write_spec(
        tmp_path / "spec.toml",
        reads=[f"{workspace.granted}/**"],
        writes=[f"{workspace.granted}/**"],
    )
    # cwd inside the granted dir so the interpreter's sys.path scan doesn't trip on an unreadable cwd.
    result = cli(
        "run", "--spec", spec, "--", "/usr/bin/python3", "-c", _CONNECT_PROBE,
        cwd=workspace.granted,
    )
    assert result.code == 7, (
        f"expected denial at connect() (exit 7), got code={result.code} stderr={result.stderr!r}"
    )
