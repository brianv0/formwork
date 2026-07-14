"""Network egress E2E (design §7.2), driven through the `formwork` CLI. macOS-only for now."""

import textwrap

import pytest

from helpers import write_blueprint

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
    blueprint = write_blueprint(
        tmp_path / "blueprint.toml",
        reads=[f"{workspace.granted}/**"],
        writes=[f"{workspace.granted}/**"],
    )
    # cwd inside the granted dir so the interpreter's sys.path scan doesn't trip on an unreadable cwd.
    result = cli(
        "run", "--blueprint", blueprint, "--", "/usr/bin/python3", "-c", _CONNECT_PROBE,
        cwd=workspace.granted,
    )
    assert result.code == 7, (
        f"expected denial at connect() (exit 7), got code={result.code} stderr={result.stderr!r}"
    )


# Direct name resolution rides UDP/TCP 53 to a resolver. Under net-deny the transport is blocked at
# the kernel, so both raise PermissionError -- exit 7. A resolver reachable on either (exit 0) is a
# leak. The high-level getaddrinfo (which macOS delegates to mDNSResponder) is checked as a
# secondary signal, but the primary assertion is the raw transport the spec names.
_DNS_PROBE = textwrap.dedent(
    """
    import socket, sys
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
        u.sendto(b'\\x00\\x00', ('1.1.1.1', 53)); sys.exit(0)
    except PermissionError:
        pass
    except Exception:
        sys.exit(8)
    try:
        t = socket.socket(); t.settimeout(3); t.connect(('1.1.1.1', 53)); sys.exit(0)
    except PermissionError:
        sys.exit(7)
    except Exception:
        sys.exit(8)
    """
)

# Ignore any proxy environment and open a raw socket straight at a remote host. A cooperative
# (proxy-env-only) enforcement would let this through; a kernel one denies it. Exit 7 = denied.
_PROXY_BYPASS_PROBE = textwrap.dedent(
    """
    import socket, sys, os
    # Prove the program sees the proxy vars and ignores them anyway (this is the bypass attempt).
    assert os.environ.get('HTTP_PROXY') and os.environ.get('ALL_PROXY')
    s = socket.socket(); s.settimeout(3)
    try:
        s.connect(('93.184.216.34', 80)); sys.exit(0)
    except PermissionError:
        sys.exit(7)
    except Exception:
        sys.exit(8)
    """
)


@pytest.mark.fw_e2e("FW-E2E-007")
def test_direct_dns_denied(cli, workspace, tmp_path):
    """Direct name resolution (UDP/TCP 53 to a resolver) is denied under net-deny; the transport is
    blocked at the kernel, not merely unconfigured. Resolution is available only through the gateway."""
    blueprint = write_blueprint(
        tmp_path / "blueprint.toml",
        reads=[f"{workspace.granted}/**"],
        writes=[f"{workspace.granted}/**"],
    )
    result = cli(
        "run", "--blueprint", blueprint, "--", "/usr/bin/python3", "-c", _DNS_PROBE,
        cwd=workspace.granted,
    )
    assert result.code == 7, (
        f"expected DNS transport denied (exit 7), got code={result.code} stderr={result.stderr!r}"
    )


# Read a "host:port" endpoint out of a granted file (standing in for an MCP tool's metadata the
# agent can see) and try to reach it directly. Exit 7 = denied.
_METADATA_EGRESS_PROBE = textwrap.dedent(
    """
    import socket, sys
    host, port = open(sys.argv[1]).read().strip().rsplit(':', 1)
    s = socket.socket(); s.settimeout(3)
    try:
        s.connect((host, int(port))); sys.exit(0)
    except PermissionError:
        sys.exit(7)
    except Exception:
        sys.exit(8)
    """
)


@pytest.mark.fw_adv("FW-ADV-003")
def test_gateway_bypass_direct_egress_denied(cli, workspace, tmp_path):
    """The agent extracts an MCP endpoint host from a granted tool's metadata and tries to reach it
    directly, outside the gateway. Direct egress is denied under net-deny: the gateway fd is the only
    path to the network. (The positive 'and the gateway fd does reach it' half is the seam
    productization tracked as cluster A in docs/gaps-plan.md, not yet a shipped command.)"""
    meta = workspace.granted / "tool-metadata.txt"
    meta.write_text("93.184.216.34:80\n")  # an endpoint 'discovered' in a granted tool's metadata
    blueprint = write_blueprint(
        tmp_path / "blueprint.toml",
        reads=[f"{workspace.granted}/**"],
        writes=[f"{workspace.granted}/**"],
    )
    result = cli(
        "run", "--blueprint", blueprint, "--", "/usr/bin/python3", "-c", _METADATA_EGRESS_PROBE,
        str(meta), cwd=workspace.granted,
    )
    assert result.code == 7, (
        f"direct egress to the extracted endpoint must be denied (exit 7), got code={result.code} "
        f"stderr={result.stderr!r}"
    )


@pytest.mark.fw_e2e("FW-E2E-008")
def test_proxy_env_bypass_denied(cli, workspace, tmp_path):
    """A program that ignores HTTP_PROXY/ALL_PROXY and opens a raw socket is still denied: enforcement
    is at the kernel, not a cooperative proxy convention, so there is no proxy-env-only bypass."""
    blueprint = write_blueprint(
        tmp_path / "blueprint.toml",
        reads=[f"{workspace.granted}/**"],
        writes=[f"{workspace.granted}/**"],
    )
    result = cli(
        "run", "--blueprint", blueprint, "--", "/usr/bin/python3", "-c", _PROXY_BYPASS_PROBE,
        cwd=workspace.granted,
        env={"HTTP_PROXY": "http://127.0.0.1:9", "ALL_PROXY": "socks5://127.0.0.1:9"},
    )
    assert result.code == 7, (
        f"expected raw connect denied despite proxy env (exit 7), got code={result.code} "
        f"stderr={result.stderr!r}"
    )
