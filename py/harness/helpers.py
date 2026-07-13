"""Shared helpers for the Formwork harness. Black-box on purpose: it drives the `formwork` CLI the
way an embedder would and never links the Rust crates, keeping it honest about the shipped interface."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

# py/harness/helpers.py -> repo root is two parents up.
REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class CliResult:
    code: int
    stdout: str
    stderr: str


def run_cli(
    binary: Path,
    *args,
    cwd: Path | None = None,
    timeout: int = 60,
    env: dict[str, str] | None = None,
) -> CliResult:
    """`env` overlays the inherited environment -- the credential tests use it to point $HOME at
    a fake home with planted (fake) credentials and to inject secret-shaped variables."""
    merged = {**os.environ, **env} if env is not None else None
    proc = subprocess.run(
        [str(binary), *(str(a) for a in args)],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=merged,
    )
    return CliResult(proc.returncode, proc.stdout, proc.stderr)


@dataclass
class Workspace:
    """A scratch layout with an in-scope `granted/` tree and an out-of-scope `secret/` tree. Paths
    are symlink-resolved so they match what the kernel enforces (macOS /var -> /private/var)."""

    root: Path

    @property
    def granted(self) -> Path:
        return self.root / "granted"

    @property
    def granted_file(self) -> Path:
        return self.granted / "ok.txt"

    @property
    def secret(self) -> Path:
        return self.root / "secret"

    @property
    def secret_file(self) -> Path:
        return self.secret / "secret.env"


def make_workspace(tmp_path: Path) -> Workspace:
    root = Path(os.path.realpath(tmp_path))
    (root / "granted").mkdir(parents=True, exist_ok=True)
    (root / "secret").mkdir(parents=True, exist_ok=True)
    (root / "granted" / "ok.txt").write_text("in-scope contents\n")
    (root / "secret" / "secret.env").write_text("TOP SECRET\n")
    return Workspace(root)


def _toml_array(items) -> str:
    return "[" + ", ".join(f'"{i}"' for i in items) + "]"


def write_blueprint(
    path: Path,
    *,
    net: str = "deny",
    read_mode: str = "closed",
    reads=(),
    writes=(),
    subtract=(),
) -> Path:
    """Write a Formwork blueprint TOML."""
    body = "\n".join(
        [
            f'net = "{net}"',
            "[fs]",
            f'read-mode = "{read_mode}"',
            f"reads = {_toml_array(reads)}",
            f"writes = {_toml_array(writes)}",
            f"subtract = {_toml_array(subtract)}",
            "",
        ]
    )
    path.write_text(body)
    return path
