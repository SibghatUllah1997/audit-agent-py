from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def write(tmp_dir: Path, rel: str, text: str) -> Path:
    p = tmp_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def run_cli(path: Path) -> subprocess.CompletedProcess[str]:
    # Use the current interpreter to run module entrypoint
    return subprocess.run(
        [sys.executable, "-m", "sibaudit", str(path)],
        capture_output=True,
        text=True,
        cwd=str(path.parent if path.is_file() else path),
    )


def test_cli_prints_findings_and_nonzero_exit(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract D {
        function i(address target) external {
            target.call(abi.encodeWithSignature("ping()")); // unchecked
            address a = tx.origin; // risky
        }
    }
    """.strip()
    dir_path = tmp_path / "contracts"
    file_path = write(dir_path, "D.sol", code)

    proc = run_cli(dir_path)

    assert proc.returncode == 1
    out = proc.stdout.strip()
    # Expect at least two findings with codes A001 and A002
    assert "A001" in out and "A002" in out
    assert str(file_path)[:10] in out  # partial path check

