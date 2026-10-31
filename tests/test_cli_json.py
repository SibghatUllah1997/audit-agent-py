from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def write(tmp_dir: Path, rel: str, text: str) -> Path:
    p = tmp_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def run_cli_json(path: Path) -> subprocess.CompletedProcess[str]:
    # Use the current interpreter to run module entrypoint with JSON format
    return subprocess.run(
        [sys.executable, "-m", "sibaudit", "--format", "json", str(path)],
        capture_output=True,
        text=True,
        cwd=str(path.parent if path.is_file() else path),
    )


def test_cli_json_outputs_findings_and_nonzero_exit(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract JJ {
        function k(address target) external {
            target.call(abi.encodeWithSignature("ping()")); // unchecked
            address a = tx.origin; // risky
        }
    }
    """.strip()
    dir_path = tmp_path / "contracts"
    file_path = write(dir_path, "JJ.sol", code)

    proc = run_cli_json(dir_path)
    assert proc.returncode == 1
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert len(lines) >= 2
    parsed = [json.loads(ln) for ln in lines]
    codes = {p["code"] for p in parsed}
    assert {"A001", "A002"} <= codes
    # Severities should be present and valid
    severities = {p.get("severity") for p in parsed}
    assert severities <= {"LOW", "MEDIUM", "HIGH"}
    assert any(p["severity"] in {"LOW", "MEDIUM", "HIGH"} for p in parsed)
    # At least some records should reference the created file
    assert any(str(file_path) in p["file_path"] for p in parsed)

