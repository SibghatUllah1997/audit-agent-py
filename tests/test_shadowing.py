from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def write(tmp_dir: Path, rel: str, text: str) -> Path:
    p = tmp_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_state_variable_shadowed_by_parameter(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract H {
        address public owner;
        function setOwner(address owner) external { // shadows state variable
            // no-op
        }
    }
    """.strip()
    file_path = write(tmp_path, "H.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert any(
        f.code == "A005" and f.file_path == file_path and "shadows a state variable" in f.message
        for f in findings
    )

