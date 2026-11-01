from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def write(tmp_dir: Path, rel: str, text: str) -> Path:
    p = tmp_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_flags_arithmetic_in_pre_0_8(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.7.6;
    contract Mathy {
        function add(uint256 a, uint256 b) external pure returns (uint256) {
            uint256 c = a + b; // potential overflow pre-0.8
            return c;
        }
    }
    """.strip()
    file_path = write(tmp_path, "MathyPre.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert any(f.code == "A007" and f.file_path == file_path for f in findings)


def test_does_not_flag_arithmetic_in_0_8_plus(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Mathy2 {
        function sub(uint256 a, uint256 b) external pure returns (uint256) {
            return a - b; // checked by compiler in 0.8+
        }
    }
    """.strip()
    write(tmp_path, "Mathy08.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert not any(f.code == "A007" for f in findings)

