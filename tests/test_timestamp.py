from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def write(tmp_dir: Path, rel: str, text: str) -> Path:
    p = tmp_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_detects_block_timestamp_usage(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Timey {
        function when() external view returns (uint256) {
            return block.timestamp; // time usage
        }
    }
    """.strip()
    file_path = write(tmp_path, "Timey.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert any(f.code == "A006" and f.file_path == file_path for f in findings)


def test_ignore_next_line_skips_timestamp(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Timey2 {
        // sibaudit:ignore-next-line
        function nowish() external view returns (uint256) { return block.timestamp; }
        function later() external view returns (uint256) { return block.timestamp; }
    }
    """.strip()
    file_path = write(tmp_path, "Timey2.sol", code)
    findings = scan_paths([str(tmp_path)])
    # One ignored, one reported
    assert sum(1 for f in findings if f.code == "A006" and f.file_path == file_path) == 1

