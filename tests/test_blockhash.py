from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, body: str) -> list:
    (tmp_path / "C.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract C {\n" + body + "\n}\n"
    )
    return scan_paths([str(tmp_path)])


def test_flags_blockhash_of_previous_block(tmp_path: Path) -> None:
    body = "function f() external view returns (bytes32) { return blockhash(block.number - 1); }"
    findings = _scan(tmp_path, body)
    assert any(f.code == "A013" and "miner-influenceable" in f.message for f in findings)


def test_flags_blockhash_of_current_block(tmp_path: Path) -> None:
    body = "function f() external view returns (bytes32) { return blockhash(block.number); }"
    findings = _scan(tmp_path, body)
    assert any(f.code == "A013" and "always zero" in f.message for f in findings)


def test_ignores_blockhash_in_comment(tmp_path: Path) -> None:
    body = "function f() external pure returns (uint256) { return 1; } // blockhash(block.number)"
    findings = _scan(tmp_path, body)
    assert not any(f.code == "A013" for f in findings)


def test_ignore_directive_skips_blockhash(tmp_path: Path) -> None:
    body = "// sibaudit:ignore-next-line\nbytes32 h = blockhash(block.number - 1);"
    findings = _scan(tmp_path, body)
    assert not any(f.code == "A013" for f in findings)
