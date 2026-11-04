from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, body: str) -> list[str]:
    (tmp_path / "C.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract C {\n" + body + "\n}\n"
    )
    return [f.code for f in scan_paths([str(tmp_path)])]


def test_flags_gasprice_check(tmp_path: Path) -> None:
    body = "function f() external view returns (bool) { return tx.gasprice > 50 gwei; }"
    assert "A010" in _scan(tmp_path, body)


def test_ignores_gasprice_in_comment(tmp_path: Path) -> None:
    body = "function f() external pure returns (uint256) { return 1; } // tx.gasprice"
    assert "A010" not in _scan(tmp_path, body)


def test_ignore_directive_skips_gasprice(tmp_path: Path) -> None:
    body = "// sibaudit:ignore-next-line\nuint256 g = tx.gasprice;"
    assert "A010" not in _scan(tmp_path, body)
