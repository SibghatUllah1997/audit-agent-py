from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, body: str) -> list[str]:
    (tmp_path / "C.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract C {\n" + body + "\n}\n"
    )
    return [f.code for f in scan_paths([str(tmp_path)])]


def test_flags_assert_on_msg_value(tmp_path: Path) -> None:
    body = "function buy() external payable { assert(msg.value >= 1 ether); }"
    assert "A011" in _scan(tmp_path, body)


def test_flags_assert_on_balance(tmp_path: Path) -> None:
    body = "function pay(address a) external view { assert(a.balance > 0); }"
    assert "A011" in _scan(tmp_path, body)


def test_allows_invariant_assert(tmp_path: Path) -> None:
    body = "uint256 total;\nfunction f(uint256 x) internal { total += x; assert(total >= x); }"
    assert "A011" not in _scan(tmp_path, body)


def test_ignore_directive_skips_assert(tmp_path: Path) -> None:
    body = (
        "function f() external payable {\n"
        "// sibaudit:ignore-next-line\nassert(msg.value > 0);\n}"
    )
    assert "A011" not in _scan(tmp_path, body)
