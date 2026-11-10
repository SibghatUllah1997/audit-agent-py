from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, body: str) -> list:
    (tmp_path / "C.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract C {\n" + body + "\n}\n"
    )
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A016"]


def test_flags_setter_that_stores_address_without_check(tmp_path: Path) -> None:
    body = (
        "address public treasury;\n"
        "function setTreasury(address newTreasury) external {\n"
        "    treasury = newTreasury;\n"
        "}"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert 'Address parameter "newTreasury"' in findings[0].message
    assert "treasury = newTreasury" in findings[0].line_text


def test_allows_require_not_equal_address_zero(tmp_path: Path) -> None:
    body = (
        "address public owner;\n"
        "function setOwner(address newOwner) external {\n"
        "    require(newOwner != address(0));\n"
        "    owner = newOwner;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_allows_address_zero_on_the_left(tmp_path: Path) -> None:
    body = (
        "address public guardian;\n"
        "function setGuardian(address next) external {\n"
        "    require(address(0) != next, \"zero\");\n"
        "    guardian = next;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_allows_if_equal_zero_revert(tmp_path: Path) -> None:
    body = (
        "address public token;\n"
        "function setToken(address next) external {\n"
        "    if (next == address(0)) revert();\n"
        "    token = next;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_allows_address_0x0_check(tmp_path: Path) -> None:
    body = (
        "address payable public feeTo;\n"
        "function setFeeTo(address payable next) external {\n"
        "    require(next != address(0x0));\n"
        "    feeTo = next;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_flags_payable_wrap_assignment(tmp_path: Path) -> None:
    body = (
        "address payable public vault;\n"
        "function setVault(address next) external {\n"
        "    vault = payable(next);\n"
        "}"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "payable(next)" in findings[0].line_text


def test_does_not_flag_mapping_key_usage(tmp_path: Path) -> None:
    body = (
        "mapping(address => uint256) public balances;\n"
        "function mint(address to, uint256 amount) external {\n"
        "    balances[to] += amount;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_does_not_flag_local_copy(tmp_path: Path) -> None:
    body = (
        "function stash(address who) external {\n"
        "    address tmp = who;\n"
        "    tmp;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_does_not_flag_local_then_assign(tmp_path: Path) -> None:
    body = (
        "function copy(address who) external {\n"
        "    address dest;\n"
        "    dest = who;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_does_not_flag_view_function(tmp_path: Path) -> None:
    body = (
        "address public owner;\n"
        "function peek(address who) external view returns (address) {\n"
        "    who;\n"
        "    return owner;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_ignore_directive_skips_assignment(tmp_path: Path) -> None:
    body = (
        "address public treasury;\n"
        "function setTreasury(address newTreasury) external {\n"
        "    // sibaudit:ignore-next-line\n"
        "    treasury = newTreasury;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_comment_assignment_is_ignored(tmp_path: Path) -> None:
    body = (
        "address public owner;\n"
        "function setOwner(address newOwner) external {\n"
        "    require(newOwner != address(0));\n"
        "    owner = newOwner;\n"
        "    // owner = newOwner;\n"
        "}"
    )
    assert not _scan(tmp_path, body)
