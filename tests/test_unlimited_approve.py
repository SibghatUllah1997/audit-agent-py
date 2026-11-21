from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths

IFACE = (
    "interface IERC20 {\n"
    "    function approve(address spender, uint256 amount) external returns (bool);\n"
    "}\n"
)


def _scan(tmp_path: Path, source: str) -> list:
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A030"]


def _contract(body: str) -> str:
    return f"pragma solidity 0.8.20;\n{IFACE}contract C {{\n{body}\n}}\n"


def test_flags_type_uint256_max(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function allow(address spender) external {\n"
        "    require(token.approve(spender, type(uint256).max), \"failed\");\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "MEDIUM"
    assert "unlimited allowance" in finding.message
    assert "type(uint256).max" in finding.line_text
    assert "finite" in finding.message


def test_flags_type_uint_max_minus_one(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function allow(address spender) external {\n"
        "    token.approve(spender, type(uint).max - 1);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "type(uint).max - 1" in findings[0].line_text


def test_flags_not_zero_and_pow_and_hex(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function allow(address spender) external {\n"
        "    require(token.approve(spender, ~uint256(0)), \"a\");\n"
        "    require(token.approve(spender, 2 ** 256 - 1), \"b\");\n"
        "    require(token.approve(spender, "
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff), \"c\");\n"
        "    require(token.approve(spender, uint256(-1)), \"d\");\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 4


def test_flags_cast_and_named_constant(tmp_path: Path) -> None:
    body = (
        "uint256 public constant MAX = type(uint256).max;\n"
        "function allow(address t, address spender) external {\n"
        "    require(IERC20(t).approve(spender, MAX), \"failed\");\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "IERC20(t).approve" in findings[0].line_text


def test_flags_local_alias(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function allow(address spender) external {\n"
        "    uint256 amount = type(uint256).max;\n"
        "    require(token.approve(spender, amount), \"failed\");\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "token.approve(spender, amount)" in findings[0].line_text


def test_flags_parenthesized_and_multiline(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function allow(address spender) external {\n"
        "    require(token.approve(\n"
        "        spender,\n"
        "        (type(uint256).max)\n"
        "    ), \"failed\");\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "token.approve(" in findings[0].line_text


def test_finite_amount_and_zero_are_clean(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function allow(address spender, uint256 amount) external {\n"
        "    require(token.approve(spender, amount), \"a\");\n"
        "    require(token.approve(spender, 0), \"b\");\n"
        "    require(token.approve(spender, 1e18), \"c\");\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_ether_and_nft_are_not_flagged(tmp_path: Path) -> None:
    body = (
        "IERC721 public nft;\n"
        "function pay(address payable to) external {\n"
        "    to.transfer(type(uint256).max);\n"
        "}\n"
        "function move(address spender) external {\n"
        "    nft.approve(spender, type(uint256).max);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_transfer_is_not_this_rule(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function pay(address to) external {\n"
        "    require(token.transfer(to, type(uint256).max), \"failed\");\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_commented_call_and_ignore_directive(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function allow(address spender) external {\n"
        "    // token.approve(spender, type(uint256).max);\n"
        "    // sibaudit:ignore-next-line\n"
        "    require(token.approve(spender, type(uint256).max), \"failed\");\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))
