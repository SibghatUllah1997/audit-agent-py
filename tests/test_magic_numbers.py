from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, body: str, *, pragma: str = "^0.8.20") -> list:
    (tmp_path / "C.sol").write_text(
        f"pragma solidity {pragma};\ncontract C {{\n" + body + "\n}\n"
    )
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A017"]


def test_flags_fee_literals(tmp_path: Path) -> None:
    body = (
        "function feeOn(uint256 amount) external pure returns (uint256) {\n"
        "    return amount * 25 / 10000;\n"
        "}"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert "25" in findings[0].message
    assert "10000" in findings[0].message
    assert "named constants" in findings[0].message


def test_allows_zero_and_one(tmp_path: Path) -> None:
    body = (
        "function ok(uint256 n) external pure returns (uint256) {\n"
        "    if (n == 0) return 1;\n"
        "    return n + 1;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_allows_named_constant(tmp_path: Path) -> None:
    body = (
        "uint256 public constant FEE_BPS = 25;\n"
        "uint256 public constant BASE = 10000;\n"
        "function feeOn(uint256 amount) external pure returns (uint256) {\n"
        "    return amount * FEE_BPS / BASE;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_treats_underscore_literal_as_one_number(tmp_path: Path) -> None:
    body = (
        "function feeOn(uint256 amount) external pure returns (uint256) {\n"
        "    return amount / 10_000;\n"
        "}"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "10_000" in findings[0].message


def test_allows_immutable_literal(tmp_path: Path) -> None:
    body = "uint256 public immutable LOCK = 7 days;"
    assert not _scan(tmp_path, body)


def test_flags_state_variable_literal(tmp_path: Path) -> None:
    body = "uint256 public feeBps = 25;"
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert findings[0].message == "Magic number 25 is not a named constant."


def test_flags_scientific_wei(tmp_path: Path) -> None:
    body = (
        "function minPay() external pure returns (uint256) {\n"
        "    return 1e18;\n"
        "}"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "1e18" in findings[0].message


def test_skips_pragma_and_type_widths(tmp_path: Path) -> None:
    body = (
        "function id(uint256 n, bytes32 h) external pure returns (uint256) {\n"
        "    h;\n"
        "    return n;\n"
        "}"
    )
    assert not _scan(tmp_path, body, pragma="^0.8.20")


def test_skips_enum_members(tmp_path: Path) -> None:
    body = (
        "enum Phase { Empty, Active, Closed }\n"
        "function current() external pure returns (Phase) {\n"
        "    return Phase.Active;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_skips_hex_literals(tmp_path: Path) -> None:
    body = (
        "bytes4 public constant SELECTOR = 0xa9059cbb;\n"
        "function sel() external pure returns (bytes4) {\n"
        "    return 0xa9059cbb;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_ignore_directive_skips_literal(tmp_path: Path) -> None:
    body = (
        "function feeOn(uint256 amount) external pure returns (uint256) {\n"
        "    // sibaudit:ignore-next-line\n"
        "    return amount * 25 / 10000;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_comment_literal_is_ignored(tmp_path: Path) -> None:
    body = (
        "function f() external pure returns (uint256) {\n"
        "    return 1; // was 100 last week\n"
        "}"
    )
    assert not _scan(tmp_path, body)
