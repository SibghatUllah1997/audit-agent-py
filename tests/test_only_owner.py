from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, body: str, *, extra: str = "") -> list:
    (tmp_path / "C.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract C {\n    address public owner;\n"
        + extra
        + body
        + "\n}\n"
    )
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A020"]


def test_flags_empty_only_owner(tmp_path: Path) -> None:
    body = "modifier onlyOwner() { _; }\nfunction bump() external onlyOwner {}\n"
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert 'Modifier "onlyOwner" never checks the caller' in findings[0].message
    assert "modifier onlyOwner()" in findings[0].line_text


def test_flags_check_after_placeholder(tmp_path: Path) -> None:
    body = (
        "modifier onlyOwner() {\n"
        "    _;\n"
        "    require(msg.sender == owner);\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "after the function body runs" in findings[0].message


def test_flags_tx_origin_auth(tmp_path: Path) -> None:
    body = (
        "modifier onlyOwner() {\n"
        "    require(tx.origin == owner);\n"
        "    _;\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "tx.origin" in findings[0].message


def test_flags_sender_compared_to_itself(tmp_path: Path) -> None:
    body = (
        "modifier onlyOwner() {\n"
        "    require(msg.sender == msg.sender);\n"
        "    _;\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "compares msg.sender to itself" in findings[0].message


def test_flags_require_true(tmp_path: Path) -> None:
    body = "modifier onlyOwner() { require(true); _; }\n"
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "requires true" in findings[0].message


def test_flags_only_admin_alias(tmp_path: Path) -> None:
    body = "modifier onlyAdmin() { _; }\nfunction bump() external onlyAdmin {}\n"
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "onlyAdmin" in findings[0].message


def test_allows_msg_sender_equals_owner(tmp_path: Path) -> None:
    body = (
        "modifier onlyOwner() {\n"
        "    require(msg.sender == owner, \"not owner\");\n"
        "    _;\n"
        "}\n"
        "function bump() external onlyOwner {}\n"
    )
    assert not _scan(tmp_path, body)


def test_allows_owner_equals_msg_sender(tmp_path: Path) -> None:
    body = (
        "modifier onlyOwner() {\n"
        "    require(owner == msg.sender);\n"
        "    _;\n"
        "}\n"
    )
    assert not _scan(tmp_path, body)


def test_allows_if_not_sender_revert(tmp_path: Path) -> None:
    body = (
        "modifier onlyOwner() {\n"
        "    if (msg.sender != owner) revert();\n"
        "    _;\n"
        "}\n"
    )
    assert not _scan(tmp_path, body)


def test_allows_msg_sender_helper(tmp_path: Path) -> None:
    extra = "function _msgSender() internal view returns (address) { return msg.sender; }\n"
    body = (
        "modifier onlyOwner() {\n"
        "    require(_msgSender() == owner);\n"
        "    _;\n"
        "}\n"
    )
    assert not _scan(tmp_path, body, extra=extra)


def test_allows_check_owner_helper(tmp_path: Path) -> None:
    extra = "function _checkOwner() internal view { require(msg.sender == owner); }\n"
    body = "modifier onlyOwner() { _checkOwner(); _; }\n"
    assert not _scan(tmp_path, body, extra=extra)


def test_allows_has_role(tmp_path: Path) -> None:
    extra = (
        "function hasRole(bytes32 role, address who) public view returns (bool) {\n"
        "    return who == owner;\n"
        "}\n"
    )
    body = (
        "bytes32 public constant ADMIN = keccak256(\"ADMIN\");\n"
        "modifier onlyAdmin() {\n"
        "    require(hasRole(ADMIN, msg.sender));\n"
        "    _;\n"
        "}\n"
    )
    assert not _scan(tmp_path, body, extra=extra)


def test_ignores_unrelated_modifier(tmp_path: Path) -> None:
    body = "modifier nonReentrant() { _; }\nfunction bump() external nonReentrant {}\n"
    assert not _scan(tmp_path, body)


def test_ignores_commented_broken_modifier(tmp_path: Path) -> None:
    body = (
        "// modifier onlyOwner() { _; }\n"
        "modifier onlyOwner() {\n"
        "    require(msg.sender == owner);\n"
        "    _;\n"
        "}\n"
    )
    assert not _scan(tmp_path, body)


def test_ignore_directive_skips_modifier(tmp_path: Path) -> None:
    body = "// sibaudit:ignore-next-line\nmodifier onlyOwner() { _; }\n"
    assert not _scan(tmp_path, body)


def test_handles_modifier_without_parameter_parens(tmp_path: Path) -> None:
    body = "modifier onlyOwner { _; }\n"
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "never checks the caller" in findings[0].message


def test_handles_multiline_modifier_header(tmp_path: Path) -> None:
    body = "modifier onlyOwner(\n)\n{\n    _;\n}\n"
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert findings[0].line_number == 4


def test_real_check_wins_over_later_placeholder(tmp_path: Path) -> None:
    body = (
        "modifier onlyOwner() {\n"
        "    require(msg.sender == owner);\n"
        "    _;\n"
        "    emit Used();\n"
        "}\n"
        "event Used();\n"
    )
    assert not _scan(tmp_path, body)
