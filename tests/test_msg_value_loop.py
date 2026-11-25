from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths
from sibaudit.suggest import hint_for


def _scan(tmp_path: Path, source: str) -> list:
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A037"]


def _contract(body: str) -> str:
    return f"pragma solidity 0.8.20;\ncontract C {{\n{body}\n}}\n"


def test_flags_msg_value_in_for_loop(tmp_path: Path) -> None:
    body = (
        "mapping(address => uint256) public credit;\n"
        "function split(address[] calldata users) external payable {\n"
        "    for (uint256 i = 0; i < users.length; i++) {\n"
        "        credit[users[i]] += msg.value;\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "HIGH"
    assert "msg.value is read inside a loop" in finding.message
    assert "msg.value" in finding.line_text
    hint = hint_for("A037", finding.message)
    assert "before the loop" in hint


def test_flags_msg_value_in_while_loop(tmp_path: Path) -> None:
    body = (
        "mapping(address => uint256) public credit;\n"
        "function split(address[] calldata users) external payable {\n"
        "    uint256 i = 0;\n"
        "    while (i < users.length) {\n"
        "        credit[users[i]] += msg.value;\n"
        "        i++;\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "credit[users[i]] += msg.value;" in findings[0].line_text


def test_flags_single_statement_loop(tmp_path: Path) -> None:
    body = (
        "mapping(address => uint256) public credit;\n"
        "function split(address[] calldata users) external payable {\n"
        "    for (uint256 i = 0; i < users.length; i++)\n"
        "        credit[users[i]] += msg.value;\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "credit[users[i]] += msg.value;" in findings[0].line_text


def test_flags_call_value_in_loop(tmp_path: Path) -> None:
    body = (
        "function spray(address[] calldata users) external payable {\n"
        "    for (uint256 i = 0; i < users.length; i++) {\n"
        "        users[i].call{value: msg.value}(\"\");\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "msg.value" in findings[0].line_text


def test_cached_value_before_loop_is_clean(tmp_path: Path) -> None:
    body = (
        "mapping(address => uint256) public credit;\n"
        "function split(address[] calldata users) external payable {\n"
        "    uint256 share = msg.value / users.length;\n"
        "    for (uint256 i = 0; i < users.length; i++) {\n"
        "        credit[users[i]] += share;\n"
        "    }\n"
        "}\n"
        "function withdraw() external {\n"
        "    uint256 amount = credit[msg.sender];\n"
        "    credit[msg.sender] = 0;\n"
        "    (bool ok, ) = msg.sender.call{value: amount}(\"\");\n"
        "    require(ok);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_msg_value_only_in_while_condition_is_clean(tmp_path: Path) -> None:
    body = (
        "function drain() external payable {\n"
        "    uint256 paid = 0;\n"
        "    while (paid < msg.value) {\n"
        "        paid += 1;\n"
        "    }\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_commented_read_and_ignore_directive(tmp_path: Path) -> None:
    body = (
        "mapping(address => uint256) public credit;\n"
        "function split(address[] calldata users) external payable {\n"
        "    for (uint256 i = 0; i < users.length; i++) {\n"
        "        // credit[users[i]] += msg.value;\n"
        "        // sibaudit:ignore-next-line\n"
        "        credit[users[i]] += msg.value;\n"
        "    }\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_empty_loop_is_clean(tmp_path: Path) -> None:
    body = (
        "function split(address[] calldata users) external payable {\n"
        "    for (uint256 i = 0; i < users.length; i++) {}\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))
