from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, source: str) -> list:
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A022"]


def _contract(body: str) -> str:
    return f"pragma solidity ^0.8.20;\ncontract C {{\n{body}\n}}\n"


def test_flags_ether_transfer(tmp_path: Path) -> None:
    body = (
        "function pay(address payable to, uint256 amount) external {\n"
        "    to.transfer(amount);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "address.transfer()" in findings[0].message
    assert "2300" in findings[0].message
    assert "to.transfer(amount)" in findings[0].line_text


def test_flags_ether_send(tmp_path: Path) -> None:
    body = (
        "function pay(address payable to, uint256 amount) external {\n"
        "    to.send(amount);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "address.send()" in findings[0].message
    assert "2300" in findings[0].message
    assert "to.send(amount)" in findings[0].line_text


def test_flags_payable_wrap_transfer(tmp_path: Path) -> None:
    body = (
        "function pay(address to) external {\n"
        "    payable(to).transfer(address(this).balance);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "transfer" in findings[0].line_text


def test_allows_erc20_transfer(tmp_path: Path) -> None:
    body = (
        "function dump(address token, address to, uint256 amount) external {\n"
        "    token.transfer(to, amount);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_allows_custom_send_with_two_args(tmp_path: Path) -> None:
    body = (
        "function push(address mailbox, bytes memory payload) external {\n"
        "    mailbox.send(payload, 0);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_allows_call_with_value(tmp_path: Path) -> None:
    body = (
        "function pay(address payable to, uint256 amount) external {\n"
        "    (bool ok, ) = to.call{value: amount}(\"\");\n"
        "    require(ok);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_allows_transfer_from(tmp_path: Path) -> None:
    body = (
        "function pull(address token, address from, uint256 amount) external {\n"
        "    token.transferFrom(from, address(this), amount);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_commented_transfer_is_ignored(tmp_path: Path) -> None:
    body = (
        "function pay(address payable to, uint256 amount) external {\n"
        "    // to.transfer(amount);\n"
        "    to;\n"
        "    amount;\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_ignore_directive_skips_transfer(tmp_path: Path) -> None:
    body = (
        "function pay(address payable to, uint256 amount) external {\n"
        "    // sibaudit:ignore-next-line\n"
        "    to.transfer(amount);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_handles_multiline_transfer(tmp_path: Path) -> None:
    body = (
        "function pay(address payable to, uint256 amount) external {\n"
        "    to.transfer(\n"
        "        amount\n"
        "    );\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert findings[0].line_number == 4
    assert "to.transfer(" in findings[0].line_text


def test_multiline_erc20_transfer_is_not_flagged(tmp_path: Path) -> None:
    body = (
        "function dump(address token, address to, uint256 amount) external {\n"
        "    token.transfer(\n"
        "        to,\n"
        "        amount\n"
        "    );\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_flags_both_send_and_transfer_in_one_function(tmp_path: Path) -> None:
    body = (
        "function pay(address payable a, address payable b, uint256 amount) external {\n"
        "    a.transfer(amount);\n"
        "    b.send(amount);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 2
    messages = {f.message for f in findings}
    assert any("transfer" in m for m in messages)
    assert any("send" in m for m in messages)


def test_selfdestruct_is_not_a_stipend_send(tmp_path: Path) -> None:
    body = (
        "function boom(address payable to) external {\n"
        "    selfdestruct(to);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))
