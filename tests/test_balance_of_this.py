from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths
from sibaudit.suggest import hint_for

TOKEN = (
    "interface IERC20 {\n"
    "    function transferFrom(address from, address to, uint256 amount) external returns (bool);\n"
    "    function safeTransferFrom(address from, address to, uint256 amount) external;\n"
    "    function transfer(address to, uint256 amount) external returns (bool);\n"
    "    function balanceOf(address account) external view returns (uint256);\n"
    "}\n"
)


def _scan(tmp_path: Path, source: str) -> list:
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A039"]


def _contract(body: str) -> str:
    return f"pragma solidity 0.8.20;\n{TOKEN}contract C {{\n{body}\n}}\n"


def test_flags_balance_of_this_after_transfer_from(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "mapping(address => uint256) public credit;\n"
        "function deposit(uint256 amount) external {\n"
        "    require(token.transferFrom(msg.sender, address(this), amount), \"pull\");\n"
        "    uint256 received = token.balanceOf(address(this));\n"
        "    credit[msg.sender] += received;\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "HIGH"
    assert "balanceOf(address(this))" in finding.message
    assert "donation" in finding.message
    assert "token.balanceOf(address(this))" in finding.line_text
    hint = hint_for("A039", finding.message)
    assert "snapshot" in hint or "amount" in hint


def test_flags_multiline_cast_receiver(tmp_path: Path) -> None:
    body = (
        "address public token;\n"
        "mapping(address => uint256) public credit;\n"
        "function deposit(uint256 amount) external {\n"
        "    require(\n"
        "        IERC20(token).transferFrom(msg.sender, address(this), amount),\n"
        "        \"pull\"\n"
        "    );\n"
        "    uint256 received = IERC20(token).balanceOf(address(this));\n"
        "    credit[msg.sender] += received;\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "balanceOf(address(this))" in findings[0].line_text


def test_flags_safe_transfer_from_and_bare_this(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "mapping(address => uint256) public credit;\n"
        "function deposit(uint256 amount) external {\n"
        "    token.safeTransferFrom(msg.sender, address(this), amount);\n"
        "    credit[msg.sender] += token.balanceOf(this);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "balanceOf(this)" in findings[0].line_text


def test_transfer_amount_is_clean(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "mapping(address => uint256) public credit;\n"
        "function deposit(uint256 amount) external {\n"
        "    require(token.transferFrom(msg.sender, address(this), amount), \"pull\");\n"
        "    credit[msg.sender] += amount;\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_balance_delta_is_clean(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "mapping(address => uint256) public credit;\n"
        "function deposit(uint256 amount) external {\n"
        "    uint256 before = token.balanceOf(address(this));\n"
        "    require(token.transferFrom(msg.sender, address(this), amount), \"pull\");\n"
        "    uint256 received = token.balanceOf(address(this)) - before;\n"
        "    credit[msg.sender] += received;\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_balance_check_comparison_is_clean(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function deposit(uint256 amount) external {\n"
        "    require(token.transferFrom(msg.sender, address(this), amount), \"pull\");\n"
        "    require(token.balanceOf(address(this)) >= amount, \"short\");\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_outbound_or_other_recipient_is_clean(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function pullTo(address to, uint256 amount) external {\n"
        "    require(token.transferFrom(msg.sender, to, amount), \"pull\");\n"
        "    uint256 leftover = token.balanceOf(address(this));\n"
        "    leftover;\n"
        "}\n"
        "function sendAll(address to) external {\n"
        "    uint256 bal = token.balanceOf(address(this));\n"
        "    require(token.transfer(to, bal), \"send\");\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_balance_of_before_pull_is_clean(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function maxPull() external view returns (uint256) {\n"
        "    return token.balanceOf(address(this));\n"
        "}\n"
        "function deposit(uint256 amount) external {\n"
        "    require(token.transferFrom(msg.sender, address(this), amount), \"pull\");\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_commented_read_and_ignore_directive(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "mapping(address => uint256) public credit;\n"
        "function deposit(uint256 amount) external {\n"
        "    require(token.transferFrom(msg.sender, address(this), amount), \"pull\");\n"
        "    // uint256 received = token.balanceOf(address(this));\n"
        "    // sibaudit:ignore-next-line\n"
        "    uint256 received = token.balanceOf(address(this));\n"
        "    credit[msg.sender] += received;\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))
