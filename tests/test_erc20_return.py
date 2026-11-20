from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths

IFACE = (
    "interface IERC20 {\n"
    "    function transfer(address to, uint256 amount) external returns (bool);\n"
    "    function transferFrom(address from, address to, uint256 amount) external returns (bool);\n"
    "    function approve(address spender, uint256 amount) external returns (bool);\n"
    "}\n"
)


def _scan(tmp_path: Path, source: str) -> list:
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A028"]


def _contract(body: str) -> str:
    return f"pragma solidity 0.8.20;\n{IFACE}contract C {{\n{body}\n}}\n"


def test_flags_ignored_transfer_on_typed_state_var(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function pay(address to, uint256 amount) external {\n"
        "    token.transfer(to, amount);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "transfer()" in findings[0].message
    assert "SafeERC20" in findings[0].message
    assert "token.transfer(to, amount)" in findings[0].line_text


def test_flags_transfer_from_on_cast(tmp_path: Path) -> None:
    body = (
        "function pull(address t, address from, uint256 amount) external {\n"
        "    IERC20(t).transferFrom(from, address(this), amount);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "transferFrom()" in findings[0].message


def test_flags_approve_on_typed_param(tmp_path: Path) -> None:
    body = (
        "function allow(IERC20 asset, address spender, uint256 amount) external {\n"
        "    asset.approve(spender, amount);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "approve()" in findings[0].message


def test_checked_with_require_is_clean(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function pay(address to, uint256 amount) external {\n"
        "    require(token.transfer(to, amount), \"transfer failed\");\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_result_assigned_or_returned_is_clean(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function pay(address to, uint256 amount) external returns (bool) {\n"
        "    bool ok = token.transfer(to, amount);\n"
        "    if (!ok) revert();\n"
        "    return token.approve(to, amount);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_safe_erc20_calls_are_clean(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function pay(address to, uint256 amount) external {\n"
        "    token.safeTransfer(to, amount);\n"
        "    token.safeTransferFrom(msg.sender, to, amount);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_ether_transfer_is_left_to_a022(tmp_path: Path) -> None:
    body = (
        "function pay(address payable to, uint256 amount) external {\n"
        "    to.transfer(amount);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_nft_transfer_from_is_not_flagged(tmp_path: Path) -> None:
    body = (
        "IERC721 public nft;\n"
        "function move(address to, uint256 id) external {\n"
        "    nft.transferFrom(msg.sender, to, id);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_wrong_arg_count_is_not_flagged(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function odd(address to) external {\n"
        "    token.transfer(to);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_multiline_call_reports_the_call_line(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function pay(address to, uint256 amount) external {\n"
        "    token.transfer(\n"
        "        to,\n"
        "        amount\n"
        "    );\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "token.transfer(" in findings[0].line_text


def test_commented_call_and_ignore_directive(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function pay(address to, uint256 amount) external {\n"
        "    // token.transfer(to, amount);\n"
        "    // sibaudit:ignore-next-line\n"
        "    token.transfer(to, amount);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_ignored_call_inside_if_block_is_flagged(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function pay(address to, uint256 amount) external {\n"
        "    if (amount > 0) { token.transfer(to, amount); }\n"
        "}\n"
    )
    assert len(_scan(tmp_path, _contract(body))) == 1
