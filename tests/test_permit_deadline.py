from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths
from sibaudit.suggest import hint_for

TOKENS = (
    "interface IERC20Permit {\n"
    "    function permit(\n"
    "        address owner, address spender, uint256 value, uint256 deadline,\n"
    "        uint8 v, bytes32 r, bytes32 s\n"
    "    ) external;\n"
    "}\n"
    "interface IDai {\n"
    "    function permit(\n"
    "        address holder, address spender, uint256 nonce, uint256 expiry,\n"
    "        bool allowed, uint8 v, bytes32 r, bytes32 s\n"
    "    ) external;\n"
    "}\n"
)


def _scan(tmp_path: Path, body: str) -> list:
    source = f"pragma solidity 0.8.20;\n{TOKENS}contract C {{\n{body}\n}}\n"
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A035"]


def test_flags_eip2612_zero_deadline(tmp_path: Path) -> None:
    body = (
        "IERC20Permit public token;\n"
        "function pull(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {\n"
        "    token.permit(msg.sender, address(this), amount, 0, v, r, s);\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "MEDIUM"
    assert "deadline 0" in finding.message
    assert "always reverts" in finding.message
    assert "token.permit(" in finding.line_text


def test_flags_multiline_cast_and_try(tmp_path: Path) -> None:
    body = (
        "address public token;\n"
        "function pull(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {\n"
        "    try IERC20Permit(token).permit(\n"
        "        msg.sender,\n"
        "        address(this),\n"
        "        amount,\n"
        "        uint256(0),\n"
        "        v, r, s\n"
        "    ) {} catch {}\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "IERC20Permit(token).permit(" in findings[0].line_text


def test_flags_packed_signature_overload(tmp_path: Path) -> None:
    body = (
        "IERC20Permit public token;\n"
        "function pull(uint256 amount, bytes calldata sig) external {\n"
        "    token.permit(msg.sender, address(this), amount, 0, sig);\n"
        "}\n"
    )
    assert len(_scan(tmp_path, body)) == 1


def test_flags_dai_zero_expiry_with_its_own_message(tmp_path: Path) -> None:
    body = (
        "IDai public dai;\n"
        "function pull(uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {\n"
        "    dai.permit(msg.sender, address(this), nonce, 0, true, v, r, s);\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "DAI-style" in findings[0].message
    assert "never expires" in findings[0].message
    hint = hint_for("A035", findings[0].message)
    assert "valid forever" in hint


def test_real_deadline_is_clean(tmp_path: Path) -> None:
    body = (
        "IERC20Permit public token;\n"
        "IDai public dai;\n"
        "function pull(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s)\n"
        "    external\n"
        "{\n"
        "    token.permit(msg.sender, address(this), amount, deadline, v, r, s);\n"
        "    token.permit(msg.sender, address(this), 0, deadline, v, r, s);\n"
        "    dai.permit(msg.sender, address(this), 0, deadline, true, v, r, s);\n"
        "}\n"
    )
    assert not _scan(tmp_path, body)


def test_other_arities_and_declarations_are_ignored(tmp_path: Path) -> None:
    # Permit2-style permit(owner, details, sig) is a different shape.
    body = (
        "address public permit2;\n"
        "function permit(address owner, address spender, uint256 value, uint256 deadline,\n"
        "    uint8 v, bytes32 r, bytes32 s) external {}\n"
        "function viaPermit2(address owner, bytes calldata sig) external {\n"
        "    IPermit2(permit2).permit(owner, 0, sig);\n"
        "}\n"
    )
    assert not _scan(tmp_path, body)


def test_comment_and_ignore_directive(tmp_path: Path) -> None:
    body = (
        "IERC20Permit public token;\n"
        "function pull(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {\n"
        "    // token.permit(msg.sender, address(this), amount, 0, v, r, s);\n"
        "    // sibaudit:ignore-next-line\n"
        "    token.permit(msg.sender, address(this), amount, 0, v, r, s);\n"
        "}\n"
    )
    assert not _scan(tmp_path, body)
