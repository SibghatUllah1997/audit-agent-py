from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, body: str) -> list:
    (tmp_path / "C.sol").write_text(
        "pragma solidity ^0.8.20;\ninterface IERC20 { function approve(address, uint256)"
        " external returns (bool); }\ncontract C {\n" + body + "\n}\n"
    )
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A018"]


def test_flags_low_level_call_in_constructor(tmp_path: Path) -> None:
    body = (
        "constructor(address hook) {\n"
        "    (bool ok, ) = hook.call(\"\");\n"
        "    require(ok);\n"
        "}"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "call via .call()" in findings[0].message
    assert "hook.call" in findings[0].line_text


def test_flags_ether_send_in_constructor(tmp_path: Path) -> None:
    body = "constructor(address payable to) payable {\n    to.transfer(msg.value);\n}"
    findings = _scan(tmp_path, body)
    assert [f.line_text.strip() for f in findings] == ["to.transfer(msg.value);"]


def test_flags_interface_cast_call(tmp_path: Path) -> None:
    body = (
        "constructor(address token, address spender) {\n"
        "    IERC20(token).approve(spender, type(uint256).max);\n"
        "}"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "IERC20(...)" in findings[0].message


def test_flags_call_on_typed_state_variable(tmp_path: Path) -> None:
    body = (
        "IERC20 public immutable token;\n"
        "constructor(IERC20 token_, address spender) {\n"
        "    token = token_;\n"
        "    token.approve(spender, 5);\n"
        "}"
    )
    findings = _scan(tmp_path, body)
    assert [f.line_text.strip() for f in findings] == ["token.approve(spender, 5);"]
    assert 'contract "token"' in findings[0].message


def test_flags_call_on_typed_constructor_param(tmp_path: Path) -> None:
    body = "constructor(IERC20 t) {\n    t.approve(msg.sender, 5);\n}"
    assert len(_scan(tmp_path, body)) == 1


def test_flags_call_through_this(tmp_path: Path) -> None:
    body = (
        "uint256 public x;\n"
        "function setX(uint256 v) external { x = v; }\n"
        "constructor() {\n    this.setX(2);\n}"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "through this" in findings[0].message


def test_ignores_same_calls_outside_constructor(tmp_path: Path) -> None:
    body = (
        "IERC20 public token;\n"
        "function f(address t) external {\n"
        "    IERC20(t).approve(msg.sender, 5);\n"
        "    token.approve(msg.sender, 5);\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_ignores_base_constructor_args_and_plain_setup(tmp_path: Path) -> None:
    (tmp_path / "C.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract Base { constructor(uint256 v) {} }\n"
        "contract C is Base {\n"
        "    address public owner;\n"
        "    uint256 public cap;\n"
        "    constructor(address o) Base(7) {\n"
        "        owner = o;\n"
        "        cap = type(uint256).max;\n"
        "        require(o != address(0), \"zero\");\n"
        "    }\n"
        "}\n"
    )
    assert not [f for f in scan_paths([str(tmp_path)]) if f.code == "A018"]


def test_ignores_library_style_calls_and_comments(tmp_path: Path) -> None:
    body = (
        "constructor(address t) {\n"
        "    // IERC20(t).approve(msg.sender, 5);\n"
        "    bytes32 h = keccak256(abi.encode(t));\n"
        "    h;\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_ignore_directive_suppresses_finding(tmp_path: Path) -> None:
    body = (
        "constructor(address t) {\n"
        "    // sibaudit:ignore-next-line\n"
        "    IERC20(t).approve(msg.sender, 5);\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_handles_multiline_constructor_header(tmp_path: Path) -> None:
    body = (
        "constructor(\n"
        "    address t\n"
        ")\n"
        "{\n"
        "    IERC20(t).approve(msg.sender, 5);\n"
        "}"
    )
    findings = _scan(tmp_path, body)
    assert [f.line_number for f in findings] == [8]
