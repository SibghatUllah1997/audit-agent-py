from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths

HEADER = "pragma solidity 0.8.20;\n"


def _scan(tmp_path: Path, body: str, name: str = "C.sol") -> list:
    (tmp_path / name).write_text(HEADER + body)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A027"]


def test_flags_sender_code_length_equals_zero(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    function enter() external {\n"
        "        require(msg.sender.code.length == 0, \"no contracts\");\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "HIGH"
    assert finding.line_number == 4
    assert "code.length" in finding.line_text
    assert "EOA" in finding.message
    assert "EIP-7702" in finding.message
    assert "constructor" in finding.message.lower()


def test_flags_zero_on_the_left_of_code_length(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    function enter() external view returns (bool) {\n"
        "        return 0 == msg.sender.code.length;\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "code.length" in findings[0].line_text


def test_flags_code_length_greater_than_zero(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    function isContract(address who) external view returns (bool) {\n"
        "        return who.code.length > 0;\n"
        "    }\n"
        "}\n"
    )
    assert len(_scan(tmp_path, body)) == 1


def test_flags_assigned_code_length_then_require_zero(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    function enter(address who) external view {\n"
        "        uint256 size = who.code.length;\n"
        "        require(size == 0, \"no contracts\");\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "who.code.length" in findings[0].line_text


def test_flags_assembly_extcodesize_assigned_then_compared(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    function enter(address account) external view {\n"
        "        uint256 size;\n"
        "        assembly {\n"
        "            size := extcodesize(account)\n"
        "        }\n"
        "        require(size == 0, \"no contracts\");\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "extcodesize" in findings[0].line_text
    assert findings[0].line_number == 6


def test_flags_iszero_extcodesize(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    function enter(address account) external view {\n"
        "        assembly {\n"
        "            if iszero(extcodesize(account)) { revert(0, 0) }\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "extcodesize" in findings[0].line_text


def test_flags_yul_eq_extcodesize_zero(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    function enter(address account) external view {\n"
        "        assembly {\n"
        "            if eq(extcodesize(account), 0) { revert(0, 0) }\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert len(_scan(tmp_path, body)) == 1


def test_flags_yul_eq_zero_then_extcodesize(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    function enter(address account) external view {\n"
        "        assembly {\n"
        "            if eq(0, extcodesize(account)) { revert(0, 0) }\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert len(_scan(tmp_path, body)) == 1


def test_flags_modifier_eoa_gate(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    modifier onlyEOA() {\n"
        "        require(msg.sender.code.length == 0, \"no contracts\");\n"
        "        _;\n"
        "    }\n"
        "    function enter() external onlyEOA {}\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "onlyEOA" in findings[0].line_text or "code.length" in findings[0].line_text


def test_flags_constructor_extcodesize_on_caller(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    constructor() {\n"
        "        require(msg.sender.code.length == 0, \"no contracts\");\n"
        "    }\n"
        "}\n"
    )
    assert len(_scan(tmp_path, body)) == 1


def test_flags_multiline_code_length_check(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    function enter() external {\n"
        "        require(\n"
        "            msg.sender.code.length == 0,\n"
        "            \"no contracts\"\n"
        "        );\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "code.length" in findings[0].line_text


def test_allows_size_returned_without_zero_compare(tmp_path: Path) -> None:
    body = (
        "contract Probe {\n"
        "    function sizeOf(address account) external view returns (uint256 size) {\n"
        "        assembly {\n"
        "            size := extcodesize(account)\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_allows_address_this_code_length(tmp_path: Path) -> None:
    # Checking this contract's own code is how some initializers detect construction.
    body = (
        "contract Proxy {\n"
        "    function inConstructor() external view returns (bool) {\n"
        "        return address(this).code.length == 0;\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_allows_extcodesize_of_this(tmp_path: Path) -> None:
    body = (
        "contract Proxy {\n"
        "    function inConstructor() external view returns (bool) {\n"
        "        uint256 size;\n"
        "        assembly {\n"
        "            size := extcodesize(address())\n"
        "        }\n"
        "        return size == 0;\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_ignores_commented_code_length_check(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    function enter() external {\n"
        "        // require(msg.sender.code.length == 0, \"no contracts\");\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_respects_ignore_next_line(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    function enter() external {\n"
        "        // sibaudit:ignore-next-line\n"
        "        require(msg.sender.code.length == 0, \"no contracts\");\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_does_not_flag_extcodecopy(tmp_path: Path) -> None:
    body = (
        "contract Copy {\n"
        "    function dump(address account) external view returns (bytes memory out) {\n"
        "        assembly {\n"
        "            extcodecopy(account, 0, 0, 32)\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []
