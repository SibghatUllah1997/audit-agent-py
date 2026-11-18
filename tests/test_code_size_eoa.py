from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths

HEADER = "pragma solidity 0.8.20;\n"


def _scan(tmp_path: Path, body: str) -> list:
    (tmp_path / "C.sol").write_text(HEADER + body)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A027"]


def _contract(*lines: str) -> str:
    inner = "".join(f"        {line}\n" for line in lines)
    return f"contract C {{\n    function f(address a) external {{\n{inner}    }}\n}}\n"


def test_flags_code_length_zero_as_eoa_check(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _contract('require(msg.sender.code.length == 0, "eoa");'))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "MEDIUM"
    assert finding.line_number == 4
    assert "constructor" in finding.message
    assert "EIP-7702" in finding.message


def test_flags_reversed_and_less_than_one_comparisons(tmp_path: Path) -> None:
    body = _contract(
        'require(0 == a.code.length, "eoa");',
        'require(a.code.length < 1, "eoa");',
    )
    assert [f.line_number for f in _scan(tmp_path, body)] == [4, 5]


def test_flags_rejecting_callers_with_code(tmp_path: Path) -> None:
    body = _contract(
        'require(!(msg.sender.code.length > 0), "no contracts");',
        'if (tx.origin.code.length != 0) revert();',
    )
    findings = _scan(tmp_path, body)
    assert [f.line_number for f in findings] == [4, 5]
    assert all("bypassable from a constructor" in f.message for f in findings)


def test_target_has_code_check_is_not_flagged(tmp_path: Path) -> None:
    body = _contract(
        'require(a.code.length > 0, "not a contract");',
        'require(a.code.length != 0, "not a contract");',
    )
    assert _scan(tmp_path, body) == []


def test_flags_negated_is_contract_and_caller_is_contract(tmp_path: Path) -> None:
    body = _contract(
        'require(!Address.isContract(a), "eoa");',
        'require(!isContract(msg.sender), "no contracts");',
        'require(!msg.sender.isContract(), "no contracts");',
    )
    assert [f.line_number for f in _scan(tmp_path, body)] == [4, 5, 6]


def test_is_contract_on_a_target_and_its_definition_are_not_flagged(tmp_path: Path) -> None:
    body = (
        "contract C {\n"
        "    function isContract(address a) internal view returns (bool) {\n"
        "        return a.code.length > 0;\n"
        "    }\n"
        "    function f(address a) external {\n"
        '        require(isContract(a), "target");\n'
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_flags_assembly_iszero_and_caller_extcodesize(tmp_path: Path) -> None:
    body = _contract(
        "bool eoa;",
        "uint256 size;",
        "assembly {",
        "    eoa := iszero(extcodesize(a))",
        "    size := extcodesize(caller())",
        "}",
    )
    assert [f.line_number for f in _scan(tmp_path, body)] == [7, 8]


def test_flags_extcodesize_result_compared_to_zero(tmp_path: Path) -> None:
    body = (
        "contract C {\n"
        "    modifier onlyEOA(address a) {\n"
        "        uint256 size;\n"
        "        assembly { size := extcodesize(a) }\n"
        '        require(size == 0, "eoa");\n'
        "        _;\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert [f.line_number for f in findings] == [5]
    assert "assembly" in findings[0].line_text


def test_extcodesize_result_used_as_target_check_is_not_flagged(tmp_path: Path) -> None:
    body = (
        "contract C {\n"
        "    function f(address a) external {\n"
        "        uint256 size;\n"
        "        assembly { size := extcodesize(a) }\n"
        '        require(size > 0, "target");\n'
        "    }\n"
        "    function g(uint256 size) external pure returns (bool) {\n"
        "        return size == 0;\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_comments_and_ignore_next_line_are_respected(tmp_path: Path) -> None:
    body = _contract(
        "// require(msg.sender.code.length == 0);",
        "// sibaudit:ignore-next-line",
        'require(msg.sender.code.length == 0, "eoa");',
    )
    assert _scan(tmp_path, body) == []
