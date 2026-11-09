from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, body: str) -> list:
    (tmp_path / "C.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract C {\n" + body + "\n}\n"
    )
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A015"]


def test_flags_state_address_never_assigned(tmp_path: Path) -> None:
    findings = _scan(tmp_path, "address public treasury;\nfunction f() external {}")
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert 'State address "treasury"' in findings[0].message


def test_state_address_set_in_constructor_is_fine(tmp_path: Path) -> None:
    body = "address public owner;\nconstructor() { owner = msg.sender; }"
    assert not _scan(tmp_path, body)


def test_state_address_set_by_setter_is_fine(tmp_path: Path) -> None:
    body = (
        "address payable internal feeTo;\n"
        "function setFeeTo(address payable to) external { feeTo = to; }"
    )
    assert not _scan(tmp_path, body)


def test_flags_local_address_never_assigned(tmp_path: Path) -> None:
    body = (
        "function pay() external {\n"
        "    address payable dest;\n"
        "    dest.transfer(1);\n"
        "}"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert 'Local address "dest"' in findings[0].message


def test_local_assigned_in_other_function_still_flagged(tmp_path: Path) -> None:
    body = (
        "function a() external {\n"
        "    address who;\n"
        "    who;\n"
        "}\n"
        "function b() external {\n"
        "    address who;\n"
        "    who = msg.sender;\n"
        "}"
    )
    findings = _scan(tmp_path, body)
    # Locals are scoped to their function, so b() does not hide a()'s bug.
    assert [f.line_number for f in findings] == [4]


def test_tuple_and_assembly_assignment_count(tmp_path: Path) -> None:
    body = (
        "function a() external {\n"
        "    address x;\n"
        "    uint256 n;\n"
        "    (x, n) = abi.decode(msg.data, (address, uint256));\n"
        "}\n"
        "function b() external {\n"
        "    address y;\n"
        "    assembly { y := caller() }\n"
        "}"
    )
    assert not _scan(tmp_path, body)


def test_initialized_and_comparison_only(tmp_path: Path) -> None:
    body = (
        "address public admin = msg.sender;\n"
        "address public guardian;\n"
        "function f() external view { require(guardian == msg.sender); }"
    )
    findings = _scan(tmp_path, body)
    assert [f.line_text.strip() for f in findings] == ["address public guardian;"]


def test_struct_fields_and_params_are_ignored(tmp_path: Path) -> None:
    body = (
        "struct Order {\n"
        "    address maker;\n"
        "    uint256 amount;\n"
        "}\n"
        "function f(address who) external pure returns (address) { return who; }"
    )
    assert not _scan(tmp_path, body)


def test_ignore_directive_skips_declaration(tmp_path: Path) -> None:
    body = "// sibaudit:ignore-next-line\naddress public unused;"
    assert not _scan(tmp_path, body)


def test_sample_contract_flags_unset_owner() -> None:
    sample = Path(__file__).resolve().parents[1] / "examples" / "Vulnerable.sol"
    findings = [f for f in scan_paths([str(sample)]) if f.code == "A015"]
    assert any('"owner"' in f.message for f in findings)
