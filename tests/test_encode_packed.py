from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, source: str, name: str = "C.sol") -> list:
    (tmp_path / name).write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A024"]


def _contract(body: str, extra: str = "") -> str:
    return f"pragma solidity 0.8.20;\ncontract C {{\n{extra}{body}\n}}\n"


def test_flags_two_string_params(tmp_path: Path) -> None:
    body = (
        "function leaf(string memory a, string memory b) external pure returns (bytes32) {\n"
        "    return keccak256(abi.encodePacked(a, b));\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "encodePacked" in findings[0].message
    assert "abi.encode" in findings[0].message
    assert "abi.encodePacked(a, b)" in findings[0].line_text


def test_flags_string_and_bytes_params(tmp_path: Path) -> None:
    body = (
        "function leaf(string memory a, bytes memory b) external pure returns (bytes32) {\n"
        "    return keccak256(abi.encodePacked(a, b));\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1


def test_flags_two_bytes_params(tmp_path: Path) -> None:
    body = (
        "function leaf(bytes memory a, bytes calldata b) external pure returns (bytes32) {\n"
        "    return keccak256(abi.encodePacked(a, b));\n"
        "}\n"
    )
    assert len(_scan(tmp_path, _contract(body))) == 1


def test_flags_dynamic_arrays(tmp_path: Path) -> None:
    body = (
        "function leaf(uint256[] memory a, uint256[] memory b) "
        "external pure returns (bytes32) {\n"
        "    return keccak256(abi.encodePacked(a, b));\n"
        "}\n"
    )
    assert len(_scan(tmp_path, _contract(body))) == 1


def test_flags_state_strings(tmp_path: Path) -> None:
    extra = "string public a;\nstring public b;\n"
    body = (
        "function leaf() external view returns (bytes32) {\n"
        "    return keccak256(abi.encodePacked(a, b));\n"
        "}\n"
    )
    assert len(_scan(tmp_path, _contract(body, extra=extra))) == 1


def test_flags_string_literals(tmp_path: Path) -> None:
    body = (
        "function leaf() external pure returns (bytes32) {\n"
        '    return keccak256(abi.encodePacked("ab", "c"));\n'
        "}\n"
    )
    assert len(_scan(tmp_path, _contract(body))) == 1


def test_flags_explicit_dynamic_casts(tmp_path: Path) -> None:
    body = (
        "function leaf(string memory a, bytes memory b) external pure "
        "returns (bytes32) {\n"
        "    return keccak256(abi.encodePacked(string(a), bytes(b)));\n"
        "}\n"
    )
    assert len(_scan(tmp_path, _contract(body))) == 1


def test_flags_msg_data_with_bytes(tmp_path: Path) -> None:
    body = (
        "function leaf(bytes memory extra) external view returns (bytes32) {\n"
        "    return keccak256(abi.encodePacked(msg.data, extra));\n"
        "}\n"
    )
    assert len(_scan(tmp_path, _contract(body))) == 1


def test_flags_two_dynamics_with_static_in_between(tmp_path: Path) -> None:
    body = (
        "function leaf(string memory a, uint256 n, string memory b) "
        "external pure returns (bytes32) {\n"
        "    return keccak256(abi.encodePacked(a, n, b));\n"
        "}\n"
    )
    assert len(_scan(tmp_path, _contract(body))) == 1


def test_allows_single_dynamic_arg(tmp_path: Path) -> None:
    body = (
        "function leaf(string memory a) external pure returns (bytes32) {\n"
        "    return keccak256(abi.encodePacked(a));\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_allows_dynamic_plus_uint(tmp_path: Path) -> None:
    body = (
        "function leaf(string memory a, uint256 n) external pure returns (bytes32) {\n"
        "    return keccak256(abi.encodePacked(a, n));\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_allows_two_uints(tmp_path: Path) -> None:
    body = (
        "function leaf(uint256 a, uint256 b) external pure returns (bytes32) {\n"
        "    return keccak256(abi.encodePacked(a, b));\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_allows_bytes32_pair(tmp_path: Path) -> None:
    body = (
        "function leaf(bytes32 a, bytes32 b) external pure returns (bytes32) {\n"
        "    return keccak256(abi.encodePacked(a, b));\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_allows_abi_encode(tmp_path: Path) -> None:
    body = (
        "function leaf(string memory a, string memory b) external pure returns (bytes32) {\n"
        "    return keccak256(abi.encode(a, b));\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_allows_encode_with_signature(tmp_path: Path) -> None:
    body = (
        "function ping(address target, string memory a, string memory b) external {\n"
        '    target.call(abi.encodeWithSignature("leaf(string,string)", a, b));\n'
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_handles_multiline_encode_packed(tmp_path: Path) -> None:
    body = (
        "function leaf(string memory a, string memory b) external pure returns (bytes32) {\n"
        "    return keccak256(abi.encodePacked(\n"
        "        a,\n"
        "        b\n"
        "    ));\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "abi.encodePacked(" in findings[0].line_text


def test_ignores_commented_encode_packed(tmp_path: Path) -> None:
    body = (
        "function leaf(string memory a, string memory b) external pure returns (bytes32) {\n"
        "    // return keccak256(abi.encodePacked(a, b));\n"
        "    return keccak256(abi.encode(a, b));\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_ignore_directive_skips_encode_packed(tmp_path: Path) -> None:
    body = (
        "function leaf(string memory a, string memory b) external pure returns (bytes32) {\n"
        "    // sibaudit:ignore-next-line\n"
        "    return keccak256(abi.encodePacked(a, b));\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_constructor_encode_packed_is_scanned(tmp_path: Path) -> None:
    body = (
        "bytes32 public leaf;\n"
        "constructor(string memory a, string memory b) {\n"
        "    leaf = keccak256(abi.encodePacked(a, b));\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "encodePacked" in findings[0].line_text
