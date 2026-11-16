from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, body: str, *, extra: str = "") -> list:
    (tmp_path / "C.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract C {\n" + extra + body + "\n}\n"
    )
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A021"]


def test_flags_assigned_ecrecover_with_no_check(tmp_path: Path) -> None:
    body = (
        "function claim(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external "
        "returns (address) {\n"
        "    address signer = ecrecover(digest, v, r, s);\n"
        "    return signer;\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "zero-address" in findings[0].message
    assert "identity" in findings[0].message
    assert "ecrecover(digest, v, r, s)" in findings[0].line_text


def test_flags_returned_ecrecover_with_no_check(tmp_path: Path) -> None:
    body = (
        "function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) "
        "external pure returns (address) {\n"
        "    return ecrecover(digest, v, r, s);\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "return ecrecover" in findings[0].line_text


def test_allows_zero_address_check_after_assignment(tmp_path: Path) -> None:
    body = (
        "function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) "
        "external pure returns (address) {\n"
        "    address signer = ecrecover(digest, v, r, s);\n"
        "    require(signer != address(0), \"bad sig\");\n"
        "    return signer;\n"
        "}\n"
    )
    assert not _scan(tmp_path, body)


def test_allows_address_zero_on_the_left(tmp_path: Path) -> None:
    body = (
        "function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) "
        "external pure returns (address) {\n"
        "    address signer = ecrecover(digest, v, r, s);\n"
        "    require(address(0) != signer);\n"
        "    return signer;\n"
        "}\n"
    )
    assert not _scan(tmp_path, body)


def test_allows_if_equal_zero_revert(tmp_path: Path) -> None:
    body = (
        "function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) "
        "external pure returns (address) {\n"
        "    address signer = ecrecover(digest, v, r, s);\n"
        "    if (signer == address(0)) revert();\n"
        "    return signer;\n"
        "}\n"
    )
    assert not _scan(tmp_path, body)


def test_allows_address_0x0_check(tmp_path: Path) -> None:
    body = (
        "function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) "
        "external pure returns (address) {\n"
        "    address signer = ecrecover(digest, v, r, s);\n"
        "    require(signer != address(0x0));\n"
        "    return signer;\n"
        "}\n"
    )
    assert not _scan(tmp_path, body)


def test_allows_identity_check_against_owner(tmp_path: Path) -> None:
    extra = "address public immutable owner = msg.sender;\n"
    body = (
        "function permit(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external view {\n"
        "    address signer = ecrecover(digest, v, r, s);\n"
        "    require(signer == owner, \"signer\");\n"
        "}\n"
    )
    assert not _scan(tmp_path, body, extra=extra)


def test_allows_owner_on_the_left_of_identity_check(tmp_path: Path) -> None:
    extra = "address public immutable owner = msg.sender;\n"
    body = (
        "function permit(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external view {\n"
        "    address signer = ecrecover(digest, v, r, s);\n"
        "    require(owner == signer);\n"
        "}\n"
    )
    assert not _scan(tmp_path, body, extra=extra)


def test_allows_inline_identity_check(tmp_path: Path) -> None:
    extra = "address public immutable owner = msg.sender;\n"
    body = (
        "function permit(bytes32 digest, uint8 v, bytes32 r, bytes32 s) "
        "external view returns (bool) {\n"
        "    return ecrecover(digest, v, r, s) == owner;\n"
        "}\n"
    )
    assert not _scan(tmp_path, body, extra=extra)


def test_allows_inline_identity_check_with_owner_first(tmp_path: Path) -> None:
    extra = "address public immutable owner = msg.sender;\n"
    body = (
        "function permit(bytes32 digest, uint8 v, bytes32 r, bytes32 s) "
        "external view returns (bool) {\n"
        "    return owner == ecrecover(digest, v, r, s);\n"
        "}\n"
    )
    assert not _scan(tmp_path, body, extra=extra)


def test_allows_inline_zero_address_check(tmp_path: Path) -> None:
    body = (
        "function ok(bytes32 digest, uint8 v, bytes32 r, bytes32 s) "
        "external pure returns (bool) {\n"
        "    return ecrecover(digest, v, r, s) != address(0);\n"
        "}\n"
    )
    assert not _scan(tmp_path, body)


def test_v_range_check_is_not_a_signer_check(tmp_path: Path) -> None:
    body = (
        "function claim(bytes32 digest, uint8 v, bytes32 r, bytes32 s) "
        "external pure returns (address) {\n"
        "    require(v == 27 || v == 28);\n"
        "    address signer = ecrecover(digest, v, r, s);\n"
        "    return signer;\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1


def test_flags_only_the_unchecked_call_when_two_are_present(tmp_path: Path) -> None:
    extra = "address public immutable owner = msg.sender;\n"
    body = (
        "function mixed(bytes32 a, bytes32 b, uint8 v, bytes32 r, bytes32 s) "
        "external view returns (address) {\n"
        "    address good = ecrecover(a, v, r, s);\n"
        "    require(good == owner);\n"
        "    address bad = ecrecover(b, v, r, s);\n"
        "    return bad;\n"
        "}\n"
    )
    findings = _scan(tmp_path, body, extra=extra)
    assert len(findings) == 1
    assert "ecrecover(b, v, r, s)" in findings[0].line_text


def test_check_before_a_later_call_does_not_cover_it(tmp_path: Path) -> None:
    body = (
        "function twice(bytes32 a, bytes32 b, uint8 v, bytes32 r, bytes32 s) "
        "external pure returns (address) {\n"
        "    address signer = ecrecover(a, v, r, s);\n"
        "    require(signer != address(0));\n"
        "    signer = ecrecover(b, v, r, s);\n"
        "    return signer;\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert findings[0].line_number >= 5


def test_handles_multiline_ecrecover(tmp_path: Path) -> None:
    body = (
        "function claim(bytes32 digest, uint8 v, bytes32 r, bytes32 s) "
        "external pure returns (address) {\n"
        "    address signer = ecrecover(\n"
        "        digest,\n"
        "        v,\n"
        "        r,\n"
        "        s\n"
        "    );\n"
        "    return signer;\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "ecrecover(" in findings[0].line_text


def test_ignores_commented_ecrecover(tmp_path: Path) -> None:
    body = (
        "function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) "
        "external pure returns (address) {\n"
        "    // return ecrecover(digest, v, r, s);\n"
        "    return address(0);\n"
        "}\n"
    )
    assert not _scan(tmp_path, body)


def test_ignore_directive_skips_ecrecover_line(tmp_path: Path) -> None:
    body = (
        "function claim(bytes32 digest, uint8 v, bytes32 r, bytes32 s) "
        "external pure returns (address) {\n"
        "    // sibaudit:ignore-next-line\n"
        "    return ecrecover(digest, v, r, s);\n"
        "}\n"
    )
    assert not _scan(tmp_path, body)


def test_constructor_ecrecover_is_scanned(tmp_path: Path) -> None:
    body = (
        "address public signer;\n"
        "constructor(bytes32 digest, uint8 v, bytes32 r, bytes32 s) {\n"
        "    signer = ecrecover(digest, v, r, s);\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "constructor" in findings[0].line_text or "ecrecover" in findings[0].line_text
