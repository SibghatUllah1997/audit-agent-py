from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, body: str) -> list:
    (tmp_path / "C.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract C {\n" + body + "\n}\n"
    )
    return scan_paths([str(tmp_path)])


def test_flags_origin_compared_to_owner(tmp_path: Path) -> None:
    body = "function f() external { require(tx.origin == owner); }"
    findings = _scan(tmp_path, body)
    a014 = [f for f in findings if f.code == "A014"]
    assert a014
    assert a014[0].severity == "HIGH"
    assert "authorization comparison" in a014[0].message
    assert any(f.code == "A001" for f in findings)


def test_flags_origin_equals_sender_as_phishing_guard(tmp_path: Path) -> None:
    body = "function f() external view { require(tx.origin == msg.sender); }"
    findings = _scan(tmp_path, body)
    a014 = [f for f in findings if f.code == "A014"]
    assert len(a014) == 1
    assert "phishing" in a014[0].message


def test_flags_sender_compared_to_origin(tmp_path: Path) -> None:
    body = "function f() external view { if (msg.sender != tx.origin) revert(); }"
    findings = _scan(tmp_path, body)
    assert any(f.code == "A014" and "phishing" in f.message for f in findings)


def test_assignment_is_not_an_auth_comparison(tmp_path: Path) -> None:
    body = "function f() external view returns (address) { return tx.origin; }"
    findings = _scan(tmp_path, body)
    assert any(f.code == "A001" for f in findings)
    assert not any(f.code == "A014" for f in findings)


def test_ignores_comparison_in_comment(tmp_path: Path) -> None:
    body = (
        "function f() external pure returns (uint256) { return 1; }"
        " // require(tx.origin == owner)"
    )
    findings = _scan(tmp_path, body)
    assert not any(f.code == "A014" for f in findings)


def test_ignore_directive_skips_origin_comparison(tmp_path: Path) -> None:
    body = "// sibaudit:ignore-next-line\nrequire(tx.origin == owner);"
    findings = _scan(tmp_path, body)
    assert not any(f.code == "A014" for f in findings)


def test_sample_contract_flags_origin_auth_comparison() -> None:
    sample = Path(__file__).resolve().parents[1] / "examples" / "Vulnerable.sol"
    findings = scan_paths([str(sample)])
    assert any(f.code == "A014" and "tx.origin == owner" in f.line_text for f in findings)
