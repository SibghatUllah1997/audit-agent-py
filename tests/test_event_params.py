from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, body: str) -> list:
    (tmp_path / "C.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract C {\n" + body + "\n}\n"
    )
    return scan_paths([str(tmp_path)])


def test_flags_transfer_event_missing_amount(tmp_path: Path) -> None:
    body = "event Transfer(address indexed from, address indexed to);"
    findings = _scan(tmp_path, body)
    assert any(f.code == "A012" and "amount" in f.message for f in findings)


def test_flags_deposit_event_missing_address(tmp_path: Path) -> None:
    body = "event Deposit(uint256 amount);"
    findings = _scan(tmp_path, body)
    assert any(f.code == "A012" and "address" in f.message for f in findings)


def test_flags_empty_transfer_event(tmp_path: Path) -> None:
    body = "event Transfer();"
    findings = _scan(tmp_path, body)
    assert any(
        f.code == "A012" and "amount" in f.message and "address" in f.message for f in findings
    )


def test_allows_complete_transfer_event(tmp_path: Path) -> None:
    body = "event Transfer(address indexed from, address indexed to, uint256 value);"
    findings = _scan(tmp_path, body)
    assert not any(f.code == "A012" for f in findings)


def test_allows_parameterless_status_event(tmp_path: Path) -> None:
    body = "event Paused();"
    findings = _scan(tmp_path, body)
    assert not any(f.code == "A012" for f in findings)


def test_ignores_event_in_comment(tmp_path: Path) -> None:
    body = "function f() external {} // event Transfer();"
    findings = _scan(tmp_path, body)
    assert not any(f.code == "A012" for f in findings)


def test_ignore_directive_skips_event(tmp_path: Path) -> None:
    body = "// sibaudit:ignore-next-line\nevent Withdraw(uint256 amount);"
    findings = _scan(tmp_path, body)
    assert not any(f.code == "A012" for f in findings)
