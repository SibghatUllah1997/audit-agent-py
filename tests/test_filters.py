from __future__ import annotations

from pathlib import Path

import pytest

from sibaudit.filters import FilterError, apply_filters, parse_codes, parse_severity
from sibaudit.scanner import Finding


def _finding(code: str, severity: str) -> Finding:
    return Finding(
        file_path=Path("demo.sol"),
        line_number=1,
        code=code,
        severity=severity,
        message="demo",
        line_text="//",
    )


def test_parse_severity_blank_is_none() -> None:
    assert parse_severity(None) is None
    assert parse_severity("") is None
    assert parse_severity("  ") is None


def test_parse_severity_canonicalizes() -> None:
    assert parse_severity("high") == "HIGH"
    assert parse_severity("MEDIUM") == "MEDIUM"
    assert parse_severity(" Low ") == "LOW"


def test_parse_severity_rejects_unknown() -> None:
    with pytest.raises(FilterError, match="unknown severity"):
        parse_severity("CRITICAL")


def test_parse_codes_splits_and_dedupes() -> None:
    assert parse_codes(["A001, a008", "A001", " A009 "]) == ("A001", "A008", "A009")
    assert parse_codes([]) == ()
    assert parse_codes(["", " , "]) == ()


def test_parse_codes_rejects_unknown() -> None:
    with pytest.raises(FilterError, match="unknown rule code"):
        parse_codes(["A001", "A999"])


def test_only_is_an_allowlist() -> None:
    findings = [_finding("A001", "MEDIUM"), _finding("A008", "HIGH"), _finding("A017", "LOW")]
    out = apply_filters(findings, only=("A001", "A017"))
    assert [f.code for f in out] == ["A001", "A017"]


def test_except_drops_codes_after_only() -> None:
    findings = [_finding("A001", "MEDIUM"), _finding("A008", "HIGH")]
    out = apply_filters(findings, only=("A001", "A008"), except_codes=("A008",))
    assert [f.code for f in out] == ["A001"]


def test_min_severity_keeps_equal_and_above() -> None:
    findings = [
        _finding("A017", "LOW"),
        _finding("A001", "MEDIUM"),
        _finding("A008", "HIGH"),
    ]
    medium = apply_filters(findings, min_severity="MEDIUM")
    assert [f.code for f in medium] == ["A001", "A008"]
    high = apply_filters(findings, min_severity="HIGH")
    assert [f.code for f in high] == ["A008"]
    low = apply_filters(findings, min_severity="LOW")
    assert [f.code for f in low] == ["A017", "A001", "A008"]


def test_filters_preserve_order_and_objects() -> None:
    findings = [_finding("A001", "MEDIUM"), _finding("A008", "HIGH")]
    out = apply_filters(findings)
    assert out == findings
    assert out[0] is findings[0]
