from __future__ import annotations

from pathlib import Path

from sibaudit.report import format_summary, summarize
from sibaudit.scanner import Finding


def _finding(code: str, severity: str, line: int = 1) -> Finding:
    return Finding(
        file_path=Path("demo.sol"),
        line_number=line,
        code=code,
        severity=severity,
        message="demo",
        line_text="//",
    )


def test_summarize_empty() -> None:
    summary = summarize([])
    assert summary.total == 0
    assert summary.by_code == ()
    assert summary.by_severity == ()
    assert format_summary([]) == "0 findings"


def test_summarize_counts_and_order() -> None:
    findings = [
        _finding("A003", "HIGH"),
        _finding("A001", "MEDIUM"),
        _finding("A003", "HIGH", line=2),
        _finding("A005", "LOW"),
        _finding("A005", "LOW", line=2),
        _finding("A005", "LOW", line=3),
    ]
    summary = summarize(findings)
    assert summary.total == 6
    assert summary.by_code == (("A001", 1), ("A003", 2), ("A005", 3))
    assert summary.by_severity == (("HIGH", 2), ("MEDIUM", 1), ("LOW", 3))
    assert summary.severity_by_code["A003"] == "HIGH"


def test_format_summary_singular_and_alignment() -> None:
    one = format_summary([_finding("A001", "MEDIUM")])
    assert one.startswith("1 finding\n")
    assert "by rule" in one
    assert "A001  MEDIUM  1" in one
    assert "by severity" in one
    assert "MEDIUM  1" in one

    many = format_summary(
        [
            _finding("A001", "MEDIUM"),
            _finding("A010", "LOW"),
            _finding("A010", "LOW", line=2),
        ]
    )
    assert many.splitlines()[0] == "3 findings"
    assert "A001  MEDIUM  1" in many
    assert "A010  LOW     2" in many
    assert "LOW     2" in many.split("by severity")[1]


def test_unknown_severity_is_listed_last() -> None:
    summary = summarize(
        [
            _finding("A001", "MEDIUM"),
            _finding("X999", "INFO"),
        ]
    )
    assert summary.by_severity == (("MEDIUM", 1), ("INFO", 1))
