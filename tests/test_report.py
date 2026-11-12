from __future__ import annotations

from pathlib import Path

from sibaudit.report import (
    format_github_annotations,
    format_summary,
    relative_display_path,
    summarize,
)
from sibaudit.scanner import Finding


def _finding(
    code: str, severity: str, line: int = 1, suggestion: str | None = None
) -> Finding:
    return Finding(
        file_path=Path("demo.sol"),
        line_number=line,
        code=code,
        severity=severity,
        message="demo",
        line_text="//",
        suggestion=suggestion,
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


def test_format_summary_includes_hints_when_present() -> None:
    text = format_summary(
        [
            _finding("A001", "MEDIUM", suggestion="Prefer msg.sender."),
            _finding("A001", "MEDIUM", line=2, suggestion="Prefer msg.sender."),
            _finding("A003", "HIGH", suggestion="Avoid delegatecall."),
        ]
    )
    assert "A001  MEDIUM  2" in text
    assert "A003  HIGH    1" in text
    assert text.count("hint: Prefer msg.sender.") == 1
    assert "hint: Avoid delegatecall." in text
    # Counts-only output is unchanged when no finding carries a hint.
    plain = format_summary([_finding("A001", "MEDIUM")])
    assert "hint:" not in plain


def test_unknown_severity_is_listed_last() -> None:
    summary = summarize(
        [
            _finding("A001", "MEDIUM"),
            _finding("X999", "INFO"),
        ]
    )
    assert summary.by_severity == (("MEDIUM", 1), ("INFO", 1))


def test_github_annotations_map_severity_and_relative_paths(tmp_path: Path) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text("//")
    findings = [
        Finding(
            file_path=sol,
            line_number=4,
            code="A003",
            severity="HIGH",
            message="delegatecall",
            line_text="//",
        ),
        Finding(
            file_path=sol,
            line_number=9,
            code="A001",
            severity="MEDIUM",
            message="tx.origin",
            line_text="//",
        ),
        Finding(
            file_path=sol,
            line_number=12,
            code="A010",
            severity="LOW",
            message="gasprice",
            line_text="//",
        ),
    ]
    text = format_github_annotations(findings, cwd=tmp_path)
    lines = text.splitlines()
    assert lines[0] == "::error file=Token.sol,line=4,title=A003 (HIGH)::delegatecall"
    assert lines[1] == "::warning file=Token.sol,line=9,title=A001 (MEDIUM)::tx.origin"
    assert lines[2] == "::notice file=Token.sol,line=12,title=A010 (LOW)::gasprice"


def test_github_annotations_escape_special_characters(tmp_path: Path) -> None:
    sol = tmp_path / "C.sol"
    sol.write_text("//")
    finding = Finding(
        file_path=sol,
        line_number=3,
        code="A001",
        severity="MEDIUM",
        message="100% bad: a, b\nand more",
        line_text="//",
    )
    text = format_github_annotations([finding], cwd=tmp_path)
    assert text.startswith("::warning file=C.sol,line=3,title=A001 (MEDIUM)::")
    assert "100%25 bad: a, b%0Aand more" in text


def test_github_annotations_append_suggestion_when_set(tmp_path: Path) -> None:
    sol = tmp_path / "C.sol"
    sol.write_text("//")
    finding = Finding(
        file_path=sol,
        line_number=3,
        code="A001",
        severity="MEDIUM",
        message="tx.origin",
        line_text="//",
        suggestion="Prefer msg.sender.",
    )
    text = format_github_annotations([finding], cwd=tmp_path)
    assert text == (
        "::warning file=C.sol,line=3,title=A001 (MEDIUM)::"
        "tx.origin — Prefer msg.sender."
    )


def test_github_annotations_empty() -> None:
    assert format_github_annotations([]) == ""


def test_relative_display_path_falls_back_outside_root(tmp_path: Path) -> None:
    outside = tmp_path / "other" / "X.sol"
    root = tmp_path / "workspace"
    root.mkdir()
    outside.parent.mkdir()
    outside.write_text("//")
    assert relative_display_path(outside, root) == outside.resolve().as_posix()
