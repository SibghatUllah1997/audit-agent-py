from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from sibaudit.report import format_html
from sibaudit.scanner import Finding


def _finding(code: str, severity: str, line: int, text: str = "x", **kw) -> Finding:
    return Finding(
        file_path=Path("/proj/src/C.sol"),
        line_number=line,
        code=code,
        severity=severity,
        message=kw.pop("message", "msg"),
        line_text=text,
        **kw,
    )


def test_empty_report_says_zero_findings() -> None:
    page = format_html([])
    assert page.startswith("<!DOCTYPE html>")
    assert '<p id="total">0 findings</p>' in page
    assert "<h2>Findings</h2>" not in page


def test_counts_titles_and_severity_order() -> None:
    findings = [
        _finding("A001", "MEDIUM", 9),
        _finding("A027", "MEDIUM", 4),
        _finding("A026", "HIGH", 12),
    ]
    page = format_html(findings, Path("/proj"))
    assert '<p id="total">3 findings</p>' in page
    assert '<td class="sev-MEDIUM">MEDIUM</td><td class="num">2</td>' in page
    assert "Signature replay" in page
    body = page.split("<h2>Findings</h2>", 1)[1]
    assert body.index("src/C.sol:12") < body.index("src/C.sol:4") < body.index("src/C.sol:9")


def test_source_text_and_hints_are_escaped() -> None:
    finding = _finding(
        "A001",
        "MEDIUM",
        3,
        text='if (a < b && c > d) { "<script>" }',
        suggestion="use <b>x</b>",
    )
    page = format_html([finding])
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert "Hint: use &lt;b&gt;x&lt;/b&gt;" in page
    assert "/proj/src/C.sol:3" in page


def test_report_is_deterministic() -> None:
    findings = [_finding("A001", "MEDIUM", 1)]
    assert format_html(findings) == format_html(list(findings))


def test_cli_writes_report_and_keeps_stdout(tmp_path: Path) -> None:
    (tmp_path / "C.sol").write_text(
        "pragma solidity 0.8.20;\n"
        "contract C {\n"
        "    function f() external view returns (address) {\n"
        "        return tx.origin;\n"
        "    }\n"
        "}\n"
    )
    report = tmp_path / "out" / "report.html"
    report.parent.mkdir()
    proc = subprocess.run(
        [sys.executable, "-m", "sibaudit", "--html-report", str(report), "C.sol"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert proc.returncode == 1
    assert "A001" in proc.stdout
    page = report.read_text(encoding="utf-8")
    assert "C.sol:4" in page
    assert str(tmp_path) not in page


def test_cli_reports_unwritable_html_path(tmp_path: Path) -> None:
    (tmp_path / "C.sol").write_text("pragma solidity 0.8.20;\ncontract C {}\n")
    missing_dir = tmp_path / "no" / "r.html"
    proc = subprocess.run(
        [sys.executable, "-m", "sibaudit", "--html-report", str(missing_dir), "C.sol"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert proc.returncode == 2
    assert "HTML report" in proc.stderr
