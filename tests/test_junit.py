from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from sibaudit.junit import format_junit
from sibaudit.scanner import Finding

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "Vulnerable.sol"


def _finding(code: str, severity: str, line: int, text: str = "x();", **kw) -> Finding:
    return Finding(
        file_path=kw.pop("path", Path("/proj/src/C.sol")),
        line_number=line,
        code=code,
        severity=severity,
        message=kw.pop("message", "msg"),
        line_text=text,
        **kw,
    )


def _suite(xml: str) -> ET.Element:
    root = ET.fromstring(xml)
    assert root.tag == "testsuites"
    assert root.attrib["name"] == "sibaudit"
    suites = list(root)
    assert len(suites) == 1
    return suites[0]


def test_clean_scan_is_one_passing_testcase() -> None:
    xml = format_junit([])
    suite = _suite(xml)
    assert suite.attrib["tests"] == "1"
    assert suite.attrib["failures"] == "0"
    cases = list(suite)
    assert len(cases) == 1
    assert cases[0].attrib["name"] == "scan"
    assert cases[0].attrib["classname"] == "sibaudit"
    assert list(cases[0]) == []
    assert xml.startswith('<?xml version="1.0" encoding="UTF-8"?>')
    assert xml.endswith("\n")


def test_findings_are_failed_testcases_with_file_and_line() -> None:
    findings = [
        _finding("A001", "MEDIUM", 9, "return tx.origin;", message="risky tx.origin"),
        _finding("A026", "HIGH", 12, "ecrecover(h, v, r, s);", message="replay"),
    ]
    xml = format_junit(findings, cwd=Path("/proj"))
    suite = _suite(xml)
    assert suite.attrib["tests"] == "2"
    assert suite.attrib["failures"] == "2"
    cases = list(suite)
    assert [c.attrib["classname"] for c in cases] == ["A026", "A001"]
    assert cases[0].attrib["file"] == "src/C.sol"
    assert cases[0].attrib["line"] == "12"
    assert cases[0].attrib["name"] == "src/C.sol:12 A026"
    failure = list(cases[0])[0]
    assert failure.tag == "failure"
    assert failure.attrib["type"] == "HIGH"
    assert failure.attrib["message"] == "replay"
    assert "src/C.sol:12: A026 replay" in (failure.text or "")
    assert "ecrecover(h, v, r, s);" in (failure.text or "")


def test_source_cannot_break_the_xml() -> None:
    finding = _finding(
        "A002",
        "MEDIUM",
        4,
        'target.call("<payload> & \'x\'");',
        message='a <b> & "c"',
    )
    xml = format_junit([finding], cwd=Path("/proj"))
    suite = _suite(xml)
    failure = list(list(suite)[0])[0]
    assert failure.attrib["message"] == 'a <b> & "c"'
    assert "<payload>" in (failure.text or "")
    assert "&" in (failure.text or "")
    ET.fromstring(xml)


def test_hint_is_appended_to_the_failure_body() -> None:
    xml = format_junit(
        [_finding("A001", "MEDIUM", 1, suggestion="use msg.sender")],
        cwd=Path("/proj"),
    )
    failure = list(list(_suite(xml))[0])[0]
    assert "Hint: use msg.sender" in (failure.text or "")


def test_order_is_stable() -> None:
    findings = [
        _finding("A017", "LOW", 1),
        _finding("A001", "MEDIUM", 5),
        _finding("A003", "HIGH", 30),
        _finding("A004", "HIGH", 2),
    ]
    first = format_junit(findings, cwd=Path("/proj"))
    second = format_junit(list(reversed(findings)), cwd=Path("/proj"))
    assert first == second
    names = [c.attrib["name"] for c in list(_suite(first))]
    assert names == [
        "src/C.sol:2 A004",
        "src/C.sol:30 A003",
        "src/C.sol:5 A001",
        "src/C.sol:1 A017",
    ]


def test_cli_junit_on_sample() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "sibaudit", "--format", "junit", str(SAMPLE)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    suite = _suite(proc.stdout)
    n = int(suite.attrib["tests"])
    assert n > 0
    assert suite.attrib["failures"] == str(n)
    codes = {c.attrib["classname"] for c in list(suite)}
    assert "A001" in codes
    assert "A032" in codes
    assert all(c.attrib["file"].endswith("examples/Vulnerable.sol") for c in list(suite))


def test_junit_report_example_writes_xml_artifact() -> None:
    text = (ROOT / "examples" / "github" / "junit-report.yml").read_text()
    assert text.lstrip().startswith("# Copy this file to .github/workflows/")
    assert "--format junit --output sibaudit-junit.xml" in text
    assert "actions/upload-artifact@v4" in text
    assert "if: always()" in text


def test_cli_junit_clean_file(tmp_path: Path) -> None:
    sol = tmp_path / "Ok.sol"
    sol.write_text("pragma solidity 0.8.24;\ncontract Ok {}\n")
    proc = subprocess.run(
        [sys.executable, "-m", "sibaudit", "--format", "junit", str(sol)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout == format_junit([])
