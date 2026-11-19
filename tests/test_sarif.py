from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sibaudit.sarif import build_sarif, format_sarif
from sibaudit.scanner import Finding


def _finding(code: str, severity: str, line: int, text: str = "x", **kw) -> Finding:
    return Finding(
        file_path=kw.pop("path", Path("/proj/src/C.sol")),
        line_number=line,
        code=code,
        severity=severity,
        message=kw.pop("message", "msg"),
        line_text=text,
        **kw,
    )


def _results(log: dict) -> list[dict]:
    return log["runs"][0]["results"]


def test_empty_log_is_valid_shape() -> None:
    log = build_sarif([], root=Path("/proj"))
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["tool"]["driver"]["name"] == "sibaudit"
    assert log["runs"][0]["tool"]["driver"]["rules"] == []
    assert _results(log) == []


def test_levels_rules_and_relative_paths() -> None:
    findings = [
        _finding("A026", "HIGH", 12, "bytes32 h = keccak256(data);"),
        _finding("A001", "MEDIUM", 3, "require(tx.origin == owner);"),
        _finding("A001", "LOW", 9, "require(tx.origin == admin);"),
    ]
    log = build_sarif(findings, root=Path("/proj"))
    rules = log["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["A001", "A026"]
    assert rules[1]["properties"]["security-severity"] == "8.0"
    assert "Signature replay" in rules[1]["shortDescription"]["text"]

    results = _results(log)
    assert [(r["ruleId"], r["level"]) for r in results] == [
        ("A001", "warning"),
        ("A001", "note"),
        ("A026", "error"),
    ]
    for result in results:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/C.sol"
    assert results[2]["locations"][0]["physicalLocation"]["region"]["startLine"] == 12


def test_hint_is_appended_to_message() -> None:
    log = build_sarif([_finding("A001", "MEDIUM", 1, suggestion="use msg.sender")])
    assert _results(log)[0]["message"]["text"] == "msg Hint: use msg.sender"


def test_fingerprint_survives_line_moves_and_whitespace() -> None:
    before = build_sarif([_finding("A001", "MEDIUM", 4, "require(tx.origin == o);")])
    after = build_sarif([_finding("A001", "MEDIUM", 40, "   require(tx.origin  ==  o);")])
    fp = _results(before)[0]["partialFingerprints"]["primaryLocationLineHash"]
    assert fp == _results(after)[0]["partialFingerprints"]["primaryLocationLineHash"]


def test_duplicate_lines_get_distinct_fingerprints() -> None:
    findings = [
        _finding("A002", "MEDIUM", 5, "to.call{value: v}(\"\");"),
        _finding("A002", "MEDIUM", 8, "to.call{value: v}(\"\");"),
    ]
    prints = [r["partialFingerprints"]["primaryLocationLineHash"] for r in _results(
        build_sarif(findings)
    )]
    assert len(set(prints)) == 2
    assert prints[0].endswith(":1") and prints[1].endswith(":2")


def test_output_is_deterministic_json() -> None:
    findings = [_finding("A001", "MEDIUM", 2), _finding("A002", "MEDIUM", 1)]
    first = format_sarif(findings, root=Path("/proj"))
    second = format_sarif(list(reversed(findings)), root=Path("/proj"))
    assert first == second
    json.loads(first)


def test_cli_sarif_format(tmp_path: Path) -> None:
    src = tmp_path / "Bad.sol"
    src.write_text(
        "pragma solidity 0.8.20;\n"
        "contract Bad {\n"
        "    address owner;\n"
        "    function f() public { require(tx.origin == owner); }\n"
        "}\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, "-m", "sibaudit", "--format", "sarif", "Bad.sol"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    log = json.loads(proc.stdout)
    results = _results(log)
    assert any(r["ruleId"] == "A001" for r in results)
    a001 = next(r for r in results if r["ruleId"] == "A001")
    loc = a001["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "Bad.sol"
    assert loc["region"]["startLine"] == 4
