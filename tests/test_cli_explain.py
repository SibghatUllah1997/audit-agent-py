from __future__ import annotations

import subprocess
import sys

from sibaudit.rules import RULES


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "sibaudit", *args], capture_output=True, text=True)


def test_list_rules_prints_one_line_per_rule() -> None:
    proc = run("--list-rules")
    assert proc.returncode == 0
    lines = proc.stdout.strip().splitlines()
    assert len(lines) == len(RULES)
    assert lines[0].startswith("A001  MEDIUM")


def test_explain_prints_rule_and_exits_zero() -> None:
    proc = run("--explain", "a020")
    assert proc.returncode == 0
    assert proc.stdout.startswith("A020 (HIGH): ")
    assert "modifier onlyOwner()" in proc.stdout


def test_explain_unknown_code_exits_two() -> None:
    proc = run("--explain", "A999")
    assert proc.returncode == 2
    assert "unknown rule code" in proc.stderr
    assert proc.stdout == ""
