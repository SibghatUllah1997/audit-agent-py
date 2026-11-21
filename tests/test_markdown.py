from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from sibaudit.markdown import format_markdown
from sibaudit.scanner import Finding

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "Vulnerable.sol"


def _finding(code: str, severity: str, line: int, text: str = "x();", **kw) -> Finding:
    return Finding(
        file_path=Path("/proj/src/C.sol"),
        line_number=line,
        code=code,
        severity=severity,
        message=kw.pop("message", "msg"),
        line_text=text,
        **kw,
    )


def test_no_findings_is_short() -> None:
    assert format_markdown([]) == "## sibaudit\n\nNo findings.\n"


def test_counts_and_rule_table() -> None:
    findings = [
        _finding("A001", "MEDIUM", 9),
        _finding("A001", "MEDIUM", 3),
        _finding("A026", "HIGH", 12),
    ]
    text = format_markdown(findings, cwd=Path("/proj"))
    assert "**3 findings** (1 high, 2 medium)" in text
    assert "| A001 | MEDIUM | Risky use of `tx.origin` | 2 |" in text
    assert "| A026 | HIGH | Signature replay" in text


def test_groups_by_severity_highest_first() -> None:
    findings = [
        _finding("A017", "LOW", 1),
        _finding("A001", "MEDIUM", 5),
        _finding("A003", "HIGH", 30),
        _finding("A004", "HIGH", 2),
    ]
    text = format_markdown(findings, cwd=Path("/proj"))
    assert text.index("### HIGH") < text.index("### MEDIUM") < text.index("### LOW")
    high = text.split("### HIGH", 1)[1].split("### MEDIUM", 1)[0]
    assert high.index("src/C.sol:2 ") < high.index("src/C.sol:30 ")
    assert text.count("### HIGH") == 1


def test_source_cannot_break_the_table() -> None:
    finding = _finding(
        "A002",
        "MEDIUM",
        4,
        text='  a | b <script> "q"  `tick`\t',
        message="pipe | in message",
    )
    text = format_markdown([finding], cwd=Path("/proj"))
    row = next(line for line in text.splitlines() if line.startswith("| src/C.sol:4"))
    assert row.count(" | ") == 3
    assert "<code>a &#124; b &lt;script&gt; \"q\" `tick`</code>" in row
    assert "pipe \\| in message" in row


def test_path_outside_root_is_kept_and_escaped() -> None:
    finding = Finding(
        file_path=Path("/other/my_file.sol"),
        line_number=1,
        code="A001",
        severity="MEDIUM",
        message="m",
        line_text="x",
    )
    text = format_markdown([finding], cwd=Path("/proj"))
    assert "| /other/my\\_file.sol:1 |" in text


def test_hint_is_appended() -> None:
    finding = _finding("A022", "MEDIUM", 7, suggestion="use call")
    text = format_markdown([finding], cwd=Path("/proj"))
    assert "msg Hint: use call" in text


def test_row_cap_keeps_counts_exact() -> None:
    findings = [_finding("A017", "LOW", n) for n in range(1, 8)]
    text = format_markdown(findings, cwd=Path("/proj"), max_rows=5)
    assert "**7 findings** (7 low)" in text
    assert sum(1 for line in text.splitlines() if line.startswith("| src/C.sol:")) == 5
    assert "_2 more findings not listed." in text


def test_output_is_stable() -> None:
    findings = [_finding("A001", "MEDIUM", 2), _finding("A003", "HIGH", 1)]
    assert format_markdown(findings, cwd=Path("/proj")) == format_markdown(
        list(reversed(findings)), cwd=Path("/proj")
    )


def test_cli_markdown_on_sample() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "sibaudit", "--format", "markdown", str(SAMPLE)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    out = proc.stdout
    assert out.startswith("## sibaudit\n")
    assert "### HIGH" in out and "### MEDIUM" in out and "### LOW" in out
    assert "| examples/Vulnerable.sol:" in out
    assert "by severity" not in out


def test_cli_markdown_clean_file(tmp_path: Path) -> None:
    sol = tmp_path / "Ok.sol"
    sol.write_text("pragma solidity 0.8.24;\ncontract Ok {}\n")
    proc = subprocess.run(
        [sys.executable, "-m", "sibaudit", "--format", "markdown", str(sol)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout == "## sibaudit\n\nNo findings.\n"
