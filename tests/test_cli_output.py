from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CODE_SCANNING = ROOT / "examples" / "github" / "code-scanning.yml"

RISKY = """
pragma solidity 0.8.20;
contract C {
    function f() external view returns (address) {
        return tx.origin;
    }
}
""".strip()


def _run(
    tmp_path: Path, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    (tmp_path / "C.sol").write_text(RISKY + "\n")
    merged = {k: v for k, v in os.environ.items() if not k.startswith("SIBAUDIT_")}
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, "-m", "sibaudit", *args, "C.sol"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=merged,
    )


def test_output_file_matches_stdout_and_silences_it(tmp_path: Path) -> None:
    report = tmp_path / "out" / "findings.txt"
    report.parent.mkdir()
    printed = _run(tmp_path, "--fail-on", "never")
    written = _run(tmp_path, "--fail-on", "never", "--output", str(report))
    assert printed.returncode == 0
    assert written.returncode == 0
    assert "A001" in printed.stdout
    assert written.stdout == ""
    assert report.read_text(encoding="utf-8") == printed.stdout


def test_output_writes_sarif_json(tmp_path: Path) -> None:
    report = tmp_path / "sibaudit.sarif"
    proc = _run(tmp_path, "--format", "sarif", "--output", str(report))
    assert proc.returncode == 1
    assert proc.stdout == ""
    log = json.loads(report.read_text(encoding="utf-8"))
    results = log["runs"][0]["results"]
    assert any(item["ruleId"] == "A001" for item in results)


def test_output_writes_markdown(tmp_path: Path) -> None:
    report = tmp_path / "summary.md"
    proc = _run(tmp_path, "--format", "markdown", "--fail-on", "never", "--output", str(report))
    assert proc.returncode == 0
    text = report.read_text(encoding="utf-8")
    assert text.startswith("## sibaudit")
    assert "A001" in text
    assert proc.stdout == ""


def test_empty_scan_still_writes_the_file(tmp_path: Path) -> None:
    (tmp_path / "Clean.sol").write_text("pragma solidity 0.8.20;\ncontract C {}\n")
    report = tmp_path / "empty.md"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sibaudit",
            "--format",
            "markdown",
            "--output",
            str(report),
            "Clean.sol",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert report.read_text(encoding="utf-8") == "## sibaudit\n\nNo findings.\n"


def test_env_output_path_and_flag_wins(tmp_path: Path) -> None:
    via_env = tmp_path / "from-env.txt"
    via_flag = tmp_path / "from-flag.txt"
    proc = _run(
        tmp_path,
        "--fail-on",
        "never",
        "--output",
        str(via_flag),
        env={"SIBAUDIT_OUTPUT": str(via_env)},
    )
    assert proc.returncode == 0
    assert via_flag.is_file()
    assert not via_env.exists()

    proc = _run(tmp_path, "--fail-on", "never", env={"SIBAUDIT_OUTPUT": str(via_env)})
    assert proc.returncode == 0
    assert via_env.is_file()
    assert "A001" in via_env.read_text(encoding="utf-8")


def test_blank_env_output_keeps_stdout(tmp_path: Path) -> None:
    proc = _run(tmp_path, "--fail-on", "never", env={"SIBAUDIT_OUTPUT": "  "})
    assert proc.returncode == 0
    assert "A001" in proc.stdout


def test_unwritable_output_path_exits_2(tmp_path: Path) -> None:
    missing = tmp_path / "no" / "dir" / "out.txt"
    proc = _run(tmp_path, "--output", str(missing))
    assert proc.returncode == 2
    assert "cannot write output file" in proc.stderr


def test_html_report_still_works_with_output(tmp_path: Path) -> None:
    text_report = tmp_path / "findings.txt"
    html_report = tmp_path / "findings.html"
    proc = _run(
        tmp_path,
        "--fail-on",
        "never",
        "--output",
        str(text_report),
        "--html-report",
        str(html_report),
    )
    assert proc.returncode == 0
    assert "A001" in text_report.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_report.read_text(encoding="utf-8")
    assert proc.stdout == ""


def test_code_scanning_example_uses_output_flag() -> None:
    text = CODE_SCANNING.read_text(encoding="utf-8")
    assert "--output sibaudit.sarif" in text
    assert "> sibaudit.sarif" not in text
