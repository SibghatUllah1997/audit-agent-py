from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / "examples" / "github" / "annotate.yml"
SAMPLE = ROOT / "examples" / "Vulnerable.sol"

ANNOTATION = re.compile(
    r"^::(?P<level>error|warning|notice) "
    r"file=(?P<file>[^,]+),line=(?P<line>\d+),"
    r"title=(?P<title>[^:]+)::(?P<message>.+)$"
)


def workflow_text() -> str:
    return WORKFLOW.read_text()


def test_workflow_file_is_a_github_actions_job() -> None:
    text = workflow_text()
    assert text.lstrip().startswith("# Copy this file to .github/workflows/")
    assert "\nname: sibaudit\n" in text
    assert "pull_request:" in text
    assert "runs-on: ubuntu-latest" in text
    assert "actions/checkout@v4" in text
    assert "actions/setup-python@v5" in text
    assert 'python-version: "3.11"' in text
    assert "pip install sibaudit" in text


def test_workflow_scan_step_uses_github_format() -> None:
    text = workflow_text()
    assert "python3 -m sibaudit --format github ." in text
    # Annotations only land when the command itself prints workflow commands.
    assert "--format json" not in text
    assert "--format text" not in text
    assert "--format summary" not in text


def test_github_format_matches_workflow_annotation_shape() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "sibaudit", "--format", "github", str(SAMPLE)],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert proc.returncode == 1
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert lines
    parsed = [ANNOTATION.match(ln) for ln in lines]
    assert all(parsed)
    levels = {match.group("level") for match in parsed if match}
    assert "error" in levels
    assert "warning" in levels
    assert all("by rule" not in ln for ln in lines)
