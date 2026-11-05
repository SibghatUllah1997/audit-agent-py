from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "examples" / "vscode" / "tasks.json"
SAMPLE = ROOT / "examples" / "Vulnerable.sol"


def load_tasks() -> list[dict]:
    return json.loads(TASKS.read_text())["tasks"]


def matcher_pattern(task: dict) -> dict:
    (matcher,) = task["problemMatcher"]
    return matcher["pattern"]


def text_tasks() -> list[dict]:
    return [t for t in load_tasks() if t["problemMatcher"]]


def run_text_scan() -> list[str]:
    proc = subprocess.run(
        [sys.executable, "-m", "sibaudit", str(SAMPLE)],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert proc.returncode == 1
    return proc.stdout.splitlines()


def test_tasks_file_covers_text_and_json_formats() -> None:
    tasks = load_tasks()
    labels = [t["label"] for t in tasks]
    assert len(labels) == len(set(labels))
    assert any("(text)" in label for label in labels)
    json_tasks = [t for t in tasks if "json" in t["args"]]
    assert json_tasks
    assert all(t["args"][:2] == ["-m", "sibaudit"] for t in tasks)


def test_problem_matcher_matches_real_cli_output() -> None:
    lines = run_text_scan()
    finding_lines = [ln for ln in lines if re.match(r".+:\d+: A\d{3} ", ln)]
    assert finding_lines
    for task in text_tasks():
        pat = matcher_pattern(task)
        rx = re.compile(pat["regexp"])
        for ln in finding_lines:
            m = rx.match(ln)
            assert m, f"matcher does not match CLI line: {ln}"
            fields = ("file", "line", "code", "message")
            path, line, code, message = (m.group(pat[k]) for k in fields)
            assert path.endswith("Vulnerable.sol")
            assert int(line) > 0
            assert re.fullmatch(r"A\d{3}", code)
            assert message.strip()


def test_problem_matcher_ignores_summary_footer() -> None:
    lines = run_text_scan()
    footer = lines[lines.index("") + 1 :]
    assert footer
    for task in text_tasks():
        rx = re.compile(matcher_pattern(task)["regexp"])
        assert not [ln for ln in footer if rx.match(ln)]


def test_problem_matcher_handles_windows_paths() -> None:
    rx = re.compile(matcher_pattern(text_tasks()[0])["regexp"])
    m = rx.match(r"C:\work\Token.sol:7: A003 Use of delegatecall detected.")
    assert m and m.group(1) == r"C:\work\Token.sol" and m.group(2) == "7"
