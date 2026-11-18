from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from sibaudit.filters import FilterError, parse_fail_on, should_fail
from sibaudit.scanner import Finding

# Findings here are MEDIUM at most (tx.origin, an unchecked low-level call).
SOURCE = """
pragma solidity 0.8.20;
contract C {
    function f(address target) external {
        address who = tx.origin;
        target.call("");
    }
}
""".lstrip()


def _finding(severity: str) -> Finding:
    return Finding(
        file_path=Path("C.sol"),
        line_number=1,
        code="A001",
        severity=severity,
        message="m",
        line_text="x",
    )


def _run(tmp_path: Path, *args: str, env: dict[str, str] | None = None):
    (tmp_path / "C.sol").write_text(SOURCE)
    base = {k: v for k, v in os.environ.items() if not k.startswith("SIBAUDIT_")}
    return subprocess.run(
        [sys.executable, "-m", "sibaudit", *args, "C.sol"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={**base, **(env or {})},
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(None, "any"), ("", "any"), ("ANY", "any"), ("never", "never"), ("high", "HIGH")],
)
def test_parse_fail_on(raw: str | None, expected: str) -> None:
    assert parse_fail_on(raw) == expected


def test_parse_fail_on_rejects_unknown_levels() -> None:
    with pytest.raises(FilterError, match="--fail-on"):
        parse_fail_on("critical")


def test_should_fail_compares_against_the_threshold() -> None:
    medium = [_finding("MEDIUM")]
    assert should_fail(medium, "any")
    assert should_fail(medium, "LOW")
    assert should_fail(medium, "MEDIUM")
    assert not should_fail(medium, "HIGH")
    assert not should_fail(medium, "never")
    assert not should_fail([], "any")


def test_cli_default_still_fails_on_any_finding(tmp_path: Path) -> None:
    assert _run(tmp_path).returncode == 1


def test_cli_fail_on_high_passes_but_still_reports(tmp_path: Path) -> None:
    proc = _run(tmp_path, "--fail-on", "high")
    assert proc.returncode == 0
    assert "A001" in proc.stdout


def test_cli_fail_on_medium_fails(tmp_path: Path) -> None:
    assert _run(tmp_path, "--fail-on", "MEDIUM").returncode == 1


def test_cli_fail_on_never_and_env_variable(tmp_path: Path) -> None:
    assert _run(tmp_path, "--fail-on", "never").returncode == 0
    assert _run(tmp_path, env={"SIBAUDIT_FAIL_ON": "HIGH"}).returncode == 0
    # An explicit flag wins over the environment.
    assert _run(tmp_path, "--fail-on", "low", env={"SIBAUDIT_FAIL_ON": "never"}).returncode == 1


def test_cli_rejects_bad_fail_on(tmp_path: Path) -> None:
    proc = _run(tmp_path, "--fail-on", "urgent")
    assert proc.returncode == 2
    assert "--fail-on" in proc.stderr
