from __future__ import annotations

import json
from pathlib import Path

import pytest

from sibaudit.baseline import dump_baseline
from sibaudit.cli import main
from sibaudit.scanner import scan_paths

RISKY = """
pragma solidity ^0.8.20;
contract C {
    function f() external view returns (address) {
        return tx.origin;
    }
}
""".strip()


def test_baseline_hides_known_finding(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = tmp_path / "src"
    src.mkdir()
    sol = src / "Token.sol"
    sol.write_text(RISKY)
    findings = scan_paths([str(sol)])
    assert any(f.code == "A001" for f in findings)

    baseline = tmp_path / "baseline.json"
    baseline.write_text(dump_baseline(findings, tmp_path))

    with pytest.raises(SystemExit) as suppressed:
        main([str(sol), "--baseline", str(baseline)])
    assert suppressed.value.code == 0
    assert capsys.readouterr().out.strip() == ""


def test_baseline_keeps_new_findings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "version": 1,
                "findings": [{"file": "Token.sol", "line": 99, "code": "A001"}],
            }
        )
    )

    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--baseline", str(baseline)])
    assert shown.value.code == 1
    out = capsys.readouterr().out
    assert "A001" in out


def test_missing_baseline_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    missing = tmp_path / "nope.json"
    with pytest.raises(SystemExit) as failed:
        main([str(sol), "--baseline", str(missing)])
    assert failed.value.code == 2
    err = capsys.readouterr().err
    assert "not found" in err


def test_write_baseline_snapshots_current_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    out = tmp_path / "snap.json"

    with pytest.raises(SystemExit) as first:
        main([str(sol), "--write-baseline", str(out)])
    assert first.value.code == 1
    capsys.readouterr()
    payload = json.loads(out.read_text())
    assert payload["version"] == 1
    assert payload["findings"]
    assert all(item["code"] == "A001" for item in payload["findings"])

    with pytest.raises(SystemExit) as second:
        main([str(sol), "--baseline", str(out)])
    assert second.value.code == 0
    assert capsys.readouterr().out.strip() == ""


def test_write_baseline_keeps_full_snapshot_when_filtering(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    old = tmp_path / "old.json"
    old.write_text(dump_baseline(scan_paths([str(sol)]), Path.cwd().resolve()))
    fresh = tmp_path / "nested" / "new.json"

    with pytest.raises(SystemExit) as filtered:
        main([str(sol), "--baseline", str(old), "--write-baseline", str(fresh)])
    assert filtered.value.code == 0
    capsys.readouterr()
    written = json.loads(fresh.read_text())
    assert written["findings"], "snapshot should include findings even when output is empty"
