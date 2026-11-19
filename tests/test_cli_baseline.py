from __future__ import annotations

import json
from pathlib import Path

import pytest

from sibaudit.baseline import dump_baseline
from sibaudit.cli import main
from sibaudit.scanner import scan_paths

RISKY = """
pragma solidity 0.8.20;
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


def test_update_baseline_follows_moved_finding_and_leaves_new_out(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    sol = src / "Token.sol"
    sol.write_text(RISKY)
    first = tmp_path / "baseline.json"

    with pytest.raises(SystemExit):
        main([str(sol), "--write-baseline", str(first)])
    capsys.readouterr()

    extra = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract C {
    function f() external view returns (address) {
        return tx.origin;
    }
    function g(address target) external {
        target.call("");
    }
}
""".strip()
    sol.write_text(extra)

    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--update-baseline", str(first)])
    assert shown.value.code == 1
    captured = capsys.readouterr()
    assert "A002" in captured.out
    assert "A001" not in captured.out
    assert "moved" in captured.err
    assert "new finding" in captured.err

    payload = json.loads(first.read_text())
    codes = {item["code"] for item in payload["findings"]}
    assert codes == {"A001"}
    assert all(item["line"] != 99 for item in payload["findings"])


def test_update_baseline_exits_zero_when_only_known_remain(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    snap = tmp_path / "baseline.json"

    with pytest.raises(SystemExit):
        main([str(sol), "--write-baseline", str(snap)])
    capsys.readouterr()

    with pytest.raises(SystemExit) as second:
        main([str(sol), "--update-baseline", str(snap)])
    assert second.value.code == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == ""
    assert "0 new findings left unsuppressed" in captured.err
    assert json.loads(snap.read_text())["findings"]


def test_update_baseline_missing_file_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    missing = tmp_path / "nope.json"
    with pytest.raises(SystemExit) as failed:
        main([str(sol), "--update-baseline", str(missing)])
    assert failed.value.code == 2
    err = capsys.readouterr().err
    assert "not found" in err
    assert "--write-baseline" in err


def test_update_baseline_rejects_write_baseline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit) as failed:
        main(
            [
                str(sol),
                "--write-baseline",
                str(tmp_path / "a.json"),
                "--update-baseline",
                str(tmp_path / "b.json"),
            ]
        )
    assert failed.value.code == 2
    assert "not both" in capsys.readouterr().err


def test_update_baseline_rejects_a_different_baseline_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit) as failed:
        main(
            [
                str(sol),
                "--baseline",
                str(tmp_path / "old.json"),
                "--update-baseline",
                str(tmp_path / "new.json"),
            ]
        )
    assert failed.value.code == 2
    assert "same file" in capsys.readouterr().err


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
