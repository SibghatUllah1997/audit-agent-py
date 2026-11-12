from __future__ import annotations

import json
from pathlib import Path

import pytest

from sibaudit.cli import main
from sibaudit.suggest import hint_for

RISKY = """
pragma solidity ^0.8.20;
contract C {
    function f() external view returns (address) {
        return tx.origin;
    }
}
""".strip()


def test_suggest_appends_hint_lines_in_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--suggest"])
    assert shown.value.code == 1
    out = capsys.readouterr().out
    lines = out.splitlines()
    finding_line = next(ln for ln in lines if ": A001 " in ln)
    hint_line = lines[lines.index(finding_line) + 1]
    expected = hint_for("A001", "Potential risky use of tx.origin (often unsafe for auth).")
    assert hint_line == f"    hint: {expected}"
    assert f"hint: {expected}" in out
    # Indented hint lines must not look like finding lines.
    assert not hint_line.startswith(str(sol))


def test_suggest_json_adds_suggestion_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit):
        main([str(sol), "--format", "json", "--suggest"])
    rows = [json.loads(ln) for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert rows
    assert all(row.get("suggestion") for row in rows)
    assert all(row["code"] == "A001" for row in rows)
    assert "msg.sender" in rows[0]["suggestion"]


def test_json_without_suggest_omits_suggestion_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit):
        main([str(sol), "--format", "json"])
    rows = [json.loads(ln) for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert rows
    assert all("suggestion" not in row for row in rows)


def test_suggest_github_includes_hint_in_annotation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--format", "github", "--suggest"])
    assert shown.value.code == 1
    out = capsys.readouterr().out
    assert "A001 (MEDIUM)" in out
    assert " — " in out
    assert "msg.sender" in out
    assert "hint:" not in out


def test_suggest_summary_lists_hint_under_the_rule(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit):
        main([str(sol), "--format", "summary", "--suggest"])
    out = capsys.readouterr().out
    assert "A001" in out
    assert "hint:" in out
    assert "msg.sender" in out
    assert "Token.sol:" not in out


def test_suggest_on_clean_file_prints_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Clean.sol"
    sol.write_text("pragma solidity ^0.8.20;\ncontract C {}\n")
    with pytest.raises(SystemExit) as clean:
        main([str(sol), "--suggest"])
    assert clean.value.code == 0
    assert capsys.readouterr().out == ""
