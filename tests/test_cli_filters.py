from __future__ import annotations

import json
from pathlib import Path

import pytest

from sibaudit.cli import main

SOURCE = """
pragma solidity ^0.8.20;
contract C {
    function f(address target) external {
        address who = tx.origin;
        target.call("");
    }
}
""".strip()


def _sol(tmp_path: Path) -> Path:
    sol = tmp_path / "Token.sol"
    sol.write_text(SOURCE)
    return sol


def _codes(capsys: pytest.CaptureFixture[str]) -> set[str]:
    records = [json.loads(ln) for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    return {row["code"] for row in records}


def test_only_keeps_named_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = _sol(tmp_path)
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--format", "json", "--only", "A001"])
    assert shown.value.code == 1
    assert _codes(capsys) == {"A001"}


def test_only_accepts_comma_list(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = _sol(tmp_path)
    with pytest.raises(SystemExit):
        main([str(sol), "--format", "json", "--only", "A001,A002"])
    assert _codes(capsys) == {"A001", "A002"}


def test_except_drops_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sol = _sol(tmp_path)
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--format", "json", "--except", "A002"])
    assert shown.value.code == 1
    codes = _codes(capsys)
    assert "A001" in codes
    assert "A002" not in codes


def test_except_after_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sol = _sol(tmp_path)
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--format", "json", "--only", "A001,A002", "--except", "A002"])
    assert shown.value.code == 1
    assert _codes(capsys) == {"A001"}


def test_min_severity_high_drops_medium(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = _sol(tmp_path)
    with pytest.raises(SystemExit) as clean:
        main([str(sol), "--format", "json", "--min-severity", "HIGH"])
    # A001 and A002 are MEDIUM, so a HIGH floor should hide them.
    assert clean.value.code == 0
    assert capsys.readouterr().out == ""


def test_min_severity_uses_config_override(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = _sol(tmp_path)
    cfg = tmp_path / "sibaudit.toml"
    cfg.write_text('[rules]\nA001 = "HIGH"\nA002 = false\n')
    with pytest.raises(SystemExit) as shown:
        main(
            [
                str(sol),
                "--config",
                str(cfg),
                "--format",
                "json",
                "--min-severity",
                "HIGH",
            ]
        )
    assert shown.value.code == 1
    records = [json.loads(ln) for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert {row["code"] for row in records} == {"A001"}
    assert records[0]["severity"] == "HIGH"


def test_unknown_only_code_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = _sol(tmp_path)
    with pytest.raises(SystemExit) as bad:
        main([str(sol), "--only", "A999"])
    assert bad.value.code == 2
    assert "unknown rule code" in capsys.readouterr().err


def test_unknown_min_severity_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = _sol(tmp_path)
    with pytest.raises(SystemExit) as bad:
        main([str(sol), "--min-severity", "CRITICAL"])
    assert bad.value.code == 2
    assert "unknown severity" in capsys.readouterr().err


def test_only_of_absent_code_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = _sol(tmp_path)
    with pytest.raises(SystemExit) as none_left:
        main([str(sol), "--only", "A010"])
    assert none_left.value.code == 0
    assert capsys.readouterr().out == ""


def test_env_min_severity_filters(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sol = _sol(tmp_path)
    monkeypatch.setenv("SIBAUDIT_MIN_SEVERITY", "HIGH")
    with pytest.raises(SystemExit) as clean:
        main([str(sol), "--format", "json"])
    assert clean.value.code == 0
    assert capsys.readouterr().out == ""


def test_env_only_filters(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sol = _sol(tmp_path)
    monkeypatch.setenv("SIBAUDIT_ONLY", "A001")
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--format", "json"])
    assert shown.value.code == 1
    assert _codes(capsys) == {"A001"}


def test_env_except_filters(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sol = _sol(tmp_path)
    monkeypatch.setenv("SIBAUDIT_EXCEPT", "A002")
    with pytest.raises(SystemExit):
        main([str(sol), "--format", "json"])
    codes = _codes(capsys)
    assert "A001" in codes
    assert "A002" not in codes


def test_cli_flags_override_env(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sol = _sol(tmp_path)
    monkeypatch.setenv("SIBAUDIT_ONLY", "A002")
    monkeypatch.setenv("SIBAUDIT_MIN_SEVERITY", "HIGH")
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--format", "json", "--only", "A001", "--min-severity", "LOW"])
    assert shown.value.code == 1
    assert _codes(capsys) == {"A001"}


def test_blank_env_is_ignored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sol = _sol(tmp_path)
    monkeypatch.setenv("SIBAUDIT_MIN_SEVERITY", "  ")
    monkeypatch.setenv("SIBAUDIT_ONLY", "")
    monkeypatch.setenv("SIBAUDIT_EXCEPT", "")
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--format", "json"])
    assert shown.value.code == 1
    codes = _codes(capsys)
    assert "A001" in codes
    assert "A002" in codes
