from __future__ import annotations

import json
from pathlib import Path

import pytest

from sibaudit.cli import main

RISKY = """
pragma solidity ^0.8.20;
contract C {
    function f() external view returns (address) {
        return tx.origin;
    }
}
""".strip()


def _sol(tmp_path: Path) -> Path:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    return sol


def test_config_disables_a_rule(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = _sol(tmp_path)
    cfg = tmp_path / "sibaudit.toml"
    cfg.write_text("[rules]\nA001 = false\n")
    with pytest.raises(SystemExit) as clean:
        main([str(sol), "--config", str(cfg)])
    assert clean.value.code == 0
    assert capsys.readouterr().out == ""


def test_config_overrides_severity_in_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = _sol(tmp_path)
    cfg = tmp_path / "sibaudit.toml"
    cfg.write_text('[rules]\nA001 = "HIGH"\n')
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--config", str(cfg), "--format", "json"])
    assert shown.value.code == 1
    records = [json.loads(ln) for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert records
    assert all(row["code"] == "A001" for row in records)
    assert all(row["severity"] == "HIGH" for row in records)


def test_config_overrides_github_annotation_level(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = _sol(tmp_path)
    cfg = tmp_path / "sibaudit.toml"
    cfg.write_text('[rules]\nA001 = { severity = "HIGH" }\n')
    with pytest.raises(SystemExit):
        main([str(sol), "--config", str(cfg), "--format", "github"])
    out = capsys.readouterr().out
    assert out.startswith("::error ")
    assert "A001 (HIGH)" in out


def test_auto_load_sibaudit_toml_from_cwd(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sol = _sol(tmp_path)
    (tmp_path / "sibaudit.toml").write_text("[rules]\nA001 = false\n")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as clean:
        main([str(sol)])
    assert clean.value.code == 0
    assert capsys.readouterr().out == ""


def test_auto_load_pyproject_from_parent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "src"
    nested.mkdir()
    sol = nested / "Token.sol"
    sol.write_text(RISKY)
    (tmp_path / "pyproject.toml").write_text("[tool.sibaudit.rules]\nA001 = false\n")
    monkeypatch.chdir(nested)
    with pytest.raises(SystemExit) as clean:
        main([str(sol)])
    assert clean.value.code == 0
    assert capsys.readouterr().out == ""


def test_missing_config_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = _sol(tmp_path)
    with pytest.raises(SystemExit) as missing:
        main([str(sol), "--config", str(tmp_path / "nope.toml")])
    assert missing.value.code == 2
    err = capsys.readouterr().err
    assert "error:" in err
    assert "not found" in err


def test_bad_config_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sol = _sol(tmp_path)
    cfg = tmp_path / "sibaudit.toml"
    cfg.write_text("[rules]\nA999 = false\n")
    with pytest.raises(SystemExit) as bad:
        main([str(sol), "--config", str(cfg)])
    assert bad.value.code == 2
    assert "unknown rule code" in capsys.readouterr().err


def test_explicit_config_wins_over_cwd_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sol = _sol(tmp_path)
    (tmp_path / "sibaudit.toml").write_text("[rules]\nA001 = false\n")
    other = tmp_path / "keep.toml"
    other.write_text("[rules]\nA002 = false\n")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--config", str(other)])
    assert shown.value.code == 1
    assert "A001" in capsys.readouterr().out
