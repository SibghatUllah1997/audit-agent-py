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


def test_text_output_ends_with_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit) as shown:
        main([str(sol)])
    assert shown.value.code == 1
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert "A001" in lines[0]
    assert "by rule" in out
    assert "by severity" in out
    assert any(ln.strip().startswith("A001") for ln in lines)


def test_summary_format_omits_file_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--format", "summary"])
    assert shown.value.code == 1
    out = capsys.readouterr().out
    assert "Token.sol:" not in out
    assert out.startswith("1 finding")
    assert "A001" in out
    assert "MEDIUM" in out


def test_summary_format_zero_findings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sol = tmp_path / "Clean.sol"
    sol.write_text("pragma solidity ^0.8.20;\ncontract C {}\n")
    with pytest.raises(SystemExit) as clean:
        main([str(sol), "--format", "summary"])
    assert clean.value.code == 0
    assert capsys.readouterr().out.strip() == "0 findings"


def test_json_format_has_no_summary_footer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit):
        main([str(sol), "--format", "json"])
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    parsed = [json.loads(ln) for ln in lines]
    assert parsed
    assert all("code" in row for row in parsed)
