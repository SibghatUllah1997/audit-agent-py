from __future__ import annotations

import re
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

ANNOTATION = re.compile(
    r"^::(?P<level>error|warning|notice) "
    r"file=(?P<file>[^,]+),line=(?P<line>\d+),"
    r"title=(?P<title>[^:]+)::(?P<message>.+)$"
)


def test_github_format_prints_workflow_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--format", "github"])
    assert shown.value.code == 1
    out = capsys.readouterr().out.strip()
    match = ANNOTATION.match(out.splitlines()[0])
    assert match is not None
    assert match.group("level") == "warning"
    assert match.group("file").endswith("Token.sol")
    assert int(match.group("line")) > 0
    assert match.group("title") == "A001 (MEDIUM)"
    assert "tx.origin" in match.group("message")
    assert "by rule" not in out
    assert "by severity" not in out


def test_github_format_zero_findings_prints_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Clean.sol"
    sol.write_text("pragma solidity ^0.8.20;\ncontract C {}\n")
    with pytest.raises(SystemExit) as clean:
        main([str(sol), "--format", "github"])
    assert clean.value.code == 0
    assert capsys.readouterr().out == ""
