from __future__ import annotations

from pathlib import Path

import pytest

from sibaudit.cli import main
from sibaudit.scanner import scan_paths

RISKY_BODY = """pragma solidity ^0.8.20;
contract A {
    function f() external {
        address a = tx.origin;
        uint256 fee = 12345;
    }
}
"""


def write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text)
    return p


def codes_for(path: Path) -> set[str]:
    return {f.code for f in scan_paths([str(path)])}


def test_baseline_file_has_findings(tmp_path: Path) -> None:
    path = write(tmp_path, "A.sol", RISKY_BODY)
    assert {"A001", "A017"} <= codes_for(path)


def test_bare_directive_skips_whole_file(tmp_path: Path) -> None:
    path = write(tmp_path, "A.sol", "// sibaudit:ignore-file\n" + RISKY_BODY)
    assert scan_paths([str(path)]) == []


def test_coded_directive_only_drops_listed_rules(tmp_path: Path) -> None:
    path = write(tmp_path, "A.sol", "// sibaudit:ignore-file A017\n" + RISKY_BODY)
    codes = codes_for(path)
    assert "A017" not in codes
    assert "A001" in codes


def test_directive_only_affects_its_own_file(tmp_path: Path) -> None:
    write(tmp_path, "Ignored.sol", "// sibaudit:ignore-file\n" + RISKY_BODY)
    kept = write(tmp_path, "Kept.sol", RISKY_BODY)
    findings = scan_paths([str(tmp_path)])
    assert findings
    assert {f.file_path for f in findings} == {kept.resolve()}


def test_directive_below_code_is_not_honored(tmp_path: Path) -> None:
    text = RISKY_BODY.replace("contract A {", "contract A {\n    // sibaudit:ignore-file")
    path = write(tmp_path, "A.sol", text)
    assert "A001" in codes_for(path)


def test_cli_exits_clean_for_ignored_file(tmp_path: Path) -> None:
    path = write(tmp_path, "A.sol", "// sibaudit:ignore-file\n" + RISKY_BODY)
    with pytest.raises(SystemExit) as exc:
        main([str(path)])
    assert exc.value.code == 0
