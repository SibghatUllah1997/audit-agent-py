from __future__ import annotations

from pathlib import Path

import pytest

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


def _project(tmp_path: Path) -> Path:
    for rel in ["src/Token.sol", "test/Token.t.sol", "lib/dep/Dep.sol", "src/MockToken.sol"]:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(RISKY)
    return tmp_path


def _names(tmp_path: Path, **kw: list[str]) -> list[str]:
    found = scan_paths([str(tmp_path)], **kw)
    return sorted({Path(f.file_path).relative_to(tmp_path.resolve()).as_posix() for f in found})


def test_no_filters_scans_everything(tmp_path: Path) -> None:
    assert len(_names(_project(tmp_path))) == 4


def test_exclude_skips_folders_and_names(tmp_path: Path) -> None:
    names = _names(_project(tmp_path), exclude=["lib/*", "test/*", "Mock*.sol"])
    assert names == ["src/Token.sol"]


def test_include_limits_scan(tmp_path: Path) -> None:
    names = _names(_project(tmp_path), include=["src/*"])
    assert names == ["src/MockToken.sol", "src/Token.sol"]


def test_exclude_wins_over_include(tmp_path: Path) -> None:
    names = _names(_project(tmp_path), include=["src/*"], exclude=["Mock*.sol"])
    assert names == ["src/Token.sol"]


def test_explicit_file_respects_exclude(tmp_path: Path) -> None:
    root = _project(tmp_path)
    target = str(root / "src" / "MockToken.sol")
    assert scan_paths([target], exclude=["Mock*.sol"]) == []
    assert scan_paths([target]) != []


def test_cli_flags_change_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _project(tmp_path)
    with pytest.raises(SystemExit) as none_left:
        main([str(root), "--exclude", "*.sol"])
    assert none_left.value.code == 0

    with pytest.raises(SystemExit) as some_left:
        main([str(root), "--include", "src/Token.sol"])
    assert some_left.value.code == 1
    out = capsys.readouterr().out.replace("\\", "/")
    assert "src/Token.sol" in out
    assert "lib/dep" not in out
