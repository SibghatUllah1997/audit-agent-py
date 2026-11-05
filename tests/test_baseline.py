from __future__ import annotations

import json
from pathlib import Path

import pytest

from sibaudit.baseline import (
    BaselineError,
    apply_baseline,
    dump_baseline,
    files_match,
    is_suppressed,
    load_baseline,
    relative_file,
    write_baseline,
)
from sibaudit.scanner import Finding


def _finding(
    tmp_path: Path,
    rel: str,
    line: int,
    code: str = "A001",
    *,
    mkdir: bool = True,
) -> Finding:
    path = tmp_path / rel
    if mkdir:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text("// placeholder\n")
    return Finding(
        file_path=path,
        line_number=line,
        code=code,
        severity="MEDIUM",
        message="demo",
        line_text="address a = tx.origin;",
    )


def test_relative_file_inside_root(tmp_path: Path) -> None:
    nested = tmp_path / "src" / "Token.sol"
    nested.parent.mkdir(parents=True)
    nested.write_text("//\n")
    assert relative_file(nested, tmp_path) == "src/Token.sol"


def test_relative_file_outside_root_keeps_absolute(tmp_path: Path) -> None:
    other = tmp_path / "other"
    other.mkdir()
    target = tmp_path / "src" / "Token.sol"
    target.parent.mkdir()
    target.write_text("//\n")
    assert relative_file(target, other) == target.resolve().as_posix()


def test_files_match_exact_and_tails() -> None:
    assert files_match("src/Token.sol", "src/Token.sol")
    assert files_match("contracts/src/Token.sol", "src/Token.sol")
    assert files_match("src/Token.sol", "contracts/src/Token.sol")
    assert files_match("./src/Token.sol", "src/Token.sol")
    assert not files_match("src/Token.sol", "src/Other.sol")
    assert not files_match("mysrc/Token.sol", "src/Token.sol")


def test_dump_and_load_round_trip(tmp_path: Path) -> None:
    findings = [
        _finding(tmp_path, "b/B.sol", 4, "A002"),
        _finding(tmp_path, "a/A.sol", 2, "A001"),
        _finding(tmp_path, "a/A.sol", 2, "A001"),
    ]
    text = dump_baseline(findings, tmp_path)
    payload = json.loads(text)
    assert payload["version"] == 1
    files = [item["file"] for item in payload["findings"]]
    assert files == ["a/A.sol", "a/A.sol", "b/B.sol"]

    path = tmp_path / "baseline.json"
    path.write_text(text)
    entries = load_baseline(path)
    assert [(e.file, e.line, e.code) for e in entries] == [
        ("a/A.sol", 2, "A001"),
        ("a/A.sol", 2, "A001"),
        ("b/B.sol", 4, "A002"),
    ]


def test_load_accepts_bare_list(tmp_path: Path) -> None:
    path = tmp_path / "legacy.json"
    path.write_text('[{"file": "A.sol", "line": 3, "code": "A001"}]\n')
    entries = load_baseline(path)
    assert len(entries) == 1
    assert entries[0].file == "A.sol"
    assert entries[0].line == 3
    assert entries[0].code == "A001"


def test_load_empty_object(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text("{}\n")
    assert load_baseline(path) == []


def test_load_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="not found"):
        load_baseline(tmp_path / "missing.json")


def test_load_invalid_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    with pytest.raises(BaselineError, match="not valid JSON"):
        load_baseline(path)


def test_load_rejects_bad_entries(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"findings": [{"file": "A.sol", "line": 0, "code": "A001"}]}))
    with pytest.raises(BaselineError, match="invalid line"):
        load_baseline(path)

    path.write_text(json.dumps({"findings": [{"file": "", "line": 1, "code": "A001"}]}))
    with pytest.raises(BaselineError, match="missing a file path"):
        load_baseline(path)

    path.write_text(json.dumps({"findings": [{"file": "A.sol", "line": 1, "code": ""}]}))
    with pytest.raises(BaselineError, match="missing a rule code"):
        load_baseline(path)


def test_apply_baseline_filters_matching_findings(tmp_path: Path) -> None:
    known = _finding(tmp_path, "src/Token.sol", 10, "A001")
    other_line = _finding(tmp_path, "src/Token.sol", 11, "A001")
    other_code = _finding(tmp_path, "src/Token.sol", 10, "A002")
    other_file = _finding(tmp_path, "src/Other.sol", 10, "A001")
    path = tmp_path / "base.json"
    write_baseline(path, [known], tmp_path)
    entries = load_baseline(path)

    remaining = apply_baseline([known, other_line, other_code, other_file], entries, tmp_path)
    assert remaining == [other_line, other_code, other_file]


def test_tail_path_is_suppressed(tmp_path: Path) -> None:
    finding = _finding(tmp_path, "contracts/src/Token.sol", 8, "A003")
    path = tmp_path / "base.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "findings": [{"file": "src/Token.sol", "line": 8, "code": "A003"}],
            }
        )
    )
    entries = load_baseline(path)
    assert is_suppressed(finding, entries, tmp_path)
    assert apply_baseline([finding], entries, tmp_path) == []
