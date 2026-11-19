from __future__ import annotations

import json
from pathlib import Path

import pytest

from sibaudit.baseline import (
    BaselineEntry,
    BaselineError,
    apply_baseline,
    dump_baseline,
    files_match,
    format_update_summary,
    is_suppressed,
    load_baseline,
    normalize_line_text,
    relative_file,
    rematch_baseline,
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


def test_dump_stores_normalized_source_text(tmp_path: Path) -> None:
    finding = _finding(tmp_path, "src/Token.sol", 10, "A001")
    payload = json.loads(dump_baseline([finding], tmp_path))
    assert payload["findings"][0]["text"] == normalize_line_text(finding.line_text)


def test_load_accepts_snapshots_without_text(tmp_path: Path) -> None:
    path = tmp_path / "old.json"
    path.write_text(
        json.dumps({"version": 1, "findings": [{"file": "A.sol", "line": 3, "code": "A001"}]})
    )
    entries = load_baseline(path)
    assert entries[0].text == ""


def test_load_rejects_non_string_text(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps({"findings": [{"file": "A.sol", "line": 1, "code": "A001", "text": 9}]})
    )
    with pytest.raises(BaselineError, match="invalid source text"):
        load_baseline(path)


def test_rematch_keeps_exact_hits_and_drops_fixed(tmp_path: Path) -> None:
    known = _finding(tmp_path, "src/Token.sol", 10, "A001")
    gone = BaselineEntry(file="src/Token.sol", line=4, code="A003", text="selfdestruct(owner);")
    matching = BaselineEntry(
        file="src/Token.sol",
        line=10,
        code="A001",
        text=normalize_line_text(known.line_text),
    )
    update = rematch_baseline([known], [matching, gone], tmp_path)
    assert update.kept == (known,)
    assert update.moved == ()
    assert update.dropped == (gone,)
    assert update.new == ()
    assert update.recorded == (known,)


def test_rematch_follows_source_text_after_line_inserts(tmp_path: Path) -> None:
    old = _finding(tmp_path, "src/Token.sol", 5, "A001")
    moved = _finding(tmp_path, "src/Token.sol", 12, "A001")
    entry = BaselineEntry(
        file="src/Token.sol",
        line=5,
        code="A001",
        text=normalize_line_text(old.line_text),
    )
    update = rematch_baseline([moved], [entry], tmp_path)
    assert update.kept == ()
    assert update.moved == (moved,)
    assert update.dropped == ()
    assert update.new == ()


def test_rematch_does_not_record_new_findings(tmp_path: Path) -> None:
    known = _finding(tmp_path, "src/Token.sol", 10, "A001")
    extra = _finding(tmp_path, "src/Token.sol", 18, "A002")
    extra_same_rule = _finding(tmp_path, "src/Other.sol", 3, "A001")
    entry = BaselineEntry(
        file="src/Token.sol",
        line=10,
        code="A001",
        text=normalize_line_text(known.line_text),
    )
    update = rematch_baseline([known, extra, extra_same_rule], [entry], tmp_path)
    assert update.recorded == (known,)
    assert extra in update.new
    assert extra_same_rule in update.new


def test_rematch_proximity_when_snapshot_has_no_text(tmp_path: Path) -> None:
    current = _finding(tmp_path, "src/Token.sol", 14, "A001")
    entry = BaselineEntry(file="src/Token.sol", line=10, code="A001")
    update = rematch_baseline([current], [entry], tmp_path)
    assert update.moved == (current,)
    assert update.new == ()


def test_rematch_does_not_follow_beyond_max_drift_without_text(tmp_path: Path) -> None:
    current = _finding(tmp_path, "src/Token.sol", 80, "A001")
    entry = BaselineEntry(file="src/Token.sol", line=10, code="A001")
    update = rematch_baseline([current], [entry], tmp_path, max_line_drift=40)
    assert update.moved == ()
    assert update.dropped == (entry,)
    assert update.new == (current,)


def test_format_update_summary_singular_and_plural(tmp_path: Path) -> None:
    known = _finding(tmp_path, "src/Token.sol", 10, "A001")
    extra = _finding(tmp_path, "src/Token.sol", 18, "A002")
    entry = BaselineEntry(
        file="src/Token.sol",
        line=10,
        code="A001",
        text=normalize_line_text(known.line_text),
    )
    one_new = rematch_baseline([known, extra], [entry], tmp_path)
    assert "1 new finding left unsuppressed" in format_update_summary(one_new)
    none_new = rematch_baseline([known], [entry], tmp_path)
    assert "0 new findings left unsuppressed" in format_update_summary(none_new)
    assert "kept 1" in format_update_summary(none_new)


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
