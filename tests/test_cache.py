from __future__ import annotations

import json
from pathlib import Path

import pytest

from sibaudit import scanner
from sibaudit.cache import ScanCache, content_hash
from sibaudit.scanner import scan_paths

RISKY = """
pragma solidity 0.8.20;
contract C {
    function f() external view returns (address) {
        return tx.origin;
    }
}
""".strip()

CLEAN = """
pragma solidity 0.8.20;
contract D {
    uint256 public x;
}
""".strip()


def _key(findings):
    return [(f.file_path, f.line_number, f.code, f.severity, f.message, f.line_text)
            for f in findings]


def _count_detector_runs(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    seen: list[Path] = []
    real = scanner.scan_source

    def spy(content: str, file_path: Path):
        seen.append(file_path)
        return real(content, file_path)

    monkeypatch.setattr(scanner, "scan_source", spy)
    return seen


def test_warm_scan_matches_cold_and_skips_detectors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "C.sol").write_text(RISKY)
    (tmp_path / "D.sol").write_text(CLEAN)
    cache_file = tmp_path / "cache.json"
    plain = scan_paths([str(tmp_path)])

    cold = ScanCache.load(cache_file, key="k")
    first = scan_paths([str(tmp_path)], cache=cold)
    cold.save()
    assert (cold.hits, cold.misses) == (0, 2)

    seen = _count_detector_runs(monkeypatch)
    warm = ScanCache.load(cache_file, key="k")
    second = scan_paths([str(tmp_path)], cache=warm)
    assert seen == []
    assert (warm.hits, warm.misses) == (2, 0)
    assert _key(plain) == _key(first) == _key(second)
    assert any(f.code == "A001" for f in second)


def test_edited_file_is_rescanned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    risky = tmp_path / "C.sol"
    risky.write_text(RISKY)
    (tmp_path / "D.sol").write_text(CLEAN)
    cache_file = tmp_path / "cache.json"
    cache = ScanCache.load(cache_file, key="k")
    scan_paths([str(tmp_path)], cache=cache)
    cache.save()

    risky.write_text(CLEAN.replace("contract D", "contract C"))
    seen = _count_detector_runs(monkeypatch)
    cache = ScanCache.load(cache_file, key="k")
    findings = scan_paths([str(tmp_path)], cache=cache)
    assert seen == [risky.resolve()]
    assert not any(f.code == "A001" for f in findings)


def test_ruleset_change_invalidates_everything(tmp_path: Path) -> None:
    (tmp_path / "C.sol").write_text(RISKY)
    cache_file = tmp_path / "cache.json"
    old = ScanCache.load(cache_file, key="old")
    scan_paths([str(tmp_path)], cache=old)
    old.save()

    new = ScanCache.load(cache_file, key="new")
    assert new.entries == {}
    scan_paths([str(tmp_path)], cache=new)
    assert (new.hits, new.misses) == (0, 1)
    new.save()
    assert json.loads(cache_file.read_text())["ruleset"] == "new"


@pytest.mark.parametrize("junk", ["", "not json", "[]", '{"format": 99, "files": {}}'])
def test_corrupt_cache_falls_back_to_cold_scan(tmp_path: Path, junk: str) -> None:
    (tmp_path / "C.sol").write_text(RISKY)
    cache_file = tmp_path / "cache.json"
    cache_file.write_text(junk)
    cache = ScanCache.load(cache_file, key="k")
    findings = scan_paths([str(tmp_path)], cache=cache)
    assert any(f.code == "A001" for f in findings)
    cache.save()
    assert json.loads(cache_file.read_text())["format"] == 1


def test_bad_entry_shape_counts_as_miss(tmp_path: Path) -> None:
    sol = tmp_path / "C.sol"
    sol.write_text(RISKY)
    digest = content_hash(sol.read_bytes())
    cache_file = tmp_path / "cache.json"
    cache_file.write_text(json.dumps({
        "format": 1,
        "ruleset": "k",
        "files": {str(sol.resolve()): {"sha256": digest, "findings": [{"bogus": 1}]}},
    }))
    cache = ScanCache.load(cache_file, key="k")
    findings = scan_paths([str(sol)], cache=cache)
    assert cache.misses == 1
    assert any(f.code == "A001" for f in findings)


def test_deleted_files_are_pruned_on_save(tmp_path: Path) -> None:
    gone = tmp_path / "Gone.sol"
    gone.write_text(RISKY)
    (tmp_path / "C.sol").write_text(RISKY)
    cache_file = tmp_path / "cache.json"
    cache = ScanCache.load(cache_file, key="k")
    scan_paths([str(tmp_path)], cache=cache)
    cache.save()

    gone.unlink()
    cache = ScanCache.load(cache_file, key="k")
    scan_paths([str(tmp_path / "C.sol")], cache=cache)
    cache.put(tmp_path / "C.sol", "x", [])  # force a write
    cache.save()
    files = json.loads(cache_file.read_text())["files"]
    assert str(gone.resolve()) not in files
    assert str((tmp_path / "C.sol").resolve()) in files


def test_unchanged_warm_scan_does_not_rewrite(tmp_path: Path) -> None:
    (tmp_path / "C.sol").write_text(RISKY)
    cache_file = tmp_path / "cache.json"
    cache = ScanCache.load(cache_file, key="k")
    scan_paths([str(tmp_path)], cache=cache)
    cache.save()
    before = cache_file.stat().st_mtime_ns

    cache = ScanCache.load(cache_file, key="k")
    scan_paths([str(tmp_path)], cache=cache)
    cache.save()
    assert cache_file.stat().st_mtime_ns == before
    assert list(tmp_path.glob(".sibaudit-cache-*")) == []


def test_file_ignore_directive_is_cached_as_empty(tmp_path: Path) -> None:
    sol = tmp_path / "C.sol"
    sol.write_text("// sibaudit:ignore-file\n" + RISKY)
    cache = ScanCache.load(tmp_path / "cache.json", key="k")
    assert scan_paths([str(sol)], cache=cache) == []
    cache.save()
    cache = ScanCache.load(tmp_path / "cache.json", key="k")
    assert scan_paths([str(sol)], cache=cache) == []
    assert cache.hits == 1


def test_cache_format_stats_string(tmp_path: Path) -> None:
    c = ScanCache.load(tmp_path / "c.json", key="k")
    assert c.format_stats() == "cache: 0 hits, 0 misses"
    c.hits, c.misses = 3, 1
    assert c.format_stats() == "cache: 3 hits, 1 misses"
