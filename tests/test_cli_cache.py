from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

RISKY = """
pragma solidity 0.8.20;
contract C {
    function f() external view returns (address) {
        return tx.origin;
    }
}
""".strip()


def _run(cwd: Path, *args: str, env: dict[str, str] | None = None):
    merged = {k: v for k, v in os.environ.items() if not k.startswith("SIBAUDIT_")}
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, "-m", "sibaudit", "--fail-on", "never", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=merged,
    )


def test_cache_flag_writes_file_and_keeps_output(tmp_path: Path) -> None:
    (tmp_path / "C.sol").write_text(RISKY + "\n")
    plain = _run(tmp_path, "C.sol")
    cold = _run(tmp_path, "--cache", ".sibaudit-cache.json", "C.sol")
    warm = _run(tmp_path, "--cache", ".sibaudit-cache.json", "C.sol")
    assert plain.stdout == cold.stdout == warm.stdout
    assert "A001" in warm.stdout
    data = json.loads((tmp_path / ".sibaudit-cache.json").read_text())
    assert data["format"] == 1
    assert len(data["files"]) == 1


def test_cache_env_var(tmp_path: Path) -> None:
    (tmp_path / "C.sol").write_text(RISKY + "\n")
    result = _run(tmp_path, "C.sol", env={"SIBAUDIT_CACHE": "cache/scan.json"})
    assert result.returncode == 0
    assert (tmp_path / "cache" / "scan.json").is_file()


def test_unwritable_cache_only_warns(tmp_path: Path) -> None:
    (tmp_path / "C.sol").write_text(RISKY + "\n")
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    result = _run(tmp_path, "--cache", str(blocker / "cache.json"), "C.sol")
    assert result.returncode == 0
    assert "A001" in result.stdout
    assert "cannot write cache file" in result.stderr


def test_config_still_applies_to_cached_findings(tmp_path: Path) -> None:
    (tmp_path / "C.sol").write_text(RISKY + "\n")
    _run(tmp_path, "--cache", "c.json", "C.sol")
    (tmp_path / "sibaudit.toml").write_text("[rules]\nA001 = false\n")
    warm = _run(tmp_path, "--cache", "c.json", "C.sol")
    assert warm.returncode == 0
    assert "A001" not in warm.stdout
