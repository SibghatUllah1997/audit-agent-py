from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from sibaudit.changed import ChangedError, filter_to_roots, list_changed_solidity

CLEAN = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity 0.8.20;\n"
    "contract Clean {\n"
    "    function ping() external pure returns (uint256) {\n"
    "        return 1;\n"
    "    }\n"
    "}\n"
)
DIRTY = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity 0.8.20;\n"
    "contract Dirty {\n"
    "    function who() external view returns (address) {\n"
    "        return tx.origin;\n"
    "    }\n"
    "}\n"
)


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "Test"
    env["GIT_AUTHOR_EMAIL"] = "test@example.com"
    env["GIT_COMMITTER_NAME"] = "Test"
    env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=check,
        env=env,
    )


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / "Keep.sol").write_text(CLEAN)
    _git(repo, "add", "Keep.sol")
    _git(repo, "commit", "-m", "keep")
    return repo


def _run_cli(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sibaudit", *args],
        cwd=repo,
        capture_output=True,
        text=True,
    )


def test_lists_files_changed_since_a_parent_commit(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "Dirty.sol").write_text(DIRTY)
    _git(repo, "add", "Dirty.sol")
    _git(repo, "commit", "-m", "dirty")
    changed = list_changed_solidity("HEAD~1", repo)
    names = {path.name for path in changed}
    assert names == {"Dirty.sol"}


def test_includes_untracked_solidity_files(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "New.sol").write_text(DIRTY)
    changed = list_changed_solidity("HEAD", repo)
    assert {path.name for path in changed} == {"New.sol"}


def test_omits_deleted_files(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    _git(repo, "rm", "Keep.sol")
    _git(repo, "commit", "-m", "drop")
    assert list_changed_solidity("HEAD~1", repo) == []


def test_filter_to_roots_keeps_files_under_a_directory(tmp_path: Path) -> None:
    src = tmp_path / "src" / "A.sol"
    other = tmp_path / "test" / "B.sol"
    src.parent.mkdir()
    other.parent.mkdir()
    src.write_text("x")
    other.write_text("x")
    kept = filter_to_roots([src, other], [tmp_path / "src"])
    assert kept == [src.resolve()]


def test_invalid_ref_raises(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    with pytest.raises(ChangedError):
        list_changed_solidity("no-such-ref", repo)


def test_outside_a_git_repo_raises(tmp_path: Path) -> None:
    with pytest.raises(ChangedError):
        list_changed_solidity("HEAD", tmp_path)


def test_cli_scans_only_changed_files(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "Dirty.sol").write_text(DIRTY)
    _git(repo, "add", "Dirty.sol")
    _git(repo, "commit", "-m", "dirty")
    proc = _run_cli(repo, "--changed-since", "HEAD~1")
    assert proc.returncode == 1
    assert "A001" in proc.stdout
    assert "Dirty.sol" in proc.stdout
    assert "Keep.sol" not in proc.stdout


def test_cli_no_changes_exits_zero(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    proc = _run_cli(repo, "--changed-since", "HEAD")
    assert proc.returncode == 0
    assert proc.stdout == ""


def test_cli_bad_ref_exits_two(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    proc = _run_cli(repo, "--changed-since", "missing")
    assert proc.returncode == 2
    assert "error:" in proc.stderr


def test_cli_path_argument_filters_changed_files(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "src").mkdir()
    (repo / "test").mkdir()
    (repo / "src" / "Token.sol").write_text(DIRTY)
    (repo / "test" / "Token.t.sol").write_text(DIRTY)
    _git(repo, "add", "src/Token.sol", "test/Token.t.sol")
    _git(repo, "commit", "-m", "both")
    proc = _run_cli(repo, "--changed-since", "HEAD~1", "src")
    assert proc.returncode == 1
    assert "src/Token.sol" in proc.stdout.replace("\\", "/")
    assert "Token.t.sol" not in proc.stdout


def test_env_changed_since_matches_the_flag(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "Dirty.sol").write_text(DIRTY)
    env = os.environ.copy()
    env["SIBAUDIT_CHANGED_SINCE"] = "HEAD"
    proc = subprocess.run(
        [sys.executable, "-m", "sibaudit"],
        cwd=repo,
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 1
    assert "A001" in proc.stdout
