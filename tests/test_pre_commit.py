from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / ".pre-commit-hooks.yaml"
SAMPLE_CONFIG = ROOT / "examples" / "pre-commit" / ".pre-commit-config.yaml"
SAMPLE_SOL = ROOT / "examples" / "Vulnerable.sol"

clientlib = pytest.importorskip("pre_commit.clientlib")
identify = pytest.importorskip("identify.identify")


def load_hooks() -> list[dict]:
    return clientlib.load_manifest(str(HOOKS))


def test_hook_manifest_is_valid_for_pre_commit() -> None:
    (hook,) = load_hooks()
    assert hook["id"] == "sibaudit"
    assert hook["language"] == "python"
    assert hook["pass_filenames"] is True


def test_hook_entry_is_the_installed_console_script() -> None:
    (hook,) = load_hooks()
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert f'{hook["entry"]} = "sibaudit.cli:main"' in pyproject


def test_hook_only_runs_on_solidity_files() -> None:
    (hook,) = load_hooks()
    assert hook["types"] == ["solidity"]
    assert "solidity" in identify.tags_from_filename("Token.sol")
    assert "solidity" not in identify.tags_from_filename("token.py")


def test_sample_config_is_valid_and_uses_this_hook() -> None:
    config = clientlib.load_config(str(SAMPLE_CONFIG))
    remote = [r for r in config["repos"] if r["repo"].endswith("/audit-agent-py")]
    assert remote, "sample config should reference this repository"
    hook_ids = {h["id"] for h in remote[0]["hooks"]}
    known_ids = {h["id"] for h in load_hooks()}
    assert hook_ids <= known_ids


def test_cli_accepts_many_filenames_like_pre_commit_passes_them(tmp_path: Path) -> None:
    clean = tmp_path / "Clean.sol"
    clean.write_text("pragma solidity ^0.8.20;\ncontract Clean { uint256 x; }\n")
    base = [sys.executable, "-m", "sibaudit"]

    dirty = subprocess.run(
        [*base, str(clean), str(SAMPLE_SOL)], capture_output=True, text=True
    )
    assert dirty.returncode == 1
    assert "Vulnerable.sol" in dirty.stdout
    assert "Clean.sol" not in dirty.stdout

    ok = subprocess.run([*base, str(clean)], capture_output=True, text=True)
    assert ok.returncode == 0
    assert ok.stdout.strip() == ""
