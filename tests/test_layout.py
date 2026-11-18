from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from sibaudit.scanner import scan_paths

RISKY = (
    "pragma solidity 0.8.20;\n"
    "contract C {\n"
    "    function who() external view returns (address) {\n"
    "        return tx.origin;\n"
    "    }\n"
    "}\n"
)


def _write(root: Path, rel: str, text: str = RISKY) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _scanned(root: Path, **kwargs: object) -> set[str]:
    findings = scan_paths([str(root)], **kwargs)  # type: ignore[arg-type]
    resolved = root.resolve()
    return {
        Path(finding.file_path).resolve().relative_to(resolved).as_posix()
        for finding in findings
        if finding.code == "A001"
    }


def test_foundry_project_scans_src_not_lib_or_test(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    _write(tmp_path, "src/Token.sol")
    _write(tmp_path, "test/Token.t.sol")
    _write(tmp_path, "lib/forge-std/Test.sol")
    assert _scanned(tmp_path) == {"src/Token.sol"}


def test_foundry_custom_src_from_toml(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text('[profile.default]\nsrc = "contracts"\n')
    _write(tmp_path, "contracts/Vault.sol")
    _write(tmp_path, "src/Old.sol")
    _write(tmp_path, "lib/dep/Dep.sol")
    assert _scanned(tmp_path) == {"contracts/Vault.sol"}


def test_foundry_also_scans_contracts_next_to_src(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    _write(tmp_path, "src/Token.sol")
    _write(tmp_path, "contracts/Adapter.sol")
    _write(tmp_path, "test/Token.t.sol")
    assert _scanned(tmp_path) == {"src/Token.sol", "contracts/Adapter.sol"}


def test_hardhat_project_scans_contracts_not_node_modules(tmp_path: Path) -> None:
    (tmp_path / "hardhat.config.ts").write_text("export default {};\n")
    _write(tmp_path, "contracts/Token.sol")
    _write(tmp_path, "test/Token.ts.sol")
    _write(tmp_path, "node_modules/dep/Dep.sol")
    assert _scanned(tmp_path) == {"contracts/Token.sol"}


def test_hardhat_js_config_is_detected(tmp_path: Path) -> None:
    (tmp_path / "hardhat.config.js").write_text("module.exports = {};\n")
    _write(tmp_path, "contracts/Box.sol")
    _write(tmp_path, "scripts/Deploy.sol")
    assert _scanned(tmp_path) == {"contracts/Box.sol"}


def test_foundry_and_hardhat_together_scan_both_layouts(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    (tmp_path / "hardhat.config.js").write_text("module.exports = {};\n")
    _write(tmp_path, "src/A.sol")
    _write(tmp_path, "contracts/B.sol")
    _write(tmp_path, "lib/C.sol")
    assert _scanned(tmp_path) == {"src/A.sol", "contracts/B.sol"}


def test_directory_without_project_marker_still_scans_everything(tmp_path: Path) -> None:
    _write(tmp_path, "src/Token.sol")
    _write(tmp_path, "test/Token.t.sol")
    _write(tmp_path, "lib/dep/Dep.sol")
    assert _scanned(tmp_path) == {"src/Token.sol", "test/Token.t.sol", "lib/dep/Dep.sol"}


def test_empty_layout_dirs_fall_back_to_the_whole_tree(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    (tmp_path / "src").mkdir()
    _write(tmp_path, "legacy/Old.sol")
    assert _scanned(tmp_path) == {"legacy/Old.sol"}


def test_explicit_file_in_lib_is_still_scanned(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    _write(tmp_path, "src/Token.sol")
    lib = _write(tmp_path, "lib/dep/Dep.sol")
    findings = scan_paths([str(lib)])
    assert any(f.code == "A001" and f.file_path == lib.resolve() for f in findings)


def test_explicit_test_directory_is_still_scanned(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    _write(tmp_path, "src/Token.sol")
    tests = tmp_path / "test"
    _write(tmp_path, "test/Token.t.sol")
    assert _scanned(tests) == {"Token.t.sol"}


def test_include_glob_still_reaches_foundry_tests(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    _write(tmp_path, "src/Token.sol")
    _write(tmp_path, "test/Token.t.sol")
    assert _scanned(tmp_path, include=["test/*"]) == {"test/Token.t.sol"}


def test_exclude_still_applies_inside_layout_dirs(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    _write(tmp_path, "src/Token.sol")
    _write(tmp_path, "src/MockToken.sol")
    assert _scanned(tmp_path, exclude=["Mock*.sol"]) == {"src/Token.sol"}


def test_foundry_src_outside_the_project_is_ignored(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    project = tmp_path / "proj"
    outside.mkdir()
    project.mkdir()
    _write(outside, "Evil.sol")
    (project / "foundry.toml").write_text('[profile.default]\nsrc = "../outside"\n')
    _write(project, "lib/Dep.sol")
    scanned = _scanned(project)
    assert scanned == {"lib/Dep.sol"}
    assert not any(path.startswith("..") for path in scanned)


def test_cli_with_no_paths_uses_foundry_src(tmp_path: Path) -> None:
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    token = _write(tmp_path, "src/Token.sol")
    _write(tmp_path, "lib/dep/Dep.sol")
    proc = subprocess.run(
        [sys.executable, "-m", "sibaudit"],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
    )
    assert proc.returncode == 1
    out = proc.stdout.replace("\\", "/")
    assert token.name in out
    assert "Dep.sol" not in out
    assert "lib/" not in out
