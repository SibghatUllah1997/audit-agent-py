from __future__ import annotations

from pathlib import Path

import pytest

from sibaudit.scanner import scan_paths

BODY = "contract C {\n    uint256 public x;\n}\n"


def _scan(tmp_path: Path, source: str, name: str = "C.sol") -> list:
    (tmp_path / name).write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A023"]


@pytest.mark.parametrize(
    "spec",
    [
        "^0.8.20",
        "~0.8.20",
        ">=0.8.0",
        ">=0.8.0 <0.9.0",
        "<0.9.0",
        "0.8.0 - 0.8.20",
        "^0.8.0 || ^0.7.0",
        "0.8.x",
        "*",
        "0.8",
    ],
)
def test_flags_floating_specs(tmp_path: Path, spec: str) -> None:
    findings = _scan(tmp_path, f"pragma solidity {spec};\n{BODY}")
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert findings[0].line_number == 1
    assert f'"{spec}"' in findings[0].message


@pytest.mark.parametrize("spec", ["0.8.20", "=0.8.20", "= 0.8.20"])
def test_allows_pinned_versions(tmp_path: Path, spec: str) -> None:
    assert not _scan(tmp_path, f"pragma solidity {spec};\n{BODY}")


def test_message_suggests_the_lower_version(tmp_path: Path) -> None:
    findings = _scan(tmp_path, f"pragma solidity >=0.8.19 <0.9.0;\n{BODY}")
    assert "for example 0.8.19" in findings[0].message
    assert "open lower bound" in findings[0].message


def test_points_at_the_pragma_line(tmp_path: Path) -> None:
    source = f"// SPDX-License-Identifier: MIT\n\npragma solidity ^0.8.20;\n{BODY}"
    findings = _scan(tmp_path, source)
    assert [f.line_number for f in findings] == [3]
    assert findings[0].line_text == "pragma solidity ^0.8.20;"


def test_flags_library_and_abstract_contract(tmp_path: Path) -> None:
    lib_dir = tmp_path / "lib"
    lib_dir.mkdir()
    lib = "pragma solidity ^0.8.20;\nlibrary L {\n    function f() internal {}\n}\n"
    assert len(_scan(lib_dir, lib, "L.sol")) == 1
    abstract_dir = tmp_path / "abstract"
    abstract_dir.mkdir()
    abstract = "pragma solidity ^0.8.20;\nabstract contract A {\n}\n"
    assert len(_scan(abstract_dir, abstract, "A.sol")) == 1


def test_interface_only_file_is_skipped(tmp_path: Path) -> None:
    source = "pragma solidity ^0.8.0;\ninterface IToken {\n    function f() external;\n}\n"
    assert not _scan(tmp_path, source, "IToken.sol")


@pytest.mark.parametrize("name", ["C.t.sol", "Deploy.s.sol", "MockToken.sol", "TokenMock.sol"])
def test_tests_scripts_and_mocks_are_skipped(tmp_path: Path, name: str) -> None:
    assert not _scan(tmp_path, f"pragma solidity ^0.8.20;\n{BODY}", name)


def test_other_pragmas_are_ignored(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\npragma abicoder v2;\n"
        f"pragma experimental SMTChecker;\n{BODY}"
    )
    assert not _scan(tmp_path, source)


def test_commented_pragma_is_ignored(tmp_path: Path) -> None:
    source = f"// pragma solidity ^0.8.20;\npragma solidity 0.8.20;\n{BODY}"
    assert not _scan(tmp_path, source)


def test_ignore_directive_skips_pragma(tmp_path: Path) -> None:
    source = f"// sibaudit:ignore-next-line\npragma solidity ^0.8.20;\n{BODY}"
    assert not _scan(tmp_path, source)


def test_ignore_file_directive_can_drop_only_a023(tmp_path: Path) -> None:
    source = f"// sibaudit:ignore-file A023\npragma solidity ^0.8.20;\n{BODY}"
    assert not _scan(tmp_path, source)
