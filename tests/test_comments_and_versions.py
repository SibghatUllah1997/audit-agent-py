from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths, _is_pre_0_8_solidity


def test_inline_block_comment_is_stripped(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
        function f() external {
            /* ignore */ address(this).call("");
        }
    }
    """.strip()
    p = tmp_path / "C.sol"
    p.write_text(code)
    findings = scan_paths([str(tmp_path)])
    assert any(f.code == "A002" for f in findings)


def test_inline_block_comment_between_dot_and_call_is_stripped(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C2 {
        function f() external {
            address(this)./* comment */call("");
        }
    }
    """.strip()
    p = tmp_path / "C2.sol"
    p.write_text(code)
    findings = scan_paths([str(tmp_path)])
    assert any(f.code == "A002" for f in findings)


def test_is_pre_0_8_solidity_various_specs() -> None:
    cases_true = [
        "pragma solidity ^0.7.6;",
        "pragma solidity >=0.5.0 <0.8.0;",
        "pragma solidity >= 0.6.0, < 0.8.0;",
    ]
    cases_false = [
        "pragma solidity ^0.8.0;",
        "pragma solidity >=0.8.0;",
        "pragma solidity >=0.8.1 <0.9.0;",
    ]
    for src in cases_true:
        assert _is_pre_0_8_solidity([src]) is True, src
    for src in cases_false:
        assert _is_pre_0_8_solidity([src]) is False, src
