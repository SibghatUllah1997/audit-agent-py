from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def test_tuple_assign_with_assert_ok(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract L1 {
        function f(address t, bytes calldata d) external {
            (bool ok, ) = t.call(d);
            assert(ok);
        }
    }
    """.strip()
    p = tmp_path / "L1.sol"
    p.write_text(code)
    findings = scan_paths([str(tmp_path)])
    assert all(f.code != "A002" for f in findings)


def test_tuple_assign_with_if_not_ok(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract L2 {
        function f(address t, bytes calldata d) external {
            (bool ok, ) = t.call(d);
            if (!ok) { revert("bad"); }
        }
    }
    """.strip()
    p = tmp_path / "L2.sol"
    p.write_text(code)
    findings = scan_paths([str(tmp_path)])
    assert all(f.code != "A002" for f in findings)
