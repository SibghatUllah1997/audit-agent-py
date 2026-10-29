from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def write(tmp_dir: Path, rel: str, text: str) -> Path:
    p = tmp_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_detects_tx_origin(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract A {
        function f() external {
            address a = tx.origin; // <- risky
        }
    }
    """.strip()
    file_path = write(tmp_path, "A.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert any(f.code == "A001" and f.file_path == file_path for f in findings)


def test_detects_unchecked_call(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract B {
        function g(address target) external {
            target.call(abi.encodeWithSignature("ping()")); // unchecked
        }
    }
    """.strip()
    file_path = write(tmp_path, "B.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert any(f.code == "A002" and f.file_path == file_path for f in findings)


def test_ignores_checked_call_with_require(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
        function h(address target) external {
            (bool ok, ) = target.call(abi.encodeWithSignature("ping()"));
            require(ok, "call failed");
        }
    }
    """.strip()
    write(tmp_path, "C.sol", code)
    findings = scan_paths([str(tmp_path)])
    # Should not raise A002 for the checked call
    assert not any(f.code == "A002" for f in findings)

def test_flags_delegatecall_usage_even_if_checked(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract D {
        function j(address target, bytes calldata data) external {
            (bool ok, ) = target.delegatecall(data);
            require(ok, "delegatecall failed");
        }
    }
    """.strip()
    file_path = write(tmp_path, "D.sol", code)
    findings = scan_paths([str(tmp_path)])
    # A003 should be reported regardless of success checks
    assert any(f.code == "A003" and f.file_path == file_path for f in findings)
    # And A002 should not be reported because it's checked
    assert not any(f.code == "A002" for f in findings)

