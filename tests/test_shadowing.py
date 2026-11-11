from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def write(tmp_dir: Path, rel: str, text: str) -> Path:
    p = tmp_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_state_variable_shadowed_by_parameter(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract H {
        address public owner;
        function setOwner(address owner) external { // shadows state variable
            // no-op
        }
    }
    """.strip()
    file_path = write(tmp_path, "H.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert any(
        f.code == "A005" and f.file_path == file_path and "shadows a state variable" in f.message
        for f in findings
    )


def test_statements_inside_functions_are_not_state_variables(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract T {
        mapping(address => uint256) public balances;
        function mint(address to, uint256 amount) external {
            balances[to] += amount;
        }
        function burn(address to, uint256 amount) external {
            balances[to] -= amount;
        }
    }
    """.strip()
    write(tmp_path, "T.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert not [f for f in findings if f.code == "A005"]


def test_return_parameters_are_not_treated_as_inputs(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
        uint256 public limit;
        function check(uint256 limit) external pure returns (bool ok) {
            ok = limit > 0;
        }
        function read() external view returns (uint256 limit) {
            limit = 1;
        }
    }
    """.strip()
    write(tmp_path, "C.sol", code)
    findings = [f for f in scan_paths([str(tmp_path)]) if f.code == "A005"]
    assert [f.line_number for f in findings] == [5]
    assert '"limit"' in findings[0].message


def test_initialised_state_variable_is_still_tracked(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    abstract contract A {
        uint256 public fee = 5; // initialised at declaration
        function setFee(uint256 fee) external virtual;
    }
    """.strip()
    write(tmp_path, "A.sol", code)
    findings = [f for f in scan_paths([str(tmp_path)]) if f.code == "A005"]
    assert len(findings) == 1 and '"fee"' in findings[0].message
