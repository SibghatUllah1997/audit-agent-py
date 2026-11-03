from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def write(tmp_dir: Path, rel: str, text: str) -> Path:
    p = tmp_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_flags_call_then_state_update(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Vault {
        mapping(address => uint256) public balances;
        function withdraw() external {
            uint256 amount = balances[msg.sender];
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok);
            balances[msg.sender] = 0;
        }
    }
    """.strip()
    file_path = write(tmp_path, "Vault.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert any(f.code == "A008" and f.file_path == file_path for f in findings)


def test_does_not_flag_effects_before_interaction(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Vault {
        mapping(address => uint256) public balances;
        function withdraw() external {
            uint256 amount = balances[msg.sender];
            balances[msg.sender] = 0;
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok);
        }
    }
    """.strip()
    write(tmp_path, "SafeVault.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert not any(f.code == "A008" for f in findings)


def test_does_not_flag_call_without_later_write(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Ping {
        function ping(address target) external {
            target.call(abi.encodeWithSignature("pong()"));
        }
    }
    """.strip()
    write(tmp_path, "Ping.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert not any(f.code == "A008" for f in findings)


def test_flags_transfer_then_state_update(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Pay {
        mapping(address => uint256) public owed;
        function pay() external {
            uint256 amount = owed[msg.sender];
            payable(msg.sender).transfer(amount);
            owed[msg.sender] = 0;
        }
    }
    """.strip()
    file_path = write(tmp_path, "Pay.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert any(f.code == "A008" and f.file_path == file_path for f in findings)


def test_ignore_next_line_skips_reentrancy_call(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Vault {
        mapping(address => uint256) public balances;
        function withdraw() external {
            uint256 amount = balances[msg.sender];
            // sibaudit:ignore-next-line
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok);
            balances[msg.sender] = 0;
        }
    }
    """.strip()
    write(tmp_path, "Ignored.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert not any(f.code == "A008" for f in findings)
