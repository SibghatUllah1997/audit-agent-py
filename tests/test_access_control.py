from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def write(tmp_dir: Path, rel: str, text: str) -> Path:
    p = tmp_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_flags_unprotected_mint(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Token {
        mapping(address => uint256) public balances;
        function mint(address to, uint256 amount) external {
            balances[to] += amount;
        }
    }
    """.strip()
    file_path = write(tmp_path, "Token.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert any(f.code == "A009" and f.file_path == file_path for f in findings)


def test_does_not_flag_only_owner_mint(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Token {
        mapping(address => uint256) public balances;
        modifier onlyOwner() { _; }
        function mint(address to, uint256 amount) external onlyOwner {
            balances[to] += amount;
        }
    }
    """.strip()
    write(tmp_path, "OwnedToken.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert not any(f.code == "A009" for f in findings)


def test_does_not_flag_sender_require(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Token {
        address public owner;
        mapping(address => uint256) public balances;
        function mint(address to, uint256 amount) external {
            require(msg.sender == owner);
            balances[to] += amount;
        }
    }
    """.strip()
    write(tmp_path, "GuardedToken.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert not any(f.code == "A009" for f in findings)


def test_flags_unprotected_selfdestruct(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Boom {
        function explode(address payable to) external {
            selfdestruct(to);
        }
    }
    """.strip()
    file_path = write(tmp_path, "Boom.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert any(f.code == "A009" and f.file_path == file_path for f in findings)


def test_does_not_flag_private_mint(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Token {
        mapping(address => uint256) public balances;
        function mint(address to, uint256 amount) private {
            balances[to] += amount;
        }
    }
    """.strip()
    write(tmp_path, "PrivateMint.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert not any(f.code == "A009" for f in findings)


def test_does_not_flag_ordinary_public_function(tmp_path: Path) -> None:
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
    assert not any(f.code == "A009" for f in findings)


def test_ignore_next_line_skips_sensitive_function(tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Token {
        mapping(address => uint256) public balances;
        // sibaudit:ignore-next-line
        function mint(address to, uint256 amount) external {
            balances[to] += amount;
        }
    }
    """.strip()
    write(tmp_path, "IgnoredMint.sol", code)
    findings = scan_paths([str(tmp_path)])
    assert not any(f.code == "A009" for f in findings)
