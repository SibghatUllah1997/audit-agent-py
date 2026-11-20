from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths

HEADER = "pragma solidity 0.8.20;\n"


def _scan(tmp_path: Path, body: str, name: str = "C.sol") -> list:
    (tmp_path / name).write_text(HEADER + body)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A029"]


def test_flags_for_loop_over_storage_array(tmp_path: Path) -> None:
    body = (
        "contract Airdrop {\n"
        "    address[] public recipients;\n"
        "    mapping(address => uint256) public credit;\n"
        "    function payout() external {\n"
        "        for (uint256 i = 0; i < recipients.length; i++) {\n"
        "            credit[recipients[i]] += 1;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "HIGH"
    assert finding.line_number == 6
    assert "recipients.length" in finding.line_text
    assert '"recipients"' in finding.message
    assert "run out of gas" in finding.message


def test_flags_while_loop_over_storage_array(tmp_path: Path) -> None:
    body = (
        "contract Sweep {\n"
        "    address[] public users;\n"
        "    function sweep() external {\n"
        "        uint256 i = 0;\n"
        "        while (i < users.length) {\n"
        "            users[i] = address(0);\n"
        "            i++;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "while" in findings[0].line_text
    assert '"users"' in findings[0].message


def test_flags_mapping_to_array_length(tmp_path: Path) -> None:
    body = (
        "contract Inbox {\n"
        "    mapping(address => address[]) public mail;\n"
        "    function clear(address who) external {\n"
        "        for (uint256 i = 0; i < mail[who].length; i++) {\n"
        "            mail[who][i] = address(0);\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "mail[who].length" in findings[0].line_text
    assert '"mail"' in findings[0].message


def test_flags_length_in_the_initializer(tmp_path: Path) -> None:
    body = (
        "contract Sweep {\n"
        "    uint256[] public amounts;\n"
        "    function drain() external {\n"
        "        for (uint256 i = amounts.length; i > 0; i--) {\n"
        "            amounts[i - 1] = 0;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "amounts.length" in findings[0].line_text


def test_flags_multiline_for_header(tmp_path: Path) -> None:
    body = (
        "contract Airdrop {\n"
        "    address[] public recipients;\n"
        "    function payout() external {\n"
        "        for (\n"
        "            uint256 i = 0;\n"
        "            i < recipients.length;\n"
        "            i++\n"
        "        ) {\n"
        "            recipients[i];\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert findings[0].line_number == 5
    assert "for (" in findings[0].line_text


def test_allows_view_function(tmp_path: Path) -> None:
    body = (
        "contract Airdrop {\n"
        "    address[] public recipients;\n"
        "    function count() external view returns (uint256 n) {\n"
        "        for (uint256 i = 0; i < recipients.length; i++) {\n"
        "            n++;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_allows_memory_array_parameter(tmp_path: Path) -> None:
    body = (
        "contract Mix {\n"
        "    function sum(uint256[] memory xs) external pure returns (uint256 n) {\n"
        "        for (uint256 i = 0; i < xs.length; i++) {\n"
        "            n += xs[i];\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_allows_calldata_array_parameter(tmp_path: Path) -> None:
    body = (
        "contract Mix {\n"
        "    function touch(address[] calldata xs) external {\n"
        "        for (uint256 i = 0; i < xs.length; i++) {\n"
        "            xs[i];\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_allows_constant_bound(tmp_path: Path) -> None:
    body = (
        "contract Mix {\n"
        "    address[] public users;\n"
        "    function firstTen() external {\n"
        "        for (uint256 i = 0; i < 10; i++) {\n"
        "            users[i] = address(0);\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_allows_capped_loop_with_max_constant(tmp_path: Path) -> None:
    body = (
        "contract Airdrop {\n"
        "    address[] public recipients;\n"
        "    uint256 public constant MAX = 50;\n"
        "    function payout() external {\n"
        "        for (uint256 i = 0; i < recipients.length && i < MAX; i++) {\n"
        "            recipients[i];\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_allows_capped_loop_with_literal_and(tmp_path: Path) -> None:
    body = (
        "contract Airdrop {\n"
        "    address[] public recipients;\n"
        "    function payout() external {\n"
        "        for (uint256 i = 0; i < recipients.length && i < 50; i++) {\n"
        "            recipients[i];\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_allows_batched_cursor_loop(tmp_path: Path) -> None:
    body = (
        "contract Airdrop {\n"
        "    address[] public recipients;\n"
        "    uint256 public constant BATCH = 50;\n"
        "    uint256 public cursor;\n"
        "    function payout() external {\n"
        "        uint256 end = cursor + BATCH;\n"
        "        if (end > recipients.length) {\n"
        "            end = recipients.length;\n"
        "        }\n"
        "        for (uint256 i = cursor; i < end; i++) {\n"
        "            recipients[i];\n"
        "        }\n"
        "        cursor = end;\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_does_not_flag_fixed_size_array(tmp_path: Path) -> None:
    body = (
        "contract Slots {\n"
        "    address[8] public seats;\n"
        "    function clear() external {\n"
        "        for (uint256 i = 0; i < seats.length; i++) {\n"
        "            seats[i] = address(0);\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_ignores_commented_loop(tmp_path: Path) -> None:
    body = (
        "contract Airdrop {\n"
        "    address[] public recipients;\n"
        "    function payout() external {\n"
        "        // for (uint256 i = 0; i < recipients.length; i++) {}\n"
        "        recipients;\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_respects_ignore_next_line(tmp_path: Path) -> None:
    body = (
        "contract Airdrop {\n"
        "    address[] public recipients;\n"
        "    function payout() external {\n"
        "        // sibaudit:ignore-next-line\n"
        "        for (uint256 i = 0; i < recipients.length; i++) {\n"
        "            recipients[i];\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []
