from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, source: str) -> list:
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A031"]


def _contract(body: str) -> str:
    return f"pragma solidity 0.8.20;\ncontract C {{\n{body}\n}}\n"


def test_flags_prevrandao_modulo(tmp_path: Path) -> None:
    body = (
        "address[] public players;\n"
        "function pick() external view returns (address) {\n"
        "    return players[block.prevrandao % players.length];\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "MEDIUM"
    assert finding.line_number == 5
    assert "block.prevrandao" in finding.message
    assert "VRF" in finding.message


def test_flags_difficulty_with_alias_note(tmp_path: Path) -> None:
    body = (
        "function roll() external view returns (uint256) {\n"
        "    return uint256(keccak256(abi.encode(block.difficulty, msg.sender))) % 6;\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "alias of prevrandao" in findings[0].message


def test_one_finding_per_line(tmp_path: Path) -> None:
    body = (
        "function roll() external view returns (uint256) {\n"
        "    return block.prevrandao ^ block.difficulty;\n"
        "}\n"
    )
    assert len(_scan(tmp_path, _contract(body))) == 1


def test_flags_yul_prevrandao_inside_assembly(tmp_path: Path) -> None:
    body = (
        "function seed() external view returns (uint256 r) {\n"
        "    assembly {\n"
        "        r := prevrandao()\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "prevrandao()" in findings[0].line_text


def test_flags_yul_difficulty_in_memory_safe_block(tmp_path: Path) -> None:
    body = (
        "function seed() external view returns (uint256 r) {\n"
        '    assembly ("memory-safe") {\n'
        "        r := difficulty()\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "alias of prevrandao" in findings[0].message


def test_ignores_solidity_function_named_difficulty(tmp_path: Path) -> None:
    body = (
        "uint256 public level;\n"
        "function difficulty() public view returns (uint256) {\n"
        "    return level;\n"
        "}\n"
        "function twice() external view returns (uint256) {\n"
        "    return difficulty() * 2;\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_ignores_comments_and_strings(tmp_path: Path) -> None:
    body = (
        "// block.prevrandao is not used here\n"
        "/* block.difficulty\n"
        "   was removed */\n"
        "string public note = \"block.prevrandao\";\n"
        "function f() external pure returns (uint256) { return 1; }\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_code_after_block_comment_on_same_line_is_scanned(tmp_path: Path) -> None:
    body = (
        "function f() external view returns (uint256) {\n"
        "    /* seed */ return block.prevrandao;\n"
        "}\n"
    )
    assert len(_scan(tmp_path, _contract(body))) == 1


def test_ignore_next_line_directive(tmp_path: Path) -> None:
    body = (
        "function f() external view returns (uint256) {\n"
        "    // sibaudit:ignore-next-line\n"
        "    return block.prevrandao;\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_ignore_file_directive_for_code(tmp_path: Path) -> None:
    source = "// sibaudit:ignore-file A031\n" + _contract(
        "function f() external view returns (uint256) { return block.prevrandao; }\n"
    )
    assert not _scan(tmp_path, source)
