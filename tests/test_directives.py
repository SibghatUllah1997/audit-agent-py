from __future__ import annotations

from sibaudit.directives import parse_ignore_file


def lines(text: str) -> list[str]:
    return text.strip("\n").splitlines()


def test_no_directive_returns_none() -> None:
    assert parse_ignore_file(lines("pragma solidity ^0.8.20;\ncontract A {}")) is None


def test_bare_directive_ignores_all_rules() -> None:
    src = """
// SPDX-License-Identifier: MIT
// sibaudit:ignore-file
pragma solidity ^0.8.20;
contract A {}
"""
    result = parse_ignore_file(lines(src))
    assert result is not None
    assert result.line_number == 2
    assert result.codes == frozenset()
    assert result.covers("A001") and result.covers("A017")


def test_directive_with_codes_limits_scope() -> None:
    src = "//sibaudit:ignore-file a001, A017\ncontract A {}"
    result = parse_ignore_file(lines(src))
    assert result is not None
    assert result.codes == {"A001", "A017"}
    assert result.covers("A001")
    assert not result.covers("A005")


def test_multiple_directives_merge_and_bare_wins() -> None:
    merged = parse_ignore_file(
        lines("// sibaudit:ignore-file A001\n// sibaudit:ignore-file A002\ncontract A {}")
    )
    assert merged is not None and merged.codes == {"A001", "A002"}
    everything = parse_ignore_file(
        lines("// sibaudit:ignore-file A001\n// sibaudit:ignore-file\ncontract A {}")
    )
    assert everything is not None and everything.codes == frozenset()


def test_directive_after_header_is_ignored() -> None:
    src = """
pragma solidity ^0.8.20;
contract A {
    // sibaudit:ignore-file
}
"""
    assert parse_ignore_file(lines(src)) is None


def test_directive_after_block_comment_and_imports() -> None:
    src = """
/*
 * Vendored test fixture.
 */
pragma solidity ^0.8.20;
import "./B.sol";
// sibaudit:ignore-file
contract A {}
"""
    result = parse_ignore_file(lines(src))
    assert result is not None and result.line_number == 6


def test_directive_inside_block_comment_is_not_honored() -> None:
    src = """
/*
// sibaudit:ignore-file
*/
contract A {}
"""
    assert parse_ignore_file(lines(src)) is None


def test_lookalike_text_does_not_match() -> None:
    for text in (
        "// sibaudit:ignore-file-later",
        "// sibaudit:ignore-file because vendored",
        "/* sibaudit:ignore-file */",
        'string constant s = "// sibaudit:ignore-file";',
    ):
        assert parse_ignore_file(lines(text + "\ncontract A {}")) is None, text
