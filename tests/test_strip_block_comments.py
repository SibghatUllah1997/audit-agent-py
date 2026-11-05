from __future__ import annotations

from sibaudit.scanner import _strip_block_comments


def test_strip_entire_line_inside_block() -> None:
    out, state = _strip_block_comments("   still inside comment", True)
    assert out == ""
    assert state is True


def test_strip_multiple_pairs() -> None:
    line = "a/*one*/b/*two*/c"
    out, state = _strip_block_comments(line, False)
    assert out == "abc"
    assert state is False


def test_strip_start_without_end() -> None:
    out, state = _strip_block_comments("a/* dangling", False)
    assert out == "a"
    assert state is True


def test_strip_end_then_rest() -> None:
    out, state = _strip_block_comments("*/call(\"\")", True)
    assert out.startswith("call")
    assert state is False
