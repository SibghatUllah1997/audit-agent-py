"""File-level suppression directives.

A Solidity file can opt out of scanning with a line comment in its header::

    // sibaudit:ignore-file              -> skip every rule for this file
    // sibaudit:ignore-file A001, A017   -> skip only the listed rule codes

The header is everything before the first line of real code: blank lines,
comments, ``pragma`` and ``import`` statements. A directive placed further
down, or one inside a ``/* ... */`` block, is not honored, so suppressions
stay visible at the top of the file.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

DIRECTIVE = "sibaudit:ignore-file"

_DIRECTIVE_RE = re.compile(
    r"^\s*//\s*sibaudit:ignore-file"
    r"(?:\s+(?P<codes>[A-Za-z]\d{3}(?:\s*,\s*[A-Za-z]\d{3})*))?\s*$"
)
_HEADER_STATEMENT_RE = re.compile(r"^\s*(?:pragma|import)\b")


@dataclass(frozen=True)
class FileIgnore:
    """Parsed ignore-file directive. Empty ``codes`` means all rules."""

    line_number: int
    codes: frozenset[str]

    def covers(self, code: str) -> bool:
        return not self.codes or code.upper() in self.codes


def _is_header_line(line: str, in_block_comment: bool) -> tuple[bool, bool]:
    """Return (is_header_line, still_in_block_comment) for one source line."""
    stripped = line.strip()
    if in_block_comment:
        return True, "*/" not in stripped
    if not stripped or stripped.startswith("//"):
        return True, False
    if stripped.startswith("/*"):
        return True, "*/" not in stripped[2:]
    if _HEADER_STATEMENT_RE.match(stripped):
        return True, False
    return False, False


def parse_ignore_file(lines: Sequence[str]) -> FileIgnore | None:
    """Find ignore-file directives in the header and merge them.

    Returns ``None`` when the file has no directive. If several directives are
    present, their codes are merged; any directive without codes wins and
    suppresses every rule.
    """
    first_line: int | None = None
    codes: set[str] = set()
    ignore_all = False
    in_block = False
    for idx, line in enumerate(lines, start=1):
        was_in_block = in_block
        is_header, in_block = _is_header_line(line, in_block)
        if not is_header:
            break
        match = None if was_in_block else _DIRECTIVE_RE.match(line)
        if not match:
            continue
        if first_line is None:
            first_line = idx
        raw = match.group("codes")
        if raw is None:
            ignore_all = True
        else:
            codes.update(part.strip().upper() for part in raw.split(","))
    if first_line is None:
        return None
    return FileIgnore(line_number=first_line, codes=frozenset() if ignore_all else frozenset(codes))
