from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

TX_ORIGIN_PATTERN = re.compile(r"\btx\.origin\b")
LOW_LEVEL_CALL_PATTERN = re.compile(
    r"\.(?:call|delegatecall|staticcall|callcode)\s*\(",
    flags=re.IGNORECASE,
)
DELEGATECALL_PATTERN = re.compile(r"\.delegatecall\s*\(", flags=re.IGNORECASE)
BOOL_ASSIGN_PATTERN = re.compile(
    # Matches: (bool success, ... ) = something.call(...)
    r"\(\s*bool\s+(?P<var>[A-Za-z_]\w*)\b[\s\S]*?\)\s*=.*?\.(?:call|delegatecall|staticcall|callcode)\s*\(",
    flags=re.IGNORECASE,
)
SELFDESTRUCT_OR_SUICIDE_PATTERN = re.compile(
    r"\b(?:selfdestruct|suicide)\s*\(",
    flags=re.IGNORECASE,
)

REQUIRE_VAR_PATTERN_FMT = r"require\s*\(\s*{var}\s*(?:[,)])"
ASSERT_VAR_PATTERN_FMT = r"assert\s*\(\s*{var}\s*\)"
IF_NOT_VAR_PATTERN_FMT = r"if\s*\(\s*!\s*{var}\s*\)"


@dataclass(frozen=True)
class Finding:
    file_path: Path
    line_number: int
    code: str
    message: str
    line_text: str


def _iter_solidity_files(paths: Iterable[Path]) -> Iterable[Path]:
    for p in paths:
        if p.is_file() and p.suffix.lower() == ".sol":
            yield p
        elif p.is_dir():
            for sub in p.rglob("*.sol"):
                if sub.is_file():
                    yield sub


def _detect_tx_origin(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterable[Finding]:
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        if TX_ORIGIN_PATTERN.search(line):
            yield Finding(
                file_path=file_path,
                line_number=idx,
                code="A001",
                message="Potential risky use of tx.origin (often unsafe for auth).",
                line_text=line.rstrip(),
            )


def _detect_unchecked_low_level_call(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterable[Finding]:
    # Simple heuristic:
    # 1) If a low-level call appears without assigning (bool var, ...) = ...call(...):
    #    flag it
    # 2) If assigned to (bool var, ...), ensure a nearby check exists:
    #    require(var), assert(var), or if(!var) { revert/... }
    window = 3  # lines to look ahead for checks
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        call_match = LOW_LEVEL_CALL_PATTERN.search(line)
        if not call_match:
            continue

        # Case: tuple assignment capturing bool success?
        tuple_assign = BOOL_ASSIGN_PATTERN.search(line)
        if tuple_assign:
            var_name = tuple_assign.group("var")
            # Look ahead a few lines for an obvious check of var_name
            for look_ahead in range(0, min(window, len(lines) - idx)):
                future_line = lines[idx + look_ahead].strip()
                if re.search(REQUIRE_VAR_PATTERN_FMT.format(var=re.escape(var_name)), future_line):
                    break
                if re.search(ASSERT_VAR_PATTERN_FMT.format(var=re.escape(var_name)), future_line):
                    break
                if re.search(IF_NOT_VAR_PATTERN_FMT.format(var=re.escape(var_name)), future_line):
                    break
            else:
                # No check found in the window; flag as potentially unchecked
                yield Finding(
                    file_path=file_path,
                    line_number=idx,
                    code="A002",
                    message="Low-level call success not obviously checked (heuristic).",
                    line_text=line.rstrip(),
                )
            continue

        # No tuple assignment found on this line — highly likely unchecked
        yield Finding(
            file_path=file_path,
            line_number=idx,
            code="A002",
            message="Low-level call without capturing/validating success (heuristic).",
            line_text=line.rstrip(),
        )

def _detect_delegatecall_usage(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterable[Finding]:
    # Flag any usage of delegatecall regardless of success checks.
    # delegatecall executes code in the caller's context and is often dangerous
    # unless used in a well-reviewed proxy pattern.
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        if DELEGATECALL_PATTERN.search(line):
            yield Finding(
                file_path=file_path,
                line_number=idx,
                code="A003",
                message="Use of delegatecall detected; review proxy pattern and calldata handling.",
                line_text=line.rstrip(),
            )

def _detect_selfdestruct_or_suicide(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterable[Finding]:
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        if SELFDESTRUCT_OR_SUICIDE_PATTERN.search(line):
            keyword = "selfdestruct" if "selfdestruct" in line.lower() else "suicide"
            yield Finding(
                file_path=file_path,
                line_number=idx,
                code="A004",
                message=f"Use of {keyword} detected; can brick contracts and break integrations.",
                line_text=line.rstrip(),
            )
def scan_paths(paths: Iterable[str]) -> list[Finding]:
    root_paths = [Path(p).resolve() for p in paths]
    findings: list[Finding] = []
    for file_path in _iter_solidity_files(root_paths):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            # Skip unreadable files
            continue
        lines = content.splitlines()
        # Build ignore set: for any line containing the directive, ignore the next line index.
        ignore_next_lines: set[int] = set()
        for idx, line in enumerate(lines, start=1):
            if "sibaudit:ignore-next-line" in line:
                ignore_next_lines.add(idx + 1)

        findings.extend(_detect_tx_origin(lines, file_path, ignore_next_lines))
        findings.extend(_detect_unchecked_low_level_call(lines, file_path, ignore_next_lines))
        findings.extend(_detect_delegatecall_usage(lines, file_path, ignore_next_lines))
        findings.extend(_detect_selfdestruct_or_suicide(lines, file_path, ignore_next_lines))
    return findings

