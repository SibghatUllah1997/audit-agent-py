from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .scanner import Finding


class BaselineError(ValueError):
    """Raised when a baseline file cannot be read or does not match the schema."""


# How far a known finding may move (in lines) when the snapshot has no source text.
MAX_LINE_DRIFT = 40


@dataclass(frozen=True)
class BaselineEntry:
    file: str
    line: int
    code: str
    text: str = ""


@dataclass(frozen=True)
class BaselineUpdate:
    """Result of refreshing a snapshot against a new scan.

    ``kept`` and ``moved`` are written back. ``new`` is left out so later scans
    still report those findings. ``dropped`` were in the file and are gone.
    """

    kept: tuple[Finding, ...]
    moved: tuple[Finding, ...]
    dropped: tuple[BaselineEntry, ...]
    new: tuple[Finding, ...]

    @property
    def recorded(self) -> tuple[Finding, ...]:
        return self.kept + self.moved


def normalize_file(path: str) -> str:
    """Use forward slashes and drop a leading `./`."""
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def relative_file(file_path: Path, root: Path) -> str:
    """Path of `file_path` relative to `root`, or an absolute POSIX path if it is outside."""
    resolved = file_path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def files_match(finding_file: str, entry_file: str) -> bool:
    """True if the two paths are the same, or one is a tail of the other."""
    left = normalize_file(finding_file)
    right = normalize_file(entry_file)
    if left == right:
        return True
    return left.endswith("/" + right) or right.endswith("/" + left)


def normalize_line_text(text: str) -> str:
    """Collapse whitespace so a statement still matches after indent changes."""
    return " ".join(text.split())


def dump_baseline(findings: Sequence[Finding], root: Path) -> str:
    """Serialize findings to a stable, indented JSON baseline document."""
    records = [
        {
            "file": relative_file(finding.file_path, root),
            "line": finding.line_number,
            "code": finding.code,
            "text": normalize_line_text(finding.line_text),
        }
        for finding in findings
    ]
    records.sort(key=lambda item: (item["file"], item["line"], item["code"], item["text"]))
    payload = {"version": 1, "findings": records}
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def write_baseline(path: Path, findings: Sequence[Finding], root: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_baseline(findings, root), encoding="utf-8")


def load_baseline(path: Path) -> list[BaselineEntry]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise BaselineError(f"baseline file not found: {path}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline file is not valid JSON: {path}") from exc

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("findings", [])
        if items is None:
            items = []
    else:
        raise BaselineError("baseline file must be an object or a list")

    if not isinstance(items, list):
        raise BaselineError('baseline "findings" must be a list')

    entries: list[BaselineEntry] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise BaselineError(f"baseline finding {index} must be an object")
        file = item.get("file")
        line = item.get("line")
        code = item.get("code")
        if not isinstance(file, str) or not file.strip():
            raise BaselineError(f"baseline finding {index} is missing a file path")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            raise BaselineError(f"baseline finding {index} has an invalid line")
        if not isinstance(code, str) or not code.strip():
            raise BaselineError(f"baseline finding {index} is missing a rule code")
        text = item.get("text", "")
        if text is None:
            text = ""
        if not isinstance(text, str):
            raise BaselineError(f"baseline finding {index} has invalid source text")
        entries.append(
            BaselineEntry(file=file, line=line, code=code, text=normalize_line_text(text))
        )
    return entries


def is_suppressed(finding: Finding, entries: Sequence[BaselineEntry], root: Path) -> bool:
    rel = relative_file(finding.file_path, root)
    for entry in entries:
        if (
            finding.line_number == entry.line
            and finding.code == entry.code
            and files_match(rel, entry.file)
        ):
            return True
    return False


def apply_baseline(
    findings: Sequence[Finding],
    entries: Sequence[BaselineEntry],
    root: Path,
) -> list[Finding]:
    """Return findings that are not listed in the baseline, preserving order."""
    return [finding for finding in findings if not is_suppressed(finding, entries, root)]


def _same_file_and_code(finding: Finding, entry: BaselineEntry, root: Path) -> bool:
    return finding.code == entry.code and files_match(
        relative_file(finding.file_path, root), entry.file
    )


def _take_match(
    unused: list[Finding],
    predicate: Callable[[Finding], bool],
) -> Finding | None:
    for index, finding in enumerate(unused):
        if predicate(finding):
            return unused.pop(index)
    return None


def rematch_baseline(
    findings: Sequence[Finding],
    entries: Sequence[BaselineEntry],
    root: Path,
    *,
    max_line_drift: int = MAX_LINE_DRIFT,
) -> BaselineUpdate:
    """Pair known entries with the current scan without recording new findings.

    Matching order:

    1. Same file, code, and source text (follows a finding that moved).
    2. Same file, code, and line (covers snapshots that stored no source text).
    3. Same file and code within ``max_line_drift`` lines.

    Current findings that never match are returned in ``new`` and must not be
    written back, so a later scan still reports them.
    """
    unused = list(findings)
    kept: list[Finding] = []
    moved: list[Finding] = []
    dropped: list[BaselineEntry] = []

    pending: list[BaselineEntry] = []
    for entry in entries:
        if not entry.text:
            pending.append(entry)
            continue
        match = _take_match(
            unused,
            lambda finding, current=entry: (
                _same_file_and_code(finding, current, root)
                and normalize_line_text(finding.line_text) == current.text
            ),
        )
        if match is None:
            pending.append(entry)
            continue
        if match.line_number == entry.line:
            kept.append(match)
        else:
            moved.append(match)

    still_pending: list[BaselineEntry] = []
    for entry in pending:
        match = _take_match(
            unused,
            lambda finding, current=entry: (
                _same_file_and_code(finding, current, root)
                and finding.line_number == current.line
            ),
        )
        if match is None:
            still_pending.append(entry)
            continue
        kept.append(match)

    for entry in still_pending:
        candidates = [
            (index, finding)
            for index, finding in enumerate(unused)
            if _same_file_and_code(finding, entry, root)
            and abs(finding.line_number - entry.line) <= max_line_drift
        ]
        if not candidates:
            dropped.append(entry)
            continue
        index, finding = min(candidates, key=lambda item: abs(item[1].line_number - entry.line))
        unused.pop(index)
        if finding.line_number == entry.line:
            kept.append(finding)
        else:
            moved.append(finding)

    return BaselineUpdate(
        kept=tuple(kept),
        moved=tuple(moved),
        dropped=tuple(dropped),
        new=tuple(unused),
    )


def format_update_summary(update: BaselineUpdate) -> str:
    n_new = len(update.new)
    noun = "finding" if n_new == 1 else "findings"
    return (
        f"baseline updated: kept {len(update.kept)}, moved {len(update.moved)}, "
        f"dropped {len(update.dropped)}; {n_new} new {noun} left unsuppressed"
    )
