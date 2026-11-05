from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .scanner import Finding


class BaselineError(ValueError):
    """Raised when a baseline file cannot be read or does not match the schema."""


@dataclass(frozen=True)
class BaselineEntry:
    file: str
    line: int
    code: str


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


def dump_baseline(findings: Sequence[Finding], root: Path) -> str:
    """Serialize findings to a stable, indented JSON baseline document."""
    records = [
        {
            "file": relative_file(finding.file_path, root),
            "line": finding.line_number,
            "code": finding.code,
        }
        for finding in findings
    ]
    records.sort(key=lambda item: (item["file"], item["line"], item["code"]))
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
        entries.append(BaselineEntry(file=file, line=line, code=code))
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
