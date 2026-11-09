from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .scanner import Finding

SEVERITY_ORDER = ("HIGH", "MEDIUM", "LOW")
GITHUB_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "notice"}


@dataclass(frozen=True)
class Summary:
    total: int
    by_code: tuple[tuple[str, int], ...]
    by_severity: tuple[tuple[str, int], ...]
    severity_by_code: dict[str, str]


def summarize(findings: Sequence[Finding]) -> Summary:
    """Count findings by rule code and by severity."""
    code_counts = Counter(f.code for f in findings)
    severity_counts = Counter(f.severity for f in findings)
    severity_by_code: dict[str, str] = {}
    for finding in findings:
        severity_by_code.setdefault(finding.code, finding.severity)

    by_code = tuple(sorted(code_counts.items()))
    known = tuple(
        (severity, severity_counts[severity])
        for severity in SEVERITY_ORDER
        if severity in severity_counts
    )
    extra = tuple(
        (severity, severity_counts[severity])
        for severity in sorted(severity_counts)
        if severity not in SEVERITY_ORDER
    )
    return Summary(
        total=len(findings),
        by_code=by_code,
        by_severity=known + extra,
        severity_by_code=severity_by_code,
    )


def format_summary(findings: Sequence[Finding]) -> str:
    """Render a plain-text table of counts per rule and per severity."""
    summary = summarize(findings)
    noun = "finding" if summary.total == 1 else "findings"
    lines = [f"{summary.total} {noun}"]
    if summary.total == 0:
        return lines[0]

    lines.append("")
    lines.append("by rule")
    code_width = max(len(code) for code, _ in summary.by_code)
    count_width = max(len(str(count)) for _, count in summary.by_code)
    severity_width = max(len(summary.severity_by_code[code]) for code, _ in summary.by_code)
    for code, count in summary.by_code:
        severity = summary.severity_by_code[code]
        lines.append(
            f"  {code:<{code_width}}  {severity:<{severity_width}}  {count:>{count_width}}"
        )

    lines.append("")
    lines.append("by severity")
    label_width = max(len(severity) for severity, _ in summary.by_severity)
    severity_count_width = max(len(str(count)) for _, count in summary.by_severity)
    for severity, count in summary.by_severity:
        lines.append(f"  {severity:<{label_width}}  {count:>{severity_count_width}}")
    return "\n".join(lines)


def _escape_github_data(value: str) -> str:
    # Percent must be escaped first so later substitutions stay literal.
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_github_param(value: str) -> str:
    return _escape_github_data(value).replace(":", "%3A").replace(",", "%2C")


def relative_display_path(path: Path, root: Path) -> str:
    """Return a workspace-relative POSIX path when `path` is under `root`."""
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def format_github_annotations(
    findings: Sequence[Finding], *, cwd: Path | None = None
) -> str:
    """Render GitHub Actions workflow commands so findings become file annotations."""
    root = (cwd or Path.cwd()).resolve()
    lines: list[str] = []
    for finding in findings:
        level = GITHUB_LEVEL.get(finding.severity, "warning")
        file_param = _escape_github_param(relative_display_path(finding.file_path, root))
        title = _escape_github_param(f"{finding.code} ({finding.severity})")
        message = _escape_github_data(finding.message)
        lines.append(
            f"::{level} file={file_param},line={finding.line_number},title={title}::{message}"
        )
    return "\n".join(lines)
