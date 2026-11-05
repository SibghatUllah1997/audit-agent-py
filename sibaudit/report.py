from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from .scanner import Finding

SEVERITY_ORDER = ("HIGH", "MEDIUM", "LOW")


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
