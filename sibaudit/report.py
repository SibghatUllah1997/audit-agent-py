from __future__ import annotations

import html
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


def _hints_by_code(findings: Sequence[Finding]) -> dict[str, tuple[str, ...]]:
    """Unique non-empty suggestions per rule, in first-seen order."""
    grouped: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}
    for finding in findings:
        hint = finding.suggestion
        if not hint:
            continue
        if hint in seen.setdefault(finding.code, set()):
            continue
        seen[finding.code].add(hint)
        grouped.setdefault(finding.code, []).append(hint)
    return {code: tuple(hints) for code, hints in grouped.items()}


def format_summary(findings: Sequence[Finding]) -> str:
    """Render a plain-text table of counts per rule and per severity."""
    summary = summarize(findings)
    noun = "finding" if summary.total == 1 else "findings"
    lines = [f"{summary.total} {noun}"]
    if summary.total == 0:
        return lines[0]

    hints = _hints_by_code(findings)
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
        for hint in hints.get(code, ()):
            lines.append(f"    hint: {hint}")

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
        message = finding.message
        if finding.suggestion:
            message = f"{message} — {finding.suggestion}"
        message = _escape_github_data(message)
        lines.append(
            f"::{level} file={file_param},line={finding.line_number},title={title}::{message}"
        )
    return "\n".join(lines)


_HTML_STYLE = """
body { font-family: system-ui, sans-serif; margin: 2rem; color: #1f2328; }
h1 { font-size: 1.4rem; }
h2 { font-size: 1.1rem; margin-top: 1.5rem; }
table { border-collapse: collapse; margin-top: 0.5rem; }
th, td { border: 1px solid #d0d7de; padding: 0.3rem 0.6rem; text-align: left; vertical-align: top; }
th { background: #f6f8fa; }
td.num { text-align: right; }
code { font-family: ui-monospace, monospace; font-size: 0.9em; }
.sev-HIGH { color: #b42318; font-weight: 600; }
.sev-MEDIUM { color: #9a6700; font-weight: 600; }
.sev-LOW { color: #57606a; }
""".strip()


def _cell(text: object, css: str | None = None) -> str:
    attr = f' class="{css}"' if css else ""
    return f"<td{attr}>{html.escape(str(text))}</td>"


def _severity_rank(severity: str) -> int:
    if severity in SEVERITY_ORDER:
        return SEVERITY_ORDER.index(severity)
    return len(SEVERITY_ORDER)


def format_html(findings: Sequence[Finding], root: Path | None = None) -> str:
    """Render a self-contained HTML report: counts, then every finding.

    The page has no scripts or external assets, and every value taken from
    the scanned sources is escaped. Output is deterministic (no timestamp),
    so two runs over the same code produce the same file. Paths are shown
    relative to ``root`` when they sit under it.
    """
    from .rules import get_rule

    summary = summarize(findings)
    noun = "finding" if summary.total == 1 else "findings"
    out = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        "<title>sibaudit report</title>",
        f"<style>\n{_HTML_STYLE}\n</style>",
        "</head>",
        "<body>",
        "<h1>sibaudit report</h1>",
        f'<p id="total">{summary.total} {noun}</p>',
    ]
    if summary.total:
        out.append("<h2>By severity</h2>")
        out.append("<table><tr><th>Severity</th><th>Count</th></tr>")
        for severity, count in summary.by_severity:
            out.append(
                f"<tr>{_cell(severity, f'sev-{severity}')}{_cell(count, 'num')}</tr>"
            )
        out.append("</table>")

        out.append("<h2>By rule</h2>")
        out.append(
            "<table><tr><th>Rule</th><th>Severity</th><th>Title</th><th>Count</th></tr>"
        )
        for code, count in summary.by_code:
            severity = summary.severity_by_code[code]
            rule = get_rule(code)
            title = rule.title if rule else ""
            out.append(
                f"<tr>{_cell(code)}{_cell(severity, f'sev-{severity}')}"
                f"{_cell(title)}{_cell(count, 'num')}</tr>"
            )
        out.append("</table>")

        out.append("<h2>Findings</h2>")
        out.append(
            "<table><tr><th>Severity</th><th>Rule</th><th>Location</th>"
            "<th>Message</th><th>Line</th></tr>"
        )
        ordered = sorted(
            findings,
            key=lambda f: (
                _severity_rank(f.severity),
                str(f.file_path),
                f.line_number,
                f.code,
            ),
        )
        for finding in ordered:
            location = f"{_display_path(Path(finding.file_path), root)}:{finding.line_number}"
            message = finding.message
            if finding.suggestion:
                message = f"{message} Hint: {finding.suggestion}"
            out.append(
                f"<tr>{_cell(finding.severity, f'sev-{finding.severity}')}"
                f"{_cell(finding.code)}{_cell(location)}{_cell(message)}"
                f"<td><code>{html.escape(finding.line_text.strip())}</code></td></tr>"
            )
        out.append("</table>")
    out.extend(["</body>", "</html>"])
    return "\n".join(out) + "\n"


def _display_path(path: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            pass
    return str(path)
