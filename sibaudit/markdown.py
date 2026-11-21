"""Markdown report for PR comments and the Actions job summary."""

from __future__ import annotations

import html
from collections.abc import Sequence
from pathlib import Path

from .report import SEVERITY_ORDER, relative_display_path, summarize
from .scanner import Finding

# GitHub caps a PR comment at 65,536 characters. Listing a few hundred rows
# keeps a noisy scan well under that while the counts above stay exact.
DEFAULT_MAX_ROWS = 200

_MD_SPECIAL = set("\\`*_[]<>#|~")


def _text(value: object) -> str:
    """Escape a value for a table cell so it renders as plain text."""
    flat = " ".join(str(value).split())
    return "".join(f"\\{ch}" if ch in _MD_SPECIAL else ch for ch in flat)


def _prose(value: object) -> str:
    """Keep inline markdown such as `code` in rule text, but stay inside the cell."""
    flat = " ".join(str(value).split())
    return html.escape(flat, quote=False).replace("|", "\\|")


def _code(value: str) -> str:
    """Render source text as inline code that cannot break out of a table cell."""
    flat = " ".join(value.split())
    if not flat:
        return ""
    return "<code>" + html.escape(flat, quote=False).replace("|", "&#124;") + "</code>"


def _rank(severity: str) -> int:
    if severity in SEVERITY_ORDER:
        return SEVERITY_ORDER.index(severity)
    return len(SEVERITY_ORDER)


def format_markdown(
    findings: Sequence[Finding],
    *,
    cwd: Path | None = None,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> str:
    """Render findings as GitHub-flavored markdown, grouped by severity.

    Counts always cover every finding; only the per-finding rows are capped
    at ``max_rows`` so the output fits in a PR comment. Output has no
    timestamp, so the same scan gives the same text.
    """
    from .rules import get_rule

    root = (cwd or Path.cwd()).resolve()
    summary = summarize(findings)
    out = ["## sibaudit", ""]
    if not summary.total:
        out.append("No findings.")
        return "\n".join(out) + "\n"

    noun = "finding" if summary.total == 1 else "findings"
    parts = ", ".join(f"{count} {sev.lower()}" for sev, count in summary.by_severity)
    out += [f"**{summary.total} {noun}** ({parts})", ""]

    out += ["| Rule | Severity | Title | Count |", "| --- | --- | --- | ---: |"]
    for code, count in summary.by_code:
        rule = get_rule(code)
        title = rule.title if rule else ""
        out.append(
            f"| {_text(code)} | {_text(summary.severity_by_code[code])} "
            f"| {_prose(title)} | {count} |"
        )

    ordered = sorted(
        findings,
        key=lambda f: (_rank(f.severity), str(f.file_path), f.line_number, f.code),
    )
    shown = ordered[: max(max_rows, 0)]
    current = None
    for finding in shown:
        if finding.severity != current:
            current = finding.severity
            out += [
                "",
                f"### {_text(current)}",
                "",
                "| Location | Rule | Message | Source |",
                "| --- | --- | --- | --- |",
            ]
        location = f"{relative_display_path(Path(finding.file_path), root)}:{finding.line_number}"
        message = finding.message
        if finding.suggestion:
            message = f"{message} Hint: {finding.suggestion}"
        out.append(
            f"| {_text(location)} | {_text(finding.code)} | {_prose(message)} "
            f"| {_code(finding.line_text)} |"
        )

    hidden = len(ordered) - len(shown)
    if hidden > 0:
        more = "finding" if hidden == 1 else "findings"
        out += ["", f"_{hidden} more {more} not listed. Use `--format json` for all of them._"]
    return "\n".join(out) + "\n"
