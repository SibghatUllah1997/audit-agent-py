"""JUnit XML report for CI test publishers."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from xml.sax.saxutils import escape

from .report import SEVERITY_ORDER, relative_display_path
from .scanner import Finding


def _attr(value: object) -> str:
    return escape(str(value), {"\"": "&quot;", "'": "&apos;"})


def _text(value: object) -> str:
    return escape(str(value))


def _rank(severity: str) -> int:
    if severity in SEVERITY_ORDER:
        return SEVERITY_ORDER.index(severity)
    return len(SEVERITY_ORDER)


def format_junit(findings: Sequence[Finding], *, cwd: Path | None = None) -> str:
    """Render findings as JUnit XML, one failed testcase per finding.

    A clean scan emits one passing ``scan`` testcase so publishers do not
    treat an empty suite as skipped. There is no timestamp, so the same
    scan gives the same XML.
    """
    root = (cwd or Path.cwd()).resolve()
    if not findings:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<testsuites name="sibaudit" tests="1" failures="0" errors="0">\n'
            '  <testsuite name="sibaudit" tests="1" failures="0" errors="0">\n'
            '    <testcase name="scan" classname="sibaudit"/>\n'
            "  </testsuite>\n"
            "</testsuites>\n"
        )

    ordered = sorted(
        findings,
        key=lambda f: (_rank(f.severity), str(f.file_path), f.line_number, f.code),
    )
    n = len(ordered)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites name="sibaudit" tests="{n}" failures="{n}" errors="0">',
        f'  <testsuite name="sibaudit" tests="{n}" failures="{n}" errors="0">',
    ]
    for finding in ordered:
        path = relative_display_path(Path(finding.file_path), root)
        name = f"{path}:{finding.line_number} {finding.code}"
        message = finding.message
        body = f"{path}:{finding.line_number}: {finding.code} {finding.message}"
        if finding.line_text.strip():
            body += f"\n{finding.line_text.strip()}"
        if finding.suggestion:
            body += f"\nHint: {finding.suggestion}"
        lines.append(
            f'    <testcase name="{_attr(name)}" classname="{_attr(finding.code)}" '
            f'file="{_attr(path)}" line="{finding.line_number}">'
        )
        lines.append(
            f'      <failure message="{_attr(message)}" type="{_attr(finding.severity)}">'
            f"{_text(body)}</failure>"
        )
        lines.append("    </testcase>")
    lines += ["  </testsuite>", "</testsuites>", ""]
    return "\n".join(lines)
