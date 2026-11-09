from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .baseline import BaselineError, apply_baseline, load_baseline, write_baseline
from .report import format_github_annotations, format_summary
from .scanner import Finding, scan_paths


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sibaudit",
        description="Scan Solidity (.sol) files for a few risky patterns (educational).",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Files or directories to scan (default: current directory).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "summary", "github"],
        default="text",
        help=(
            "Output format: 'text' (default), 'json' (newline-delimited objects), "
            "'summary', or 'github' (Actions workflow annotations)."
        ),
    )
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="GLOB",
        help="Only scan files matching this glob (repeatable), e.g. --include 'src/*'.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Skip files matching this glob (repeatable); wins over --include.",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        default=None,
        help="JSON file of known findings to suppress (file, line, and rule code).",
    )
    parser.add_argument(
        "--write-baseline",
        metavar="FILE",
        default=None,
        help="Write a JSON snapshot of current findings (before --baseline filtering).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    ns = parse_args(sys.argv[1:] if argv is None else argv)
    findings = scan_paths(ns.paths, include=ns.include, exclude=ns.exclude)
    root = Path.cwd().resolve()
    entries = []
    if ns.baseline:
        try:
            entries = load_baseline(Path(ns.baseline))
        except BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(2)
    if ns.write_baseline:
        write_baseline(Path(ns.write_baseline), findings, root)
    if entries:
        findings = apply_baseline(findings, entries, root)
    _print_findings(findings, ns.format)
    # Exit non-zero if any findings
    sys.exit(1 if findings else 0)


def _print_findings(findings: list[Finding], fmt: str) -> None:
    if fmt == "json":
        import json

        for f in findings:
            record = {
                "file_path": str(Path(f.file_path)),
                "line_number": f.line_number,
                "code": f.code,
                "severity": f.severity,
                "message": f.message,
            }
            print(json.dumps(record, ensure_ascii=False))
        return
    if fmt == "github":
        text = format_github_annotations(findings)
        if text:
            print(text)
        return
    if fmt == "summary":
        print(format_summary(findings))
        return
    for f in findings:
        rel = str(Path(f.file_path))
        print(f"{rel}:{f.line_number}: {f.code} {f.message}")
    if findings:
        print()
        print(format_summary(findings))

