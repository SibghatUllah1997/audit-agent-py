from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .scanner import scan_paths


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
        choices=["text", "json"],
        default="text",
        help="Output format: 'text' (default) or 'json' (newline-delimited JSON objects).",
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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    ns = parse_args(sys.argv[1:] if argv is None else argv)
    findings = scan_paths(ns.paths, include=ns.include, exclude=ns.exclude)
    if ns.format == "json":
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
    else:
        for f in findings:
            rel = str(Path(f.file_path))
            print(f"{rel}:{f.line_number}: {f.code} {f.message}")
    # Exit non-zero if any findings
    sys.exit(1 if findings else 0)

