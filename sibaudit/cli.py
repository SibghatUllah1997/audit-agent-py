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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    ns = parse_args(sys.argv[1:] if argv is None else argv)
    findings = scan_paths(ns.paths)
    for f in findings:
        rel = str(Path(f.file_path))
        print(f"{rel}:{f.line_number}: {f.code} {f.message}")
    # Exit non-zero if any findings
    sys.exit(1 if findings else 0)

