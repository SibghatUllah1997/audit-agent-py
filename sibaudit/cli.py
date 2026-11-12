from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .baseline import BaselineError, apply_baseline, load_baseline, write_baseline
from .report import format_github_annotations, format_summary
from .rules import format_explain, format_rule_list, get_rule
from .scanner import Finding, scan_paths
from .suggest import SuggestError, attach_hints, builtin_catalog, load_catalog, with_overrides


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
    parser.add_argument(
        "--explain",
        metavar="CODE",
        default=None,
        help="Print why a rule matters plus a flagged and a fixed example, then exit.",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="List every rule code with its severity and title, then exit.",
    )
    parser.add_argument(
        "--suggest",
        action="store_true",
        help=(
            "Attach a local fix hint to each finding from the built-in catalog. "
            "Works fully offline; nothing is sent over the network."
        ),
    )
    parser.add_argument(
        "--suggest-catalog",
        metavar="FILE",
        default=None,
        help=(
            "JSON object mapping rule codes to custom hints. Implies --suggest. "
            "Overrides the built-in catalog for those codes."
        ),
    )
    parser.add_argument(
        "--suggest-cmd",
        metavar="CMD",
        default=None,
        help=(
            "Optional local command. Each finding is written as one JSON object "
            "on stdin; the first non-empty stdout line becomes the hint. If the "
            "command fails or times out, the catalog hint is used instead. "
            "Implies --suggest."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    ns = parse_args(sys.argv[1:] if argv is None else argv)
    if ns.list_rules:
        print(format_rule_list())
        sys.exit(0)
    if ns.explain is not None:
        rule = get_rule(ns.explain)
        if rule is None:
            print(f"error: unknown rule code {ns.explain!r}; see --list-rules", file=sys.stderr)
            sys.exit(2)
        print(format_explain(rule))
        sys.exit(0)
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
    catalog = builtin_catalog()
    if ns.suggest_catalog:
        try:
            catalog = with_overrides(catalog, load_catalog(Path(ns.suggest_catalog)))
        except SuggestError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(2)
    if ns.suggest or ns.suggest_catalog or ns.suggest_cmd:
        findings = attach_hints(findings, catalog=catalog, command=ns.suggest_cmd)
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
            if f.suggestion:
                record["suggestion"] = f.suggestion
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
        if f.suggestion:
            print(f"    hint: {f.suggestion}")
    if findings:
        print()
        print(format_summary(findings))

