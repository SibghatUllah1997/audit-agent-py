from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .baseline import BaselineError, apply_baseline, load_baseline, write_baseline
from .config import ConfigError, apply_config, find_and_load_config, load_config
from .filters import FilterError, apply_filters, parse_codes, parse_severity
from .report import format_github_annotations, format_summary
from .rules import format_explain, format_rule_list, get_rule
from .scanner import Finding, scan_paths
from .suggest import (
    DEFAULT_LOCAL_URL,
    LocalModelSuggester,
    SuggestError,
    attach_hints,
    builtin_catalog,
    load_catalog,
    with_overrides,
)


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
        "--config",
        metavar="FILE",
        default=None,
        help=(
            "TOML config that enables, disables, or sets severity of rules. "
            "Default: nearest sibaudit.toml or [tool.sibaudit] in pyproject.toml."
        ),
    )
    parser.add_argument(
        "--min-severity",
        metavar="LEVEL",
        default=None,
        help="Hide findings below this severity (LOW, MEDIUM, or HIGH).",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="CODE",
        help="Only report these rule codes (repeatable, comma-separated).",
    )
    parser.add_argument(
        "--except",
        dest="except_codes",
        action="append",
        default=[],
        metavar="CODE",
        help="Skip these rule codes (repeatable, comma-separated).",
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
    parser.add_argument(
        "--suggest-backend",
        choices=["catalog", "local-llm"],
        default="catalog",
        help=(
            "Where suggestions come from: 'catalog' (default, built-in or "
            "--suggest-catalog hints) or 'local-llm' (a model served on this "
            "machine; falls back to the catalog)."
        ),
    )
    parser.add_argument(
        "--llm-model",
        metavar="NAME",
        default=None,
        help="Model name for --suggest-backend local-llm.",
    )
    parser.add_argument(
        "--llm-url",
        metavar="URL",
        default=None,
        help="Loopback URL of the local model server (default: http://127.0.0.1:11434).",
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
    try:
        config = load_config(Path(ns.config)) if ns.config else find_and_load_config(Path.cwd())
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    findings = scan_paths(ns.paths, include=ns.include, exclude=ns.exclude)
    findings = apply_config(findings, config)
    try:
        findings = apply_filters(
            findings,
            min_severity=parse_severity(ns.min_severity or os.environ.get("SIBAUDIT_MIN_SEVERITY")),
            only=parse_codes(_flag_or_env(ns.only, "SIBAUDIT_ONLY")),
            except_codes=parse_codes(_flag_or_env(ns.except_codes, "SIBAUDIT_EXCEPT")),
        )
    except FilterError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
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
    if (ns.llm_model or ns.llm_url) and ns.suggest_backend != "local-llm":
        print(
            "error: --llm-model and --llm-url require --suggest-backend local-llm",
            file=sys.stderr,
        )
        sys.exit(2)
    catalog = builtin_catalog()
    if ns.suggest_catalog:
        try:
            catalog = with_overrides(catalog, load_catalog(Path(ns.suggest_catalog)))
        except SuggestError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(2)
    model: LocalModelSuggester | None = None
    if ns.suggest_backend == "local-llm":
        try:
            model = LocalModelSuggester(ns.llm_model or "", ns.llm_url or DEFAULT_LOCAL_URL)
        except SuggestError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(2)
    if ns.suggest or ns.suggest_catalog or ns.suggest_cmd or model is not None:
        findings = attach_hints(
            findings, catalog=catalog, command=ns.suggest_cmd, model=model
        )
        if model is not None and model.failures:
            print(
                "note: local model gave no answer for "
                f"{model.failures} finding(s); used catalog hints",
                file=sys.stderr,
            )
    _print_findings(findings, ns.format)
    # Exit non-zero if any findings
    sys.exit(1 if findings else 0)


def _flag_or_env(flag_values: list[str], env_name: str) -> list[str]:
    """CLI flags win; otherwise a comma-separated environment value is used."""
    if flag_values:
        return flag_values
    value = os.environ.get(env_name, "").strip()
    return [value] if value else []


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
                if f.suggestion_source:
                    record["suggestion_source"] = f.suggestion_source
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

