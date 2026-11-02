from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__ as SIBAUDIT_VERSION
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
        choices=["text", "json", "sarif"],
        default="text",
        help=(
            "Output format: 'text' (default), 'json' (newline-delimited JSON objects), "
            "or 'sarif' (single SARIF v2.1.0 JSON document)."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    ns = parse_args(sys.argv[1:] if argv is None else argv)
    findings = scan_paths(ns.paths)
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
    elif ns.format == "sarif":
        import json
        from datetime import datetime, timezone

        # Map our severities to SARIF levels
        level_map = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

        # Define rules metadata (ids and descriptions)
        rules_meta = {
            "A001": {
                "id": "A001",
                "shortDescription": {"text": "Risky use of tx.origin"},
                "fullDescription": {
                    "text": "Potential risky use of tx.origin (often unsafe for authentication)."
                },
                "defaultConfiguration": {"level": level_map["MEDIUM"]},
            },
            "A002": {
                "id": "A002",
                "shortDescription": {"text": "Unchecked low-level call"},
                "fullDescription": {
                    "text": "Low-level call without capturing/validating success (heuristic)."
                },
                "defaultConfiguration": {"level": level_map["MEDIUM"]},
            },
            "A003": {
                "id": "A003",
                "shortDescription": {"text": "Use of delegatecall"},
                "fullDescription": {
                    "text": (
                        "Use of delegatecall detected; review proxy pattern and "
                        "calldata handling."
                    )
                },
                "defaultConfiguration": {"level": level_map["HIGH"]},
            },
            "A004": {
                "id": "A004",
                "shortDescription": {"text": "Use of selfdestruct/suicide"},
                "fullDescription": {
                    "text": (
                        "Use of selfdestruct/suicide detected; can brick contracts "
                        "and break integrations."
                    )
                },
                "defaultConfiguration": {"level": level_map["HIGH"]},
            },
            "A005": {
                "id": "A005",
                "shortDescription": {"text": "State variable shadowing"},
                "fullDescription": {
                    "text": "Function parameter shadows a state variable (heuristic)."
                },
                "defaultConfiguration": {"level": level_map["LOW"]},
            },
            "A006": {
                "id": "A006",
                "shortDescription": {"text": "Use of block.timestamp/now"},
                "fullDescription": {
                    "text": "Use of block.timestamp/now detected; time can be manipulated slightly."
                },
                "defaultConfiguration": {"level": level_map["MEDIUM"]},
            },
            "A007": {
                "id": "A007",
                "shortDescription": {"text": "Unchecked arithmetic pre-0.8"},
                "fullDescription": {
                    "text": "Unchecked arithmetic in pre-0.8 Solidity (overflow/underflow risk)."
                },
                "defaultConfiguration": {"level": level_map["MEDIUM"]},
            },
        }

        results = []
        for f in findings:
            level = level_map.get(f.severity.upper(), "warning")
            results.append(
                {
                    "ruleId": f.code,
                    "level": level,
                    "message": {"text": f.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": str(Path(f.file_path)),
                                },
                                "region": {"startLine": f.line_number},
                            }
                        }
                    ],
                    "properties": {"lineText": f.line_text},
                }
            )

        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "sibaudit",
                            "informationUri": "https://github.com/",
                            "semanticVersion": SIBAUDIT_VERSION,
                            "rules": list(rules_meta.values()),
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                    "results": results,
                }
            ],
        }
        print(json.dumps(sarif, ensure_ascii=False))
    else:
        for f in findings:
            rel = str(Path(f.file_path))
            print(f"{rel}:{f.line_number}: {f.code} {f.message}")
    # Exit non-zero if any findings
    sys.exit(1 if findings else 0)

