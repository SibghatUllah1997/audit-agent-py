from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .report import relative_display_path
from .scanner import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
# GitHub code scanning reads this property to rank alerts (0.0-10.0).
SECURITY_SEVERITY = {"HIGH": "8.0", "MEDIUM": "5.0", "LOW": "2.0"}
INFO_URI = "https://github.com/SibghatUllah1997/audit-agent-py"


def _line_fingerprint(finding: Finding, path: str) -> str:
    """Stable id for one finding that survives edits elsewhere in the file.

    Built from the path, rule code, and whitespace-normalized source line,
    but not the line number, so code scanning keeps the same alert open when
    the line only moves.
    """
    normalized = " ".join(finding.line_text.split())
    digest = hashlib.sha256(f"{path}\0{finding.code}\0{normalized}".encode()).hexdigest()
    return f"{digest[:32]}:1"


def _rule_descriptor(code: str, severity: str) -> dict:
    from .rules import get_rule

    rule = get_rule(code)
    title = rule.title if rule else code
    descriptor: dict = {
        "id": code,
        "name": code,
        "shortDescription": {"text": title},
        "defaultConfiguration": {"level": SARIF_LEVEL.get(severity, "warning")},
        "helpUri": f"{INFO_URI}/blob/main/docs/RULES.md",
        "properties": {
            "tags": ["security", "solidity"],
            "security-severity": SECURITY_SEVERITY.get(severity, "5.0"),
        },
    }
    if rule is not None:
        descriptor["fullDescription"] = {"text": rule.rationale.strip()}
    return descriptor


def build_sarif(findings: Sequence[Finding], *, root: Path | None = None) -> dict:
    """Return a SARIF 2.1.0 log with one run, one rule per reported code.

    Paths are made relative to ``root`` (default: cwd) so GitHub can map
    alerts onto the checked-out tree. Output order is deterministic.
    """
    base = (root or Path.cwd()).resolve()
    ordered = sorted(findings, key=lambda f: (str(f.file_path), f.line_number, f.code))

    severity_by_code: dict[str, str] = {}
    for finding in ordered:
        severity_by_code.setdefault(finding.code, finding.severity)
    codes = sorted(severity_by_code)
    index = {code: i for i, code in enumerate(codes)}

    results = []
    occurrences: dict[str, int] = {}
    for finding in ordered:
        path = relative_display_path(Path(finding.file_path), base)
        message = finding.message
        if finding.suggestion:
            message = f"{message} Hint: {finding.suggestion}"
        fingerprint = _line_fingerprint(finding, path)
        # Identical lines in one file (same rule) still need distinct ids.
        seen = occurrences.get(fingerprint, 0) + 1
        occurrences[fingerprint] = seen
        if seen > 1:
            fingerprint = f"{fingerprint.rsplit(':', 1)[0]}:{seen}"
        results.append(
            {
                "ruleId": finding.code,
                "ruleIndex": index[finding.code],
                "level": SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": path},
                            "region": {
                                "startLine": max(1, finding.line_number),
                                "snippet": {"text": finding.line_text.rstrip("\n")},
                            },
                        }
                    }
                ],
                "partialFingerprints": {"primaryLocationLineHash": fingerprint},
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sibaudit",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": [_rule_descriptor(c, severity_by_code[c]) for c in codes],
                    }
                },
                "results": results,
            }
        ],
    }


def format_sarif(findings: Sequence[Finding], *, root: Path | None = None) -> str:
    return json.dumps(build_sarif(findings, root=root), indent=2, ensure_ascii=False) + "\n"
