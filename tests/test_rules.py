from __future__ import annotations

import re
from pathlib import Path

import pytest

from sibaudit.rules import RULES, Rule, format_explain, get_rule
from sibaudit.scanner import scan_paths

ROOT = Path(__file__).resolve().parents[1]
SCANNER_SOURCE = (ROOT / "sibaudit" / "scanner.py").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def _scan_snippet(tmp_path: Path, name: str, source: str) -> list[tuple[str, str]]:
    path = tmp_path / f"{name}.sol"
    path.write_text(source, encoding="utf-8")
    return [(f.code, f.severity) for f in scan_paths([str(path)])]


def test_catalog_codes_are_unique_and_ordered() -> None:
    codes = [rule.code for rule in RULES]
    assert codes == sorted(set(codes))


def test_catalog_covers_every_code_the_scanner_emits() -> None:
    emitted = set(re.findall(r'code="(A\d{3})"', SCANNER_SOURCE))
    assert emitted == {rule.code for rule in RULES}


def test_catalog_severity_matches_readme_table() -> None:
    for rule in RULES:
        assert f"| {rule.code} | {rule.severity}" in README, rule.code


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.code)
def test_flagged_example_triggers_its_rule(rule: Rule, tmp_path: Path) -> None:
    findings = _scan_snippet(tmp_path, f"{rule.code}_flagged", rule.flagged)
    assert (rule.code, rule.severity) in findings


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.code)
def test_fixed_example_is_clean(rule: Rule, tmp_path: Path) -> None:
    # The fixed version should not just silence its own rule; it should
    # not trade one finding for another.
    assert _scan_snippet(tmp_path, f"{rule.code}_fixed", rule.fixed) == []


def test_get_rule_is_case_insensitive_and_rejects_unknown_codes() -> None:
    assert get_rule(" a014 ") is get_rule("A014")
    assert get_rule("A999") is None


def test_explain_includes_rationale_and_both_examples() -> None:
    rule = get_rule("A008")
    assert rule is not None
    text = format_explain(rule)
    assert text.startswith("A008 (HIGH): ")
    assert rule.rationale in text
    assert "Flagged:" in text and "Fixed:" in text
    assert "    contract Bank {" in text
