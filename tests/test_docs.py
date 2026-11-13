from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
ROADMAP = ROOT / "ROADMAP.md"


def test_readme_documents_new_rule_codes() -> None:
    text = README.read_text(encoding="utf-8")
    assert "| A016 | MEDIUM" in text
    assert "| A017 | LOW" in text


def test_roadmap_marks_zero_address_and_magic_numbers_done() -> None:
    text = ROADMAP.read_text(encoding="utf-8")
    assert "- [x] Day 24: Add rule for missing zero-address checks" in text
    assert "- [x] Day 25: Add rule for magic numbers without constants" in text


def test_constructor_call_rule_is_documented_and_marked_done() -> None:
    assert "| A018 | MEDIUM" in README.read_text(encoding="utf-8")
    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert "- [x] Day 26: Add rule for external calls in constructors" in roadmap


def test_payable_and_only_owner_rules_are_documented_and_marked_done() -> None:
    text = README.read_text(encoding="utf-8")
    assert "| A019 | MEDIUM" in text
    assert "| A020 | HIGH" in text
    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert "- [x] Day 27: Add rule for payable functions w/o withdraw paths" in roadmap
    assert "- [x] Day 28: Add rule for incorrect `onlyOwner` patterns" in roadmap


def test_rules_reference_is_generated_from_the_catalog() -> None:
    from sibaudit.rules import render_markdown

    rules_doc = ROOT / "docs" / "RULES.md"
    assert rules_doc.read_text(encoding="utf-8") == render_markdown(), (
        "docs/RULES.md is stale; run `python -m sibaudit.rules > docs/RULES.md`"
    )


def test_rule_examples_are_documented_and_marked_done() -> None:
    assert "sibaudit --explain" in README.read_text(encoding="utf-8")
    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert "- [x] Day 29: Add doc examples for each rule with rationale" in roadmap


def test_config_and_filters_are_documented_and_days_31_32_are_done() -> None:
    from sibaudit.config import load_config

    text = README.read_text(encoding="utf-8")
    assert "sibaudit.toml" in text
    assert "[tool.sibaudit]" in text
    assert "--min-severity" in text
    assert "--only" in text
    assert "--except" in text
    assert "SIBAUDIT_MIN_SEVERITY" in text
    assert "SIBAUDIT_ONLY" in text
    assert "SIBAUDIT_EXCEPT" in text
    assert "examples/sibaudit.toml" in text
    sample = load_config(ROOT / "examples" / "sibaudit.toml")
    assert sample.rules["A017"].enabled is False
    assert sample.rules["A006"].severity == "LOW"
    assert sample.rules["A001"].severity == "HIGH"
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## 2026-11-13" in changelog
    assert "sibaudit.toml" in changelog
    assert "--min-severity" in changelog
    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert (
        "- [x] Day 31: Add `sibaudit.toml` / `pyproject` config for enabling, "
        "disabling, and setting severity of rules"
    ) in roadmap
    assert (
        "- [x] Day 32: Add `--min-severity` and `--only` / `--except` CLI filters, "
        "honored by the existing GitHub Action too"
    ) in roadmap


def test_suggest_is_documented_and_days_one_and_thirty_are_done() -> None:
    from sibaudit.suggest import hint_for

    text = README.read_text(encoding="utf-8")
    assert "--suggest" in text
    assert "--suggest-catalog" in text
    assert "--suggest-cmd" in text
    assert "examples/suggest/" in text
    assert f"hint: {hint_for('A001')}" in text
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## 2026-11-12" in changelog
    assert "--suggest" in changelog
    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert "- [x] Day 1: Minimal CLI + 2 rules (tx.origin, unchecked call)" in roadmap
    assert "- [x] Day 30: Optional LLM-assisted suggestions (offline/local first)" in roadmap
