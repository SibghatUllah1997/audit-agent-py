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
