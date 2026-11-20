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


def test_ecrecover_and_stipend_rules_are_documented_and_days_34_35_are_done() -> None:
    text = README.read_text(encoding="utf-8")
    assert "| A021 | HIGH" in text
    assert "| A022 | MEDIUM" in text
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## 2026-11-16" in changelog
    assert "A021" in changelog
    assert "A022" in changelog
    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert (
        "- [x] Day 34: Add rule A021: `ecrecover` without a zero-address / "
        "identity check on the recovered signer"
    ) in roadmap
    assert (
        "- [x] Day 35: Add rule A022: ether `transfer`/`send` (2300-gas stipend) "
        "used instead of `call`"
    ) in roadmap


def test_floating_pragma_rule_is_documented_and_day_36_is_done() -> None:
    assert "| A023 | LOW" in README.read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "A023" in changelog
    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert (
        "- [x] Day 36: Add rule A023: floating Solidity pragma (`^` / `>=`) in production sources"
    ) in roadmap


def test_encode_packed_and_initializer_rules_are_documented_and_days_37_38_are_done() -> None:
    text = README.read_text(encoding="utf-8")
    assert "| A024 | HIGH" in text
    assert "| A025 | HIGH" in text
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## 2026-11-17" in changelog
    assert "A024" in changelog
    assert "A025" in changelog
    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert (
        "- [x] Day 37: Add rule A024: hash collisions from `abi.encodePacked` of dynamic types"
    ) in roadmap
    assert (
        "- [x] Day 38: Add rule A025: upgradeable initializer left public, or "
        "`_disableInitializers` missing in the constructor"
    ) in roadmap



def test_signature_replay_rule_is_documented_and_day_39_is_done() -> None:
    assert "| A026 | HIGH" in README.read_text(encoding="utf-8")
    assert "A026" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert (
        "- [x] Day 39: Add rule A026: signature-replay risk "
        "(signed data missing nonce, deadline, or chain id)"
    ) in roadmap


def test_extcodesize_and_layout_discovery_are_documented_and_days_40_41_are_done() -> None:
    text = README.read_text(encoding="utf-8")
    assert "| A027 | HIGH" in text
    assert "foundry.toml" in text
    assert "hardhat.config.js" in text
    assert "src/" in text and "contracts/" in text
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## 2026-11-18" in changelog
    assert "A027" in changelog
    assert "Foundry" in changelog
    assert "Hardhat" in changelog
    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert (
        "- [x] Day 40: Add rule A027: `extcodesize == 0` used as an EOA check "
        "(breaks under constructor and EIP-7702)"
    ) in roadmap
    assert (
        "- [x] Day 41: Discover Foundry and Hardhat layouts (`src/`, `contracts/`) "
        "when a directory is scanned with no paths"
    ) in roadmap


def test_baseline_update_and_v0_2_catalog_are_documented_and_days_43_44_are_done() -> None:
    readme = README.read_text(encoding="utf-8")
    assert "--update-baseline" in readme
    assert "docs/catalog-v0.2.md" in readme
    assert "examples/catalog/" in readme
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## 2026-11-19" in changelog
    assert "--update-baseline" in changelog
    assert "A021" in changelog and "A027" in changelog
    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert (
        "- [x] Day 43: Add a baseline auto-update command that records current "
        "findings without hiding new ones later"
    ) in roadmap
    assert (
        "- [x] Day 44: Tag v0.2.0 and publish a rule catalog with examples for A021–A027"
    ) in roadmap


def test_fail_on_and_html_report_are_documented_and_day_42_is_done() -> None:
    readme = README.read_text(encoding="utf-8")
    assert "--fail-on" in readme
    assert "--html-report" in readme
    assert "SIBAUDIT_FAIL_ON" in readme
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "--fail-on" in changelog
    assert "--html-report" in changelog
    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert (
        "- [x] Day 42: Add an HTML summary report and a `--fail-on` exit policy"
    ) in roadmap


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


def test_erc20_return_rule_is_documented_and_day_46_is_done() -> None:
    assert "| A028 | MEDIUM" in README.read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## 2026-11-20 (day 46)" in changelog
    assert "A028" in changelog
    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert "# Phase 3" in roadmap
    assert (
        "- [x] Day 46: Add rule A028: ERC-20 `transfer` / `transferFrom` / `approve` "
        "return value ignored (no SafeERC20 or check)"
    ) in roadmap
