from __future__ import annotations

import tomllib
from pathlib import Path

from sibaudit import __version__
from sibaudit.rules import (
    PHASE2_CODES,
    RULES,
    render_json_catalog,
    render_phase2_markdown,
    rules_for,
)
from sibaudit.scanner import scan_paths

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "examples" / "catalog"
DOCS = ROOT / "docs"


def test_package_version_is_0_2_0() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == "0.2.0"
    assert __version__ == "0.2.0"


def test_phase2_codes_are_the_seven_v0_2_rules() -> None:
    assert PHASE2_CODES == ("A021", "A022", "A023", "A024", "A025", "A026", "A027")
    catalog_codes = {rule.code for rule in RULES}
    assert set(PHASE2_CODES) <= catalog_codes
    assert [rule.code for rule in rules_for(PHASE2_CODES)] == list(PHASE2_CODES)


def test_phase2_markdown_catalog_is_generated() -> None:
    path = DOCS / "catalog-v0.2.md"
    assert path.read_text(encoding="utf-8") == render_phase2_markdown(), (
        "docs/catalog-v0.2.md is stale; run "
        "`python -m sibaudit.rules --codes A021 A022 A023 A024 A025 A026 A027 "
        "> docs/catalog-v0.2.md`"
    )


def test_phase2_json_catalog_is_generated() -> None:
    path = DOCS / "catalog-v0.2.json"
    expected = render_json_catalog(rules_for(PHASE2_CODES))
    assert path.read_text(encoding="utf-8") == expected, (
        "docs/catalog-v0.2.json is stale; run "
        "`python -m sibaudit.rules --json --codes A021 A022 A023 A024 A025 A026 A027 "
        "> docs/catalog-v0.2.json`"
    )
    assert f'"version": "{__version__}"' in expected


def test_catalog_solidity_examples_match_the_rules() -> None:
    for rule in rules_for(PHASE2_CODES):
        flagged = CATALOG / "flagged" / f"{rule.code}.sol"
        fixed = CATALOG / "fixed" / f"{rule.code}.sol"
        assert flagged.read_text(encoding="utf-8") == rule.flagged
        assert fixed.read_text(encoding="utf-8") == rule.fixed


def test_flagged_catalog_dir_triggers_each_phase2_rule() -> None:
    findings = scan_paths([str(CATALOG / "flagged")])
    by_file: dict[str, set[str]] = {}
    for finding in findings:
        by_file.setdefault(finding.file_path.name, set()).add(finding.code)
    for code in PHASE2_CODES:
        assert code in by_file[f"{code}.sol"], (code, by_file.get(f"{code}.sol"))


def test_fixed_catalog_dir_is_clean() -> None:
    findings = scan_paths([str(CATALOG / "fixed")])
    assert findings == []
