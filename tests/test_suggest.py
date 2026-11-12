from __future__ import annotations

import json
from pathlib import Path

import pytest

from sibaudit.rules import RULES
from sibaudit.scanner import Finding
from sibaudit.suggest import (
    FALLBACK,
    SuggestError,
    attach_hints,
    builtin_catalog,
    hint_for,
    load_catalog,
    with_overrides,
)

PHISHING_MSG = (
    "tx.origin == msg.sender does not stop phishing; "
    "a malicious contract can still relay the call."
)


def test_builtin_catalog_covers_every_rule_and_nothing_else() -> None:
    catalog = builtin_catalog()
    expected = {rule.code for rule in RULES}
    assert set(catalog.defaults) == expected
    assert set(catalog.variants) <= expected
    for hint in catalog.defaults.values():
        assert hint.strip()
        assert hint != FALLBACK
        assert "\n" not in hint


def test_hint_for_is_case_insensitive_on_the_code() -> None:
    a = hint_for("a001")
    b = hint_for(" A001 ")
    c = hint_for("A001")
    assert a == b == c
    assert "msg.sender" in a
    assert "tx.origin" in a


def test_hint_for_unknown_code_returns_fallback() -> None:
    assert hint_for("A999") == FALLBACK
    assert hint_for("") == FALLBACK


def test_message_variants_are_more_specific_than_the_default() -> None:
    phishing = hint_for("A014", PHISHING_MSG)
    auth = hint_for("A014", "tx.origin used in an authorization comparison; prefer msg.sender.")
    default = hint_for("A014")
    assert "phishing" in phishing
    assert "msg.sender" in auth
    assert phishing != auth
    assert default == auth

    zero = hint_for("A013", "blockhash(block.number) is always zero and cannot seed randomness.")
    general = hint_for(
        "A013",
        "blockhash is miner-influenceable and only defined for the last 256 blocks.",
    )
    assert "always zero" in zero
    assert "block producer" in general
    assert zero != general

    unchecked = hint_for("A002", "Low-level call without capturing/validating success (heuristic).")
    delayed = hint_for("A002", "Low-level call success not obviously checked (heuristic).")
    assert "Capture (bool ok" in unchecked
    assert "next line" in delayed
    assert unchecked != delayed


def test_state_and_local_uninitialized_address_hints_differ() -> None:
    state = hint_for("A015", 'State address "owner" is never assigned and stays address(0).')
    local = hint_for("A015", 'Local address "tmp" is never assigned and stays address(0).')
    assert "constructor" in state
    assert "local" in local.lower()
    assert state != local


def test_only_owner_variants_cover_the_scanner_messages() -> None:
    after = hint_for(
        "A020",
        'Modifier "onlyOwner" checks authorization after the function body runs.',
    )
    origin = hint_for(
        "A020",
        'Modifier "onlyOwner" authenticates with tx.origin; use msg.sender.',
    )
    tautology = hint_for("A020", 'Modifier "onlyOwner" compares msg.sender to itself.')
    dummy = hint_for("A020", 'Modifier "onlyOwner" requires true and never checks the caller.')
    empty = hint_for("A020", 'Modifier "onlyOwner" never checks the caller.')
    assert "before" in after and "_;" in after
    assert "msg.sender" in origin and "tx.origin" in origin
    assert "dummy comparison" in tautology
    assert "require(true)" in dummy
    assert "_;" in empty
    assert len({after, origin, tautology, dummy, empty}) == 5


def test_overrides_replace_a_code_and_drop_its_variants() -> None:
    catalog = with_overrides(builtin_catalog(), {"a014": "Use the admin role instead."})
    assert hint_for("A014", catalog=catalog) == "Use the admin role instead."
    phishing = hint_for("A014", PHISHING_MSG, catalog=catalog)
    assert phishing == "Use the admin role instead."
    # Other codes keep their built-in text.
    assert "reentrancy" in hint_for("A008", catalog=catalog).lower() or "storage" in hint_for(
        "A008", catalog=catalog
    )


def test_load_catalog_reads_code_to_hint_object(tmp_path: Path) -> None:
    path = tmp_path / "hints.json"
    path.write_text(json.dumps({"a001": "  custom one  ", "A002": "custom two"}))
    loaded = load_catalog(path)
    assert loaded == {"A001": "custom one", "A002": "custom two"}


def _finding(
    code: str = "A001",
    message: str = "Potential risky use of tx.origin (often unsafe for auth).",
) -> Finding:
    return Finding(
        file_path=Path("demo.sol"),
        line_number=7,
        code=code,
        severity="MEDIUM",
        message=message,
        line_text="address a = tx.origin;",
    )


def test_attach_hints_sets_suggestion_and_leaves_originals_alone() -> None:
    original = _finding()
    attached = attach_hints([original])
    assert original.suggestion is None
    assert len(attached) == 1
    assert attached[0].suggestion == hint_for("A001", original.message)
    assert attached[0].file_path == original.file_path
    assert attached[0].line_number == original.line_number
    assert attached[0].code == original.code
    assert attached[0].message == original.message


def test_attach_hints_uses_message_variants_and_overrides() -> None:
    phishing = _finding(
        "A014",
        PHISHING_MSG,
    )
    unknown = _finding("A999", "mystery")
    catalog = with_overrides(builtin_catalog(), {"A001": "Custom A001 hint."})
    attached = attach_hints(
        [_finding(), phishing, unknown],
        catalog=catalog,
    )
    assert attached[0].suggestion == "Custom A001 hint."
    assert attached[1].suggestion == hint_for("A014", PHISHING_MSG)
    assert "phishing" in (attached[1].suggestion or "")
    assert attached[2].suggestion == FALLBACK


def test_attach_hints_empty_list() -> None:
    assert attach_hints([]) == []


def test_load_catalog_missing_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    with pytest.raises(SuggestError, match="not found"):
        load_catalog(missing)


def test_load_catalog_rejects_invalid_json_and_schema(tmp_path: Path) -> None:
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{")
    with pytest.raises(SuggestError, match="not valid JSON"):
        load_catalog(bad_json)

    as_list = tmp_path / "list.json"
    as_list.write_text("[]")
    with pytest.raises(SuggestError, match="JSON object"):
        load_catalog(as_list)

    empty_hint = tmp_path / "empty.json"
    empty_hint.write_text(json.dumps({"A001": "  "}))
    with pytest.raises(SuggestError, match="non-empty string"):
        load_catalog(empty_hint)
