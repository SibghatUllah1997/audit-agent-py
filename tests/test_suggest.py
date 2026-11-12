from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest

from sibaudit.rules import RULES
from sibaudit.scanner import Finding
from sibaudit.suggest import (
    FALLBACK,
    LocalModelSuggester,
    SuggestError,
    attach_hints,
    builtin_catalog,
    hint_for,
    load_catalog,
    read_context,
    require_loopback,
    run_local_hint,
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
    assert attached[0].suggestion_source == "catalog"
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


def _py_cmd(source: str) -> str:
    return f"{shlex.quote(sys.executable)} -c {shlex.quote(source)}"


def test_run_local_hint_returns_first_stdout_line() -> None:
    payload = {"code": "A001", "message": "demo"}
    cmd = _py_cmd("import json,sys; print('  from cmd  '); print('ignored')")
    assert run_local_hint(cmd, payload) == "from cmd"


def test_run_local_hint_falls_back_on_failure_timeout_and_empty() -> None:
    payload = {"code": "A001"}
    failing = _py_cmd("raise SystemExit(1)")
    empty = _py_cmd("pass")
    sleepy = _py_cmd("import time; time.sleep(5)")
    broken = "this-command-does-not-exist-sibaudit-xyz"
    quoted_badly = "python3 'unterminated"
    assert run_local_hint(failing, payload) is None
    assert run_local_hint(empty, payload) is None
    assert run_local_hint(sleepy, payload, timeout=0.2) is None
    assert run_local_hint(broken, payload) is None
    assert run_local_hint(quoted_badly, payload) is None
    assert run_local_hint("", payload) is None


def test_attach_hints_prefers_local_command_then_catalog() -> None:
    finding = _finding()
    catalog_hint = hint_for("A001", finding.message)
    ok = attach_hints([finding], command=_py_cmd("print('cmd wins')"))
    assert ok[0].suggestion == "cmd wins"
    assert ok[0].suggestion_source == "command"
    failed = attach_hints([finding], command=_py_cmd("raise SystemExit(2)"))
    assert failed[0].suggestion == catalog_hint
    assert failed[0].suggestion_source == "catalog"
    silent = attach_hints([finding], command=_py_cmd("pass"))
    assert silent[0].suggestion == catalog_hint


def test_sample_catalog_and_local_script_are_usable() -> None:
    root = Path(__file__).resolve().parents[1]
    catalog_path = root / "examples" / "suggest" / "catalog.json"
    script = root / "examples" / "suggest" / "local-hint.py"
    loaded = load_catalog(catalog_path)
    assert "A001" in loaded and "A008" in loaded
    catalog = with_overrides(builtin_catalog(), loaded)
    assert hint_for("A001", catalog=catalog) == loaded["A001"]
    # Codes not in the file keep the built-in text.
    assert hint_for("A003", catalog=catalog) == hint_for("A003")

    cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(script))}"
    from_script = run_local_hint(cmd, {"code": "A001", "message": "demo"})
    assert from_script == loaded["A001"]
    fallback = run_local_hint(cmd, {"code": "A003", "message": "demo"})
    assert fallback is None


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://localhost:1/", "http://[::1]:8"])
def test_loopback_urls_are_accepted(url: str) -> None:
    assert require_loopback(url) == url.rstrip("/")


@pytest.mark.parametrize(
    "url", ["http://example.com", "http://10.0.0.5:11434", "ftp://127.0.0.1", "not a url"]
)
def test_non_loopback_urls_are_rejected(url: str) -> None:
    with pytest.raises(SuggestError):
        require_loopback(url)


def test_read_context_numbers_lines_around_finding(tmp_path: Path) -> None:
    src = tmp_path / "c.sol"
    src.write_text("\n".join(f"line{i}" for i in range(1, 11)), encoding="utf-8")
    finding = Finding(
        file_path=src,
        line_number=5,
        code="A001",
        severity="MEDIUM",
        message="msg",
        line_text="line5",
    )
    ctx = read_context(finding, radius=1)
    assert ctx.splitlines() == ["   4: line4", "   5: line5", "   6: line6"]
    missing = Finding(
        file_path=tmp_path / "missing.sol",
        line_number=1,
        code="A001",
        severity="MEDIUM",
        message="msg",
        line_text="emit Seen(tx.origin);",
    )
    assert read_context(missing) == "emit Seen(tx.origin);"


def test_local_model_answer_is_used_and_prompt_has_context(tmp_path: Path) -> None:
    src = tmp_path / "c.sol"
    src.write_text("contract C {\n  function f() external {\n    emit Seen(tx.origin);\n  }\n}\n")
    finding = Finding(
        file_path=src,
        line_number=3,
        code="A001",
        severity="MEDIUM",
        message="Potential risky use of tx.origin (often unsafe for auth).",
        line_text="    emit Seen(tx.origin);",
    )
    seen: dict[str, object] = {}

    def transport(url: str, body: bytes, timeout: float) -> bytes:
        seen["url"] = url
        seen["payload"] = json.loads(body)
        return json.dumps({"response": "  Use   msg.sender here.\n"}).encode()

    sug = LocalModelSuggester("tiny", transport=transport)
    attached = attach_hints([finding], model=sug)
    assert attached[0].suggestion_source == "local-llm"
    assert attached[0].suggestion == "Use msg.sender here."
    assert seen["url"] == "http://127.0.0.1:11434/api/generate"
    payload = seen["payload"]
    assert isinstance(payload, dict)
    assert payload["model"] == "tiny" and payload["stream"] is False
    assert "emit Seen(tx.origin);" in payload["prompt"]
    assert sug.failures == 0


@pytest.mark.parametrize("reply", [b"not json", b"{}", b'{"response": "  "}', b"[1, 2]"])
def test_bad_model_reply_falls_back_to_catalog(reply: bytes) -> None:
    finding = _finding()
    sug = LocalModelSuggester("tiny", transport=lambda u, b, t: reply)
    attached = attach_hints([finding], model=sug)
    assert attached[0].suggestion_source == "catalog"
    assert attached[0].suggestion == hint_for(finding.code, finding.message)
    assert sug.failures == 1


def test_unreachable_model_falls_back_to_catalog() -> None:
    def transport(url: str, body: bytes, timeout: float) -> bytes:
        raise ConnectionRefusedError

    sug = LocalModelSuggester("tiny", transport=transport)
    attached = attach_hints([_finding()], model=sug)
    assert attached[0].suggestion_source == "catalog"
    assert sug.failures == 1


def test_long_model_reply_is_truncated() -> None:
    long = json.dumps({"response": "word " * 500}).encode()
    sug = LocalModelSuggester("tiny", transport=lambda u, b, t: long)
    attached = attach_hints([_finding()], model=sug)
    assert attached[0].suggestion is not None
    assert len(attached[0].suggestion) <= 400
    assert attached[0].suggestion.endswith("...")
    assert attached[0].suggestion_source == "local-llm"


def test_local_model_requires_a_name() -> None:
    with pytest.raises(SuggestError, match="model name"):
        LocalModelSuggester("")


def test_attach_hints_prefers_model_then_command_then_catalog() -> None:
    finding = _finding()
    catalog_hint = hint_for("A001", finding.message)
    ok_model = LocalModelSuggester(
        "tiny", transport=lambda u, b, t: json.dumps({"response": "from model"}).encode()
    )
    ok = attach_hints(
        [finding], command=_py_cmd("print('from cmd')"), model=ok_model
    )
    assert ok[0].suggestion == "from model"
    assert ok[0].suggestion_source == "local-llm"

    bad_model = LocalModelSuggester("tiny", transport=lambda u, b, t: b"{}")
    mid = attach_hints(
        [finding], command=_py_cmd("print('from cmd')"), model=bad_model
    )
    assert mid[0].suggestion == "from cmd"
    assert mid[0].suggestion_source == "command"

    both_bad = attach_hints(
        [finding],
        command=_py_cmd("raise SystemExit(1)"),
        model=LocalModelSuggester("tiny", transport=lambda u, b, t: b"{}"),
    )
    assert both_bad[0].suggestion == catalog_hint
    assert both_bad[0].suggestion_source == "catalog"
