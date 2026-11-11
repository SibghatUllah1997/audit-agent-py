from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "Vulnerable.sol"


def test_sample_contract_flags_reentrancy_and_access_control() -> None:
    findings = scan_paths([str(EXAMPLES)])
    codes = {f.code for f in findings}
    assert {"A008", "A009"} <= codes
    assert any(f.code == "A008" and ".call" in f.line_text for f in findings)
    assert any(f.code == "A009" and "mint" in f.line_text for f in findings)


def test_sample_contract_flags_event_params_and_blockhash() -> None:
    findings = scan_paths([str(EXAMPLES)])
    codes = {f.code for f in findings}
    assert {"A012", "A013"} <= codes
    assert any(f.code == "A012" and "Transfer" in f.line_text for f in findings)
    assert any(f.code == "A013" and "blockhash" in f.line_text for f in findings)


def test_sample_contract_flags_zero_address_and_magic_numbers() -> None:
    findings = scan_paths([str(EXAMPLES)])
    codes = {f.code for f in findings}
    assert {"A016", "A017"} <= codes
    assert any(f.code == "A016" and "treasury = newTreasury" in f.line_text for f in findings)
    assert any(
        f.code == "A017" and "25" in f.line_text and "10000" in f.line_text for f in findings
    )


def test_sample_contract_flags_constructor_external_call() -> None:
    findings = scan_paths([str(EXAMPLES)])
    assert any(f.code == "A018" and "registry.call" in f.line_text for f in findings)


def test_sample_contract_flags_payable_without_withdraw() -> None:
    findings = scan_paths([str(EXAMPLES)])
    locked = [f for f in findings if f.code == "A019"]
    assert locked
    assert any("donate" in f.message or "donate" in f.line_text for f in locked)
    assert any("receive" in f.message.lower() or "receive()" in f.line_text for f in locked)
    # The main sample already sends ether in withdraw(), so it must stay quiet.
    assert not any("function withdraw()" in f.line_text for f in locked)
