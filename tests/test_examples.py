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


def test_sample_contract_flags_broken_only_owner() -> None:
    findings = scan_paths([str(EXAMPLES)])
    broken = [f for f in findings if f.code == "A020"]
    assert broken
    assert any("onlyOwner" in f.line_text for f in broken)
    assert any("never checks the caller" in f.message for f in broken)


def test_sample_contract_flags_unchecked_ecrecover() -> None:
    findings = scan_paths([str(EXAMPLES)])
    recovered = [f for f in findings if f.code == "A021"]
    assert recovered
    assert any("ecrecover" in f.line_text for f in recovered)
    assert any("zero-address" in f.message or "identity" in f.message for f in recovered)


def test_sample_contract_flags_stipend_ether_send() -> None:
    findings = scan_paths([str(EXAMPLES)])
    stipend = [f for f in findings if f.code == "A022"]
    assert stipend
    assert any(".transfer(" in f.line_text for f in stipend)
    assert any("2300" in f.message for f in stipend)


def test_sample_contract_flags_floating_pragma() -> None:
    findings = scan_paths([str(EXAMPLES)])
    floating = [f for f in findings if f.code == "A023"]
    assert len(floating) == 1
    assert floating[0].line_number == 2
    assert "^0.7.6" in floating[0].message


def test_sample_contract_flags_encode_packed_collision() -> None:
    findings = scan_paths([str(EXAMPLES)])
    packed = [f for f in findings if f.code == "A024"]
    assert packed
    assert any("encodePacked" in f.line_text for f in packed)
    assert any("dynamic" in f.message for f in packed)


def test_sample_contract_flags_upgradeable_initializer() -> None:
    findings = scan_paths([str(EXAMPLES)])
    inits = [f for f in findings if f.code == "A025"]
    assert inits
    assert any("initialize" in f.line_text for f in inits)
    assert any("without an initializer lock" in f.message for f in inits)
    assert any("_disableInitializers" in f.message for f in inits)


def test_sample_contract_flags_signature_replay() -> None:
    findings = scan_paths([str(EXAMPLES)])
    replay = [f for f in findings if f.code == "A026"]
    assert len(replay) == 1
    assert "ecrecover" in replay[0].line_text
    assert "no nonce, deadline, chain id" in replay[0].message


def test_sample_contract_flags_extcodesize_eoa_check() -> None:
    findings = scan_paths([str(EXAMPLES)])
    eoa = [f for f in findings if f.code == "A027"]
    assert len(eoa) == 1
    assert "code.length" in eoa[0].line_text
    assert "EOA" in eoa[0].message
    assert eoa[0].severity == "HIGH"


def test_sample_contract_flags_unchecked_erc20_return() -> None:
    findings = scan_paths([str(EXAMPLES)])
    dropped = [f for f in findings if f.code == "A028"]
    assert len(dropped) == 1
    assert "token.transfer(to, amount)" in dropped[0].line_text
    assert dropped[0].severity == "MEDIUM"


def test_sample_contract_flags_unbounded_storage_loop() -> None:
    findings = scan_paths([str(EXAMPLES)])
    loops = [f for f in findings if f.code == "A029"]
    assert len(loops) == 1
    assert "recipients.length" in loops[0].line_text
    assert "run out of gas" in loops[0].message
    assert loops[0].severity == "HIGH"
