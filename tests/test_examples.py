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
