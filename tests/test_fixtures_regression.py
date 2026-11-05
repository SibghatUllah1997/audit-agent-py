from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _collect_codes(findings) -> set[str]:
    return {f.code for f in findings}


def test_true_positive_fixtures_detect_expected_rules(tmp_path: Path) -> None:
    fixtures_dir = Path(__file__).parent / "fixtures" / "true_positive"
    files = sorted(p for p in fixtures_dir.glob("*.sol"))
    assert files, "no TP fixtures found"

    findings = scan_paths([str(fixtures_dir)])
    codes = _collect_codes(findings)

    # Expect each rule to be exercised by at least one TP fixture
    expected = {"A001", "A002", "A003", "A004", "A005", "A006", "A007"}
    assert expected.issubset(
        codes
    ), f"Missing expected codes from true positive fixtures. Got: {sorted(codes)}"


def test_false_positive_fixtures_have_no_findings(tmp_path: Path) -> None:
    fixtures_dir = Path(__file__).parent / "fixtures" / "false_positive"
    files = sorted(p for p in fixtures_dir.glob("*.sol"))
    assert files, "no FP fixtures found"

    findings = scan_paths([str(fixtures_dir)])
    assert not findings, f"Expected no findings for false positive fixtures, got: {findings}"
