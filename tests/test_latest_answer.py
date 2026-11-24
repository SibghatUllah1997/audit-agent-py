from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths

IFACE = (
    "interface AggregatorV2Interface {\n"
    "    function latestAnswer() external view returns (int256);\n"
    "}\n"
)


def _scan(tmp_path: Path, source: str) -> list:
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A033"]


def _contract(body: str) -> str:
    return f"pragma solidity 0.8.20;\n{IFACE}contract C {{\n{body}\n}}\n"


def test_flags_direct_return(tmp_path: Path) -> None:
    body = (
        "AggregatorV2Interface public feed;\n"
        "function read() external view returns (int256) {\n"
        "    return feed.latestAnswer();\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "HIGH"
    assert "answer > 0" in finding.message
    assert "feed.latestAnswer()" in finding.line_text


def test_flags_cast_receiver_and_renamed_price(tmp_path: Path) -> None:
    body = (
        "function read(address f) external view returns (int256) {\n"
        "    int256 price = AggregatorV2Interface(f).latestAnswer();\n"
        "    return price;\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "AggregatorV2Interface(f).latestAnswer()" in findings[0].line_text


def test_flags_bare_call(tmp_path: Path) -> None:
    body = (
        "AggregatorV2Interface public feed;\n"
        "function poke() external view {\n"
        "    feed.latestAnswer();\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "feed.latestAnswer()" in findings[0].line_text


def test_answer_greater_than_zero_is_clean(tmp_path: Path) -> None:
    body = (
        "AggregatorV2Interface public feed;\n"
        "function read() external view returns (int256) {\n"
        "    int256 answer = feed.latestAnswer();\n"
        "    require(answer > 0, \"bad answer\");\n"
        "    return answer;\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_inline_comparison_is_clean(tmp_path: Path) -> None:
    body = (
        "AggregatorV2Interface public feed;\n"
        "function read() external view returns (int256) {\n"
        "    require(feed.latestAnswer() > 0, \"bad answer\");\n"
        "    return feed.latestAnswer();\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    # The require line is a check; the return still uses the price unchecked.
    assert len(findings) == 1
    assert "return feed.latestAnswer()" in findings[0].line_text


def test_inline_comparison_only_is_clean(tmp_path: Path) -> None:
    body = (
        "AggregatorV2Interface public feed;\n"
        "function ok() external view {\n"
        "    require(feed.latestAnswer() > 0, \"bad answer\");\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_cast_then_compared_is_clean(tmp_path: Path) -> None:
    body = (
        "AggregatorV2Interface public feed;\n"
        "function ok() external view {\n"
        "    require(uint256(feed.latestAnswer()) > 0, \"bad answer\");\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_latest_round_data_is_not_this_rule(tmp_path: Path) -> None:
    body = (
        "interface AggregatorV3Interface {\n"
        "    function latestRoundData() external view returns (\n"
        "        uint80, int256, uint256, uint256, uint80\n"
        "    );\n"
        "}\n"
        "contract C {\n"
        "    AggregatorV3Interface public feed;\n"
        "    function read() external view returns (int256) {\n"
        "        (, int256 answer, , , ) = feed.latestRoundData();\n"
        "        return answer;\n"
        "    }\n"
        "}\n"
    )
    (tmp_path / "C.sol").write_text("pragma solidity 0.8.20;\n" + body)
    assert not [f for f in scan_paths([str(tmp_path)]) if f.code == "A033"]


def test_commented_call_and_ignore_directive(tmp_path: Path) -> None:
    body = (
        "AggregatorV2Interface public feed;\n"
        "function read() external view returns (int256) {\n"
        "    // return feed.latestAnswer();\n"
        "    // sibaudit:ignore-next-line\n"
        "    return feed.latestAnswer();\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_interface_declaration_is_not_a_call(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "interface AggregatorV2Interface {\n"
        "    function latestAnswer() external view returns (int256);\n"
        "}\n"
        "contract C {\n"
        "    function f() external pure returns (uint256) { return 1; }\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)
