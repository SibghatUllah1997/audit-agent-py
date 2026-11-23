from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths

IFACE = (
    "interface AggregatorV3Interface {\n"
    "    function latestRoundData() external view returns (\n"
    "        uint80 roundId, int256 answer, uint256 startedAt,\n"
    "        uint256 updatedAt, uint80 answeredInRound\n"
    "    );\n"
    "    function getRoundData(uint80 roundId) external view returns (\n"
    "        uint80 id, int256 answer, uint256 startedAt,\n"
    "        uint256 updatedAt, uint80 answeredInRound\n"
    "    );\n"
    "}\n"
)


def _scan(tmp_path: Path, source: str) -> list:
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A032"]


def _contract(body: str) -> str:
    return f"pragma solidity 0.8.20;\n{IFACE}contract C {{\n{body}\n}}\n"


def test_flags_unpacked_answer_with_no_checks(tmp_path: Path) -> None:
    body = (
        "AggregatorV3Interface public feed;\n"
        "function read() external view returns (int256) {\n"
        "    (, int256 answer, , , ) = feed.latestRoundData();\n"
        "    return answer;\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "HIGH"
    assert "staleness" in finding.message
    assert "answer > 0" in finding.message
    assert "feed.latestRoundData()" in finding.line_text


def test_flags_cast_receiver_and_renamed_price(tmp_path: Path) -> None:
    body = (
        "function read(address f) external view returns (int256) {\n"
        "    (, int256 price, , , ) = AggregatorV3Interface(f).latestRoundData();\n"
        "    return price;\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "AggregatorV3Interface(f).latestRoundData()" in findings[0].line_text


def test_flags_struct_style_assignment(tmp_path: Path) -> None:
    body = (
        "struct Round { int256 answer; uint256 updatedAt; }\n"
        "AggregatorV3Interface public feed;\n"
        "function read() external view returns (int256) {\n"
        "    Round memory round;\n"
        "    round.answer = 1;\n"
        "    return round.answer;\n"
        "}\n"
        "function spot() external view returns (int256) {\n"
        "    // not a real Aggregator struct; still a single assignment of the call\n"
        "    int256 data = 0;\n"
        "    data = 0;\n"
        "    feed.latestRoundData();\n"
        "    return data;\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "feed.latestRoundData()" in findings[0].line_text


def test_flags_multiline_unpack(tmp_path: Path) -> None:
    body = (
        "AggregatorV3Interface public feed;\n"
        "function read() external view returns (int256) {\n"
        "    (\n"
        "        ,\n"
        "        int256 answer,\n"
        "        ,\n"
        "        ,\n"
        "    ) = feed.latestRoundData();\n"
        "    return answer;\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "feed.latestRoundData()" in findings[0].line_text


def test_answer_greater_than_zero_is_clean(tmp_path: Path) -> None:
    body = (
        "AggregatorV3Interface public feed;\n"
        "function read() external view returns (int256) {\n"
        "    (, int256 answer, , , ) = feed.latestRoundData();\n"
        "    require(answer > 0, \"bad answer\");\n"
        "    return answer;\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_answered_in_round_is_clean(tmp_path: Path) -> None:
    body = (
        "AggregatorV3Interface public feed;\n"
        "function read() external view returns (int256) {\n"
        "    (uint80 roundId, int256 answer, , , uint80 answeredInRound) =\n"
        "        feed.latestRoundData();\n"
        "    require(answeredInRound >= roundId, \"stale round\");\n"
        "    return answer;\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_updated_at_heartbeat_is_clean(tmp_path: Path) -> None:
    body = (
        "AggregatorV3Interface public feed;\n"
        "uint256 public constant HEARTBEAT = 3600;\n"
        "function read() external view returns (int256) {\n"
        "    (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();\n"
        "    require(updatedAt > block.timestamp - HEARTBEAT, \"stale\");\n"
        "    return answer;\n"
        "}\n"
    )
    findings = [f for f in _scan(tmp_path, _contract(body))]
    assert not findings


def test_get_round_data_is_not_this_rule(tmp_path: Path) -> None:
    body = (
        "AggregatorV3Interface public feed;\n"
        "function read(uint80 id) external view returns (int256) {\n"
        "    (, int256 answer, , , ) = feed.getRoundData(id);\n"
        "    return answer;\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_commented_call_and_ignore_directive(tmp_path: Path) -> None:
    body = (
        "AggregatorV3Interface public feed;\n"
        "function read() external view returns (int256) {\n"
        "    // (, int256 answer, , , ) = feed.latestRoundData();\n"
        "    // sibaudit:ignore-next-line\n"
        "    (, int256 answer, , , ) = feed.latestRoundData();\n"
        "    return answer;\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))
