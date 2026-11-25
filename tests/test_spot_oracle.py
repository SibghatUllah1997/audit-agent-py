from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths
from sibaudit.suggest import hint_for

PAIR = (
    "interface IUniswapV2Pair {\n"
    "    function getReserves() external view returns (uint112, uint112, uint32);\n"
    "    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data)\n"
    "        external;\n"
    "}\n"
    "interface IUniswapV3Pool {\n"
    "    function slot0() external view returns (\n"
    "        uint160 sqrtPriceX96, int24 tick, uint16 observationIndex,\n"
    "        uint16 observationCardinality, uint16 observationCardinalityNext,\n"
    "        uint8 feeProtocol, bool unlocked\n"
    "    );\n"
    "    function observe(uint32[] calldata secondsAgos) external view returns (\n"
    "        int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s\n"
    "    );\n"
    "    function swap(\n"
    "        address recipient, bool zeroForOne, int256 amountSpecified,\n"
    "        uint160 sqrtPriceLimitX96, bytes calldata data\n"
    "    ) external returns (int256 amount0, int256 amount1);\n"
    "}\n"
)


def _scan(tmp_path: Path, source: str) -> list:
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A036"]


def _contract(body: str) -> str:
    return f"pragma solidity 0.8.20;\n{PAIR}contract C {{\n{body}\n}}\n"


def test_flags_get_reserves_as_price(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Pair public pair;\n"
        "function price() external view returns (uint112, uint112) {\n"
        "    (uint112 r0, uint112 r1,) = pair.getReserves();\n"
        "    return (r0, r1);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "HIGH"
    assert "getReserves()" in finding.message
    assert "flash loan" in finding.message
    assert "pair.getReserves()" in finding.line_text
    hint = hint_for("A036", finding.message)
    assert "getReserves" in hint or "TWAP" in hint


def test_flags_slot0_as_price(tmp_path: Path) -> None:
    body = (
        "IUniswapV3Pool public pool;\n"
        "function tick() external view returns (int24) {\n"
        "    (, int24 t,,,,,) = pool.slot0();\n"
        "    return t;\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "slot0()" in findings[0].message
    assert "pool.slot0()" in findings[0].line_text
    hint = hint_for("A036", findings[0].message)
    assert "observe" in hint


def test_flags_cast_receiver_and_try(tmp_path: Path) -> None:
    body = (
        "address public pair;\n"
        "function peek() external view returns (uint112, uint112) {\n"
        "    try IUniswapV2Pair(pair).getReserves() returns (uint112 r0, uint112 r1, uint32) {\n"
        "        return (r0, r1);\n"
        "    } catch {\n"
        "        return (0, 0);\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "IUniswapV2Pair(pair).getReserves()" in findings[0].line_text


def test_swap_in_same_function_is_clean(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Pair public pair;\n"
        "function dump(uint256 amount0Out, address to) external {\n"
        "    (uint112 r0, uint112 r1,) = pair.getReserves();\n"
        "    r0; r1;\n"
        "    pair.swap(amount0Out, 0, to, \"\");\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_observe_in_same_function_is_clean(tmp_path: Path) -> None:
    body = (
        "IUniswapV3Pool public pool;\n"
        "function twap(uint32[] calldata secondsAgos) external view returns (int56[] memory) {\n"
        "    pool.slot0();\n"
        "    (int56[] memory ticks,) = pool.observe(secondsAgos);\n"
        "    return ticks;\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_v3_swap_in_same_function_is_clean(tmp_path: Path) -> None:
    body = (
        "IUniswapV3Pool public pool;\n"
        "function trade(address to, bool zeroForOne, int256 amount, uint160 limit) external {\n"
        "    (uint160 sqrtPriceX96,,,,,,) = pool.slot0();\n"
        "    sqrtPriceX96;\n"
        "    pool.swap(to, zeroForOne, amount, limit, \"\");\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_helper_named_get_reserves_is_clean(tmp_path: Path) -> None:
    body = (
        "function getReserves(IUniswapV2Pair pair) internal view returns (uint112, uint112) {\n"
        "    (uint112 r0, uint112 r1,) = pair.getReserves();\n"
        "    return (r0, r1);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_get_amounts_out_helper_is_clean(tmp_path: Path) -> None:
    body = (
        "function getAmountsOut(IUniswapV2Pair pair, uint256 amountIn)\n"
        "    internal view returns (uint256)\n"
        "{\n"
        "    (uint112 r0, uint112 r1,) = pair.getReserves();\n"
        "    return amountIn * uint256(r1) / uint256(r0);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_interface_declaration_is_not_a_call(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "interface IUniswapV2Pair {\n"
        "    function getReserves() external view returns (uint112, uint112, uint32);\n"
        "}\n"
        "contract C {\n"
        "    function f() external pure returns (uint256) { return 1; }\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)


def test_commented_call_and_ignore_directive(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Pair public pair;\n"
        "function price() external view returns (uint112, uint112) {\n"
        "    // (uint112 r0, uint112 r1,) = pair.getReserves();\n"
        "    // sibaudit:ignore-next-line\n"
        "    (uint112 r0, uint112 r1,) = pair.getReserves();\n"
        "    return (r0, r1);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))
