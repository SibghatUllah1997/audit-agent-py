from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths
from sibaudit.suggest import hint_for

ROUTERS = (
    "interface IUniswapV2Router {\n"
    "    function swapExactTokensForTokens(\n"
    "        uint256 amountIn, uint256 amountOutMin, address[] calldata path,\n"
    "        address to, uint256 deadline\n"
    "    ) external returns (uint256[] memory amounts);\n"
    "    function swapExactETHForTokens(\n"
    "        uint256 amountOutMin, address[] calldata path,\n"
    "        address to, uint256 deadline\n"
    "    ) external payable returns (uint256[] memory amounts);\n"
    "    function swapTokensForExactETH(\n"
    "        uint256 amountOut, uint256 amountInMax, address[] calldata path,\n"
    "        address to, uint256 deadline\n"
    "    ) external returns (uint256[] memory amounts);\n"
    "}\n"
    "interface ISwapRouter {\n"
    "    struct ExactInputSingleParams {\n"
    "        address tokenIn; address tokenOut; uint24 fee; address recipient;\n"
    "        uint256 deadline; uint256 amountIn; uint256 amountOutMinimum;\n"
    "        uint160 sqrtPriceLimitX96;\n"
    "    }\n"
    "    struct ExactOutputParams {\n"
    "        bytes path; address recipient; uint256 deadline;\n"
    "        uint256 amountOut; uint256 amountInMaximum;\n"
    "    }\n"
    "    function exactInputSingle(ExactInputSingleParams calldata params)\n"
    "        external payable returns (uint256 amountOut);\n"
    "    function exactOutput(ExactOutputParams calldata params)\n"
    "        external payable returns (uint256 amountIn);\n"
    "}\n"
)


def _scan(tmp_path: Path, body: str) -> list:
    source = f"pragma solidity 0.8.20;\n{ROUTERS}contract C {{\n{body}\n}}\n"
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A038"]


def test_flags_v2_swap_with_zero_deadline(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function sell(uint256 amountIn, uint256 minOut, address[] calldata path) external {\n"
        "    router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, 0);\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "MEDIUM"
    assert "deadline 0" in finding.message
    assert "always reverts" in finding.message
    assert "swapExactTokensForTokens(" in finding.line_text


def test_flags_payable_v2_swap_with_cast_zero(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function buy(uint256 minOut, address[] calldata path) external payable {\n"
        "    router.swapExactETHForTokens{value: msg.value}(\n"
        "        minOut, path, msg.sender, uint256(0)\n"
        "    );\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "swapExactETHForTokens" in findings[0].line_text


def test_flags_exact_output_v2_variant(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function exit(uint256 out, uint256 maxIn, address[] calldata path) external {\n"
        "    router.swapTokensForExactETH(out, maxIn, path, msg.sender, (0));\n"
        "}\n"
    )
    assert len(_scan(tmp_path, body)) == 1


def test_flags_v3_inline_params_struct(tmp_path: Path) -> None:
    body = (
        "ISwapRouter public router;\n"
        "function sell(address a, address b, uint256 amountIn, uint256 minOut) external {\n"
        "    router.exactInputSingle(ISwapRouter.ExactInputSingleParams({\n"
        "        tokenIn: a, tokenOut: b, fee: 3000, recipient: msg.sender,\n"
        "        deadline: 0, amountIn: amountIn, amountOutMinimum: minOut,\n"
        "        sqrtPriceLimitX96: 0\n"
        "    }));\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "router.exactInputSingle(" in findings[0].line_text


def test_flags_v3_params_built_before_the_call(tmp_path: Path) -> None:
    body = (
        "ISwapRouter public router;\n"
        "function buy(bytes calldata path, uint256 out, uint256 maxIn) external {\n"
        "    ISwapRouter.ExactOutputParams memory params = ISwapRouter.ExactOutputParams({\n"
        "        path: path, recipient: msg.sender, deadline: 0x0,\n"
        "        amountOut: out, amountInMaximum: maxIn\n"
        "    });\n"
        "    router.exactOutput(params);\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert "ExactOutputParams({" in findings[0].line_text


def test_real_deadlines_stay_quiet(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "ISwapRouter public v3;\n"
        "function sell(\n"
        "    uint256 amountIn, uint256 minOut, address[] calldata path, uint256 deadline\n"
        ") external {\n"
        "    router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, deadline);\n"
        "    router.swapExactTokensForTokens(\n"
        "        amountIn, minOut, path, msg.sender, block.timestamp + 300\n"
        "    );\n"
        "    v3.exactInputSingle(ISwapRouter.ExactInputSingleParams({\n"
        "        tokenIn: path[0], tokenOut: path[1], fee: 3000, recipient: msg.sender,\n"
        "        deadline: deadline, amountIn: amountIn, amountOutMinimum: minOut,\n"
        "        sqrtPriceLimitX96: 0\n"
        "    }));\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_zero_in_other_slots_is_not_a_deadline(tmp_path: Path) -> None:
    # amountOutMin 0 is A034's job; a zero sqrtPriceLimitX96 is normal.
    body = (
        "IUniswapV2Router public router;\n"
        "function sell(uint256 amountIn, address[] calldata path, uint256 deadline) external {\n"
        "    router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, deadline);\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_unrelated_swap_signatures_are_ignored(tmp_path: Path) -> None:
    # A V2 pair's swap(amount0Out, amount1Out, to, data) has no deadline.
    body = (
        "function go(address pair) external {\n"
        "    IPair(pair).swap(0, 100, msg.sender, new bytes(0));\n"
        "    helper.swapTokensForEth(1, 0);\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_comments_and_ignore_directive_are_respected(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function sell(uint256 amountIn, uint256 minOut, address[] calldata path) external {\n"
        "    // router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, 0);\n"
        "    // sibaudit:ignore-next-line\n"
        "    router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, 0);\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_hint_points_at_a_real_deadline() -> None:
    hint = hint_for("A038", "")
    assert "deadline" in hint
    assert "instead of 0" in hint
