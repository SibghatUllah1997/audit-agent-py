from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths

ROUTER = (
    "interface IUniswapV2Router {\n"
    "    function getAmountsOut(uint256 amountIn, address[] calldata path)\n"
    "        external view returns (uint256[] memory amounts);\n"
    "    function getAmountsIn(uint256 amountOut, address[] calldata path)\n"
    "        external view returns (uint256[] memory amounts);\n"
    "    function quote(uint256 amountA, uint256 reserveA, uint256 reserveB)\n"
    "        external pure returns (uint256 amountB);\n"
    "    function swapExactTokensForTokens(\n"
    "        uint256 amountIn, uint256 amountOutMin, address[] calldata path,\n"
    "        address to, uint256 deadline\n"
    "    ) external returns (uint256[] memory amounts);\n"
    "    function swapExactETHForTokens(\n"
    "        uint256 amountOutMin, address[] calldata path,\n"
    "        address to, uint256 deadline\n"
    "    ) external payable returns (uint256[] memory amounts);\n"
    "    function swapTokensForExactTokens(\n"
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
    "    struct ExactOutputSingleParams {\n"
    "        address tokenIn; address tokenOut; uint24 fee; address recipient;\n"
    "        uint256 deadline; uint256 amountOut; uint256 amountInMaximum;\n"
    "        uint160 sqrtPriceLimitX96;\n"
    "    }\n"
    "    function exactInputSingle(ExactInputSingleParams calldata params)\n"
    "        external payable returns (uint256 amountOut);\n"
    "    function exactOutputSingle(ExactOutputSingleParams calldata params)\n"
    "        external payable returns (uint256 amountIn);\n"
    "}\n"
    "interface IQuoter {\n"
    "    function quoteExactInputSingle(\n"
    "        address tokenIn, address tokenOut, uint24 fee, uint256 amountIn, uint160 limit\n"
    "    ) external returns (uint256 amountOut);\n"
    "    function quoteExactOutputSingle(\n"
    "        address tokenIn, address tokenOut, uint24 fee, uint256 amountOut, uint160 limit\n"
    "    ) external returns (uint256 amountIn);\n"
    "}\n"
)


def _scan(tmp_path: Path, source: str) -> list:
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A040"]


def _contract(body: str) -> str:
    return f"pragma solidity 0.8.20;\n{ROUTER}contract C {{\n{body}\n}}\n"


def test_flags_inline_get_amounts_out(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function dump(uint256 amountIn, address[] calldata path, uint256 deadline) external {\n"
        "    router.swapExactTokensForTokens(\n"
        "        amountIn, router.getAmountsOut(amountIn, path)[path.length - 1],\n"
        "        path, msg.sender, deadline\n"
        "    );\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "HIGH"
    assert "amountOutMin" in finding.message
    assert "sandwich" in finding.message
    assert "getAmountsOut" in finding.line_text or "swapExactTokensForTokens" in finding.line_text


def test_flags_quoted_min_alias(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function dump(uint256 amountIn, address[] calldata path, uint256 deadline) external {\n"
        "    uint256 minOut = router.getAmountsOut(amountIn, path)[path.length - 1];\n"
        "    router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, deadline);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "minOut" in findings[0].line_text


def test_flags_get_amounts_out_array_index(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function dump(uint256 amountIn, address[] calldata path, uint256 deadline) external {\n"
        "    uint256[] memory amounts = router.getAmountsOut(amountIn, path);\n"
        "    router.swapExactTokensForTokens(\n"
        "        amountIn, amounts[amounts.length - 1], path, msg.sender, deadline\n"
        "    );\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "swapExactTokensForTokens" in findings[0].line_text


def test_flags_library_quote(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function dump(\n"
        "    uint256 amountA, uint256 reserveA, uint256 reserveB,\n"
        "    address[] calldata path, uint256 deadline\n"
        ") external {\n"
        "    uint256 minOut = router.quote(amountA, reserveA, reserveB);\n"
        "    router.swapExactTokensForTokens(amountA, minOut, path, msg.sender, deadline);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "minOut" in findings[0].line_text


def test_flags_exact_eth_for_tokens(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function buy(address[] calldata path, uint256 deadline) external payable {\n"
        "    router.swapExactETHForTokens{value: msg.value}(\n"
        "        router.getAmountsOut(msg.value, path)[path.length - 1],\n"
        "        path, msg.sender, deadline\n"
        "    );\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "swapExactETHForTokens" in findings[0].line_text


def test_flags_get_amounts_in_as_amount_in_max(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function buy(uint256 amountOut, address[] calldata path, uint256 deadline) external {\n"
        "    router.swapTokensForExactTokens(\n"
        "        amountOut, router.getAmountsIn(amountOut, path)[0], path, msg.sender, deadline\n"
        "    );\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "amountInMax" in findings[0].message
    assert (
        "getAmountsIn" in findings[0].line_text
        or "swapTokensForExactTokens" in findings[0].line_text
    )


def test_flags_v3_named_quote_as_amount_out_minimum(tmp_path: Path) -> None:
    body = (
        "ISwapRouter public router;\n"
        "IQuoter public quoter;\n"
        "function dump(address tokenIn, address tokenOut, uint256 amountIn, uint256 deadline)\n"
        "    external\n"
        "{\n"
        "    router.exactInputSingle(\n"
        "        ISwapRouter.ExactInputSingleParams({\n"
        "            tokenIn: tokenIn,\n"
        "            tokenOut: tokenOut,\n"
        "            fee: 3000,\n"
        "            recipient: msg.sender,\n"
        "            deadline: deadline,\n"
        "            amountIn: amountIn,\n"
        "            amountOutMinimum: quoter.quoteExactInputSingle(\n"
        "                tokenIn, tokenOut, 3000, amountIn, 0\n"
        "            ),\n"
        "            sqrtPriceLimitX96: 0\n"
        "        })\n"
        "    );\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "exactInputSingle" in findings[0].line_text
    assert "amountOutMin" in findings[0].message


def test_flags_v3_params_literal_built_before_the_call(tmp_path: Path) -> None:
    body = (
        "ISwapRouter public router;\n"
        "IQuoter public quoter;\n"
        "function dump(address tokenIn, address tokenOut, uint256 amountIn, uint256 deadline)\n"
        "    external\n"
        "{\n"
        "    uint256 quoted = quoter.quoteExactInputSingle(tokenIn, tokenOut, 3000, amountIn, 0);\n"
        "    ISwapRouter.ExactInputSingleParams memory params = "
        "ISwapRouter.ExactInputSingleParams({\n"
        "        tokenIn: tokenIn,\n"
        "        tokenOut: tokenOut,\n"
        "        fee: 3000,\n"
        "        recipient: msg.sender,\n"
        "        deadline: deadline,\n"
        "        amountIn: amountIn,\n"
        "        amountOutMinimum: quoted,\n"
        "        sqrtPriceLimitX96: 0\n"
        "    });\n"
        "    router.exactInputSingle(params);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "ExactInputSingleParams" in findings[0].line_text


def test_flags_v3_quoted_amount_in_maximum(tmp_path: Path) -> None:
    body = (
        "ISwapRouter public router;\n"
        "IQuoter public quoter;\n"
        "function buy(address tokenIn, address tokenOut, uint256 amountOut, uint256 deadline)\n"
        "    external\n"
        "{\n"
        "    router.exactOutputSingle(\n"
        "        ISwapRouter.ExactOutputSingleParams({\n"
        "            tokenIn: tokenIn,\n"
        "            tokenOut: tokenOut,\n"
        "            fee: 3000,\n"
        "            recipient: msg.sender,\n"
        "            deadline: deadline,\n"
        "            amountOut: amountOut,\n"
        "            amountInMaximum: quoter.quoteExactOutputSingle(\n"
        "                tokenIn, tokenOut, 3000, amountOut, 0\n"
        "            ),\n"
        "            sqrtPriceLimitX96: 0\n"
        "        })\n"
        "    );\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "exactOutputSingle" in findings[0].line_text
    assert "amountInMax" in findings[0].message


def test_slippage_adjusted_quote_is_clean(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function dump(uint256 amountIn, address[] calldata path, uint256 deadline) external {\n"
        "    uint256 quoted = router.getAmountsOut(amountIn, path)[path.length - 1];\n"
        "    router.swapExactTokensForTokens(\n"
        "        amountIn, quoted * 99 / 100, path, msg.sender, deadline\n"
        "    );\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_caller_chosen_min_is_clean(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function dump(\n"
        "    uint256 amountIn, uint256 amountOutMin, address[] calldata path, uint256 deadline\n"
        ") external {\n"
        "    router.getAmountsOut(amountIn, path);\n"
        "    router.swapExactTokensForTokens(amountIn, amountOutMin, path, msg.sender, deadline);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_zero_min_is_not_this_rule(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function dump(uint256 amountIn, address[] calldata path, uint256 deadline) external {\n"
        "    router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, deadline);\n"
        "}\n"
    )
    source = _contract(body)
    (tmp_path / "C.sol").write_text(source)
    findings = scan_paths([str(tmp_path)])
    assert not [f for f in findings if f.code == "A040"]
    assert [f for f in findings if f.code == "A034"]


def test_commented_call_and_ignore_directive(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function dump(uint256 amountIn, address[] calldata path, uint256 deadline) external {\n"
        "    // router.swapExactTokensForTokens(\n"
        "    //     amountIn, router.getAmountsOut(amountIn, path)[1], "
        "path, msg.sender, deadline);\n"
        "    // sibaudit:ignore-next-line\n"
        "    router.swapExactTokensForTokens(\n"
        "        amountIn, router.getAmountsOut(amountIn, path)[1], path, msg.sender, deadline\n"
        "    );\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_interface_declaration_is_not_a_call(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "interface IUniswapV2Router {\n"
        "    function getAmountsOut(uint256 amountIn, address[] calldata path)\n"
        "        external view returns (uint256[] memory amounts);\n"
        "    function swapExactTokensForTokens(\n"
        "        uint256 amountIn, uint256 amountOutMin, address[] calldata path,\n"
        "        address to, uint256 deadline\n"
        "    ) external returns (uint256[] memory amounts);\n"
        "}\n"
        "contract C {\n"
        "    function f() external pure returns (uint256) { return 1; }\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)
