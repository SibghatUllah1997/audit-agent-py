from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths

ROUTER = (
    "interface IUniswapV2Router {\n"
    "    function swapExactTokensForTokens(\n"
    "        uint256 amountIn, uint256 amountOutMin, address[] calldata path,\n"
    "        address to, uint256 deadline\n"
    "    ) external returns (uint256[] memory amounts);\n"
    "    function swapExactETHForTokens(\n"
    "        uint256 amountOutMin, address[] calldata path,\n"
    "        address to, uint256 deadline\n"
    "    ) external payable returns (uint256[] memory amounts);\n"
    "    function swapExactTokensForETH(\n"
    "        uint256 amountIn, uint256 amountOutMin, address[] calldata path,\n"
    "        address to, uint256 deadline\n"
    "    ) external returns (uint256[] memory amounts);\n"
    "    function swapExactTokensForTokensSupportingFeeOnTransferTokens(\n"
    "        uint256 amountIn, uint256 amountOutMin, address[] calldata path,\n"
    "        address to, uint256 deadline\n"
    "    ) external;\n"
    "}\n"
    "interface ISwapRouter {\n"
    "    struct ExactInputSingleParams {\n"
    "        address tokenIn; address tokenOut; uint24 fee; address recipient;\n"
    "        uint256 deadline; uint256 amountIn; uint256 amountOutMinimum;\n"
    "        uint160 sqrtPriceLimitX96;\n"
    "    }\n"
    "    function exactInputSingle(ExactInputSingleParams calldata params)\n"
    "        external payable returns (uint256 amountOut);\n"
    "}\n"
)


def _scan(tmp_path: Path, source: str) -> list:
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A034"]


def _contract(body: str) -> str:
    return f"pragma solidity 0.8.20;\n{ROUTER}contract C {{\n{body}\n}}\n"


def test_flags_swap_exact_tokens_for_tokens_zero_min(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function dump(uint256 amountIn, address[] calldata path, uint256 deadline) external {\n"
        "    router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, deadline);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "HIGH"
    assert "amountOutMin 0" in finding.message
    assert "sandwich" in finding.message
    assert "swapExactTokensForTokens(amountIn, 0," in finding.line_text


def test_flags_swap_exact_eth_for_tokens(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function buy(address[] calldata path, uint256 deadline) external payable {\n"
        "    router.swapExactETHForTokens{value: msg.value}(0, path, msg.sender, deadline);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "swapExactETHForTokens" in findings[0].line_text


def test_flags_swap_exact_tokens_for_eth_uint_cast(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function sell(uint256 amountIn, address[] calldata path, uint256 deadline) external {\n"
        "    router.swapExactTokensForETH(amountIn, uint256(0), path, msg.sender, deadline);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "uint256(0)" in findings[0].line_text


def test_flags_fee_on_transfer_variant(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function dump(uint256 amountIn, address[] calldata path, uint256 deadline) external {\n"
        "    router.swapExactTokensForTokensSupportingFeeOnTransferTokens(\n"
        "        amountIn, 0, path, msg.sender, deadline\n"
        "    );\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "SupportingFeeOnTransferTokens" in findings[0].line_text


def test_flags_v3_named_amount_out_minimum(tmp_path: Path) -> None:
    body = (
        "ISwapRouter public router;\n"
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
        "            amountOutMinimum: 0,\n"
        "            sqrtPriceLimitX96: 0\n"
        "        })\n"
        "    );\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "exactInputSingle" in findings[0].line_text
    assert "sandwich" in findings[0].message


def test_nonzero_min_is_clean(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function dump(\n"
        "    uint256 amountIn, uint256 amountOutMin, address[] calldata path, uint256 deadline\n"
        ") external {\n"
        "    router.swapExactTokensForTokens(amountIn, amountOutMin, path, msg.sender, deadline);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_v3_nonzero_named_field_is_clean(tmp_path: Path) -> None:
    body = (
        "ISwapRouter public router;\n"
        "function dump(\n"
        "    address tokenIn, address tokenOut, uint256 amountIn,\n"
        "    uint256 minOut, uint256 deadline\n"
        ") external {\n"
        "    router.exactInputSingle(\n"
        "        ISwapRouter.ExactInputSingleParams({\n"
        "            tokenIn: tokenIn,\n"
        "            tokenOut: tokenOut,\n"
        "            fee: 3000,\n"
        "            recipient: msg.sender,\n"
        "            deadline: deadline,\n"
        "            amountIn: amountIn,\n"
        "            amountOutMinimum: minOut,\n"
        "            sqrtPriceLimitX96: 0\n"
        "        })\n"
        "    );\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_sqrt_price_limit_zero_is_not_this_rule(tmp_path: Path) -> None:
    body = (
        "ISwapRouter public router;\n"
        "function dump(\n"
        "    address tokenIn, address tokenOut, uint256 amountIn,\n"
        "    uint256 minOut, uint256 deadline\n"
        ") external {\n"
        "    router.exactInputSingle(\n"
        "        ISwapRouter.ExactInputSingleParams({\n"
        "            tokenIn: tokenIn,\n"
        "            tokenOut: tokenOut,\n"
        "            fee: 3000,\n"
        "            recipient: msg.sender,\n"
        "            deadline: deadline,\n"
        "            amountIn: amountIn,\n"
        "            amountOutMinimum: minOut,\n"
        "            sqrtPriceLimitX96: 0\n"
        "        })\n"
        "    );\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_commented_call_and_ignore_directive(tmp_path: Path) -> None:
    body = (
        "IUniswapV2Router public router;\n"
        "function dump(uint256 amountIn, address[] calldata path, uint256 deadline) external {\n"
        "    // router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, deadline);\n"
        "    // sibaudit:ignore-next-line\n"
        "    router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, deadline);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_interface_declaration_is_not_a_call(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "interface IUniswapV2Router {\n"
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
