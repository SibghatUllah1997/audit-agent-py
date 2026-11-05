// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract TP_Pre08_Arith {
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        // Unchecked arithmetic in pre-0.8
        return a + b;
    }
}
