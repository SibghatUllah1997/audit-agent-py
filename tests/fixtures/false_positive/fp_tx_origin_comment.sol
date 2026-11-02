// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FP_TX_Origin_Comment {
    function noFinding() external pure returns (uint256) {
        /* tx.origin in comment should not trigger */
        return 1;
    }
}
