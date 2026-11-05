// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FP_Timestamp_Comment {
    function ok() external pure returns (uint256) {
        /* block.timestamp mention in comment only */
        return 0;
    }
}
