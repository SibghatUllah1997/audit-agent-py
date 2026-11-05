// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TP_Timestamp {
    function when() external view returns (uint256) {
        return block.timestamp;
    }
}
