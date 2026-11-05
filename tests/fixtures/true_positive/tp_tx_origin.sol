// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TP_TX_Origin {
    address public owner;
    constructor() {
        owner = msg.sender;
    }
    function adminOnly() external view {
        // Risky auth with tx.origin
        require(tx.origin == owner, "not owner");
    }
}
