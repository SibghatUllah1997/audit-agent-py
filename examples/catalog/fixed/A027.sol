// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Gate {
    mapping(address => bool) public allowed;

    function enter() external {
        require(allowed[msg.sender], "not allowed");
    }
}
