// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Gate {
    function enter() external {
        require(msg.sender.code.length == 0, "no contracts");
    }
}
