// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TP_Selfdestruct {
    function bye(address payable to) external {
        selfdestruct(to);
    }
}
