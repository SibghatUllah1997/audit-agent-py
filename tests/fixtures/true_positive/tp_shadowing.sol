// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TP_Shadowing {
    address public owner;
    function setOwner(address owner) external { // shadows state var
        // sibaudit:ignore-next-line
        owner = owner;
    }
}
