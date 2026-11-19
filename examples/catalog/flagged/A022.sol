// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Wallet {
    function pay(address payable to, uint256 amount) external {
        to.transfer(amount);
    }
}
