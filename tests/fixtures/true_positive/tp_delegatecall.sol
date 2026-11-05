// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TP_Delegatecall {
    function bad(address target, bytes calldata data) external {
        // Delegatecall detected
        (bool ok, ) = target.delegatecall(data);
        require(ok, "fail");
    }
}
