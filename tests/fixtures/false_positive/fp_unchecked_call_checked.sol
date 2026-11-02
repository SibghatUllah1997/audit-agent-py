// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FP_Unchecked_Call_Checked {
    function ok(address target, bytes calldata data) external {
        // Properly checked
        (bool success, ) = target.call(data);
        require(success, "call failed");
    }
}
