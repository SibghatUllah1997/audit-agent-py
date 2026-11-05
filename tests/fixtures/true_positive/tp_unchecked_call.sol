// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TP_Unchecked_Call {
    function run(address target, bytes calldata data) external {
        // Low-level call without checking success
        (bool /*ok*/, ) = target.call(data);
    }
}
