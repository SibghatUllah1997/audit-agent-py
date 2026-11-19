// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Permit {
    mapping(address => uint256) public nonces;

    function claim(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(digest, v, r, s);
        nonces[signer] += 1;
    }
}
