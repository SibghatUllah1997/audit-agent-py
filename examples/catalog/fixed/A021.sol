// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Permit {
    address public immutable issuer;

    constructor(address who) {
        require(who != address(0), "zero");
        issuer = who;
    }

    function claim(bytes32 digest, uint8 v, bytes32 r, bytes32 s)
        external
        view
        returns (bool)
    {
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad sig");
        return signer == issuer;
    }
}
