// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Voucher {
    address public immutable issuer;
    mapping(address => uint256) public credit;

    constructor(address who) {
        require(who != address(0), "zero");
        issuer = who;
    }

    function redeem(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(msg.sender, amount));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0) && signer == issuer, "bad sig");
        credit[msg.sender] += amount;
    }
}
