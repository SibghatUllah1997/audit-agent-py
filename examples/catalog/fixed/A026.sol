// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Voucher {
    address public immutable issuer;
    mapping(address => uint256) public credit;
    mapping(address => uint256) public nonces;

    constructor(address who) {
        require(who != address(0), "zero");
        issuer = who;
    }

    function redeem(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // sibaudit:ignore-next-line
        require(block.timestamp <= deadline, "expired");
        uint256 nonce = nonces[msg.sender]++;
        bytes32 digest = keccak256(
            abi.encode(
                block.chainid, address(this), msg.sender, amount, nonce, deadline
            )
        );
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0) && signer == issuer, "bad sig");
        credit[msg.sender] += amount;
    }
}
