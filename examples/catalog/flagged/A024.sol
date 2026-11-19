// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Merkle {
    function leaf(string memory a, string memory b)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(a, b));
    }
}
