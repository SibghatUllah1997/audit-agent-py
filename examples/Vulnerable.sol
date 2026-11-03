// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract Vulnerable {
    address public owner;
    mapping(address => uint256) public balances;

    // Unchecked low-level call and origin usage
    function ping(address target) external {
        // A002: unchecked low-level call
        // A001: origin risky usage
        target.call(abi.encodeWithSignature("pong()"));
        address a = tx.origin;
        a; // silence warning
    }

    // delegatecall without checks
    function run(address target, bytes calldata data) external {
        // A002 + A003
        target.delegatecall(data);
    }

    // selfdestruct
    function nuke(address payable to) external {
        // A004
        selfdestruct(to);
    }

    // timestamp usage
    function when() external view returns (uint256) {
        // A006
        return block.timestamp;
    }

    // state var shadowing by parameter
    function setOwner(address owner) external {
        // A005
        owner;
    }

    // arithmetic pre-0.8 (unchecked)
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        // A007
        uint256 c = a + b;
        return c;
    }

    // reentrancy: external call then storage write
    function withdraw() external {
        // A008
        payable(msg.sender).call{value: balances[msg.sender]}("");
        balances[msg.sender] = 0;
    }

    // missing access control on a privileged mint
    function mint(address recipient, uint256 qty) external {
        // A009
        balances[recipient] += qty;
    }
}

