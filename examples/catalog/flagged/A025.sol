// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

abstract contract Initializable {
    function _disableInitializers() internal {}
}

contract Vault is Initializable {
    address public owner;

    function initialize(address owner_) public {
        owner = owner_;
    }
}
