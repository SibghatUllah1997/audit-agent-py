// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

abstract contract Initializable {
    uint64 private _initialized;

    modifier initializer() {
        require(_initialized == 0, "init");
        _initialized = 1;
        _;
    }

    function _disableInitializers() internal {
        _initialized = type(uint64).max;
    }
}

contract Vault is Initializable {
    address public owner;

    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_) public initializer {
        require(owner_ != address(0), "zero");
        owner = owner_;
    }
}
