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

    // tx.origin used as an authorization comparison
    function onlyOrigin() external {
        // A001 + A014
        require(tx.origin == owner);
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

    // event missing a critical amount parameter
    event Transfer(address from, address to);

    function logMove(address from, address to) external {
        // A012
        emit Transfer(from, to);
    }

    // blockhash of the current block is always zero
    function raffle() external view returns (uint256) {
        // A013
        return uint256(blockhash(block.number));
    }

    // address parameter stored without an address(0) guard
    address public treasury;

    function setTreasury(address newTreasury) external {
        // A016
        treasury = newTreasury;
    }

    // fee math uses unnamed numeric literals
    function feeOn(uint256 amount) external pure returns (uint256) {
        // A017
        return amount * 25 / 10000;
    }

    // constructor hands control to an outside contract before setup is done
    constructor(address registry) {
        // A018
        (bool ok, ) = registry.call(abi.encodeWithSignature("register()"));
        require(ok, "register failed");
    }
}

// Ether can enter, but nothing in this contract can send it out.
contract LockedVault {
    mapping(address => uint256) public gifts;

    receive() external payable {}

    function donate() external payable {
        // A019
        gifts[msg.sender] += msg.value;
    }
}

// onlyOwner looks like access control but never checks the caller.
contract FakeOwnable {
    uint256 public n;

    modifier onlyOwner() {
        // A020
        _;
    }

    function bump() external onlyOwner {
        n = 1;
    }
}

// ecrecover result is trusted without rejecting address(0) or matching a signer.
contract OpenPermit {
    mapping(address => uint256) public nonces;

    function claim(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
        // A021
        address signer = ecrecover(digest, v, r, s);
        nonces[signer] += 1;
    }
}

// 2300-gas stipend sends fail when the recipient does more than log an event.
contract StipendPay {
    function payout(address payable to) external {
        // A022
        to.transfer(address(this).balance);
    }
}

// Packed dynamic values can be split more than one way and still hash the same.
contract PackedLeaf {
    function leaf(string memory a, string memory b) external pure returns (bytes32) {
        // A024
        return keccak256(abi.encodePacked(a, b));
    }
}

// Proxy implementation leaves initialize public and never disables initializers.
abstract contract Initializable {
    function _disableInitializers() internal {}
}

contract OpenVault is Initializable {
    address public admin;

    function initialize(address admin_) public {
        // A025
        admin = admin_;
    }
}

// Signed voucher with no nonce, deadline or chain id can be redeemed again and again.
contract ReplayVoucher {
    address public immutable issuer;
    mapping(address => uint256) public credit;

    constructor(address who) {
        require(who != address(0), "zero");
        issuer = who;
    }

    function redeem(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(msg.sender, amount));
        // A026
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0) && signer == issuer, "bad sig");
        credit[msg.sender] += amount;
    }
}

// code.length == 0 does not prove the caller is an EOA (constructors, EIP-7702).
contract EoaGate {
    function enter() external {
        // A027
        require(msg.sender.code.length == 0, "no contracts");
    }
}

// Some tokens return false instead of reverting, so a dropped result hides failures.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract TokenPayout {
    IERC20 public token;

    function pay(address to, uint256 amount) external {
        // A028
        token.transfer(to, amount);
    }
}

// An unlimited allowance lets a compromised spender drain current and future tokens.
contract TokenSpender {
    IERC20 public token;

    function allow(address spender) external {
        // A030
        require(token.approve(spender, type(uint256).max), "approve failed");
    }
}

// Looping a storage array in one transaction can run out of gas as the list grows.
contract Airdrop {
    address[] public recipients;
    mapping(address => uint256) public credit;

    function add(address who) external {
        require(who != address(0), "zero");
        recipients.push(who);
    }

    function payout() external {
        // A029
        for (uint256 i = 0; i < recipients.length; i++) {
            credit[recipients[i]] += 1;
        }
    }
}

// The proposer sees prevrandao before publishing and can re-roll it by skipping a slot.
contract Lottery {
    address[] public players;

    function pick() external view returns (address) {
        // A031
        return players[block.prevrandao % players.length];
    }
}

// A frozen or zero Chainlink round can price assets wrong if the answer is trusted as-is.
interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

contract OraclePrice {
    AggregatorV3Interface public feed;

    function read() external view returns (int256) {
        // A032
        (, int256 answer, , , ) = feed.latestRoundData();
        return answer;
    }
}

// latestAnswer is a single int256 with no round metadata; a zero figure still prices assets.
interface AggregatorV2Interface {
    function latestAnswer() external view returns (int256);
}

contract SpotPrice {
    AggregatorV2Interface public feed;

    function read() external view returns (int256) {
        // A033
        return feed.latestAnswer();
    }
}

// amountOutMin of 0 lets a sandwich take the whole trade.
interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

contract Dump {
    IUniswapV2Router public router;

    function dump(uint256 amountIn, address[] calldata path, uint256 deadline) external {
        // A034
        router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, deadline);
    }
}

// A zero deadline is already expired, so this permit always reverts.
interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

contract PermitPull {
    IERC20Permit public token;

    function pull(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        // A035
        token.permit(msg.sender, address(this), amount, 0, v, r, s);
    }
}
