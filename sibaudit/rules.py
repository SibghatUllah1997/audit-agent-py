"""Catalog of rule codes with a rationale and a flagged/fixed example for each.

The catalog backs ``sibaudit --explain`` and ``sibaudit --list-rules`` and is the
single source for ``docs/RULES.md``. Tests scan every example with the real
scanner, so an example that drifts away from what its rule detects fails CI.
"""

from __future__ import annotations

from dataclasses import dataclass
from textwrap import dedent

HEADER = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n\n"
LEGACY_HEADER = "// SPDX-License-Identifier: MIT\npragma solidity ^0.7.6;\n\n"


@dataclass(frozen=True)
class Rule:
    code: str
    severity: str
    title: str
    rationale: str
    flagged: str
    fixed: str


def _sol(body: str, header: str = HEADER) -> str:
    return header + dedent(body).strip() + "\n"


RULES: tuple[Rule, ...] = (
    Rule(
        code="A001",
        severity="MEDIUM",
        title="Risky use of `tx.origin`",
        rationale=(
            "`tx.origin` is the wallet that started the transaction, not the contract or "
            "account calling you. Any logic built on it trusts every contract in the call "
            "chain and breaks for smart-contract wallets."
        ),
        flagged=_sol(
            """
            contract Logger {
                event Seen(address who);

                function touch() external {
                    emit Seen(tx.origin);
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Logger {
                event Seen(address who);

                function touch() external {
                    emit Seen(msg.sender);
                }
            }
            """
        ),
    ),
    Rule(
        code="A002",
        severity="MEDIUM",
        title="Low-level call without checking success",
        rationale=(
            "`.call` returns `false` instead of reverting when the callee fails. If the "
            "result is dropped, the contract carries on as if the call worked."
        ),
        flagged=_sol(
            """
            contract Pinger {
                function ping(address target) external {
                    target.call(abi.encodeWithSignature("pong()"));
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Pinger {
                function ping(address target) external {
                    (bool ok, ) = target.call(abi.encodeWithSignature("pong()"));
                    require(ok, "ping failed");
                }
            }
            """
        ),
    ),
    Rule(
        code="A003",
        severity="HIGH",
        title="Any `delegatecall` usage",
        rationale=(
            "`delegatecall` runs foreign code against this contract's storage and balance. "
            "One wrong target or storage layout mismatch hands the contract to the callee. "
            "Every use needs a fixed, trusted target and a review."
        ),
        flagged=_sol(
            """
            contract Runner {
                function run(address target, bytes calldata data) external {
                    (bool ok, ) = target.delegatecall(data);
                    require(ok, "failed");
                }
            }
            """
        ),
        fixed=_sol(
            """
            interface IWorker {
                function work(bytes calldata data) external;
            }

            contract Runner {
                IWorker public immutable worker;

                constructor(IWorker w) {
                    worker = w;
                }
            }
            """
        ),
    ),
    Rule(
        code="A004",
        severity="HIGH",
        title="`selfdestruct` / `suicide`",
        rationale=(
            "`selfdestruct` is deprecated and its behaviour changed in recent forks. "
            "Contracts that rely on it can be bricked or leave integrations pointing at "
            "an address with different semantics. Prefer a pause flag."
        ),
        flagged=_sol(
            """
            contract Killable {
                address public immutable owner = msg.sender;

                function kill() external {
                    require(msg.sender == owner, "owner");
                    selfdestruct(payable(owner));
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Pausable {
                address public immutable owner = msg.sender;
                bool public paused;

                function pause() external {
                    require(msg.sender == owner, "owner");
                    paused = true;
                }
            }
            """
        ),
    ),
    Rule(
        code="A005",
        severity="LOW",
        title="Function parameter shadows a state variable",
        rationale=(
            "A parameter with the same name as a state variable hides it inside the "
            "function. Code that means to write storage silently writes the local instead."
        ),
        flagged=_sol(
            """
            contract Config {
                uint256 public limit;

                function check(uint256 limit) external pure returns (bool) {
                    return limit > 0;
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Config {
                uint256 public limit;

                function check(uint256 newLimit) external pure returns (bool) {
                    return newLimit > 0;
                }
            }
            """
        ),
    ),
    Rule(
        code="A006",
        severity="MEDIUM",
        title="`block.timestamp` / `now` usage",
        rationale=(
            "Block producers can nudge the timestamp by a few seconds. That is fine for "
            "day-scale deadlines but not for randomness or tight windows, so every use "
            "deserves a look."
        ),
        flagged=_sol(
            """
            contract Lottery {
                function pick(uint256 n) external view returns (uint256) {
                    return block.timestamp % n;
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Lottery {
                function pick(uint256 seed, uint256 n) external pure returns (uint256) {
                    return uint256(keccak256(abi.encode(seed))) % n;
                }
            }
            """
        ),
    ),
    Rule(
        code="A007",
        severity="MEDIUM",
        title="Unchecked arithmetic in pre-0.8 Solidity",
        rationale=(
            "Before 0.8 integer math wraps silently on overflow and underflow. Use "
            "SafeMath or upgrade the compiler so overflows revert."
        ),
        flagged=_sol(
            """
            contract Adder {
                function add(uint256 a, uint256 b) external pure returns (uint256) {
                    uint256 c = a + b;
                    return c;
                }
            }
            """,
            LEGACY_HEADER,
        ),
        fixed=_sol(
            """
            contract Adder {
                function add(uint256 a, uint256 b) external pure returns (uint256) {
                    uint256 c = a + b;
                    return c;
                }
            }
            """
        ),
    ),
    Rule(
        code="A008",
        severity="HIGH",
        title="External call before a later state update (reentrancy heuristic)",
        rationale=(
            "If storage is updated after an external call, the callee can re-enter "
            "while the old state is still visible, for example to withdraw twice. "
            "Update state first (checks-effects-interactions)."
        ),
        flagged=_sol(
            """
            contract Bank {
                mapping(address => uint256) public balances;

                function withdraw() external {
                    uint256 amount = balances[msg.sender];
                    (bool ok, ) = payable(msg.sender).call{value: amount}("");
                    require(ok, "send failed");
                    balances[msg.sender] = 0;
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Bank {
                mapping(address => uint256) public balances;

                function withdraw() external {
                    uint256 amount = balances[msg.sender];
                    balances[msg.sender] = 0;
                    (bool ok, ) = payable(msg.sender).call{value: amount}("");
                    require(ok, "send failed");
                }
            }
            """
        ),
    ),
    Rule(
        code="A009",
        severity="HIGH",
        title="Sensitive function that appears to lack access control",
        rationale=(
            "Functions such as `mint`, `setOwner` or `withdrawAll` change who owns what. "
            "Without a modifier or `msg.sender` check anyone can call them."
        ),
        flagged=_sol(
            """
            contract Token {
                mapping(address => uint256) public balances;

                function mint(address to, uint256 amount) external {
                    balances[to] += amount;
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Token {
                address public immutable owner = msg.sender;
                mapping(address => uint256) public balances;

                function mint(address to, uint256 amount) external {
                    require(msg.sender == owner, "owner");
                    balances[to] += amount;
                }
            }
            """
        ),
    ),
    Rule(
        code="A010",
        severity="LOW",
        title="Logic that relies on `tx.gasprice`",
        rationale=(
            "The sender picks the gas price, and on chains with EIP-1559 it says little "
            "about the user. Rules keyed on it are easy to game."
        ),
        flagged=_sol(
            """
            contract Fees {
                function discounted() external view returns (bool) {
                    return tx.gasprice > 100 gwei;
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Fees {
                mapping(address => bool) public members;

                function discounted() external view returns (bool) {
                    return members[msg.sender];
                }
            }
            """
        ),
    ),
    Rule(
        code="A011",
        severity="LOW",
        title="`assert` used on caller input or balances",
        rationale=(
            "`assert` is for invariants that should never fail. Bad input is expected, so "
            "check it with `require` and a reason string."
        ),
        flagged=_sol(
            """
            contract Vault {
                function canPay(uint256 amount) external view returns (bool) {
                    assert(address(this).balance >= amount);
                    return true;
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Vault {
                function canPay(uint256 amount) external view returns (bool) {
                    require(address(this).balance >= amount, "low balance");
                    return true;
                }
            }
            """
        ),
    ),
    Rule(
        code="A012",
        severity="LOW",
        title="Event missing a critical amount or address parameter",
        rationale=(
            "Indexers and monitors reconstruct state from events. A `Transfer` without "
            "an amount, or an ownership change without the new owner, is useless to them."
        ),
        flagged=_sol(
            """
            contract Token {
                event Transfer(address from, address to);
            }
            """
        ),
        fixed=_sol(
            """
            contract Token {
                event Transfer(address indexed from, address indexed to, uint256 value);
            }
            """
        ),
    ),
    Rule(
        code="A013",
        severity="MEDIUM",
        title="`blockhash` used as randomness or on the current block",
        rationale=(
            "`blockhash(block.number)` is always zero, and older hashes are known to block "
            "producers. Neither is a safe source of randomness; use a VRF or commit-reveal."
        ),
        flagged=_sol(
            """
            contract Raffle {
                function draw() external view returns (uint256) {
                    return uint256(blockhash(block.number));
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Raffle {
                uint256 public lastRandom;

                function onRandom(uint256 value) external {
                    lastRandom = value;
                }
            }
            """
        ),
    ),
    Rule(
        code="A014",
        severity="HIGH",
        title="`tx.origin` used in an authorization comparison",
        rationale=(
            "Checking `tx.origin == owner` lets any contract the owner interacts with act "
            "as the owner, which is the classic phishing pattern. Compare `msg.sender`."
        ),
        flagged=_sol(
            """
            contract Wallet {
                address public immutable owner = msg.sender;
                uint256 public limit;

                function setLimit(uint256 value) external {
                    require(tx.origin == owner, "owner");
                    limit = value;
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Wallet {
                address public immutable owner = msg.sender;
                uint256 public limit;

                function setLimit(uint256 value) external {
                    require(msg.sender == owner, "owner");
                    limit = value;
                }
            }
            """
        ),
    ),
    Rule(
        code="A015",
        severity="MEDIUM",
        title="`address` variable declared without a value and never assigned",
        rationale=(
            "An address that is never set stays `address(0)`. Ether or tokens sent there "
            "are burned, and checks against it pass for nobody or for everybody."
        ),
        flagged=_sol(
            """
            contract Fees {
                address public collector;

                function target() external view returns (address) {
                    return collector;
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Fees {
                address public immutable collector;

                constructor(address c) {
                    require(c != address(0), "zero");
                    collector = c;
                }
            }
            """
        ),
    ),
    Rule(
        code="A016",
        severity="MEDIUM",
        title="Address parameter stored without a zero-address check",
        rationale=(
            "Storing `address(0)` by mistake, often from a default value in a script, "
            "can lock admin roles or burn funds. Reject it before writing storage."
        ),
        flagged=_sol(
            """
            contract Treasury {
                address public treasury;

                function configure(address newTreasury) external {
                    treasury = newTreasury;
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Treasury {
                address public treasury;

                function configure(address newTreasury) external {
                    require(newTreasury != address(0), "zero");
                    treasury = newTreasury;
                }
            }
            """
        ),
    ),
    Rule(
        code="A017",
        severity="LOW",
        title="Numeric literal that is not a named constant",
        rationale=(
            "A bare `25` or `10000` hides intent and is easy to change in one place but "
            "not another. A named `constant` documents the unit and keeps values in sync."
        ),
        flagged=_sol(
            """
            contract Fees {
                function feeOn(uint256 amount) external pure returns (uint256) {
                    return amount * 25 / 10000;
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Fees {
                uint256 public constant FEE_BPS = 25;
                uint256 public constant BPS_DENOMINATOR = 10000;

                function feeOn(uint256 amount) external pure returns (uint256) {
                    return amount * FEE_BPS / BPS_DENOMINATOR;
                }
            }
            """
        ),
    ),
    Rule(
        code="A018",
        severity="MEDIUM",
        title="External call made inside a constructor",
        rationale=(
            "During construction the contract has no code yet and its state is half "
            "set. Calling out hands control to code that may call back into that state. "
            "Move the call to a separate setup step."
        ),
        flagged=_sol(
            """
            interface IRegistry {
                function register() external;
            }

            contract Module {
                constructor(IRegistry registry) {
                    registry.register();
                }
            }
            """
        ),
        fixed=_sol(
            """
            interface IRegistry {
                function register() external;
            }

            contract Module {
                IRegistry public immutable registry;

                constructor(IRegistry r) {
                    registry = r;
                }
            }
            """
        ),
    ),
    Rule(
        code="A019",
        severity="MEDIUM",
        title="Payable function that can receive ether with no withdraw path",
        rationale=(
            "If a contract accepts ether but has no `transfer`, `send` or value call, the "
            "ether is locked forever. Add a withdraw function or drop `payable`."
        ),
        flagged=_sol(
            """
            contract Jar {
                mapping(address => uint256) public gifts;

                function donate() external payable {
                    gifts[msg.sender] += msg.value;
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Jar {
                address public immutable owner = msg.sender;
                mapping(address => uint256) public gifts;

                function donate() external payable {
                    gifts[msg.sender] += msg.value;
                }

                function withdraw() external {
                    require(msg.sender == owner, "owner");
                    payable(owner).transfer(address(this).balance);
                }
            }
            """
        ),
    ),
    Rule(
        code="A020",
        severity="HIGH",
        title="`onlyOwner`-style modifier that does not actually check the caller",
        rationale=(
            "A modifier named `onlyOwner` that never compares `msg.sender`, checks it "
            "after `_;`, or uses `tx.origin` gives the look of access control without "
            "the effect."
        ),
        flagged=_sol(
            """
            contract Box {
                address public immutable owner = msg.sender;

                modifier onlyOwner() {
                    _;
                }
            }
            """
        ),
        fixed=_sol(
            """
            contract Box {
                address public immutable owner = msg.sender;

                modifier onlyOwner() {
                    require(msg.sender == owner, "owner");
                    _;
                }
            }
            """
        ),
    ),
)

_BY_CODE = {rule.code: rule for rule in RULES}


def get_rule(code: str) -> Rule | None:
    """Return the rule for ``code`` (case-insensitive), or ``None`` if unknown."""
    return _BY_CODE.get(code.strip().upper())


def known_codes() -> frozenset[str]:
    """Every rule code in the catalog."""
    return frozenset(_BY_CODE)


def format_rule_list() -> str:
    """One line per rule: code, severity, title."""
    return "\n".join(f"{r.code}  {r.severity:<6}  {r.title}" for r in RULES)


def format_explain(rule: Rule) -> str:
    """Plain-text explanation for ``sibaudit --explain``."""
    parts = [
        f"{rule.code} ({rule.severity}): {rule.title}",
        "",
        rule.rationale,
        "",
        "Flagged:",
        _indent(rule.flagged),
        "",
        "Fixed:",
        _indent(rule.fixed),
    ]
    return "\n".join(parts)


def render_markdown() -> str:
    """Render the full catalog as Markdown (the content of docs/RULES.md)."""
    out = [
        "# Rule reference",
        "",
        "<!-- Generated by `python -m sibaudit.rules > docs/RULES.md`; do not edit by hand. -->",
        "",
        "Each rule lists why it matters, a snippet sibaudit flags, and a fixed version "
        "it accepts. The same text is available offline with `sibaudit --explain CODE`.",
        "",
    ]
    for rule in RULES:
        out += [
            f"## {rule.code}: {rule.title}",
            "",
            f"Severity: **{rule.severity}**",
            "",
            rule.rationale,
            "",
            "Flagged:",
            "",
            "```solidity",
            rule.flagged.rstrip(),
            "```",
            "",
            "Fixed:",
            "",
            "```solidity",
            rule.fixed.rstrip(),
            "```",
            "",
        ]
    return "\n".join(out)


def _indent(text: str) -> str:
    return "\n".join(f"    {line}" if line else "" for line in text.rstrip().splitlines())


if __name__ == "__main__":
    print(render_markdown(), end="")
