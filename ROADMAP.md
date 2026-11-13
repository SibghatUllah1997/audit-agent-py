# Roadmap (30 tiny daily steps)

- [x] Day 1: Minimal CLI + 2 rules (tx.origin, unchecked call)
- [x] Day 2: Add rule for `delegatecall` usage with comments
- [x] Day 3: Add rule for `selfdestruct`/`suicide`
- [x] Day 4: Support JSON output format
- [x] Day 5: Add file-level ignores via `// sibaudit:ignore-next-line`
- [x] Day 6: Add severity levels and codes documentation
- [x] Day 7: Add rule for state variable shadowing
- [x] Day 8: Add rule for `block.timestamp` time manipulation checks
- [x] Day 9: Add rule for numeric underflow/overflow patterns (pre-0.8)
- [x] Day 10: Add rule for reentrancy-prone external calls (heuristic)
- [x] Day 11: Add rule for missing access control on sensitive funcs
- [x] Day 12: Add rule for `tx.gasprice` reliance
- [x] Day 13: Add rule for `assert` misuse (business logic)
- [x] Day 14: Add rule for events missing critical parameters
- [x] Day 15: Add rule for `blockhash` misuse
- [x] Day 16: Configurable include/exclude globs
- [x] Day 17: Baseline suppression file
- [x] Day 18: Rich summary report with counts per rule
- [x] Day 19: VS Code task snippet examples
- [x] Day 20: Add `pre-commit` sample config
- [x] Day 21: Add GitHub Action to annotate findings
- [x] Day 22: Add rule for dangerous `tx.origin` comparisons depth
- [x] Day 23: Add rule for uninitialized `address` variables
- [x] Day 24: Add rule for missing zero-address checks
- [x] Day 25: Add rule for magic numbers without constants
- [x] Day 26: Add rule for external calls in constructors
- [x] Day 27: Add rule for payable functions w/o withdraw paths
- [x] Day 28: Add rule for incorrect `onlyOwner` patterns
- [x] Day 29: Add doc examples for each rule with rationale
- [x] Day 30: Optional LLM-assisted suggestions (offline/local first)

# Phase 2

More rules and scanner UX, still one small shippable step per day. Keep the analyzer heuristic and dependency-free unless a step explicitly adds a library.

- [x] Day 31: Add `sibaudit.toml` / `pyproject` config for enabling, disabling, and setting severity of rules
- [x] Day 32: Add `--min-severity` and `--only` / `--except` CLI filters, honored by the existing GitHub Action too
- [x] Day 33: Add a file-level `// sibaudit:ignore-file` directive and honor it in the scanner
- [ ] Day 34: Add rule A021: `ecrecover` without a zero-address / identity check on the recovered signer
- [ ] Day 35: Add rule A022: ether `transfer`/`send` (2300-gas stipend) used instead of `call`
- [ ] Day 36: Add rule A023: floating Solidity pragma (`^` / `>=`) in production sources
- [ ] Day 37: Add rule A024: hash collisions from `abi.encodePacked` of dynamic types
- [ ] Day 38: Add rule A025: upgradeable initializer left public, or `_disableInitializers` missing in the constructor
- [ ] Day 39: Add rule A026: signature-replay risk (signed data missing nonce, deadline, or chain id)
- [ ] Day 40: Add rule A027: `extcodesize == 0` used as an EOA check (breaks under constructor and EIP-7702)
- [ ] Day 41: Discover Foundry and Hardhat layouts (`src/`, `contracts/`) when a directory is scanned with no paths
- [ ] Day 42: Add an HTML summary report and a `--fail-on` exit policy (for example, fail only on high)
- [ ] Day 43: Add a baseline auto-update command that records current findings without hiding new ones later
- [ ] Day 44: Tag v0.2.0 and publish a rule catalog with examples for A021–A027
