# Changelog

## 2026-11-21
- Added rule A030 to flag ERC-20 `approve` of `type(uint256).max` (and the usual aliases such as `~uint256(0)`), which grants an unlimited allowance a compromised spender can drain.
- Added `--output FILE` (and `SIBAUDIT_OUTPUT`) so the chosen `--format` is written to a file instead of stdout, which is handy as a CI artifact without a shell redirect.
- Marked days 50 and 51 complete on the roadmap.

## 2026-11-21
- Added `--format markdown`: a total, counts per rule, and one findings table per severity, ready for a PR comment or `$GITHUB_STEP_SUMMARY`.
- Source text is escaped so it cannot break a table, and rows stop at 200 to stay under GitHub's comment limit while counts stay exact.
- Added `examples/github/job-summary.yml` and marked day 49 complete on the roadmap.

## 2026-11-20
- Added rule A029 to flag a `for`/`while` that walks a storage array's `.length` in a state-changing function, which can run out of gas as the list grows. A batch cap or cursor is enough to stay quiet.
- Added `--changed-since REF` (and `SIBAUDIT_CHANGED_SINCE`) so a scan only looks at Solidity files git reports as changed against that ref, including untracked files.
- Marked days 47 and 48 complete on the roadmap.

## 2026-11-20 (day 46)
- Added rule A028 to flag ERC-20 `transfer`, `transferFrom`, and `approve` calls used as bare statements, so a token that returns `false` instead of reverting cannot fail silently.
- Only receivers typed as an ERC-20 (`IERC20`, `ERC20`, `IERC20Metadata`, ...) or cast with `IERC20(addr)` count, which keeps ether `transfer` (A022) and ERC-721 `transferFrom` out of it.
- Planned phase 3 on the roadmap (days 46-49) and marked day 46 complete.

## 2026-11-19 (day 45)
- Added `--format sarif`, a SARIF 2.1.0 log with one rule entry per reported code, `error`/`warning`/`note` levels, and a `security-severity` score for GitHub code scanning.
- Each result carries a fingerprint from path, rule, and normalized source line, so alerts survive line moves; repeated identical lines get distinct ids.
- Added `examples/github/code-scanning.yml` to upload the log with `upload-sarif`. Marked day 45 complete on the roadmap.

## 2026-11-19
- Added `--update-baseline FILE` to refresh a known-issue snapshot: findings that moved stay suppressed, fixed ones are dropped, and new findings are not recorded so they still show up.
- Snapshots now store the source line text so an update can follow a finding after edits; older files without `text` still load.
- Published a v0.2.0 catalog of rules A021–A027 (markdown, JSON, and flagged/fixed Solidity examples) and marked days 43 and 44 complete on the roadmap.

## 2026-11-18
- Added rule A027 to flag `extcodesize == 0` and `.code.length == 0` used as an EOA check, which breaks for constructors and EIP-7702 accounts.
- When a Foundry or Hardhat directory is scanned, sibaudit now looks in `src/` and `contracts/` instead of walking lib, test, and node_modules.
- Marked days 40 and 41 complete on the roadmap.
- Added `--fail-on LEVEL` (or `never`) so the exit code can fail only on findings at or above a severity; `SIBAUDIT_FAIL_ON` works the same and the sample GitHub Action forwards it.
- Added `--html-report FILE`, a self-contained HTML page with counts by severity and rule and every finding, highest severity first.
- Marked day 42 complete on the roadmap.

## 2026-11-17
- Added rule A024 to flag `abi.encodePacked` of two or more dynamic values (`string`, `bytes`, arrays), which can hash-collide; prefer `abi.encode`.
- Added rule A025 to flag a public upgradeable `initialize` without an initializer lock, and implementations that skip `_disableInitializers()` in the constructor.
- Marked days 37 and 38 complete on the roadmap.
- Added rule A026 to flag a signature check whose signed digest (built in the function or a same-contract caller) has no nonce, deadline, or chain id; EIP-712 typed data counts as chain-bound, and digests passed in already hashed are skipped.
- Marked day 39 complete on the roadmap.

## 2026-11-16
- Added rule A021 to flag `ecrecover` when the recovered signer is never checked against `address(0)` or a known identity.
- Added rule A022 to flag ether `transfer` and `send`, which forward only 2300 gas; prefer `call{value: ...}` and check success.
- Marked days 34 and 35 complete on the roadmap.
- Added rule A023 to flag a floating `pragma solidity` (`^`, `~`, `>=`, ranges, wildcards) in deployable sources; tests (`.t.sol`), scripts (`.s.sol`), mocks and interface-only files are skipped.
- Catalog examples and clean test fixtures now pin `0.8.20`. Marked day 36 complete on the roadmap.

## 2026-11-13
- Added `sibaudit.toml` and `[tool.sibaudit]` config so rules can be turned off or given a new severity.
- Added `--min-severity`, `--only`, and `--except`; the sample GitHub Action forwards the same filters through `SIBAUDIT_*` variables.
- Marked days 31 and 32 complete on the roadmap.
- Added a file-level `// sibaudit:ignore-file` directive; on its own it skips the file, and with rule codes (`// sibaudit:ignore-file A017`) it drops only those rules. It must sit in the file header.
- Marked day 33 complete on the roadmap.

## 2026-11-12
- Added `--suggest` so each finding can carry a local fix hint from a built-in catalog that never talks to the network.
- Hints can be overridden with `--suggest-catalog` or a local `--suggest-cmd`; the catalog is used if the command fails.
- Added an opt-in `--suggest-backend local-llm` that asks a model on this machine (Ollama-compatible API) for a tailored hint; only loopback URLs are allowed and any failure falls back to the catalog hint.
- Marked days 1 and 30 complete on the roadmap.

## 2026-11-11
- Added a rule catalog with a rationale, a flagged snippet, and a fixed snippet for every code, exposed as `sibaudit --explain CODE` and `sibaudit --list-rules`.
- Added `docs/RULES.md`, generated from the catalog; tests scan every snippet so flagged examples must trigger their rule and fixed ones must come back clean.
- Fixed A005 false positives: statements inside functions are no longer read as state variables, and `returns (...)` lists are no longer read as inputs.
- Refreshed the README sample output and marked day 29 on the roadmap.
- Added rule A019 to flag payable functions, `receive`/`fallback`, and payable constructors that take ether when the contract has no way to send it out.
- Added rule A020 to flag `onlyOwner`-style modifiers that never check the caller, check after the body runs, or authenticate with `tx.origin`.
- Documented both codes and marked days 27 and 28 on the roadmap.

## 2026-11-10
- Added rule A018 to flag external calls inside constructors: low-level calls and ether sends, `Interface(addr).fn()` casts, calls on contract-typed variables, and `this.fn()`.
- Added a constructor example to the sample contract, documented the code, and marked day 26 on the roadmap.
- Added rule A016 to flag address parameters written into storage without an `address(0)` check, including constructors.
- Added rule A017 to flag numeric literals that are not named `constant` or `immutable` values.
- Documented both codes and marked days 24 and 25 on the roadmap.

## 2026-11-09
- Added rule A015 to flag `address` variables that are declared without a value and never assigned, so they silently stay `address(0)`.
- State variables count as set if any line in the file assigns them; locals only count assignments inside their own function.
- Documented the code and marked day 23 on the roadmap.
- Added `--format github` and a sample GitHub Action so findings show up as pull request annotations.
- Added rule A014 to flag `tx.origin` used in authorization comparisons, including the phishing-prone `tx.origin == msg.sender` check.
- Marked days 21 and 22 complete on the roadmap.

## 2026-11-06
- Added a `.pre-commit-hooks.yaml` so other repositories can run sibaudit as a pre-commit hook on staged `.sol` files.
- Added a sample `.pre-commit-config.yaml` under `examples/pre-commit/`, plus tests that validate both files with pre-commit's own schema.
- CI now installs pre-commit so those tests run instead of being skipped.
- Removed a stale second copy of the README that had been appended after the license section.
- Documented the pre-commit hook and marked day 20 on the roadmap.

## 2026-11-05
- Added a baseline file so known findings can be snapshotted and hidden on later scans.
- Added a summary report that counts findings by rule and by severity.
- Marked days 17 and 18 complete on the roadmap.
- Added VS Code task examples with a problem matcher so findings show up in the Problems panel, plus a test that keeps the matcher in sync with the CLI output.
- Documented the VS Code tasks and marked day 19 on the roadmap.

## 2026-11-04
- Added repeatable `--include` and `--exclude` glob options to choose which files are scanned.
- Documented the new options and marked day 16 on the roadmap.
- Added rule A012 to flag events that omit amounts, addresses, or other critical parameters.
- Added rule A013 to flag `blockhash` used as randomness or on the current block (always zero).
- Documented both codes and marked days 14 and 15 on the roadmap.
- Added rule A010 to flag contract logic that relies on `tx.gasprice`.
- Added rule A011 to flag `assert` used on caller input or balances, where `require` fits better.
- Documented both codes and marked days 12 and 13 on the roadmap.

## 2026-11-03
- Added a reentrancy heuristic that flags external calls made before state is updated.
- Added a check for sensitive functions that appear to lack access control.
- Documented both rules and marked days 10 and 11 on the roadmap.

## 2026-11-01
- Added rule A006 to flag `block.timestamp`/`now` usage and corresponding tests.
- Added rule A007 to flag unchecked arithmetic in pre-0.8 contracts with tests.
- Updated README and marked Day 8 and Day 9 complete in ROADMAP.

## 2026-10-31
- Added severity levels to findings and documented rule codes.
- Implemented rule A005 for state variable shadowing and extended tests.

## 2026-10-30
- Added `--format json` to emit newline-delimited JSON findings.
- Introduced `// sibaudit:ignore-next-line` directive to skip the next line for all rules.

## 2026-10-29
- Added rule A003 to flag any `delegatecall` usage and accompanying tests.
- Added rule A004 to detect `selfdestruct`/`suicide` usage.
- Updated `ROADMAP.md` to mark Day 2 and Day 3 as completed.

## Day 1
- Initial project scaffolding (pyproject, package).
- Added CLI with two heuristic rules (tx.origin, unchecked low-level call).
- CI (ruff, pytest), docs, and basic tests included.

