# Changelog

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

