# Changelog

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

