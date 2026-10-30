# Changelog

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

