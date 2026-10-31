# Sibghat's Solidity Audit Helper

A tiny, educational Python CLI that scans Solidity (`.sol`) files for a few well-known risky patterns:

- Use of `tx.origin` (often misused for authentication)
- Unchecked low-level calls (e.g., `address.call(...)`) where the success value is not obviously verified
- Use of `delegatecall`
- Use of `selfdestruct` / `suicide`

This is an intentionally minimal, static checker to bootstrap a daily portfolio project.

## Quickstart

1) Ensure Python 3.11+
2) Install in editable mode:

```bash
python3 -m pip install -e .
```

3) Run against a file or directory:

```bash
sibaudit path/to/contracts
# or
python3 -m sibaudit path/to/contracts
```

Findings are printed in `path:line: CODE message` format. The CLI exits with code 1 if any findings are detected, otherwise 0.

### JSON output

You can emit newline-delimited JSON records instead of text:

```bash
python3 -m sibaudit --format json path/to/contracts > findings.ndjson
```

Each line is a JSON object with:

- `file_path` (string)
- `line_number` (int)
- `code` (string, e.g. `A001`)
- `severity` (string: `LOW` | `MEDIUM` | `HIGH`)
- `message` (string)

### Ignoring one line

Add the following directive on a line to ignore the very next line (for all rules):

```solidity
// sibaudit:ignore-next-line
address a = tx.origin; // this line will be ignored
```

## Severities and rule codes

- A001 (MEDIUM): Potential risky use of `tx.origin`
- A002 (MEDIUM): Low-level call without capturing/validating success (heuristic)
- A003 (HIGH): Use of `delegatecall` detected (dangerous; review proxy usage carefully)
- A004 (HIGH): Use of `selfdestruct`/`suicide` detected (can brick contracts)
- A005 (LOW): State variable shadowing by a parameter or local variable (heuristic) — planned

## What this is (and isn’t)

- This is an educational toy, not a full static analyzer.
- Rules are intentionally naive heuristics to keep things approachable.
- You should always verify results manually and consult professional tools and reviews for any real security work.

## License

MIT — Copyright (c) 2026 HM Sibghat Ullah

