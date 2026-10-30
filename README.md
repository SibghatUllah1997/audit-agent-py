# Sibghat's Solidity Audit Helper (Day 1)

A tiny, educational Python CLI that scans Solidity (`.sol`) files for a couple of well-known risky patterns:

- Use of `tx.origin` (often misused for authentication)
- Unchecked low-level calls (e.g., `address.call(...)`) where the success value is not obviously verified

This is an intentionally minimal, static checker to bootstrap a daily portfolio project. Future days may add more rules — but this Day 1 is pure, simple Python.

## Quickstart

1) Ensure Python 3.11+
2) Install in editable mode:

```bash
pip install -e .
```

3) Run against a file or directory:

```bash
sibaudit path/to/contracts
# or
python -m sibaudit path/to/contracts
```

Findings are printed in `path:line: CODE message` format. The CLI exits with code 1 if any findings are detected, otherwise 0.

### JSON output

You can emit newline-delimited JSON records instead of text:

```bash
python -m sibaudit --format json path/to/contracts > findings.ndjson
```

Each line is a JSON object with:

- `file_path` (string)
- `line_number` (int)
- `code` (string, e.g. `A001`)
- `message` (string)

### Ignoring one line

Add the following directive on a line to ignore the very next line (for all rules):

```solidity
// sibaudit:ignore-next-line
address a = tx.origin; // this line will be ignored
```

## Current rules

- A001: Potential risky use of `tx.origin`
- A002: Low-level call without capturing/validating success (heuristic)
- A003: Use of `delegatecall` detected (dangerous; review proxy usage carefully)
- A004: Use of `selfdestruct`/`suicide` detected (can brick contracts)

## What this is (and isn’t)

- This is an educational toy, not a full static analyzer.
- Rules are intentionally naive heuristics to keep things approachable on Day 1.
- You should always verify results manually and consult professional tools and reviews for any real security work.

## License

MIT — Copyright (c) 2026 HM Sibghat Ullah

# audit-agent-py
