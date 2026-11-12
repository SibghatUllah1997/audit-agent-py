#!/usr/bin/env python3
"""Read one finding as JSON on stdin and print a one-line local hint.

Print nothing to keep the scanner's built-in catalog hint. Exit non-zero
to force the same fallback. This file never talks to the network.
"""

from __future__ import annotations

import json
import sys

# Extra notes for a few codes; anything else falls back to the built-in catalog.
NOTES = {
    "A001": "Project convention: new code must use msg.sender, never tx.origin.",
    "A008": "Update balances before the call; add a nonReentrant modifier if needed.",
}


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 1
    if not isinstance(payload, dict):
        return 1
    code = str(payload.get("code", "")).strip().upper()
    note = NOTES.get(code)
    if note:
        print(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
