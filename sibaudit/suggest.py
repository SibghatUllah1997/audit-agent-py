"""Local, offline fix hints for each rule code.

The catalog is the default source for ``sibaudit --suggest``. It never
makes a network call. A JSON override file can replace individual hints;
an optional local command can too, and the catalog is used if that
command fails or times out.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path

from .scanner import Finding

FALLBACK = "Review this finding; no built-in hint for this rule code."

# (code, default hint, ((message substring, more specific hint), ...))
# Specific variants are matched first, case-insensitively, against the finding message.
_HINTS: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...] = (
    (
        "A001",
        "Prefer msg.sender for identity and authorization; "
        "tx.origin trusts every contract in the call chain.",
        (),
    ),
    (
        "A002",
        "Capture (bool ok, ) from the call and require(ok, ...) before continuing.",
        (
            (
                "not obviously checked",
                "Check the captured success flag with require on the next line, "
                "not several statements later.",
            ),
            (
                "without capturing",
                "Capture (bool ok, ) from the call and require(ok, ...) before continuing.",
            ),
        ),
    ),
    (
        "A003",
        "Avoid delegatecall unless this is a reviewed proxy with a fixed implementation address.",
        (),
    ),
    (
        "A004",
        "Replace selfdestruct/suicide with a pause flag; "
        "destruction is deprecated and bricks integrations.",
        (),
    ),
    (
        "A005",
        "Rename the parameter so it does not hide the state variable of the same name.",
        (),
    ),
    (
        "A006",
        "Do not use block.timestamp or now as randomness; for deadlines, allow a generous window.",
        (),
    ),
    (
        "A007",
        "Upgrade to Solidity 0.8+ or wrap arithmetic in SafeMath so overflow reverts.",
        (),
    ),
    (
        "A008",
        "Update storage before the external call (checks-effects-interactions), "
        "or add a reentrancy guard.",
        (),
    ),
    (
        "A009",
        "Gate this function with a modifier or require(msg.sender == owner) "
        "before it changes state.",
        (),
    ),
    (
        "A010",
        "Do not branch on tx.gasprice; the sender chooses it and it is not a privilege signal.",
        (),
    ),
    (
        "A011",
        'Use require(..., "reason") for caller input and balances; '
        "keep assert for invariants only.",
        (),
    ),
    (
        "A012",
        "Add the missing amount and/or address argument so indexers can reconstruct the event.",
        (),
    ),
    (
        "A013",
        "blockhash is known to the block producer; "
        "use a VRF or commit-reveal instead of it as randomness.",
        (
            (
                "always zero",
                "blockhash(block.number) is always zero; "
                "use a VRF or commit-reveal for randomness.",
            ),
        ),
    ),
    (
        "A014",
        "Compare msg.sender to the owner; never authorize with tx.origin.",
        (
            (
                "does not stop phishing",
                "tx.origin == msg.sender does not stop phishing; compare msg.sender to the owner.",
            ),
            (
                "authorization comparison",
                "Compare msg.sender to the owner; never authorize with tx.origin.",
            ),
        ),
    ),
    (
        "A015",
        "Initialize the address in the constructor (and reject address(0)) "
        "or assign it before use.",
        (
            (
                "State address",
                "Set this state address in the constructor and reject address(0).",
            ),
            (
                "Local address",
                "Assign this local address before reading it; the default is address(0).",
            ),
        ),
    ),
    (
        "A016",
        "Require the parameter is not address(0) before writing it into storage.",
        (),
    ),
    (
        "A017",
        "Lift the literal into a named constant (or immutable) so the unit and intent are obvious.",
        (),
    ),
    (
        "A018",
        "Move the external call out of the constructor into a separate setup "
        "step after deployment.",
        (),
    ),
    (
        "A019",
        "Add a withdraw or transfer path, or drop payable if the contract should not hold ether.",
        (),
    ),
    (
        "A020",
        "Compare msg.sender to the owner before _; in the modifier body.",
        (
            (
                "after the function body",
                "Move the authorization check before _; so the function body cannot run first.",
            ),
            (
                "tx.origin",
                "Authenticate with msg.sender, not tx.origin.",
            ),
            (
                "compares msg.sender to itself",
                "Replace the dummy comparison with require(msg.sender == owner).",
            ),
            (
                "requires true",
                "Replace require(true) with require(msg.sender == owner).",
            ),
            (
                "never checks the caller",
                "Compare msg.sender to the owner before _; in the modifier body.",
            ),
        ),
    ),
)


class SuggestError(ValueError):
    """Raised when a suggestion catalog file cannot be read or does not match the schema."""


@dataclass(frozen=True)
class Catalog:
    """Default hints per rule code, plus optional message-specific variants."""

    defaults: dict[str, str]
    variants: dict[str, tuple[tuple[str, str], ...]]


@lru_cache(maxsize=1)
def builtin_catalog() -> Catalog:
    """Return the shipped catalog (built once, never talks to the network)."""
    defaults: dict[str, str] = {}
    variants: dict[str, tuple[tuple[str, str], ...]] = {}
    for code, hint, extra in _HINTS:
        defaults[code] = hint
        if extra:
            variants[code] = extra
    return Catalog(defaults=defaults, variants=variants)


def hint_for(code: str, message: str = "", catalog: Catalog | None = None) -> str:
    """Return a local fix hint for ``code``, using ``message`` to pick a variant."""
    catalog = catalog if catalog is not None else builtin_catalog()
    key = code.strip().upper()
    text = message or ""
    lowered = text.lower()
    for needle, hint in catalog.variants.get(key, ()):
        if needle.lower() in lowered:
            return hint
    if key in catalog.defaults:
        return catalog.defaults[key]
    return FALLBACK


def with_overrides(catalog: Catalog, overrides: dict[str, str]) -> Catalog:
    """Replace hints for the given codes. An override drops message-specific variants."""
    defaults = dict(catalog.defaults)
    variants = dict(catalog.variants)
    for raw_code, hint in overrides.items():
        key = raw_code.strip().upper()
        defaults[key] = hint
        variants.pop(key, None)
    return Catalog(defaults=defaults, variants=variants)


def load_catalog(path: Path) -> dict[str, str]:
    """Load a JSON object of ``{rule code: hint}`` from ``path``."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise SuggestError(f"suggestion catalog not found: {path}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SuggestError(f"suggestion catalog is not valid JSON: {path}") from exc
    if not isinstance(data, dict):
        raise SuggestError("suggestion catalog must be a JSON object of code to hint")
    overrides: dict[str, str] = {}
    for index, (key, value) in enumerate(data.items()):
        if not isinstance(key, str) or not key.strip():
            raise SuggestError(f"suggestion catalog entry {index} is missing a rule code")
        if not isinstance(value, str) or not value.strip():
            raise SuggestError(f"suggestion catalog entry {key!r} must be a non-empty string")
        overrides[key.strip().upper()] = value.strip()
    return overrides


def attach_hints(
    findings: Sequence[Finding],
    catalog: Catalog | None = None,
) -> list[Finding]:
    """Return copies of ``findings`` with a local hint on each one."""
    chosen = catalog if catalog is not None else builtin_catalog()
    attached: list[Finding] = []
    for finding in findings:
        hint = hint_for(finding.code, finding.message, chosen)
        attached.append(replace(finding, suggestion=hint))
    return attached
