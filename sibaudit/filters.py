"""CLI filters for findings: min severity, allowlist, and blocklist."""

from __future__ import annotations

from collections.abc import Sequence

from .config import SEVERITY_RANK, ConfigError, normalize_severity
from .rules import get_rule
from .scanner import Finding


class FilterError(ValueError):
    """Raised when a CLI filter value is invalid."""


def parse_severity(value: str | None) -> str | None:
    """Return a canonical severity, or ``None`` when ``value`` is blank."""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return normalize_severity(text)
    except ConfigError as exc:
        raise FilterError(str(exc)) from None


def parse_codes(values: Sequence[str] | None) -> tuple[str, ...]:
    """Split comma-separated rule codes, uppercased, de-duplicated, validated."""
    if not values:
        return ()
    codes: list[str] = []
    seen: set[str] = set()
    for raw in values:
        for part in raw.split(","):
            code = part.strip().upper()
            if not code:
                continue
            if get_rule(code) is None:
                raise FilterError(f"unknown rule code {code!r}; see --list-rules")
            if code not in seen:
                seen.add(code)
                codes.append(code)
    return tuple(codes)


def apply_filters(
    findings: Sequence[Finding],
    *,
    min_severity: str | None = None,
    only: Sequence[str] = (),
    except_codes: Sequence[str] = (),
) -> list[Finding]:
    """Keep findings that pass ``only``, then ``except``, then ``min_severity``.

    ``min_severity`` is compared against each finding's (possibly overridden)
    severity. ``LOW`` < ``MEDIUM`` < ``HIGH``.
    """
    only_set = set(only) if only else None
    except_set = set(except_codes)
    min_rank = SEVERITY_RANK[min_severity] if min_severity else None
    out: list[Finding] = []
    for finding in findings:
        if only_set is not None and finding.code not in only_set:
            continue
        if finding.code in except_set:
            continue
        if min_rank is not None and SEVERITY_RANK.get(finding.severity, 0) < min_rank:
            continue
        out.append(finding)
    return out
