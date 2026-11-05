from __future__ import annotations

from collections.abc import Iterable, Sequence
from fnmatch import fnmatchcase
from pathlib import PurePosixPath


def _normalize(pattern: str) -> str:
    """Use forward slashes and drop a leading `./`."""
    pattern = pattern.replace("\\", "/")
    while pattern.startswith("./"):
        pattern = pattern[2:]
    return pattern


def _candidates(rel_path: str) -> list[str]:
    """Return the path and each of its tails: `a/b/C.sol` -> `a/b/C.sol`, `b/C.sol`, `C.sol`."""
    parts = PurePosixPath(rel_path.replace("\\", "/")).parts
    return ["/".join(parts[i:]) for i in range(len(parts))]


def matches_any(rel_path: str, patterns: Iterable[str]) -> bool:
    """True if `rel_path` matches any glob.

    A pattern may match the whole relative path or any trailing part of it, so
    `Mock*.sol` matches `contracts/test/MockToken.sol`. `*` also crosses `/`.
    """
    tails = _candidates(rel_path)
    for raw in patterns:
        pattern = _normalize(raw)
        options = {pattern}
        if pattern.startswith("**/"):
            options.add(pattern[3:])
        for option in options:
            if any(fnmatchcase(tail, option) for tail in tails):
                return True
    return False


def is_selected(
    rel_path: str,
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
) -> bool:
    """Apply include then exclude. No include globs means "include everything"."""
    if include and not matches_any(rel_path, include):
        return False
    return not (exclude and matches_any(rel_path, exclude))
