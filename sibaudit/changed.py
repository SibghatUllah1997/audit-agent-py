"""List Solidity files git reports as changed against a ref."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

GIT_TIMEOUT = 15.0


class ChangedError(ValueError):
    """Raised when ``--changed-since`` cannot talk to git or the ref is invalid."""


def _run_git(args: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ChangedError("git is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise ChangedError("git timed out") from exc


def git_toplevel(cwd: Path) -> Path:
    """Return the repository root that contains ``cwd``."""
    proc = _run_git(["rev-parse", "--show-toplevel"], cwd)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip() or "not a git repository"
        raise ChangedError(detail)
    return Path(proc.stdout.strip()).resolve()


def _nul_paths(payload: str) -> list[str]:
    return [part for part in payload.split("\0") if part]


def list_changed_solidity(ref: str, cwd: Path) -> list[Path]:
    """Tracked and untracked ``.sol`` files that differ from ``ref``.

    Deleted files are omitted. Paths are absolute and only returned if they
    still exist on disk. ``ref`` is passed to ``git diff`` as-is, so
    ``HEAD~1`` and ``origin/main...HEAD`` both work.
    """
    ref = ref.strip()
    if not ref:
        raise ChangedError("changed-since ref is empty")
    top = git_toplevel(cwd)
    diff = _run_git(
        ["diff", "--name-only", "-z", "--diff-filter=ACMR", ref],
        top,
    )
    if diff.returncode != 0:
        detail = (diff.stderr or diff.stdout).strip() or f"invalid git ref {ref!r}"
        raise ChangedError(detail)
    extra = _run_git(
        ["ls-files", "-z", "--others", "--exclude-standard"],
        top,
    )
    if extra.returncode != 0:
        detail = (extra.stderr or extra.stdout).strip() or "cannot list untracked files"
        raise ChangedError(detail)
    names = _nul_paths(diff.stdout) + _nul_paths(extra.stdout)
    found: list[Path] = []
    seen: set[Path] = set()
    for name in names:
        path = (top / name).resolve()
        if path.suffix.lower() != ".sol" or not path.is_file() or path in seen:
            continue
        seen.add(path)
        found.append(path)
    found.sort()
    return found


def filter_to_roots(files: Sequence[Path], roots: Sequence[Path]) -> list[Path]:
    """Keep files that are one of ``roots`` or sit under a root directory."""
    resolved_roots = [Path(root).resolve() for root in roots]
    kept: list[Path] = []
    for file_path in files:
        resolved = file_path.resolve()
        for root in resolved_roots:
            if root.is_file():
                if resolved == root:
                    kept.append(resolved)
                    break
                continue
            try:
                resolved.relative_to(root)
            except ValueError:
                continue
            kept.append(resolved)
            break
    return kept
