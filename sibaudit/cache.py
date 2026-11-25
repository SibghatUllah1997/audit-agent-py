"""Per-file findings cache keyed by file content.

A repeat scan of a large repo mostly re-reads files that did not change. The
cache stores the findings for each file next to a SHA-256 of its bytes, so a
file whose hash still matches is answered from the cache instead of running
every detector again.

The whole cache is tied to a ruleset key (package version plus a hash of the
scanner source). Upgrading sibaudit or editing a detector changes the key and
the old entries are ignored, so a stale cache can never hide a new rule.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__

CACHE_FORMAT = 1


def content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ruleset_key() -> str:
    """Changes whenever the version or any detector code changes."""
    scanner_src = Path(__file__).with_name("scanner.py").read_bytes()
    digest = hashlib.sha256(scanner_src).hexdigest()[:16]
    return f"{__version__}:{digest}"


@dataclass
class CachedFinding:
    line_number: int
    code: str
    severity: str
    message: str
    line_text: str


@dataclass
class ScanCache:
    path: Path
    key: str
    entries: dict[str, dict] = field(default_factory=dict)
    hits: int = 0
    misses: int = 0
    _dirty: bool = False

    @classmethod
    def load(cls, path: Path, key: str | None = None) -> ScanCache:
        key = key or ruleset_key()
        cache = cls(path=path, key=key)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # Missing or corrupt cache just means a cold scan.
            return cache
        if (
            not isinstance(raw, dict)
            or raw.get("format") != CACHE_FORMAT
            or raw.get("ruleset") != key
            or not isinstance(raw.get("files"), dict)
        ):
            cache._dirty = True
            return cache
        cache.entries = raw["files"]
        return cache

    def get(self, file_path: Path, digest: str) -> list[CachedFinding] | None:
        entry = self.entries.get(_key_for(file_path))
        if not isinstance(entry, dict) or entry.get("sha256") != digest:
            self.misses += 1
            return None
        try:
            found = [CachedFinding(**item) for item in entry.get("findings", [])]
        except TypeError:
            self.misses += 1
            return None
        self.hits += 1
        return found

    def put(self, file_path: Path, digest: str, findings: list[CachedFinding]) -> None:
        self.entries[_key_for(file_path)] = {
            "sha256": digest,
            "findings": [vars(f) for f in findings],
        }
        self._dirty = True

    def prune_missing(self) -> None:
        """Drop entries for files that no longer exist on disk."""
        gone = [name for name in self.entries if not Path(name).is_file()]
        for name in gone:
            del self.entries[name]
        if gone:
            self._dirty = True

    def save(self) -> None:
        if not self._dirty:
            return
        self.prune_missing()
        payload = {"format": CACHE_FORMAT, "ruleset": self.key, "files": self.entries}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Write to a temp file first so an interrupted run never leaves half a cache.
        fd, tmp = tempfile.mkstemp(prefix=".sibaudit-cache-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, sort_keys=True)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        self._dirty = False


    def format_stats(self) -> str:
        """Human-friendly summary of cache effectiveness for this run."""
        return f"cache: {self.hits} hits, {self.misses} misses"
\
def _key_for(file_path: Path) -> str:
    return str(file_path.resolve())
