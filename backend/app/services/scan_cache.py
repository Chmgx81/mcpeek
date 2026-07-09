"""Simple in-memory cache for scan results.

Prevents redundant scans of the same target within a configurable TTL.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass



@dataclass
class _CacheEntry:
    scan_id: str
    created_at: float
    ttl_seconds: int = 3600  # 1 hour default


class ScanResultCache:
    """In-memory cache mapping (target, target_type) → scan_id.

    Skips re-scanning if a completed scan exists within the TTL.
    Thread-safe for asyncio (single event loop).
    """

    def __init__(self, ttl_seconds: int = 3600):
        self._cache: dict[str, _CacheEntry] = {}
        self._ttl = ttl_seconds

    def _key(self, target: str, target_type: str) -> str:
        raw = f"{target_type}:{target}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def get(self, target: str, target_type: str) -> str | None:
        """Return cached scan_id if valid, else None."""
        key = self._key(target, target_type)
        entry = self._cache.get(key)
        if entry is None:
            return None
        if time.monotonic() - entry.created_at > self._ttl:
            del self._cache[key]
            return None
        return entry.scan_id

    def put(self, target: str, target_type: str, scan_id: str) -> None:
        """Store a scan_id in the cache."""
        key = self._key(target, target_type)
        self._cache[key] = _CacheEntry(
            scan_id=scan_id,
            created_at=time.monotonic(),
            ttl_seconds=self._ttl,
        )

    def invalidate(self, target: str, target_type: str) -> None:
        """Remove a cached entry."""
        key = self._key(target, target_type)
        self._cache.pop(key, None)

    def clear(self) -> None:
        """Clear the entire cache."""
        self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


# Global singleton
scan_cache = ScanResultCache()
