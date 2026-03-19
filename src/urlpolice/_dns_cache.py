"""Thread-safe TTL cache for urlpolice.

Provides a simple in-memory cache with time-based expiration, used
primarily to cache DNS check results and avoid redundant lookups.
"""

from __future__ import annotations

import threading
import time
from typing import Any


class DNSCache:
    """Thread-safe cache with TTL-based expiration.

    Stores arbitrary values keyed by string.  Used by the DNS check to
    cache ``CheckResult`` objects so repeated validations of the same
    hostname avoid redundant DNS lookups.

    Args:
        ttl: Time-to-live in seconds for cached entries.  Defaults to 300
            (five minutes).
    """

    def __init__(self, ttl: int = 300) -> None:
        self._ttl = ttl
        self._lock = threading.Lock()
        self._store: dict[str, tuple[Any, float]] = {}

    def get(self, key: str) -> Any | None:
        """Retrieve a cached value by *key*, or ``None`` if expired/missing.

        Args:
            key: The cache key to look up.

        Returns:
            The cached value, or ``None`` if the entry is missing or has
            expired.
        """
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, timestamp = entry
            if time.monotonic() - timestamp > self._ttl:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: Any) -> None:
        """Store a value under *key*.

        Args:
            key: The cache key.
            value: The value to cache.
        """
        with self._lock:
            self._store[key] = (value, time.monotonic())

    def clear(self) -> None:
        """Remove all cached entries."""
        with self._lock:
            self._store.clear()
