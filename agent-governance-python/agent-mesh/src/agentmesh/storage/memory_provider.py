# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
In-Memory Storage Provider.

Simple in-memory implementation for development and testing.
"""

import time
from collections import defaultdict
from typing import Optional

from .provider import AbstractStorageProvider, StorageConfig


class MemoryStorageProvider(AbstractStorageProvider):
    """
    In-memory storage provider.

    Uses Python dictionaries for storage. Data is lost on restart.
    Suitable for development and testing only.
    """

    def __init__(self, config: StorageConfig):
        """Initialize in-memory storage."""
        super().__init__(config)
        self._data: dict[str, str] = {}
        self._hashes: dict[str, dict[str, str]] = defaultdict(dict)
        self._lists: dict[str, list[str]] = defaultdict(list)
        self._sorted_sets: dict[str, dict[str, float]] = defaultdict(dict)
        self._ttls: dict[str, float] = {}
        self._connected = False

    async def connect(self) -> None:
        """Establish connection (no-op for memory)."""
        self._connected = True

    async def disconnect(self) -> None:
        """Close connection (no-op for memory)."""
        self._connected = False

    async def health_check(self) -> bool:
        """Check if storage is healthy."""
        return self._connected

    def _expire(self, key: str) -> None:
        """Drop *key* if its TTL has passed, as Redis does when a key is read."""
        expires_at = self._ttls.get(key)
        if expires_at is not None and time.time() >= expires_at:
            del self._ttls[key]
            self._data.pop(key, None)

    def _expire_all(self) -> None:
        """Drop every key whose TTL has passed."""
        for key in list(self._ttls):
            self._expire(key)

    # Key-Value Operations

    async def get(self, key: str) -> Optional[str]:
        """Get value by key."""
        self._expire(key)
        return self._data.get(key)

    async def set(
        self,
        key: str,
        value: str,
        ttl_seconds: Optional[int] = None,
    ) -> bool:
        """Set value with optional TTL."""
        self._data[key] = value
        if ttl_seconds is not None:
            self._ttls[key] = time.time() + ttl_seconds
        else:
            # Like Redis SET, a write without a TTL clears the previous one.
            self._ttls.pop(key, None)
        return True

    async def delete(self, key: str) -> bool:
        """Delete key."""
        self._expire(key)
        self._ttls.pop(key, None)
        if key in self._data:
            del self._data[key]
            return True
        return False

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        self._expire(key)
        return key in self._data

    # Hash Operations

    async def hget(self, key: str, field: str) -> Optional[str]:
        """Get hash field value."""
        return self._hashes.get(key, {}).get(field)

    async def hset(self, key: str, field: str, value: str) -> bool:
        """Set hash field value."""
        self._hashes[key][field] = value
        return True

    async def hgetall(self, key: str) -> dict[str, str]:
        """Get all hash fields."""
        return dict(self._hashes.get(key, {}))

    async def hdel(self, key: str, field: str) -> bool:
        """Delete hash field."""
        if key in self._hashes and field in self._hashes[key]:
            del self._hashes[key][field]
            return True
        return False

    async def hkeys(self, key: str) -> list[str]:
        """Get all hash field names."""
        return list(self._hashes.get(key, {}).keys())

    # List Operations

    async def lpush(self, key: str, value: str) -> int:
        """Push value to head of list."""
        self._lists[key].insert(0, value)
        return len(self._lists[key])

    async def rpush(self, key: str, value: str) -> int:
        """Push value to tail of list."""
        self._lists[key].append(value)
        return len(self._lists[key])

    async def lrange(self, key: str, start: int, stop: int) -> list[str]:
        """Get list range [start, stop]."""
        lst = self._lists.get(key, [])
        if stop == -1:
            return lst[start:]
        return lst[start:stop + 1]

    async def llen(self, key: str) -> int:
        """Get list length."""
        return len(self._lists.get(key, []))

    # Sorted Set Operations

    async def zadd(self, key: str, score: float, member: str) -> bool:
        """Add member to sorted set with score."""
        self._sorted_sets[key][member] = score
        return True

    async def zscore(self, key: str, member: str) -> Optional[float]:
        """Get score of member in sorted set."""
        return self._sorted_sets.get(key, {}).get(member)

    async def zrange(
        self,
        key: str,
        start: int,
        stop: int,
        with_scores: bool = False,
    ) -> list[str] | list[tuple[str, float]]:
        """Get sorted set range."""
        sorted_set = self._sorted_sets.get(key, {})
        sorted_items = sorted(sorted_set.items(), key=lambda x: x[1])

        if stop == -1:
            items = sorted_items[start:]
        else:
            items = sorted_items[start:stop + 1]

        if with_scores:
            return items
        return [member for member, _ in items]

    async def zrangebyscore(
        self,
        key: str,
        min_score: float,
        max_score: float,
        with_scores: bool = False,
    ) -> list[str] | list[tuple[str, float]]:
        """Get sorted set range by score."""
        sorted_set = self._sorted_sets.get(key, {})
        items = [
            (member, score)
            for member, score in sorted(sorted_set.items(), key=lambda x: x[1])
            if min_score <= score <= max_score
        ]

        if with_scores:
            return items
        return [member for member, _ in items]

    # Atomic Operations

    async def incr(self, key: str) -> int:
        """Increment value atomically."""
        self._expire(key)
        current = int(self._data.get(key, "0"))
        new_value = current + 1
        self._data[key] = str(new_value)
        return new_value

    async def decr(self, key: str) -> int:
        """Decrement value atomically."""
        self._expire(key)
        current = int(self._data.get(key, "0"))
        new_value = current - 1
        self._data[key] = str(new_value)
        return new_value

    async def incrby(self, key: str, amount: int) -> int:
        """Increment value by amount."""
        self._expire(key)
        current = int(self._data.get(key, "0"))
        new_value = current + amount
        self._data[key] = str(new_value)
        return new_value

    # Batch Operations

    async def mget(self, keys: list[str]) -> list[Optional[str]]:
        """Get multiple values."""
        for key in keys:
            self._expire(key)
        return [self._data.get(key) for key in keys]

    async def mset(self, mapping: dict[str, str]) -> bool:
        """Set multiple key-value pairs."""
        self._data.update(mapping)
        for key in mapping:
            self._ttls.pop(key, None)
        return True

    # Pattern Operations

    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching pattern."""
        import fnmatch
        self._expire_all()
        return [key for key in self._data.keys() if fnmatch.fnmatch(key, pattern)]

    async def scan(
        self,
        cursor: int = 0,
        match: Optional[str] = None,
        count: int = 100,
    ) -> tuple[int, list[str]]:
        """Scan keys with cursor."""
        self._expire_all()
        all_keys = list(self._data.keys())

        if match:
            import fnmatch
            all_keys = [key for key in all_keys if fnmatch.fnmatch(key, match)]

        start = cursor
        end = cursor + count
        keys = all_keys[start:end]

        new_cursor = end if end < len(all_keys) else 0
        return new_cursor, keys
