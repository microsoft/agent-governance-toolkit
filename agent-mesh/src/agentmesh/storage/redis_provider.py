# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Redis Storage Provider.

Production-ready Redis backend with connection pooling and error handling.
"""

from typing import Optional
import logging

from .provider import AbstractStorageProvider, StorageConfig

logger = logging.getLogger(__name__)


class RedisStorageProvider(AbstractStorageProvider):
    """
    Redis storage provider.

    Features:
    - Connection pooling
    - Automatic reconnection
    - TTL support
    - High-performance caching

    Requires: redis[asyncio] package
    """

    def __init__(self, config: StorageConfig):
        """Initialize Redis storage."""
        super().__init__(config)
        self._client = None
        self._pool = None

    async def connect(self) -> None:
        """Establish connection to Redis."""
        try:
            import redis.asyncio as aioredis
        except ImportError:
            raise ImportError(
                "redis package is required for RedisStorageProvider. "
                "Install with: pip install redis[asyncio]"
            )

        # Create connection pool
        self._pool = aioredis.ConnectionPool(
            host=self.config.redis_host,
            port=self.config.redis_port,
            db=self.config.redis_db,
            password=self.config.redis_password,
            ssl=self.config.redis_ssl,
            max_connections=self.config.pool_size,
            socket_timeout=self.config.timeout_seconds,
            socket_connect_timeout=self.config.timeout_seconds,
            decode_responses=True,
        )

        self._client = aioredis.Redis(connection_pool=self._pool)

        # Test connection
        await self._client.ping()

    async def disconnect(self) -> None:
        """Close connection to Redis."""
        if self._client:
            await self._client.close()
        if self._pool:
            await self._pool.disconnect()

    async def health_check(self) -> bool:
        """Check if Redis is healthy."""
        try:
            if self._client:
                await self._client.ping()
                return True
        except Exception:
            logger.debug("Redis health check failed", exc_info=True)
        return False

    # Key-Value Operations

    async def get(self, key: str) -> Optional[str]:
        """Get value by key."""
        return await self._client.get(key)

    async def set(
        self,
        key: str,
        value: str,
        ttl_seconds: Optional[int] = None,
    ) -> bool:
        """Set value with optional TTL."""
        if ttl_seconds is not None:
            return await self._client.setex(key, ttl_seconds, value)
        return await self._client.set(key, value)

    async def delete(self, key: str) -> bool:
        """Delete key."""
        result = await self._client.delete(key)
        return result > 0

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        result = await self._client.exists(key)
        return result > 0

    # Hash Operations

    async def hget(self, key: str, field: str) -> Optional[str]:
        """Get hash field value."""
        return await self._client.hget(key, field)

    async def hset(self, key: str, field: str, value: str) -> bool:
        """Set hash field value."""
        result = await self._client.hset(key, field, value)
        return result >= 0

    async def hgetall(self, key: str) -> dict[str, str]:
        """Get all hash fields."""
        return await self._client.hgetall(key)

    async def hdel(self, key: str, field: str) -> bool:
        """Delete hash field."""
        result = await self._client.hdel(key, field)
        return result > 0

    async def hkeys(self, key: str) -> list[str]:
        """Get all hash field names."""
        return await self._client.hkeys(key)

    # List Operations

    async def lpush(self, key: str, value: str) -> int:
        """Push value to head of list."""
        return await self._client.lpush(key, value)

    async def rpush(self, key: str, value: str) -> int:
        """Push value to tail of list."""
        return await self._client.rpush(key, value)

    async def lrange(self, key: str, start: int, stop: int) -> list[str]:
        """Get list range [start, stop]."""
        return await self._client.lrange(key, start, stop)

    async def llen(self, key: str) -> int:
        """Get list length."""
        return await self._client.llen(key)

    # Sorted Set Operations

    async def zadd(self, key: str, score: float, member: str) -> bool:
        """Add member to sorted set with score."""
        result = await self._client.zadd(key, {member: score})
        return result >= 0

    async def zscore(self, key: str, member: str) -> Optional[float]:
        """Get score of member in sorted set."""
        return await self._client.zscore(key, member)

    async def zrange(
        self,
        key: str,
        start: int,
        stop: int,
        with_scores: bool = False,
    ) -> list[str] | list[tuple[str, float]]:
        """Get sorted set range."""
        return await self._client.zrange(
            key, start, stop, withscores=with_scores
        )

    async def zrangebyscore(
        self,
        key: str,
        min_score: float,
        max_score: float,
        with_scores: bool = False,
    ) -> list[str] | list[tuple[str, float]]:
        """Get sorted set range by score."""
        return await self._client.zrangebyscore(
            key, min_score, max_score, withscores=with_scores
        )

    # Atomic Operations

    async def incr(self, key: str) -> int:
        """Increment value atomically."""
        return await self._client.incr(key)

    async def decr(self, key: str) -> int:
        """Decrement value atomically."""
        return await self._client.decr(key)

    async def incrby(self, key: str, amount: int) -> int:
        """Increment value by amount."""
        return await self._client.incrby(key, amount)

    # Batch Operations

    async def mget(self, keys: list[str]) -> list[Optional[str]]:
        """Get multiple values."""
        return await self._client.mget(keys)

    async def mset(self, mapping: dict[str, str]) -> bool:
        """Set multiple key-value pairs."""
        return await self._client.mset(mapping)

    # Pattern Operations

    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching pattern."""
        return await self._client.keys(pattern)

    async def scan(
        self,
        cursor: int = 0,
        match: Optional[str] = None,
        count: int = 100,
    ) -> tuple[int, list[str]]:
        """Scan keys with cursor."""
        new_cursor, keys = await self._client.scan(
            cursor=cursor,
            match=match,
            count=count,
        )
        return new_cursor, keys
