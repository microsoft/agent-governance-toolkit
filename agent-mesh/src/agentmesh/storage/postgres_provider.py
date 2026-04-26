# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
PostgreSQL Storage Provider.

Enterprise-grade PostgreSQL backend with async SQLAlchemy ORM.
"""

from typing import Optional
import logging

from .provider import AbstractStorageProvider, StorageConfig

logger = logging.getLogger(__name__)


class PostgresStorageProvider(AbstractStorageProvider):
    """
    PostgreSQL storage provider.

    Features:
    - Async SQLAlchemy ORM
    - Connection pooling
    - JSONB support for structured data
    - Full ACID compliance

    Requires: sqlalchemy[asyncio], asyncpg packages
    """

    def __init__(self, config: StorageConfig):
        """Initialize PostgreSQL storage."""
        super().__init__(config)
        self._engine = None
        self._session_factory = None

    async def connect(self) -> None:
        """Establish connection to PostgreSQL."""
        try:
            from sqlalchemy.ext.asyncio import (
                create_async_engine,
                async_sessionmaker,
            )
        except ImportError:
            raise ImportError(
                "sqlalchemy[asyncio] and asyncpg packages are required for PostgresStorageProvider. "
                "Install with: pip install sqlalchemy[asyncio] asyncpg"
            )

        # Build connection string
        if self.config.connection_string:
            conn_str = self.config.connection_string
        else:
            password_part = (
                f":{self.config.postgres_password}"
                if self.config.postgres_password
                else ""
            )
            conn_str = (
                f"postgresql+asyncpg://{self.config.postgres_user}"
                f"{password_part}@{self.config.postgres_host}"
                f":{self.config.postgres_port}/{self.config.postgres_database}"
            )

            if self.config.postgres_ssl_mode != "disable":
                conn_str += f"?ssl={self.config.postgres_ssl_mode}"

        # Create engine
        self._engine = create_async_engine(
            conn_str,
            pool_size=self.config.pool_size,
            max_overflow=20,
            pool_pre_ping=True,
            echo=False,
        )

        self._session_factory = async_sessionmaker(
            self._engine,
            expire_on_commit=False,
        )

        # Initialize schema
        await self._init_schema()

    async def _init_schema(self) -> None:
        """Initialize database schema."""
        from sqlalchemy import text

        # Create tables for key-value, hashes, lists, etc.
        async with self._engine.begin() as conn:
            await conn.execute(text(
                """
                CREATE TABLE IF NOT EXISTS agentmesh_kv (
                    key VARCHAR(512) PRIMARY KEY,
                    value TEXT NOT NULL,
                    expires_at TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_kv_expires ON agentmesh_kv(expires_at);

                CREATE TABLE IF NOT EXISTS agentmesh_hash (
                    key VARCHAR(512) NOT NULL,
                    field VARCHAR(512) NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (key, field)
                );

                CREATE TABLE IF NOT EXISTS agentmesh_list (
                    key VARCHAR(512) NOT NULL,
                    idx INTEGER NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (key, idx)
                );
                CREATE INDEX IF NOT EXISTS idx_list_key ON agentmesh_list(key, idx);

                CREATE TABLE IF NOT EXISTS agentmesh_zset (
                    key VARCHAR(512) NOT NULL,
                    member VARCHAR(512) NOT NULL,
                    score DOUBLE PRECISION NOT NULL,
                    PRIMARY KEY (key, member)
                );
                CREATE INDEX IF NOT EXISTS idx_zset_score ON agentmesh_zset(key, score);
                """
            ))

    async def disconnect(self) -> None:
        """Close connection to PostgreSQL."""
        if self._engine:
            await self._engine.dispose()

    async def health_check(self) -> bool:
        """Check if PostgreSQL is healthy."""
        try:
            if self._engine:
                from sqlalchemy import text
                async with self._engine.begin() as conn:
                    await conn.execute(text("SELECT 1"))
                return True
        except Exception:
            logger.debug("PostgreSQL health check failed", exc_info=True)
        return False

    # Key-Value Operations

    async def get(self, key: str) -> Optional[str]:
        """Get value by key."""
        async with self._session_factory() as session:
            result = await session.execute(
                "SELECT value FROM agentmesh_kv WHERE key = :key "
                "AND (expires_at IS NULL OR expires_at > NOW())",
                {"key": key},
            )
            row = result.fetchone()
            return row[0] if row else None

    async def set(
        self,
        key: str,
        value: str,
        ttl_seconds: Optional[int] = None,
    ) -> bool:
        """Set value with optional TTL."""
        async with self._session_factory() as session:
            if ttl_seconds:
                await session.execute(
                    "INSERT INTO agentmesh_kv (key, value, expires_at) "
                    "VALUES (:key, :value, NOW() + INTERVAL '1 second' * :ttl) "
                    "ON CONFLICT (key) DO UPDATE SET value = :value, expires_at = NOW() + INTERVAL '1 second' * :ttl",
                    {"key": key, "value": value, "ttl": ttl_seconds},
                )
            else:
                await session.execute(
                    "INSERT INTO agentmesh_kv (key, value, expires_at) "
                    "VALUES (:key, :value, NULL) "
                    "ON CONFLICT (key) DO UPDATE SET value = :value, expires_at = NULL",
                    {"key": key, "value": value},
                )
            await session.commit()
        return True

    async def delete(self, key: str) -> bool:
        """Delete key."""
        async with self._session_factory() as session:
            result = await session.execute(
                "DELETE FROM agentmesh_kv WHERE key = :key",
                {"key": key},
            )
            await session.commit()
            return result.rowcount > 0

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        result = await self.get(key)
        return result is not None

    # Hash Operations

    async def hget(self, key: str, field: str) -> Optional[str]:
        """Get hash field value."""
        async with self._session_factory() as session:
            result = await session.execute(
                "SELECT value FROM agentmesh_hash WHERE key = :key AND field = :field",
                {"key": key, "field": field},
            )
            row = result.fetchone()
            return row[0] if row else None

    async def hset(self, key: str, field: str, value: str) -> bool:
        """Set hash field value."""
        async with self._session_factory() as session:
            await session.execute(
                "INSERT INTO agentmesh_hash (key, field, value) "
                "VALUES (:key, :field, :value) "
                "ON CONFLICT (key, field) DO UPDATE SET value = :value",
                {"key": key, "field": field, "value": value},
            )
            await session.commit()
        return True

    async def hgetall(self, key: str) -> dict[str, str]:
        """Get all hash fields."""
        async with self._session_factory() as session:
            result = await session.execute(
                "SELECT field, value FROM agentmesh_hash WHERE key = :key",
                {"key": key},
            )
            return {row[0]: row[1] for row in result.fetchall()}

    async def hdel(self, key: str, field: str) -> bool:
        """Delete hash field."""
        async with self._session_factory() as session:
            result = await session.execute(
                "DELETE FROM agentmesh_hash WHERE key = :key AND field = :field",
                {"key": key, "field": field},
            )
            await session.commit()
            return result.rowcount > 0

    async def hkeys(self, key: str) -> list[str]:
        """Get all hash field names."""
        async with self._session_factory() as session:
            result = await session.execute(
                "SELECT field FROM agentmesh_hash WHERE key = :key",
                {"key": key},
            )
            return [row[0] for row in result.fetchall()]

    # List Operations

    async def lpush(self, key: str, value: str) -> int:
        """Push value to head of list."""
        async with self._session_factory() as session:
            # Shift all indices up
            await session.execute(
                "UPDATE agentmesh_list SET idx = idx + 1 WHERE key = :key",
                {"key": key},
            )
            # Insert at position 0
            await session.execute(
                "INSERT INTO agentmesh_list (key, idx, value) VALUES (:key, 0, :value)",
                {"key": key, "value": value},
            )
            await session.commit()
            # Get new length
            result = await session.execute(
                "SELECT COUNT(*) FROM agentmesh_list WHERE key = :key",
                {"key": key},
            )
            return result.scalar()

    async def rpush(self, key: str, value: str) -> int:
        """Push value to tail of list."""
        async with self._session_factory() as session:
            # Get max index
            result = await session.execute(
                "SELECT COALESCE(MAX(idx), -1) FROM agentmesh_list WHERE key = :key",
                {"key": key},
            )
            max_idx = result.scalar()
            # Insert at end
            await session.execute(
                "INSERT INTO agentmesh_list (key, idx, value) VALUES (:key, :idx, :value)",
                {"key": key, "idx": max_idx + 1, "value": value},
            )
            await session.commit()
            return max_idx + 2

    async def lrange(self, key: str, start: int, stop: int) -> list[str]:
        """Get list range [start, stop]."""
        async with self._session_factory() as session:
            if stop == -1:
                result = await session.execute(
                    "SELECT value FROM agentmesh_list WHERE key = :key AND idx >= :start ORDER BY idx",
                    {"key": key, "start": start},
                )
            else:
                result = await session.execute(
                    "SELECT value FROM agentmesh_list WHERE key = :key AND idx >= :start AND idx <= :stop ORDER BY idx",
                    {"key": key, "start": start, "stop": stop},
                )
            return [row[0] for row in result.fetchall()]

    async def llen(self, key: str) -> int:
        """Get list length."""
        async with self._session_factory() as session:
            result = await session.execute(
                "SELECT COUNT(*) FROM agentmesh_list WHERE key = :key",
                {"key": key},
            )
            return result.scalar()

    # Sorted Set Operations

    async def zadd(self, key: str, score: float, member: str) -> bool:
        """Add member to sorted set with score."""
        async with self._session_factory() as session:
            await session.execute(
                "INSERT INTO agentmesh_zset (key, member, score) "
                "VALUES (:key, :member, :score) "
                "ON CONFLICT (key, member) DO UPDATE SET score = :score",
                {"key": key, "member": member, "score": score},
            )
            await session.commit()
        return True

    async def zscore(self, key: str, member: str) -> Optional[float]:
        """Get score of member in sorted set."""
        async with self._session_factory() as session:
            result = await session.execute(
                "SELECT score FROM agentmesh_zset WHERE key = :key AND member = :member",
                {"key": key, "member": member},
            )
            row = result.fetchone()
            return row[0] if row else None

    async def zrange(
        self,
        key: str,
        start: int,
        stop: int,
        with_scores: bool = False,
    ) -> list[str] | list[tuple[str, float]]:
        """Get sorted set range."""
        async with self._session_factory() as session:
            if stop == -1:
                result = await session.execute(
                    "SELECT member, score FROM agentmesh_zset WHERE key = :key "
                    "ORDER BY score OFFSET :start",
                    {"key": key, "start": start},
                )
            else:
                result = await session.execute(
                    "SELECT member, score FROM agentmesh_zset WHERE key = :key "
                    "ORDER BY score LIMIT :limit OFFSET :start",
                    {"key": key, "start": start, "limit": stop - start + 1},
                )
            rows = result.fetchall()
            if with_scores:
                return [(row[0], row[1]) for row in rows]
            return [row[0] for row in rows]

    async def zrangebyscore(
        self,
        key: str,
        min_score: float,
        max_score: float,
        with_scores: bool = False,
    ) -> list[str] | list[tuple[str, float]]:
        """Get sorted set range by score."""
        async with self._session_factory() as session:
            result = await session.execute(
                "SELECT member, score FROM agentmesh_zset "
                "WHERE key = :key AND score >= :min AND score <= :max ORDER BY score",
                {"key": key, "min": min_score, "max": max_score},
            )
            rows = result.fetchall()
            if with_scores:
                return [(row[0], row[1]) for row in rows]
            return [row[0] for row in rows]

    # Atomic Operations

    async def incr(self, key: str) -> int:
        """Increment value atomically."""
        return await self.incrby(key, 1)

    async def decr(self, key: str) -> int:
        """Decrement value atomically."""
        return await self.incrby(key, -1)

    async def incrby(self, key: str, amount: int) -> int:
        """Increment value by amount."""
        async with self._session_factory() as session:
            # Use PostgreSQL's atomic UPDATE ... RETURNING
            result = await session.execute(
                "INSERT INTO agentmesh_kv (key, value) VALUES (:key, :amount) "
                "ON CONFLICT (key) DO UPDATE SET value = "
                "(CAST(agentmesh_kv.value AS INTEGER) + :amount)::TEXT "
                "RETURNING CAST(value AS INTEGER)",
                {"key": key, "amount": str(amount)},
            )
            await session.commit()
            return result.scalar()

    # Batch Operations

    async def mget(self, keys: list[str]) -> list[Optional[str]]:
        """Get multiple values."""
        async with self._session_factory() as session:
            result = await session.execute(
                "SELECT key, value FROM agentmesh_kv WHERE key = ANY(:keys) "
                "AND (expires_at IS NULL OR expires_at > NOW())",
                {"keys": keys},
            )
            values_dict = {row[0]: row[1] for row in result.fetchall()}
            return [values_dict.get(key) for key in keys]

    async def mset(self, mapping: dict[str, str]) -> bool:
        """Set multiple key-value pairs."""
        async with self._session_factory() as session:
            for key, value in mapping.items():
                await session.execute(
                    "INSERT INTO agentmesh_kv (key, value) VALUES (:key, :value) "
                    "ON CONFLICT (key) DO UPDATE SET value = :value",
                    {"key": key, "value": value},
                )
            await session.commit()
        return True

    # Pattern Operations

    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching pattern."""
        # Convert glob pattern to SQL LIKE pattern
        sql_pattern = pattern.replace("*", "%").replace("?", "_")
        async with self._session_factory() as session:
            result = await session.execute(
                "SELECT key FROM agentmesh_kv WHERE key LIKE :pattern "
                "AND (expires_at IS NULL OR expires_at > NOW())",
                {"pattern": sql_pattern},
            )
            return [row[0] for row in result.fetchall()]

    async def scan(
        self,
        cursor: int = 0,
        match: Optional[str] = None,
        count: int = 100,
    ) -> tuple[int, list[str]]:
        """Scan keys with cursor."""
        async with self._session_factory() as session:
            if match:
                sql_pattern = match.replace("*", "%").replace("?", "_")
                result = await session.execute(
                    "SELECT key FROM agentmesh_kv WHERE key LIKE :pattern "
                    "AND (expires_at IS NULL OR expires_at > NOW()) "
                    "ORDER BY key LIMIT :count OFFSET :cursor",
                    {"pattern": sql_pattern, "count": count, "cursor": cursor},
                )
            else:
                result = await session.execute(
                    "SELECT key FROM agentmesh_kv "
                    "WHERE expires_at IS NULL OR expires_at > NOW() "
                    "ORDER BY key LIMIT :count OFFSET :cursor",
                    {"count": count, "cursor": cursor},
                )
            keys = [row[0] for row in result.fetchall()]
            new_cursor = cursor + count if len(keys) == count else 0
            return new_cursor, keys
