# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Abstract Storage Provider Interface.

Defines the contract that all storage backends must implement.
"""

from abc import ABC, abstractmethod
from typing import Optional
from pydantic import BaseModel, Field


class StorageConfig(BaseModel):
    """Configuration for storage provider."""

    backend: str = Field(default="memory", description="Storage backend type")
    connection_string: Optional[str] = Field(default=None, description="Connection string")
    pool_size: int = Field(default=10, ge=1, le=100, description="Connection pool size")
    timeout_seconds: int = Field(default=30, ge=1, le=300, description="Operation timeout")

    # Redis-specific
    redis_host: Optional[str] = Field(default="localhost")
    redis_port: int = Field(default=6379, ge=1, le=65535)
    redis_db: int = Field(default=0, ge=0)
    redis_password: Optional[str] = None
    redis_ssl: bool = False

    # PostgreSQL-specific
    postgres_host: Optional[str] = Field(default="localhost")
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_database: Optional[str] = Field(default="agentmesh")
    postgres_user: Optional[str] = None
    postgres_password: Optional[str] = None
    postgres_ssl_mode: str = Field(default="prefer")

    # Cache settings
    cache_ttl_seconds: int = Field(default=300, ge=0)
    enable_cache: bool = True


class AbstractStorageProvider(ABC):
    """
    Abstract storage provider.

    All storage backends (Redis, Postgres, etc.) must implement this interface.
    Supports:
    - Key-value operations
    - Hash operations (for structured data)
    - List operations (for audit logs, events)
    - TTL support
    - Async operations
    """

    def __init__(self, config: StorageConfig):
        """Initialize storage provider with configuration."""
        self.config = config

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to storage backend."""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to storage backend."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if storage backend is healthy."""
        pass

    # Key-Value Operations

    @abstractmethod
    async def get(self, key: str) -> Optional[str]:
        """Get value by key."""
        pass

    @abstractmethod
    async def set(
        self,
        key: str,
        value: str,
        ttl_seconds: Optional[int] = None,
    ) -> bool:
        """Set value with optional TTL."""
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete key."""
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        pass

    # Hash Operations (for structured data)

    @abstractmethod
    async def hget(self, key: str, field: str) -> Optional[str]:
        """Get hash field value."""
        pass

    @abstractmethod
    async def hset(self, key: str, field: str, value: str) -> bool:
        """Set hash field value."""
        pass

    @abstractmethod
    async def hgetall(self, key: str) -> dict[str, str]:
        """Get all hash fields."""
        pass

    @abstractmethod
    async def hdel(self, key: str, field: str) -> bool:
        """Delete hash field."""
        pass

    @abstractmethod
    async def hkeys(self, key: str) -> list[str]:
        """Get all hash field names."""
        pass

    # List Operations (for audit logs, events)

    @abstractmethod
    async def lpush(self, key: str, value: str) -> int:
        """Push value to head of list. Returns new list length."""
        pass

    @abstractmethod
    async def rpush(self, key: str, value: str) -> int:
        """Push value to tail of list. Returns new list length."""
        pass

    @abstractmethod
    async def lrange(self, key: str, start: int, stop: int) -> list[str]:
        """Get list range [start, stop]."""
        pass

    @abstractmethod
    async def llen(self, key: str) -> int:
        """Get list length."""
        pass

    # Sorted Set Operations (for trust scores)

    @abstractmethod
    async def zadd(
        self,
        key: str,
        score: float,
        member: str,
    ) -> bool:
        """Add member to sorted set with score."""
        pass

    @abstractmethod
    async def zscore(self, key: str, member: str) -> Optional[float]:
        """Get score of member in sorted set."""
        pass

    @abstractmethod
    async def zrange(
        self,
        key: str,
        start: int,
        stop: int,
        with_scores: bool = False,
    ) -> list[str] | list[tuple[str, float]]:
        """Get sorted set range."""
        pass

    @abstractmethod
    async def zrangebyscore(
        self,
        key: str,
        min_score: float,
        max_score: float,
        with_scores: bool = False,
    ) -> list[str] | list[tuple[str, float]]:
        """Get sorted set range by score."""
        pass

    # Atomic Operations

    @abstractmethod
    async def incr(self, key: str) -> int:
        """Increment value atomically. Returns new value."""
        pass

    @abstractmethod
    async def decr(self, key: str) -> int:
        """Decrement value atomically. Returns new value."""
        pass

    @abstractmethod
    async def incrby(self, key: str, amount: int) -> int:
        """Increment value by amount. Returns new value."""
        pass

    # Batch Operations

    @abstractmethod
    async def mget(self, keys: list[str]) -> list[Optional[str]]:
        """Get multiple values."""
        pass

    @abstractmethod
    async def mset(self, mapping: dict[str, str]) -> bool:
        """Set multiple key-value pairs."""
        pass

    # Pattern Operations

    @abstractmethod
    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching pattern."""
        pass

    @abstractmethod
    async def scan(
        self,
        cursor: int = 0,
        match: Optional[str] = None,
        count: int = 100,
    ) -> tuple[int, list[str]]:
        """Scan keys with cursor. Returns (new_cursor, keys)."""
        pass
