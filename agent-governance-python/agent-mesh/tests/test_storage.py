# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for storage providers.

Tests the abstract storage interface and concrete implementations.
"""

from types import SimpleNamespace

import pytest

from agentmesh.storage import (
    AbstractStorageProvider,
    MemoryStorageProvider,
    StorageConfig,
)
from agentmesh.storage import memory_provider as memory_provider_module


@pytest.fixture
async def memory_provider():
    """Create and connect a memory storage provider."""
    config = StorageConfig(backend="memory")
    provider = MemoryStorageProvider(config)
    await provider.connect()
    yield provider
    await provider.disconnect()


class TestMemoryStorageProvider:
    """Test MemoryStorageProvider."""
    
    @pytest.mark.asyncio
    async def test_connect_disconnect(self, memory_provider):
        """Test connection lifecycle."""
        assert await memory_provider.health_check()
        await memory_provider.disconnect()
        assert not await memory_provider.health_check()
    
    @pytest.mark.asyncio
    async def test_key_value_operations(self, memory_provider):
        """Test basic key-value operations."""
        # Set and get
        assert await memory_provider.set("test_key", "test_value")
        assert await memory_provider.get("test_key") == "test_value"
        
        # Exists
        assert await memory_provider.exists("test_key")
        assert not await memory_provider.exists("nonexistent")
        
        # Delete
        assert await memory_provider.delete("test_key")
        assert not await memory_provider.exists("test_key")
        assert await memory_provider.get("test_key") is None
    
    @pytest.mark.asyncio
    async def test_hash_operations(self, memory_provider):
        """Test hash operations."""
        # Set hash fields
        assert await memory_provider.hset("user:1", "name", "Alice")
        assert await memory_provider.hset("user:1", "email", "alice@example.com")
        
        # Get hash field
        assert await memory_provider.hget("user:1", "name") == "Alice"
        assert await memory_provider.hget("user:1", "email") == "alice@example.com"
        
        # Get all hash fields
        all_fields = await memory_provider.hgetall("user:1")
        assert all_fields == {"name": "Alice", "email": "alice@example.com"}
        
        # Get hash keys
        keys = await memory_provider.hkeys("user:1")
        assert set(keys) == {"name", "email"}
        
        # Delete hash field
        assert await memory_provider.hdel("user:1", "email")
        assert await memory_provider.hget("user:1", "email") is None
        assert await memory_provider.hget("user:1", "name") == "Alice"
    
    @pytest.mark.asyncio
    async def test_list_operations(self, memory_provider):
        """Test list operations."""
        # Push to head
        assert await memory_provider.lpush("mylist", "item1") == 1
        assert await memory_provider.lpush("mylist", "item2") == 2
        
        # Push to tail
        assert await memory_provider.rpush("mylist", "item3") == 3
        
        # Get list length
        assert await memory_provider.llen("mylist") == 3
        
        # Get range
        items = await memory_provider.lrange("mylist", 0, -1)
        assert items == ["item2", "item1", "item3"]
        
        # Get partial range
        items = await memory_provider.lrange("mylist", 0, 1)
        assert items == ["item2", "item1"]
    
    @pytest.mark.asyncio
    async def test_sorted_set_operations(self, memory_provider):
        """Test sorted set operations."""
        # Add members with scores
        assert await memory_provider.zadd("leaderboard", 100.0, "alice")
        assert await memory_provider.zadd("leaderboard", 200.0, "bob")
        assert await memory_provider.zadd("leaderboard", 150.0, "charlie")
        
        # Get score
        assert await memory_provider.zscore("leaderboard", "bob") == 200.0
        
        # Get range (ascending by score)
        members = await memory_provider.zrange("leaderboard", 0, -1)
        assert members == ["alice", "charlie", "bob"]
        
        # Get range with scores
        members_with_scores = await memory_provider.zrange("leaderboard", 0, -1, with_scores=True)
        assert members_with_scores == [
            ("alice", 100.0),
            ("charlie", 150.0),
            ("bob", 200.0),
        ]
        
        # Get range by score
        members = await memory_provider.zrangebyscore("leaderboard", 100.0, 150.0)
        assert members == ["alice", "charlie"]
    
    @pytest.mark.asyncio
    async def test_atomic_operations(self, memory_provider):
        """Test atomic increment/decrement operations."""
        # Increment
        assert await memory_provider.incr("counter") == 1
        assert await memory_provider.incr("counter") == 2
        
        # Increment by amount
        assert await memory_provider.incrby("counter", 5) == 7
        
        # Decrement
        assert await memory_provider.decr("counter") == 6
    
    @pytest.mark.asyncio
    async def test_batch_operations(self, memory_provider):
        """Test batch get/set operations."""
        # Multi-set
        await memory_provider.mset({
            "key1": "value1",
            "key2": "value2",
            "key3": "value3",
        })
        
        # Multi-get
        values = await memory_provider.mget(["key1", "key2", "key3", "nonexistent"])
        assert values == ["value1", "value2", "value3", None]
    
    @pytest.mark.asyncio
    async def test_pattern_operations(self, memory_provider):
        """Test pattern matching operations."""
        # Set some keys
        await memory_provider.set("user:1", "alice")
        await memory_provider.set("user:2", "bob")
        await memory_provider.set("admin:1", "charlie")
        
        # Find keys by pattern
        user_keys = await memory_provider.keys("user:*")
        assert set(user_keys) == {"user:1", "user:2"}
        
        # Scan keys
        cursor, keys = await memory_provider.scan(cursor=0, match="user:*", count=10)
        assert set(keys) == {"user:1", "user:2"}
    
    @pytest.mark.asyncio
    async def test_ttl_operations(self, memory_provider):
        """Test TTL (time-to-live) operations."""
        # Set with TTL
        assert await memory_provider.set("temp_key", "temp_value", ttl_seconds=1)
        assert await memory_provider.exists("temp_key")

    @pytest.fixture
    def clock(self, monkeypatch):
        """Replace the memory provider's clock with a settable one."""
        now = [1_000.0]
        monkeypatch.setattr(
            memory_provider_module, "time", SimpleNamespace(time=lambda: now[0]), raising=False
        )
        return now

    @pytest.mark.asyncio
    async def test_ttl_expires_key(self, memory_provider, clock):
        """A key set with a TTL is gone once the TTL has passed."""
        await memory_provider.set("temp_key", "temp_value", ttl_seconds=10)
        await memory_provider.set("kept_key", "kept_value")

        clock[0] += 9
        assert await memory_provider.get("temp_key") == "temp_value"

        clock[0] += 1
        assert await memory_provider.get("temp_key") is None
        assert not await memory_provider.exists("temp_key")
        assert await memory_provider.mget(["temp_key", "kept_key"]) == [None, "kept_value"]
        assert await memory_provider.keys("*") == ["kept_key"]
        assert await memory_provider.scan(match="*") == (0, ["kept_key"])
        assert not await memory_provider.delete("temp_key")

    @pytest.mark.asyncio
    async def test_set_without_ttl_clears_previous_ttl(self, memory_provider, clock):
        """Like Redis SET and MSET, a write without a TTL makes the key persistent."""
        await memory_provider.set("set_key", "old", ttl_seconds=10)
        await memory_provider.set("set_key", "new")
        await memory_provider.set("mset_key", "old", ttl_seconds=10)
        await memory_provider.mset({"mset_key": "new"})

        clock[0] += 60
        assert await memory_provider.get("set_key") == "new"
        assert await memory_provider.get("mset_key") == "new"

    @pytest.mark.asyncio
    async def test_delete_clears_ttl(self, memory_provider, clock):
        """A key recreated after delete does not inherit the deleted key's TTL."""
        await memory_provider.set("temp_key", "old", ttl_seconds=10)
        assert await memory_provider.delete("temp_key")
        await memory_provider.incr("temp_key")

        clock[0] += 60
        assert await memory_provider.get("temp_key") == "1"

    @pytest.mark.asyncio
    async def test_incr_after_expiry_starts_from_zero(self, memory_provider, clock):
        """Incrementing an expired counter starts a new one, as in Redis."""
        await memory_provider.set("counter", "5", ttl_seconds=10)
        clock[0] += 10
        assert await memory_provider.incr("counter") == 1


@pytest.mark.skip(reason="Requires Redis server")
class TestRedisStorageProvider:
    """Test RedisStorageProvider (requires running Redis)."""
    
    @pytest.fixture
    async def redis_provider(self):
        """Create and connect a Redis storage provider."""
        from agentmesh.storage import RedisStorageProvider
        
        config = StorageConfig(
            backend="redis",
            redis_host="localhost",
            redis_port=6379,
        )
        provider = RedisStorageProvider(config)
        await provider.connect()
        yield provider
        await provider.disconnect()
    
    @pytest.mark.asyncio
    async def test_redis_connection(self, redis_provider):
        """Test Redis connection."""
        assert await redis_provider.health_check()


@pytest.mark.skip(reason="Requires PostgreSQL server")
class TestPostgresStorageProvider:
    """Test PostgresStorageProvider (requires running PostgreSQL)."""
    
    @pytest.fixture
    async def postgres_provider(self):
        """Create and connect a PostgreSQL storage provider."""
        from agentmesh.storage import PostgresStorageProvider
        
        config = StorageConfig(
            backend="postgres",
            postgres_host="localhost",
            postgres_port=5432,
            postgres_database="agentmesh_test",
            postgres_user="agentmesh",
            # Test-only password — not for production use
            postgres_password="test-only-not-for-production",
        )
        provider = PostgresStorageProvider(config)
        await provider.connect()
        yield provider
        await provider.disconnect()
    
    @pytest.mark.asyncio
    async def test_postgres_connection(self, postgres_provider):
        """Test PostgreSQL connection."""
        assert await postgres_provider.health_check()
