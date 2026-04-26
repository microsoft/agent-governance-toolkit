# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Context Caching module."""

import pytest
import time
from datetime import datetime, timezone, timedelta

from caas.caching import (
    ContextCache,
    CacheConfig,
    CacheEntry,
    CacheResult,
    CacheType,
    CacheProvider,
    CacheStats,
    AnthropicCacheStrategy,
    OpenAICacheStrategy,
    LocalCacheStrategy,
    LRUCache,
    create_cache,
)


class TestCacheConfig:
    """Tests for CacheConfig."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = CacheConfig()
        
        assert config.ttl_seconds == 3600
        assert config.max_entries == 1000
        assert config.min_tokens_for_caching == 1024
        assert config.semantic_threshold == 0.95
        assert config.enable_provider_cache is True
        assert config.enable_local_cache is True
        assert config.track_costs is True
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = CacheConfig(
            ttl_seconds=7200,
            max_entries=500,
            min_tokens_for_caching=2048,
        )
        
        assert config.ttl_seconds == 7200
        assert config.max_entries == 500
        assert config.min_tokens_for_caching == 2048


class TestCacheEntry:
    """Tests for CacheEntry."""
    
    def test_create_entry(self):
        """Test creating a cache entry."""
        now = datetime.now(timezone.utc)
        entry = CacheEntry(
            key="test-key",
            content="Test content",
            metadata={"source": "test"},
            created_at=now,
            last_accessed=now,
            token_count=100,
        )
        
        assert entry.key == "test-key"
        assert entry.content == "Test content"
        assert entry.access_count == 1
        assert entry.token_count == 100
    
    def test_entry_expiration(self):
        """Test entry expiration check."""
        # Create entry that's 2 hours old
        old_time = datetime.now(timezone.utc) - timedelta(hours=2)
        entry = CacheEntry(
            key="test",
            content="content",
            metadata={},
            created_at=old_time,
            last_accessed=old_time,
        )
        
        # Should be expired with 1 hour TTL
        assert entry.is_expired(3600) is True
        
        # Should not be expired with 3 hour TTL
        assert entry.is_expired(10800) is False


class TestLRUCache:
    """Tests for LRUCache."""
    
    def test_basic_put_get(self):
        """Test basic put and get operations."""
        cache = LRUCache(max_size=10)
        now = datetime.now(timezone.utc)
        
        entry = CacheEntry(
            key="key1",
            content="value1",
            metadata={},
            created_at=now,
            last_accessed=now,
        )
        cache.put(entry)
        
        result = cache.get("key1", ttl_seconds=3600)
        assert result is not None
        assert result.content == "value1"
    
    def test_get_nonexistent(self):
        """Test getting a nonexistent key."""
        cache = LRUCache(max_size=10)
        
        result = cache.get("nonexistent", ttl_seconds=3600)
        assert result is None
    
    def test_lru_eviction(self):
        """Test LRU eviction when at capacity."""
        cache = LRUCache(max_size=3)
        now = datetime.now(timezone.utc)
        
        # Add 3 entries
        for i in range(3):
            entry = CacheEntry(
                key=f"key{i}",
                content=f"value{i}",
                metadata={},
                created_at=now,
                last_accessed=now,
            )
            cache.put(entry)
        
        assert len(cache) == 3
        
        # Add 4th entry - should evict oldest (key0)
        entry4 = CacheEntry(
            key="key3",
            content="value3",
            metadata={},
            created_at=now,
            last_accessed=now,
        )
        cache.put(entry4)
        
        assert len(cache) == 3
        assert cache.get("key0", 3600) is None  # Evicted
        assert cache.get("key3", 3600) is not None  # Present
    
    def test_access_updates_order(self):
        """Test that accessing an entry moves it to the end."""
        cache = LRUCache(max_size=3)
        now = datetime.now(timezone.utc)
        
        # Add 3 entries
        for i in range(3):
            entry = CacheEntry(
                key=f"key{i}",
                content=f"value{i}",
                metadata={},
                created_at=now,
                last_accessed=now,
            )
            cache.put(entry)
        
        # Access key0 (moves it to end)
        cache.get("key0", 3600)
        
        # Add new entry - should evict key1 (now oldest)
        entry = CacheEntry(
            key="key3",
            content="value3",
            metadata={},
            created_at=now,
            last_accessed=now,
        )
        cache.put(entry)
        
        assert cache.get("key0", 3600) is not None  # Still present
        assert cache.get("key1", 3600) is None  # Evicted
    
    def test_remove(self):
        """Test removing an entry."""
        cache = LRUCache(max_size=10)
        now = datetime.now(timezone.utc)
        
        entry = CacheEntry(
            key="key1",
            content="value1",
            metadata={},
            created_at=now,
            last_accessed=now,
        )
        cache.put(entry)
        
        assert cache.remove("key1") is True
        assert cache.get("key1", 3600) is None
        assert cache.remove("key1") is False  # Already removed
    
    def test_clear(self):
        """Test clearing the cache."""
        cache = LRUCache(max_size=10)
        now = datetime.now(timezone.utc)
        
        for i in range(5):
            entry = CacheEntry(
                key=f"key{i}",
                content=f"value{i}",
                metadata={},
                created_at=now,
                last_accessed=now,
            )
            cache.put(entry)
        
        assert len(cache) == 5
        
        cache.clear()
        
        assert len(cache) == 0
    
    def test_cleanup_expired(self):
        """Test cleaning up expired entries."""
        cache = LRUCache(max_size=10)
        now = datetime.now(timezone.utc)
        old = now - timedelta(hours=2)
        
        # Add old entry
        entry1 = CacheEntry(
            key="old",
            content="old value",
            metadata={},
            created_at=old,
            last_accessed=old,
        )
        cache.put(entry1)
        
        # Add new entry
        entry2 = CacheEntry(
            key="new",
            content="new value",
            metadata={},
            created_at=now,
            last_accessed=now,
        )
        cache.put(entry2)
        
        # Cleanup with 1 hour TTL
        removed = cache.cleanup_expired(3600)
        
        assert removed == 1
        assert cache.get("old", 3600) is None
        assert cache.get("new", 3600) is not None


class TestAnthropicCacheStrategy:
    """Tests for AnthropicCacheStrategy."""
    
    def test_provider(self):
        """Test provider identification."""
        strategy = AnthropicCacheStrategy()
        assert strategy.provider == CacheProvider.ANTHROPIC
    
    def test_prepare_messages_with_large_context(self):
        """Test message preparation with large context (should add cache_control)."""
        strategy = AnthropicCacheStrategy()
        
        # Create large context (> 1024 tokens ≈ 4096 chars)
        large_context = "x" * 5000
        
        messages = strategy.prepare_messages(
            system_prompt="You are a helpful assistant.",
            context=large_context,
            messages=[{"role": "user", "content": "Hello"}],
        )
        
        # Should have system message with cache_control
        assert len(messages) >= 2
        system_msg = messages[0]
        assert system_msg["role"] == "system"
        
        # Check for cache_control in content blocks
        content = system_msg["content"]
        assert isinstance(content, list)
        
        # At least one block should have cache_control
        has_cache_control = any(
            "cache_control" in block
            for block in content
            if isinstance(block, dict)
        )
        assert has_cache_control is True
    
    def test_prepare_messages_with_small_context(self):
        """Test message preparation with small context (no cache_control)."""
        strategy = AnthropicCacheStrategy()
        
        # Small context (< 1024 tokens)
        small_context = "Short context"
        
        messages = strategy.prepare_messages(
            system_prompt="Assistant",
            context=small_context,
            messages=[],
        )
        
        # Should not have cache_control for small content
        system_msg = messages[0]
        content = system_msg["content"]
        
        has_cache_control = any(
            "cache_control" in block
            for block in content
            if isinstance(block, dict)
        )
        assert has_cache_control is False
    
    def test_estimate_savings_cached(self):
        """Test savings estimation for cached content."""
        strategy = AnthropicCacheStrategy()
        
        # 10,000 tokens cached
        tokens_saved, cost_saved = strategy.estimate_savings(10000, is_cached=True)
        
        # Should have significant savings (90% of tokens)
        assert tokens_saved == 9000  # 90% of 10000
        assert cost_saved > 0
    
    def test_estimate_savings_not_cached(self):
        """Test savings estimation for non-cached content."""
        strategy = AnthropicCacheStrategy()
        
        tokens_saved, cost_saved = strategy.estimate_savings(10000, is_cached=False)
        
        assert tokens_saved == 0
        assert cost_saved == 0.0
    
    def test_estimate_savings_small_context(self):
        """Test that small contexts show no savings."""
        strategy = AnthropicCacheStrategy()
        
        # Below minimum threshold
        tokens_saved, cost_saved = strategy.estimate_savings(500, is_cached=True)
        
        assert tokens_saved == 0
        assert cost_saved == 0.0


class TestOpenAICacheStrategy:
    """Tests for OpenAICacheStrategy."""
    
    def test_provider(self):
        """Test provider identification."""
        strategy = OpenAICacheStrategy()
        assert strategy.provider == CacheProvider.OPENAI
    
    def test_prepare_messages(self):
        """Test message preparation (no special formatting for OpenAI)."""
        strategy = OpenAICacheStrategy()
        
        messages = strategy.prepare_messages(
            system_prompt="You are helpful.",
            context="Some context here.",
            messages=[{"role": "user", "content": "Hi"}],
        )
        
        # Should have system message
        assert messages[0]["role"] == "system"
        # Content should be combined string (not list)
        assert isinstance(messages[0]["content"], str)
        assert "You are helpful" in messages[0]["content"]
        assert "Some context" in messages[0]["content"]
    
    def test_estimate_savings(self):
        """Test savings estimation (50% for OpenAI)."""
        strategy = OpenAICacheStrategy()
        
        tokens_saved, cost_saved = strategy.estimate_savings(10000, is_cached=True)
        
        # 50% savings for OpenAI
        assert tokens_saved == 5000
        assert cost_saved > 0


class TestLocalCacheStrategy:
    """Tests for LocalCacheStrategy."""
    
    def test_provider(self):
        """Test provider identification."""
        strategy = LocalCacheStrategy()
        assert strategy.provider == CacheProvider.LOCAL
    
    def test_estimate_savings(self):
        """Test savings estimation (100% for local cache)."""
        strategy = LocalCacheStrategy()
        
        tokens_saved, cost_saved = strategy.estimate_savings(10000, is_cached=True)
        
        # 100% token savings for local cache
        assert tokens_saved == 10000
        assert cost_saved > 0


class TestContextCache:
    """Tests for ContextCache."""
    
    def test_create_default_cache(self):
        """Test creating cache with defaults."""
        cache = ContextCache()
        
        assert cache.strategy.provider == CacheProvider.LOCAL
        assert cache.config.ttl_seconds == 3600
    
    def test_create_cache_with_strategy(self):
        """Test creating cache with specific strategy."""
        cache = ContextCache(strategy=AnthropicCacheStrategy())
        
        assert cache.strategy.provider == CacheProvider.ANTHROPIC
    
    def test_compute_key(self):
        """Test cache key computation."""
        cache = ContextCache()
        
        key1 = cache.compute_key("test content")
        key2 = cache.compute_key("test content")
        key3 = cache.compute_key("different content")
        
        assert key1 == key2  # Same content = same key
        assert key1 != key3  # Different content = different key
    
    def test_compute_key_with_metadata(self):
        """Test key computation includes metadata."""
        cache = ContextCache()
        
        key1 = cache.compute_key("content", metadata={"model": "gpt-4"})
        key2 = cache.compute_key("content", metadata={"model": "gpt-3.5"})
        
        assert key1 != key2  # Different metadata = different key
    
    def test_lookup_miss_small_context(self):
        """Test lookup returns miss for small contexts."""
        cache = ContextCache(config=CacheConfig(min_tokens_for_caching=100))
        
        # Small context (< 100 tokens)
        result = cache.lookup("short")
        
        assert result.cache_type == CacheType.MISS
    
    def test_store_and_lookup(self):
        """Test storing and looking up content."""
        cache = ContextCache(
            config=CacheConfig(
                min_tokens_for_caching=10,  # Low threshold for testing
                enable_provider_cache=False,  # Only local
            )
        )
        
        # Large enough context
        context = "x" * 100
        
        # Store
        key = cache.store(context, response="cached response")
        
        # Lookup
        result = cache.lookup(context)
        
        assert result.cache_type == CacheType.LOCAL_EXACT
        assert result.cached_content == "cached response"
    
    def test_prepare_messages(self):
        """Test message preparation delegates to strategy."""
        cache = ContextCache(strategy=AnthropicCacheStrategy())
        
        messages = cache.prepare_messages(
            system_prompt="Hello",
            context="Context",
            messages=[{"role": "user", "content": "Hi"}],
        )
        
        assert len(messages) >= 1
    
    def test_invalidate(self):
        """Test cache invalidation."""
        cache = ContextCache(
            config=CacheConfig(
                min_tokens_for_caching=10,
                enable_provider_cache=False,
            )
        )
        
        context = "x" * 100
        key = cache.store(context)
        
        # Should find it
        result = cache.lookup(context)
        assert result.cache_type == CacheType.LOCAL_EXACT
        
        # Invalidate
        assert cache.invalidate(key) is True
        
        # Should not find it anymore
        result = cache.lookup(context)
        assert result.cache_type == CacheType.MISS
    
    def test_clear(self):
        """Test clearing cache."""
        cache = ContextCache(
            config=CacheConfig(
                min_tokens_for_caching=10,
                enable_provider_cache=False,
            )
        )
        
        # Store some entries
        for i in range(5):
            cache.store(f"content {i}" * 20)
        
        stats = cache.get_stats()
        assert stats["current_entries"] > 0
        
        # Clear
        cache.clear()
        
        stats = cache.get_stats()
        assert stats["current_entries"] == 0
    
    def test_get_stats(self):
        """Test getting cache statistics."""
        cache = ContextCache(
            config=CacheConfig(
                min_tokens_for_caching=10,
                enable_provider_cache=False,
            )
        )
        
        context = "x" * 100
        cache.store(context)
        cache.lookup(context)
        cache.lookup(context)
        
        stats = cache.get_stats()
        
        assert stats["total_requests"] == 2
        assert stats["local_exact_hits"] == 2
        assert stats["hit_rate"] == 1.0
    
    def test_reset_stats(self):
        """Test resetting statistics."""
        cache = ContextCache()
        
        # Generate some stats
        cache.lookup("x" * 5000)
        
        # Reset
        cache.reset_stats()
        
        stats = cache.get_stats()
        assert stats["total_requests"] == 0


class TestCacheStats:
    """Tests for CacheStats."""
    
    def test_hit_rate_calculation(self):
        """Test hit rate calculation."""
        stats = CacheStats(
            total_requests=100,
            provider_hits=30,
            local_exact_hits=20,
            local_semantic_hits=10,
            misses=40,
        )
        
        # 60 hits out of 100 = 60%
        assert stats.hit_rate == 0.6
    
    def test_hit_rate_zero_requests(self):
        """Test hit rate with zero requests."""
        stats = CacheStats()
        
        assert stats.hit_rate == 0.0
    
    def test_to_dict(self):
        """Test serialization."""
        stats = CacheStats(
            total_requests=10,
            provider_hits=5,
        )
        
        d = stats.to_dict()
        
        assert d["total_requests"] == 10
        assert d["provider_hits"] == 5
        assert "hit_rate" in d


class TestCreateCache:
    """Tests for create_cache convenience function."""
    
    def test_create_anthropic_cache(self):
        """Test creating Anthropic cache."""
        cache = create_cache("anthropic")
        
        assert cache.strategy.provider == CacheProvider.ANTHROPIC
    
    def test_create_openai_cache(self):
        """Test creating OpenAI cache."""
        cache = create_cache("openai")
        
        assert cache.strategy.provider == CacheProvider.OPENAI
    
    def test_create_local_cache(self):
        """Test creating local cache."""
        cache = create_cache("local")
        
        assert cache.strategy.provider == CacheProvider.LOCAL
    
    def test_create_cache_with_config(self):
        """Test creating cache with custom config."""
        cache = create_cache("anthropic", ttl_seconds=7200, max_entries=500)
        
        assert cache.config.ttl_seconds == 7200
        assert cache.config.max_entries == 500
    
    def test_create_cache_with_enum(self):
        """Test creating cache with CacheProvider enum."""
        cache = create_cache(CacheProvider.OPENAI)
        
        assert cache.strategy.provider == CacheProvider.OPENAI
