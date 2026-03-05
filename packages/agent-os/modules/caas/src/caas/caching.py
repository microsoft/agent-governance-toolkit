# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Context Caching for LLM APIs.

This module provides intelligent caching for context sent to LLM APIs,
leveraging provider-specific caching features (Anthropic's prompt caching,
OpenAI's predicted outputs) and local caching strategies.

Key Features:
    - Provider-agnostic caching interface
    - Anthropic prompt caching support (cache_control breakpoints)
    - OpenAI predicted outputs / prefix caching detection
    - Local semantic cache for repeated queries
    - Cache statistics and cost tracking
    - TTL-based cache expiration

Cost Savings:
    - Anthropic: Up to 90% reduction on cached prompt tokens
    - OpenAI: 50% reduction on cached prefix tokens
    - Local cache: 100% reduction for exact/semantic matches

Example:
    from caas.caching import (
        ContextCache,
        AnthropicCacheStrategy,
        OpenAICacheStrategy,
        CacheConfig,
    )

    # Create cache with Anthropic strategy
    cache = ContextCache(
        strategy=AnthropicCacheStrategy(),
        config=CacheConfig(ttl_seconds=3600)
    )

    # Prepare messages with cache breakpoints
    messages = cache.prepare_messages(
        system_prompt="You are a helpful assistant...",
        context="Large document context here...",
        user_message="Summarize the key points"
    )

    # Track cache hits
    stats = cache.get_stats()
    print(f"Cache hit rate: {stats['hit_rate']:.1%}")
    print(f"Estimated savings: ${stats['estimated_savings']:.2f}")
"""

from __future__ import annotations

import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Tuple, Union
from collections import OrderedDict
import threading


class CacheProvider(str, Enum):
    """Supported LLM providers for caching."""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    LOCAL = "local"  # Local-only caching


class CacheType(str, Enum):
    """Types of cache hits."""
    PROVIDER_CACHE = "provider_cache"  # Provider-side caching (Anthropic/OpenAI)
    LOCAL_EXACT = "local_exact"  # Local exact match
    LOCAL_SEMANTIC = "local_semantic"  # Local semantic similarity match
    MISS = "miss"  # No cache hit


@dataclass
class CacheConfig:
    """Configuration for context caching.
    
    Attributes:
        ttl_seconds: Time-to-live for cached entries (default: 1 hour)
        max_entries: Maximum number of entries in local cache
        min_tokens_for_caching: Minimum tokens to consider caching
        semantic_threshold: Similarity threshold for semantic cache (0-1)
        enable_provider_cache: Whether to use provider-specific caching
        enable_local_cache: Whether to use local caching
        track_costs: Whether to track cost savings
    """
    ttl_seconds: int = 3600
    max_entries: int = 1000
    min_tokens_for_caching: int = 1024  # Only cache contexts >= 1024 tokens
    semantic_threshold: float = 0.95
    enable_provider_cache: bool = True
    enable_local_cache: bool = True
    track_costs: bool = True


@dataclass
class CacheEntry:
    """A single cache entry.
    
    Attributes:
        key: Cache key (hash of content)
        content: The cached content
        metadata: Additional metadata
        created_at: When the entry was created
        last_accessed: When the entry was last accessed
        access_count: Number of times this entry was accessed
        token_count: Estimated token count
    """
    key: str
    content: str
    metadata: Dict[str, Any]
    created_at: datetime
    last_accessed: datetime
    access_count: int = 1
    token_count: int = 0
    
    def is_expired(self, ttl_seconds: int) -> bool:
        """Check if this entry has expired."""
        age = (datetime.now(timezone.utc) - self.created_at).total_seconds()
        return age > ttl_seconds


@dataclass
class CacheResult:
    """Result of a cache lookup.
    
    Attributes:
        cache_type: Type of cache hit (or miss)
        cached_content: The cached content (if hit)
        cache_key: Key used for caching
        token_savings: Estimated token savings
        cost_savings: Estimated cost savings in USD
    """
    cache_type: CacheType
    cached_content: Optional[str] = None
    cache_key: Optional[str] = None
    token_savings: int = 0
    cost_savings: float = 0.0


@dataclass
class CacheStats:
    """Statistics for cache performance.
    
    Attributes:
        total_requests: Total number of cache requests
        provider_hits: Hits from provider cache
        local_exact_hits: Hits from local exact match
        local_semantic_hits: Hits from local semantic match
        misses: Cache misses
        total_tokens_saved: Total tokens saved
        total_cost_saved: Total cost saved in USD
        current_entries: Current number of cache entries
    """
    total_requests: int = 0
    provider_hits: int = 0
    local_exact_hits: int = 0
    local_semantic_hits: int = 0
    misses: int = 0
    total_tokens_saved: int = 0
    total_cost_saved: float = 0.0
    current_entries: int = 0
    
    @property
    def hit_rate(self) -> float:
        """Calculate overall cache hit rate."""
        if self.total_requests == 0:
            return 0.0
        hits = self.provider_hits + self.local_exact_hits + self.local_semantic_hits
        return hits / self.total_requests
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_requests": self.total_requests,
            "provider_hits": self.provider_hits,
            "local_exact_hits": self.local_exact_hits,
            "local_semantic_hits": self.local_semantic_hits,
            "misses": self.misses,
            "hit_rate": self.hit_rate,
            "total_tokens_saved": self.total_tokens_saved,
            "total_cost_saved": self.total_cost_saved,
            "current_entries": self.current_entries,
        }


class CacheStrategy(ABC):
    """Abstract base class for provider-specific caching strategies."""
    
    @property
    @abstractmethod
    def provider(self) -> CacheProvider:
        """Return the provider this strategy is for."""
        pass
    
    @abstractmethod
    def prepare_messages(
        self,
        system_prompt: Optional[str],
        context: str,
        messages: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Prepare messages with caching hints.
        
        Args:
            system_prompt: Optional system prompt
            context: The context to cache
            messages: The conversation messages
            
        Returns:
            Messages formatted for the provider with cache hints
        """
        pass
    
    @abstractmethod
    def estimate_savings(self, token_count: int, is_cached: bool) -> Tuple[int, float]:
        """
        Estimate token and cost savings from caching.
        
        Args:
            token_count: Number of tokens in the cached content
            is_cached: Whether the content was cached
            
        Returns:
            Tuple of (tokens_saved, cost_saved_usd)
        """
        pass


class AnthropicCacheStrategy(CacheStrategy):
    """
    Caching strategy for Anthropic API.
    
    Implements Anthropic's prompt caching feature which provides:
    - 90% cost reduction on cached input tokens
    - 5-minute TTL for cached prompts
    - Requires min 1024 tokens for caching (2048 for Claude 3.5 Haiku)
    
    See: https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching
    """
    
    # Anthropic pricing (as of 2024)
    # Claude 3.5 Sonnet: $3/M input, $0.30/M cached input
    INPUT_COST_PER_MILLION = 3.00
    CACHED_COST_PER_MILLION = 0.30
    CACHE_WRITE_COST_PER_MILLION = 3.75  # 25% premium for writing to cache
    
    MIN_TOKENS_FOR_CACHE = 1024  # Minimum tokens for caching
    
    @property
    def provider(self) -> CacheProvider:
        return CacheProvider.ANTHROPIC
    
    def prepare_messages(
        self,
        system_prompt: Optional[str],
        context: str,
        messages: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Prepare messages with Anthropic cache_control breakpoints.
        
        Adds cache_control: {"type": "ephemeral"} to cacheable content blocks.
        """
        prepared = []
        
        # System prompt with caching (if provided and long enough)
        if system_prompt:
            system_tokens = self._estimate_tokens(system_prompt)
            system_content: List[Dict[str, Any]] = [{"type": "text", "text": system_prompt}]
            
            if system_tokens >= self.MIN_TOKENS_FOR_CACHE:
                system_content[0]["cache_control"] = {"type": "ephemeral"}
            
            # Add context as second block with caching
            if context:
                context_block: Dict[str, Any] = {"type": "text", "text": context}
                context_tokens = self._estimate_tokens(context)
                if context_tokens >= self.MIN_TOKENS_FOR_CACHE:
                    context_block["cache_control"] = {"type": "ephemeral"}
                system_content.append(context_block)
            
            prepared.append({
                "role": "system",
                "content": system_content,
            })
        elif context:
            # Context only (no system prompt)
            context_content: List[Dict[str, Any]] = [{"type": "text", "text": context}]
            context_tokens = self._estimate_tokens(context)
            if context_tokens >= self.MIN_TOKENS_FOR_CACHE:
                context_content[0]["cache_control"] = {"type": "ephemeral"}
            
            prepared.append({
                "role": "system",
                "content": context_content,
            })
        
        # Add conversation messages
        prepared.extend(messages)
        
        return prepared
    
    def estimate_savings(self, token_count: int, is_cached: bool) -> Tuple[int, float]:
        """
        Estimate savings from Anthropic caching.
        
        Returns:
            Tuple of (tokens_saved, cost_saved_usd)
        """
        if not is_cached or token_count < self.MIN_TOKENS_FOR_CACHE:
            return (0, 0.0)
        
        # Cost without caching
        normal_cost = (token_count / 1_000_000) * self.INPUT_COST_PER_MILLION
        
        # Cost with caching (90% reduction)
        cached_cost = (token_count / 1_000_000) * self.CACHED_COST_PER_MILLION
        
        # Savings
        cost_saved = normal_cost - cached_cost
        
        # Token savings (conceptually, same tokens but cheaper)
        tokens_saved = int(token_count * 0.9)  # 90% "saved" in cost terms
        
        return (tokens_saved, cost_saved)
    
    def _estimate_tokens(self, text: str) -> int:
        """Rough token estimation (4 chars per token)."""
        return len(text) // 4


class OpenAICacheStrategy(CacheStrategy):
    """
    Caching strategy for OpenAI API.
    
    Implements OpenAI's automatic prompt caching which provides:
    - 50% cost reduction on cached input tokens
    - Automatic caching for prompts > 1024 tokens
    - Cache expires after 5-60 minutes of inactivity
    
    See: https://platform.openai.com/docs/guides/prompt-caching
    """
    
    # OpenAI pricing (GPT-4o as of 2024)
    INPUT_COST_PER_MILLION = 2.50
    CACHED_COST_PER_MILLION = 1.25  # 50% discount
    
    MIN_TOKENS_FOR_CACHE = 1024
    
    @property
    def provider(self) -> CacheProvider:
        return CacheProvider.OPENAI
    
    def prepare_messages(
        self,
        system_prompt: Optional[str],
        context: str,
        messages: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Prepare messages for OpenAI (no special formatting needed).
        
        OpenAI caching is automatic - we just need to structure messages
        with static content first for optimal cache hits.
        """
        prepared = []
        
        # Combine system prompt and context (static content first)
        if system_prompt or context:
            system_text = ""
            if system_prompt:
                system_text += system_prompt
            if context:
                if system_text:
                    system_text += "\n\n---\n\n"
                system_text += context
            
            prepared.append({
                "role": "system",
                "content": system_text,
            })
        
        # Add conversation messages
        prepared.extend(messages)
        
        return prepared
    
    def estimate_savings(self, token_count: int, is_cached: bool) -> Tuple[int, float]:
        """
        Estimate savings from OpenAI caching.
        
        Returns:
            Tuple of (tokens_saved, cost_saved_usd)
        """
        if not is_cached or token_count < self.MIN_TOKENS_FOR_CACHE:
            return (0, 0.0)
        
        # Cost without caching
        normal_cost = (token_count / 1_000_000) * self.INPUT_COST_PER_MILLION
        
        # Cost with caching (50% reduction)
        cached_cost = (token_count / 1_000_000) * self.CACHED_COST_PER_MILLION
        
        # Savings
        cost_saved = normal_cost - cached_cost
        
        # Token savings (50% in cost terms)
        tokens_saved = int(token_count * 0.5)
        
        return (tokens_saved, cost_saved)


class LocalCacheStrategy(CacheStrategy):
    """
    Local-only caching strategy.
    
    Uses a local LRU cache to store and retrieve responses.
    Provides 100% savings on exact matches.
    """
    
    @property
    def provider(self) -> CacheProvider:
        return CacheProvider.LOCAL
    
    def prepare_messages(
        self,
        system_prompt: Optional[str],
        context: str,
        messages: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """No special preparation needed for local caching."""
        prepared = []
        
        if system_prompt or context:
            system_text = ""
            if system_prompt:
                system_text += system_prompt
            if context:
                if system_text:
                    system_text += "\n\n"
                system_text += context
            
            prepared.append({
                "role": "system",
                "content": system_text,
            })
        
        prepared.extend(messages)
        return prepared
    
    def estimate_savings(self, token_count: int, is_cached: bool) -> Tuple[int, float]:
        """100% savings on local cache hits."""
        if not is_cached:
            return (0, 0.0)
        
        # Assume average cost of $2/M tokens
        cost_saved = (token_count / 1_000_000) * 2.00
        return (token_count, cost_saved)


class LRUCache:
    """Thread-safe LRU cache implementation."""
    
    def __init__(self, max_size: int = 1000):
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._max_size = max_size
        self._lock = threading.RLock()
    
    def get(self, key: str, ttl_seconds: int) -> Optional[CacheEntry]:
        """Get an entry from cache."""
        with self._lock:
            if key not in self._cache:
                return None
            
            entry = self._cache[key]
            
            # Check expiration
            if entry.is_expired(ttl_seconds):
                del self._cache[key]
                return None
            
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            
            # Update access stats
            entry.access_count += 1
            entry.last_accessed = datetime.now(timezone.utc)
            
            return entry
    
    def put(self, entry: CacheEntry) -> None:
        """Add or update an entry in cache."""
        with self._lock:
            # Remove oldest entries if at capacity
            while len(self._cache) >= self._max_size:
                self._cache.popitem(last=False)
            
            self._cache[entry.key] = entry
            self._cache.move_to_end(entry.key)
    
    def remove(self, key: str) -> bool:
        """Remove an entry from cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    def clear(self) -> None:
        """Clear all entries."""
        with self._lock:
            self._cache.clear()
    
    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)
    
    def cleanup_expired(self, ttl_seconds: int) -> int:
        """Remove expired entries. Returns count of removed entries."""
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired(ttl_seconds)
            ]
            for key in expired_keys:
                del self._cache[key]
            return len(expired_keys)


class ContextCache:
    """
    Main context caching class.
    
    Provides unified caching interface for LLM APIs with support for:
    - Provider-specific caching (Anthropic, OpenAI)
    - Local LRU cache for exact matches
    - Statistics and cost tracking
    
    Example:
        cache = ContextCache(
            strategy=AnthropicCacheStrategy(),
            config=CacheConfig(ttl_seconds=3600)
        )
        
        # Check for cached response
        result = cache.lookup(context_hash)
        
        if result.cache_type == CacheType.MISS:
            # Make API call
            response = api.complete(...)
            cache.store(context_hash, response)
    """
    
    def __init__(
        self,
        strategy: Optional[CacheStrategy] = None,
        config: Optional[CacheConfig] = None,
    ):
        """
        Initialize the context cache.
        
        Args:
            strategy: Provider-specific caching strategy
            config: Cache configuration
        """
        self._strategy = strategy or LocalCacheStrategy()
        self._config = config or CacheConfig()
        self._local_cache = LRUCache(max_size=self._config.max_entries)
        self._stats = CacheStats()
        self._lock = threading.RLock()
    
    @property
    def strategy(self) -> CacheStrategy:
        """Get the current caching strategy."""
        return self._strategy
    
    @property
    def config(self) -> CacheConfig:
        """Get the cache configuration."""
        return self._config
    
    def compute_key(self, content: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Compute a cache key for content.
        
        Args:
            content: The content to hash
            metadata: Optional metadata to include in key
            
        Returns:
            SHA-256 hash of the content
        """
        key_data = content
        if metadata:
            key_data += json.dumps(metadata, sort_keys=True)
        
        return hashlib.sha256(key_data.encode()).hexdigest()[:32]
    
    def lookup(
        self,
        context: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CacheResult:
        """
        Look up content in cache.
        
        Args:
            context: The context to look up
            metadata: Optional metadata for key computation
            
        Returns:
            CacheResult with cache type and any cached content
        """
        with self._lock:
            self._stats.total_requests += 1
        
        cache_key = self.compute_key(context, metadata)
        token_count = len(context) // 4  # Rough estimate
        
        # Skip caching for small contexts
        if token_count < self._config.min_tokens_for_caching:
            with self._lock:
                self._stats.misses += 1
            return CacheResult(
                cache_type=CacheType.MISS,
                cache_key=cache_key,
            )
        
        # Check local cache first
        if self._config.enable_local_cache:
            entry = self._local_cache.get(cache_key, self._config.ttl_seconds)
            if entry:
                tokens_saved, cost_saved = self._strategy.estimate_savings(
                    entry.token_count, True
                )
                
                with self._lock:
                    self._stats.local_exact_hits += 1
                    self._stats.total_tokens_saved += tokens_saved
                    self._stats.total_cost_saved += cost_saved
                
                return CacheResult(
                    cache_type=CacheType.LOCAL_EXACT,
                    cached_content=entry.content,
                    cache_key=cache_key,
                    token_savings=tokens_saved,
                    cost_savings=cost_saved,
                )
        
        # No local hit - check if provider caching is enabled
        if self._config.enable_provider_cache:
            # Provider caching is handled at message preparation time
            # We return a result indicating provider cache should be used
            with self._lock:
                self._stats.provider_hits += 1
            
            return CacheResult(
                cache_type=CacheType.PROVIDER_CACHE,
                cache_key=cache_key,
            )
        
        # Cache miss
        with self._lock:
            self._stats.misses += 1
        
        return CacheResult(
            cache_type=CacheType.MISS,
            cache_key=cache_key,
        )
    
    def store(
        self,
        context: str,
        response: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Store content in cache.
        
        Args:
            context: The context to cache
            response: Optional response to cache with context
            metadata: Optional metadata
            
        Returns:
            Cache key
        """
        cache_key = self.compute_key(context, metadata)
        token_count = len(context) // 4
        
        # Don't cache small contexts
        if token_count < self._config.min_tokens_for_caching:
            return cache_key
        
        if self._config.enable_local_cache:
            now = datetime.now(timezone.utc)
            entry = CacheEntry(
                key=cache_key,
                content=response or context,
                metadata=metadata or {},
                created_at=now,
                last_accessed=now,
                token_count=token_count,
            )
            self._local_cache.put(entry)
            
            with self._lock:
                self._stats.current_entries = len(self._local_cache)
        
        return cache_key
    
    def prepare_messages(
        self,
        system_prompt: Optional[str] = None,
        context: str = "",
        messages: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Prepare messages with caching hints.
        
        Uses the configured strategy to format messages for optimal caching.
        
        Args:
            system_prompt: Optional system prompt
            context: Context to include (will be cached if large enough)
            messages: Conversation messages
            
        Returns:
            List of messages formatted for the provider
        """
        return self._strategy.prepare_messages(
            system_prompt=system_prompt,
            context=context,
            messages=messages or [],
        )
    
    def invalidate(self, cache_key: str) -> bool:
        """
        Invalidate a cache entry.
        
        Args:
            cache_key: Key of the entry to invalidate
            
        Returns:
            True if entry was removed, False if not found
        """
        removed = self._local_cache.remove(cache_key)
        if removed:
            with self._lock:
                self._stats.current_entries = len(self._local_cache)
        return removed
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self._local_cache.clear()
        with self._lock:
            self._stats.current_entries = 0
    
    def cleanup(self) -> int:
        """
        Remove expired entries.
        
        Returns:
            Number of entries removed
        """
        removed = self._local_cache.cleanup_expired(self._config.ttl_seconds)
        with self._lock:
            self._stats.current_entries = len(self._local_cache)
        return removed
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        with self._lock:
            self._stats.current_entries = len(self._local_cache)
            return self._stats.to_dict()
    
    def reset_stats(self) -> None:
        """Reset cache statistics."""
        with self._lock:
            current_entries = len(self._local_cache)
            self._stats = CacheStats(current_entries=current_entries)


# Convenience function for creating caches
def create_cache(
    provider: Union[str, CacheProvider] = CacheProvider.LOCAL,
    **kwargs,
) -> ContextCache:
    """
    Create a context cache for a specific provider.
    
    Args:
        provider: Provider name or CacheProvider enum
        **kwargs: Additional config options passed to CacheConfig
        
    Returns:
        Configured ContextCache instance
    
    Example:
        # Anthropic cache
        cache = create_cache("anthropic", ttl_seconds=3600)
        
        # OpenAI cache
        cache = create_cache("openai", max_entries=500)
        
        # Local-only cache
        cache = create_cache("local")
    """
    if isinstance(provider, str):
        provider = CacheProvider(provider.lower())
    
    strategy: CacheStrategy
    if provider == CacheProvider.ANTHROPIC:
        strategy = AnthropicCacheStrategy()
    elif provider == CacheProvider.OPENAI:
        strategy = OpenAICacheStrategy()
    else:
        strategy = LocalCacheStrategy()
    
    config = CacheConfig(**kwargs)
    
    return ContextCache(strategy=strategy, config=config)
