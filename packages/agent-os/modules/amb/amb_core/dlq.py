# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Dead Letter Queue (DLQ) for AMB.

This module provides DLQ functionality for handling failed messages.
Messages that cannot be processed are moved to the DLQ for investigation
and potential retry.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Awaitable
from datetime import datetime, timezone
from dataclasses import dataclass, field
from collections import defaultdict
import asyncio

from amb_core.models import Message


class DLQReason(str, Enum):
    """Reasons why a message was moved to DLQ."""
    HANDLER_ERROR = "handler_error"          # Handler raised an exception
    VALIDATION_ERROR = "validation_error"    # Schema validation failed
    EXPIRED = "expired"                      # Message TTL exceeded
    MAX_RETRIES = "max_retries"             # Maximum retry attempts exceeded
    REJECTED = "rejected"                    # Explicitly rejected by handler
    UNKNOWN = "unknown"                      # Unknown error


@dataclass
class DLQEntry:
    """
    Entry in the Dead Letter Queue.
    
    Contains the original message plus metadata about the failure.
    """
    message: Message
    reason: DLQReason
    error_message: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    retry_count: int = 0
    original_topic: str = ""
    stack_trace: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.original_topic:
            self.original_topic = self.message.topic
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary for serialization."""
        return {
            "message": self.message.model_dump(),
            "reason": self.reason.value,
            "error_message": self.error_message,
            "timestamp": self.timestamp.isoformat(),
            "retry_count": self.retry_count,
            "original_topic": self.original_topic,
            "stack_trace": self.stack_trace,
            "metadata": self.metadata
        }


# Type alias for DLQ handler
DLQHandler = Callable[[DLQEntry], Awaitable[None]]


class DeadLetterQueue:
    """
    Dead Letter Queue for managing failed messages.
    
    Provides storage, retrieval, and retry capabilities for messages
    that failed to process successfully.
    
    Example:
        dlq = DeadLetterQueue(max_size=1000)
        
        # Add failed message
        entry = DLQEntry(
            message=failed_message,
            reason=DLQReason.HANDLER_ERROR,
            error_message="Connection timeout"
        )
        await dlq.add(entry)
        
        # Get entries for investigation
        entries = await dlq.get_entries(topic="fraud.alerts")
        
        # Retry a message
        await dlq.retry(entry.message.id, retry_handler)
    """
    
    def __init__(
        self,
        max_size: int = 10000,
        max_retries: int = 3,
        on_entry_added: Optional[DLQHandler] = None
    ):
        """
        Initialize the Dead Letter Queue.
        
        Args:
            max_size: Maximum number of entries to store
            max_retries: Maximum retry attempts before permanent failure
            on_entry_added: Optional callback when entry is added
        """
        self._entries: Dict[str, DLQEntry] = {}  # message_id -> entry
        self._topic_index: Dict[str, List[str]] = defaultdict(list)  # topic -> [message_ids]
        self._max_size = max_size
        self._max_retries = max_retries
        self._on_entry_added = on_entry_added
        self._lock = asyncio.Lock()
    
    async def add(self, entry: DLQEntry) -> bool:
        """
        Add an entry to the DLQ.
        
        Args:
            entry: DLQ entry to add
            
        Returns:
            True if added, False if DLQ is full and oldest entry was evicted
        """
        async with self._lock:
            message_id = entry.message.id
            evicted = False
            
            # Evict oldest if at capacity
            if len(self._entries) >= self._max_size and message_id not in self._entries:
                oldest_id = next(iter(self._entries))
                oldest_entry = self._entries[oldest_id]
                del self._entries[oldest_id]
                if oldest_id in self._topic_index.get(oldest_entry.original_topic, []):
                    self._topic_index[oldest_entry.original_topic].remove(oldest_id)
                evicted = True
            
            # Add or update entry
            self._entries[message_id] = entry
            if message_id not in self._topic_index[entry.original_topic]:
                self._topic_index[entry.original_topic].append(message_id)
        
        # Call handler outside lock
        if self._on_entry_added:
            try:
                await self._on_entry_added(entry)
            except Exception:
                pass  # Don't fail on handler errors
        
        return not evicted
    
    async def get(self, message_id: str) -> Optional[DLQEntry]:
        """
        Get a specific DLQ entry by message ID.
        
        Args:
            message_id: The message ID to look up
            
        Returns:
            DLQ entry or None if not found
        """
        return self._entries.get(message_id)
    
    async def get_entries(
        self,
        topic: Optional[str] = None,
        reason: Optional[DLQReason] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[DLQEntry]:
        """
        Get DLQ entries with optional filtering.
        
        Args:
            topic: Filter by original topic
            reason: Filter by failure reason
            limit: Maximum entries to return
            offset: Number of entries to skip
            
        Returns:
            List of DLQ entries
        """
        if topic:
            message_ids = self._topic_index.get(topic, [])
            entries = [self._entries[mid] for mid in message_ids if mid in self._entries]
        else:
            entries = list(self._entries.values())
        
        # Filter by reason if specified
        if reason:
            entries = [e for e in entries if e.reason == reason]
        
        # Sort by timestamp (newest first)
        entries.sort(key=lambda e: e.timestamp, reverse=True)
        
        # Apply pagination
        return entries[offset:offset + limit]
    
    async def remove(self, message_id: str) -> bool:
        """
        Remove an entry from the DLQ.
        
        Args:
            message_id: Message ID to remove
            
        Returns:
            True if removed, False if not found
        """
        async with self._lock:
            if message_id not in self._entries:
                return False
            
            entry = self._entries[message_id]
            del self._entries[message_id]
            
            if message_id in self._topic_index.get(entry.original_topic, []):
                self._topic_index[entry.original_topic].remove(message_id)
            
            return True
    
    async def retry(
        self,
        message_id: str,
        handler: Callable[[Message], Awaitable[None]]
    ) -> bool:
        """
        Retry processing a failed message.
        
        Args:
            message_id: Message ID to retry
            handler: Handler function to process the message
            
        Returns:
            True if successful, False if failed or not found
            
        Raises:
            ValueError: If max retries exceeded
        """
        entry = await self.get(message_id)
        if not entry:
            return False
        
        if entry.retry_count >= self._max_retries:
            raise ValueError(
                f"Message {message_id} has exceeded max retries ({self._max_retries})"
            )
        
        try:
            await handler(entry.message)
            await self.remove(message_id)
            return True
        except Exception as e:
            # Update retry count
            entry.retry_count += 1
            entry.error_message = str(e)
            if entry.retry_count >= self._max_retries:
                entry.reason = DLQReason.MAX_RETRIES
            return False
    
    async def retry_all(
        self,
        handler: Callable[[Message], Awaitable[None]],
        topic: Optional[str] = None
    ) -> Dict[str, bool]:
        """
        Retry all messages in the DLQ.
        
        Args:
            handler: Handler function to process messages
            topic: Optional topic filter
            
        Returns:
            Dict mapping message IDs to success/failure
        """
        entries = await self.get_entries(topic=topic, limit=self._max_size)
        results = {}
        
        for entry in entries:
            try:
                results[entry.message.id] = await self.retry(entry.message.id, handler)
            except ValueError:
                results[entry.message.id] = False
        
        return results
    
    async def clear(self, topic: Optional[str] = None) -> int:
        """
        Clear entries from the DLQ.
        
        Args:
            topic: Optional topic filter (clears all if None)
            
        Returns:
            Number of entries cleared
        """
        async with self._lock:
            if topic:
                message_ids = self._topic_index.get(topic, []).copy()
                for mid in message_ids:
                    if mid in self._entries:
                        del self._entries[mid]
                self._topic_index[topic].clear()
                return len(message_ids)
            else:
                count = len(self._entries)
                self._entries.clear()
                self._topic_index.clear()
                return count
    
    def __len__(self) -> int:
        """Get number of entries in DLQ."""
        return len(self._entries)
    
    @property
    def size(self) -> int:
        """Get current size of DLQ."""
        return len(self._entries)
    
    @property
    def max_size(self) -> int:
        """Get maximum size of DLQ."""
        return self._max_size
    
    async def get_stats(self) -> Dict[str, Any]:
        """
        Get DLQ statistics.
        
        Returns:
            Dict with DLQ statistics
        """
        entries = list(self._entries.values())
        
        reason_counts = defaultdict(int)
        topic_counts = defaultdict(int)
        
        for entry in entries:
            reason_counts[entry.reason.value] += 1
            topic_counts[entry.original_topic] += 1
        
        return {
            "total_entries": len(entries),
            "max_size": self._max_size,
            "by_reason": dict(reason_counts),
            "by_topic": dict(topic_counts),
            "max_retries_setting": self._max_retries
        }
