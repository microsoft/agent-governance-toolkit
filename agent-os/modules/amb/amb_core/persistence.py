# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Message persistence for AMB.

This module provides message persistence capabilities for durability
and replay functionality.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, AsyncIterator
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
import asyncio
import json
from pathlib import Path
import aiofiles
import aiofiles.os

from amb_core.models import Message


class MessageStatus(str, Enum):
    """Status of a persisted message."""
    PENDING = "pending"           # Not yet delivered
    DELIVERED = "delivered"       # Successfully delivered
    ACKNOWLEDGED = "acknowledged" # Acknowledged by subscriber
    FAILED = "failed"            # Delivery failed
    EXPIRED = "expired"          # TTL expired


@dataclass 
class PersistedMessage:
    """
    A message with persistence metadata.
    """
    message: Message
    status: MessageStatus = MessageStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    delivery_count: int = 0
    last_error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "message": self.message.model_dump(),
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "delivery_count": self.delivery_count,
            "last_error": self.last_error
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PersistedMessage":
        """Create from dictionary."""
        return cls(
            message=Message.model_validate(data["message"]),
            status=MessageStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            delivery_count=data.get("delivery_count", 0),
            last_error=data.get("last_error")
        )


class MessageStore(ABC):
    """
    Abstract base class for message persistence stores.
    
    Implementations provide durable message storage for replay,
    audit trails, and crash recovery.
    """
    
    @abstractmethod
    async def store(self, message: Message) -> str:
        """
        Store a message.
        
        Args:
            message: Message to store
            
        Returns:
            Storage ID
        """
        pass
    
    @abstractmethod
    async def get(self, message_id: str) -> Optional[PersistedMessage]:
        """
        Get a message by ID.
        
        Args:
            message_id: Message ID
            
        Returns:
            Persisted message or None
        """
        pass
    
    @abstractmethod
    async def update_status(
        self, 
        message_id: str, 
        status: MessageStatus,
        error: Optional[str] = None
    ) -> bool:
        """
        Update message status.
        
        Args:
            message_id: Message ID
            status: New status
            error: Optional error message
            
        Returns:
            True if updated, False if not found
        """
        pass
    
    @abstractmethod
    async def get_by_topic(
        self,
        topic: str,
        status: Optional[MessageStatus] = None,
        limit: int = 100,
        after_id: Optional[str] = None
    ) -> List[PersistedMessage]:
        """
        Get messages by topic.
        
        Args:
            topic: Topic to query
            status: Optional status filter
            limit: Maximum messages to return
            after_id: Return messages after this ID (for pagination)
            
        Returns:
            List of persisted messages
        """
        pass
    
    @abstractmethod
    async def replay(
        self,
        topic: str,
        from_timestamp: Optional[datetime] = None,
        to_timestamp: Optional[datetime] = None
    ) -> AsyncIterator[Message]:
        """
        Replay messages from a topic.
        
        Args:
            topic: Topic to replay
            from_timestamp: Start timestamp (inclusive)
            to_timestamp: End timestamp (inclusive)
            
        Yields:
            Messages in chronological order
        """
        pass
    
    @abstractmethod
    async def delete(self, message_id: str) -> bool:
        """
        Delete a message.
        
        Args:
            message_id: Message ID
            
        Returns:
            True if deleted, False if not found
        """
        pass
    
    @abstractmethod
    async def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        pass


class InMemoryMessageStore(MessageStore):
    """
    In-memory message store for testing and development.
    
    Messages are stored in memory and lost on restart.
    """
    
    def __init__(self, max_messages: int = 100000):
        """
        Initialize in-memory store.
        
        Args:
            max_messages: Maximum messages to store
        """
        self._messages: Dict[str, PersistedMessage] = {}
        self._topic_index: Dict[str, List[str]] = {}
        self._max_messages = max_messages
        self._lock = asyncio.Lock()
    
    async def store(self, message: Message) -> str:
        """Store a message in memory."""
        async with self._lock:
            # Evict oldest if at capacity
            if len(self._messages) >= self._max_messages:
                oldest_id = next(iter(self._messages))
                await self._remove_internal(oldest_id)
            
            persisted = PersistedMessage(message=message)
            self._messages[message.id] = persisted
            
            if message.topic not in self._topic_index:
                self._topic_index[message.topic] = []
            self._topic_index[message.topic].append(message.id)
            
            return message.id
    
    async def get(self, message_id: str) -> Optional[PersistedMessage]:
        """Get a message by ID."""
        return self._messages.get(message_id)
    
    async def update_status(
        self,
        message_id: str,
        status: MessageStatus,
        error: Optional[str] = None
    ) -> bool:
        """Update message status."""
        async with self._lock:
            if message_id not in self._messages:
                return False
            
            persisted = self._messages[message_id]
            persisted.status = status
            persisted.updated_at = datetime.now(timezone.utc)
            if error:
                persisted.last_error = error
            if status == MessageStatus.DELIVERED:
                persisted.delivery_count += 1
            
            return True
    
    async def get_by_topic(
        self,
        topic: str,
        status: Optional[MessageStatus] = None,
        limit: int = 100,
        after_id: Optional[str] = None
    ) -> List[PersistedMessage]:
        """Get messages by topic."""
        message_ids = self._topic_index.get(topic, [])
        
        # Find start index if after_id specified
        start_idx = 0
        if after_id and after_id in message_ids:
            start_idx = message_ids.index(after_id) + 1
        
        results = []
        for msg_id in message_ids[start_idx:]:
            if len(results) >= limit:
                break
            
            persisted = self._messages.get(msg_id)
            if persisted and (status is None or persisted.status == status):
                results.append(persisted)
        
        return results
    
    async def replay(
        self,
        topic: str,
        from_timestamp: Optional[datetime] = None,
        to_timestamp: Optional[datetime] = None
    ) -> AsyncIterator[Message]:
        """Replay messages from a topic."""
        message_ids = self._topic_index.get(topic, [])
        
        for msg_id in message_ids:
            persisted = self._messages.get(msg_id)
            if not persisted:
                continue
            
            msg_time = persisted.message.timestamp
            
            if from_timestamp and msg_time < from_timestamp:
                continue
            if to_timestamp and msg_time > to_timestamp:
                continue
            
            yield persisted.message
    
    async def delete(self, message_id: str) -> bool:
        """Delete a message."""
        async with self._lock:
            return await self._remove_internal(message_id)
    
    async def _remove_internal(self, message_id: str) -> bool:
        """Internal remove without lock."""
        if message_id not in self._messages:
            return False
        
        persisted = self._messages[message_id]
        topic = persisted.message.topic
        
        del self._messages[message_id]
        
        if topic in self._topic_index and message_id in self._topic_index[topic]:
            self._topic_index[topic].remove(message_id)
        
        return True
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        status_counts = {}
        for persisted in self._messages.values():
            status = persisted.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "total_messages": len(self._messages),
            "max_messages": self._max_messages,
            "topics": len(self._topic_index),
            "by_status": status_counts
        }


class FileMessageStore(MessageStore):
    """
    File-based message store for persistence across restarts.
    
    Messages are stored as JSON files in a directory structure.
    """
    
    def __init__(self, base_path: str, max_messages_per_file: int = 1000):
        """
        Initialize file store.
        
        Args:
            base_path: Base directory for message storage
            max_messages_per_file: Maximum messages per file
        """
        self._base_path = Path(base_path)
        self._max_per_file = max_messages_per_file
        self._index: Dict[str, str] = {}  # message_id -> file_path
        self._loaded = False
        self._lock = asyncio.Lock()
    
    async def _ensure_initialized(self) -> None:
        """Ensure storage directory exists and index is loaded."""
        if self._loaded:
            return
        
        async with self._lock:
            if self._loaded:
                return
            
            # Create base directory
            self._base_path.mkdir(parents=True, exist_ok=True)
            
            # Load index from existing files
            await self._load_index()
            self._loaded = True
    
    async def _load_index(self) -> None:
        """Load message index from existing files."""
        if not self._base_path.exists():
            return
        
        for topic_dir in self._base_path.iterdir():
            if not topic_dir.is_dir():
                continue
            
            for msg_file in topic_dir.glob("*.json"):
                try:
                    async with aiofiles.open(msg_file, 'r') as f:
                        content = await f.read()
                        data = json.loads(content)
                        msg_id = data.get("message", {}).get("id")
                        if msg_id:
                            self._index[msg_id] = str(msg_file)
                except Exception:
                    continue
    
    async def store(self, message: Message) -> str:
        """Store a message to file."""
        await self._ensure_initialized()
        
        # Create topic directory
        topic_dir = self._base_path / message.topic.replace(".", "_")
        topic_dir.mkdir(parents=True, exist_ok=True)
        
        # Create message file
        persisted = PersistedMessage(message=message)
        file_path = topic_dir / f"{message.id}.json"
        
        async with aiofiles.open(file_path, 'w') as f:
            await f.write(json.dumps(persisted.to_dict(), indent=2, default=str))
        
        self._index[message.id] = str(file_path)
        return message.id
    
    async def get(self, message_id: str) -> Optional[PersistedMessage]:
        """Get a message by ID."""
        await self._ensure_initialized()
        
        file_path = self._index.get(message_id)
        if not file_path:
            return None
        
        try:
            async with aiofiles.open(file_path, 'r') as f:
                content = await f.read()
                data = json.loads(content)
                return PersistedMessage.from_dict(data)
        except Exception:
            return None
    
    async def update_status(
        self,
        message_id: str,
        status: MessageStatus,
        error: Optional[str] = None
    ) -> bool:
        """Update message status in file."""
        await self._ensure_initialized()
        
        persisted = await self.get(message_id)
        if not persisted:
            return False
        
        persisted.status = status
        persisted.updated_at = datetime.now(timezone.utc)
        if error:
            persisted.last_error = error
        if status == MessageStatus.DELIVERED:
            persisted.delivery_count += 1
        
        file_path = self._index[message_id]
        async with aiofiles.open(file_path, 'w') as f:
            await f.write(json.dumps(persisted.to_dict(), indent=2, default=str))
        
        return True
    
    async def get_by_topic(
        self,
        topic: str,
        status: Optional[MessageStatus] = None,
        limit: int = 100,
        after_id: Optional[str] = None
    ) -> List[PersistedMessage]:
        """Get messages by topic from files."""
        await self._ensure_initialized()
        
        topic_dir = self._base_path / topic.replace(".", "_")
        if not topic_dir.exists():
            return []
        
        results = []
        found_after = after_id is None
        
        for msg_file in sorted(topic_dir.glob("*.json")):
            if len(results) >= limit:
                break
            
            try:
                async with aiofiles.open(msg_file, 'r') as f:
                    content = await f.read()
                    data = json.loads(content)
                    persisted = PersistedMessage.from_dict(data)
                    
                    if not found_after:
                        if persisted.message.id == after_id:
                            found_after = True
                        continue
                    
                    if status is None or persisted.status == status:
                        results.append(persisted)
            except Exception:
                continue
        
        return results
    
    async def replay(
        self,
        topic: str,
        from_timestamp: Optional[datetime] = None,
        to_timestamp: Optional[datetime] = None
    ) -> AsyncIterator[Message]:
        """Replay messages from files."""
        messages = await self.get_by_topic(topic, limit=100000)
        
        # Sort by timestamp
        messages.sort(key=lambda p: p.message.timestamp)
        
        for persisted in messages:
            msg_time = persisted.message.timestamp
            
            if from_timestamp and msg_time < from_timestamp:
                continue
            if to_timestamp and msg_time > to_timestamp:
                continue
            
            yield persisted.message
    
    async def delete(self, message_id: str) -> bool:
        """Delete a message file."""
        await self._ensure_initialized()
        
        file_path = self._index.get(message_id)
        if not file_path:
            return False
        
        try:
            await aiofiles.os.remove(file_path)
            del self._index[message_id]
            return True
        except Exception:
            return False
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        await self._ensure_initialized()
        
        return {
            "total_messages": len(self._index),
            "base_path": str(self._base_path),
            "topics": len([d for d in self._base_path.iterdir() if d.is_dir()]) if self._base_path.exists() else 0
        }
