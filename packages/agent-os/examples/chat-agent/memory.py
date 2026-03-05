# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Simple Episodic Memory for Chat Agent

This is a simplified version for the example.
For production, use the full EMK module.
"""

from typing import List, Dict, Optional
from collections import defaultdict
from datetime import datetime, timezone


class EpisodicMemory:
    """Simple conversation memory store."""
    
    def __init__(self, max_turns: int = 50, summarize_after: int = 20):
        """
        Initialize memory.
        
        Args:
            max_turns: Maximum turns to store
            summarize_after: Summarize after this many turns
        """
        self.max_turns = max_turns
        self.summarize_after = summarize_after
        self._conversations: Dict[str, List[Dict]] = defaultdict(list)
        self._summaries: Dict[str, str] = {}
    
    def add_turn(
        self,
        conversation_id: str,
        user_message: str,
        assistant_message: str
    ) -> None:
        """Add a conversation turn."""
        turn = {
            "user": user_message,
            "assistant": assistant_message,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        self._conversations[conversation_id].append(turn)
        
        # Trim if too long
        if len(self._conversations[conversation_id]) > self.max_turns:
            self._conversations[conversation_id] = \
                self._conversations[conversation_id][-self.max_turns:]
    
    def get_history(
        self,
        conversation_id: str,
        limit: Optional[int] = None
    ) -> List[Dict]:
        """Get conversation history."""
        history = self._conversations.get(conversation_id, [])
        
        if limit:
            return history[-limit:]
        
        return history
    
    def clear(self, conversation_id: str) -> None:
        """Clear conversation history."""
        if conversation_id in self._conversations:
            del self._conversations[conversation_id]
        if conversation_id in self._summaries:
            del self._summaries[conversation_id]
    
    def get_summary(self, conversation_id: str) -> Optional[str]:
        """Get conversation summary if available."""
        return self._summaries.get(conversation_id)
    
    def set_summary(self, conversation_id: str, summary: str) -> None:
        """Set conversation summary."""
        self._summaries[conversation_id] = summary
