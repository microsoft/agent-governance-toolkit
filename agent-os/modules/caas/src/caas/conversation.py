# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Conversation Manager for Sliding Window (FIFO) history management.

The Brutal Squeeze Philosophy:
"Chopping > Summarizing"

Instead of asking an AI to summarize conversation history (which costs money and loses nuance),
we use a brutal "Sliding Window" approach:
- Keep the last 10 turns perfectly intact
- Delete turn 11 (FIFO - First In First Out)
- No summarization = No lossy compression
- Recent Precision over Vague History

Why this works:
- Users rarely refer back to what they said 20 minutes ago
- They constantly refer to the exact code snippet they pasted 30 seconds ago
- Summary = Lossy Compression (loses specific error codes, exact wording)
- Chopping = Lossless Compression (of the recent past)

Example:
Turn 1: "I tried X and it failed with error code 500"
With Summarization: "User attempted troubleshooting" (ERROR CODE LOST!)
With Chopping: After 10 new turns, this is deleted entirely
                But turns 2-11 are perfectly intact with all details
"""

from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
import uuid
import logging

from caas.models import ConversationTurn, ConversationState

# Set up logger
logger = logging.getLogger(__name__)


class ConversationManager:
    """
    Manages conversation history using a Sliding Window (FIFO) approach.
    
    The Sliding Window ensures:
    1. Recent precision: Last N turns are perfectly intact
    2. Zero summarization cost: No AI calls needed
    3. No information loss: What's kept is lossless
    4. Predictable behavior: Always know what's in context
    
    Philosophy:
    In a frugal architecture, we value Recent Precision over Vague History.
    """
    
    def __init__(self, max_turns: int = 10):
        """
        Initialize the conversation manager.
        
        Args:
            max_turns: Maximum number of turns to keep (default: 10)
        """
        self.state = ConversationState(max_turns=max_turns)
    
    def add_turn(
        self, 
        user_message: str,
        ai_response: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add a conversation turn to the history.
        
        This implements the FIFO Sliding Window:
        - If we have < max_turns, just add the turn
        - If we have = max_turns, delete the oldest turn and add the new one
        - No summarization, no compression, just brutal chopping
        
        Args:
            user_message: The user's message
            ai_response: The AI's response (optional)
            metadata: Optional metadata for the turn
            
        Returns:
            The ID of the created turn
        """
        turn_id = str(uuid.uuid4())
        turn = ConversationTurn(
            id=turn_id,
            user_message=user_message,
            ai_response=ai_response,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {}
        )
        
        # FIFO: If we're at max capacity, delete the oldest turn
        if len(self.state.turns) >= self.state.max_turns:
            deleted_turn = self.state.turns.pop(0)  # Remove first (oldest) turn
            logger.debug(f"FIFO: Deleted oldest turn (ID: {deleted_turn.id[:8]}...) to make room")
        
        # Add the new turn at the end
        self.state.turns.append(turn)
        self.state.total_turns_ever += 1
        
        return turn_id
    
    def update_turn_response(self, turn_id: str, ai_response: str) -> bool:
        """
        Update the AI response for a specific turn.
        
        Useful when you add a turn with just the user message
        and want to update it with the AI response later.
        
        Args:
            turn_id: The ID of the turn to update
            ai_response: The AI response to add
            
        Returns:
            True if turn was found and updated, False otherwise
        """
        for turn in self.state.turns:
            if turn.id == turn_id:
                turn.ai_response = ai_response
                return True
        return False
    
    def get_conversation_history(
        self, 
        include_metadata: bool = False,
        format_as_text: bool = True
    ) -> Union[List[ConversationTurn], str]:
        """
        Get the conversation history (last N turns).
        
        Returns the history in FIFO order (oldest to newest).
        All turns are perfectly intact - no summarization, no loss.
        
        Args:
            include_metadata: Whether to include metadata in text format
            format_as_text: If True, return formatted text; if False, return list of turns
            
        Returns:
            Formatted conversation history or list of turns
        """
        if not format_as_text:
            return self.state.turns
        
        if not self.state.turns:
            return "No conversation history."
        
        # Format as text
        parts = ["# Conversation History (Sliding Window)\n"]
        parts.append(f"_Keeping last {self.state.max_turns} turns intact (no summarization)_\n")
        parts.append(f"_Total turns ever: {self.state.total_turns_ever}_\n\n")
        
        for i, turn in enumerate(self.state.turns, 1):
            parts.append(f"## Turn {i}\n")
            parts.append(f"**User**: {turn.user_message}\n")
            if turn.ai_response:
                parts.append(f"**AI**: {turn.ai_response}\n")
            if include_metadata and turn.metadata:
                parts.append(f"_Metadata: {turn.metadata}_\n")
            parts.append("\n")
        
        return "".join(parts)
    
    def get_recent_turns(self, n: int = 5) -> List[ConversationTurn]:
        """
        Get the N most recent turns.
        
        Args:
            n: Number of recent turns to get
            
        Returns:
            List of recent turns (newest last)
        """
        return self.state.turns[-n:] if len(self.state.turns) > n else self.state.turns
    
    def clear_conversation(self):
        """Clear all conversation history."""
        self.state.turns = []
    
    def get_state(self) -> ConversationState:
        """
        Get the current conversation state.
        
        Returns:
            The current conversation state
        """
        return self.state
    
    def set_state(self, state: ConversationState):
        """
        Set the conversation state.
        
        Args:
            state: The new conversation state
        """
        self.state = state
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the conversation.
        
        Returns:
            Dictionary with statistics
        """
        if not self.state.turns:
            return {
                "current_turns": 0,
                "max_turns": self.state.max_turns,
                "total_turns_ever": self.state.total_turns_ever,
                "deleted_turns": self.state.total_turns_ever,
                "oldest_turn": None,
                "newest_turn": None,
            }
        
        return {
            "current_turns": len(self.state.turns),
            "max_turns": self.state.max_turns,
            "total_turns_ever": self.state.total_turns_ever,
            "deleted_turns": self.state.total_turns_ever - len(self.state.turns),
            "oldest_turn": self.state.turns[0].timestamp if self.state.turns else None,
            "newest_turn": self.state.turns[-1].timestamp if self.state.turns else None,
        }
