# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Failure Triage Engine - Decides sync (JIT) vs async (batch) correction strategy.

This is the missing component that sits between Failure Detection and Correction.
It analyzes the context to determine if a failure should be fixed immediately
(blocking the user) or asynchronously (returning error quickly, fixing later).
"""

from enum import Enum
from typing import Dict, Any, Optional


class FixStrategy(Enum):
    """Strategy for fixing agent failures."""
    SYNC_JIT = "jit_retry"       # High Latency, High Reliability - Fix NOW and wait
    ASYNC_BATCH = "async_patch"  # Low Latency, Eventual Consistency - Fix LATER


class FailureTriage:
    """
    Decision engine for routing failures to sync (JIT) or async (batch) correction.
    
    The triage engine applies three rules to determine criticality:
    1. Safety/Write Operations → SYNC_JIT (must fix immediately)
    2. High Effort Prompts → SYNC_JIT (user expects deep thinking)
    3. Read/Query Operations → ASYNC_BATCH (save user time)
    
    This enables "thinking fast" (async) for trivial failures and
    "thinking slow" (sync) for critical failures.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the triage engine.
        
        Args:
            config: Optional configuration for custom critical tools and keywords
        """
        self.config = config or {}
        
        # Critical tools that require synchronous fixing (can be customized via config)
        self.critical_tools = self.config.get("critical_tools", [
            "delete_resource",
            "update_db",
            "execute_payment",
            "drop_table",
            "refund_user",
            "delete_file",
            "execute_sql",
            "write_file",
            "modify_permissions",
            "delete_user"  # User deletion is critical
        ])
        
        # Keywords indicating high-effort prompts requiring deep thinking
        self.high_effort_keywords = self.config.get("high_effort_keywords", [
            "carefully",
            "critical",
            "important",
            "urgent",
            "must",
            "required",
            "ensure"
        ])
    
    def decide_strategy(
        self,
        prompt: str,
        tool_name: Optional[str] = None,
        user_metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> FixStrategy:
        """
        Decide whether to fix this failure sync (JIT) or async (batch).
        
        Decision Rules (in priority order):
        1. Cognitive failures with full trace → SYNC_JIT (deep diagnosis needed)
        2. Safety/Write Operations → SYNC_JIT
        3. High Effort Prompts → SYNC_JIT  
        4. VIP Users → SYNC_JIT
        5. Default (Read/Query) → ASYNC_BATCH
        
        Args:
            prompt: The user prompt that led to the failure
            tool_name: Name of the tool that failed (if available)
            user_metadata: Metadata about the user (e.g., VIP status)
            context: Additional context about the failure
            
        Returns:
            FixStrategy indicating sync (JIT) or async (batch) correction
        """
        # Rule 0: Cognitive failures with full trace (chain_of_thought + failed_action)
        # These warrant immediate deep analysis with Shadow Teacher
        if context:
            has_chain = context.get("chain_of_thought") is not None
            has_failed_action = context.get("failed_action") is not None
            if has_chain and has_failed_action:
                return FixStrategy.SYNC_JIT
        
        # Rule 1: Safety/Write Operations are always Critical
        if tool_name and tool_name in self.critical_tools:
            return FixStrategy.SYNC_JIT
        
        # Check context for critical actions (fallback if tool_name not provided)
        if context:
            action = context.get("action", "")
            if action in self.critical_tools:
                return FixStrategy.SYNC_JIT
            
            # Also check failed_action if present
            failed_action = context.get("failed_action")
            if failed_action and isinstance(failed_action, dict):
                failed_action_name = failed_action.get("action", "")
                if failed_action_name in self.critical_tools:
                    return FixStrategy.SYNC_JIT
        
        # Rule 2: "High Effort" prompts request deep thinking
        prompt_lower = prompt.lower()
        if any(keyword in prompt_lower for keyword in self.high_effort_keywords):
            return FixStrategy.SYNC_JIT
        
        # Rule 3: VIP users get priority treatment (optional)
        if user_metadata and user_metadata.get("is_vip", False):
            return FixStrategy.SYNC_JIT
        
        # Rule 4: Default to Async for "Read/Query" failures to save user time
        return FixStrategy.ASYNC_BATCH
    
    def is_critical(
        self,
        prompt: str,
        tool_name: Optional[str] = None,
        user_metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Convenience method to check if a failure is critical (needs SYNC_JIT).
        
        Args:
            prompt: The user prompt
            tool_name: Name of the tool that failed
            user_metadata: User metadata
            context: Additional context
            
        Returns:
            True if critical (SYNC_JIT), False if non-critical (ASYNC_BATCH)
        """
        strategy = self.decide_strategy(prompt, tool_name, user_metadata, context)
        return strategy == FixStrategy.SYNC_JIT
