# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Trust callback handler for LangChain."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult

from langchain_agentmesh.identity import CMVKIdentity


class TrustCallbackHandler(BaseCallbackHandler):
    """Callback handler that tracks trust metrics for LangChain operations."""
    
    def __init__(
        self,
        identity: CMVKIdentity,
        log_to_console: bool = False,
    ):
        self.identity = identity
        self.log_to_console = log_to_console
        
        # Metrics
        self._total_calls = 0
        self._successful_calls = 0
        self._failed_calls = 0
        self._total_tokens = 0
        self._total_cost = 0.0
        
        # Audit log
        self._audit_log: List[Dict[str, Any]] = []
    
    def _log(self, event_type: str, data: Dict[str, Any]) -> None:
        """Log an event to the audit trail."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_did": self.identity.did,
            "agent_name": self.identity.agent_name,
            "event_type": event_type,
            **data,
        }
        self._audit_log.append(entry)
        
        if self.log_to_console:
            print(f"[Trust] {event_type}: {data}")
    
    # LLM Callbacks
    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM starts."""
        self._total_calls += 1
        self._log("llm_start", {
            "run_id": str(run_id),
            "model": serialized.get("name", "unknown"),
            "prompt_count": len(prompts),
        })
    
    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM ends."""
        self._successful_calls += 1
        
        # Extract token usage if available
        token_usage = {}
        if response.llm_output:
            token_usage = response.llm_output.get("token_usage", {})
            self._total_tokens += token_usage.get("total_tokens", 0)
        
        self._log("llm_end", {
            "run_id": str(run_id),
            "generations": len(response.generations),
            "token_usage": token_usage,
        })
    
    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM errors."""
        self._failed_calls += 1
        self._log("llm_error", {
            "run_id": str(run_id),
            "error": str(error),
        })
    
    # Chain Callbacks
    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when chain starts."""
        self._log("chain_start", {
            "run_id": str(run_id),
            "chain_type": serialized.get("name", "unknown"),
        })
    
    def on_chain_end(
        self,
        outputs: Dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when chain ends."""
        self._log("chain_end", {
            "run_id": str(run_id),
            "output_keys": list(outputs.keys()) if isinstance(outputs, dict) else [],
        })
    
    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when chain errors."""
        self._log("chain_error", {
            "run_id": str(run_id),
            "error": str(error),
        })
    
    # Tool Callbacks
    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when tool starts."""
        self._log("tool_start", {
            "run_id": str(run_id),
            "tool_name": serialized.get("name", "unknown"),
        })
    
    def on_tool_end(
        self,
        output: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when tool ends."""
        self._log("tool_end", {
            "run_id": str(run_id),
            "output_length": len(str(output)),
        })
    
    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when tool errors."""
        self._log("tool_error", {
            "run_id": str(run_id),
            "error": str(error),
        })
    
    # Metrics
    def get_metrics(self) -> Dict[str, Any]:
        """Get current trust metrics."""
        success_rate = (
            self._successful_calls / self._total_calls
            if self._total_calls > 0 else 0.0
        )
        
        # Calculate trust score based on success rate
        trust_score = 0.5 + (success_rate * 0.3)  # Base 0.5, max 0.8 from calls
        
        return {
            "agent_did": self.identity.did,
            "agent_name": self.identity.agent_name,
            "total_calls": self._total_calls,
            "successful_calls": self._successful_calls,
            "failed_calls": self._failed_calls,
            "success_rate": success_rate,
            "total_tokens": self._total_tokens,
            "trust_score": trust_score,
            "capabilities": self.identity.capabilities,
        }
    
    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get the full audit log."""
        return self._audit_log.copy()
    
    def clear_audit_log(self) -> None:
        """Clear the audit log."""
        self._audit_log.clear()
