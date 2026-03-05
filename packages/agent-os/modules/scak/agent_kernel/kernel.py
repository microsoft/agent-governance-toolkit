# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic self-correction with retry
"""
Self-Correcting Agent Kernel — Community Edition.

Basic self-correction with simple retry logic and exponential backoff.
"""

import logging
import time
from typing import Optional, Dict, Any, List, Callable

from .models import (
    AgentFailure, FailureAnalysis, CorrectionPatch, AgentState,
    AgentOutcome, ClassifiedPatch, ToolExecutionTelemetry,
)
from .detector import FailureDetector, FailureQueue
from .analyzer import FailureAnalyzer
from .outcome_analyzer import OutcomeAnalyzer
from .triage import FailureTriage, FixStrategy

logger = logging.getLogger(__name__)


class SelfCorrectingAgentKernel:
    """
    Community Edition — basic self-correction with retry.

    Provides simple retry-with-backoff for agent failures and
    basic give-up detection on agent outcomes.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the self-correcting agent kernel.

        Args:
            config: Optional configuration dictionary.
                Supported keys:
                - max_retries (int): Max retry attempts, default 3
                - backoff_base (float): Base seconds for exponential backoff, default 1.0
                - log_level (str): Logging level, default "INFO"
        """
        self.config = config or {}

        self.max_retries: int = self.config.get("max_retries", 3)
        self.backoff_base: float = self.config.get("backoff_base", 1.0)

        self.detector = FailureDetector()
        self.analyzer = FailureAnalyzer()
        self.outcome_analyzer = OutcomeAnalyzer()
        self.triage = FailureTriage(config=self.config.get("triage_config"))

        self.failure_history: List[AgentFailure] = []
        self.patch_history: List[Dict[str, Any]] = []
        self.agent_states: Dict[str, AgentState] = {}
        self.async_failure_queue: List[Dict[str, Any]] = []

        self._setup_logging()
        logger.info("SelfCorrectingAgentKernel initialized (Community Edition)")

    def _setup_logging(self):
        """Setup logging configuration."""
        log_level = self.config.get("log_level", "INFO")
        logging.basicConfig(
            level=getattr(logging, log_level),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

    # ------------------------------------------------------------------
    # Core failure handling with simple retry + exponential backoff
    # ------------------------------------------------------------------

    def handle_failure(
        self,
        agent_id: str,
        error_message: str,
        context: Optional[Dict[str, Any]] = None,
        stack_trace: Optional[str] = None,
        auto_patch: bool = True,
        user_prompt: Optional[str] = None,
        chain_of_thought: Optional[List[str]] = None,
        failed_action: Optional[Dict[str, Any]] = None,
        user_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Handle an agent failure with simple retry logic.

        Args:
            agent_id: Identifier of the failed agent
            error_message: Error message from the failure
            context: Additional context about the failure
            stack_trace: Optional stack trace
            auto_patch: Whether to automatically apply the patch
            user_prompt: Original user prompt
            chain_of_thought: Agent's reasoning steps
            failed_action: The specific action that failed
            user_metadata: User metadata for triage decisions

        Returns:
            Dictionary containing the results of the self-correction process
        """
        logger.info(f"Failure detected for agent {agent_id}: {error_message}")

        failure = self.detector.detect_failure(
            agent_id=agent_id,
            error_message=error_message,
            context=context,
            stack_trace=stack_trace,
            user_prompt=user_prompt,
            chain_of_thought=chain_of_thought,
            failed_action=failed_action,
        )
        self.failure_history.append(failure)

        analysis = self.analyzer.analyze(failure)

        return {
            "success": True,
            "failure": failure,
            "analysis": analysis,
            "retries_available": self.max_retries,
            "message": "Failure recorded; use retry() to attempt recovery",
        }

    def retry(
        self,
        action: Callable[[], Any],
        agent_id: str = "default",
    ) -> Dict[str, Any]:
        """
        Execute *action* with retry + exponential backoff.

        Args:
            action: Callable to retry on failure.
            agent_id: Identifier for logging.

        Returns:
            Dict with keys success, result | error, attempts.
        """
        last_error: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                result = action()
                logger.info(f"Agent {agent_id} succeeded on attempt {attempt}")
                return {"success": True, "result": result, "attempts": attempt}
            except Exception as exc:
                last_error = exc
                wait = self.backoff_base * (2 ** (attempt - 1))
                logger.warning(
                    f"Agent {agent_id} attempt {attempt} failed: {exc}. "
                    f"Retrying in {wait:.1f}s…"
                )
                time.sleep(wait)

        logger.error(f"Agent {agent_id} exhausted {self.max_retries} retries")
        return {
            "success": False,
            "error": str(last_error),
            "attempts": self.max_retries,
        }

    # ------------------------------------------------------------------
    # Agent status helpers
    # ------------------------------------------------------------------

    def get_agent_status(self, agent_id: str) -> AgentState:
        """Get the current status of an agent."""
        if agent_id not in self.agent_states:
            self.agent_states[agent_id] = AgentState(
                agent_id=agent_id, status="active"
            )
        return self.agent_states[agent_id]

    def rollback_patch(self, patch_id: str) -> bool:
        """Rollback a previously applied patch (no-op in Community Edition)."""
        logger.info(f"Rollback requested for {patch_id} (no-op in Community Edition)")
        return False

    def get_failure_history(
        self, agent_id: Optional[str] = None, limit: int = 100
    ) -> List[AgentFailure]:
        """Get failure history, optionally filtered by agent_id."""
        history = self.failure_history
        if agent_id:
            history = [f for f in history if f.agent_id == agent_id]
        return history[-limit:]

    def get_patch_history(
        self, agent_id: Optional[str] = None
    ) -> List[CorrectionPatch]:
        """Get patch history (empty in Community Edition)."""
        return []

    def wake_up_and_fix(
        self,
        agent_id: str,
        error_message: str,
        context: Optional[Dict[str, Any]] = None,
    ):
        """Convenience method — records failure and returns analysis."""
        return self.handle_failure(agent_id, error_message, context, auto_patch=True)

    # ------------------------------------------------------------------
    # Outcome handling (basic give-up detection)
    # ------------------------------------------------------------------

    def handle_outcome(
        self,
        agent_id: str,
        user_prompt: str,
        agent_response: str,
        context: Optional[Dict[str, Any]] = None,
        tool_telemetry: Optional[List[ToolExecutionTelemetry]] = None,
        auto_nudge: bool = True,
    ) -> Dict[str, Any]:
        """
        Analyse an agent outcome for give-up signals.

        Args:
            agent_id: ID of the agent
            user_prompt: Original user request
            agent_response: Agent's response
            context: Additional context
            tool_telemetry: Optional tool execution telemetry
            auto_nudge: Unused in Community Edition

        Returns:
            Dictionary with outcome analysis
        """
        outcome = self.outcome_analyzer.analyze_outcome(
            agent_id=agent_id,
            user_prompt=user_prompt,
            agent_response=agent_response,
            context=context,
        )

        needs_audit = self.outcome_analyzer.should_trigger_audit(outcome)
        if needs_audit:
            logger.warning(f"Give-up detected for agent {agent_id}")

        return {
            "outcome": outcome,
            "needs_audit": needs_audit,
            "audit": None,
            "patch": None,
            "classified_patch": None,
            "nudge_result": None,
        }

    # ------------------------------------------------------------------
    # Model upgrade (simple version reset)
    # ------------------------------------------------------------------

    def upgrade_model(self, new_model_version: str) -> Dict[str, Any]:
        """
        Record a model version upgrade.

        Args:
            new_model_version: New model version string

        Returns:
            Dictionary with upgrade info
        """
        old = self.config.get("model_version", "unknown")
        self.config["model_version"] = new_model_version
        logger.info(f"Model upgraded: {old} -> {new_model_version}")
        return {"old_version": old, "new_version": new_model_version}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_alignment_stats(self) -> Dict[str, Any]:
        """Get basic alignment statistics."""
        return {
            "outcome_analyzer": {
                "total_outcomes": len(self.outcome_analyzer.outcome_history),
                "give_up_rate": self.outcome_analyzer.get_give_up_rate(),
            },
            "total_failures": len(self.failure_history),
        }

    def get_classified_patches(self) -> Dict[str, List[ClassifiedPatch]]:
        """Get classified patches (empty in Community Edition)."""
        return {"purgeable": [], "permanent": []}

    def process_async_queue(self, batch_size: int = 10) -> Dict[str, Any]:
        """Process queued async failures (no-op in Community Edition)."""
        return {
            "processed": 0,
            "succeeded": 0,
            "failed": 0,
            "remaining": len(self.async_failure_queue),
        }

    def get_triage_stats(self) -> Dict[str, Any]:
        """Get triage statistics."""
        return {"async_queue_size": len(self.async_failure_queue)}
