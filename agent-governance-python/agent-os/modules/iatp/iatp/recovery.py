# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Recovery Engine Integration with SCAK (Self-Correcting Agent Kernel).

This module wraps the agent_kernel (scak) to provide failure recovery
and rollback capabilities for IATP.
"""
import asyncio
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Optional

from agent_primitives import (
    AgentFailure,
    FailureType,
    FailureSeverity,
)

from iatp.models import CapabilityManifest

logger = logging.getLogger(__name__)


class RecoveryStrategy(str, Enum):
    """Recovery strategies for IATP."""
    ROLLBACK = "rollback"  # Execute compensation transaction
    RETRY = "retry"  # Retry the operation
    GIVE_UP = "give_up"  # No recovery possible


class IATPRecoveryEngine:
    """
    Wrapper around SCAK for IATP failure recovery.

    This integrates the Self-Correcting Agent Kernel (scak) to provide
    automatic failure detection, triage, and recovery for agent interactions.
    """

    def __init__(self):
        """Initialize the IATP Recovery Engine."""
        # Note: SelfCorrectingAgentKernel requires specific initialization
        # We'll use the triage and diagnosis functions directly
        self.recovery_history: Dict[str, Any] = {}

    async def handle_failure(
        self,
        trace_id: str,
        error: Exception,
        manifest: CapabilityManifest,
        payload: Dict[str, Any],
        compensation_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Handle a failure in agent communication.

        This is the main entry point for failure recovery. It:
        1. Diagnoses the failure using scak
        2. Determines the appropriate recovery strategy
        3. Executes compensation if available

        Args:
            trace_id: Unique trace ID for this request
            error: The exception that occurred
            manifest: The agent's capability manifest
            payload: The original request payload
            compensation_callback: Optional callback for rollback

        Returns:
            Dictionary with recovery result and actions taken
        """
        logger.info(f"[Recovery] Handling failure for trace {trace_id}")

        # Determine failure type from exception
        error_name = type(error).__name__
        if "Timeout" in error_name:
            failure_type = FailureType.TIMEOUT
        elif "Resource" in error_name or "Limit" in error_name:
            failure_type = FailureType.RESOURCE_EXHAUSTED
        elif "Invalid" in error_name or "Validation" in error_name:
            failure_type = FailureType.INVALID_ACTION
        else:
            failure_type = FailureType.UNKNOWN

        # Create failure record using scak's AgentFailure model
        failure = AgentFailure(
            agent_id=manifest.agent_id,
            failure_type=failure_type,
            error_message=str(error),
            context={
                "trace_id": trace_id,
                "payload": payload,
                "reversibility": manifest.capabilities.reversibility.value,
            },
            timestamp=datetime.now(timezone.utc)
        )

        # Determine recovery strategy based on manifest and failure type
        # Note: scak's diagnose_failure requires complex tool traces,
        # so we use a simplified diagnosis based on the failure record
        diagnosis = f"{failure_type.value}: {error_name}"

        strategy = self._determine_strategy(
            diagnosis,
            manifest,
            compensation_callback is not None
        )

        # Execute recovery
        recovery_result = await self._execute_recovery(
            strategy=strategy,
            trace_id=trace_id,
            failure=failure,
            manifest=manifest,
            compensation_callback=compensation_callback
        )

        # Record in history
        self.recovery_history[trace_id] = {
            "failure": failure,
            "diagnosis": diagnosis,
            "strategy": strategy,
            "result": recovery_result,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        return recovery_result

    def _determine_strategy(
        self,
        diagnosis: str,
        manifest: CapabilityManifest,
        has_compensation: bool
    ) -> RecoveryStrategy:
        """
        Determine the appropriate recovery strategy.

        Args:
            diagnosis: Failure diagnosis from scak
            manifest: Agent capability manifest
            has_compensation: Whether compensation callback is available

        Returns:
            RecoveryStrategy to use for recovery
        """
        # Check if agent supports reversibility
        reversibility = manifest.capabilities.reversibility.value

        if reversibility in ["full", "partial"] and has_compensation:
            # Agent supports rollback and we have compensation logic
            return RecoveryStrategy.ROLLBACK
        elif reversibility == "partial":
            # Partial rollback - log and warn
            return RecoveryStrategy.RETRY
        elif diagnosis.lower().find("timeout") >= 0:
            # Timeout errors might be transient
            return RecoveryStrategy.RETRY
        else:
            # No recovery possible
            return RecoveryStrategy.GIVE_UP

    async def _execute_recovery(
        self,
        strategy: RecoveryStrategy,
        trace_id: str,
        failure: AgentFailure,
        manifest: CapabilityManifest,
        compensation_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Execute the determined recovery strategy.

        Args:
            strategy: Recovery strategy to execute
            trace_id: Trace ID
            failure: Failure details
            manifest: Agent manifest
            compensation_callback: Optional compensation callback

        Returns:
            Dictionary with recovery results
        """
        result = {
            "strategy": strategy.value,
            "success": False,
            "actions_taken": [],
            "trace_id": trace_id
        }

        if strategy == RecoveryStrategy.ROLLBACK:
            logger.info(f"[Recovery] Executing rollback for {trace_id}")
            result["actions_taken"].append("initiated_rollback")

            if compensation_callback:
                try:
                    # Execute compensation transaction
                    if asyncio.iscoroutinefunction(compensation_callback):
                        await compensation_callback()
                    else:
                        compensation_callback()

                    result["success"] = True
                    result["actions_taken"].append("compensation_executed")
                    logger.info(f"[Recovery] Rollback successful for {trace_id}")
                except Exception as e:
                    result["actions_taken"].append(f"compensation_failed: {str(e)}")
                    logger.error(f"[Recovery] Rollback failed for {trace_id}: {e}")
            else:
                result["actions_taken"].append("no_compensation_available")
                logger.warning(f"[Recovery] No compensation callback for {trace_id}")

        elif strategy == RecoveryStrategy.RETRY:
            logger.info(f"[Recovery] Retry recommended for {trace_id}")
            result["actions_taken"].append("retry_recommended")
            result["retry_possible"] = True
            # Note: Actual retry logic would be implemented by the caller

        else:  # GIVE_UP
            logger.info(f"[Recovery] No recovery possible for {trace_id}")
            result["actions_taken"].append("recovery_not_possible")
            result["message"] = (
                f"Agent '{manifest.agent_id}' does not support rollback and "
                "error is not recoverable. Transaction may be in inconsistent state."
            )

        return result

    def get_recovery_history(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """
        Get recovery history for a trace ID.

        Args:
            trace_id: Trace ID to look up

        Returns:
            Recovery history or None if not found
        """
        return self.recovery_history.get(trace_id)

    def should_attempt_recovery(
        self,
        error: Exception,
        manifest: CapabilityManifest
    ) -> bool:
        """
        Determine if recovery should be attempted for this error.

        Args:
            error: The exception that occurred
            manifest: Agent capability manifest

        Returns:
            True if recovery should be attempted
        """
        # Always attempt recovery if agent supports reversibility
        if manifest.capabilities.reversibility.value in ["full", "partial"]:
            return True

        # Attempt recovery for certain error types
        error_name = type(error).__name__
        recoverable_errors = [
            "TimeoutError",
            "ConnectionError",
            "HTTPError",
            "ServiceUnavailable"
        ]

        return any(err in error_name for err in recoverable_errors)

    async def execute_compensation_transaction(
        self,
        trace_id: str,
        manifest: CapabilityManifest,
        compensation_endpoint: str,
        compensation_payload: Dict[str, Any]
    ) -> bool:
        """
        Execute a compensation transaction using the agent's compensation endpoint.

        This is used when the agent provides a specific compensation/rollback
        endpoint as specified in the handshake.

        Args:
            trace_id: Trace ID
            manifest: Agent manifest with undo_window info
            compensation_endpoint: URL for compensation
            compensation_payload: Payload for compensation request

        Returns:
            True if compensation succeeded
        """
        import httpx

        logger.info(f"[Recovery] Executing compensation transaction for {trace_id}")

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    compensation_endpoint,
                    json=compensation_payload,
                    headers={
                        "X-Agent-Trace-ID": trace_id,
                        "X-Compensation-Request": "true"
                    },
                    timeout=30.0
                )

                if 200 <= response.status_code < 300:
                    logger.info(f"[Recovery] Compensation successful for {trace_id}")
                    return True
                else:
                    logger.error(
                        f"[Recovery] Compensation failed for {trace_id}: "
                        f"status {response.status_code}"
                    )
                    return False

        except Exception as e:
            logger.error(f"[Recovery] Compensation exception for {trace_id}: {e}")
            return False
