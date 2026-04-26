# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
GovernedRunner - Agent-Lightning Runner with Policy Enforcement
================================================================

Wraps agent execution with Agent OS kernel governance.
Policy violations during training become learning signals.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar

logger = logging.getLogger(__name__)

T_task = TypeVar("T_task")


class PolicyViolationType(Enum):
    """Types of policy violations."""
    BLOCKED = "blocked"          # Action was blocked entirely
    MODIFIED = "modified"        # Action was modified before execution
    WARNED = "warned"            # Warning issued but action allowed
    SIGNAL_SENT = "signal_sent"  # Kernel signal was sent (SIGSTOP, etc.)


@dataclass
class PolicyViolation:
    """Record of a policy violation during execution."""
    violation_type: PolicyViolationType
    policy_name: str
    description: str
    severity: str  # critical, high, medium, low
    timestamp: datetime = field(default_factory=datetime.utcnow)
    action_blocked: bool = False
    penalty: float = 0.0

    def __post_init__(self):
        """Calculate penalty based on severity."""
        severity_penalties = {
            "critical": 100.0,
            "high": 50.0,
            "medium": 10.0,
            "low": 1.0,
        }
        self.penalty = severity_penalties.get(self.severity, 10.0)


@dataclass
class GovernedRollout:
    """Rollout with governance metadata."""
    task_input: Any
    task_output: Any
    success: bool
    violations: list[PolicyViolation] = field(default_factory=list)
    signals_sent: list[str] = field(default_factory=list)
    total_penalty: float = 0.0
    execution_time_ms: float = 0.0

    def __post_init__(self):
        """Calculate total penalty from violations."""
        self.total_penalty = sum(v.penalty for v in self.violations)


class GovernedRunner(Generic[T_task]):
    """
    Agent-Lightning compatible runner with Agent OS governance.

    This runner wraps agent execution in the kernel, enforcing policies
    and collecting violation data that can be used as RL training signals.

    Example:
        >>> from agent_os import KernelSpace
        >>> from agent_os.policies import SQLPolicy, CostControlPolicy
        >>>
        >>> kernel = KernelSpace(policy=[
        ...     SQLPolicy(deny=["DROP", "DELETE"]),
        ...     CostControlPolicy(max_cost_usd=100)
        ... ])
        >>>
        >>> runner = GovernedRunner(kernel)
        >>>
        >>> # Use with Agent-Lightning trainer
        >>> from agentlightning import Trainer
        >>> trainer = Trainer(runner=runner, algorithm="GRPO")
    """

    def __init__(
        self,
        kernel: Any,  # KernelSpace
        *,
        fail_on_violation: bool = False,
        log_violations: bool = True,
        violation_callback: callable | None = None,
    ):
        """
        Initialize governed runner.

        Args:
            kernel: Agent OS KernelSpace with loaded policies
            fail_on_violation: If True, raise exception on policy violation
            log_violations: If True, log all violations
            violation_callback: Optional callback for each violation
        """
        self.kernel = kernel
        self.fail_on_violation = fail_on_violation
        self.log_violations = log_violations
        self.violation_callback = violation_callback

        # Track violations across rollouts
        self._current_violations: list[PolicyViolation] = []
        self._current_signals: list[str] = []
        self._total_violations = 0
        self._total_rollouts = 0

        logger.info("GovernedRunner initialized with kernel policies")

    def init(self, agent: Any, **kwargs: Any) -> None:
        """
        Initialize runner with agent.

        This is called once during setup, not for each worker.
        """
        self.agent = agent
        self._setup_kernel_hooks()
        logger.info(f"GovernedRunner initialized for agent: {getattr(agent, 'name', 'unnamed')}")

    def init_worker(self, worker_id: int, store: Any, **kwargs: Any) -> None:
        """
        Configure worker-local state.

        Args:
            worker_id: Unique worker identifier
            store: LightningStore for coordination
        """
        self.worker_id = worker_id
        self.store = store
        logger.debug(f"Worker {worker_id} initialized")

    def teardown(self) -> None:
        """Release resources."""
        logger.info(
            f"GovernedRunner teardown: {self._total_rollouts} rollouts, "
            f"{self._total_violations} violations"
        )

    def teardown_worker(self, worker_id: int) -> None:
        """Release worker resources."""
        logger.debug(f"Worker {worker_id} torn down")

    def _setup_kernel_hooks(self) -> None:
        """Set up kernel hooks to capture violations and signals."""
        # Hook into kernel's policy check
        if hasattr(self.kernel, 'on_policy_violation'):
            self.kernel.on_policy_violation(self._handle_violation)

        # Hook into kernel's signal dispatch
        if hasattr(self.kernel, 'on_signal'):
            self.kernel.on_signal(self._handle_signal)

    def _handle_violation(
        self,
        policy_name: str,
        description: str,
        severity: str,
        blocked: bool,
    ) -> None:
        """Handle a policy violation from the kernel."""
        violation = PolicyViolation(
            violation_type=PolicyViolationType.BLOCKED if blocked else PolicyViolationType.WARNED,
            policy_name=policy_name,
            description=description,
            severity=severity,
            action_blocked=blocked,
        )

        self._current_violations.append(violation)
        self._total_violations += 1

        if self.log_violations:
            logger.warning(
                f"Policy violation: {policy_name} - {description} "
                f"(severity={severity}, blocked={blocked})"
            )

        if self.violation_callback:
            self.violation_callback(violation)

        if self.fail_on_violation and blocked:
            raise PolicyViolationError(violation)

    def _handle_signal(self, signal: str, agent_id: str) -> None:
        """Handle a kernel signal."""
        self._current_signals.append(signal)
        logger.debug(f"Signal {signal} sent to agent {agent_id}")

    def _clear_current_state(self) -> None:
        """Clear state for new rollout."""
        self._current_violations = []
        self._current_signals = []

    async def step(
        self,
        input: T_task,
        *,
        resources: Any | None = None,
        mode: str | None = None,
        event: Any | None = None,
    ) -> GovernedRollout:
        """
        Execute a single task with governance.

        This is the main entry point for Agent-Lightning integration.

        Args:
            input: Task input
            resources: Optional named resources
            mode: Rollout mode ("train" or "eval")
            event: Cooperative stop signal

        Returns:
            GovernedRollout with execution results and violation data
        """
        import time

        self._clear_current_state()
        start_time = time.perf_counter()

        try:
            # Execute through kernel
            if hasattr(self.kernel, 'execute_async'):
                result = await self.kernel.execute_async(self.agent, input)
            elif hasattr(self.kernel, 'execute'):
                result = self.kernel.execute(self.agent, input)
            else:
                # Fallback: direct agent call (no governance)
                logger.warning("Kernel has no execute method, running agent directly")
                result = await self.agent(input)

            success = True

        except PolicyViolationError as e:
            result = None
            success = False
            logger.error(f"Execution blocked by policy: {e.violation.description}")

        except Exception as e:
            result = None
            success = False
            logger.error(f"Execution failed: {e}")

        execution_time = (time.perf_counter() - start_time) * 1000
        self._total_rollouts += 1

        rollout = GovernedRollout(
            task_input=input,
            task_output=result,
            success=success,
            violations=self._current_violations.copy(),
            signals_sent=self._current_signals.copy(),
            execution_time_ms=execution_time,
        )

        # Emit to Agent-Lightning if available
        self._emit_governance_spans(rollout)

        return rollout

    async def iter(self, *, event: Any | None = None) -> None:
        """
        Run continuously, processing tasks from the store.

        Args:
            event: Cooperative stop signal
        """
        while event is None or not event.is_set():
            task = await self._get_next_task()
            if task is None:
                break

            rollout = await self.step(task)
            await self._submit_rollout(rollout)

    async def _get_next_task(self) -> T_task | None:
        """Get next task from store."""
        if hasattr(self.store, 'get_task'):
            return await self.store.get_task()
        return None

    async def _submit_rollout(self, rollout: GovernedRollout) -> None:
        """Submit rollout to store."""
        if hasattr(self.store, 'submit_rollout'):
            await self.store.submit_rollout(rollout)

    def _emit_governance_spans(self, rollout: GovernedRollout) -> None:
        """Emit governance data as Agent-Lightning spans."""
        try:
            from agentlightning.emitter import emit_annotation

            # Emit violation summary
            if rollout.violations:
                emit_annotation({
                    "agent_os.violations": len(rollout.violations),
                    "agent_os.total_penalty": rollout.total_penalty,
                    "agent_os.violation_types": [v.violation_type.value for v in rollout.violations],
                    "agent_os.policies_violated": list({v.policy_name for v in rollout.violations}),
                })

            # Emit signal summary
            if rollout.signals_sent:
                emit_annotation({
                    "agent_os.signals": rollout.signals_sent,
                })

        except ImportError:
            # Agent-Lightning not available
            pass

    def get_violation_rate(self) -> float:
        """Get the violation rate across all rollouts."""
        if self._total_rollouts == 0:
            return 0.0
        return self._total_violations / self._total_rollouts

    def get_stats(self) -> dict:
        """Get runner statistics."""
        return {
            "total_rollouts": self._total_rollouts,
            "total_violations": self._total_violations,
            "violation_rate": self.get_violation_rate(),
        }


class PolicyViolationError(Exception):
    """Raised when a policy violation blocks execution."""

    def __init__(self, violation: PolicyViolation):
        self.violation = violation
        super().__init__(f"Policy violation: {violation.description}")
