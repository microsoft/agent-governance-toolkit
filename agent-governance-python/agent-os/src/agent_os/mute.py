# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Mute Agent Primitives — Face/Hands Architecture as Kernel-Level Primitives.

Separates reasoning from execution with a kernel-enforced trust boundary:
  - Face agent: reasons, plans — never executes actions
  - Mute (Hands) agent: executes — never calls LLMs or produces text

This is the agent equivalent of Unix privilege separation (OpenSSH privsep).

Example:
    >>> from agent_os.mute import face_agent, mute_agent, ExecutionPlan, pipe
    >>>
    >>> @face_agent(capabilities=["db.read", "file.write"])
    ... async def planner(task: str) -> ExecutionPlan:
    ...     # Can call LLM, reason, plan — but cannot execute
    ...     return ExecutionPlan(steps=[
    ...         ActionStep(action="db.read", params={"query": "SELECT 1"})
    ...     ])
    >>>
    >>> @mute_agent(capabilities=["db.read", "file.write"])
    ... async def executor(step: ActionStep) -> dict:
    ...     # Can execute actions — but cannot call LLM or produce text
    ...     return {"rows": [1]}
    >>>
    >>> result = await pipe(planner, executor, "get me the count")
"""

from __future__ import annotations

import functools
import time
from collections.abc import Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
)
from uuid import uuid4

# =============================================================================
# Core Data Types
# =============================================================================


class ActionStatus(Enum):
    """Status of an individual action step."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXECUTED = "executed"
    FAILED = "failed"


@dataclass
class ActionStep:
    """A single atomic action in an execution plan.

    Each step maps to exactly one capability. The kernel validates
    that the step's action is within the agent's granted capabilities
    before allowing execution.

    Attributes:
        action: Capability-scoped action name (e.g. "db.read", "file.write")
        params: Parameters for the action
        description: Human-readable description of what this step does
        depends_on: Indices of steps that must complete before this one
    """
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    depends_on: list[int] = field(default_factory=list)


@dataclass
class ExecutionPlan:
    """Structured output from a Face agent — the contract between Face and Hands.

    The plan is fully enumerable: every step has a named action from a
    known capability set. The kernel validates the entire plan before
    any step executes.

    Attributes:
        steps: Ordered list of action steps
        metadata: Optional metadata from the reasoning phase
        plan_id: Unique identifier for this plan
    """
    steps: list[ActionStep] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    plan_id: str = field(default_factory=lambda: str(uuid4())[:12])

    def __post_init__(self):
        if not isinstance(self.steps, list):
            raise TypeError("steps must be a list of ActionStep")

    @property
    def actions_used(self) -> set[str]:
        """Set of distinct action names used in this plan."""
        return {step.action for step in self.steps}


@dataclass
class StepResult:
    """Result of executing a single ActionStep."""
    step_index: int
    action: str
    status: ActionStatus
    data: Any = None
    error: str | None = None
    duration_ms: float = 0.0


@dataclass
class PipelineResult:
    """Full result of a Face→Hands pipeline execution."""
    plan: ExecutionPlan
    step_results: list[StepResult] = field(default_factory=list)
    success: bool = False
    total_duration_ms: float = 0.0
    denied_steps: list[int] = field(default_factory=list)
    audit_log: list[dict[str, Any]] = field(default_factory=list)

    @property
    def data(self) -> list[Any]:
        """Convenience: collect data from all successful steps."""
        return [r.data for r in self.step_results if r.status == ActionStatus.EXECUTED]


# =============================================================================
# Capability Enforcement
# =============================================================================


class CapabilityViolation(Exception):
    """Raised when an agent tries to use an action outside its capabilities."""

    def __init__(self, agent_role: str, action: str, allowed: set[str]):
        self.agent_role = agent_role
        self.action = action
        self.allowed = allowed
        super().__init__(
            f"{agent_role} agent attempted '{action}' but only has "
            f"capabilities: {sorted(allowed)}"
        )


def _validate_plan_capabilities(
    plan: ExecutionPlan, capabilities: set[str]
) -> list[int]:
    """Validate every step in a plan against allowed capabilities.

    Returns list of step indices that are denied.
    """
    denied: list[int] = []
    for i, step in enumerate(plan.steps):
        if step.action not in capabilities:
            denied.append(i)
    return denied


# =============================================================================
# Decorators — @face_agent and @mute_agent
# =============================================================================


def face_agent(
    capabilities: list[str] | None = None,
):
    """Decorator that marks a function as a Face (reasoning) agent.

    The decorated function:
      - CAN call LLMs, reason, and produce plans
      - MUST return an ExecutionPlan
      - CANNOT execute side-effects (enforced by convention + audit)

    Args:
        capabilities: List of capabilities the plan is allowed to use.
            If provided, the returned plan is validated against this set.
    """
    cap_set = set(capabilities) if capabilities else None

    def decorator(fn: Callable[..., Awaitable[ExecutionPlan]]):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs) -> ExecutionPlan:
            plan = await fn(*args, **kwargs)
            if not isinstance(plan, ExecutionPlan):
                raise TypeError(
                    f"@face_agent function must return ExecutionPlan, "
                    f"got {type(plan).__name__}"
                )
            # Validate plan capabilities if specified
            if cap_set:
                denied = _validate_plan_capabilities(plan, cap_set)
                if denied:
                    bad_actions = {plan.steps[i].action for i in denied}
                    raise CapabilityViolation("face", str(bad_actions), cap_set)
            return plan

        wrapper._agent_role = "face"
        wrapper._capabilities = cap_set
        return wrapper

    return decorator


def mute_agent(
    capabilities: list[str] | None = None,
):
    """Decorator that marks a function as a Mute (Hands/execution) agent.

    The decorated function:
      - CAN execute actions (DB queries, file I/O, API calls)
      - CANNOT call LLMs or produce unstructured text
      - Receives a single ActionStep and returns structured data

    Args:
        capabilities: List of capabilities this executor handles.
    """
    cap_set = set(capabilities) if capabilities else None

    def decorator(fn: Callable[..., Awaitable[Any]]):
        @functools.wraps(fn)
        async def wrapper(step: ActionStep, **kwargs) -> Any:
            if not isinstance(step, ActionStep):
                raise TypeError(
                    f"@mute_agent function receives ActionStep, "
                    f"got {type(step).__name__}"
                )
            # Enforce capability boundary
            if cap_set and step.action not in cap_set:
                raise CapabilityViolation("mute", step.action, cap_set)
            return await fn(step, **kwargs)

        wrapper._agent_role = "mute"
        wrapper._capabilities = cap_set
        return wrapper

    return decorator


# =============================================================================
# Pipeline — kernel.pipe(face, hands, input)
# =============================================================================


async def pipe(
    face_fn: Callable[..., Awaitable[ExecutionPlan]],
    mute_fn: Callable[[ActionStep], Awaitable[Any]],
    task: Any,
    *,
    face_args: dict[str, Any] | None = None,
    halt_on_deny: bool = True,
    halt_on_error: bool = False,
) -> PipelineResult:
    """Execute a Face→Hands pipeline with kernel-level validation.

    1. Face agent produces an ExecutionPlan from the task
    2. Kernel validates plan capabilities
    3. Hands agent executes each step sequentially
    4. Full audit trail is recorded

    Args:
        face_fn: A @face_agent decorated function
        mute_fn: A @mute_agent decorated function
        task: Input to pass to the face agent
        face_args: Extra keyword args for the face agent
        halt_on_deny: Stop pipeline if any step is denied (default True)
        halt_on_error: Stop pipeline if any step fails (default False)

    Returns:
        PipelineResult with step results, audit log, and success status
    """
    start = time.perf_counter()
    audit: list[dict[str, Any]] = []
    result = PipelineResult(plan=ExecutionPlan(), audit_log=audit)

    # Validate decorator roles
    if not getattr(face_fn, "_agent_role", None) == "face":
        raise TypeError("First argument to pipe() must be a @face_agent function")
    if not getattr(mute_fn, "_agent_role", None) == "mute":
        raise TypeError("Second argument to pipe() must be a @mute_agent function")

    # --- Phase 1: Reasoning (Face) ---
    audit.append({
        "phase": "face",
        "event": "start",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "task_preview": str(task)[:200],
    })

    try:
        kw = face_args or {}
        plan = await face_fn(task, **kw)
    except (CapabilityViolation, TypeError) as e:
        audit.append({"phase": "face", "event": "error", "error": str(e)})
        result.success = False
        result.total_duration_ms = (time.perf_counter() - start) * 1000
        return result

    result.plan = plan
    audit.append({
        "phase": "face",
        "event": "plan_produced",
        "plan_id": plan.plan_id,
        "step_count": len(plan.steps),
        "actions": sorted(plan.actions_used),
    })

    # --- Phase 2: Capability Validation (Kernel) ---
    mute_caps = getattr(mute_fn, "_capabilities", None) or set()
    denied_indices = _validate_plan_capabilities(plan, mute_caps) if mute_caps else []
    result.denied_steps = denied_indices

    if denied_indices:
        denied_actions = {plan.steps[i].action for i in denied_indices}
        audit.append({
            "phase": "kernel",
            "event": "capability_denied",
            "denied_steps": denied_indices,
            "denied_actions": sorted(denied_actions),
            "allowed": sorted(mute_caps),
        })
        if halt_on_deny:
            result.success = False
            result.total_duration_ms = (time.perf_counter() - start) * 1000
            for i in denied_indices:
                result.step_results.append(StepResult(
                    step_index=i,
                    action=plan.steps[i].action,
                    status=ActionStatus.DENIED,
                    error=f"Capability '{plan.steps[i].action}' not granted to mute agent",
                ))
            return result

    # --- Phase 3: Execution (Hands) ---
    all_ok = True
    for i, step in enumerate(plan.steps):
        if i in denied_indices:
            result.step_results.append(StepResult(
                step_index=i, action=step.action, status=ActionStatus.DENIED,
            ))
            continue

        # Check dependencies
        deps_met = all(
            result.step_results[d].status == ActionStatus.EXECUTED
            for d in step.depends_on
            if d < len(result.step_results)
        )
        if not deps_met:
            result.step_results.append(StepResult(
                step_index=i, action=step.action, status=ActionStatus.FAILED,
                error="Dependency not met",
            ))
            all_ok = False
            if halt_on_error:
                break
            continue

        step_start = time.perf_counter()
        try:
            data = await mute_fn(step)
            duration = (time.perf_counter() - step_start) * 1000
            result.step_results.append(StepResult(
                step_index=i, action=step.action,
                status=ActionStatus.EXECUTED, data=data, duration_ms=duration,
            ))
            audit.append({
                "phase": "mute",
                "event": "step_executed",
                "step": i,
                "action": step.action,
                "duration_ms": round(duration, 2),
            })
        except CapabilityViolation:
            raise  # Never swallow capability violations
        except Exception as exc:
            duration = (time.perf_counter() - step_start) * 1000
            result.step_results.append(StepResult(
                step_index=i, action=step.action,
                status=ActionStatus.FAILED,
                error=str(exc), duration_ms=duration,
            ))
            audit.append({
                "phase": "mute",
                "event": "step_failed",
                "step": i,
                "action": step.action,
                "error": str(exc),
            })
            all_ok = False
            if halt_on_error:
                break

    result.success = all_ok and len(denied_indices) == 0
    result.total_duration_ms = (time.perf_counter() - start) * 1000
    audit.append({
        "phase": "pipeline",
        "event": "complete",
        "success": result.success,
        "total_ms": round(result.total_duration_ms, 2),
    })

    return result


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Data types
    "ActionStep",
    "ActionStatus",
    "ExecutionPlan",
    "StepResult",
    "PipelineResult",
    # Decorators
    "face_agent",
    "mute_agent",
    # Pipeline
    "pipe",
    # Errors
    "CapabilityViolation",
]
