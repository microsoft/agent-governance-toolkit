# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Chaos engine — fault injection and resilience testing for agents."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class FaultType(Enum):
    """Types of faults that can be injected (Community Edition: 3 basic types)."""

    LATENCY_INJECTION = "latency_injection"
    ERROR_INJECTION = "error_injection"
    TIMEOUT_INJECTION = "timeout_injection"

    # Adversarial fault types
    PROMPT_INJECTION = "prompt_injection"
    POLICY_BYPASS = "policy_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    TOOL_ABUSE = "tool_abuse"
    IDENTITY_SPOOFING = "identity_spoofing"


class ExperimentState(Enum):
    """State of a chaos experiment."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ABORTED = "aborted"
    FAILED = "failed"


@dataclass
class Fault:
    """A fault to inject during a chaos experiment."""

    fault_type: FaultType
    target: str  # tool name, agent ID, provider name
    rate: float = 1.0  # Fraction of calls affected (0.0-1.0)
    params: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def latency_injection(target: str, delay_ms: int = 5000, rate: float = 1.0) -> Fault:
        """Inject latency into a target."""
        return Fault(FaultType.LATENCY_INJECTION, target, rate, {"delay_ms": delay_ms})

    @staticmethod
    def error_injection(target: str, error: str = "internal_error", rate: float = 1.0) -> Fault:
        """Inject errors into a target."""
        return Fault(FaultType.ERROR_INJECTION, target, rate, {"error": error})

    @staticmethod
    def timeout_injection(target: str, delay_ms: int = 30000, rate: float = 1.0) -> Fault:
        """Inject timeouts into a target."""
        return Fault(FaultType.TIMEOUT_INJECTION, target, rate, {"delay_ms": delay_ms})

    # Adversarial fault factory methods

    @staticmethod
    def prompt_injection(target: str, technique: str = "direct_override", rate: float = 1.0) -> Fault:
        """Inject a prompt injection attack against a target."""
        return Fault(FaultType.PROMPT_INJECTION, target, rate, {"technique": technique})

    @staticmethod
    def policy_bypass(target: str, policy_name: str = "default", rate: float = 1.0) -> Fault:
        """Attempt to bypass a governance policy."""
        return Fault(FaultType.POLICY_BYPASS, target, rate, {"policy_name": policy_name})

    @staticmethod
    def privilege_escalation(target: str, target_role: str = "admin", rate: float = 1.0) -> Fault:
        """Attempt privilege escalation against a target."""
        return Fault(FaultType.PRIVILEGE_ESCALATION, target, rate, {"target_role": target_role})

    @staticmethod
    def data_exfiltration(target: str, data_type: str = "pii", rate: float = 1.0) -> Fault:
        """Simulate data exfiltration attempt."""
        return Fault(FaultType.DATA_EXFILTRATION, target, rate, {"data_type": data_type})

    @staticmethod
    def tool_abuse(target: str, tool_name: str = "shell_exec", rate: float = 1.0) -> Fault:
        """Simulate abuse of a dangerous tool."""
        return Fault(FaultType.TOOL_ABUSE, target, rate, {"tool_name": tool_name})

    @staticmethod
    def identity_spoofing(target: str, spoofed_id: str = "admin-agent", rate: float = 1.0) -> Fault:
        """Simulate identity spoofing attack."""
        return Fault(FaultType.IDENTITY_SPOOFING, target, rate, {"spoofed_id": spoofed_id})

    # Legacy aliases for backward compatibility
    @staticmethod
    def tool_timeout(tool: str, delay_ms: int = 30000, rate: float = 1.0) -> Fault:
        return Fault.timeout_injection(tool, delay_ms, rate)

    @staticmethod
    def tool_error(tool: str, error: str = "internal_error", rate: float = 1.0) -> Fault:
        return Fault.error_injection(tool, error, rate)

    @staticmethod
    def llm_latency(provider: str, p99_ms: int = 15000, rate: float = 1.0) -> Fault:
        return Fault.latency_injection(provider, p99_ms, rate)

    @staticmethod
    def tool_wrong_schema(tool: str, rate: float = 1.0) -> Fault:
        """Not available in Community Edition."""
        raise NotImplementedError("tool_wrong_schema is not available in Community Edition")

    @staticmethod
    def llm_degraded(provider: str, quality: float = 0.5, rate: float = 1.0) -> Fault:
        """Not available in Community Edition."""
        raise NotImplementedError("llm_degraded is not available in Community Edition")

    @staticmethod
    def delegation_reject(from_agent: str, rate: float = 0.1) -> Fault:
        """Not available in Community Edition."""
        raise NotImplementedError("delegation_reject is not available in Community Edition")

    @staticmethod
    def credential_expire(agent: str) -> Fault:
        """Not available in Community Edition."""
        raise NotImplementedError("credential_expire is not available in Community Edition")

    @staticmethod
    def network_partition(agents: list[str]) -> Fault:
        """Not available in Community Edition."""
        raise NotImplementedError("network_partition is not available in Community Edition")

    @staticmethod
    def cost_spike(tool: str, multiplier: float = 10.0) -> Fault:
        """Not available in Community Edition."""
        raise NotImplementedError("cost_spike is not available in Community Edition")

    def to_dict(self) -> dict[str, Any]:
        return {
            "fault_type": self.fault_type.value,
            "target": self.target,
            "rate": self.rate,
            "params": self.params,
        }


@dataclass
class AbortCondition:
    """Condition that stops a chaos experiment for safety."""

    metric: str
    threshold: float
    comparator: str = "lte"  # abort when metric drops below threshold

    def should_abort(self, value: float) -> bool:
        if self.comparator == "lte":
            return value <= self.threshold
        elif self.comparator == "gte":
            return value >= self.threshold
        return False

    def to_dict(self) -> dict[str, Any]:
        return {"metric": self.metric, "threshold": self.threshold, "comparator": self.comparator}


@dataclass
class FaultInjectionEvent:
    """Record of a fault being injected."""

    fault_type: FaultType
    target: str
    timestamp: float = field(default_factory=time.time)
    applied: bool = True
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fault_type": self.fault_type.value,
            "target": self.target,
            "timestamp": self.timestamp,
            "applied": self.applied,
            "details": self.details,
        }


@dataclass
class ResilienceScore:
    """Fault impact score from a chaos experiment (simple pass/fail)."""

    overall: float = 0.0  # 0-100
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall,
            "passed": self.passed,
        }


class ChaosExperiment:
    """A chaos engineering experiment against agent(s)."""

    def __init__(
        self,
        name: str,
        target_agent: str,
        faults: list[Fault],
        duration_seconds: int = 1800,
        abort_conditions: list[AbortCondition] | None = None,
        blast_radius: float = 1.0,
        description: str = "",
    ) -> None:
        self.experiment_id = uuid.uuid4().hex[:12]
        self.name = name
        self.target_agent = target_agent
        self.faults = faults
        self.duration_seconds = duration_seconds
        self.abort_conditions = abort_conditions or []
        self.blast_radius = min(max(blast_radius, 0.0), 1.0)
        self.description = description
        self.state = ExperimentState.PENDING
        self.injection_events: list[FaultInjectionEvent] = []
        self.started_at: float | None = None
        self.ended_at: float | None = None
        self.abort_reason: str | None = None
        self.resilience: ResilienceScore = ResilienceScore()

    @property
    def elapsed_seconds(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.ended_at or time.time()
        return end - self.started_at

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.duration_seconds - self.elapsed_seconds)

    @property
    def is_expired(self) -> bool:
        return self.elapsed_seconds >= self.duration_seconds

    def start(self) -> None:
        """Start the experiment."""
        self.state = ExperimentState.RUNNING
        self.started_at = time.time()

    def inject_fault(self, fault: Fault, applied: bool = True, details: dict[str, Any] | None = None) -> None:
        """Record a fault injection event."""
        self.injection_events.append(FaultInjectionEvent(
            fault_type=fault.fault_type,
            target=fault.target,
            applied=applied,
            details=details or fault.params,
        ))

    def check_abort(self, metrics: dict[str, float]) -> bool:
        """Check abort conditions. Returns True if experiment should stop."""
        for condition in self.abort_conditions:
            value = metrics.get(condition.metric)
            if value is not None and condition.should_abort(value):
                self.abort(reason=f"{condition.metric} = {value} (threshold: {condition.threshold})")
                return True
        return False

    def abort(self, reason: str = "") -> None:
        """Abort the experiment."""
        self.state = ExperimentState.ABORTED
        self.ended_at = time.time()
        self.abort_reason = reason

    def complete(self, resilience: ResilienceScore | None = None) -> None:
        """Mark the experiment as completed."""
        self.state = ExperimentState.COMPLETED
        self.ended_at = time.time()
        if resilience:
            self.resilience = resilience

    def calculate_resilience(
        self,
        baseline_success_rate: float,
        experiment_success_rate: float,
        recovery_time_ms: float = 0.0,
        cost_increase_percent: float = 0.0,
    ) -> ResilienceScore:
        """Calculate fault impact score — simple pass/fail based on success rate."""
        passed = experiment_success_rate >= (baseline_success_rate * 0.9)
        overall = (experiment_success_rate / max(baseline_success_rate, 0.001)) * 100
        overall = max(0.0, min(100.0, overall))

        self.resilience = ResilienceScore(
            overall=round(overall, 1),
            passed=passed,
        )
        return self.resilience

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "name": self.name,
            "target_agent": self.target_agent,
            "state": self.state.value,
            "duration_seconds": self.duration_seconds,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "blast_radius": self.blast_radius,
            "faults": [f.to_dict() for f in self.faults],
            "abort_conditions": [a.to_dict() for a in self.abort_conditions],
            "injection_count": len(self.injection_events),
            "abort_reason": self.abort_reason,
            "resilience": self.resilience.to_dict(),
        }
