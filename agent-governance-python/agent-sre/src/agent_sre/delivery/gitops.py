# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""GitOps rollout spec — declarative YAML deployment definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agent_sre.delivery.rollout import (
    AnalysisCriterion,
    DeploymentStrategy,
    RollbackCondition,
    RolloutStep,
)


class SpecVersion(Enum):
    """GitOps spec API version."""
    V1ALPHA1 = "agent-sre.io/v1alpha1"
    V1BETA1 = "agent-sre.io/v1beta1"


@dataclass
class AgentRef:
    """Reference to an agent version."""
    name: str
    version: str
    image: str = ""
    model: str = ""
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name, "version": self.version}
        if self.image:
            d["image"] = self.image
        if self.model:
            d["model"] = self.model
        if self.config:
            d["config"] = self.config
        return d


@dataclass
class SLORef:
    """Reference to SLO requirements for the rollout."""
    name: str
    target: float
    indicator: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name, "target": self.target}
        if self.indicator:
            d["indicator"] = self.indicator
        return d


@dataclass
class RolloutSpec:
    """Declarative rollout specification for GitOps-style deployments.

    Designed to be serialized to YAML and stored in version control.
    """
    api_version: SpecVersion = SpecVersion.V1ALPHA1
    kind: str = "AgentRollout"
    name: str = ""
    namespace: str = "default"
    description: str = ""
    current: AgentRef = field(default_factory=lambda: AgentRef(name="", version=""))
    candidate: AgentRef = field(default_factory=lambda: AgentRef(name="", version=""))
    strategy: DeploymentStrategy = DeploymentStrategy.CANARY
    steps: list[RolloutStep] = field(default_factory=list)
    rollback_conditions: list[RollbackCondition] = field(default_factory=list)
    slo_requirements: list[SLORef] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "apiVersion": self.api_version.value,
            "kind": self.kind,
            "metadata": {
                "name": self.name,
                "namespace": self.namespace,
                "labels": self.labels,
                "annotations": self.annotations,
            },
            "spec": {
                "description": self.description,
                "strategy": self.strategy.value,
                "current": self.current.to_dict(),
                "candidate": self.candidate.to_dict(),
                "steps": [s.to_dict() for s in self.steps],
                "rollbackConditions": [r.to_dict() for r in self.rollback_conditions],
                "sloRequirements": [s.to_dict() for s in self.slo_requirements],
            },
        }

    def validate(self) -> list[str]:
        """Validate the spec and return a list of errors."""
        errors: list[str] = []
        if not self.name:
            errors.append("metadata.name is required")
        if not self.candidate.name:
            errors.append("spec.candidate.name is required")
        if not self.candidate.version:
            errors.append("spec.candidate.version is required")
        if not self.steps:
            errors.append("spec.steps must have at least one step")
        for i, step in enumerate(self.steps):
            if not (0.0 <= step.weight <= 1.0):
                errors.append(f"spec.steps[{i}].weight must be between 0.0 and 1.0")
        # Steps should be in increasing weight order
        weights = [s.weight for s in self.steps]
        if weights != sorted(weights):
            errors.append("spec.steps weights must be in increasing order")
        return errors

    @classmethod
    def default_canary(
        cls,
        name: str,
        current_version: str,
        candidate_version: str,
        agent_name: str = "",
    ) -> RolloutSpec:
        """Create a default staged rollout spec."""
        return cls(
            name=name,
            current=AgentRef(name=agent_name or name, version=current_version),
            candidate=AgentRef(name=agent_name or name, version=candidate_version),
            strategy=DeploymentStrategy.CANARY,
            steps=[
                RolloutStep(name="canary-5", weight=0.05, duration_seconds=7200,
                    analysis=[AnalysisCriterion("task_success_rate", 0.99)]),
                RolloutStep(name="canary-25", weight=0.25, duration_seconds=14400,
                    analysis=[AnalysisCriterion("task_success_rate", 0.995)]),
                RolloutStep(name="canary-50", weight=0.50, duration_seconds=14400,
                    analysis=[AnalysisCriterion("task_success_rate", 0.995)]),
                RolloutStep(name="full", weight=1.0, duration_seconds=0),
            ],
            rollback_conditions=[
                RollbackCondition("error_rate", 0.05, "gte"),
                RollbackCondition("hallucination_rate", 0.10, "gte"),
            ],
        )

    @classmethod
    def default_shadow(
        cls,
        name: str,
        current_version: str,
        candidate_version: str,
        agent_name: str = "",
    ) -> RolloutSpec:
        """Create a default shadow testing spec."""
        return cls(
            name=name,
            current=AgentRef(name=agent_name or name, version=current_version),
            candidate=AgentRef(name=agent_name or name, version=candidate_version),
            strategy=DeploymentStrategy.SHADOW,
            steps=[
                RolloutStep(name="shadow", weight=0.0, duration_seconds=86400,
                    analysis=[AnalysisCriterion("similarity_score", 0.90)]),
            ],
        )
