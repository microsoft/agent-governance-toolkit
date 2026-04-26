# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Kubernetes Operator for Agent-SRE.

Provides CRD definitions, a reconciliation loop, and status management
for deploying Agent-SRE rollouts on Kubernetes. The reconciler translates
``AgentRollout`` CRD specs into in-memory ``CanaryRollout`` instances,
manages their lifecycle, and reports status back.

This module is a **library**, not a standalone operator binary. It can be
embedded into a K8s controller built with ``kopf``, ``operator-sdk``,
or any other controller framework.

Components:
- CRDSchema: AgentRollout CRD YAML generator
- Reconciler: Spec → CanaryRollout lifecycle management
- ResourceStatus: K8s-style status sub-resource
- ConditionType / Condition: K8s status conditions

Usage:
    reconciler = Reconciler()

    # On CRD create/update
    spec_dict = get_crd_spec()
    result = reconciler.reconcile("my-rollout", "default", spec_dict)

    # Check status
    status = reconciler.get_status("my-rollout", "default")
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from agent_sre.delivery.gitops import AgentRef, RolloutSpec, SLORef, SpecVersion
from agent_sre.delivery.rollout import (
    AnalysisCriterion,
    CanaryRollout,
    DeploymentStrategy,
    RollbackCondition,
    RolloutState,
    RolloutStep,
)

# ---------------------------------------------------------------------------
# CRD schema
# ---------------------------------------------------------------------------

CRD_GROUP = "agent-sre.io"
CRD_VERSION = "v1alpha1"
CRD_KIND = "AgentRollout"
CRD_PLURAL = "agentrollouts"


def generate_crd_manifest() -> dict[str, Any]:
    """Generate the AgentRollout CustomResourceDefinition manifest.

    Returns a dict suitable for serialisation to YAML and ``kubectl apply``.
    """
    return {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {
            "name": f"{CRD_PLURAL}.{CRD_GROUP}",
        },
        "spec": {
            "group": CRD_GROUP,
            "names": {
                "kind": CRD_KIND,
                "plural": CRD_PLURAL,
                "singular": "agentrollout",
                "shortNames": ["aroll"],
            },
            "scope": "Namespaced",
            "versions": [
                {
                    "name": CRD_VERSION,
                    "served": True,
                    "storage": True,
                    "schema": {
                        "openAPIV3Schema": _openapi_schema(),
                    },
                    "subresources": {"status": {}},
                    "additionalPrinterColumns": [
                        {"name": "Strategy", "type": "string", "jsonPath": ".spec.strategy"},
                        {"name": "Phase", "type": "string", "jsonPath": ".status.phase"},
                        {"name": "Weight", "type": "number", "jsonPath": ".status.currentWeight"},
                        {"name": "Age", "type": "date", "jsonPath": ".metadata.creationTimestamp"},
                    ],
                }
            ],
        },
    }


def _openapi_schema() -> dict[str, Any]:
    """OpenAPI v3 schema for AgentRollout CRD."""
    return {
        "type": "object",
        "properties": {
            "spec": {
                "type": "object",
                "required": ["candidate"],
                "properties": {
                    "description": {"type": "string"},
                    "strategy": {
                        "type": "string",
                        "enum": ["canary", "shadow", "blue_green"],
                        "default": "canary",
                    },
                    "current": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "version": {"type": "string"},
                            "image": {"type": "string"},
                            "model": {"type": "string"},
                        },
                    },
                    "candidate": {
                        "type": "object",
                        "required": ["name", "version"],
                        "properties": {
                            "name": {"type": "string"},
                            "version": {"type": "string"},
                            "image": {"type": "string"},
                            "model": {"type": "string"},
                        },
                    },
                    "steps": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "weight": {"type": "number", "minimum": 0, "maximum": 1},
                                "durationSeconds": {"type": "integer", "minimum": 0},
                                "manualGate": {"type": "boolean", "default": False},
                            },
                        },
                    },
                    "rollbackConditions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "metric": {"type": "string"},
                                "threshold": {"type": "number"},
                                "operator": {"type": "string", "enum": ["gte", "lte", "gt", "lt"]},
                            },
                        },
                    },
                    "sloRequirements": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "target": {"type": "number"},
                                "indicator": {"type": "string"},
                            },
                        },
                    },
                },
            },
            "status": {
                "type": "object",
                "properties": {
                    "phase": {"type": "string"},
                    "currentStep": {"type": "integer"},
                    "currentWeight": {"type": "number"},
                    "conditions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string"},
                                "status": {"type": "string"},
                                "reason": {"type": "string"},
                                "message": {"type": "string"},
                                "lastTransitionTime": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# Status conditions (K8s-style)
# ---------------------------------------------------------------------------

class ConditionType(Enum):
    """Standard K8s-style condition types for AgentRollout."""

    AVAILABLE = "Available"
    PROGRESSING = "Progressing"
    DEGRADED = "Degraded"
    ROLLED_BACK = "RolledBack"


class ConditionStatus(Enum):
    TRUE = "True"
    FALSE = "False"
    UNKNOWN = "Unknown"


@dataclass
class Condition:
    """A K8s-style status condition."""

    type: ConditionType
    status: ConditionStatus = ConditionStatus.UNKNOWN
    reason: str = ""
    message: str = ""
    last_transition_time: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "status": self.status.value,
            "reason": self.reason,
            "message": self.message,
            "lastTransitionTime": self.last_transition_time,
        }


@dataclass
class ResourceStatus:
    """Status sub-resource for an AgentRollout."""

    phase: str = "Pending"
    current_step: int = 0
    current_weight: float = 0.0
    conditions: list[Condition] = field(default_factory=list)
    observed_generation: int = 0
    message: str = ""

    def set_condition(
        self,
        ctype: ConditionType,
        status: ConditionStatus,
        reason: str = "",
        message: str = "",
    ) -> None:
        """Set or update a condition, replacing any existing one of the same type."""
        for i, c in enumerate(self.conditions):
            if c.type == ctype:
                self.conditions[i] = Condition(ctype, status, reason, message)
                return
        self.conditions.append(Condition(ctype, status, reason, message))

    def get_condition(self, ctype: ConditionType) -> Condition | None:
        for c in self.conditions:
            if c.type == ctype:
                return c
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "currentStep": self.current_step,
            "currentWeight": self.current_weight,
            "conditions": [c.to_dict() for c in self.conditions],
            "observedGeneration": self.observed_generation,
            "message": self.message,
        }


# ---------------------------------------------------------------------------
# Reconcile result
# ---------------------------------------------------------------------------

class ReconcileAction(Enum):
    """What the reconciler decided to do."""

    CREATED = "created"      # New rollout started
    ADVANCED = "advanced"    # Moved to next step
    ROLLED_BACK = "rolled_back"  # Rollback triggered
    COMPLETED = "completed"  # Rollout finished successfully
    NOOP = "noop"            # No change needed
    ERROR = "error"          # Reconciliation failed


@dataclass
class ReconcileResult:
    """Result of a reconciliation cycle."""

    action: ReconcileAction
    name: str
    namespace: str
    status: ResourceStatus
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "name": self.name,
            "namespace": self.namespace,
            "status": self.status.to_dict(),
            "message": self.message,
        }


# ---------------------------------------------------------------------------
# Reconciler
# ---------------------------------------------------------------------------

def _parse_spec(spec_dict: dict[str, Any]) -> RolloutSpec:
    """Parse a CRD spec dict into a RolloutSpec."""
    strategy_str = spec_dict.get("strategy", "canary")
    strategy = DeploymentStrategy(strategy_str)

    current_data = spec_dict.get("current", {})
    candidate_data = spec_dict.get("candidate", {})

    steps = []
    for s in spec_dict.get("steps", []):
        analysis = []
        for a in s.get("analysis", []):
            analysis.append(AnalysisCriterion(a["metric"], a["threshold"]))
        steps.append(RolloutStep(
            name=s.get("name", ""),
            weight=s.get("weight", 0.0),
            duration_seconds=s.get("durationSeconds", 3600),
            analysis=analysis,
            manual_gate=s.get("manualGate", False),
        ))

    rollback_conditions = []
    for rc in spec_dict.get("rollbackConditions", []):
        rollback_conditions.append(RollbackCondition(
            metric=rc["metric"],
            threshold=rc["threshold"],
            comparator=rc.get("operator", "gte"),
        ))

    slo_reqs = []
    for sr in spec_dict.get("sloRequirements", []):
        slo_reqs.append(SLORef(
            name=sr["name"],
            target=sr["target"],
            indicator=sr.get("indicator", ""),
        ))

    return RolloutSpec(
        strategy=strategy,
        current=AgentRef(
            name=current_data.get("name", ""),
            version=current_data.get("version", ""),
            image=current_data.get("image", ""),
            model=current_data.get("model", ""),
        ),
        candidate=AgentRef(
            name=candidate_data.get("name", ""),
            version=candidate_data.get("version", ""),
            image=candidate_data.get("image", ""),
            model=candidate_data.get("model", ""),
        ),
        steps=steps,
        rollback_conditions=rollback_conditions,
        slo_requirements=slo_reqs,
    )


class Reconciler:
    """Reconciles AgentRollout CRD specs into CanaryRollout instances.

    Tracks active rollouts and their status. Each ``reconcile()`` call
    is idempotent — the reconciler decides the appropriate action based
    on current state vs desired spec.
    """

    def __init__(self) -> None:
        self._rollouts: dict[str, CanaryRollout] = {}  # key = "namespace/name"
        self._statuses: dict[str, ResourceStatus] = {}
        self._specs: dict[str, RolloutSpec] = {}
        self._generations: dict[str, int] = {}

    def _key(self, name: str, namespace: str) -> str:
        return f"{namespace}/{name}"

    # -- Reconciliation --

    def reconcile(
        self,
        name: str,
        namespace: str,
        spec_dict: dict[str, Any],
        generation: int = 1,
    ) -> ReconcileResult:
        """Reconcile a CRD spec — create, advance, or rollback as needed."""
        key = self._key(name, namespace)

        try:
            parsed = _parse_spec(spec_dict)
        except (KeyError, ValueError) as exc:
            status = ResourceStatus(phase="Error", message=str(exc))
            self._statuses[key] = status
            return ReconcileResult(
                action=ReconcileAction.ERROR,
                name=name,
                namespace=namespace,
                status=status,
                message=f"Invalid spec: {exc}",
            )

        # Check if this is a new rollout or an update
        existing = self._rollouts.get(key)
        prev_gen = self._generations.get(key, 0)

        if existing is None or generation > prev_gen:
            return self._create_rollout(key, name, namespace, parsed, generation)

        # Existing rollout — check if it needs advancing or rollback
        return self._sync_rollout(key, name, namespace, existing, parsed)

    def _create_rollout(
        self,
        key: str,
        name: str,
        namespace: str,
        spec: RolloutSpec,
        generation: int,
    ) -> ReconcileResult:
        """Create a new rollout from spec."""
        rollout = CanaryRollout(
            name=name,
            steps=spec.steps or [RolloutStep(weight=1.0)],
            rollback_conditions=spec.rollback_conditions,
        )
        rollout.start()

        self._rollouts[key] = rollout
        self._specs[key] = spec
        self._generations[key] = generation

        status = ResourceStatus(
            phase=rollout.state.value,
            current_step=0,
            current_weight=rollout.current_step.weight if rollout.current_step else 0.0,
            observed_generation=generation,
            message=f"Rollout started: {spec.candidate.name}@{spec.candidate.version}",
        )
        status.set_condition(
            ConditionType.PROGRESSING,
            ConditionStatus.TRUE,
            reason="RolloutStarted",
            message=f"Started canary for {spec.candidate.name}",
        )
        self._statuses[key] = status

        return ReconcileResult(
            action=ReconcileAction.CREATED,
            name=name,
            namespace=namespace,
            status=status,
            message=f"Created rollout for {spec.candidate.name}@{spec.candidate.version}",
        )

    def _sync_rollout(
        self,
        key: str,
        name: str,
        namespace: str,
        rollout: CanaryRollout,
        spec: RolloutSpec,
    ) -> ReconcileResult:
        """Sync an existing rollout — check if advance or rollback needed."""
        status = self._statuses.get(key, ResourceStatus())

        # Already complete or rolled back?
        if rollout.state in (RolloutState.COMPLETE, RolloutState.ROLLED_BACK):
            status.phase = rollout.state.value
            action = ReconcileAction.COMPLETED if rollout.state == RolloutState.COMPLETE else ReconcileAction.ROLLED_BACK
            return ReconcileResult(
                action=action,
                name=name,
                namespace=namespace,
                status=status,
            )

        # Default noop
        status.phase = rollout.state.value
        status.current_weight = rollout.current_step.weight if rollout.current_step else 0.0
        self._statuses[key] = status

        return ReconcileResult(
            action=ReconcileAction.NOOP,
            name=name,
            namespace=namespace,
            status=status,
        )

    # -- Manual operations --

    def advance(self, name: str, namespace: str) -> ReconcileResult:
        """Advance a rollout to the next step."""
        key = self._key(name, namespace)
        rollout = self._rollouts.get(key)
        if rollout is None:
            return ReconcileResult(
                action=ReconcileAction.ERROR,
                name=name,
                namespace=namespace,
                status=ResourceStatus(phase="Error", message="Rollout not found"),
                message="Rollout not found",
            )

        advanced = rollout.advance()
        status = self._statuses.get(key, ResourceStatus())

        if rollout.state == RolloutState.COMPLETE:
            status.phase = "complete"
            status.current_weight = 1.0
            status.set_condition(
                ConditionType.AVAILABLE,
                ConditionStatus.TRUE,
                reason="RolloutComplete",
                message="Candidate promoted to 100%",
            )
            status.set_condition(
                ConditionType.PROGRESSING,
                ConditionStatus.FALSE,
                reason="RolloutComplete",
            )
            self._statuses[key] = status
            return ReconcileResult(
                action=ReconcileAction.COMPLETED,
                name=name,
                namespace=namespace,
                status=status,
                message="Rollout completed",
            )

        if advanced:
            step = rollout.current_step
            status.phase = rollout.state.value
            status.current_step += 1
            status.current_weight = step.weight if step else 0.0
            status.message = f"Advanced to step {status.current_step}"
            self._statuses[key] = status
            return ReconcileResult(
                action=ReconcileAction.ADVANCED,
                name=name,
                namespace=namespace,
                status=status,
                message=f"Advanced to weight {status.current_weight}",
            )

        return ReconcileResult(
            action=ReconcileAction.NOOP,
            name=name,
            namespace=namespace,
            status=status,
        )

    def rollback(self, name: str, namespace: str, reason: str = "") -> ReconcileResult:
        """Rollback a rollout."""
        key = self._key(name, namespace)
        rollout = self._rollouts.get(key)
        if rollout is None:
            return ReconcileResult(
                action=ReconcileAction.ERROR,
                name=name,
                namespace=namespace,
                status=ResourceStatus(phase="Error", message="Rollout not found"),
            )

        rollout.rollback(reason)
        status = self._statuses.get(key, ResourceStatus())
        status.phase = "rolled_back"
        status.current_weight = 0.0
        status.message = reason or "Manual rollback"
        status.set_condition(
            ConditionType.ROLLED_BACK,
            ConditionStatus.TRUE,
            reason="ManualRollback",
            message=reason,
        )
        self._statuses[key] = status

        return ReconcileResult(
            action=ReconcileAction.ROLLED_BACK,
            name=name,
            namespace=namespace,
            status=status,
            message=f"Rolled back: {reason}",
        )

    # -- Queries --

    def get_status(self, name: str, namespace: str) -> ResourceStatus | None:
        return self._statuses.get(self._key(name, namespace))

    def get_rollout(self, name: str, namespace: str) -> CanaryRollout | None:
        return self._rollouts.get(self._key(name, namespace))

    def list_rollouts(self, namespace: str | None = None) -> list[dict[str, Any]]:
        """List all managed rollouts."""
        results = []
        for key, status in self._statuses.items():
            ns, name = key.split("/", 1)
            if namespace and ns != namespace:
                continue
            results.append({
                "name": name,
                "namespace": ns,
                "phase": status.phase,
                "currentWeight": status.current_weight,
            })
        return results

    @property
    def active_count(self) -> int:
        """Number of active (non-terminal) rollouts."""
        count = 0
        for _key, rollout in self._rollouts.items():
            if rollout.state not in (RolloutState.COMPLETE, RolloutState.ROLLED_BACK):
                count += 1
        return count
