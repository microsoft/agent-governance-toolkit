# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Declarative Saga DSL.

Parses step definitions and fan-out groups (with their declared policy and
validated branch references) into a ``SagaDefinition``. ``fan_out_step_ids`` and
``sequential_steps`` expose which steps run in parallel; fan-out groups are
executed by ``FanOutOrchestrator``, which enforces the declared policy.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from hypervisor.saga.fan_out import FanOutPolicy
from hypervisor.saga.schema import SagaSchemaValidator
from hypervisor.saga.state_machine import SagaStep


@dataclass
class SagaDSLStep:
    """A step parsed from the DSL definition."""

    id: str = ""
    action_id: str = ""
    agent: str = ""
    execute_api: str = ""
    undo_api: str | None = None
    timeout: int = 300
    retries: int = 0
    checkpoint_goal: str | None = None


@dataclass
class SagaDSLFanOut:
    """A fan-out group: branches that run in parallel under ``policy``."""

    policy: FanOutPolicy = FanOutPolicy.ALL_MUST_SUCCEED
    branch_step_ids: list[str] = field(default_factory=list)


@dataclass
class SagaDefinition:
    """A complete saga definition parsed from DSL."""

    name: str = ""
    session_id: str = ""
    saga_id: str = field(default_factory=lambda: f"saga:{uuid.uuid4().hex[:8]}")
    steps: list[SagaDSLStep] = field(default_factory=list)
    fan_outs: list[SagaDSLFanOut] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def step_ids(self) -> list[str]:
        return [s.id for s in self.steps]

    @property
    def fan_out_step_ids(self) -> set[str]:
        """Step IDs that belong to any fan-out group (run in parallel)."""
        ids: set[str] = set()
        for fan_out in self.fan_outs:
            ids.update(fan_out.branch_step_ids)
        return ids

    @property
    def sequential_steps(self) -> list[SagaDSLStep]:
        """Steps that are not part of any fan-out group."""
        parallel = self.fan_out_step_ids
        return [s for s in self.steps if s.id not in parallel]


class SagaDSLParser:
    """
    Parses saga definitions from a dict into a ``SagaDefinition``, including
    fan-out groups with their declared policy and validated branch step IDs.
    """

    def __init__(self, *, schema_validation: bool = False) -> None:
        self._schema_validator = SagaSchemaValidator() if schema_validation else None

    def parse(self, definition: dict[str, Any]) -> SagaDefinition:
        """Parse a saga definition dict into a SagaDefinition.

        If schema_validation was enabled at construction, validates against
        the JSON schema before parsing.
        """
        if self._schema_validator is not None:
            self._schema_validator.validate_or_raise(definition)

        name = definition.get("name", "")
        if not name:
            raise SagaDSLError("Saga definition must have a 'name'")

        session_id = definition.get("session_id", "")
        if not session_id:
            raise SagaDSLError("Saga definition must have a 'session_id'")

        raw_steps = definition.get("steps", [])
        if not raw_steps:
            raise SagaDSLError("Saga must have at least one step")

        steps = []
        step_ids = set()
        for raw in raw_steps:
            step = self._parse_step(raw)
            if step.id in step_ids:
                raise SagaDSLError(f"Duplicate step ID: {step.id}")
            step_ids.add(step.id)
            steps.append(step)

        raw_fan_outs = definition.get("fan_out", [])
        if not isinstance(raw_fan_outs, list):
            raise SagaDSLError("'fan_out' must be a list of fan-out groups")
        fan_outs = [self._parse_fan_out(raw_fan_out, step_ids) for raw_fan_out in raw_fan_outs]

        return SagaDefinition(
            name=name,
            session_id=session_id,
            saga_id=definition.get("saga_id", f"saga:{uuid.uuid4().hex[:8]}"),
            steps=steps,
            fan_outs=fan_outs,
            metadata=definition.get("metadata", {}),
        )

    def _parse_step(self, raw: dict) -> SagaDSLStep:
        step_id = raw.get("id", "")
        if not step_id:
            raise SagaDSLError("Each step must have an 'id'")

        action_id = raw.get("action_id", "")
        if not action_id:
            raise SagaDSLError(f"Step {step_id} must have an 'action_id'")

        agent = raw.get("agent", "")
        if not agent:
            raise SagaDSLError(f"Step {step_id} must have an 'agent'")

        return SagaDSLStep(
            id=step_id,
            action_id=action_id,
            agent=agent,
            execute_api=raw.get("execute_api", ""),
            undo_api=raw.get("undo_api"),
            timeout=raw.get("timeout", 300),
            retries=raw.get("retries", 0),
            checkpoint_goal=raw.get("checkpoint_goal"),
        )

    def _parse_fan_out(self, raw: dict, valid_step_ids: set[str]) -> SagaDSLFanOut:
        """Parse a fan-out group, honoring its declared ``policy`` and
        validating each branch against the parsed step IDs.

        Raises ``SagaDSLError`` (not a raw ``AttributeError``/``TypeError``) on
        malformed input, since ``parse`` runs with ``schema_validation=False`` by
        default and so cannot rely on the JSON schema to reject bad shapes.
        """
        if not isinstance(raw, dict):
            raise SagaDSLError(f"Each fan-out group must be an object, got {type(raw).__name__}")

        branches = raw.get("branches", [])
        if not isinstance(branches, list):
            raise SagaDSLError("Fan-out 'branches' must be a list of step IDs")
        for branch_id in branches:
            if branch_id not in valid_step_ids:
                raise SagaDSLError(
                    f"Fan-out branch references unknown step '{branch_id}'"
                )

        policy_raw = raw.get("policy")
        if policy_raw is None:
            policy = FanOutPolicy.ALL_MUST_SUCCEED
        else:
            try:
                policy = FanOutPolicy(policy_raw)
            except ValueError as exc:
                raise SagaDSLError(f"Invalid fan-out policy: '{policy_raw}'") from exc

        return SagaDSLFanOut(policy=policy, branch_step_ids=list(branches))

    def to_saga_steps(self, definition: SagaDefinition) -> list[SagaStep]:
        """Convert a SagaDefinition into SagaStep objects."""
        return [
            SagaStep(
                step_id=s.id,
                action_id=s.action_id,
                agent_did=s.agent,
                execute_api=s.execute_api,
                undo_api=s.undo_api,
                timeout_seconds=s.timeout,
                max_retries=s.retries,
            )
            for s in definition.steps
        ]

    def validate(self, definition: dict[str, Any]) -> list[str]:
        """Validate a definition and return list of errors (empty = valid)."""
        errors = []
        if not definition.get("name"):
            errors.append("Missing 'name'")
        if not definition.get("session_id"):
            errors.append("Missing 'session_id'")
        if not definition.get("steps"):
            errors.append("Missing 'steps'")
        else:
            step_ids = set()
            for i, step in enumerate(definition["steps"]):
                if not step.get("id"):
                    errors.append(f"Step {i} missing 'id'")
                elif step["id"] in step_ids:
                    errors.append(f"Duplicate step ID: {step['id']}")
                else:
                    step_ids.add(step["id"])
                if not step.get("action_id"):
                    errors.append(f"Step {step.get('id', i)} missing 'action_id'")
                if not step.get("agent"):
                    errors.append(f"Step {step.get('id', i)} missing 'agent'")
        return errors


class SagaDSLError(Exception):
    """Raised for invalid saga DSL definitions."""
