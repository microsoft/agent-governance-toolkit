# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
JSON Schema validation for Saga DSL definitions.

Validates saga definitions at parse time with clear error messages
for missing fields, invalid types, and constraint violations.
"""

from __future__ import annotations

from typing import Any

import jsonschema

# Valid action type prefixes for step action_ids
VALID_ACTION_PREFIXES = (
    "model.", "data.", "deploy.", "validate.", "notify.",
    "infra.", "security.", "monitor.", "config.", "test.",
)

SAGA_STEP_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["id", "action_id", "agent"],
    "properties": {
        "id": {
            "type": "string",
            "minLength": 1,
            "description": "Unique step identifier",
        },
        "action_id": {
            "type": "string",
            "minLength": 1,
            "description": "Action type (e.g. 'model.validate', 'deploy.k8s')",
        },
        "agent": {
            "type": "string",
            "minLength": 1,
            "description": "Agent DID or identifier",
        },
        "execute_api": {
            "type": "string",
            "description": "API endpoint for execution",
        },
        "undo_api": {
            "type": ["string", "null"],
            "description": "API endpoint for compensation/rollback",
        },
        "timeout": {
            "type": "integer",
            "minimum": 1,
            "maximum": 86400,
            "description": "Timeout in seconds (1–86400)",
        },
        "retries": {
            "type": "integer",
            "minimum": 0,
            "maximum": 10,
            "description": "Max retries (0–10)",
        },
        "checkpoint_goal": {
            "type": ["string", "null"],
            "description": "Semantic checkpoint goal",
        },
        "depends_on": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
            "uniqueItems": True,
            "description": "Step IDs this step depends on",
        },
    },
    "additionalProperties": False,
}

SAGA_DEFINITION_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SagaDefinition",
    "description": "Schema for saga DSL definitions",
    "type": "object",
    "required": ["name", "session_id", "steps"],
    "properties": {
        "name": {
            "type": "string",
            "minLength": 1,
            "description": "Saga name",
        },
        "session_id": {
            "type": "string",
            "minLength": 1,
            "description": "Session identifier",
        },
        "saga_id": {
            "type": "string",
            "description": "Optional saga identifier",
        },
        "steps": {
            "type": "array",
            "minItems": 1,
            "items": SAGA_STEP_SCHEMA,
            "description": "Ordered list of saga steps",
        },
        "fan_out": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "policy": {"type": "string"},
                    "branches": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            },
            "description": "Fan-out groups (Public Preview: ignored)",
        },
        "metadata": {
            "type": "object",
            "description": "Arbitrary metadata",
        },
    },
    "additionalProperties": False,
}


class SagaSchemaValidator:
    """Validates saga definitions against JSON schema and semantic rules."""

    def __init__(self) -> None:
        self._validator = jsonschema.Draft202012Validator(SAGA_DEFINITION_SCHEMA)

    def validate(self, definition: dict[str, Any]) -> list[str]:
        """Validate definition and return list of error messages (empty = valid).

        Performs both JSON schema validation and semantic checks:
        - Required fields and types
        - Step structure constraints
        - Unique step IDs
        - Valid action type prefixes
        - Timeout and retry ranges
        - Compensation requirements
        - Step dependency references
        """
        errors: list[str] = []

        # JSON schema validation
        for error in sorted(self._validator.iter_errors(definition), key=lambda e: list(e.path)):
            path = ".".join(str(p) for p in error.absolute_path) or "(root)"
            errors.append(f"[{path}] {error.message}")

        # Semantic checks only if basic structure is valid
        if not errors and isinstance(definition.get("steps"), list):
            errors.extend(self._check_semantic_rules(definition))

        return errors

    def validate_or_raise(self, definition: dict[str, Any]) -> None:
        """Validate and raise SagaSchemaError if invalid."""
        errors = self.validate(definition)
        if errors:
            raise SagaSchemaError(
                f"Saga definition has {len(errors)} validation error(s):\n"
                + "\n".join(f"  - {e}" for e in errors),
                errors=errors,
            )

    def _check_semantic_rules(self, definition: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        steps = definition["steps"]
        step_ids: set[str] = set()

        for i, step in enumerate(steps):
            sid = step.get("id", f"<index {i}>")

            # Duplicate step IDs
            if sid in step_ids:
                errors.append(f"Duplicate step ID: '{sid}'")
            step_ids.add(sid)

            # Action type prefix validation
            action_id = step.get("action_id", "")
            if action_id and not any(action_id.startswith(p) for p in VALID_ACTION_PREFIXES):
                errors.append(
                    f"Step '{sid}': action_id '{action_id}' does not start with a "
                    f"valid prefix ({', '.join(VALID_ACTION_PREFIXES)})"
                )

            # Compensation requirement: every step should have undo_api
            if step.get("undo_api") is None:
                errors.append(
                    f"Step '{sid}': missing 'undo_api' — every action should have a compensation endpoint"
                )

        # Dependency validation
        for step in steps:
            for dep in step.get("depends_on", []):
                if dep not in step_ids:
                    errors.append(
                        f"Step '{step['id']}': depends_on references unknown step '{dep}'"
                    )

        # Circular dependency detection
        errors.extend(self._check_circular_deps(steps))

        return errors

    def _check_circular_deps(self, steps: list[dict[str, Any]]) -> list[str]:
        """Detect circular dependencies via DFS."""
        graph: dict[str, list[str]] = {}
        for step in steps:
            sid = step.get("id", "")
            graph[sid] = step.get("depends_on", [])

        visited: set[str] = set()
        in_stack: set[str] = set()
        errors: list[str] = []

        def dfs(node: str) -> bool:
            if node in in_stack:
                errors.append(f"Circular dependency detected involving step '{node}'")
                return True
            if node in visited:
                return False
            visited.add(node)
            in_stack.add(node)
            for dep in graph.get(node, []):
                if dfs(dep):
                    return True
            in_stack.discard(node)
            return False

        for sid in graph:
            if sid not in visited:
                dfs(sid)

        return errors


class SagaSchemaError(Exception):
    """Raised when a saga definition fails schema validation."""

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or []
