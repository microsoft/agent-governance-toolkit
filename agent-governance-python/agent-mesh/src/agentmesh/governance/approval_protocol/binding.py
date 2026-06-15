# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Action binding for the action-bound approval protocol (ADR-0030 section 2).

An :class:`ActionBinding` captures the exact executable request an approval
authorizes. Its ``action_digest`` is the SHA-256 over the RFC 8785 JCS
serialization of the binding, so an approval for one binding can never
authorize a different action: change a parameter, the target, the tool schema
version, the acting agent, or the represented subject, and the digest changes.

The full parameters need not be persisted in the approval record, but the
execution boundary MUST be able to recompute the digest from the action it is
about to execute (see :mod:`.coordinator`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from .digest import sha256_jcs

#: Schema version stamped into every binding. Bump only with a migration.
SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class ActionTarget:
    """The tool/resource an action operates on."""

    tool_name: str
    tool_schema_version: str
    resource: Optional[str] = None

    def to_canonical(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_schema_version": self.tool_schema_version,
            "resource": self.resource,
        }


@dataclass(frozen=True)
class ActionBinding:
    """The exact executable request an approval is bound to.

    Args:
        operation: Operation kind, e.g. ``"tool.invoke"``.
        agent_id: The acting agent.
        target: The tool/resource being acted on.
        parameters: The exact parameters the action will execute with. Values
            must be JSON types; non-JSON values raise from :func:`digest`.
        subject_id: The represented principal, if any.
        schema_version: Binding schema version (defaults to current).
    """

    operation: str
    agent_id: str
    target: ActionTarget
    parameters: Mapping[str, Any] = field(default_factory=dict)
    subject_id: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def to_canonical(self) -> dict[str, Any]:
        """Return the canonical mapping hashed into the action digest."""
        return {
            "schema_version": self.schema_version,
            "operation": self.operation,
            "agent_id": self.agent_id,
            "subject_id": self.subject_id,
            "target": self.target.to_canonical(),
            "parameters": dict(self.parameters),
        }

    def digest(self) -> str:
        """Return the ``"sha256:<hex>"`` action digest for this binding."""
        return sha256_jcs(self.to_canonical())
