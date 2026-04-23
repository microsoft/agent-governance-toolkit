# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Session state with monotonic (ratchet) attributes.

Tracks runtime attributes across tool calls within a session.
Attributes declared as ``monotonic`` can only move forward in their
ordering — once an agent touches confidential data, sensitivity
cannot be reset to public.

Usage::

    from agentmesh.governance.session_state import SessionState, SessionAttribute

    state = SessionState([
        SessionAttribute(
            name="data_sensitivity",
            ordering=["public", "internal", "confidential", "restricted"],
            monotonic=True,
        ),
    ])

    state.set("data_sensitivity", "confidential")  # OK
    state.set("data_sensitivity", "public")         # ignored (monotonic)
    assert state.get("data_sensitivity") == "confidential"
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class SessionAttribute:
    """Definition of a session-scoped attribute.

    Attributes:
        name: Attribute name (used in policy conditions as ``session.<name>``).
        ordering: Ordered list of allowed values (low → high).
        monotonic: If True, value can only move forward in ordering.
        initial: Starting value. Defaults to first item in ordering.
    """

    name: str
    ordering: list[str] = field(default_factory=list)
    monotonic: bool = False
    initial: Optional[str] = None

    def __post_init__(self):
        if self.initial is None and self.ordering:
            self.initial = self.ordering[0]


class SessionState:
    """Tracks runtime session attributes with optional monotonic enforcement.

    Integrates with PolicyEngine by injecting ``session.*`` keys into
    the evaluation context.
    """

    def __init__(self, attributes: list[SessionAttribute] | None = None):
        self._definitions: dict[str, SessionAttribute] = {}
        self._values: dict[str, str] = {}

        for attr in (attributes or []):
            self._definitions[attr.name] = attr
            if attr.initial is not None:
                self._values[attr.name] = attr.initial

    def define(self, attr: SessionAttribute) -> None:
        """Register a new session attribute."""
        self._definitions[attr.name] = attr
        if attr.name not in self._values and attr.initial is not None:
            self._values[attr.name] = attr.initial

    def set(self, name: str, value: str) -> bool:
        """Set a session attribute value.

        For monotonic attributes, the value can only move forward in
        the ordering. Attempts to move backward are silently ignored
        and return False.

        Args:
            name: Attribute name.
            value: New value.

        Returns:
            True if the value was updated, False if rejected (monotonic).
        """
        defn = self._definitions.get(name)

        if defn and defn.monotonic and defn.ordering:
            current = self._values.get(name, defn.initial or "")
            try:
                current_idx = defn.ordering.index(current) if current else -1
            except ValueError:
                current_idx = -1
            try:
                new_idx = defn.ordering.index(value)
            except ValueError:
                logger.warning(
                    "Session attribute '%s' value '%s' not in ordering — rejected",
                    name, value,
                )
                return False

            if new_idx <= current_idx:
                logger.debug(
                    "Monotonic ratchet: '%s' cannot move from '%s' (%d) to '%s' (%d)",
                    name, current, current_idx, value, new_idx,
                )
                return False

        self._values[name] = value
        return True

    def get(self, name: str) -> Optional[str]:
        """Get current value of a session attribute."""
        return self._values.get(name)

    def get_all(self) -> dict[str, str]:
        """Get all current attribute values."""
        return dict(self._values)

    def inject_context(self, context: dict) -> dict:
        """Inject session state into a policy evaluation context.

        Adds ``session.*`` keys so policy conditions can reference them:
        ``session.data_sensitivity == 'confidential'``

        Args:
            context: Existing policy context dict.

        Returns:
            The context dict with ``session`` key added (mutated in place).
        """
        context["session"] = dict(self._values)
        return context

    def reset(self) -> None:
        """Reset all attributes to their initial values."""
        for name, defn in self._definitions.items():
            if defn.initial is not None:
                self._values[name] = defn.initial
            else:
                self._values.pop(name, None)

    @classmethod
    def from_policy_yaml(cls, yaml_content: str) -> "SessionState":
        """Parse session_attributes from a policy YAML string.

        Example YAML::

            session_attributes:
              - name: data_sensitivity
                ordering: [public, internal, confidential, restricted]
                monotonic: true
                initial: public

        Args:
            yaml_content: Raw YAML string.

        Returns:
            A configured SessionState instance.
        """
        import yaml

        data = yaml.safe_load(yaml_content) or {}
        attrs_data = data.get("session_attributes", [])
        attributes = []
        for ad in attrs_data:
            attributes.append(SessionAttribute(
                name=ad["name"],
                ordering=ad.get("ordering", []),
                monotonic=ad.get("monotonic", False),
                initial=ad.get("initial"),
            ))
        return cls(attributes)
