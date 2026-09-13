# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Role-Based Access Control (RBAC) for Agent OS.

Provides role assignment and permission checking for agents.
"""

from enum import Enum

import yaml


class Role(Enum):
    """Standard roles for agent access control."""
    READER = "reader"
    WRITER = "writer"
    ADMIN = "admin"
    AUDITOR = "auditor"


# Action permissions per role
_ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.READER: {"read"},
    Role.WRITER: {"read", "write", "search"},
    Role.ADMIN: {"read", "write", "search", "admin", "delete", "audit"},
    Role.AUDITOR: {"read", "search", "audit"},
}

DEFAULT_ROLE = Role.READER


class RBACManager:
    """Manages role-based access control for agents.

    Assigns roles to agents and checks action permissions. Unknown agents
    receive the READER role.
    """

    def __init__(self) -> None:
        self._roles: dict[str, Role] = {}
        self._custom_permissions: dict[Role, set[str]] = {}

    def assign_role(self, agent_id: str, role: Role) -> None:
        """Assign a role to an agent."""
        self._roles[agent_id] = role

    def get_role(self, agent_id: str) -> Role:
        """Return the role for an agent, defaulting to READER."""
        return self._roles.get(agent_id, DEFAULT_ROLE)

    def has_permission(self, agent_id: str, action: str) -> bool:
        """Check whether an agent is permitted to perform an action."""
        role = self.get_role(agent_id)
        perms = self._custom_permissions.get(role, _ROLE_PERMISSIONS.get(role, set()))
        return action in perms

    def remove_role(self, agent_id: str) -> None:
        """Remove a role assignment, reverting the agent to the default role."""
        self._roles.pop(agent_id, None)

    # ── YAML serialisation ────────────────────────────────────

    def to_yaml(self, path: str) -> None:
        """Save current role assignments and custom definitions to a YAML file."""
        data: dict[str, object] = {
            "assignments": {aid: role.value for aid, role in self._roles.items()},
        }
        if self._custom_permissions:
            data["custom_permissions"] = {
                role.value: sorted(perms)
                for role, perms in self._custom_permissions.items()
            }
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    @classmethod
    def from_yaml(cls, path: str) -> "RBACManager":
        """Load an RBACManager from a YAML file."""
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ValueError(f"Expected a YAML mapping, got {type(data).__name__}")

        mgr = cls()

        # Role assignments
        for agent_id, role_value in data.get("assignments", {}).items():
            mgr.assign_role(agent_id, Role(role_value))

        # Custom permissions
        for role_value, perms_list in data.get("custom_permissions", {}).items():
            role = Role(role_value)
            mgr._custom_permissions[role] = set(perms_list)

        return mgr
