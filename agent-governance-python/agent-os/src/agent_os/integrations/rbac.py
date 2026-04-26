# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Role-Based Access Control (RBAC) for Agent OS.

Provides role assignment, policy lookup, and permission checking for agents.
"""

from enum import Enum

import yaml

from agent_os.integrations.base import GovernancePolicy


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

# Default policy templates per role
_DEFAULT_POLICIES: dict[Role, GovernancePolicy] = {
    Role.READER: GovernancePolicy(
        max_tool_calls=0,
        allowed_tools=[],
        require_human_approval=True,
    ),
    Role.WRITER: GovernancePolicy(
        max_tool_calls=5,
        allowed_tools=["read", "write", "search"],
        require_human_approval=False,
    ),
    Role.ADMIN: GovernancePolicy(
        max_tool_calls=50,
        allowed_tools=[],
        max_tokens=16384,
        require_human_approval=False,
    ),
    Role.AUDITOR: GovernancePolicy(
        max_tool_calls=5,
        allowed_tools=["read", "search", "audit"],
        log_all_calls=True,
        require_human_approval=False,
    ),
}

DEFAULT_ROLE = Role.READER


class RBACManager:
    """Manages role-based access control for agents.

    Assigns roles to agents, resolves governance policies per role,
    and checks action permissions. Unknown agents receive the READER role.
    """

    def __init__(self) -> None:
        self._roles: dict[str, Role] = {}
        self._custom_policies: dict[Role, GovernancePolicy] = {}
        self._custom_permissions: dict[Role, set[str]] = {}

    def assign_role(self, agent_id: str, role: Role) -> None:
        """Assign a role to an agent."""
        self._roles[agent_id] = role

    def get_role(self, agent_id: str) -> Role:
        """Return the role for an agent, defaulting to READER."""
        return self._roles.get(agent_id, DEFAULT_ROLE)

    def get_policy(self, agent_id: str) -> GovernancePolicy:
        """Return the governance policy template for an agent's role."""
        role = self.get_role(agent_id)
        if role in self._custom_policies:
            return self._custom_policies[role]
        return _DEFAULT_POLICIES[role]

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
        if self._custom_policies:
            data["custom_policies"] = {
                role.value: yaml.safe_load(policy.to_yaml())
                for role, policy in self._custom_policies.items()
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

        # Custom policies
        for role_value, policy_dict in data.get("custom_policies", {}).items():
            role = Role(role_value)
            yaml_str = yaml.dump(policy_dict, default_flow_style=False)
            mgr._custom_policies[role] = GovernancePolicy.from_yaml(yaml_str)

        # Custom permissions
        for role_value, perms_list in data.get("custom_permissions", {}).items():
            role = Role(role_value)
            mgr._custom_permissions[role] = set(perms_list)

        return mgr
