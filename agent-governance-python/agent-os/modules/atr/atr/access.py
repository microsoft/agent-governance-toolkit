# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Access control for ATR tools.

Provides permission-based access control for tool execution.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set


class Permission(str, Enum):
    """Built-in permission types."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    ADMIN = "admin"
    ALL = "*"


@dataclass(frozen=True)
class Principal:
    """Represents an entity (user, agent, service) that can access tools.

    Attributes:
        id: Unique identifier for the principal.
        type: Type of principal (e.g., "agent", "user", "service").
        roles: Set of roles assigned to this principal.
        attributes: Additional attributes for attribute-based access control.
    """

    id: str
    type: str = "agent"
    roles: FrozenSet[str] = field(default_factory=frozenset)
    attributes: FrozenSet[tuple] = field(default_factory=frozenset)

    def has_role(self, role: str) -> bool:
        """Check if principal has a specific role."""
        return role in self.roles or "admin" in self.roles

    def get_attribute(self, key: str) -> Optional[Any]:
        """Get an attribute value."""
        for k, v in self.attributes:
            if k == key:
                return v
        return None

    @classmethod
    def create(
        cls,
        id: str,
        type: str = "agent",
        roles: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> "Principal":
        """Create a principal with mutable inputs."""
        return cls(
            id=id,
            type=type,
            roles=frozenset(roles or []),
            attributes=frozenset((attributes or {}).items()),
        )


@dataclass
class AccessPolicy:
    """Defines access requirements for a tool.

    Attributes:
        allowed_principals: Specific principal IDs that can access.
        allowed_roles: Roles that can access.
        allowed_types: Principal types that can access.
        denied_principals: Principals explicitly denied.
        required_attributes: Attributes that must match.
        custom_check: Custom authorization function.
    """

    allowed_principals: Set[str] = field(default_factory=set)
    allowed_roles: Set[str] = field(default_factory=set)
    allowed_types: Set[str] = field(default_factory=set)
    denied_principals: Set[str] = field(default_factory=set)
    required_attributes: Dict[str, Any] = field(default_factory=dict)
    custom_check: Optional[Callable[[Principal, str], bool]] = None

    def allows(self, principal: Principal, tool_name: str) -> bool:
        """Check if the policy allows access.

        Args:
            principal: The principal requesting access.
            tool_name: Name of the tool being accessed.

        Returns:
            True if access is allowed, False otherwise.
        """
        # Explicit deny takes precedence
        if principal.id in self.denied_principals:
            return False

        # Check custom authorization
        if self.custom_check is not None:
            return self.custom_check(principal, tool_name)

        # Admin role bypasses all checks
        if principal.has_role("admin"):
            return True

        # Check explicit principal allowlist
        if self.allowed_principals and principal.id in self.allowed_principals:
            return True

        # Check role-based access
        if self.allowed_roles and any(principal.has_role(role) for role in self.allowed_roles):
            return True

        # Check type-based access
        if self.allowed_types and principal.type in self.allowed_types:
            return True

        # Check required attributes
        if self.required_attributes:
            for key, required_value in self.required_attributes.items():
                actual_value = principal.get_attribute(key)
                if actual_value != required_value:
                    return False
            return True

        # If no restrictions defined, allow by default
        if (
            not self.allowed_principals
            and not self.allowed_roles
            and not self.allowed_types
            and not self.required_attributes
        ):
            return True

        return False

    @classmethod
    def allow_all(cls) -> "AccessPolicy":
        """Create a policy that allows all access."""
        return cls()

    @classmethod
    def deny_all(cls) -> "AccessPolicy":
        """Create a policy that denies all access."""
        return cls(custom_check=lambda _p, _t: False)

    @classmethod
    def roles_only(cls, *roles: str) -> "AccessPolicy":
        """Create a policy that only allows specific roles."""
        return cls(allowed_roles=set(roles))

    @classmethod
    def principals_only(cls, *principals: str) -> "AccessPolicy":
        """Create a policy that only allows specific principals."""
        return cls(allowed_principals=set(principals))


class AccessDeniedError(Exception):
    """Raised when access to a tool is denied."""

    def __init__(self, principal: Principal, tool_name: str, reason: str = ""):
        self.principal = principal
        self.tool_name = tool_name
        self.reason = reason
        message = f"Access denied for '{principal.id}' to tool '{tool_name}'"
        if reason:
            message += f": {reason}"
        super().__init__(message)


class AccessControlManager:
    """Manages access control for tools.

    Example:
        >>> manager = AccessControlManager()
        >>>
        >>> # Set policy for a tool
        >>> manager.set_policy("sensitive_tool", AccessPolicy.roles_only("admin", "security"))
        >>>
        >>> # Check access
        >>> agent = Principal.create("agent-1", roles=["claims"])
        >>> if manager.can_access(agent, "sensitive_tool"):
        ...     # Execute tool
        ...     pass
    """

    def __init__(self, default_policy: Optional[AccessPolicy] = None):
        """Initialize access control manager.

        Args:
            default_policy: Policy to use when no specific policy is set.
        """
        self._policies: Dict[str, AccessPolicy] = {}
        self._default_policy = default_policy or AccessPolicy.allow_all()
        self._lock = threading.RLock()
        self._audit_log: List[Dict[str, Any]] = []
        self._audit_enabled = False

    def set_policy(self, tool_name: str, policy: AccessPolicy) -> None:
        """Set access policy for a tool.

        Args:
            tool_name: Name of the tool.
            policy: The access policy to apply.
        """
        with self._lock:
            self._policies[tool_name] = policy

    def get_policy(self, tool_name: str) -> AccessPolicy:
        """Get access policy for a tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            The tool's policy or default policy.
        """
        with self._lock:
            return self._policies.get(tool_name, self._default_policy)

    def remove_policy(self, tool_name: str) -> bool:
        """Remove a tool's specific policy.

        Args:
            tool_name: Name of the tool.

        Returns:
            True if policy was removed, False if didn't exist.
        """
        with self._lock:
            if tool_name in self._policies:
                del self._policies[tool_name]
                return True
            return False

    def can_access(self, principal: Principal, tool_name: str) -> bool:
        """Check if a principal can access a tool.

        Args:
            principal: The principal requesting access.
            tool_name: Name of the tool.

        Returns:
            True if access is allowed.
        """
        policy = self.get_policy(tool_name)
        allowed = policy.allows(principal, tool_name)

        if self._audit_enabled:
            self._log_access(principal, tool_name, allowed)

        return allowed

    def require_access(self, principal: Principal, tool_name: str) -> None:
        """Require access or raise AccessDeniedError.

        Args:
            principal: The principal requesting access.
            tool_name: Name of the tool.

        Raises:
            AccessDeniedError: If access is denied.
        """
        if not self.can_access(principal, tool_name):
            raise AccessDeniedError(principal, tool_name)

    def enable_audit(self, enabled: bool = True) -> None:
        """Enable or disable audit logging.

        Args:
            enabled: Whether to enable audit logging.
        """
        self._audit_enabled = enabled

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get the audit log.

        Returns:
            List of audit log entries.
        """
        with self._lock:
            return list(self._audit_log)

    def clear_audit_log(self) -> None:
        """Clear the audit log."""
        with self._lock:
            self._audit_log.clear()

    def _log_access(self, principal: Principal, tool_name: str, allowed: bool) -> None:
        """Log an access attempt."""
        from datetime import datetime

        with self._lock:
            self._audit_log.append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "principal_id": principal.id,
                    "principal_type": principal.type,
                    "tool_name": tool_name,
                    "allowed": allowed,
                }
            )

            # Keep only last 10000 entries
            if len(self._audit_log) > 10000:
                self._audit_log = self._audit_log[-10000:]

    def list_accessible_tools(self, principal: Principal, tool_names: List[str]) -> List[str]:
        """Get list of tools a principal can access.

        Args:
            principal: The principal to check.
            tool_names: List of tool names to check.

        Returns:
            List of accessible tool names.
        """
        return [name for name in tool_names if self.can_access(principal, name)]


# Global access control manager
_global_access_manager: AccessControlManager = AccessControlManager()


def get_access_manager() -> AccessControlManager:
    """Get the global access control manager.

    Returns:
        The global AccessControlManager instance.
    """
    return _global_access_manager


def set_access_manager(manager: AccessControlManager) -> None:
    """Set the global access control manager.

    Args:
        manager: The manager to use globally.
    """
    global _global_access_manager
    _global_access_manager = manager
