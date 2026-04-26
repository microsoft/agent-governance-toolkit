# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Namespace Manager

Manages agent namespaces, membership, and cross-namespace communication rules.
Default behaviour: same-namespace agents communicate freely; cross-namespace
requires an explicit NamespaceRule that allows it.
"""

from typing import Optional

from agentmesh.identity.namespace import AgentNamespace, NamespaceRule


class NamespaceManager:
    """Central manager for agent namespaces and cross-namespace rules.

    Default behaviour: same-namespace agents communicate freely;
    cross-namespace requires an explicit allow-rule.
    """

    def __init__(self) -> None:
        self._namespaces: dict[str, AgentNamespace] = {}
        self._rules: list[NamespaceRule] = []

    # ── Namespace CRUD ──────────────────────────────────────────────

    def create_namespace(
        self,
        name: str,
        description: str,
        parent: Optional[str] = None,
    ) -> AgentNamespace:
        """Create a new namespace, optionally nested under *parent*.

        Args:
            name: Unique namespace name (e.g. "finance.trading").
            description: Human-readable description.
            parent: Parent namespace name for nesting.

        Returns:
            The newly created AgentNamespace.

        Raises:
            ValueError: If the namespace already exists or parent is invalid.
        """
        if name in self._namespaces:
            raise ValueError(f"Namespace already exists: {name}")
        if parent and parent not in self._namespaces:
            raise ValueError(f"Parent namespace does not exist: {parent}")
        ns = AgentNamespace(name=name, description=description, parent=parent)
        self._namespaces[name] = ns
        return ns

    def get_namespace(self, name: str) -> AgentNamespace:
        """Return a namespace by name.

        Args:
            name: The namespace name to look up.

        Returns:
            The matching AgentNamespace.

        Raises:
            KeyError: If the namespace is not found.
        """
        if name not in self._namespaces:
            raise KeyError(f"Namespace not found: {name}")
        return self._namespaces[name]

    def list_namespaces(self) -> list[AgentNamespace]:
        """Return all registered namespaces.

        Returns:
            List of all AgentNamespace objects.
        """
        return list(self._namespaces.values())

    # ── Membership ──────────────────────────────────────────────────

    def add_member(self, namespace_name: str, agent_did: str) -> None:
        """Add an agent DID to a namespace.

        Args:
            namespace_name: Name of the target namespace.
            agent_did: DID of the agent to add.

        Raises:
            KeyError: If the namespace does not exist.
        """
        ns = self.get_namespace(namespace_name)
        ns.members.add(agent_did)

    def remove_member(self, namespace_name: str, agent_did: str) -> None:
        """Remove an agent DID from a namespace.

        Args:
            namespace_name: Name of the target namespace.
            agent_did: DID of the agent to remove.

        Raises:
            KeyError: If the namespace does not exist.
        """
        ns = self.get_namespace(namespace_name)
        ns.members.discard(agent_did)

    def get_agent_namespace(self, agent_did: str) -> Optional[str]:
        """Return the namespace name an agent belongs to.

        Args:
            agent_did: DID of the agent to look up.

        Returns:
            The namespace name, or None if the agent is not in any namespace.
        """
        for ns in self._namespaces.values():
            if agent_did in ns.members:
                return ns.name
        return None

    # ── Rules ───────────────────────────────────────────────────────

    def add_rule(self, rule: NamespaceRule) -> None:
        """Register a cross-namespace communication rule.

        Args:
            rule: The NamespaceRule to add.
        """
        self._rules.append(rule)

    # ── Access checks ───────────────────────────────────────────────

    def _is_ancestor(self, ancestor: str, descendant: str) -> bool:
        """Check if *ancestor* is a parent/grandparent of *descendant*."""
        current = self._namespaces.get(descendant)
        while current and current.parent:
            if current.parent == ancestor:
                return True
            current = self._namespaces.get(current.parent)
        return False

    def _share_lineage(self, ns_a: str, ns_b: str) -> bool:
        """Return True if the two namespaces share a parent–child lineage."""
        return (
            ns_a == ns_b
            or self._is_ancestor(ns_a, ns_b)
            or self._is_ancestor(ns_b, ns_a)
        )

    def _find_rule(self, src_ns: str, tgt_ns: str) -> Optional[NamespaceRule]:
        """Find the first matching rule for a source→target pair."""
        for rule in self._rules:
            if rule.source_namespace == src_ns and rule.target_namespace == tgt_ns:
                return rule
        return None

    def can_communicate(self, from_did: str, to_did: str) -> bool:
        """Check whether *from_did* may communicate with *to_did*.

        Same namespace (or shared lineage) → always allowed.
        Cross-namespace → only if an explicit allow-rule exists.
        Agents not in any namespace → denied.

        Args:
            from_did: DID of the initiating agent.
            to_did: DID of the target agent.

        Returns:
            True if communication is allowed.
        """
        src_ns = self.get_agent_namespace(from_did)
        tgt_ns = self.get_agent_namespace(to_did)

        if src_ns is None or tgt_ns is None:
            return False

        if self._share_lineage(src_ns, tgt_ns):
            return True

        rule = self._find_rule(src_ns, tgt_ns)
        return rule is not None and rule.allowed

    def can_delegate(self, from_did: str, to_did: str) -> bool:
        """Check whether *from_did* may delegate to *to_did*.

        Default: delegation is restricted to the same namespace only.

        Args:
            from_did: DID of the delegating agent.
            to_did: DID of the delegate agent.

        Returns:
            True if delegation is allowed.
        """
        src_ns = self.get_agent_namespace(from_did)
        tgt_ns = self.get_agent_namespace(to_did)

        if src_ns is None or tgt_ns is None:
            return False

        return src_ns == tgt_ns
