# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Capability Scoping

Simple string-based capability scope checking.
"""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator
import uuid


class CapabilityGrant(BaseModel):
    """
    A specific capability grant to an agent.

    Capabilities follow the format: action:resource[:qualifier]
    Examples:
    - read:data
    - write:reports
    - execute:tools:calculator
    - admin:*

    ``qualifier`` captures the *entire* sub-resource path after
    ``action:resource``, including any further colon-separated
    segments. For example ``write:database:table_users:row_1`` parses
    to ``action='write'``, ``resource='database'``,
    ``qualifier='table_users:row_1'``. It is compared as an opaque
    exact-match token, so a grant scoped to a leaf does not authorize
    its parent or its siblings.
    """

    # ``action``/``resource``/``qualifier`` are a *serialized mirror* of
    # ``capability`` (they appear in ``model_dump``). The authorization
    # path does NOT read them — ``matches()`` delegates to
    # ``capability_scope_matches``, which re-derives from ``capability``
    # independently. validate_assignment re-runs the validator when a
    # field is mutated, so reassigning ``capability`` keeps that mirror
    # from serializing a stale (truncated) qualifier. This is
    # serialization consistency, not an authorization safeguard.
    model_config = ConfigDict(validate_assignment=True)

    grant_id: str = Field(default_factory=lambda: f"grant_{uuid.uuid4().hex[:12]}")

    # Capability specification
    capability: str = Field(..., description="Capability string (e.g., 'read:data')")
    # action/resource/qualifier are derived from ``capability`` by the
    # ``_derive_components`` model validator; any values passed at
    # construction are overwritten, so they carry defaults rather than
    # being required (the validator runs after field validation).
    action: str = Field(default="", description="Action part (e.g., 'read')")
    resource: str = Field(default="", description="Resource part (e.g., 'data')")
    qualifier: Optional[str] = Field(None, description="Optional qualifier")

    # Grant metadata
    granted_to: str = Field(..., description="DID of grantee")
    granted_by: str = Field(..., description="DID of grantor")

    # Scope restrictions
    resource_ids: list[str] = Field(
        default_factory=list,
        description="Specific resource IDs this grant applies to"
    )
    conditions: dict = Field(
        default_factory=dict,
        description="Additional conditions for this grant"
    )

    # Timing
    granted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = Field(None)

    # Status
    active: bool = Field(default=True)
    revoked_at: Optional[datetime] = Field(None)

    @classmethod
    def parse_capability(cls, capability: str) -> tuple[str, str, Optional[str]]:
        """Parse a capability string into (action, resource, qualifier).

        ``qualifier`` is the full remainder after ``action:resource``:
        every colon-separated segment from index 2 onward is preserved
        and re-joined with ``":"``. Dropping segments past index 2
        (the historical behavior) collapsed a leaf grant onto its
        parent/siblings and caused a privilege escalation (#3180).

        Empty colon-separated segments (e.g. ``write:database:``,
        ``write::table``, ``:data``) are rejected: an empty segment is a
        malformed scope whose matching behavior is ambiguous, so it fails
        closed at parse time rather than being silently accepted.
        """
        parts = capability.split(":")
        if len(parts) < 2:
            raise ValueError(f"Invalid capability format: {capability}")
        if any(part == "" for part in parts):
            raise ValueError(
                f"Invalid capability format (empty segment): {capability}"
            )

        action = parts[0]
        resource = parts[1]
        qualifier = ":".join(parts[2:]) if len(parts) > 2 else None

        return action, resource, qualifier

    @model_validator(mode="after")
    def _derive_components(self):
        """Re-derive action/resource/qualifier from ``capability``.

        These fields are a *serialized mirror* of ``capability`` (they
        appear in ``model_dump`` output). The authorization path does not
        read them: ``matches()`` delegates to ``capability_scope_matches``,
        which parses ``capability`` afresh on each call. This validator
        therefore exists to keep the SERIALIZED mirror consistent with the
        source string, not to protect an authorization decision — e.g. a
        grant built or mutated as
        ``CapabilityGrant(capability="a:b:c:d", qualifier="c")`` would
        otherwise serialize a stale, truncated ``qualifier``.

        Runs after every construction, ``model_validate``, and (because
        ``validate_assignment`` is enabled) every field reassignment,
        regardless of input type (dict, mapping, model instance); the
        ``model_copy`` override applies the same re-derivation to copies,
        which Pydantic otherwise builds without validation.
        """
        action, resource, qualifier = self.parse_capability(self.capability)
        # object.__setattr__ avoids re-triggering validate_assignment
        # (which would recurse through this validator).
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "resource", resource)
        object.__setattr__(self, "qualifier", qualifier)
        return self

    def model_copy(self, *, update=None, deep=False):
        """Copy the grant, re-deriving components from ``capability``.

        Pydantic's ``model_copy`` does NOT run validators, so a plain
        ``super().model_copy(update={"capability": ...})`` would rewrite
        ``capability`` while leaving the serialized
        ``action``/``resource``/``qualifier`` mirror stale. Overriding it
        here re-derives them from the copy's ``capability`` so the
        serialized mirror stays consistent on every copy, including
        ``update`` payloads that rewrite the capability. Raises
        ``ValueError`` if the resulting ``capability`` is malformed
        (fail-closed), matching construction-time behavior.
        """
        copied = super().model_copy(update=update, deep=deep)
        action, resource, qualifier = self.parse_capability(copied.capability)
        object.__setattr__(copied, "action", action)
        object.__setattr__(copied, "resource", resource)
        object.__setattr__(copied, "qualifier", qualifier)
        return copied

    @classmethod
    def create(
        cls,
        capability: str,
        granted_to: str,
        granted_by: str,
        resource_ids: Optional[list[str]] = None,
        expires_at: Optional[datetime] = None,
    ) -> "CapabilityGrant":
        """Create a new capability grant from a capability string.

        ``action``/``resource``/``qualifier`` are derived from
        ``capability`` by the ``_derive_components`` validator, so they
        are not passed explicitly here.
        """
        return cls(
            capability=capability,
            granted_to=granted_to,
            granted_by=granted_by,
            resource_ids=resource_ids or [],
            expires_at=expires_at,
        )

    def is_valid(self) -> bool:
        """Check if the grant is currently active and not expired."""
        if not self.active:
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True

    def matches(self, requested: str, resource_id: Optional[str] = None) -> bool:
        """Check if this grant satisfies a requested capability.

        Delegates the string-scope decision to
        :func:`capability_scope_matches` (shared with other capability
        checkers so the semantics cannot drift), then applies this
        grant's validity and ``resource_ids`` scoping.
        """
        if not self.is_valid():
            return False

        if not capability_scope_matches(self.capability, requested):
            return False

        # Check resource ID scope. A grant restricted to specific
        # resource_ids must not satisfy a check that omits resource_id
        # (broader than the grant) nor one naming a resource outside the
        # set. Only an unrestricted grant (empty resource_ids) matches
        # regardless of resource_id.
        if self.resource_ids:
            if resource_id is None or resource_id not in self.resource_ids:
                return False

        return True

    def revoke(self) -> None:
        """Revoke this grant immediately."""
        self.active = False
        self.revoked_at = datetime.now(timezone.utc)


def capability_scope_matches(granted: str, requested: str) -> bool:
    """Return ``True`` if a grant of ``granted`` authorizes ``requested``.

    Pure ``action:resource[:qualifier]`` string-scope decision, with no
    grant validity or ``resource_ids`` handling. This is the single
    authoritative scope matcher; every capability checker (``CapabilityGrant.matches``
    and the MCP tool gate) delegates here so their semantics cannot drift.

    Rules, in order:

    1. Global wildcard (``*``) or exact match.
    2. Trailing wildcard (``granted`` ends with ``:*``): ``requested`` must
       start with the colon-terminated prefix.
    3. Colon-boundary prefix: a broad grant authorizes a strictly deeper
       (narrower) request, e.g. ``write:database`` authorizes
       ``write:database:table_users``. The ``+ ":"`` prevents ``read``
       from matching ``readwrite:secret``.
    4. Component fallback: compare action, resource, and the full qualifier
       (the entire sub-resource remainder) as opaque exact tokens, so a leaf
       grant (``write:database:table_users:row_1``) does NOT authorize its
       parent (``write:database:table_users``) or a sibling (``...:row_2``).
       Malformed inputs (no colon, empty segment) fail closed to ``False``.
    """
    if granted == "*" or granted == requested:
        return True
    if granted.endswith(":*"):
        return requested.startswith(granted[:-1])
    if ":" in granted and requested.startswith(granted + ":"):
        return True
    try:
        g_action, g_resource, g_qualifier = CapabilityGrant.parse_capability(granted)
        r_action, r_resource, r_qualifier = CapabilityGrant.parse_capability(requested)
    except ValueError:
        return False
    if g_action != "*" and g_action != r_action:
        return False
    if g_resource != "*" and g_resource != r_resource:
        return False
    if g_qualifier is not None and g_qualifier != "*":
        if r_qualifier != g_qualifier:
            return False
    return True


class CapabilityScope(BaseModel):
    """
    Complete capability scope for an agent.

    Aggregates all grants and provides capability checking.
    """

    agent_did: str
    grants: list[CapabilityGrant] = Field(default_factory=list)

    # Denied capabilities (blocklist)
    denied: list[str] = Field(default_factory=list)

    def add_grant(self, grant: CapabilityGrant) -> None:
        """Add a capability grant to this scope.

        Args:
            grant: The ``CapabilityGrant`` to add.

        Raises:
            ValueError: If the grant's ``granted_to`` does not match
                this scope's ``agent_did``.
        """
        if grant.granted_to != self.agent_did:
            raise ValueError("Grant is for different agent")
        self.grants.append(grant)

    def has_capability(
        self,
        capability: str,
        resource_id: Optional[str] = None,
    ) -> bool:
        """Check if the agent has a specific capability.

        Checks the deny list first, then searches for a valid,
        matching grant.

        Args:
            capability: Capability string to check (e.g.
                ``"read:data"``).
            resource_id: Optional resource ID for scoped checks.

        Returns:
            ``True`` if the capability is not denied and a matching
            valid grant exists.
        """
        # Check denied first
        if capability in self.denied:
            return False

        # Check for matching grant
        for grant in self.grants:
            if grant.matches(capability, resource_id):
                return True

        return False

    def get_capabilities(self) -> list[str]:
        """Get all active capability strings for this agent.

        Returns:
            De-duplicated list of capability strings from grants that
            are currently valid.
        """
        capabilities = set()
        for grant in self.grants:
            if grant.is_valid():
                capabilities.add(grant.capability)
        return list(capabilities)

    def filter_capabilities(self, requested: list[str]) -> list[str]:
        """Filter a list of requested capabilities to only those allowed.

        Args:
            requested: Capability strings the caller wants to use.

        Returns:
            Subset of *requested* that this scope permits.
        """
        return [cap for cap in requested if self.has_capability(cap)]

    def deny(self, capability: str) -> None:
        """Add a capability to the deny list.

        Denied capabilities take precedence over any matching grants.

        Args:
            capability: Capability string to deny (e.g.
                ``"write:data"``).
        """
        if capability not in self.denied:
            self.denied.append(capability)

    def revoke_all(self) -> int:
        """Revoke all active grants in this scope.

        Returns:
            Number of grants that were revoked.
        """
        count = 0
        for grant in self.grants:
            if grant.active:
                grant.revoke()
                count += 1
        return count

    def revoke_from(self, grantor_did: str) -> int:
        """Revoke all active grants issued by a specific grantor.

        Args:
            grantor_did: DID of the grantor whose grants should be
                revoked.

        Returns:
            Number of grants that were revoked.
        """
        count = 0
        for grant in self.grants:
            if grant.active and grant.granted_by == grantor_did:
                grant.revoke()
                count += 1
        return count

    def cleanup_expired(self) -> int:
        """Remove expired and revoked grants from the scope.

        Returns:
            Number of grants that were removed.
        """
        before = len(self.grants)
        self.grants = [g for g in self.grants if g.is_valid()]
        return before - len(self.grants)


class CapabilityRegistry:
    """
    Central registry for capability grants.

    Tracks who has what capabilities across the mesh.
    """

    def __init__(self):
        """Initialise an empty capability registry."""
        self._scopes: dict[str, CapabilityScope] = {}
        self._grants_by_grantor: dict[str, list[str]] = {}  # grantor -> [grant_ids]

    def get_scope(self, agent_did: str) -> CapabilityScope:
        """Get or create the capability scope for an agent.

        Args:
            agent_did: The agent's decentralized identifier.

        Returns:
            The existing ``CapabilityScope``, or a new empty one if
            the agent was not previously registered.
        """
        if agent_did not in self._scopes:
            self._scopes[agent_did] = CapabilityScope(agent_did=agent_did)
        return self._scopes[agent_did]

    def grant(
        self,
        capability: str,
        to_agent: str,
        from_agent: str,
        resource_ids: Optional[list[str]] = None,
        require_grantor_capability: bool = False,
    ) -> CapabilityGrant:
        """Grant a capability to an agent.

        Creates a ``CapabilityGrant``, adds it to the agent's scope,
        and tracks it by grantor for bulk revocation.

        Args:
            capability: Capability string (e.g. ``"read:data"``).
            to_agent: DID of the agent receiving the grant.
            from_agent: DID of the agent issuing the grant.
            resource_ids: Optional specific resource IDs to scope the
                grant to.
            require_grantor_capability: When ``True``, verify that
                ``from_agent`` already holds ``capability`` (i.e. can
                actually delegate it). Bootstrap/admin grants set this
                to ``False``. Callers that accept grants over the
                network MUST set this to ``True`` to prevent privilege
                escalation via unauthenticated grantor claims.

        Raises:
            PermissionError: If ``require_grantor_capability`` is
                ``True`` and ``from_agent`` does not hold the
                requested capability.
            ValueError: If ``from_agent == to_agent`` (self-grant) or
                the capability string is malformed.

        Returns:
            The newly created ``CapabilityGrant``.
        """
        if from_agent == to_agent:
            # Self-grants are meaningless and would bypass delegation
            # checks (an agent could "grant" itself any capability).
            raise ValueError("Cannot self-grant a capability")

        if require_grantor_capability:
            grantor_scope = self._scopes.get(from_agent)
            if grantor_scope is None:
                raise PermissionError(
                    f"Grantor {from_agent} does not hold capability {capability!r}"
                )
            if resource_ids:
                # The grant is resource-scoped, so the grantor must hold the
                # capability for each requested resource. Checking without a
                # resource_id would wrongly reject a grantor whose own grant
                # is scoped to exactly these resources (the unscoped
                # has_capability() now fails closed on resource-scoped grants).
                missing = [
                    r
                    for r in resource_ids
                    if not grantor_scope.has_capability(capability, resource_id=r)
                ]
                if missing:
                    raise PermissionError(
                        f"Grantor {from_agent} does not hold capability "
                        f"{capability!r} for resources {missing}"
                    )
            elif not grantor_scope.has_capability(capability):
                raise PermissionError(
                    f"Grantor {from_agent} does not hold capability {capability!r}"
                )

        grant = CapabilityGrant.create(
            capability=capability,
            granted_to=to_agent,
            granted_by=from_agent,
            resource_ids=resource_ids,
        )

        scope = self.get_scope(to_agent)
        scope.add_grant(grant)

        # Track by grantor
        if from_agent not in self._grants_by_grantor:
            self._grants_by_grantor[from_agent] = []
        self._grants_by_grantor[from_agent].append(grant.grant_id)

        return grant

    def check(
        self,
        agent_did: str,
        capability: str,
        resource_id: Optional[str] = None,
    ) -> bool:
        """Check if an agent has a specific capability.

        Args:
            agent_did: The agent's decentralized identifier.
            capability: Capability string to check.
            resource_id: Optional resource ID for scoped checks.

        Returns:
            ``True`` if a valid matching grant exists for the agent.
        """
        scope = self._scopes.get(agent_did)
        if not scope:
            return False
        return scope.has_capability(capability, resource_id)

    def revoke_all_from(self, grantor_did: str) -> int:
        """Revoke all grants issued by a specific grantor.

        Useful when a grantor agent is compromised and all grants it
        issued must be invalidated immediately.

        Args:
            grantor_did: DID of the grantor whose grants should be
                revoked across all agent scopes.

        Returns:
            Total number of grants that were revoked.
        """
        count = 0
        for scope in self._scopes.values():
            count += scope.revoke_from(grantor_did)
        return count

    def get_agents_with_capability(self, capability: str) -> list[str]:
        """Get all agent DIDs that currently hold a capability.

        Args:
            capability: Capability string to search for.

        Returns:
            List of agent DIDs that have a valid grant matching the
            requested capability.
        """
        result = []
        for agent_did, scope in self._scopes.items():
            if scope.has_capability(capability):
                result.append(agent_did)
        return result
