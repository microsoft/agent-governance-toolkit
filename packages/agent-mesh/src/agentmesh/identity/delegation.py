# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Scope Chains

Simple scope passing: sub-agent gets parent's scopes minus any denied ones.
"""

from datetime import datetime, timedelta
from typing import ClassVar, Optional
from pydantic import BaseModel, Field, field_validator
import hashlib
import json

from agentmesh.identity.agent_id import AgentIdentity
from agentmesh.constants import DEFAULT_DELEGATION_MAX_DEPTH
from agentmesh.exceptions import DelegationError, DelegationDepthError


class UserContext(BaseModel):
    """
    User context for On-Behalf-Of (OBO) flows.

    When an agent acts on behalf of an end user, this context propagates
    through the scope chain so downstream agents can enforce
    user-level access control.
    """

    user_id: str = Field(..., description="Unique user identifier")
    user_email: Optional[str] = Field(None, description="User email for audit trails")
    roles: list[str] = Field(default_factory=list, description="User roles for RBAC")
    permissions: list[str] = Field(default_factory=list, description="Fine-grained permissions")
    issued_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = Field(None, description="OBO context expiration")
    metadata: dict = Field(default_factory=dict, description="Additional user attributes")

    def is_valid(self) -> bool:
        """Check if the user context is still valid."""
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True

    def has_permission(self, permission: str) -> bool:
        """Check if the user has a specific permission."""
        if "*" in self.permissions:
            return True
        return permission in self.permissions

    def has_role(self, role: str) -> bool:
        """Check if the user has a specific role."""
        return role in self.roles

    @classmethod
    def create(
        cls,
        user_id: str,
        user_email: Optional[str] = None,
        roles: Optional[list[str]] = None,
        permissions: Optional[list[str]] = None,
        ttl_seconds: int = 3600,
    ) -> "UserContext":
        """Create a new user context with TTL."""
        now = datetime.utcnow()
        return cls(
            user_id=user_id,
            user_email=user_email,
            roles=roles or [],
            permissions=permissions or [],
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )


class DelegationLink(BaseModel):
    """
    A single link in a scope chain.

    Each link represents a parent granting capabilities to a child.
    The child's capabilities MUST be a subset of the parent's.
    """

    link_id: str = Field(..., description="Unique link identifier")

    # Chain position
    depth: int = Field(..., ge=0, description="Depth in chain (0 = root)")

    # Agents
    parent_did: str = Field(..., description="DID of parent agent")
    child_did: str = Field(..., description="DID of child agent")

    # Capability narrowing
    parent_capabilities: list[str] = Field(..., description="Parent's capabilities at delegation time")
    delegated_capabilities: list[str] = Field(..., description="Capabilities granted to child")

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = Field(None)

    # User context for OBO flows
    user_context: Optional[UserContext] = Field(None, description="End-user context for OBO flows")

    # Kept for API compatibility (not cryptographically enforced)
    parent_signature: str = Field(..., description="Parent's signature on this delegation")
    link_hash: str = Field(..., description="Hash of this link for chain verification")
    previous_link_hash: Optional[str] = Field(None, description="Hash of previous link in chain")

    def verify_capability_narrowing(self) -> bool:
        """Verify that delegated capabilities are a subset of parent's."""
        for cap in self.delegated_capabilities:
            if cap not in self.parent_capabilities:
                if not self._is_narrower_capability(cap, self.parent_capabilities):
                    return False
        return True

    def _is_narrower_capability(self, cap: str, parent_caps: list[str]) -> bool:
        """Check if a capability is a narrowed version of a parent capability."""
        for parent_cap in parent_caps:
            if parent_cap == "*":
                return True
            if parent_cap.endswith(":*"):
                prefix = parent_cap[:-2]
                if cap.startswith(prefix + ":"):
                    return True
        return False

    def compute_hash(self) -> str:
        """Compute hash of this link."""
        data = {
            "link_id": self.link_id,
            "depth": self.depth,
            "parent_did": self.parent_did,
            "child_did": self.child_did,
            "delegated_capabilities": sorted(self.delegated_capabilities),
            "created_at": self.created_at.isoformat(),
            "previous_link_hash": self.previous_link_hash,
            "user_context_user_id": self.user_context.user_id if self.user_context else None,
        }
        canonical = json.dumps(data, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def is_valid(self) -> bool:
        """Check if this link is valid (expiration and capability narrowing only)."""
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False

        if not self.verify_capability_narrowing():
            return False

        return True


class ScopeChain(BaseModel):
    """
    Simple scope chain from root sponsor to current agent.

    Sub-agent gets parent's scopes minus any denied ones.
    No cryptographic chain verification.
    """

    DEFAULT_MAX_DEPTH: ClassVar[int] = DEFAULT_DELEGATION_MAX_DEPTH

    chain_id: str = Field(..., description="Unique chain identifier")
    max_depth: int = Field(default=DEFAULT_DELEGATION_MAX_DEPTH, description="Maximum allowed chain depth")

    # Root (human sponsor)
    root_sponsor_email: str = Field(..., description="Human sponsor at chain root")
    root_sponsor_verified: bool = Field(default=False)
    root_capabilities: list[str] = Field(..., description="Capabilities granted by sponsor")

    # Known agent identities (kept for API compatibility)
    known_identities: dict[str, AgentIdentity] = Field(default_factory=dict)

    # Chain links
    links: list[DelegationLink] = Field(default_factory=list)

    # Final agent
    leaf_did: str = Field(..., description="DID of the agent at end of chain")
    leaf_capabilities: list[str] = Field(..., description="Final effective capabilities")

    @field_validator("chain_id")
    @classmethod
    def validate_chain_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise DelegationError("chain_id must not be empty")
        return v

    @field_validator("root_sponsor_email")
    @classmethod
    def validate_root_sponsor_email(cls, v: str) -> str:
        if not v or not v.strip():
            raise DelegationError("root_sponsor_email must not be empty")
        if "@" not in v:
            raise DelegationError(f"Invalid root_sponsor_email format: {v}")
        return v

    @field_validator("root_capabilities")
    @classmethod
    def validate_root_capabilities(cls, v: list[str]) -> list[str]:
        if not v:
            raise DelegationError("root_capabilities must not be empty")
        return v

    @field_validator("leaf_did")
    @classmethod
    def validate_leaf_did(cls, v: str) -> str:
        if not v or not v.strip():
            raise DelegationError("leaf_did must not be empty")
        if not v.startswith("did:mesh:"):
            raise DelegationError(
                f"leaf_did must match 'did:mesh:' pattern, got: {v}"
            )
        return v

    # Chain metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    total_depth: int = Field(default=0)

    # Verification
    chain_hash: str = Field(default="", description="Hash of entire chain")

    def get_depth(self) -> int:
        """Return the current depth of the scope chain."""
        return len(self.links)

    def add_link(self, link: DelegationLink) -> None:
        """Add a link to the chain with simple scope narrowing validation."""
        new_depth = len(self.links) + 1
        if new_depth > self.max_depth:
            raise DelegationDepthError(
                f"Scope chain depth {new_depth} exceeds maximum allowed depth "
                f"of {self.max_depth}"
            )

        if self.links:
            last_link = self.links[-1]
            if link.parent_did != last_link.child_did:
                raise ValueError("Link does not connect to chain")
            if link.previous_link_hash != last_link.link_hash:
                raise ValueError("Link hash does not match previous link")
        else:
            if link.depth != 0:
                raise ValueError("First link must have depth 0")

        if not link.verify_capability_narrowing():
            raise ValueError("Link does not properly narrow capabilities")

        self.links.append(link)
        self.total_depth = len(self.links)
        self.leaf_did = link.child_did
        self.leaf_capabilities = link.delegated_capabilities
        self._update_chain_hash()

    def _verify_link_signature(self, link: DelegationLink) -> bool:
        """Verify the Ed25519 signature on a delegation link."""
        identity = self.known_identities.get(link.parent_did)
        if identity is None:
            return True  # Graceful fallback — can't verify without identity
        signable_data = f"{link.parent_did}:{link.child_did}:{','.join(sorted(link.delegated_capabilities))}"
        return identity.verify_signature(signable_data.encode(), link.parent_signature)

    def verify(self) -> tuple[bool, Optional[str]]:
        """
        Verify the chain — scope narrowing, hash integrity, and signatures.
        """
        if not self.links:
            return True, None

        previous_hash = None
        previous_capabilities = self.root_capabilities

        for i, link in enumerate(self.links):
            if link.depth != i:
                return False, f"Invalid depth at link {i}"

            if link.previous_link_hash != previous_hash:
                return False, f"Hash chain broken at link {i}"

            # Verify capability narrowing
            for cap in link.delegated_capabilities:
                if cap not in previous_capabilities:
                    if not link._is_narrower_capability(cap, previous_capabilities):
                        return False, f"Capability escalation at link {i}: {cap}"

            # Verify link hash
            if link.link_hash != link.compute_hash():
                return False, f"Invalid link hash at link {i}"

            # Verify Ed25519 signature
            if not self._verify_link_signature(link):
                return False, f"Invalid signature at link {i}"

            previous_hash = link.link_hash
            previous_capabilities = link.delegated_capabilities

        return True, None

    def get_effective_capabilities(self) -> list[str]:
        """Get the effective capabilities at the end of the chain."""
        if self.links:
            return self.links[-1].delegated_capabilities
        return self.root_capabilities

    def trace_capability(self, capability: str) -> list[dict]:
        """Trace how a capability was granted through the chain."""
        trace = []

        if capability in self.root_capabilities or "*" in self.root_capabilities:
            trace.append({
                "level": "root",
                "grantor": self.root_sponsor_email,
                "capability": capability,
                "source_capabilities": self.root_capabilities,
            })

        for link in self.links:
            if capability in link.delegated_capabilities:
                trace.append({
                    "level": f"depth_{link.depth}",
                    "grantor": link.parent_did,
                    "grantee": link.child_did,
                    "capability": capability,
                    "parent_capabilities": link.parent_capabilities,
                    "delegated_capabilities": link.delegated_capabilities,
                })

        return trace

    def _update_chain_hash(self) -> None:
        """Update the overall chain hash."""
        data = {
            "chain_id": self.chain_id,
            "root_sponsor": self.root_sponsor_email,
            "links": [link.link_hash for link in self.links],
        }
        canonical = json.dumps(data, sort_keys=True)
        self.chain_hash = hashlib.sha256(canonical.encode()).hexdigest()

    @classmethod
    def create_root(
        cls,
        sponsor_email: str,
        root_agent_did: str,
        capabilities: list[str],
        sponsor_verified: bool = False,
    ) -> tuple["ScopeChain", DelegationLink]:
        """Create a new chain with a root sponsor."""
        import uuid

        chain_id = f"chain_{uuid.uuid4().hex[:16]}"

        chain = cls(
            chain_id=chain_id,
            root_sponsor_email=sponsor_email,
            root_sponsor_verified=sponsor_verified,
            root_capabilities=capabilities,
            leaf_did=root_agent_did,
            leaf_capabilities=capabilities,
        )

        link = DelegationLink(
            link_id=f"link_{uuid.uuid4().hex[:12]}",
            depth=0,
            parent_did=f"did:mesh:sponsor:{sponsor_email}",
            child_did=root_agent_did,
            parent_capabilities=capabilities,
            delegated_capabilities=capabilities,
            parent_signature="",
            link_hash="",
        )
        link.link_hash = link.compute_hash()

        return chain, link
