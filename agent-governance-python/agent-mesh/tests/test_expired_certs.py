# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for expired certificate handling in scope chains (#119).

Validates that credentials and delegation links with expired timestamps are
correctly rejected, including edge cases around clock skew and boundary times.
"""

import uuid
from datetime import datetime, timedelta

import pytest

from agentmesh.identity.agent_id import AgentIdentity
from agentmesh.identity.credentials import Credential, CredentialManager
from agentmesh.identity.delegation import ScopeChain, DelegationLink


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_identity(name: str = "test") -> AgentIdentity:
    return AgentIdentity.create(
        name=name,
        sponsor=f"{name}@test.example.com",
        capabilities=["read", "write"],
    )


def _chain_with_expiring_link(
    expires_at: datetime | None,
) -> tuple[ScopeChain, DelegationLink]:
    """Build a 2-link chain where the second link has the given expiry."""
    agent_b_did = f"did:mesh:{uuid.uuid4().hex[:16]}"
    agent_c_did = f"did:mesh:{uuid.uuid4().hex[:16]}"

    chain, root_link = ScopeChain.create_root(
        sponsor_email="sponsor@example.com",
        root_agent_did=agent_b_did,
        capabilities=["read", "write"],
    )
    chain.add_link(root_link)

    child_link = DelegationLink(
        link_id=f"link_{uuid.uuid4().hex[:12]}",
        depth=1,
        parent_did=agent_b_did,
        child_did=agent_c_did,
        parent_capabilities=["read", "write"],
        delegated_capabilities=["read"],
        parent_signature="sig",
        link_hash="",
        previous_link_hash=root_link.link_hash,
        expires_at=expires_at,
    )
    child_link.link_hash = child_link.compute_hash()
    chain.add_link(child_link)
    return chain, child_link


# ---------------------------------------------------------------------------
# Credential expiry tests
# ---------------------------------------------------------------------------

class TestCredentialExpiry:
    """Credential.is_valid rejects expired credentials."""

    def test_just_expired_one_second_ago(self):
        """Credential that expired 1 second ago is invalid."""
        cred = Credential.issue(agent_did="did:mesh:test", ttl_seconds=-1)
        assert not cred.is_valid()

    def test_far_expired_one_year_ago(self):
        """Credential expired 1 year ago is invalid."""
        cred = Credential.issue(agent_did="did:mesh:test", ttl_seconds=1)
        cred.expires_at = datetime.utcnow() - timedelta(days=366)
        assert not cred.is_valid()

    def test_valid_credential(self):
        """Credential with future expiry is valid."""
        cred = Credential.issue(agent_did="did:mesh:test", ttl_seconds=3600)
        assert cred.is_valid()

    def test_credential_at_exact_boundary(self):
        """Credential whose expires_at == now is technically expired (< not <=)."""
        cred = Credential.issue(agent_did="did:mesh:test", ttl_seconds=0)
        # expires_at was set at issue time; by the time we check, utcnow >= expires_at
        assert not cred.is_valid()

    def test_not_yet_valid_future_issue(self):
        """Credential issued in the future but active status is considered valid
        by is_valid (which only checks status + expires_at). The issued_at field
        is informational; applications should check it separately if needed."""
        cred = Credential.issue(agent_did="did:mesh:test", ttl_seconds=7200)
        cred.issued_at = datetime.utcnow() + timedelta(hours=1)
        # is_valid only checks status + expires_at
        assert cred.is_valid()

    def test_revoked_credential_invalid(self):
        """Revoked credential is invalid regardless of expiry."""
        cred = Credential.issue(agent_did="did:mesh:test", ttl_seconds=3600)
        cred.revoke("test revocation")
        assert not cred.is_valid()


class TestCredentialManagerExpiry:
    """CredentialManager.validate rejects expired tokens."""

    def test_validate_returns_none_for_expired(self):
        """Expired credential token returns None from validate."""
        mgr = CredentialManager()
        cred = mgr.issue("did:mesh:test", ttl_seconds=1)
        # Force expiry
        cred.expires_at = datetime.utcnow() - timedelta(seconds=10)
        assert mgr.validate(cred.token) is None

    def test_cleanup_removes_expired(self):
        """cleanup_expired removes non-active expired credentials."""
        mgr = CredentialManager()
        cred = mgr.issue("did:mesh:test", ttl_seconds=1)
        cred.expires_at = datetime.utcnow() - timedelta(seconds=10)
        cred.status = "expired"
        removed = mgr.cleanup_expired()
        assert removed >= 1


# ---------------------------------------------------------------------------
# Delegation link expiry tests
# ---------------------------------------------------------------------------

class TestDelegationLinkExpiry:
    """DelegationLink.is_valid rejects expired links."""

    def test_expired_link_invalid(self):
        """Link with past expires_at is invalid."""
        _, link = _chain_with_expiring_link(
            expires_at=datetime.utcnow() - timedelta(seconds=1),
        )
        assert not link.is_valid()

    def test_far_expired_link(self):
        """Link expired 1 year ago is invalid."""
        _, link = _chain_with_expiring_link(
            expires_at=datetime.utcnow() - timedelta(days=366),
        )
        assert not link.is_valid()

    def test_valid_link_future_expiry(self):
        """Link with future expiry is valid."""
        _, link = _chain_with_expiring_link(
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        assert link.is_valid()

    def test_link_no_expiry_valid(self):
        """Link with no expires_at is valid (no expiry set)."""
        _, link = _chain_with_expiring_link(expires_at=None)
        assert link.is_valid()

    def test_link_at_exact_expiry_boundary(self):
        """Link whose expires_at just passed is invalid."""
        # Set expiry to just barely in the past
        _, link = _chain_with_expiring_link(
            expires_at=datetime.utcnow() - timedelta(milliseconds=100),
        )
        assert not link.is_valid()


class TestScopeChainWithExpiredLinks:
    """Chain verification with expired links in the chain."""

    def test_chain_with_expired_link_verify_passes_structurally(self):
        """Chain.verify() checks structural integrity (hashes, narrowing,
        signatures) — link expiry is checked via link.is_valid() separately.
        This test documents current behaviour: verify() does NOT reject
        expired links automatically."""
        chain, link = _chain_with_expiring_link(
            expires_at=datetime.utcnow() - timedelta(days=1),
        )
        # Structural verification still passes
        is_valid, error = chain.verify()
        assert is_valid is True

        # But the individual link reports itself invalid
        assert not link.is_valid()

    def test_application_checks_link_validity(self):
        """Applications should iterate links and check is_valid for expiry."""
        chain, _ = _chain_with_expiring_link(
            expires_at=datetime.utcnow() - timedelta(seconds=30),
        )
        expired_links = [lnk for lnk in chain.links if not lnk.is_valid()]
        assert len(expired_links) >= 1


# ---------------------------------------------------------------------------
# Clock skew tolerance tests
# ---------------------------------------------------------------------------

class TestClockSkewTolerance:
    """Edge cases around small time differences."""

    def test_credential_within_grace_period(self):
        """Credential expiring within a small grace window may still be valid."""
        cred = Credential.issue(agent_did="did:mesh:test", ttl_seconds=30)
        # Still has 30s left — should be valid
        assert cred.is_valid()

    def test_credential_is_expiring_soon(self):
        """is_expiring_soon detects credentials about to expire."""
        cred = Credential.issue(agent_did="did:mesh:test", ttl_seconds=30)
        # With default threshold of 60s, a 30s credential is expiring soon
        assert cred.is_expiring_soon(threshold_seconds=60)

    def test_credential_not_expiring_soon(self):
        """Credential with plenty of TTL remaining is not expiring soon."""
        cred = Credential.issue(agent_did="did:mesh:test", ttl_seconds=3600)
        assert not cred.is_expiring_soon(threshold_seconds=60)


# ---------------------------------------------------------------------------
# Agent identity expiry tests
# ---------------------------------------------------------------------------

class TestAgentIdentityExpiry:
    """AgentIdentity.is_active respects expires_at."""

    def test_expired_identity_not_active(self):
        """Identity with past expires_at is not active."""
        identity = _make_identity()
        identity.expires_at = datetime.utcnow() - timedelta(seconds=1)
        assert not identity.is_active()

    def test_identity_not_yet_expired(self):
        """Identity with future expires_at is active."""
        identity = _make_identity()
        identity.expires_at = datetime.utcnow() + timedelta(hours=1)
        assert identity.is_active()

    def test_identity_no_expiry_active(self):
        """Identity with no expires_at is active."""
        identity = _make_identity()
        assert identity.expires_at is None
        assert identity.is_active()

    def test_revoked_identity_not_active(self):
        """Revoked identity is not active even if not expired."""
        identity = _make_identity()
        identity.expires_at = datetime.utcnow() + timedelta(hours=1)
        identity.revoke("test")
        assert not identity.is_active()
