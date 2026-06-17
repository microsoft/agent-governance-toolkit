# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the additive DelegationChain.effective_restrictions method.

Includes a behavioral non-regression check that the new method left
validate()'s contract (return shape + reason substrings) unchanged.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from structural_authz_agentmesh.trust import DelegationChain, DelegationLink


def _link(
    delegator: str,
    delegatee: str,
    scopes: list,
    expires_at: Optional[datetime] = None,
) -> DelegationLink:
    return DelegationLink(
        delegator_did=delegator,
        delegatee_did=delegatee,
        scopes=scopes,
        delegator_public_key="AAAA",
        signature="BBBB",
        expires_at=expires_at,
    )


def test_effective_restrictions_method_matches_pure_fn():
    chain = DelegationChain("did:authz:root", ["read"])
    parent = frozenset({"no_external_export"})
    child = frozenset({"no_memory_write"})
    # The method computes the same grow-only union the pure merge_restrictions does.
    assert chain.effective_restrictions(parent, child) == (parent | child)


def test_effective_restrictions_is_grow_only():
    chain = DelegationChain("did:authz:root", ["read"])
    parent = frozenset({"no_external_export"})
    # a child declaring nothing still inherits the parent restriction
    assert "no_external_export" in chain.effective_restrictions(parent, frozenset())


def test_validate_signature_and_reasons_unchanged():
    """The additive method must not alter validate()'s shape or reason strings."""
    # circular
    c1 = DelegationChain("did:authz:root", ["read"])
    c1.add_link(_link("did:authz:root", "did:authz:root", ["read"]))
    ok1, reason1 = c1.validate()
    assert ok1 is False
    assert isinstance(reason1, str)
    assert "circular" in reason1

    # expired
    past = datetime.now(timezone.utc) - timedelta(days=1)
    c2 = DelegationChain("did:authz:root", ["read"])
    c2.add_link(_link("did:authz:root", "did:authz:agent", ["read"], expires_at=past))
    ok2, reason2 = c2.validate()
    assert ok2 is False
    assert "expired" in reason2

    # scope widening ("exceed")
    c3 = DelegationChain("did:authz:root", ["read"])
    c3.add_link(_link("did:authz:root", "did:authz:agent", ["read", "admin"]))
    ok3, reason3 = c3.validate(verify_signatures=False)
    assert ok3 is False
    assert "exceed" in reason3

    # success path still returns the (bool, str) tuple shape
    ok0, reason0 = DelegationChain("did:authz:root", ["read"]).validate()
    assert ok0 is True
    assert reason0 == ""
