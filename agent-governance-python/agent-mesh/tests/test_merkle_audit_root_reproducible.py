# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for ``MerkleAuditChain`` root reproducibility.

The root recorded incrementally on each :meth:`MerkleAuditChain.add_entry`
must equal a from-scratch rebuild over the same entries, so that an exported
``merkle_root`` is reproducible by an independent verifier.

Before the fix, ``add_entry`` padded *interior* tree levels with singleton
zero nodes while ``_rebuild_tree`` padded at the *leaf* level and hashed the
padding upward. The two constructions produced different roots once a real
leaf's authentication path reached an interior padding node, first observable
at five entries (and again at 6, 9, ...).
"""

from __future__ import annotations

import hashlib

from agentmesh.governance.audit import AuditEntry, MerkleAuditChain


def _entry(i: int) -> AuditEntry:
    return AuditEntry(
        event_type="tool_invocation",
        agent_did=f"did:mesh:agent-{i}",
        action=f"act-{i}",
        resource=f"res-{i}",
    )


def _rebuilt_root(chain: MerkleAuditChain) -> str | None:
    """Independently recompute the root from the recorded entries."""
    chain._rebuild_tree()
    return chain.get_root_hash()


class TestMerkleRootReproducible:
    def test_incremental_root_matches_rebuild_for_every_size(self):
        # Spans the first two capacity doublings and the sizes that diverged
        # before the fix (5, 6, 9).
        for n in range(1, 17):
            chain = MerkleAuditChain()
            for i in range(n):
                chain.add_entry(_entry(i))
            incremental = chain.get_root_hash()
            rebuilt = _rebuilt_root(chain)
            assert incremental == rebuilt, (
                f"n={n}: incremental root {incremental} != rebuilt root {rebuilt}"
            )

    def test_five_entries_is_the_minimal_reproducer(self):
        chain = MerkleAuditChain()
        for i in range(5):
            chain.add_entry(_entry(i))
        recorded = chain.get_root_hash()
        # Feeding the same entries to a fresh chain must yield the same root.
        fresh = MerkleAuditChain()
        for entry in list(chain._entries):
            fresh.add_entry(entry)
        assert fresh.get_root_hash() == recorded
        # And a from-scratch rebuild over the recorded entries must agree.
        assert _rebuilt_root(chain) == recorded

    def test_inclusion_proofs_verify_against_recorded_root(self):
        chain = MerkleAuditChain()
        entries = [_entry(i) for i in range(5)]
        for entry in entries:
            chain.add_entry(entry)
        root = chain.get_root_hash()
        for entry in entries:
            proof = chain.get_proof(entry.entry_id)
            assert proof is not None
            assert chain.verify_proof(entry.entry_hash, proof, root) is True

    def test_tampered_leaf_changes_the_rebuilt_root(self):
        chain = MerkleAuditChain()
        for i in range(5):
            chain.add_entry(_entry(i))
        recorded = chain.get_root_hash()
        # Corrupt a stored leaf hash; a verifier that recomputes the root must
        # observe a different value, i.e. tampering remains detectable.
        chain._entries[1].entry_hash = hashlib.sha256(b"tampered").hexdigest()
        assert _rebuilt_root(chain) != recorded
