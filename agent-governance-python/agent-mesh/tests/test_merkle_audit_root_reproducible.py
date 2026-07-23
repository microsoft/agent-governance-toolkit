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

import copy
import hashlib

from agentmesh.governance.audit import AuditEntry, MerkleAuditChain


def _entry(i: int) -> AuditEntry:
    return AuditEntry(
        event_type="tool_invocation",
        agent_did=f"did:mesh:agent-{i}",
        action=f"act-{i}",
        resource=f"res-{i}",
    )


def _textbook_merkle_root(leaf_hashes: list[str]) -> str | None:
    """Independent, pure-hashlib textbook Merkle root (zero-leaf padded to a
    power of two).

    Deliberately shares no code with :class:`MerkleAuditChain`, so the
    reproducibility assertions cannot pass by comparing the implementation with
    itself.
    """
    if not leaf_hashes:
        return None
    level = list(leaf_hashes)
    while len(level) & (len(level) - 1) != 0:
        level.append('0' * 64)
    while len(level) > 1:
        level = [
            hashlib.sha256((level[i] + level[i + 1]).encode()).hexdigest()
            for i in range(0, len(level), 2)
        ]
    return level[0]


class TestMerkleRootReproducible:
    def test_incremental_root_matches_independent_recompute(self):
        # The incremental root must equal a from-scratch textbook recomputation
        # over the same leaves, across several capacity doublings and every size
        # that diverged before the fix (5, 6, 9-14, 17-30).
        for n in range(1, 33):
            chain = MerkleAuditChain()
            for i in range(n):
                chain.add_entry(_entry(i))
            incremental = chain.get_root_hash()
            independent = _textbook_merkle_root([e.entry_hash for e in chain._entries])
            assert incremental == independent, (
                f"n={n}: incremental root {incremental} != independent recompute {independent}"
            )

    def test_incremental_root_matches_full_rebuild(self):
        # The incremental construction and the from-scratch _rebuild_tree are
        # separate code paths that must converge on the same canonical root.
        # This deliberately calls the private _rebuild_tree: the divergence being
        # regression-tested is *between* the two internal constructions, so the
        # black-box public API alone cannot exercise it (the independent textbook
        # recompute in the sibling test covers the public-API reproducibility).
        for n in (5, 6, 9, 13, 16, 20):
            chain = MerkleAuditChain()
            for i in range(n):
                chain.add_entry(_entry(i))
            incremental = chain.get_root_hash()
            chain._rebuild_tree()
            assert chain.get_root_hash() == incremental, f"n={n}: rebuild disagrees with incremental"

    def test_empty_chain_root_is_none(self):
        chain = MerkleAuditChain()
        assert chain.get_root_hash() is None
        assert _textbook_merkle_root([]) is None

    def test_five_entries_is_the_minimal_reproducer(self):
        chain = MerkleAuditChain()
        for i in range(5):
            chain.add_entry(_entry(i))
        recorded = chain.get_root_hash()
        # Feeding the same entries to a fresh chain must yield the same root.
        # Deep-copy each entry: add_entry rewrites previous_hash/entry_hash in
        # place, so passing the originals would mutate chain._entries and make
        # the independent recompute below no longer independent.
        fresh = MerkleAuditChain()
        for entry in list(chain._entries):
            fresh.add_entry(copy.deepcopy(entry))
        assert fresh.get_root_hash() == recorded
        # And an independent recompute over the recorded entries must agree.
        assert _textbook_merkle_root([e.entry_hash for e in chain._entries]) == recorded

    def test_inclusion_proofs_verify_against_recorded_root(self):
        chain = MerkleAuditChain()
        entries = [_entry(i) for i in range(5)]
        for entry in entries:
            chain.add_entry(entry)
        root = chain.get_root_hash()
        for entry in entries:
            proof = chain.get_proof(entry.entry_id)
            assert proof is not None
            assert chain.verify_proof(entry.entry_hash, proof, root)

    def test_tampered_leaf_changes_the_rebuilt_root(self):
        chain = MerkleAuditChain()
        for i in range(5):
            chain.add_entry(_entry(i))
        recorded = chain.get_root_hash()
        # Corrupt a stored leaf hash; a verifier that recomputes the root must
        # observe a different value, i.e. tampering remains detectable.
        chain._entries[1].entry_hash = hashlib.sha256(b"tampered").hexdigest()
        assert _textbook_merkle_root([e.entry_hash for e in chain._entries]) != recorded
