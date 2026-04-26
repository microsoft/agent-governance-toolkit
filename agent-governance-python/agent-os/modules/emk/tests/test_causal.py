# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Causal Episodic Memory."""

import time
import pytest
from emk.causal import CausalEpisode, CausalMemoryStore


# =============================================================================
# CausalEpisode tests
# =============================================================================


class TestCausalEpisode:
    def test_auto_id(self):
        ep = CausalEpisode(action="db_query", params={"q": "SELECT 1"})
        assert len(ep.episode_id) == 64  # SHA-256 hex

    def test_frozen(self):
        ep = CausalEpisode(action="read")
        with pytest.raises(AttributeError):
            ep.action = "write"

    def test_roundtrip_dict(self):
        ep = CausalEpisode(
            action="shell",
            params={"cmd": "ls"},
            result={"exit_code": 0},
            caused_by="abc123",
            caused_effects=("def456",),
            agent_id="did:agent:1",
        )
        d = ep.to_dict()
        ep2 = CausalEpisode.from_dict(d)
        assert ep2.action == "shell"
        assert ep2.caused_by == "abc123"
        assert ep2.caused_effects == ("def456",)

    def test_unique_ids(self):
        a = CausalEpisode(action="a", agent_id="1")
        b = CausalEpisode(action="b", agent_id="1")
        assert a.episode_id != b.episode_id

    def test_explicit_id_preserved(self):
        ep = CausalEpisode(action="x", episode_id="my-id-123")
        assert ep.episode_id == "my-id-123"


# =============================================================================
# CausalMemoryStore — basic CRUD
# =============================================================================


class TestStoreBasic:
    def test_record_and_get(self):
        store = CausalMemoryStore()
        ep = CausalEpisode(action="query", params={"sql": "SELECT 1"})
        eid = store.record(ep)
        assert eid == ep.episode_id

        fetched = store.get(eid)
        assert fetched is not None
        assert fetched.action == "query"

    def test_get_nonexistent(self):
        store = CausalMemoryStore()
        assert store.get("nonexistent") is None

    def test_episode_count(self):
        store = CausalMemoryStore()
        assert store.episode_count == 0
        store.record(CausalEpisode(action="a"))
        store.record(CausalEpisode(action="b"))
        assert store.episode_count == 2

    def test_query_by_agent(self):
        store = CausalMemoryStore()
        store.record(CausalEpisode(action="a", agent_id="alice"))
        store.record(CausalEpisode(action="b", agent_id="bob"))
        store.record(CausalEpisode(action="c", agent_id="alice"))

        alice_eps = store.query_by_agent("alice")
        assert len(alice_eps) == 2
        assert all(e.agent_id == "alice" for e in alice_eps)

    def test_query_by_action(self):
        store = CausalMemoryStore()
        store.record(CausalEpisode(action="db_query", agent_id="x"))
        store.record(CausalEpisode(action="shell", agent_id="x"))
        store.record(CausalEpisode(action="db_query", agent_id="y"))

        results = store.query_by_action("db_query")
        assert len(results) == 2


# =============================================================================
# Causal graph tests
# =============================================================================


class TestCausalGraph:
    def _build_chain(self, store: CausalMemoryStore):
        """Build: A → B → C"""
        a = CausalEpisode(
            action="user_request", episode_id="ep-a", timestamp=1.0
        )
        b = CausalEpisode(
            action="db_query", episode_id="ep-b", caused_by="ep-a", timestamp=2.0
        )
        c = CausalEpisode(
            action="report_gen", episode_id="ep-c", caused_by="ep-b", timestamp=3.0
        )
        store.record(a)
        store.record(b)
        store.record(c)
        return a, b, c

    def test_get_effects(self):
        store = CausalMemoryStore()
        self._build_chain(store)
        effects = store.get_effects("ep-a")
        assert len(effects) == 1
        assert effects[0].episode_id == "ep-b"

    def test_get_causes(self):
        store = CausalMemoryStore()
        self._build_chain(store)
        causes = store.get_causes("ep-b")
        assert len(causes) == 1
        assert causes[0].episode_id == "ep-a"

    def test_backward_chain(self):
        store = CausalMemoryStore()
        self._build_chain(store)
        chain = store.get_causal_chain("ep-c", direction="backward")
        ids = [e.episode_id for e in chain]
        assert ids == ["ep-a", "ep-b", "ep-c"]

    def test_forward_chain(self):
        store = CausalMemoryStore()
        self._build_chain(store)
        chain = store.get_causal_chain("ep-a", direction="forward")
        ids = [e.episode_id for e in chain]
        assert ids == ["ep-a", "ep-b", "ep-c"]

    def test_both_directions(self):
        store = CausalMemoryStore()
        self._build_chain(store)
        chain = store.get_causal_chain("ep-b", direction="both")
        ids = [e.episode_id for e in chain]
        assert "ep-a" in ids
        assert "ep-b" in ids
        assert "ep-c" in ids

    def test_edge_count(self):
        store = CausalMemoryStore()
        self._build_chain(store)
        assert store.edge_count == 2

    def test_branching_graph(self):
        """A → B, A → C (fan-out)."""
        store = CausalMemoryStore()
        store.record(CausalEpisode(action="root", episode_id="r", timestamp=1.0))
        store.record(CausalEpisode(action="b1", episode_id="b1", caused_by="r", timestamp=2.0))
        store.record(CausalEpisode(action="b2", episode_id="b2", caused_by="r", timestamp=3.0))

        effects = store.get_effects("r")
        assert len(effects) == 2

        chain = store.get_causal_chain("r", direction="forward")
        assert len(chain) == 3

    def test_max_depth_limits_traversal(self):
        store = CausalMemoryStore()
        # Build long chain: 0 → 1 → 2 → ... → 10
        for i in range(11):
            store.record(CausalEpisode(
                action=f"step_{i}",
                episode_id=f"s{i}",
                caused_by=f"s{i-1}" if i > 0 else None,
                timestamp=float(i),
            ))
        chain = store.get_causal_chain("s10", direction="backward", max_depth=3)
        assert len(chain) <= 4  # at most 4 nodes (depth 0,1,2,3)

    def test_cycle_protection(self):
        """Cycles shouldn't cause infinite loops."""
        store = CausalMemoryStore()
        store.record(CausalEpisode(action="a", episode_id="c1", timestamp=1.0))
        store.record(CausalEpisode(action="b", episode_id="c2", caused_by="c1", timestamp=2.0))
        # Manually add edge c2 → c1 (creates a cycle)
        store._conn.execute(
            "INSERT OR IGNORE INTO causal_edges (from_id, to_id) VALUES (?, ?)",
            ("c2", "c1"),
        )
        store._conn.commit()

        chain = store.get_causal_chain("c1", direction="forward")
        # Should terminate, not hang
        assert len(chain) >= 2

    def test_caused_effects_field_populated(self):
        store = CausalMemoryStore()
        self._build_chain(store)
        fetched = store.get("ep-a")
        assert "ep-b" in fetched.caused_effects

    def test_policy_and_trust_context(self):
        store = CausalMemoryStore()
        ep = CausalEpisode(
            action="risky_op",
            policy_context={"deny": ["DROP"]},
            trust_context={"peer:bob": 0.8},
            agent_id="did:agent:alice",
        )
        store.record(ep)
        fetched = store.get(ep.episode_id)
        assert fetched.policy_context == {"deny": ["DROP"]}
        assert fetched.trust_context == {"peer:bob": 0.8}


# =============================================================================
# Persistence test
# =============================================================================


class TestPersistence:
    def test_file_backed_survives_reopen(self, tmp_path):
        db = str(tmp_path / "causal.db")
        store1 = CausalMemoryStore(db_path=db)
        store1.record(CausalEpisode(action="persisted", episode_id="p1"))
        store1.close()

        store2 = CausalMemoryStore(db_path=db)
        assert store2.get("p1") is not None
        assert store2.get("p1").action == "persisted"
        store2.close()
