# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the durable SQLite ApprovalStore (ADR-0030 sections 5 and 6)."""

from __future__ import annotations

import multiprocessing
import sqlite3
import threading
from contextlib import closing
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentmesh.governance.approval_protocol import (
    ActionBinding,
    ActionTarget,
    ApprovalChain,
    ApprovalChainEntry,
    ApprovalCoordinator,
    ApprovalRequest,
    ApprovalResolution,
    ApprovalStage,
    ApprovalStatus,
    ApprovalStore,
    ApproverKind,
    EntryDecision,
    InMemoryApprovalStore,
    Outcome,
    ReasonCode,
    SQLiteApprovalStore,
)

ALICE = "did:web:example.com:users:alice"
BOB = "did:web:example.com:users:bob"
START = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)


class Clock:
    def __init__(self, start: datetime = START) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def make_binding() -> ActionBinding:
    return ActionBinding(
        operation="tool.invoke",
        agent_id="agent-123",
        target=ActionTarget("sql_execute", "2", resource="prod-db"),
        parameters={"statement": "DELETE FROM accounts WHERE id = ?", "values": [42]},
        subject_id="user-456",
    )


def single_stage_chain() -> ApprovalChain:
    return ApprovalChain(
        chain_id="high-risk-tools",
        version="3",
        stages=(ApprovalStage(0, allowed_identities=frozenset({ALICE})),),
    )


def two_stage_chain() -> ApprovalChain:
    return ApprovalChain(
        chain_id="two-stage",
        version="1",
        stages=(
            ApprovalStage(0, allowed_identities=frozenset({ALICE})),
            ApprovalStage(1, allowed_roles=frozenset({"compliance"})),
        ),
    )


def make_request(**overrides) -> ApprovalRequest:
    fields = dict(
        policy_decision_id="pd_1",
        action_digest="sha256:" + "a" * 64,
        agent_id="agent-123",
        operation="tool.invoke",
        policy_version="v1",
        approval_chain_id="high-risk-tools",
        approval_chain_version="3",
        expires_at=START + timedelta(minutes=10),
        subject_id="user-456",
        target_resource="prod-db",
    )
    fields.update(overrides)
    return ApprovalRequest(**fields)


def make_entry(request_id: str, previous: str | None = None, **overrides) -> ApprovalChainEntry:
    fields = dict(
        approval_request_id=request_id,
        stage_index=0,
        approver_kind=ApproverKind.HUMAN,
        approver_identity=ALICE,
        identity_assurance="oidc",
        decision=EntryDecision.ALLOW,
        input_digest="sha256:" + "b" * 64,
        previous_entry_digest=previous,
    )
    fields.update(overrides)
    return ApprovalChainEntry(**fields).seal()


def open_and_approve(coord: ApprovalCoordinator, chain: ApprovalChain):
    binding = make_binding()
    _, request = coord.open_request(
        binding,
        policy_rule_id="prod-db-deletes",
        policy_version="v1",
        chain_id=chain.chain_id,
        ttl_seconds=600,
    )
    coord.submit_entry(
        request.approval_request_id,
        stage_index=0,
        approver_kind=ApproverKind.HUMAN,
        approver_identity=ALICE,
        identity_assurance="oidc",
        decision=EntryDecision.ALLOW,
    )
    return binding, request


def validate(coord: ApprovalCoordinator, request_id: str, binding, chain, *, consume=True):
    return coord.validate_for_execution(
        request_id,
        current_action_digest=binding.digest(),
        current_policy_version="v1",
        current_chain_version=chain.version,
        consume=consume,
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "approvals.db"


@pytest.fixture
def sqlite_store(db_path: Path):
    store = SQLiteApprovalStore(db_path)
    yield store
    store.close()


@pytest.fixture(params=["memory", "sqlite"])
def any_store(request, tmp_path: Path):
    """Each contract test runs against both the reference store and SQLite."""
    if request.param == "memory":
        yield InMemoryApprovalStore()
    else:
        store = SQLiteApprovalStore(tmp_path / "contract.db")
        yield store
        store.close()


# --------------------------------------------------------------------------- #
# Store contract (same behaviour as InMemoryApprovalStore)
# --------------------------------------------------------------------------- #


class TestStoreContract:
    def test_satisfies_protocol(self, any_store):
        assert isinstance(any_store, ApprovalStore)

    def test_request_round_trip(self, any_store):
        request = make_request()
        any_store.save_request(request)
        assert any_store.get_request(request.approval_request_id) == request

    def test_optional_fields_round_trip_as_none(self, any_store):
        request = make_request(subject_id=None, target_resource=None, fail_closed_on_timeout=False)
        any_store.save_request(request)
        loaded = any_store.get_request(request.approval_request_id)
        assert loaded == request
        assert loaded.subject_id is None and loaded.target_resource is None
        assert loaded.fail_closed_on_timeout is False

    def test_save_request_again_updates_it(self, any_store):
        request = make_request()
        any_store.save_request(request)
        request.status = ApprovalStatus.CANCELLED
        any_store.save_request(request)
        assert any_store.get_request(request.approval_request_id).status == ApprovalStatus.CANCELLED

    def test_unknown_ids(self, any_store):
        assert any_store.get_request("ar_missing") is None
        assert any_store.get_entries("ar_missing") == []
        assert any_store.get_resolution("ar_missing") is None
        assert any_store.consume("ar_missing") is False
        any_store.set_status("ar_missing", ApprovalStatus.DENIED)  # no-op, no error

    def test_set_status(self, any_store):
        request = make_request()
        any_store.save_request(request)
        any_store.set_status(request.approval_request_id, ApprovalStatus.DENIED)
        assert any_store.get_request(request.approval_request_id).status == ApprovalStatus.DENIED

    def test_entries_keep_insertion_order(self, any_store):
        request = make_request()
        any_store.save_request(request)
        first = make_entry(request.approval_request_id)
        second = make_entry(request.approval_request_id, first.entry_digest, stage_index=1)
        third = make_entry(request.approval_request_id, second.entry_digest, stage_index=2)
        for entry in (first, second, third):
            any_store.append_entry(entry)
        assert any_store.get_entries(request.approval_request_id) == [first, second, third]

    def test_entries_are_scoped_to_their_request(self, any_store):
        a, b = make_request(), make_request()
        any_store.save_request(a)
        any_store.save_request(b)
        any_store.append_entry(make_entry(a.approval_request_id))
        assert len(any_store.get_entries(a.approval_request_id)) == 1
        assert any_store.get_entries(b.approval_request_id) == []

    def test_resolution_round_trip(self, any_store):
        request = make_request()
        any_store.save_request(request)
        resolution = ApprovalResolution(
            approval_request_id=request.approval_request_id,
            outcome=Outcome.ALLOW,
            action_digest=request.action_digest,
            policy_version="v1",
            approval_chain_version="3",
            final_entry_digest="sha256:" + "c" * 64,
        )
        any_store.save_resolution(resolution)
        assert any_store.get_resolution(request.approval_request_id) == resolution

    def test_consume_only_allowed_and_only_once(self, any_store):
        request = make_request()
        any_store.save_request(request)
        rid = request.approval_request_id
        for status in (ApprovalStatus.PENDING, ApprovalStatus.DENIED, ApprovalStatus.EXPIRED):
            any_store.set_status(rid, status)
            assert any_store.consume(rid) is False
        any_store.set_status(rid, ApprovalStatus.ALLOWED)
        assert any_store.consume(rid) is True
        assert any_store.consume(rid) is False
        assert any_store.get_request(rid).status == ApprovalStatus.CONSUMED


# --------------------------------------------------------------------------- #
# Coordinator end to end on SQLite
# --------------------------------------------------------------------------- #


class TestCoordinatorOnSQLite:
    def test_allow_then_consume_once(self, sqlite_store):
        chain = single_stage_chain()
        coord = ApprovalCoordinator(sqlite_store, {chain.chain_id: chain}, clock=Clock())
        binding, request = open_and_approve(coord, chain)

        first = validate(coord, request.approval_request_id, binding, chain)
        second = validate(coord, request.approval_request_id, binding, chain)
        assert first.allowed and first.reason_code == ReasonCode.OK
        assert not second.allowed and second.reason_code == ReasonCode.ALREADY_CONSUMED

    def test_deny_short_circuits(self, sqlite_store):
        chain = single_stage_chain()
        coord = ApprovalCoordinator(sqlite_store, {chain.chain_id: chain}, clock=Clock())
        binding = make_binding()
        _, request = coord.open_request(
            binding,
            policy_rule_id="r",
            policy_version="v1",
            chain_id=chain.chain_id,
            ttl_seconds=600,
        )
        coord.submit_entry(
            request.approval_request_id,
            stage_index=0,
            approver_kind=ApproverKind.HUMAN,
            approver_identity=ALICE,
            identity_assurance="oidc",
            decision=EntryDecision.DENY,
        )
        verdict = validate(coord, request.approval_request_id, binding, chain)
        assert verdict.reason_code == ReasonCode.NOT_TERMINAL_ALLOW
        assert sqlite_store.get_request(request.approval_request_id).status == ApprovalStatus.DENIED

    def test_expiry_resolves_and_persists(self, sqlite_store):
        chain = single_stage_chain()
        clock = Clock()
        coord = ApprovalCoordinator(sqlite_store, {chain.chain_id: chain}, clock=clock)
        binding = make_binding()
        _, request = coord.open_request(
            binding,
            policy_rule_id="r",
            policy_version="v1",
            chain_id=chain.chain_id,
            ttl_seconds=60,
        )
        clock.advance(61)
        verdict = validate(coord, request.approval_request_id, binding, chain)
        assert verdict.reason_code == ReasonCode.EXPIRED
        resolution = sqlite_store.get_resolution(request.approval_request_id)
        assert resolution is not None and resolution.outcome == Outcome.EXPIRED

    def test_concurrent_expiry_fails_closed(self, db_path):
        # Two workers loaded the same PENDING request and both see it expire.
        # The second resolution is rejected. Execution must still be refused.
        chain = single_stage_chain()
        chains = {chain.chain_id: chain}
        clock = Clock()
        with SQLiteApprovalStore(db_path) as s1, SQLiteApprovalStore(db_path) as s2:
            coord1 = ApprovalCoordinator(s1, chains, clock=clock)
            coord2 = ApprovalCoordinator(s2, chains, clock=clock)
            binding = make_binding()
            _, request = coord1.open_request(
                binding,
                policy_rule_id="r",
                policy_version="v1",
                chain_id=chain.chain_id,
                ttl_seconds=60,
            )
            clock.advance(61)
            stale = s2.get_request(request.approval_request_id)
            first = validate(coord1, request.approval_request_id, binding, chain)
            assert first.reason_code == ReasonCode.EXPIRED
            with pytest.raises(sqlite3.IntegrityError):
                coord2._expire_if_due(stale)
            again = validate(coord2, request.approval_request_id, binding, chain)
            assert not again.allowed and again.reason_code == ReasonCode.EXPIRED

    def test_tampered_row_is_detected(self, sqlite_store, db_path):
        chain = single_stage_chain()
        coord = ApprovalCoordinator(sqlite_store, {chain.chain_id: chain}, clock=Clock())
        binding, request = open_and_approve(coord, chain)

        # Change a stored entry behind the store's back, without resealing it.
        with closing(sqlite3.connect(db_path)) as raw, raw:
            raw.execute(
                "UPDATE agt_approval_chain_entries SET approver_identity = ? "
                "WHERE approval_request_id = ?",
                (BOB, request.approval_request_id),
            )

        verdict = validate(coord, request.approval_request_id, binding, chain)
        assert verdict.reason_code == ReasonCode.CHAIN_TAMPERED


# --------------------------------------------------------------------------- #
# Durability across restart (ADR-0030 section 5)
# --------------------------------------------------------------------------- #


class TestRestart:
    def test_pending_request_resumes_after_restart(self, db_path):
        chain = two_stage_chain()
        chains = {chain.chain_id: chain}
        binding = make_binding()

        # Worker 1: open the request, record stage 0, then "crash".
        store = SQLiteApprovalStore(db_path)
        coord = ApprovalCoordinator(store, chains, clock=Clock())
        _, request = coord.open_request(
            binding,
            policy_rule_id="r",
            policy_version="v1",
            chain_id=chain.chain_id,
            ttl_seconds=600,
        )
        coord.submit_entry(
            request.approval_request_id,
            stage_index=0,
            approver_kind=ApproverKind.HUMAN,
            approver_identity=ALICE,
            identity_assurance="oidc",
            decision=EntryDecision.ALLOW,
        )
        saved_request = store.get_request(request.approval_request_id)
        saved_entries = store.get_entries(request.approval_request_id)
        store.close()

        # Worker 2: a fresh store and coordinator on the same file.
        with SQLiteApprovalStore(db_path) as restarted:
            assert restarted.get_request(request.approval_request_id) == saved_request
            assert restarted.get_entries(request.approval_request_id) == saved_entries
            assert saved_request.status == ApprovalStatus.PENDING

            coord2 = ApprovalCoordinator(restarted, chains, clock=Clock())
            coord2.submit_entry(
                request.approval_request_id,
                stage_index=1,
                approver_kind=ApproverKind.HUMAN,
                approver_identity=BOB,
                identity_assurance="oidc",
                decision=EntryDecision.ALLOW,
                roles=("compliance",),
            )
            verdict = validate(coord2, request.approval_request_id, binding, chain)
            assert verdict.allowed and verdict.reason_code == ReasonCode.OK

    def test_consumed_state_survives_restart(self, db_path):
        chain = single_stage_chain()
        chains = {chain.chain_id: chain}
        with SQLiteApprovalStore(db_path) as store:
            coord = ApprovalCoordinator(store, chains, clock=Clock())
            binding, request = open_and_approve(coord, chain)
            assert validate(coord, request.approval_request_id, binding, chain).allowed

        with SQLiteApprovalStore(db_path) as restarted:
            coord2 = ApprovalCoordinator(restarted, chains, clock=Clock())
            verdict = validate(coord2, request.approval_request_id, binding, chain)
            assert verdict.reason_code == ReasonCode.ALREADY_CONSUMED

    def test_chain_digests_verify_after_reload(self, db_path):
        # Microseconds and a non-UTC offset must survive, because the entry
        # digest covers decided_at.isoformat().
        ist = timezone(timedelta(hours=5, minutes=30))
        decided_at = datetime(2026, 6, 11, 17, 30, 0, 123456, tzinfo=ist)
        request = make_request()
        first = make_entry(request.approval_request_id, decided_at=decided_at)
        second = make_entry(
            request.approval_request_id,
            first.entry_digest,
            stage_index=1,
            approver_kind=ApproverKind.LLM_ADVISORY,
            reason_code="advisory: looks destructive",
        )
        with SQLiteApprovalStore(db_path) as store:
            store.save_request(request)
            store.append_entry(first)
            store.append_entry(second)

        with SQLiteApprovalStore(db_path) as restarted:
            loaded = restarted.get_entries(request.approval_request_id)
        assert loaded == [first, second]
        assert loaded[0].decided_at.isoformat() == decided_at.isoformat()
        assert all(entry.verify_digest() for entry in loaded)
        assert loaded[1].previous_entry_digest == loaded[0].entry_digest


# --------------------------------------------------------------------------- #
# Append-only / terminal guarantees and lifecycle
# --------------------------------------------------------------------------- #


class TestIntegrityGuards:
    def test_duplicate_chain_entry_id_rejected(self, sqlite_store):
        request = make_request()
        sqlite_store.save_request(request)
        entry = make_entry(request.approval_request_id)
        sqlite_store.append_entry(entry)
        with pytest.raises(sqlite3.IntegrityError):
            sqlite_store.append_entry(entry)
        assert sqlite_store.get_entries(request.approval_request_id) == [entry]

    def test_second_resolution_rejected(self, sqlite_store):
        request = make_request()
        sqlite_store.save_request(request)
        kwargs = dict(
            approval_request_id=request.approval_request_id,
            action_digest=request.action_digest,
            policy_version="v1",
            approval_chain_version="3",
        )
        allow = ApprovalResolution(outcome=Outcome.ALLOW, **kwargs)
        sqlite_store.save_resolution(allow)
        with pytest.raises(sqlite3.IntegrityError):
            sqlite_store.save_resolution(ApprovalResolution(outcome=Outcome.DENY, **kwargs))
        assert sqlite_store.get_resolution(request.approval_request_id) == allow

    def test_returned_objects_are_copies(self, sqlite_store):
        request = make_request()
        sqlite_store.save_request(request)
        loaded = sqlite_store.get_request(request.approval_request_id)
        loaded.status = ApprovalStatus.ALLOWED
        stored = sqlite_store.get_request(request.approval_request_id)
        assert stored.status == ApprovalStatus.PENDING

    def test_closed_store_raises(self, db_path):
        store = SQLiteApprovalStore(db_path)
        store.close()
        store.close()  # idempotent
        with pytest.raises(sqlite3.ProgrammingError):
            store.get_request("ar_any")

    def test_in_memory_database_works(self):
        with SQLiteApprovalStore(":memory:") as store:
            request = make_request()
            store.save_request(request)
            assert store.get_request(request.approval_request_id) == request

    def test_negative_busy_timeout_rejected(self, db_path):
        with pytest.raises(ValueError):
            SQLiteApprovalStore(db_path, busy_timeout_ms=-1)

    def test_chain_entry_id_unique_per_request_only(self, sqlite_store):
        # The coordinator's idempotency check is per request, so the same
        # caller-supplied id may appear on two different requests.
        a, b = make_request(), make_request()
        sqlite_store.save_request(a)
        sqlite_store.save_request(b)
        sqlite_store.append_entry(make_entry(a.approval_request_id, chain_entry_id="stage0"))
        sqlite_store.append_entry(make_entry(b.approval_request_id, chain_entry_id="stage0"))
        assert len(sqlite_store.get_entries(a.approval_request_id)) == 1
        assert len(sqlite_store.get_entries(b.approval_request_id)) == 1

    def test_forked_chain_rejected(self, sqlite_store):
        # Two submitters that read the same tail would both link to it.
        request = make_request()
        sqlite_store.save_request(request)
        rid = request.approval_request_id
        head = make_entry(rid)
        sqlite_store.append_entry(head)
        sqlite_store.append_entry(make_entry(rid, head.entry_digest, approver_identity=ALICE))
        with pytest.raises(sqlite3.IntegrityError):
            sqlite_store.append_entry(make_entry(rid, head.entry_digest, approver_identity=BOB))
        with pytest.raises(sqlite3.IntegrityError):
            sqlite_store.append_entry(make_entry(rid, None, approver_identity=BOB))
        assert len(sqlite_store.get_entries(rid)) == 2

    @pytest.mark.parametrize(
        ("outcome", "status"),
        [
            (Outcome.ALLOW, ApprovalStatus.ALLOWED),
            (Outcome.DENY, ApprovalStatus.DENIED),
            (Outcome.EXPIRED, ApprovalStatus.EXPIRED),
        ],
    )
    def test_save_resolution_sets_terminal_status_atomically(self, sqlite_store, outcome, status):
        # If the process dies between save_resolution and set_status, the
        # request must not be left PENDING with a resolution already stored.
        request = make_request()
        sqlite_store.save_request(request)
        sqlite_store.save_resolution(
            ApprovalResolution(
                approval_request_id=request.approval_request_id,
                outcome=outcome,
                action_digest=request.action_digest,
                policy_version="v1",
                approval_chain_version="3",
            )
        )
        assert sqlite_store.get_request(request.approval_request_id).status == status

    def test_save_resolution_does_not_touch_non_pending_status(self, sqlite_store):
        request = make_request(status=ApprovalStatus.CANCELLED)
        sqlite_store.save_request(request)
        sqlite_store.save_resolution(
            ApprovalResolution(
                approval_request_id=request.approval_request_id,
                outcome=Outcome.ALLOW,
                action_digest=request.action_digest,
                policy_version="v1",
                approval_chain_version="3",
            )
        )
        stored = sqlite_store.get_request(request.approval_request_id)
        assert stored.status == ApprovalStatus.CANCELLED

    def test_rejected_resolution_leaves_status_unchanged(self, sqlite_store):
        request = make_request()
        sqlite_store.save_request(request)
        kwargs = dict(
            approval_request_id=request.approval_request_id,
            action_digest=request.action_digest,
            policy_version="v1",
            approval_chain_version="3",
        )
        sqlite_store.save_resolution(ApprovalResolution(outcome=Outcome.ALLOW, **kwargs))
        assert sqlite_store.consume(request.approval_request_id) is True
        with pytest.raises(sqlite3.IntegrityError):
            sqlite_store.save_resolution(ApprovalResolution(outcome=Outcome.EXPIRED, **kwargs))
        stored = sqlite_store.get_request(request.approval_request_id)
        assert stored.status == ApprovalStatus.CONSUMED

    def test_expired_resolution_without_final_digest_round_trips(self, db_path):
        request = make_request()
        resolution = ApprovalResolution(
            approval_request_id=request.approval_request_id,
            outcome=Outcome.EXPIRED,
            action_digest=request.action_digest,
            policy_version="v1",
            approval_chain_version="3",
            final_entry_digest=None,
        )
        with SQLiteApprovalStore(db_path) as store:
            store.save_request(request)
            store.save_resolution(resolution)
        with SQLiteApprovalStore(db_path) as restarted:
            assert restarted.get_resolution(request.approval_request_id) == resolution

    def test_unknown_schema_version_rejected(self, db_path):
        SQLiteApprovalStore(db_path).close()
        with closing(sqlite3.connect(db_path)) as raw, raw:
            raw.execute("UPDATE agt_approval_meta SET value = '999' WHERE key = 'schema_version'")
        with pytest.raises(RuntimeError, match="schema version"):
            SQLiteApprovalStore(db_path)


# --------------------------------------------------------------------------- #
# One-time consume under concurrency (ADR-0030 section 6)
# --------------------------------------------------------------------------- #


def _seed_allowed_request(db_path: Path) -> str:
    request = make_request(status=ApprovalStatus.ALLOWED)
    with SQLiteApprovalStore(db_path) as store:
        store.save_request(request)
    return request.approval_request_id


def _consume_in_process(db_path: str, request_id: str, start, results) -> None:
    # Module-level so it can be pickled by the "spawn" start method.
    with SQLiteApprovalStore(db_path, busy_timeout_ms=30000) as store:
        start.wait()
        results.put(store.consume(request_id))


class TestConcurrentConsume:
    def test_threads_sharing_one_store(self, sqlite_store, db_path):
        request = make_request(status=ApprovalStatus.ALLOWED)
        sqlite_store.save_request(request)
        barrier = threading.Barrier(16)
        results: list[bool] = []
        lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            won = sqlite_store.consume(request.approval_request_id)
            with lock:
                results.append(won)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results.count(True) == 1
        assert results.count(False) == 15

    def test_separate_connections_in_parallel(self, db_path):
        # Each thread has its own store, so there is no shared Python lock and
        # the calls contend at the SQLite level.
        request_id = _seed_allowed_request(db_path)
        stores = [SQLiteApprovalStore(db_path, busy_timeout_ms=30000) for _ in range(8)]
        barrier = threading.Barrier(len(stores))
        results: list[bool] = []
        lock = threading.Lock()

        def worker(store: SQLiteApprovalStore) -> None:
            barrier.wait()
            won = store.consume(request_id)
            with lock:
                results.append(won)

        threads = [threading.Thread(target=worker, args=(s,)) for s in stores]
        try:
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            for store in stores:
                store.close()
        assert results.count(True) == 1
        assert results.count(False) == len(stores) - 1

    def test_consume_is_one_conditional_statement(self, sqlite_store):
        # Race tests cannot reliably catch a read-then-write consume(): the
        # window between the two statements is too small to hit on demand.
        # Assert the property directly instead. consume() must issue exactly
        # one statement, an UPDATE whose WHERE clause checks the status, so the
        # check and the change happen atomically inside SQLite.
        request = make_request(status=ApprovalStatus.ALLOWED)
        sqlite_store.save_request(request)
        statements: list[str] = []
        sqlite_store._db().set_trace_callback(statements.append)
        try:
            assert sqlite_store.consume(request.approval_request_id) is True
        finally:
            sqlite_store._db().set_trace_callback(None)
        assert len(statements) == 1
        sql = " ".join(statements[0].split()).upper()
        assert sql.startswith("UPDATE AGT_APPROVAL_REQUESTS SET STATUS")
        assert "AND STATUS = 'ALLOWED'" in sql

    def test_separate_processes(self, db_path):
        request_id = _seed_allowed_request(db_path)
        ctx = multiprocessing.get_context("spawn")
        start = ctx.Event()
        results = ctx.Queue()
        workers = [
            ctx.Process(target=_consume_in_process, args=(str(db_path), request_id, start, results))
            for _ in range(6)
        ]
        for p in workers:
            p.start()
        start.set()
        outcomes = [results.get(timeout=60) for _ in workers]
        for p in workers:
            p.join(timeout=60)
            assert p.exitcode == 0
        assert outcomes.count(True) == 1
        assert outcomes.count(False) == len(workers) - 1
        with SQLiteApprovalStore(db_path) as store:
            assert store.get_request(request_id).status == ApprovalStatus.CONSUMED
