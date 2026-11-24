# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Durable SQLite :class:`ApprovalStore` (ADR-0030 sections 5 and 6).

:class:`SQLiteApprovalStore` persists approval requests, hash-linked chain
entries and resolutions in a local SQLite database. This means that:

* a pending request survives a process restart and can be resumed by a new
  worker that opens the same database file (ADR-0030 section 5); and
* :meth:`SQLiteApprovalStore.consume` is atomic across threads *and* across
  processes that share the database file, so one ``ALLOWED`` approval is
  consumed exactly once (ADR-0030 section 6).

Only the Python standard library is used. Values are stored losslessly:
datetimes as their ``isoformat()`` text and enums by ``.value``. As a result,
every reloaded :class:`ApprovalChainEntry` recomputes the same digest, and
chain verification passes after a restart.

Scope: one host, or several processes sharing a local database file. SQLite
locking is unreliable on network filesystems, so this store is not intended
for multi-host deployments. Use a server-backed store for those.

Example::

    from agentmesh.governance.approval_protocol import (
        ApprovalCoordinator, SQLiteApprovalStore,
    )

    with SQLiteApprovalStore("approvals.db") as store:
        coordinator = ApprovalCoordinator(store, {chain.chain_id: chain})
        ...
"""

from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime
from types import TracebackType

from .models import (
    ApprovalChainEntry,
    ApprovalRequest,
    ApprovalResolution,
    ApprovalStatus,
    ApproverKind,
    EntryDecision,
    Outcome,
)

__all__ = ["SQLiteApprovalStore", "STORE_SCHEMA_VERSION"]

#: Version of the on-disk schema. Opening a database written with a different
#: version raises instead of guessing at a migration.
STORE_SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agt_approval_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agt_approval_requests (
    approval_request_id    TEXT PRIMARY KEY,
    policy_decision_id     TEXT NOT NULL,
    action_digest          TEXT NOT NULL,
    agent_id               TEXT NOT NULL,
    operation              TEXT NOT NULL,
    policy_version         TEXT NOT NULL,
    approval_chain_id      TEXT NOT NULL,
    approval_chain_version TEXT NOT NULL,
    expires_at             TEXT NOT NULL,
    subject_id             TEXT,
    target_resource        TEXT,
    fail_closed_on_timeout INTEGER NOT NULL,
    status                 TEXT NOT NULL,
    requested_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agt_approval_chain_entries (
    seq                   INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_entry_id        TEXT NOT NULL,
    approval_request_id   TEXT NOT NULL,
    stage_index           INTEGER NOT NULL,
    approver_kind         TEXT NOT NULL,
    approver_identity     TEXT NOT NULL,
    identity_assurance    TEXT NOT NULL,
    decision              TEXT NOT NULL,
    input_digest          TEXT NOT NULL,
    reason_code           TEXT NOT NULL,
    previous_entry_digest TEXT,
    decided_at            TEXT NOT NULL,
    entry_digest          TEXT,
    -- Idempotency in the coordinator is per request, so ids are unique per request.
    UNIQUE (approval_request_id, chain_entry_id)
);

-- A hash-linked chain never has two entries with the same predecessor. Two
-- concurrent submitters that read the same tail cannot both append, so the
-- chain is never forked. COALESCE makes the first entry (no predecessor) unique
-- too, because SQLite treats NULLs as distinct in UNIQUE constraints.
CREATE UNIQUE INDEX IF NOT EXISTS agt_approval_chain_entries_no_fork
    ON agt_approval_chain_entries (approval_request_id, COALESCE(previous_entry_digest, ''));

CREATE INDEX IF NOT EXISTS agt_approval_chain_entries_by_request
    ON agt_approval_chain_entries (approval_request_id, seq);

CREATE TABLE IF NOT EXISTS agt_approval_resolutions (
    approval_request_id    TEXT PRIMARY KEY,
    approval_resolution_id TEXT NOT NULL,
    outcome                TEXT NOT NULL,
    action_digest          TEXT NOT NULL,
    policy_version         TEXT NOT NULL,
    approval_chain_version TEXT NOT NULL,
    final_entry_digest     TEXT,
    resolved_at            TEXT NOT NULL
);
"""

_REQUEST_COLUMNS = (
    "approval_request_id",
    "policy_decision_id",
    "action_digest",
    "agent_id",
    "operation",
    "policy_version",
    "approval_chain_id",
    "approval_chain_version",
    "expires_at",
    "subject_id",
    "target_resource",
    "fail_closed_on_timeout",
    "status",
    "requested_at",
)

_ENTRY_COLUMNS = (
    "chain_entry_id",
    "approval_request_id",
    "stage_index",
    "approver_kind",
    "approver_identity",
    "identity_assurance",
    "decision",
    "input_digest",
    "reason_code",
    "previous_entry_digest",
    "decided_at",
    "entry_digest",
)

_RESOLUTION_COLUMNS = (
    "approval_request_id",
    "approval_resolution_id",
    "outcome",
    "action_digest",
    "policy_version",
    "approval_chain_version",
    "final_entry_digest",
    "resolved_at",
)


# Mirrors ApprovalCoordinator._resolve: the request status each outcome leads to.
_TERMINAL_STATUS = {
    Outcome.ALLOW: ApprovalStatus.ALLOWED,
    Outcome.DENY: ApprovalStatus.DENIED,
    Outcome.EXPIRED: ApprovalStatus.EXPIRED,
}


def _dt_to_text(value: datetime) -> str:
    # isoformat() keeps microseconds and the UTC offset, and fromisoformat()
    # restores an equal datetime. Chain digests hash decided_at.isoformat(), so
    # this round trip must be exact.
    return value.isoformat()


def _text_to_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


class SQLiteApprovalStore:
    """Durable, process-safe :class:`ApprovalStore` backed by SQLite.

    Args:
        path: Database file path, or ``":memory:"`` for a private in-memory
            database (useful for tests; it is not durable and not shared).
        busy_timeout_ms: How long a write waits for another connection's lock
            before raising ``sqlite3.OperationalError``.

    The store behaves like :class:`InMemoryApprovalStore`, with these
    differences:

    * Every read returns fresh model objects. Mutating a returned object does
      not change stored state; use the store methods for that.
    * Chain entries are append-only. Appending an entry raises
      ``sqlite3.IntegrityError`` if its ``chain_entry_id`` is already used for
      the same request, or if another entry already has the same
      ``previous_entry_digest`` (a forked chain).
    * A resolution is terminal. A second ``save_resolution`` for the same
      request raises ``sqlite3.IntegrityError`` instead of overwriting the
      first. Overwriting would let the losing writer's following
      ``set_status`` move a ``CONSUMED`` request back to ``ALLOWED``.
    * ``save_resolution`` moves a ``PENDING`` request to the matching terminal
      status in the same transaction. A crash between the coordinator's
      ``save_resolution`` and ``set_status`` therefore cannot leave a resolved
      request ``PENDING``.

    Database errors are never swallowed, so a storage failure cannot be
    mistaken for "not found" or for a successful consume. The coordinator
    already turns unexpected errors in ``validate_for_execution`` into a
    fail-closed ``INTERNAL_ERROR``.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        busy_timeout_ms: int = 5000,
    ) -> None:
        if busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be >= 0")
        self._path = os.fspath(path)
        self._lock = threading.RLock()
        # Autocommit mode: every statement is its own transaction, which makes
        # the single-statement consume() atomic. check_same_thread=False is
        # safe because every use of the connection holds self._lock.
        self._conn: sqlite3.Connection | None = sqlite3.connect(
            self._path,
            timeout=busy_timeout_ms / 1000.0,
            isolation_level=None,
            check_same_thread=False,
        )
        try:
            self._conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
            if self._path != ":memory:":
                # WAL lets readers proceed while another process is writing.
                self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.executescript(_SCHEMA)
            self._check_schema_version()
        except BaseException:
            self._conn.close()
            self._conn = None
            raise

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        """Close the underlying connection. Safe to call more than once."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def __enter__(self) -> SQLiteApprovalStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            raise sqlite3.ProgrammingError("SQLiteApprovalStore is closed")
        return self._conn

    def _check_schema_version(self) -> None:
        conn = self._db()
        conn.execute(
            "INSERT OR IGNORE INTO agt_approval_meta (key, value) VALUES ('schema_version', ?)",
            (str(STORE_SCHEMA_VERSION),),
        )
        row = conn.execute(
            "SELECT value FROM agt_approval_meta WHERE key = 'schema_version'"
        ).fetchone()
        if row is None or row[0] != str(STORE_SCHEMA_VERSION):
            found = None if row is None else row[0]
            raise RuntimeError(
                f"unsupported approval store schema version {found!r} "
                f"(expected {STORE_SCHEMA_VERSION})"
            )

    # -- requests -----------------------------------------------------------

    def save_request(self, request: ApprovalRequest) -> None:
        values = (
            request.approval_request_id,
            request.policy_decision_id,
            request.action_digest,
            request.agent_id,
            request.operation,
            request.policy_version,
            request.approval_chain_id,
            request.approval_chain_version,
            _dt_to_text(request.expires_at),
            request.subject_id,
            request.target_resource,
            1 if request.fail_closed_on_timeout else 0,
            ApprovalStatus(request.status).value,
            _dt_to_text(request.requested_at),
        )
        columns = ", ".join(_REQUEST_COLUMNS)
        placeholders = ", ".join("?" for _ in _REQUEST_COLUMNS)
        updates = ", ".join(f"{c} = excluded.{c}" for c in _REQUEST_COLUMNS[1:])
        with self._lock:
            self._db().execute(
                f"INSERT INTO agt_approval_requests ({columns}) VALUES ({placeholders}) "
                f"ON CONFLICT (approval_request_id) DO UPDATE SET {updates}",
                values,
            )

    def get_request(self, approval_request_id: str) -> ApprovalRequest | None:
        with self._lock:
            row = (
                self._db()
                .execute(
                    f"SELECT {', '.join(_REQUEST_COLUMNS)} FROM agt_approval_requests "
                    "WHERE approval_request_id = ?",
                    (approval_request_id,),
                )
                .fetchone()
            )
        if row is None:
            return None
        data = dict(zip(_REQUEST_COLUMNS, row))
        return ApprovalRequest(
            approval_request_id=data["approval_request_id"],
            policy_decision_id=data["policy_decision_id"],
            action_digest=data["action_digest"],
            agent_id=data["agent_id"],
            operation=data["operation"],
            policy_version=data["policy_version"],
            approval_chain_id=data["approval_chain_id"],
            approval_chain_version=data["approval_chain_version"],
            expires_at=_text_to_dt(data["expires_at"]),
            subject_id=data["subject_id"],
            target_resource=data["target_resource"],
            fail_closed_on_timeout=bool(data["fail_closed_on_timeout"]),
            status=ApprovalStatus(data["status"]),
            requested_at=_text_to_dt(data["requested_at"]),
        )

    def set_status(self, approval_request_id: str, status: ApprovalStatus) -> None:
        with self._lock:
            self._db().execute(
                "UPDATE agt_approval_requests SET status = ? WHERE approval_request_id = ?",
                (ApprovalStatus(status).value, approval_request_id),
            )

    # -- chain entries ------------------------------------------------------

    def append_entry(self, entry: ApprovalChainEntry) -> None:
        values = (
            entry.chain_entry_id,
            entry.approval_request_id,
            int(entry.stage_index),
            ApproverKind(entry.approver_kind).value,
            entry.approver_identity,
            entry.identity_assurance,
            EntryDecision(entry.decision).value,
            entry.input_digest,
            entry.reason_code,
            entry.previous_entry_digest,
            _dt_to_text(entry.decided_at),
            entry.entry_digest,
        )
        columns = ", ".join(_ENTRY_COLUMNS)
        placeholders = ", ".join("?" for _ in _ENTRY_COLUMNS)
        with self._lock:
            self._db().execute(
                f"INSERT INTO agt_approval_chain_entries ({columns}) VALUES ({placeholders})",
                values,
            )

    def get_entries(self, approval_request_id: str) -> list[ApprovalChainEntry]:
        with self._lock:
            rows = (
                self._db()
                .execute(
                    f"SELECT {', '.join(_ENTRY_COLUMNS)} FROM agt_approval_chain_entries "
                    "WHERE approval_request_id = ? ORDER BY seq",
                    (approval_request_id,),
                )
                .fetchall()
            )
        entries = []
        for row in rows:
            data = dict(zip(_ENTRY_COLUMNS, row))
            entries.append(
                ApprovalChainEntry(
                    chain_entry_id=data["chain_entry_id"],
                    approval_request_id=data["approval_request_id"],
                    stage_index=data["stage_index"],
                    approver_kind=ApproverKind(data["approver_kind"]),
                    approver_identity=data["approver_identity"],
                    identity_assurance=data["identity_assurance"],
                    decision=EntryDecision(data["decision"]),
                    input_digest=data["input_digest"],
                    reason_code=data["reason_code"],
                    previous_entry_digest=data["previous_entry_digest"],
                    decided_at=_text_to_dt(data["decided_at"]),
                    entry_digest=data["entry_digest"],
                )
            )
        return entries

    # -- resolutions --------------------------------------------------------

    def save_resolution(self, resolution: ApprovalResolution) -> None:
        values = (
            resolution.approval_request_id,
            resolution.approval_resolution_id,
            Outcome(resolution.outcome).value,
            resolution.action_digest,
            resolution.policy_version,
            resolution.approval_chain_version,
            resolution.final_entry_digest,
            _dt_to_text(resolution.resolved_at),
        )
        columns = ", ".join(_RESOLUTION_COLUMNS)
        placeholders = ", ".join("?" for _ in _RESOLUTION_COLUMNS)
        terminal = _TERMINAL_STATUS[Outcome(resolution.outcome)]
        with self._lock:
            conn = self._db()
            conn.execute("BEGIN IMMEDIATE")
            try:
                # Plain INSERT: a resolution is terminal, so a second one for
                # the same request raises IntegrityError instead of overwriting.
                conn.execute(
                    f"INSERT INTO agt_approval_resolutions ({columns}) VALUES ({placeholders})",
                    values,
                )
                conn.execute(
                    "UPDATE agt_approval_requests SET status = ? "
                    "WHERE approval_request_id = ? AND status = ?",
                    (terminal.value, resolution.approval_request_id, ApprovalStatus.PENDING.value),
                )
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")

    def get_resolution(self, approval_request_id: str) -> ApprovalResolution | None:
        with self._lock:
            row = (
                self._db()
                .execute(
                    f"SELECT {', '.join(_RESOLUTION_COLUMNS)} FROM agt_approval_resolutions "
                    "WHERE approval_request_id = ?",
                    (approval_request_id,),
                )
                .fetchone()
            )
        if row is None:
            return None
        data = dict(zip(_RESOLUTION_COLUMNS, row))
        return ApprovalResolution(
            approval_request_id=data["approval_request_id"],
            approval_resolution_id=data["approval_resolution_id"],
            outcome=Outcome(data["outcome"]),
            action_digest=data["action_digest"],
            policy_version=data["policy_version"],
            approval_chain_version=data["approval_chain_version"],
            final_entry_digest=data["final_entry_digest"],
            resolved_at=_text_to_dt(data["resolved_at"]),
        )

    # -- one-time use -------------------------------------------------------

    def consume(self, approval_request_id: str) -> bool:
        """Atomically mark an ``ALLOWED`` request ``CONSUMED``.

        A single conditional ``UPDATE`` checks and changes the status in one
        step. SQLite serialises writers across connections and processes, so
        exactly one caller sees a changed row and gets ``True``. Every other
        caller gets ``False``.
        """
        with self._lock:
            cursor = self._db().execute(
                "UPDATE agt_approval_requests SET status = ? "
                "WHERE approval_request_id = ? AND status = ?",
                (
                    ApprovalStatus.CONSUMED.value,
                    approval_request_id,
                    ApprovalStatus.ALLOWED.value,
                ),
            )
            return cursor.rowcount == 1
