# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""SLI persistence backends — durable measurement storage across agent restarts."""

from __future__ import annotations

import json
import sqlite3
import threading
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator


# ---------------------------------------------------------------------------
# Value transport type (mirrors SLIValue but avoids circular import)
# ---------------------------------------------------------------------------

class _Row:
    """Lightweight row returned by store queries."""

    __slots__ = ("name", "value", "timestamp", "metadata")

    def __init__(self, name: str, value: float, timestamp: float, metadata: dict[str, Any]) -> None:
        self.name = name
        self.value = value
        self.timestamp = timestamp
        self.metadata = metadata


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class MeasurementStore(ABC):
    """Pluggable backend for SLI measurement persistence.

    Implementors must provide append/query/clear operations.
    The contract guarantees that ``query(name, since)`` returns rows
    in ascending timestamp order.
    """

    @abstractmethod
    def append(self, name: str, value: float, timestamp: float, metadata: dict[str, Any]) -> None:
        """Persist a new measurement."""

    @abstractmethod
    def query(self, name: str, since: float) -> list[_Row]:
        """Return all measurements for *name* with timestamp >= *since*."""

    @abstractmethod
    def clear(self, name: str | None = None) -> None:
        """Delete measurements. If *name* is None, clear everything."""


# ---------------------------------------------------------------------------
# In-memory (default — identical behaviour to the original list)
# ---------------------------------------------------------------------------

class InMemoryMeasurementStore(MeasurementStore):
    """Thread-safe in-memory store that matches the original ``_measurements`` list.

    This is the default backend; it preserves backward-compatible behaviour.
    A ``threading.Lock`` protects all mutations and reads so concurrent agents
    sharing an instance will not observe torn state.
    """

    def __init__(self) -> None:
        self._rows: list[_Row] = []
        self._lock = threading.Lock()

    def append(self, name: str, value: float, timestamp: float, metadata: dict[str, Any]) -> None:
        """Append a measurement (thread-safe)."""
        with self._lock:
            self._rows.append(_Row(name, value, timestamp, metadata))

    def query(self, name: str, since: float) -> list[_Row]:
        """Return rows for *name* with timestamp >= *since* (thread-safe)."""
        with self._lock:
            return [r for r in self._rows if r.name == name and r.timestamp >= since]

    def clear(self, name: str | None = None) -> None:
        """Delete measurements (thread-safe). Pass *name* to delete one SLI only."""
        with self._lock:
            if name is None:
                self._rows.clear()
            else:
                self._rows = [r for r in self._rows if r.name != name]


# ---------------------------------------------------------------------------
# SQLite (durable)
# ---------------------------------------------------------------------------

_VALID_DB_SCHEMES = frozenset(("", ":memory:"))

# Maximum accepted path length (guards against resource-exhaustion attacks).
_MAX_DB_PATH_LEN = 4096

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS sli_measurements (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT    NOT NULL,
    value     REAL    NOT NULL,
    timestamp REAL    NOT NULL,
    metadata  TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_sli_name_ts ON sli_measurements(name, timestamp);
"""

_INSERT = "INSERT INTO sli_measurements (name, value, timestamp, metadata) VALUES (?, ?, ?, ?)"
_QUERY  = "SELECT name, value, timestamp, metadata FROM sli_measurements WHERE name=? AND timestamp>=? ORDER BY timestamp ASC"
_CLEAR_ALL  = "DELETE FROM sli_measurements"
_CLEAR_NAME = "DELETE FROM sli_measurements WHERE name=?"


def _validate_db_path(raw: str) -> str:
    """Resolve and validate *raw* database path.

    Accepts only:
    - the special literal ``:memory:``
    - ``file://`` URIs whose path resolves inside the current user's home
      directory or the system's standard temporary directory
    - Plain filesystem paths (absolute or relative)

    Raises ``ValueError`` for:
    - Non-``file://`` URI schemes (``http://``, ``ftp://``, etc.)
    - ``file://`` URIs that point outside safe directories (e.g.
      ``file:///etc/passwd``)
    - Paths that are excessively long (> 4 096 chars)

    Returns the normalised, resolved path string.
    """
    import tempfile as _tempfile

    if raw == ":memory:":
        return raw

    if len(raw) > _MAX_DB_PATH_LEN:
        raise ValueError(
            f"Invalid db_path: path exceeds {_MAX_DB_PATH_LEN} characters."
        )

    # Handle file:// URIs — extract the path component and validate it.
    if raw.startswith("file://"):
        # Strip the scheme; handle both file:///abs/path and file://host/path
        path_part = raw[len("file://"):]
        # If it starts with a third slash it's the canonical file:///abs form
        if path_part.startswith("/"):
            raw = path_part  # e.g. "/etc/passwd"
        elif len(path_part) >= 2 and path_part[0].isalpha() and path_part[1] in (":", "/"):
            raw = path_part  # Windows drive letter: file://C:\path or file://C:/path
        else:
            # file://hostname/path — reject (remote paths not supported)
            raise ValueError(
                f"Invalid db_path {raw!r}: remote file:// URIs are not supported."
            )

    # Reject any remaining URI scheme (http://, ftp://, etc.)
    if "://" in raw:
        raise ValueError(
            f"Invalid db_path {raw!r}: only plain file paths or ':memory:' are supported."
        )

    resolved = Path(raw).expanduser().resolve()

    # Confine to safe root directories: user home and system temp.
    safe_roots = [Path.home().resolve(), Path(_tempfile.gettempdir()).resolve()]
    # Also allow paths that are *inside* the current working directory.
    safe_roots.append(Path.cwd().resolve())

    if not any(
        str(resolved).startswith(str(root)) for root in safe_roots
    ):
        raise ValueError(
            f"Invalid db_path {raw!r}: resolved path {resolved} is outside "
            f"allowed directories (home, temp, cwd). Move the database file "
            f"to one of these locations."
        )

    return str(resolved)


class SQLiteMeasurementStore(MeasurementStore):
    """SQLite-backed persistent store.

    Measurements survive agent restarts. The database file is created on first
    use; pass ``db_path=":memory:"`` for an in-process SQLite during tests.

    Note: ``":memory:"`` databases use a single persistent connection because
    each new ``sqlite3.connect(":memory:")`` call creates a fresh, empty DB.
    File-based databases open a new connection per operation (safe for
    multi-process use).

    Example::

        store = SQLiteMeasurementStore(db_path="~/.agent/sli.db")
        sli = TaskSuccessRate(store=store)
    """

    def __init__(self, db_path: str | Path = "sli_measurements.db") -> None:
        self._db_path = _validate_db_path(str(db_path))
        self._in_memory = self._db_path == ":memory:"
        # For :memory: databases keep one connection alive for the lifetime of this object.
        # A dedicated lock serialises concurrent access to this shared connection.
        self._mem_conn: sqlite3.Connection | None = None
        self._mem_lock = threading.Lock()
        if self._in_memory:
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.executescript(_CREATE_TABLE)
            self._mem_conn.commit()
        else:
            self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_CREATE_TABLE)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        if self._in_memory:
            assert self._mem_conn is not None  # noqa: S101 — data integrity assertion
            with self._mem_lock:
                yield self._mem_conn
                self._mem_conn.commit()
            return
        conn = sqlite3.connect(self._db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def append(self, name: str, value: float, timestamp: float, metadata: dict[str, Any]) -> None:
        """Persist a measurement to SQLite."""
        with self._connect() as conn:
            conn.execute(_INSERT, (name, value, timestamp, json.dumps(metadata)))

    def query(self, name: str, since: float) -> list[_Row]:
        """Return rows for *name* with timestamp >= *since*, ascending order."""
        with self._connect() as conn:
            rows = conn.execute(_QUERY, (name, since)).fetchall()
        return [
            _Row(r["name"], r["value"], r["timestamp"], json.loads(r["metadata"]))
            for r in rows
        ]

    def clear(self, name: str | None = None) -> None:
        """Delete measurements. Pass *name* to delete one SLI only."""
        with self._connect() as conn:
            if name is None:
                conn.execute(_CLEAR_ALL)
            else:
                conn.execute(_CLEAR_NAME, (name,))

    def close(self) -> None:
        """Release the persistent connection (only relevant for :memory: stores)."""
        if self._mem_conn is not None:
            self._mem_conn.close()
            self._mem_conn = None
