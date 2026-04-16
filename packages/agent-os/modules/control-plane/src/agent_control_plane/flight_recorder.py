# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Flight Recorder - Black Box Audit Logger for Agent Control Plane

This module provides SQLite-based audit logging for all agent actions,
capturing the exact state for forensic analysis and compliance.

Performance optimizations:
- WAL mode for concurrent reads during writes
- Batched writes with configurable flush interval
- Connection pooling to reduce overhead

Security features:
- Merkle chain for tamper detection
- Hash verification on reads
"""

import sqlite3
import uuid
import hashlib
import threading
import atexit
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
from collections import deque
import json
import logging


class FlightRecorder:
    """The Black Box Recorder for AI Agents.

    Logs every action attempt with full context for forensic analysis.
    Similar to an aircraft's flight data recorder, this captures:

    - **Timestamp**: When the action was attempted
    - **AgentID**: Which agent attempted it
    - **InputPrompt**: The original user/agent intent
    - **IntendedAction**: What the agent tried to do
    - **PolicyVerdict**: Whether it was allowed or blocked
    - **Result**: What actually happened

    Performance features:
        - WAL mode for better concurrent performance
        - Batched writes (configurable ``batch_size`` and ``flush_interval``)
        - Connection reuse within threads via thread-local storage

    Security features:
        - Merkle chain: Each entry includes SHA-256 hash of previous entry
        - Tamper detection: ``verify_integrity()`` checks the full hash chain

    Example:
        Basic recording workflow::

            recorder = FlightRecorder(db_path="audit.db")

            # Start a trace before executing a tool
            trace_id = recorder.start_trace(
                agent_id="agent-001",
                tool_name="web_search",
                tool_args={"query": "latest news"},
                input_prompt="Find me today's headlines",
            )

            # Log the outcome
            recorder.log_success(trace_id, result="Found 10 articles", execution_time_ms=152.3)

            # Query the audit log
            violations = recorder.query_logs(policy_verdict="blocked")

            # Verify tamper-proof integrity
            integrity = recorder.verify_integrity()
            assert integrity["valid"]

            recorder.close()
    """

    def __init__(
        self, 
        db_path: str = "flight_recorder.db",
        batch_size: int = 100,
        flush_interval_seconds: float = 5.0,
        enable_batching: bool = True
    ):
        """Initialize the Flight Recorder.

        Sets up the SQLite database with WAL mode, creates the audit log
        schema if it doesn't exist, and restores the Merkle hash chain
        from the last recorded entry.

        Args:
            db_path: Path to the SQLite database file. The file is created
                if it does not exist. Defaults to ``"flight_recorder.db"``.
            batch_size: Number of write operations to buffer before
                committing to disk. Larger values improve throughput at the
                cost of increased memory usage. Defaults to ``100``.
            flush_interval_seconds: Maximum number of seconds between
                automatic flushes, regardless of buffer size. Defaults to
                ``5.0``.
            enable_batching: When ``False``, every write is committed
                immediately (legacy behaviour). Defaults to ``True``.

        Raises:
            sqlite3.OperationalError: If the database file cannot be opened
                or the schema migration fails.
        """
        self.db_path = db_path
        self.logger = logging.getLogger("FlightRecorder")
        self.batch_size = batch_size
        self.flush_interval = flush_interval_seconds
        self.enable_batching = enable_batching
        
        # Batching state
        self._write_buffer: deque = deque()
        self._buffer_lock = threading.Lock()
        self._last_flush = datetime.utcnow()
        self._last_hash: Optional[str] = None
        
        # Cache immutable trace data for content hash recomputation
        self._trace_data: Dict[str, Dict[str, Any]] = {}
        
        # Thread-local connections for better performance
        self._local = threading.local()
        
        self._init_database()
        
        # Register cleanup on exit
        atexit.register(self._flush_and_close)

    def _get_connection(self) -> sqlite3.Connection:
        """Get a thread-local database connection with WAL mode."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            # Enable WAL mode for better concurrent performance
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")  # Good balance of safety/speed
            conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
            self._local.conn = conn
        return self._local.conn

    def _compute_hash(self, data: str, previous_hash: Optional[str] = None) -> str:
        """Compute SHA256 hash for Merkle chain."""
        content = f"{previous_hash or 'genesis'}:{data}"
        return hashlib.sha256(content.encode()).hexdigest()

    def _compute_content_hash(
        self,
        trace_id: str,
        timestamp: str,
        agent_id: str,
        tool_name: str,
        tool_args: Optional[str],
        policy_verdict: str,
        violation_reason: Optional[str] = None,
        result: Optional[str] = None,
        execution_time_ms: Optional[float] = None,
    ) -> str:
        """Compute SHA-256 hash over all substantive fields for tamper detection.

        Unlike ``_compute_hash`` which builds the Merkle chain and is set
        once at INSERT time, the content hash is recomputed whenever the
        row is updated (e.g. when a verdict changes from *pending* to
        *allowed*).  ``verify_integrity`` uses this hash to detect
        post-hoc field tampering.
        """
        data = (
            f"{trace_id}:{timestamp}:{agent_id}:{tool_name}:{tool_args}"
            f":{policy_verdict}:{violation_reason}:{result}:{execution_time_ms}"
        )
        return hashlib.sha256(data.encode()).hexdigest()

    def _recompute_content_hash(
        self,
        trace_id: str,
        policy_verdict: str,
        violation_reason: Optional[str] = None,
        result: Optional[str] = None,
        execution_time_ms: Optional[float] = None,
    ) -> Optional[str]:
        """Recompute content hash using cached trace data.

        Looks up the immutable fields (timestamp, agent_id, etc.) from the
        in-memory ``_trace_data`` cache populated at ``start_trace`` time,
        then delegates to ``_compute_content_hash`` with the updated
        mutable fields.  Returns ``None`` if the trace_id is not in the
        cache (e.g. recorder was re-instantiated between start and log).
        """
        trace = self._trace_data.get(trace_id)
        if trace is None:
            return None
        return self._compute_content_hash(
            trace_id,
            trace['timestamp'],
            trace['agent_id'],
            trace['tool_name'],
            trace['tool_args_json'],
            policy_verdict,
            violation_reason=violation_reason,
            result=result,
            execution_time_ms=execution_time_ms,
        )

    def _flush_buffer(self):
        """Flush pending writes to database."""
        with self._buffer_lock:
            if not self._write_buffer:
                return
            
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                while self._write_buffer:
                    operation = self._write_buffer.popleft()
                    cursor.execute(operation['sql'], operation['params'])
                
                conn.commit()
                self._last_flush = datetime.utcnow()
                self.logger.debug(f"Flushed write buffer")
            except Exception as e:
                conn.rollback()
                self.logger.error(f"Failed to flush buffer: {e}")
                raise

    def _maybe_flush(self):
        """Flush if batch size reached or interval exceeded."""
        if not self.enable_batching:
            self._flush_buffer()
            return
            
        should_flush = (
            len(self._write_buffer) >= self.batch_size or
            (datetime.utcnow() - self._last_flush).total_seconds() >= self.flush_interval
        )
        if should_flush:
            self._flush_buffer()

    def _queue_write(self, sql: str, params: tuple):
        """Queue a write operation."""
        with self._buffer_lock:
            self._write_buffer.append({'sql': sql, 'params': params})
        self._maybe_flush()

    def _flush_and_close(self):
        """Flush buffer and close connections on exit."""
        try:
            self._flush_buffer()
            if hasattr(self._local, 'conn') and self._local.conn:
                self._local.conn.close()
                self._local.conn = None
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def _init_database(self):
        """Initialize the SQLite database schema with WAL mode."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Enable WAL mode for concurrent reads during writes
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")

        # Create the main audit log table with hash column for Merkle chain
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trace_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                tool_args TEXT,
                input_prompt TEXT,
                policy_verdict TEXT NOT NULL,
                violation_reason TEXT,
                result TEXT,
                execution_time_ms REAL,
                metadata TEXT,
                entry_hash TEXT,
                previous_hash TEXT,
                content_hash TEXT
            )
        """
        )
        
        # Add hash columns if they don't exist (migration for existing DBs)
        try:
            cursor.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        try:
            cursor.execute("ALTER TABLE audit_log ADD COLUMN previous_hash TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        try:
            cursor.execute("ALTER TABLE audit_log ADD COLUMN content_hash TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists

        # Create indexes for common queries
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_agent_id ON audit_log(agent_id)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_policy_verdict ON audit_log(policy_verdict)
        """
        )

        conn.commit()
        conn.close()

        # Get last hash for Merkle chain
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        self._last_hash = row[0] if row else None

        self.logger.info(f"Flight Recorder initialized with WAL mode: {self.db_path}")

    def start_trace(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
        input_prompt: Optional[str] = None,
    ) -> str:
        """Start a new trace for an agent action.

        Creates a pending audit log entry and links it into the Merkle
        hash chain for tamper detection. The returned ``trace_id`` must be
        passed to one of the outcome methods (``log_success``,
        ``log_violation``, ``log_error``, ``log_shadow_exec``) to finalize
        the entry.

        Args:
            agent_id: Unique identifier of the agent performing the action.
            tool_name: Name of the tool being called (e.g. ``"web_search"``).
            tool_args: Keyword arguments passed to the tool. Serialized as
                JSON in the audit log. Defaults to ``None``.
            input_prompt: The original user or agent prompt that triggered
                this tool call. Defaults to ``None``.

        Returns:
            A UUID string uniquely identifying this trace. Use this value
            with the ``log_*`` methods to record the outcome.

        Example:
            >>> trace_id = recorder.start_trace(
            ...     agent_id="agent-001",
            ...     tool_name="file_write",
            ...     tool_args={"path": "/tmp/out.txt", "data": "hello"},
            ... )
            >>> recorder.log_success(trace_id, result="wrote 5 bytes")
        """
        trace_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()
        tool_args_json = json.dumps(tool_args) if tool_args else None
        
        # Compute hash for Merkle chain (immutable after INSERT)
        data = f"{trace_id}:{timestamp}:{agent_id}:{tool_name}:{tool_args_json}:pending"
        entry_hash = self._compute_hash(data, self._last_hash)
        previous_hash = self._last_hash
        self._last_hash = entry_hash

        # Compute content hash covering all substantive fields
        content_hash = self._compute_content_hash(
            trace_id, timestamp, agent_id, tool_name, tool_args_json,
            'pending',
        )

        # Cache immutable data so log_success/log_violation can recompute
        self._trace_data[trace_id] = {
            'timestamp': timestamp,
            'agent_id': agent_id,
            'tool_name': tool_name,
            'tool_args_json': tool_args_json,
        }

        self._queue_write(
            """
            INSERT INTO audit_log 
            (trace_id, timestamp, agent_id, tool_name, tool_args, input_prompt, policy_verdict, entry_hash, previous_hash, content_hash)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
            """,
            (trace_id, timestamp, agent_id, tool_name, tool_args_json, input_prompt, entry_hash, previous_hash, content_hash)
        )

        return trace_id

    def log_violation(self, trace_id: str, violation_reason: str):
        """Log a policy violation for a trace.

        Updates the audit entry identified by ``trace_id`` to ``blocked``
        status and records the reason. A warning is emitted to the logger.

        Args:
            trace_id: The trace ID returned by ``start_trace``.
            violation_reason: Human-readable explanation of why the action
                was blocked (e.g. ``"Tool 'rm_rf' not in allowed_tools"``).
        """
        content_hash = self._recompute_content_hash(
            trace_id, 'blocked', violation_reason=violation_reason,
        )

        self._queue_write(
            """
            UPDATE audit_log 
            SET policy_verdict = 'blocked', 
                violation_reason = ?,
                content_hash = ?
            WHERE trace_id = ?
            """,
            (violation_reason, content_hash, trace_id)
        )

        self.logger.warning(f"BLOCKED: {trace_id} - {violation_reason}")

    def log_shadow_exec(self, trace_id: str, simulated_result: Optional[str] = None):
        """Log a shadow mode execution (simulated, not real).

        Shadow mode allows the governance layer to return a plausible
        simulated result to the agent without actually executing the tool.
        This is useful for testing policy enforcement in production
        without impacting real systems.

        Args:
            trace_id: The trace ID returned by ``start_trace``.
            simulated_result: The simulated result string returned to the
                agent. Defaults to ``"Simulated success"`` when ``None``.
        """
        result_val = simulated_result or "Simulated success"
        content_hash = self._recompute_content_hash(
            trace_id, 'shadow', result=result_val,
        )

        self._queue_write(
            """
            UPDATE audit_log 
            SET policy_verdict = 'shadow', 
                result = ?,
                content_hash = ?
            WHERE trace_id = ?
            """,
            (result_val, content_hash, trace_id)
        )

        self.logger.info(f"SHADOW: {trace_id}")

    def log_success(
        self, trace_id: str, result: Optional[Any] = None, execution_time_ms: Optional[float] = None
    ):
        """Log a successful execution.

        Updates the audit entry to ``allowed`` status and records the
        result and timing information.

        Args:
            trace_id: The trace ID returned by ``start_trace``.
            result: The return value of the tool execution. Non-string
                values are JSON-serialized before storage. Defaults to
                ``None``.
            execution_time_ms: Wall-clock execution time in milliseconds.
                Defaults to ``None``.
        """
        result_str = (
            json.dumps(result)
            if result and not isinstance(result, str)
            else str(result) if result else None
        )

        content_hash = self._recompute_content_hash(
            trace_id, 'allowed', result=result_str,
            execution_time_ms=execution_time_ms,
        )

        self._queue_write(
            """
            UPDATE audit_log 
            SET policy_verdict = 'allowed', 
                result = ?,
                execution_time_ms = ?,
                content_hash = ?
            WHERE trace_id = ?
            """,
            (result_str, execution_time_ms, content_hash, trace_id)
        )

        self.logger.info(f"ALLOWED: {trace_id}")

    def log_error(self, trace_id: str, error: str):
        """Log an execution error.

        Updates the audit entry to ``error`` status. Unlike violations,
        errors indicate that the tool was *allowed* by policy but failed
        during execution (e.g. network timeout, invalid arguments).

        Args:
            trace_id: The trace ID returned by ``start_trace``.
            error: Error message describing the failure.
        """
        content_hash = self._recompute_content_hash(
            trace_id, 'error', violation_reason=error,
        )

        self._queue_write(
            """
            UPDATE audit_log 
            SET policy_verdict = 'error', 
                violation_reason = ?,
                content_hash = ?
            WHERE trace_id = ?
            """,
            (error, content_hash, trace_id)
        )

        self.logger.error(f"ERROR: {trace_id} - {error}")

    def query_logs(
        self,
        agent_id: Optional[str] = None,
        policy_verdict: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list:
        """Query the audit logs with filters.

        Opens a new read-only connection (safe for concurrent access under
        WAL mode) and returns matching entries ordered by timestamp
        descending.

        Args:
            agent_id: Filter by agent identifier. When ``None``, all
                agents are included.
            policy_verdict: Filter by verdict string. Valid values are
                ``"allowed"``, ``"blocked"``, ``"shadow"``, ``"error"``,
                and ``"pending"``. When ``None``, all verdicts are included.
            start_time: Include only entries at or after this timestamp.
            end_time: Include only entries at or before this timestamp.
            limit: Maximum number of results to return. Defaults to ``100``.

        Returns:
            A list of dictionaries, each representing one audit log entry
            with keys: ``trace_id``, ``timestamp``, ``agent_id``,
            ``tool_name``, ``tool_args``, ``input_prompt``,
            ``policy_verdict``, ``violation_reason``, ``result``,
            ``execution_time_ms``, ``metadata``, ``entry_hash``,
            ``previous_hash``.

        Example:
            >>> blocked = recorder.query_logs(
            ...     agent_id="agent-001",
            ...     policy_verdict="blocked",
            ...     limit=50,
            ... )
            >>> for entry in blocked:
            ...     print(entry["violation_reason"])
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []

        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        if policy_verdict:
            query += " AND policy_verdict = ?"
            params.append(policy_verdict)

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        results = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregate statistics about the audit log.

        Returns:
            A dictionary containing:

            - ``total_actions`` (int): Total number of recorded actions.
            - ``by_verdict`` (Dict[str, int]): Action counts grouped by
              policy verdict (e.g. ``{"allowed": 42, "blocked": 3}``).
            - ``top_agents`` (List[Dict]): Up to 10 most active agents,
              each with ``agent_id`` and ``count`` keys.
            - ``avg_execution_time_ms`` (Optional[float]): Mean execution
              time across all successful actions, or ``None`` if no timing
              data is available.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Total actions
        cursor.execute("SELECT COUNT(*) FROM audit_log")
        total = cursor.fetchone()[0]

        # By verdict
        cursor.execute(
            """
            SELECT policy_verdict, COUNT(*) as count 
            FROM audit_log 
            GROUP BY policy_verdict
        """
        )
        by_verdict = {row[0]: row[1] for row in cursor.fetchall()}

        # By agent
        cursor.execute(
            """
            SELECT agent_id, COUNT(*) as count 
            FROM audit_log 
            GROUP BY agent_id
            ORDER BY count DESC
            LIMIT 10
        """
        )
        top_agents = [{"agent_id": row[0], "count": row[1]} for row in cursor.fetchall()]

        # Average execution time
        cursor.execute(
            """
            SELECT AVG(execution_time_ms) 
            FROM audit_log 
            WHERE execution_time_ms IS NOT NULL
        """
        )
        avg_exec_time = cursor.fetchone()[0]

        conn.close()

        return {
            "total_actions": total,
            "by_verdict": by_verdict,
            "top_agents": top_agents,
            "avg_execution_time_ms": avg_exec_time,
        }

    def close(self):
        """Clean up resources by flushing the write buffer and closing connections."""
        self._flush_and_close()
    
    def flush(self):
        """Manually flush the write buffer to disk."""
        self._flush_buffer()
    
    # ===== Tamper Detection =====
    
    def verify_integrity(self) -> Dict[str, Any]:
        """Verify the integrity of the audit log.

        Flushes any buffered writes, then walks the entire audit log in
        insertion order performing two checks for every entry:

        1. **Chain integrity** – each entry's ``previous_hash`` must match
           the ``entry_hash`` of its predecessor.
        2. **Content integrity** – the stored ``content_hash`` must match
           a freshly computed hash over all substantive row fields
           (including the current ``policy_verdict``).  This detects
           post-hoc tampering with the verdict or any other field.

        Returns:
            A dictionary with the following keys:

            - ``valid`` (bool): ``True`` if both checks pass for every
              entry.
            - ``total_entries`` (int): Number of entries checked.
            - ``message`` (str): Human-readable summary (when valid).
            - ``first_tampered_id`` (int): Row ID of the first entry
              where a check fails (only present when invalid).
            - ``error`` (str): Description of the integrity failure
              (only present when invalid).

        Example:
            >>> result = recorder.verify_integrity()
            >>> if not result["valid"]:
            ...     print(f"Tampered at entry {result['first_tampered_id']}")
        """
        self._flush_buffer()  # Ensure all writes are committed
        
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, trace_id, timestamp, agent_id, tool_name, tool_args, 
                   policy_verdict, violation_reason, result, execution_time_ms,
                   entry_hash, previous_hash, content_hash
            FROM audit_log 
            ORDER BY id ASC
        """)
        
        entries = cursor.fetchall()
        
        if not entries:
            return {"valid": True, "total_entries": 0, "message": "No entries to verify"}
        
        expected_previous_hash = None
        
        for entry in entries:
            # 1. Verify chain link (previous_hash matches predecessor)
            if entry['previous_hash'] != expected_previous_hash:
                # First entry should have None/null previous_hash
                if entry['id'] == 1 and entry['previous_hash'] is None:
                    pass  # OK - genesis entry
                else:
                    return {
                        "valid": False,
                        "total_entries": len(entries),
                        "first_tampered_id": entry['id'],
                        "error": f"Hash chain broken at entry {entry['id']}: expected previous_hash {expected_previous_hash}, got {entry['previous_hash']}"
                    }
            
            # 2. Verify content hash (detects field tampering including verdict)
            if entry['content_hash']:
                expected_content = self._compute_content_hash(
                    entry['trace_id'],
                    entry['timestamp'],
                    entry['agent_id'],
                    entry['tool_name'],
                    entry['tool_args'],
                    entry['policy_verdict'],
                    violation_reason=entry['violation_reason'],
                    result=entry['result'],
                    execution_time_ms=entry['execution_time_ms'],
                )
                if expected_content != entry['content_hash']:
                    return {
                        "valid": False,
                        "total_entries": len(entries),
                        "first_tampered_id": entry['id'],
                        "error": f"Content hash mismatch at entry {entry['id']}: field tampering detected"
                    }
            
            expected_previous_hash = entry['entry_hash']
        
        return {
            "valid": True,
            "total_entries": len(entries),
            "message": "Hash chain integrity verified"
        }
    
    # ===== Time-Travel Debugging Support =====
    
    def get_log(self) -> list:
        """Get the complete audit log for time-travel debugging.

        Returns all entries ordered by timestamp ascending, enabling
        chronological replay of agent actions.

        Returns:
            A list of dictionaries representing every audit log entry,
            ordered oldest-first.
        """
        self._flush_buffer()  # Ensure all writes are committed

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT * FROM audit_log 
            ORDER BY timestamp ASC
            """
        )
        results = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return results
    
    def get_events_in_time_range(
        self,
        start_time: datetime,
        end_time: datetime,
        agent_id: Optional[str] = None
    ) -> list:
        """Get events within a specific time range for time-travel replay.

        Useful for replaying agent behaviour during a specific incident
        window or for generating compliance reports.

        Args:
            start_time: Inclusive start of the time range.
            end_time: Inclusive end of the time range.
            agent_id: When provided, only entries for this agent are
                returned. Defaults to ``None`` (all agents).

        Returns:
            A list of audit log entry dictionaries within the given time
            range, ordered oldest-first.
        """
        self._flush_buffer()  # Ensure all writes are committed

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
            SELECT * FROM audit_log 
            WHERE timestamp >= ? AND timestamp <= ?
        """
        params = [start_time.isoformat(), end_time.isoformat()]
        
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        
        query += " ORDER BY timestamp ASC"
        
        cursor.execute(query, params)
        results = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return results

