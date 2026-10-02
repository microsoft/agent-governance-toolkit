# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
External append-only audit trail backends with cryptographic integrity.

Provides pluggable audit sinks that write signed, hash-chained entries
to external storage (files, databases, etc.).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from .audit import AuditEntry

logger = logging.getLogger(__name__)

# Not defined on Windows; there a symlinked audit path is a smaller risk
# (no unprivileged-user symlink-swap TOCTOU) so opening without it is fine.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
# Not defined on Windows, which has no equivalent POSIX-permission concept.
_HAS_FCHMOD = hasattr(os, "fchmod")


# ---------------------------------------------------------------------------
# AuditSink Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class AuditSink(Protocol):
    """Abstract interface for external audit sinks."""

    def write(self, entry: AuditEntry) -> None:
        """Write a single audit entry to the sink."""
        ...

    def write_batch(self, entries: list[AuditEntry]) -> None:
        """Write a batch of audit entries to the sink."""
        ...

    def verify_integrity(self) -> tuple[bool, str | None]:
        """Verify the integrity of the audit chain in this sink.

        Returns:
            Tuple of (is_valid, error_message_or_none).
        """
        ...

    def close(self) -> None:
        """Release resources held by the sink."""
        ...


# ---------------------------------------------------------------------------
# SignedAuditEntry
# ---------------------------------------------------------------------------


class SignedAuditEntry(BaseModel):
    """Wrapper that adds cryptographic integrity to an :class:`AuditEntry`.

    Each signed entry contains:
    * A SHA-256 content hash covering all entry fields.
    * A ``previous_hash`` chain link to the preceding entry.
    * An HMAC-SHA256 signature computed with a caller-supplied secret key.
    """

    entry_id: str
    timestamp: str  # ISO-8601 string for stable serialisation
    event_type: str
    agent_did: str
    action: str
    resource: Optional[str] = None
    target_did: Optional[str] = None
    data: dict[str, Any] = Field(default_factory=dict)
    outcome: str = "success"
    policy_decision: Optional[str] = None
    matched_rule: Optional[str] = None
    trace_id: Optional[str] = None
    session_id: Optional[str] = None

    # Execution-context enrichment — stored for observability; excluded from
    # ``_canonical_payload()`` so that existing HMAC chains remain verifiable.
    sandbox_id: Optional[str] = None
    environment: Optional[str] = None
    compute_driver: Optional[str] = None

    # Integrity fields
    content_hash: str = ""
    previous_hash: str = ""
    signature: str = ""

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_entry(
        cls,
        entry: AuditEntry,
        previous_hash: str,
        secret_key: bytes,
    ) -> SignedAuditEntry:
        """Build a :class:`SignedAuditEntry` from an :class:`AuditEntry`.

        Args:
            entry: The raw audit entry.
            previous_hash: Hash of the previous signed entry (or ``""``
                for the genesis entry).
            secret_key: HMAC secret used to sign the entry.
        """
        signed = cls(
            entry_id=entry.entry_id,
            timestamp=entry.timestamp.isoformat(),
            event_type=entry.event_type,
            agent_did=entry.agent_did,
            action=entry.action,
            resource=entry.resource,
            target_did=entry.target_did,
            data=entry.data,
            outcome=entry.outcome,
            policy_decision=entry.policy_decision,
            matched_rule=entry.matched_rule,
            trace_id=entry.trace_id,
            session_id=entry.session_id,
            sandbox_id=entry.sandbox_id,
            environment=entry.environment,
            compute_driver=entry.compute_driver,
            previous_hash=previous_hash,
        )

        signed.content_hash = signed._compute_content_hash()
        signed.signature = signed._compute_signature(secret_key)
        return signed

    # ------------------------------------------------------------------
    # Hashing & signing
    # ------------------------------------------------------------------

    def _canonical_payload(self) -> bytes:
        """Deterministic JSON payload used for hashing.

        Excludes ``content_hash`` and ``signature`` so they can be
        recomputed during verification.

        Also excludes execution-context fields (``sandbox_id``,
        ``environment``, ``compute_driver``) so that they can be added
        to entries without invalidating existing HMAC chains.
        """
        payload: dict[str, Any] = {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "agent_did": self.agent_did,
            "action": self.action,
            "resource": self.resource,
            "target_did": self.target_did,
            "data": self.data,
            "outcome": self.outcome,
            "policy_decision": self.policy_decision,
            "matched_rule": self.matched_rule,
            "trace_id": self.trace_id,
            "session_id": self.session_id,
            "previous_hash": self.previous_hash,
        }
        return json.dumps(payload, sort_keys=True, default=str).encode()

    def _compute_content_hash(self) -> str:
        """SHA-256 hex digest of the canonical payload."""
        return hashlib.sha256(self._canonical_payload()).hexdigest()

    def _compute_signature(self, secret_key: bytes) -> str:
        """HMAC-SHA256 hex digest of ``content_hash`` using *secret_key*."""
        return hmac.new(
            secret_key,
            self.content_hash.encode(),
            hashlib.sha256,
        ).hexdigest()

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, secret_key: bytes) -> bool:
        """Check that the content hash and HMAC signature are valid.

        Args:
            secret_key: The HMAC secret used when the entry was signed.

        Returns:
            ``True`` if both the hash and signature match, ``False``
            otherwise.
        """
        expected_hash = self._compute_content_hash()
        if not hmac.compare_digest(self.content_hash, expected_hash):
            return False

        expected_sig = self._compute_signature(secret_key)
        return hmac.compare_digest(self.signature, expected_sig)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain ``dict`` suitable for JSON output."""
        return self.model_dump()


def _iter_parsed_entries(path: Path) -> list[SignedAuditEntry]:
    """Parse every line of *path*, skipping (and logging) any that don't.

    A write interrupted mid-line (crash, disk full) leaves a corrupt
    line; treating that as a hard failure would turn one bad append into
    a permanent block on ever reading or verifying the file again. This
    doesn't weaken the hash chain: a skipped line is simply excluded from
    it, so replacing a real entry with garbage still breaks chain
    continuity at the next real entry - it can't be smoothed over without
    the signing key. Shared by read_entries, HashChainVerifier.verify_file,
    and FileAuditSink's own chain-resume logic, so all three agree on what
    "readable" means.
    """
    entries: list[SignedAuditEntry] = []
    if not path.exists():
        return entries
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                entries.append(SignedAuditEntry.model_validate_json(stripped))
            except Exception:
                logger.warning("%s: skipping unparsable line %d", path, lineno)
    return entries


# ---------------------------------------------------------------------------
# FileAuditSink
# ---------------------------------------------------------------------------


class FileAuditSink:
    """Append-only, file-based audit sink writing JSON-lines.

    Each line in the output file is a JSON-serialised
    :class:`SignedAuditEntry`.  The sink maintains a hash-chain across
    entries and signs every entry with an HMAC key.

    Args:
        path: Destination file path.
        secret_key: HMAC secret for signing entries.
        max_file_size: Maximum file size in bytes before rotation.
            ``0`` disables rotation (default).
    """

    def __init__(
        self,
        path: Path | str,
        secret_key: bytes,
        *,
        max_file_size: int = 0,
    ) -> None:
        self._path = Path(path)
        # Validated here rather than left for the first write() to hit
        # FileNotFoundError/IsADirectoryError/ELOOP by accident: a caller
        # going through govern() already gets a construction-time error for
        # a bad key, and a bad path deserves the same rather than a lazily
        # discovered one. A symlinked path specifically would otherwise
        # still open successfully (following it) for every operation except
        # _append_line's O_NOFOLLOW, which only raises ELOOP once the first
        # entry is actually written.
        if self._path.is_symlink():
            raise ValueError(f"audit sink path must not be a symlink: {self._path}")
        if self._path.is_dir():
            raise IsADirectoryError(f"audit sink path is a directory: {self._path}")
        if not self._path.parent.is_dir():
            raise FileNotFoundError(
                f"audit sink parent directory does not exist: {self._path.parent}"
            )
        self._secret_key = secret_key
        self._max_file_size = max_file_size
        self._lock = threading.Lock()
        self._previous_hash: str = ""
        self._closed = False

        # Resume chain if the file already has entries.
        if self._path.exists() and self._path.stat().st_size > 0:
            self._previous_hash = self._read_last_hash()
        # (st_dev, st_ino) of the file backing previous_hash above, so a
        # write() can tell whether *path* still names that same file or an
        # external rotation (logrotate-style rename) replaced it - see
        # _resync_if_rotated.
        self._file_id = self._current_file_id()

    # ------------------------------------------------------------------
    # AuditSink interface
    # ------------------------------------------------------------------

    def write(self, entry: AuditEntry) -> None:
        """Write a single entry, rotating the file if necessary."""
        with self._lock:
            self._maybe_rotate()
            self._resync_if_rotated()
            signed = SignedAuditEntry.from_entry(
                entry,
                previous_hash=self._previous_hash,
                secret_key=self._secret_key,
            )
            self._append_line(signed)
            self._previous_hash = signed.content_hash
            self._file_id = self._current_file_id()

    def write_batch(self, entries: list[AuditEntry]) -> None:
        """Write a batch of entries atomically (under lock)."""
        with self._lock:
            self._resync_if_rotated()
            for entry in entries:
                self._maybe_rotate()
                signed = SignedAuditEntry.from_entry(
                    entry,
                    previous_hash=self._previous_hash,
                    secret_key=self._secret_key,
                )
                self._append_line(signed)
                self._previous_hash = signed.content_hash
            self._file_id = self._current_file_id()

    def verify_integrity(self) -> tuple[bool, str | None]:
        """Read back the file and verify hash chain + HMAC signatures."""
        verifier = HashChainVerifier()
        is_valid, errors = verifier.verify_file(self._path, self._secret_key)
        if is_valid:
            return True, None
        return False, "; ".join(errors)

    def matches_key(self, secret_key: bytes) -> bool:
        """Whether *secret_key* is the key this sink signs entries with."""
        return hmac.compare_digest(self._secret_key, secret_key)

    def close(self) -> None:
        """Mark the sink as closed."""
        self._closed = True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _append_line(self, signed: SignedAuditEntry) -> None:
        """Append a single JSON line to the file.

        Opens with O_CREAT|O_APPEND and mode 0600 rather than plain
        open(path, "a"): entries can carry an agent's call arguments, so
        the default 0644 a plain open() creates would make audit content
        world-readable, and O_NOFOLLOW refuses to write through a symlink
        planted at the configured path. The 0o600 above only applies if
        this call created the file; one that already existed (e.g. 0644)
        keeps its old mode otherwise, so fchmod tightens it explicitly too
        - inside the fdopen block, on the file object's own descriptor, so
        a failing fchmod (e.g. EPERM: the file is owned by another user)
        still closes the descriptor via the same exception path a failing
        write would, rather than leaking it. A file this process can't
        chmod now fails every write instead of silently leaving it at its
        existing, looser mode.
        """
        line = json.dumps(signed.to_dict(), sort_keys=True, default=str)
        fd = os.open(
            self._path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | _O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            if _HAS_FCHMOD:
                os.fchmod(fh.fileno(), 0o600)
            fh.write(line + "\n")

    def _maybe_rotate(self) -> None:
        """Rotate the file if it exceeds *max_file_size*."""
        if self._max_file_size <= 0:
            return
        if not self._path.exists():
            return
        if self._path.stat().st_size >= self._max_file_size:
            rotated = self._path.with_suffix(
                f".{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.jsonl"
            )
            os.replace(self._path, rotated)
            # Reset chain for the new file
            self._previous_hash = ""

    def _current_file_id(self) -> tuple[int, int] | None:
        """(st_dev, st_ino) of the file at self._path, or None if absent."""
        try:
            st = self._path.stat()
        except OSError:
            return None
        return (st.st_dev, st.st_ino)

    def _resync_if_rotated(self) -> None:
        """Re-derive previous_hash if *path* no longer names the file this
        sink last wrote to.

        _maybe_rotate() is this sink's own, self-triggered rotation and
        already resets previous_hash directly. This instead covers a file
        replaced out from under a *shared* sink by something external
        (logrotate-style rename, another process, a caller removing the
        file by hand): without it, the cached previous_hash keeps chaining
        onto a hash from a file that's gone, and verify_integrity() on the
        replacement breaks at its first entry. Caller must hold self._lock.
        """
        current_id = self._current_file_id()
        if current_id == self._file_id:
            return
        self._previous_hash = self._read_last_hash() if current_id is not None else ""
        self._file_id = current_id

    def _read_last_hash(self) -> str:
        """Return the content_hash to chain the next entry onto, after
        verifying the existing chain authenticates under this sink's key.

        Resuming onto an unverified chain would let a file swapped out
        from under this sink - by another process, an attacker, or just a
        different key - get silently extended as if it were ours;
        verify_integrity() would then fail confusingly, if anyone thought
        to check. Fail closed here instead, at resume time, with a clear
        reason. Unparsable lines are skipped, not treated as a failure -
        see _iter_parsed_entries.
        """
        previous_hash = ""
        for entry in _iter_parsed_entries(self._path):
            if entry.previous_hash != previous_hash or not entry.verify(self._secret_key):
                raise ValueError(
                    f"{self._path}: existing audit chain does not verify "
                    "under the configured audit_secret_key - refusing to "
                    "resume onto an unauthenticated or tampered file."
                )
            previous_hash = entry.content_hash
        return previous_hash

    def read_entries(self) -> list[SignedAuditEntry]:
        """Read all signed entries from the file (for testing/querying).
        Unparsable lines are skipped - see _iter_parsed_entries."""
        return _iter_parsed_entries(self._path)


# ---------------------------------------------------------------------------
# HashChainVerifier
# ---------------------------------------------------------------------------


class HashChainVerifier:
    """Standalone tool to verify the integrity of a JSON-lines audit file.

    Checks:
    * Hash chain continuity (each ``previous_hash`` matches the prior
      entry's ``content_hash``).
    * Content hash correctness (recomputed vs stored).
    * HMAC signature validity.
    """

    def verify_file(
        self,
        path: Path | str,
        secret_key: bytes,
    ) -> tuple[bool, list[str]]:
        """Verify a JSON-lines audit file.

        Args:
            path: Path to the audit file.
            secret_key: HMAC secret used when entries were written.

        Returns:
            Tuple of ``(is_valid, list_of_error_strings)``.
        """
        path = Path(path)
        errors: list[str] = []

        if not path.exists():
            return False, ["File does not exist"]

        # Unparsable lines are skipped, not a hard failure - see
        # _iter_parsed_entries. A genuinely tampered or foreign entry among
        # what does parse still fails chain-continuity or HMAC below.
        entries = _iter_parsed_entries(path)

        previous_hash = ""
        for idx, entry in enumerate(entries):
            # Chain link
            if entry.previous_hash != previous_hash:
                errors.append(
                    f"Entry {idx} ({entry.entry_id}): chain break — "
                    f"expected previous_hash={previous_hash!r}, "
                    f"got {entry.previous_hash!r}"
                )

            # Content hash
            expected_hash = entry._compute_content_hash()
            if not hmac.compare_digest(entry.content_hash, expected_hash):
                errors.append(
                    f"Entry {idx} ({entry.entry_id}): content hash mismatch"
                )

            # HMAC signature
            if not entry.verify(secret_key):
                errors.append(
                    f"Entry {idx} ({entry.entry_id}): HMAC signature invalid"
                )

            previous_hash = entry.content_hash

        return (len(errors) == 0), errors


# ---------------------------------------------------------------------------
# StdoutAuditSink
# ---------------------------------------------------------------------------


class StdoutAuditSink:
    """Audit sink that emits one JSON object per line (JSONL) to stdout.

    Designed for containerised deployments where log aggregation systems
    (Kubernetes, Docker, OpenShell, sidecar shippers, ``jq`` pipelines)
    consume structured JSON from process stdout.

    Properties:
    * One valid JSON object per line -- never split across lines.
    * UTF-8 safe: non-ASCII characters are included verbatim (not escaped).
    * Flushed after every :meth:`write` and after every :meth:`write_batch`.
    * Thread-safe: a **class-level** lock serialises all stdout writes
      across every :class:`StdoutAuditSink` instance in the process.
      Multiple instances therefore cannot interleave their output.
    * No ANSI formatting, no pretty-printing, no extra timestamps.
    * No signing or chain verification -- use :class:`FileAuditSink` when
      cryptographic integrity is required.

    The JSON schema matches :class:`AuditEntry` (Pydantic ``model_dump``
    with ``mode="json"``), which includes the optional execution-context
    fields (``sandbox_id``, ``environment``, ``compute_driver``) when
    present.

    Args:
        stream: Output stream. Defaults to ``sys.stdout``.
        include_context: Whether to include sandbox context fields
            (sandbox_id, environment, compute_driver) in the output.
            Defaults to ``True``.

    Example::

        sink = StdoutAuditSink()
        log = AuditLog(sink=sink)
        log.log(event_type="tool_invocation", agent_did="did:web:a1", action="read")
    """

    # Class-level lock -- shared across all instances so that concurrent
    # writes from separate StdoutAuditSink objects cannot interleave on
    # the process-global sys.stdout.
    _stdout_lock: threading.Lock = threading.Lock()

    def __init__(
        self,
        stream: Any = None,
        *,
        include_context: bool = True,
    ) -> None:
        self._stream = stream  # None means use sys.stdout at write time
        self._include_context = include_context
        self._closed = False

    def write(self, entry: AuditEntry) -> None:
        """Serialise *entry* to JSONL and write it to the output stream.

        The output stream is flushed immediately after the write so that
        container log drivers observe the line without buffering delay.
        """
        if self._closed:
            return
        line = self._serialize_entry(entry)
        with self._stdout_lock:
            out = self._stream if self._stream is not None else sys.stdout
            out.write(line + "\n")
            out.flush()

    def write_batch(self, entries: list[AuditEntry]) -> None:
        """Serialise all entries and write them under a single lock.

        All lines are serialised before the lock is acquired, then
        written in a single call so the batch is as atomic as possible,
        followed by one flush.
        """
        if not entries or self._closed:
            return
        block = "".join(self._serialize_entry(e) + "\n" for e in entries)
        with self._stdout_lock:
            out = self._stream if self._stream is not None else sys.stdout
            out.write(block)
            out.flush()

    def verify_integrity(self) -> tuple[bool, str | None]:
        """Stdout is a streaming sink; integrity verification is not supported.

        Returns (True, None) since stdout is write-only.
        """
        return True, None

    def close(self) -> None:
        """Flush the output stream. Does NOT close the underlying stream."""
        self._closed = True
        with self._stdout_lock:
            out = self._stream if self._stream is not None else sys.stdout
            out.flush()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _serialize_entry(self, entry: AuditEntry) -> str:
        """Return a compact, sorted JSON string for *entry*.

        When include_context is True, uses Pydantic model_dump for full
        fidelity. When False, manually constructs the dict excluding
        sandbox context fields.
        """
        if self._include_context:
            return json.dumps(
                entry.model_dump(mode="json", exclude_none=True),
                sort_keys=True,
                ensure_ascii=False,
            )
        # Exclude context fields when include_context=False
        data: dict[str, Any] = {
            "entry_id": entry.entry_id,
            "timestamp": entry.timestamp.isoformat().replace("+00:00", "Z"),
            "event_type": entry.event_type,
            "agent_did": entry.agent_did,
            "action": entry.action,
            "outcome": entry.outcome,
        }
        if entry.resource is not None:
            data["resource"] = entry.resource
        if entry.target_did is not None:
            data["target_did"] = entry.target_did
        if entry.data:
            data["data"] = entry.data
        if entry.policy_decision is not None:
            data["policy_decision"] = entry.policy_decision
        if entry.matched_rule is not None:
            data["matched_rule"] = entry.matched_rule
        if entry.trace_id is not None:
            data["trace_id"] = entry.trace_id
        if entry.session_id is not None:
            data["session_id"] = entry.session_id
        return json.dumps(data, sort_keys=True, default=str)

    @staticmethod
    def _serialise(entry: AuditEntry) -> str:
        """Return a compact, sorted JSON string (legacy static helper).

        Uses Pydantic model_dump with exclude_none=True for full fidelity
        serialisation including all context fields.
        """
        return json.dumps(entry.model_dump(mode="json", exclude_none=True), sort_keys=True, ensure_ascii=False)
