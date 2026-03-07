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
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from .audit import AuditEntry


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
        self._secret_key = secret_key
        self._max_file_size = max_file_size
        self._lock = threading.Lock()
        self._previous_hash: str = ""
        self._closed = False

        # Resume chain if the file already has entries.
        if self._path.exists() and self._path.stat().st_size > 0:
            self._previous_hash = self._read_last_hash()

    # ------------------------------------------------------------------
    # AuditSink interface
    # ------------------------------------------------------------------

    def write(self, entry: AuditEntry) -> None:
        """Write a single entry, rotating the file if necessary."""
        with self._lock:
            self._maybe_rotate()
            signed = SignedAuditEntry.from_entry(
                entry,
                previous_hash=self._previous_hash,
                secret_key=self._secret_key,
            )
            self._append_line(signed)
            self._previous_hash = signed.content_hash

    def write_batch(self, entries: list[AuditEntry]) -> None:
        """Write a batch of entries atomically (under lock)."""
        with self._lock:
            for entry in entries:
                self._maybe_rotate()
                signed = SignedAuditEntry.from_entry(
                    entry,
                    previous_hash=self._previous_hash,
                    secret_key=self._secret_key,
                )
                self._append_line(signed)
                self._previous_hash = signed.content_hash

    def verify_integrity(self) -> tuple[bool, str | None]:
        """Read back the file and verify hash chain + HMAC signatures."""
        verifier = HashChainVerifier()
        is_valid, errors = verifier.verify_file(self._path, self._secret_key)
        if is_valid:
            return True, None
        return False, "; ".join(errors)

    def close(self) -> None:
        """Mark the sink as closed."""
        self._closed = True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _append_line(self, signed: SignedAuditEntry) -> None:
        """Append a single JSON line to the file."""
        line = json.dumps(signed.to_dict(), sort_keys=True, default=str)
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def _maybe_rotate(self) -> None:
        """Rotate the file if it exceeds *max_file_size*."""
        if self._max_file_size <= 0:
            return
        if not self._path.exists():
            return
        if self._path.stat().st_size >= self._max_file_size:
            rotated = self._path.with_suffix(
                f".{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.jsonl"
            )
            os.replace(self._path, rotated)
            # Reset chain for the new file
            self._previous_hash = ""

    def _read_last_hash(self) -> str:
        """Read the content_hash of the last entry in the file."""
        last_line = ""
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
        if not last_line:
            return ""
        data = json.loads(last_line)
        return data.get("content_hash", "")

    def read_entries(self) -> list[SignedAuditEntry]:
        """Read all signed entries from the file (for testing/querying)."""
        entries: list[SignedAuditEntry] = []
        if not self._path.exists():
            return entries
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    entries.append(SignedAuditEntry.model_validate_json(stripped))
        return entries


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

        entries: list[SignedAuditEntry] = []
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    entries.append(SignedAuditEntry.model_validate_json(stripped))
                except Exception as exc:
                    errors.append(f"Line {lineno}: parse error: {exc}")

        if errors:
            return False, errors

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
            if entry.content_hash != expected_hash:
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
