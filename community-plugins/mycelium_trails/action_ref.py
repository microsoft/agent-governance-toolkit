"""
Canonical action_ref derivation: RFC 8785 JCS + SHA-256.

action_ref = SHA-256(JCS({
    "agent_id":    "<string>",
    "action_type": "<string>",
    "scope":       "<string>",
    "timestamp":   "<RFC 3339 UTC, 3-digit ms precision>"
}))

JCS (RFC 8785) for a dict with only string values is equivalent to
json.dumps with sorted keys, no spaces, and UTF-8 encoding. We implement
it inline to avoid adding an external dependency for this simple case.

timestamp format: "2026-05-15T10:00:00.123Z" (3-digit ms, mandatory Z).
"""

from __future__ import annotations

import datetime
import hashlib
import json


def _jcs_encode(d: dict[str, str]) -> bytes:
    """RFC 8785 JCS encoding for a flat dict of string values.

    Key ordering is lexicographic Unicode code point order, which for
    ASCII-only keys matches alphabetical order. Values are JSON strings
    with no Unicode escaping for codepoints above U+001F (RFC 8785 §3.2.3).
    """
    return json.dumps(
        dict(sorted(d.items())),
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def format_timestamp(dt: datetime.datetime) -> str:
    """Format a datetime as RFC 3339 UTC with 3-digit ms precision.

    Input must be UTC (tzinfo=timezone.utc or naive treated as UTC).
    Output: "2026-05-15T10:00:00.123Z"
    """
    ms = dt.microsecond // 1000
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z")


def compute_action_ref(
    agent_id: str,
    action_type: str,
    scope: str,
    timestamp: str,
) -> str:
    """Derive action_ref from the four canonical fields.

    timestamp must already be in RFC 3339 UTC format with 3-digit ms precision
    (e.g. "2026-05-15T10:00:00.123Z"). Use format_timestamp() to produce it
    from a datetime object.

    Returns the SHA-256 hex digest (64 lowercase hex characters).
    """
    payload = {
        "agent_id": agent_id,
        "action_type": action_type,
        "scope": scope,
        "timestamp": timestamp,
    }
    canonical = _jcs_encode(payload)
    return hashlib.sha256(canonical).hexdigest()
