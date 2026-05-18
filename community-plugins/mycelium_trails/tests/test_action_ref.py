"""Tests for action_ref derivation (JCS + SHA-256)."""

import hashlib
import json

import pytest

from mycelium_trails.action_ref import compute_action_ref, format_timestamp
import datetime


# Known-good vector: JCS of the 4-field payload, then SHA-256.
# JCS key order (lexicographic): action_type < agent_id < scope < timestamp
_VECTOR_FIELDS = {
    "agent_id": "test-agent",
    "action_type": "stripe:charge",
    "scope": "agt-evidence",
    "timestamp": "2026-05-15T10:00:00.123Z",
}
# JCS canonical form (keys sorted, no spaces):
_VECTOR_JCS = '{"action_type":"stripe:charge","agent_id":"test-agent","scope":"agt-evidence","timestamp":"2026-05-15T10:00:00.123Z"}'
_VECTOR_ACTION_REF = hashlib.sha256(_VECTOR_JCS.encode("utf-8")).hexdigest()


def test_compute_action_ref_known_vector():
    result = compute_action_ref(
        agent_id=_VECTOR_FIELDS["agent_id"],
        action_type=_VECTOR_FIELDS["action_type"],
        scope=_VECTOR_FIELDS["scope"],
        timestamp=_VECTOR_FIELDS["timestamp"],
    )
    assert result == _VECTOR_ACTION_REF


def test_compute_action_ref_deterministic():
    a = compute_action_ref("agent-1", "file:write", "audit", "2026-05-15T00:00:00.000Z")
    b = compute_action_ref("agent-1", "file:write", "audit", "2026-05-15T00:00:00.000Z")
    assert a == b


def test_compute_action_ref_different_fields_produce_different_refs():
    ref1 = compute_action_ref("agent-1", "file:write", "audit", "2026-05-15T00:00:00.000Z")
    ref2 = compute_action_ref("agent-2", "file:write", "audit", "2026-05-15T00:00:00.000Z")
    assert ref1 != ref2


def test_compute_action_ref_output_is_64_hex_chars():
    ref = compute_action_ref("a", "b", "c", "2026-01-01T00:00:00.000Z")
    assert len(ref) == 64
    assert all(c in "0123456789abcdef" for c in ref)


def test_jcs_key_ordering():
    """Verify that our JCS encoding sorts keys lexicographically."""
    fields = {
        "agent_id": "x",
        "action_type": "y",
        "scope": "z",
        "timestamp": "t",
    }
    # lexicographic order: action_type, agent_id, scope, timestamp
    canonical = json.dumps(dict(sorted(fields.items())), separators=(",", ":"), ensure_ascii=False)
    assert canonical == '{"action_type":"y","agent_id":"x","scope":"z","timestamp":"t"}'


def test_format_timestamp_3digit_ms():
    dt = datetime.datetime(2026, 5, 15, 10, 0, 0, 123000)
    result = format_timestamp(dt)
    assert result == "2026-05-15T10:00:00.123Z"


def test_format_timestamp_zero_ms():
    dt = datetime.datetime(2026, 1, 1, 0, 0, 0, 0)
    result = format_timestamp(dt)
    assert result == "2026-01-01T00:00:00.000Z"


def test_format_timestamp_ends_with_Z():
    dt = datetime.datetime(2026, 5, 15, 12, 30, 45, 7000)
    result = format_timestamp(dt)
    assert result.endswith("Z")
    assert "." in result
    # ms part is always 3 digits
    ms_part = result.split(".")[1].rstrip("Z")
    assert len(ms_part) == 3
