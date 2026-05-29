# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Red-team regression tests for the handshake protocol.

Each test exercises a specific bypass primitive enumerated in the
red-team review and asserts the *secure* post-hardening behavior.
When run against the pre-fix tree (commit 5997d781) every test in this
file fails for the documented reason. When run against the hardening
patch they pass.

Findings covered: C1, H1, H6, L1, L2.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.handshake_protocol import (  # noqa: E402
    ActionProposal,
    HandshakeProtocol,
    HandshakeState,
    ValidationResult,
)

try:  # post-fix: ALLOW_ANY sentinel; pre-fix: None is permissive
    from src.core.handshake_protocol import ALLOW_ANY  # noqa: E402
except ImportError:  # pragma: no cover - pre-fix branch
    ALLOW_ANY = None


def _validated_session(protocol, metadata=None):
    proposal = ActionProposal(
        action_id="act_redteam",
        parameters={},
        context={},
        justification="redteam",
    )
    session = protocol.initiate_handshake(proposal)
    if metadata:
        session.metadata.update(metadata)
    protocol.validate_proposal(
        session.session_id,
        ValidationResult(is_valid=True),
    )
    return session


# --- C1: confirmation-gate bypass via direct metadata write -------------

def test_C1_metadata_satisfied_flag_cannot_bypass_confirmation_gate():
    """C1: caller marks a confirmation-required session as satisfied by
    writing to ``session.metadata`` directly and then accepting.

    Pre-fix: ``is_confirmation_satisfied`` reads the metadata flag, so
    accept_proposal returns successfully.
    Post-fix: the truth source is an audited ConfirmationRecord written
    only by ``confirm_session``; raw metadata is ignored for the gate.
    """
    protocol = HandshakeProtocol()
    session = _validated_session(
        protocol,
        metadata={"confirmation_required": True},
    )

    # Attacker / buggy caller flips the satisfied flag without ever
    # going through confirm_session.
    session.metadata["confirmation_satisfied"] = True

    with pytest.raises(ValueError, match="confirmation"):
        protocol.accept_proposal(session.session_id)


# --- H1: state rollback via direct attribute write ----------------------

def test_H1_state_cannot_be_rolled_back_via_attribute_write():
    """H1: state must not be mutable from outside the protocol.

    Pre-fix: HandshakeSession.state is a plain dataclass field — an
    in-process attacker can roll an ACCEPTED session back to VALIDATED
    (or forward to ACCEPTED) bypassing transition checks.
    Post-fix: state is a read-only property; direct assignment raises
    AttributeError.
    """
    protocol = HandshakeProtocol()
    session = _validated_session(protocol)
    protocol.accept_proposal(session.session_id)
    assert session.state == HandshakeState.ACCEPTED

    with pytest.raises(AttributeError):
        session.state = HandshakeState.VALIDATED

    # The state must remain ACCEPTED — protocol invariant intact.
    assert session.state == HandshakeState.ACCEPTED


# --- H6: fail-closed default for allowed_confirmers ---------------------

def test_H6_default_allowed_confirmers_is_fail_closed():
    """H6: HandshakeProtocol() with no allowed_confirmers must reject all
    confirmation attempts.

    Pre-fix: allowed_confirmers=None means "no allowlist check" — any
    non-empty confirmer name is accepted (fail-open).
    Post-fix: None means "no confirmers allowed" — callers wanting the
    old behavior must pass the ALLOW_ANY sentinel.
    """
    protocol = HandshakeProtocol()
    session = _validated_session(
        protocol,
        metadata={"confirmation_required": True},
    )
    with pytest.raises(ValueError, match="not.*allowed|fail-closed|no confirmers"):
        protocol.confirm_session(session.session_id, confirmed_by="bob")


# --- L1: allowlist normalization on insert AND compare ------------------

def test_L1_allowlist_entries_are_normalized_on_insert_and_compare():
    """L1: allowlist entries with stray whitespace should still match
    sanitized confirmer values.

    Pre-fix: allowlist is frozenset(raw) — ' alice ' is stored verbatim
    and 'alice' is not in the set, so the operator is locked out.
    Post-fix: entries are .strip()'d on insert and incoming
    confirmed_by is .strip()'d on compare.
    """
    protocol = HandshakeProtocol(allowed_confirmers=[" alice ", "\tbob\n"])
    session = _validated_session(
        protocol,
        metadata={"confirmation_required": True},
    )
    # Should succeed even though the allowlist entry has whitespace.
    protocol.confirm_session(session.session_id, confirmed_by="alice")


# --- L2: confirmed_by sanitization (log/audit-trail injection) ----------

def test_L2_confirmed_by_is_sanitized_and_length_capped():
    """L2: stored confirmed_by must have CR/LF/ANSI escapes stripped and
    be length-capped before reaching the audit trail.

    Pre-fix: confirmed_by is only .strip()'d at the edges — embedded
    newlines, ANSI escapes, and arbitrarily long blobs land verbatim
    in session.metadata['confirmed_by'].
    Post-fix: control chars and ANSI sequences are stripped; length
    capped at 256 chars.
    """
    # ALLOW_ANY (post-fix) / None (pre-fix permissive) so we can focus
    # the assertion purely on output sanitization, not the allowlist.
    protocol = HandshakeProtocol(allowed_confirmers=ALLOW_ANY)
    session = _validated_session(
        protocol,
        metadata={"confirmation_required": True},
    )
    confirmed = protocol.confirm_session(
        session.session_id,
        confirmed_by="alice\n\rFAKE-LOG-LINE",
    )
    stored = confirmed.metadata["confirmed_by"]
    assert "\n" not in stored
    assert "\r" not in stored

    # Length cap — exact ceiling is an implementation detail but must
    # be bounded.
    huge_protocol = HandshakeProtocol(allowed_confirmers=ALLOW_ANY)
    session2 = _validated_session(
        huge_protocol,
        metadata={"confirmation_required": True},
    )
    confirmed2 = huge_protocol.confirm_session(
        session2.session_id, confirmed_by="x" * 1000
    )
    assert len(confirmed2.metadata["confirmed_by"]) <= 256
