# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Red-team regression tests for the ListenerAgent intervention paths.

Findings covered: C2 (concurrent-mutation crash), H5 (silent alert
delivery failure).

Each test asserts the secure post-hardening behavior. On the pre-fix
tree (commit 14ebaecc — after the handshake refactor but before the
listener fix) both tests fail for the documented reason.
"""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.handshake_protocol import (  # noqa: E402
    ActionProposal,
    HandshakeProtocol,
    ValidationResult,
)
from src.listener.listener import ListenerAgent  # noqa: E402
from src.listener.threshold_config import (  # noqa: E402
    InterventionLevel,
    ThresholdRule,
    ThresholdType,
)

try:  # post-fix only
    from src.core.handshake_protocol import ALLOW_ANY  # noqa: E402
except ImportError:  # pragma: no cover
    ALLOW_ANY = None


def _validated_session(protocol):
    proposal = ActionProposal(
        action_id="act",
        parameters={},
        context={},
        justification="j",
    )
    s = protocol.initiate_handshake(proposal)
    protocol.validate_proposal(s.session_id, ValidationResult(is_valid=True))
    return s


def _bare_listener(protocol, security_adapter=None):
    listener = ListenerAgent.__new__(ListenerAgent)
    listener.protocol = protocol
    listener._security_adapter = security_adapter
    return listener


# --- C2: dictionary-changed-during-iteration -----------------------------

def test_C2_emergency_halt_safe_under_concurrent_session_creation():
    """C2: listener._execute_intervention_action('require_confirmation', ...)
    iterates ``self.protocol.sessions`` while other threads call
    ``protocol.initiate_handshake`` concurrently.

    Pre-fix: the iteration is over the live dict (``self.protocol.sessions.items()``).
    Concurrent insertion raises ``RuntimeError: dictionary changed size during iteration``.
    Post-fix: snapshot_sessions() returns a lock-protected copy and
    no RuntimeError can surface.

    Stress: 8 churners + 50 listener iterations + 100 pre-populated
    sessions — enough race surface that pre-fix code reliably trips
    within the test budget.
    """
    protocol = HandshakeProtocol(allowed_confirmers=ALLOW_ANY)
    listener = _bare_listener(protocol)
    # Pre-populate so each iteration has plenty of work.
    for _ in range(100):
        s = _validated_session(protocol)
        protocol.accept_proposal(s.session_id)

    stop = threading.Event()
    errors = []

    def churn():
        while not stop.is_set():
            try:
                # Just bump the dict — full validation isn't needed to
                # mutate protocol.sessions.
                proposal = ActionProposal(
                    action_id="c",
                    parameters={},
                    context={},
                    justification="c",
                )
                protocol.initiate_handshake(proposal)
            except RuntimeError as e:  # noqa: BLE001
                errors.append(("churn", e))
            except Exception:  # noqa: BLE001
                pass

    churners = [threading.Thread(target=churn) for _ in range(8)]
    for t in churners:
        t.start()
    try:
        for _ in range(50):
            try:
                listener._execute_intervention_action(
                    "require_confirmation",
                    InterventionLevel.HARD_BLOCK,
                    [
                        ThresholdRule(
                            threshold_type=ThresholdType.ANOMALY_SCORE_MAXIMUM,
                            value=0.8,
                            intervention_level=InterventionLevel.HARD_BLOCK,
                            description="boom",
                        )
                    ],
                )
            except RuntimeError as e:  # noqa: BLE001
                errors.append(("listener", e))
    finally:
        stop.set()
        for t in churners:
            t.join(timeout=2.0)

    assert not errors, f"Concurrent mutation raised RuntimeError(s): {errors!r}"


# --- H5: silent alert-delivery failure -----------------------------------

def test_H5_emergency_alert_delivery_failure_is_surfaced():
    """H5: when the wired security adapter's emergency_alert raises,
    the listener must not silently swallow the failure.

    Pre-fix: ``except Exception: pass`` — outcome string only reports
    'Emergency halt: N sessions terminated', no alert status.
    Post-fix: logger.exception(...) at ERROR and outcome string carries
    'alert=failed' so callers cannot miss a failed side-channel.
    """
    protocol = HandshakeProtocol(allowed_confirmers=ALLOW_ANY)
    s = _validated_session(protocol)
    protocol.accept_proposal(s.session_id)

    class ExplodingSecurityAdapter:
        def emergency_alert(self, **_kwargs):
            raise RuntimeError("alerting backend down")

    listener = _bare_listener(protocol, security_adapter=ExplodingSecurityAdapter())
    outcome = listener._execute_intervention_action(
        "emergency_halt",
        InterventionLevel.EMERGENCY,
        [
            ThresholdRule(
                threshold_type=ThresholdType.ANOMALY_SCORE_MAXIMUM,
                value=0.99,
                intervention_level=InterventionLevel.EMERGENCY,
                description="boom",
            )
        ],
    )
    # The outcome must surface the alert delivery failure.
    assert "fail" in outcome.lower(), (
        f"emergency_alert failure was silently swallowed; outcome={outcome!r}"
    )
