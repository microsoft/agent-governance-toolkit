# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.core.execution_agent import ExecutionAgent  # noqa: E402
from src.core.handshake_protocol import (  # noqa: E402
    ALLOW_ANY,
    CONFIRMATION_REQUIRED_KEY,
    CONFIRMATION_SATISFIED_KEY,
    ActionProposal,
    HandshakeProtocol,
    HandshakeState,
    ValidationResult,
)
from src.listener.adapters import (  # noqa: E402
    caas_adapter,
    control_plane_adapter,
    iatp_adapter,
    scak_adapter,
)
from src.listener.adapters.caas_adapter import ContextAdapter  # noqa: E402
from src.listener.adapters.control_plane_adapter import ControlPlaneAdapter  # noqa: E402
from src.listener.adapters.iatp_adapter import PermissionCheck, SecurityAdapter  # noqa: E402
from src.listener.adapters.scak_adapter import IntelligenceAdapter  # noqa: E402
from src.listener.listener import ListenerAgent  # noqa: E402
from src.listener.threshold_config import (  # noqa: E402
    InterventionLevel,
    ThresholdRule,
    ThresholdType,
)


def _make_protocol(allowed_confirmers=ALLOW_ANY):
    """Build a protocol. Tests opt into permissive confirmer policy by default
    so that the existing handshake-flow coverage isn't tangled with the
    confirmer ACL surface; ACL-specific tests pass their own argument."""
    return HandshakeProtocol(allowed_confirmers=allowed_confirmers)


def _validated_session(protocol: HandshakeProtocol):
    session = protocol.initiate_handshake(
        ActionProposal(
            action_id="restart_service",
            parameters={"service": "payments"},
            context={"user": "operator"},
            justification="operator requested restart",
        )
    )
    protocol.validate_proposal(session.session_id, ValidationResult(is_valid=True))
    return session


# ---------------------------------------------------------------------
# Adapter fail-closed (regression for earlier hardening)
# ---------------------------------------------------------------------
def test_iatp_adapter_non_mock_mode_fails_closed_when_backend_missing(monkeypatch):
    def missing_backend(_name):
        raise ImportError("iatp unavailable")

    monkeypatch.setattr(iatp_adapter, "import_module", missing_backend)

    adapter = SecurityAdapter()

    assert adapter.connect() is False
    assert adapter.is_connected is False
    with pytest.raises(ConnectionError, match=r"Failed to connect to iatp"):
        adapter.check_permission("user-1", "delete")


def test_iatp_adapter_mock_mode_requires_explicit_opt_in():
    adapter = SecurityAdapter(mock_mode=True)

    assert adapter.connect() is True
    check = adapter.check_permission("user-1", "read")
    assert check == PermissionCheck(
        allowed=True,
        actor_id="user-1",
        permission="read",
        reason="Mock: all permissions allowed",
        escalation_detected=False,
    )


# ---------------------------------------------------------------------
# Confirmation gate
# ---------------------------------------------------------------------
def test_confirmation_required_session_cannot_be_accepted_until_confirmed():
    protocol = _make_protocol()
    session = _validated_session(protocol)
    protocol.mark_confirmation_required(session.session_id, reason="soft block")

    with pytest.raises(ValueError, match="until confirmation is satisfied"):
        protocol.accept_proposal(session.session_id)

    assert session.state == HandshakeState.VALIDATED

    protocol.confirm_session(session.session_id, confirmed_by="operator")
    accepted = protocol.accept_proposal(session.session_id)

    assert accepted.state == HandshakeState.ACCEPTED
    assert accepted.metadata[CONFIRMATION_SATISFIED_KEY] is True
    assert accepted.metadata["confirmed_by"] == "operator"


def test_listener_soft_block_resets_confirmation_and_blocks_execution():
    protocol = _make_protocol()
    session = _validated_session(protocol)
    protocol.accept_proposal(session.session_id)
    assert session.state == HandshakeState.ACCEPTED

    listener = ListenerAgent.__new__(ListenerAgent)
    listener.protocol = protocol
    rule = ThresholdRule(
        threshold_type=ThresholdType.ANOMALY_SCORE_MAXIMUM,
        value=0.7,
        intervention_level=InterventionLevel.SOFT_BLOCK,
        description="anomaly detected",
    )
    outcome = listener._execute_intervention_action(
        "require_confirmation",
        InterventionLevel.SOFT_BLOCK,
        [rule],
    )

    execution = ExecutionAgent(protocol)

    assert outcome == "Soft block applied to 1 pending sessions"
    assert session.metadata[CONFIRMATION_REQUIRED_KEY] is True
    assert session.metadata[CONFIRMATION_SATISFIED_KEY] is False
    assert execution.can_execute(session.session_id) is False
    with pytest.raises(ValueError, match="Cannot complete execution"):
        protocol.complete_execution(session.session_id, {"status": "bypassed"})
    with pytest.raises(ValueError, match="confirmation is satisfied"):
        execution.execute(session.session_id)
    assert session.state == HandshakeState.ACCEPTED

    protocol.confirm_session(session.session_id, confirmed_by="operator")
    assert execution.can_execute(session.session_id) is True
    completed = execution.execute(session.session_id)
    assert completed.state == HandshakeState.COMPLETED


# ---------------------------------------------------------------------
# Layer adapters: missing backend
# ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "module, adapter_cls, layer_name",
    [
        (scak_adapter, IntelligenceAdapter, "scak"),
        (caas_adapter, ContextAdapter, "caas"),
        (control_plane_adapter, ControlPlaneAdapter, "agent-control-plane"),
    ],
)
def test_layer_adapters_fail_closed_when_backend_missing(module, adapter_cls, layer_name, monkeypatch):
    def missing_backend(_name):
        raise ImportError(f"{layer_name} unavailable")

    monkeypatch.setattr(module, "import_module", missing_backend)

    adapter = adapter_cls()

    assert adapter.connect() is False
    assert adapter.is_connected is False
    status = adapter.health_check()
    assert status.connected is False
    # Parens here matter: pre-existing precedence bug fixed.
    assert status.error and (
        layer_name in status.error.lower()
        or "backendunavailable" in status.error.lower()
    )


# ---------------------------------------------------------------------
# Terminal-state guards
# ---------------------------------------------------------------------
def test_handshake_cannot_revalidate_rejected_session():
    protocol = _make_protocol()
    session = protocol.initiate_handshake(
        ActionProposal(
            action_id="restart_service",
            parameters={"service": "payments"},
            context={"user": "operator"},
            justification="op",
        )
    )
    protocol.validate_proposal(
        session.session_id, ValidationResult(is_valid=False, errors=["bad"])
    )
    assert session.state == HandshakeState.REJECTED

    with pytest.raises(ValueError, match="Cannot validate proposal in state"):
        protocol.validate_proposal(session.session_id, ValidationResult(is_valid=True))
    assert session.state == HandshakeState.REJECTED


def test_handshake_terminal_state_guards_block_reject_and_fail():
    protocol = _make_protocol()
    session = _validated_session(protocol)
    protocol.accept_proposal(session.session_id)
    protocol.start_execution(session.session_id)
    protocol.complete_execution(session.session_id, {"status": "ok"})

    with pytest.raises(ValueError, match="terminal state"):
        protocol.reject_proposal(session.session_id, "too late")
    with pytest.raises(ValueError, match="terminal state"):
        protocol.fail_execution(session.session_id, "too late")
    assert session.state == HandshakeState.COMPLETED


@pytest.mark.parametrize("alias_key", ["confirmation_required", "requires_confirmation"])
def test_confirmation_gate_accepts_both_metadata_aliases(alias_key):
    protocol = _make_protocol()
    session = _validated_session(protocol)
    session.metadata[alias_key] = True

    with pytest.raises(ValueError, match="until confirmation is satisfied"):
        protocol.accept_proposal(session.session_id)
    assert session.state == HandshakeState.VALIDATED


def test_confirm_session_refused_in_terminal_state():
    protocol = _make_protocol()
    session = _validated_session(protocol)
    protocol.mark_confirmation_required(session.session_id)
    protocol.reject_proposal(session.session_id, "blocked")

    with pytest.raises(ValueError, match="terminal state"):
        protocol.confirm_session(session.session_id, confirmed_by="operator")
    assert session.metadata[CONFIRMATION_SATISFIED_KEY] is False


# ---------------------------------------------------------------------
# Adapter base_adapter logging
# ---------------------------------------------------------------------
def test_health_check_failure_records_last_error_and_persists():
    from src.listener.adapters import iatp_adapter as iatp_mod
    from src.listener.adapters.iatp_adapter import SecurityAdapter

    class FlakyClient:
        def ping(self):
            raise RuntimeError("backend ping timeout")

    # client_factory now requires mock_mode=True (post-init lockdown).
    adapter = SecurityAdapter(
        mock_mode=True,
        config={"client_factory": lambda _cfg: FlakyClient()},
    )
    assert adapter.connect() is True
    monkeypatched_ping = lambda self: self._client.ping()  # noqa: E731
    iatp_mod.SecurityAdapter._health_ping = monkeypatched_ping
    try:
        status = adapter.health_check()
        assert status.connected is False
        # H4: error string surfaces type name and adapter-controlled hint,
        # NEVER the raw driver exception text.
        assert "RuntimeError" in (status.error or "")
        assert "backend ping timeout" not in (status.error or "")
        assert adapter._last_error and "RuntimeError" in adapter._last_error
        assert "backend ping timeout" not in adapter._last_error
    finally:
        del iatp_mod.SecurityAdapter._health_ping


def test_confirm_session_requires_non_empty_confirmed_by():
    protocol = _make_protocol()
    session = _validated_session(protocol)
    protocol.mark_confirmation_required(session.session_id)

    with pytest.raises(ValueError, match="non-empty string"):
        protocol.confirm_session(session.session_id, confirmed_by="")
    with pytest.raises(ValueError, match="non-empty string"):
        protocol.confirm_session(session.session_id, confirmed_by="   ")
    assert session.metadata.get(CONFIRMATION_SATISFIED_KEY) is not True


def test_confirm_session_enforces_allowlist_when_configured():
    protocol = HandshakeProtocol(allowed_confirmers=["operator", "oncall"])
    session = _validated_session(protocol)
    protocol.mark_confirmation_required(session.session_id)

    with pytest.raises(ValueError, match="not in the allowed confirmers"):
        protocol.confirm_session(session.session_id, confirmed_by="stranger")
    assert session.metadata.get(CONFIRMATION_SATISFIED_KEY) is not True

    confirmed = protocol.confirm_session(session.session_id, confirmed_by="oncall")
    assert confirmed.metadata[CONFIRMATION_SATISFIED_KEY] is True
    assert confirmed.metadata["confirmed_by"] == "oncall"


def test_confirm_session_accepts_any_principal_with_allow_any_sentinel():
    protocol = HandshakeProtocol(allowed_confirmers=ALLOW_ANY)
    session = _validated_session(protocol)
    protocol.mark_confirmation_required(session.session_id)

    confirmed = protocol.confirm_session(session.session_id, confirmed_by="any-operator")
    assert confirmed.metadata[CONFIRMATION_SATISFIED_KEY] is True
    assert confirmed.metadata["confirmed_by"] == "any-operator"


def test_connect_logs_and_records_unexpected_exception(caplog):
    import logging
    from src.listener.adapters import base_adapter as base_mod

    class ExplodingAdapter(base_mod.BaseLayerAdapter):
        def get_layer_name(self) -> str:
            return "exploding"

        def _create_client(self):
            raise RuntimeError("driver kaboom: api-key=SUPER-SECRET")

        def _mock_client(self):
            return object()

    adapter = ExplodingAdapter()
    with caplog.at_level(logging.ERROR, logger=base_mod.__name__):
        result = adapter.connect()
    assert result is False
    # H4: never include str(e) in adapter-surfaced error text. Driver
    # secrets such as the api-key above must not leak into _last_error.
    assert "RuntimeError" in (adapter._last_error or "")
    assert "SUPER-SECRET" not in (adapter._last_error or "")
    assert "driver kaboom" not in (adapter._last_error or "")
    assert any(
        "exploding" in rec.message and rec.exc_info is not None
        for rec in caplog.records
    )


def test_disconnect_logs_and_records_close_failure(caplog):
    import logging
    from src.listener.adapters import base_adapter as base_mod

    class FlakyCloseClient:
        def close(self):
            raise OSError("socket gone: token=ABC123")

    class FlakyAdapter(base_mod.BaseLayerAdapter):
        def get_layer_name(self) -> str:
            return "flaky"

        def _create_client(self):
            return FlakyCloseClient()

        def _mock_client(self):
            return FlakyCloseClient()

    adapter = FlakyAdapter()
    assert adapter.connect() is True
    with caplog.at_level(logging.ERROR, logger=base_mod.__name__):
        adapter.disconnect()
    assert "OSError" in (adapter._last_error or "")
    assert "ABC123" not in (adapter._last_error or "")
    assert any(
        "flaky" in rec.message and rec.exc_info is not None
        for rec in caplog.records
    )
    assert adapter._connected is False


def test_connect_records_expected_backend_unavailable_exception():
    from src.listener.adapters import iatp_adapter as iatp_mod

    adapter = iatp_mod.SecurityAdapter()
    result = adapter.connect()
    assert result is False
    assert adapter._last_error is not None
    assert "BackendUnavailable" in adapter._last_error


def test_listener_intervention_counter_safe_under_concurrency():
    """Spawn many threads incrementing the counter via _perform_intervention's
    locked critical section. The final total must equal the number of attempts.
    """
    import threading
    from collections import deque
    from datetime import datetime
    from src.listener.listener import ListenerAgent

    listener = ListenerAgent.__new__(ListenerAgent)
    listener._counter_lock = threading.Lock()
    listener._intervention_count_this_minute = 0
    listener._event_counter = 0
    listener._minute_start = datetime.now()
    listener._interventions = deque(maxlen=100000)

    threads_n = 16
    per_thread = 500

    def worker():
        for _ in range(per_thread):
            with listener._counter_lock:
                listener._event_counter += 1
                listener._intervention_count_this_minute += 1
                listener._interventions.append(listener._event_counter)

    threads = [threading.Thread(target=worker) for _ in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    expected = threads_n * per_thread
    assert listener._event_counter == expected
    assert listener._intervention_count_this_minute == expected
    assert len(listener._interventions) == expected
    assert len(set(listener._interventions)) == expected


# =====================================================================
# Red-team regression tests
# =====================================================================
def test_C1_metadata_write_cannot_bypass_confirmation_gate():
    """C1 / 🚨: Writing CONFIRMATION_SATISFIED_KEY=True to session.metadata
    must NOT make is_confirmation_satisfied() return True. The truth source
    is the protocol's audited _confirmations table.
    """
    protocol = _make_protocol()
    session = _validated_session(protocol)
    protocol.mark_confirmation_required(session.session_id)

    # Attacker writes the metadata key.
    session.metadata[CONFIRMATION_SATISFIED_KEY] = True

    # Gate still blocks: not in _confirmations.
    assert protocol.is_confirmation_satisfied(session) is False
    with pytest.raises(ValueError, match="until confirmation is satisfied"):
        protocol.accept_proposal(session.session_id)


def test_H1_state_attribute_is_read_only_externally():
    """H1 / ⚠️: session.state has no setter; external mutation raises.
    Internal protocol state transitions still work via the private _state.
    """
    protocol = _make_protocol()
    session = _validated_session(protocol)
    assert session.state == HandshakeState.VALIDATED

    # Attacker attempts to roll back to VALIDATED after rejection.
    protocol.reject_proposal(session.session_id, "denied")
    assert session.state == HandshakeState.REJECTED

    with pytest.raises(AttributeError):
        session.state = HandshakeState.VALIDATED  # type: ignore[misc]


def test_H6_default_allowed_confirmers_is_fail_closed():
    """H6 / ⚠️: HandshakeProtocol() with no allowlist arg refuses ALL
    confirmations. Callers must explicitly opt into ALLOW_ANY or pass a
    real allowlist.
    """
    protocol = HandshakeProtocol()  # default: fail-closed
    session = _validated_session(protocol)
    protocol.mark_confirmation_required(session.session_id)

    with pytest.raises(ValueError, match="not in the allowed confirmers"):
        protocol.confirm_session(session.session_id, confirmed_by="operator")


def test_L1_allowlist_entries_are_normalized_on_insert():
    """L1 / ℹ️: Allowlist entries are stripped of whitespace and control
    chars on insert so that an entry of " admin\\n" matches input "admin".
    """
    protocol = HandshakeProtocol(allowed_confirmers=[" admin\n", "\tops "])
    session = _validated_session(protocol)
    protocol.mark_confirmation_required(session.session_id)

    confirmed = protocol.confirm_session(session.session_id, confirmed_by="admin")
    assert confirmed.metadata["confirmed_by"] == "admin"


def test_L2_confirmed_by_is_sanitized_and_length_capped():
    """L2 / ℹ️: confirmed_by is stripped of CR/LF/ANSI control chars and
    length-capped so it can't be used for log/UI injection or audit DoS.
    """
    protocol = HandshakeProtocol(allowed_confirmers=ALLOW_ANY)
    session = _validated_session(protocol)
    protocol.mark_confirmation_required(session.session_id)

    # CRLF + ANSI escape injection attempt.
    confirmed = protocol.confirm_session(
        session.session_id,
        confirmed_by="alice\r\n\x1b[31madmin\x1b[0m",
    )
    stored = confirmed.metadata["confirmed_by"]
    assert "\r" not in stored
    assert "\n" not in stored
    assert "\x1b" not in stored
    assert stored.startswith("alice")

    # Length cap.
    session2 = _validated_session(protocol)
    protocol.mark_confirmation_required(session2.session_id)
    huge = "x" * 10_000
    confirmed2 = protocol.confirm_session(session2.session_id, confirmed_by=huge)
    assert len(confirmed2.metadata["confirmed_by"]) <= 256


def test_C2_listener_emergency_halt_safe_against_concurrent_mutation():
    """C2 / 🚨: listener.emergency_halt iterates protocol sessions while
    other threads create/mutate sessions. Must not raise
    RuntimeError("dictionary changed size during iteration").
    """
    import threading

    protocol = _make_protocol()
    listener = ListenerAgent.__new__(ListenerAgent)
    listener.protocol = protocol
    listener._security_adapter = None

    # Pre-populate sessions.
    for _ in range(10):
        s = _validated_session(protocol)
        protocol.accept_proposal(s.session_id)

    stop = threading.Event()
    churn_iters = [0]

    def churn():
        while not stop.is_set():
            try:
                _validated_session(protocol)
            except Exception:
                pass
            churn_iters[0] += 1
            time.sleep(0)  # yield

    churners = [threading.Thread(target=churn) for _ in range(2)]
    for t in churners:
        t.start()
    try:
        # Just a few halts is plenty — the test exists to prove the
        # snapshot iteration doesn't raise RuntimeError("dictionary
        # changed size during iteration") under concurrent mutation.
        for _ in range(3):
            listener._execute_intervention_action(
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
    finally:
        stop.set()
        for t in churners:
            t.join(timeout=2.0)
    assert churn_iters[0] > 0  # churners actually ran concurrently


def test_H5_emergency_alert_failure_is_logged_and_reported(caplog):
    """H5 / ⚠️: When the security adapter's emergency_alert raises, the
    listener logs at ERROR with stack trace AND the outcome string
    surfaces the delivery failure so callers don't silently miss it.
    """
    import logging

    protocol = _make_protocol()
    _validated_session(protocol)  # something to halt

    class ExplodingSecurityAdapter:
        def emergency_alert(self, **kwargs):
            raise RuntimeError("oncall pager down")

    listener = ListenerAgent.__new__(ListenerAgent)
    listener.protocol = protocol
    listener._security_adapter = ExplodingSecurityAdapter()

    with caplog.at_level(logging.ERROR):
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
    assert "alert=failed" in outcome
    assert any(
        "emergency_alert failed to deliver" in rec.message
        for rec in caplog.records
    )


def test_H5_emergency_alert_delivered_reports_delivered():
    """H5 happy path: outcome surfaces alert=delivered when the security
    adapter accepted the alert.
    """
    protocol = _make_protocol()

    class GoodAdapter:
        def __init__(self):
            self.calls = 0

        def emergency_alert(self, **kwargs):
            self.calls += 1

    adapter = GoodAdapter()
    listener = ListenerAgent.__new__(ListenerAgent)
    listener.protocol = protocol
    listener._security_adapter = adapter

    outcome = listener._execute_intervention_action(
        "emergency_halt",
        InterventionLevel.EMERGENCY,
        [],
    )
    assert "alert=delivered" in outcome
    assert adapter.calls == 1


def test_H2_client_factory_requires_mock_mode_opt_in():
    """H2 / ⚠️: A config-supplied client_factory hook is a test-only
    seam. It must NOT be honored unless mock_mode=True was set at
    construction time.
    """
    sentinel_calls = []

    def factory(_cfg):
        sentinel_calls.append(_cfg)
        return object()

    adapter = SecurityAdapter(config={"client_factory": factory})
    # mock_mode defaults to False => factory must be ignored, real
    # backend resolution path must run (and fail closed because no
    # backend installed).
    assert adapter.connect() is False
    assert sentinel_calls == []
    assert "BackendUnavailable" in (adapter._last_error or "")

    # With explicit mock_mode=True the factory is allowed.
    adapter2 = SecurityAdapter(mock_mode=True, config={"client_factory": factory})
    assert adapter2.connect() is True
    assert len(sentinel_calls) == 1


def test_H3_mock_mode_is_frozen_post_construction():
    """H3 / ⚠️: mock_mode cannot be re-enabled at runtime via attribute
    mutation. The post-init __setattr__ guard rejects the write.
    """
    adapter = SecurityAdapter()
    assert adapter.mock_mode is False

    with pytest.raises(AttributeError, match="mock_mode is immutable"):
        adapter.mock_mode = True

    # Backing slot is also rejected.
    with pytest.raises(AttributeError, match="mock_mode is immutable"):
        adapter._mock_mode = True


def test_M1_connect_returns_false_when_create_client_returns_none():
    """M1 / ⚠️: If _create_client() returns None (subtle subclass bug or
    misconfigured upstream), connect() must report failure rather than
    flipping is_connected=True with self._client=None.
    """
    from src.listener.adapters import base_adapter as base_mod

    class NoneClientAdapter(base_mod.BaseLayerAdapter):
        def get_layer_name(self) -> str:
            return "none-client"

        def _create_client(self):
            return None

        def _mock_client(self):
            return None

    adapter = NoneClientAdapter()
    assert adapter.connect() is False
    assert adapter.is_connected is False
    assert adapter._last_error is not None
    assert "None" in adapter._last_error or "client" in adapter._last_error.lower()
