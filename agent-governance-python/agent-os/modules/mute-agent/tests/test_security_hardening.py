# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.core.execution_agent import ExecutionAgent  # noqa: E402
from src.core.handshake_protocol import (  # noqa: E402
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


def test_iatp_adapter_non_mock_mode_fails_closed_when_backend_missing(monkeypatch):
    def missing_backend(_name):
        raise ImportError("iatp unavailable")

    monkeypatch.setattr(iatp_adapter, "import_module", missing_backend)

    adapter = SecurityAdapter()

    assert adapter.connect() is False
    assert adapter.is_connected is False
    with pytest.raises(ConnectionError, match=r"Failed to connect to iatp:.*SecurityBackendUnavailable"):
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


def test_confirmation_required_session_cannot_be_accepted_until_confirmed():
    protocol = HandshakeProtocol()
    session = _validated_session(protocol)
    session.metadata[CONFIRMATION_REQUIRED_KEY] = True
    session.metadata["confirmation_reason"] = "soft block"

    with pytest.raises(ValueError, match="until confirmation is satisfied"):
        protocol.accept_proposal(session.session_id)

    assert session.state == HandshakeState.VALIDATED

    protocol.confirm_session(session.session_id, confirmed_by="operator")
    accepted = protocol.accept_proposal(session.session_id)

    assert accepted.state == HandshakeState.ACCEPTED
    assert accepted.metadata[CONFIRMATION_SATISFIED_KEY] is True
    assert accepted.metadata["confirmed_by"] == "operator"


def test_listener_soft_block_resets_confirmation_and_blocks_execution():
    protocol = HandshakeProtocol()
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
    assert status.error and layer_name in status.error.lower() or "backendunavailable" in (status.error or "").lower()


def test_handshake_cannot_revalidate_rejected_session():
    protocol = HandshakeProtocol()
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
    protocol = HandshakeProtocol()
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
    protocol = HandshakeProtocol()
    session = _validated_session(protocol)
    session.metadata[alias_key] = True

    with pytest.raises(ValueError, match="until confirmation is satisfied"):
        protocol.accept_proposal(session.session_id)
    assert session.state == HandshakeState.VALIDATED
