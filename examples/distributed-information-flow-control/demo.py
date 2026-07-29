# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Proof slice for AgentMesh-native distributed IFC receipts."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
AGENT_MESH_SRC = REPO_ROOT / "agent-governance-python" / "agent-mesh" / "src"
sys.path.insert(0, str(AGENT_MESH_SRC))

from agentmesh.identity.agent_id import AgentIdentity  # noqa: E402
from agentmesh.transport.information_flow import (  # noqa: E402
    InformationFlowNonceCache,
    attach_information_flow_receipt,
    create_information_flow_receipt,
    extract_information_flow_receipt,
    verify_information_flow_receipt,
)


@dataclass(frozen=True)
class DemoEnvelope:
    envelope_id: str
    workflow_id: str
    aggregate_sensitivity: str
    integrity: str
    version: int


def main() -> None:
    sender = AgentIdentity.create(
        name="triage-agent",
        sponsor="triage@example.com",
        capabilities=["summarize", "delegate"],
    )
    receiver = AgentIdentity.create(
        name="response-agent",
        sponsor="response@example.com",
        capabilities=["respond"],
    )

    payload = {"task": "summarize", "text": "private untrusted support ticket"}
    envelope = DemoEnvelope(
        envelope_id="env-support-001",
        workflow_id="workflow-support-001",
        aggregate_sensitivity="confidential",
        integrity="untrusted",
        version=1,
    )
    receipt = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-001",
        envelope=envelope,
        payload=payload,
        nonce="nonce-001",
    )
    message = attach_information_flow_receipt(
        {"id": "message-001", "to": str(receiver.did), "payload": payload},
        receipt,
    )
    extracted = extract_information_flow_receipt(message)
    if extracted is None:
        raise RuntimeError("message is missing its information-flow receipt")

    nonce_cache = InformationFlowNonceCache()
    verified = verify_information_flow_receipt(
        extracted,
        sender,
        payload=payload,
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-001",
        nonce_cache=nonce_cache,
    )
    print(f"valid_receipt: {'allowed' if verified.allowed else 'denied'}")

    tampered = verify_information_flow_receipt(
        receipt,
        sender,
        payload={"task": "summarize", "text": "altered"},
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-001",
        nonce_cache=InformationFlowNonceCache(),
    )
    print(f"tampered_payload: {'allowed' if tampered.allowed else 'denied'}")

    child_payload = {"task": "respond", "text": "derived response"}
    downgraded = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-002",
        envelope=DemoEnvelope(
            envelope_id="env-support-001",
            workflow_id="workflow-support-001",
            aggregate_sensitivity="public",
            integrity="trusted",
            version=2,
        ),
        payload=child_payload,
        nonce="nonce-002",
        parent_receipt=receipt,
    )
    downgrade = verify_information_flow_receipt(
        downgraded,
        sender,
        payload=child_payload,
        previous_receipt=receipt,
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-002",
        nonce_cache=InformationFlowNonceCache(),
    )
    print(f"downgrade_attempt: {'allowed' if downgrade.allowed else 'denied'}")

    replay = verify_information_flow_receipt(
        receipt,
        sender,
        payload=payload,
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-001",
        nonce_cache=nonce_cache,
    )
    print(f"replay_attempt: {'allowed' if replay.allowed else 'denied'}")


if __name__ == "__main__":
    main()
