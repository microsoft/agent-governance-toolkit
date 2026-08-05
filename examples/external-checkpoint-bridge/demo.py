#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
External Checkpoint Bridge - Demo

Demonstrates how AGT can send a deterministic action envelope to an external
checkpoint before a tool executes, then map the returned verdict back to local
runtime enforcement.

Usage:
    python examples/external-checkpoint-bridge/demo.py

Optional:
    EXTERNAL_CHECKPOINT_URL=https://checkpoint.example.com/review \
        python examples/external-checkpoint-bridge/demo.py
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any, Literal, TypedDict
from uuid import UUID, uuid5


Verdict = Literal["allow", "require_approval", "deny"]
Enforcement = Literal["execute", "pause_for_human_approval", "block"]
ACTION_REF_NAMESPACE = UUID("7c9f4db5-99e0-44a7-a2f3-4f1d84d3f8f6")
ALLOWED_VERDICTS: set[str] = {"allow", "require_approval", "deny"}


class ActionEnvelope(TypedDict):
    action_ref: str
    actor: str
    runtime: str
    tool_name: str
    proposed_action: str
    arguments: dict[str, Any]
    policy_id: str


class CheckpointVerdict(TypedDict):
    verdict: Verdict
    reason: str
    decision_id: str
    action_ref: str


def stable_json(value: Any) -> str:
    """Serialize JSON deterministically for checkpoint review."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def action_ref_for(value: Any) -> str:
    """Return an opaque deterministic reference for a proposed action.

    The demo keeps raw arguments inside the action envelope sent for review, but
    avoids copying those arguments into the reference stored in proof objects.
    Production deployments should use the SDK's approved digest/signature APIs
    or an external verifier for cryptographic proof material.
    """
    return f"agt-demo-ref:{uuid5(ACTION_REF_NAMESPACE, stable_json(value))}"


def build_action_envelope(
    *,
    actor: str,
    runtime: str,
    tool_name: str,
    proposed_action: str,
    arguments: dict[str, Any],
    policy_id: str,
) -> ActionEnvelope:
    """Build an action envelope whose stable ref excludes review metadata."""
    ref_input = {
        "actor": actor,
        "runtime": runtime,
        "tool_name": tool_name,
        "proposed_action": proposed_action,
        "arguments": arguments,
        "policy_id": policy_id,
    }
    return {
        "action_ref": action_ref_for(ref_input),
        **ref_input,
    }


def local_checkpoint(envelope: ActionEnvelope) -> CheckpointVerdict:
    """Return a local checkpoint verdict for the demo's sample actions."""
    arguments = envelope["arguments"]
    tool_name = envelope["tool_name"]

    if tool_name.startswith("filesystem.delete"):
        verdict: Verdict = "deny"
        reason = "Destructive file operation is outside this agent's boundary."
    elif arguments.get("contains_pii") or int(arguments.get("record_limit", 0)) > 10:
        verdict = "require_approval"
        reason = "Customer data export requires approval before execution."
    else:
        verdict = "allow"
        reason = "Action is within the low-risk policy boundary."

    return {
        "verdict": verdict,
        "reason": reason,
        "decision_id": f"local-{envelope['tool_name']}",
        "action_ref": envelope["action_ref"],
    }


def remote_checkpoint(url: str, envelope: ActionEnvelope) -> CheckpointVerdict:
    """Send an action envelope to a remote checkpoint endpoint."""
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise ValueError("EXTERNAL_CHECKPOINT_URL must be an HTTPS endpoint.")

    body = stable_json(envelope).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = response.read().decode("utf-8")

    return parse_remote_verdict(payload, envelope)


def parse_remote_verdict(payload: str, envelope: ActionEnvelope) -> CheckpointVerdict:
    """Validate and normalize a remote checkpoint response.

    Remote checkpoints are optional in this example, so malformed responses
    should fail closed with a clear error rather than surfacing incidental
    `KeyError` or `AttributeError` exceptions.
    """
    try:
        raw_verdict = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("Remote checkpoint returned invalid JSON.") from exc

    if not isinstance(raw_verdict, dict):
        raise ValueError("Remote checkpoint response must be a JSON object.")

    remote_action_ref = raw_verdict.get("action_ref")
    if remote_action_ref != envelope["action_ref"]:
        raise ValueError(
            "Remote checkpoint returned a verdict for a different action_ref."
        )

    verdict = raw_verdict.get("verdict")
    if verdict not in ALLOWED_VERDICTS:
        raise ValueError(
            "Remote checkpoint verdict must be one of: allow, require_approval, deny."
        )

    reason = raw_verdict.get("reason", "External checkpoint returned no reason.")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("Remote checkpoint reason must be a non-empty string.")

    decision_id = raw_verdict.get("decision_id", f"remote-{envelope['tool_name']}")
    if not isinstance(decision_id, str) or not decision_id.strip():
        raise ValueError("Remote checkpoint decision_id must be a non-empty string.")

    return {
        "verdict": verdict,
        "reason": reason,
        "decision_id": decision_id,
        "action_ref": envelope["action_ref"],
    }


def review_action(envelope: ActionEnvelope) -> CheckpointVerdict:
    """Review an action with either a remote endpoint or the local demo checkpoint."""
    checkpoint_url = os.environ.get("EXTERNAL_CHECKPOINT_URL")
    if checkpoint_url:
        return remote_checkpoint(checkpoint_url, envelope)
    return local_checkpoint(envelope)


def map_to_enforcement(verdict: Verdict) -> Enforcement:
    """Map a checkpoint verdict into local runtime enforcement semantics."""
    if verdict == "allow":
        return "execute"
    if verdict == "require_approval":
        return "pause_for_human_approval"
    if verdict == "deny":
        return "block"
    raise ValueError(f"Unsupported checkpoint verdict: {verdict!r}")


def sample_actions() -> list[ActionEnvelope]:
    """Return sample action envelopes that exercise allow, review, and deny."""
    return [
        build_action_envelope(
            actor="agent:researcher",
            runtime="demo-runtime",
            tool_name="crm.lookup_customer",
            proposed_action="Read one customer profile for support triage.",
            arguments={
                "account_id": "acme-123",
                "record_limit": 1,
                "contains_pii": False,
            },
            policy_id="policy:customer-data:v1",
        ),
        build_action_envelope(
            actor="agent:ops-analyst",
            runtime="demo-runtime",
            tool_name="crm.export_customer_records",
            proposed_action="Export customer records to an internal compliance workspace.",
            arguments={
                "account_id": "acme-123",
                "record_limit": 25,
                "contains_pii": True,
            },
            policy_id="policy:customer-data:v1",
        ),
        build_action_envelope(
            actor="agent:ops-analyst",
            runtime="demo-runtime",
            tool_name="filesystem.delete_file",
            proposed_action="Delete a file from a production evidence directory.",
            arguments={"path": "/prod/evidence/customer-export.jsonl"},
            policy_id="policy:filesystem:v1",
        ),
    ]


def main() -> None:
    """Run the external checkpoint bridge demo."""
    checkpoint_url = os.environ.get("EXTERNAL_CHECKPOINT_URL")
    print("External Checkpoint Bridge")
    print(f"checkpoint: {checkpoint_url or 'local'}\n")
    print(f"{'Action':<32} {'Verdict':<20} {'AGT enforcement'}")
    print("-" * 76)

    proof_objects: list[dict[str, str]] = []
    for envelope in sample_actions():
        verdict = review_action(envelope)
        enforcement = map_to_enforcement(verdict["verdict"])
        proof_objects.append(
            {
                "decision_id": verdict["decision_id"],
                "action_ref": verdict["action_ref"],
                "verdict": verdict["verdict"],
                "enforcement": enforcement,
            }
        )
        print(f"{envelope['tool_name']:<32} {verdict['verdict']:<20} {enforcement}")

    print("\nSample proof object:")
    print(json.dumps(proof_objects[1], indent=2))

    print("\nNext steps:")
    print(
        "  - Replace the local checkpoint with an internal or third-party review service."
    )
    print(
        "  - Store the proof object next to the AGT audit trail for replay and review."
    )
    print("  - Require human approval when enforcement is pause_for_human_approval.")


if __name__ == "__main__":
    main()
