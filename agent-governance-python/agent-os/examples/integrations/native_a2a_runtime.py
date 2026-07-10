# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Minimal A2A adapter using the public native runtime path."""

from __future__ import annotations

from pathlib import Path

from agt.policies.runtime import AgtRuntime

from agent_os.integrations.a2a_adapter import A2AGovernanceAdapter


class RequestPolicy:
    """Allow the example request while recording a real ACS invocation."""

    def evaluate(self, invocation):  # type: ignore[no-untyped-def]
        policy_input = dict(invocation).get("policy_input", {})
        target = policy_input.get("policy_target", {}).get("value", {})
        if isinstance(target, dict) and target.get("blocked") is True:
            return {
                "decision": "deny",
                "reason": "example_blocked_request",
            }
        return {"decision": "allow"}


def main() -> None:
    manifest = Path(__file__).with_name("native_a2a_manifest.yaml")
    runtime = AgtRuntime.from_manifest(
        manifest,
        policy_dispatcher=RequestPolicy(),
    )
    adapter = A2AGovernanceAdapter(runtime=runtime)
    evaluation = adapter.evaluate_task(
        {
            "id": "task-1",
            "skill_id": "weather",
            "messages": [{"role": "user", "parts": [{"text": "Forecast"}]}],
            "metadata": {
                "source_did": "did:mesh:example",
                "source_trust_score": 700,
            },
        }
    )
    print(evaluation.to_dict())


if __name__ == "__main__":
    main()
