#!/usr/bin/env python3
"""Stdlib-only mock host flow for bank-agent.

This demo does not execute Rego. It mirrors the bundled policy template in
Python so the scaffold is runnable anywhere and shows verdict/effect handling
across lifecycle, model, tool, and output intervention points.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
# AGT D1: warn/escalate/deny no longer carry transformations (the
# strict runtime rejects effects[] per 1d8fcb64). The rego template
# under policy/bank_agent_rego.rego now returns transform decisions
# for pre_model_call, post_tool_call, and output; the demo mirrors
# the new shape so STAGE_FIXTURES asserts what the policy actually
# produces.
STAGE_FIXTURES = [
    ("agent_startup", "agent_startup.canonical.json", "allow", False),
    ("input", "input.canonical.json", "allow", False),
    ("pre_model_call", "pre_model_call.canonical.json", "transform", True),
    ("post_model_call", "post_model_call.canonical.json", "allow", False),
    ("pre_tool_call", "pre_tool_call.canonical.json", "escalate", False),
    ("pre_tool_call", "pre_tool_call.safe.canonical.json", "allow", False),
    ("post_tool_call", "post_tool_call.canonical.json", "transform", True),
    ("output", "output.canonical.json", "transform", True),
    ("agent_shutdown", "agent_shutdown.canonical.json", "warn", False),
]


def load_json(relative_path: str) -> Any:
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def path_tokens(path: str) -> list[str | int]:
    if path == "$policy_target":
        return []
    if not path.startswith("$policy_target"):
        raise ValueError(f"effect path must be rooted at $policy_target: {path}")
    tokens: list[str | int] = []
    rest = path[len("$policy_target"):]
    while rest:
        if rest.startswith("."):
            rest = rest[1:]
            match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", rest)
            if not match:
                raise ValueError(f"invalid effect path segment: {path}")
            tokens.append(match.group(0))
            rest = rest[match.end():]
        elif rest.startswith("["):
            end = rest.index("]")
            tokens.append(int(rest[1:end]))
            rest = rest[end + 1:]
        else:
            raise ValueError(f"invalid effect path: {path}")
    return tokens


def target_parent(policy_target: Any, path: str) -> tuple[Any, str | int | None]:
    tokens = path_tokens(path)
    if not tokens:
        return None, None
    current = policy_target
    for token in tokens[:-1]:
        current = current[token]
    return current, tokens[-1]


def apply_effect(policy_target: Any, effect: dict[str, Any]) -> Any:
    raise AssertionError(
        "AGT D1 rejected effects[]; use a transform decision with a "
        "transform payload instead."
    )


def apply_effects(policy_target: Any, effects: list[dict[str, Any]]) -> Any:
    raise AssertionError(
        "AGT D1 rejected effects[]; use a transform decision with a "
        "transform payload instead."
    )


def account_redaction_effect(text: str) -> dict[str, Any] | None:
    raise AssertionError(
        "AGT D1 rejected effects[]; the output stage now emits a "
        "transform decision that replaces $policy_target.text."
    )


def apply_transform(policy_target: Any, transform: dict[str, Any]) -> Any:
    """AGT D1.1: apply a single-target transform payload.

    `transform` is the canonical mutation payload returned by AGT
    `transform` decisions. The runtime applies `value` at `path` and
    propagates the result; the demo reuses the same path-walking
    utility as the legacy effects path but only supports a single
    transform per verdict (no append/prepend/redact list semantics).
    """

    updated = copy.deepcopy(policy_target)
    path = transform["path"]
    value = transform["value"]
    parent, key = target_parent(updated, path)
    if key is None:
        return copy.deepcopy(value)
    parent[key] = copy.deepcopy(value)
    return updated


def evaluate_policy(policy_input: dict[str, Any]) -> dict[str, Any]:
    stage = policy_input["intervention_point"]
    policy_target = policy_input["policy_target"]["value"]
    annotations = policy_input["annotations"]
    tool = policy_input["tool"] or {}

    if stage == "input" and annotations["prompt_classifier"]["risk_score"] >= 0.95:
        return {
            "decision": "deny",
            "reason": "input_classifier_high_risk",
            "message": "The request is too risky for this demo bank agent.",
        }

    if stage == "pre_model_call" and annotations["model_request_classifier"].get("contains_large_transfer"):
        # AGT D1.1: append the system reminder via a single-target
        # transform that replaces `messages` with the appended list,
        # mirroring policy/bank_agent_rego.rego.
        appended = list(policy_target["messages"]) + [
            {
                "role": "system",
                "content": "Do not execute high-value transfers without explicit approval.",
            }
        ]
        return {
            "decision": "transform",
            "reason": "large_transfer_instruction_added",
            "message": "A high-value transfer reminder was added before the model call.",
            "transform": {
                "path": "$policy_target.messages",
                "value": appended,
            },
        }

    if stage == "post_model_call" and "bypass approval" in policy_target["message"]["content"].lower():
        return {
            "decision": "deny",
            "reason": "model_suggested_approval_bypass",
            "message": "The model response suggested bypassing an approval path.",
        }

    if stage == "pre_tool_call" and tool.get("name") == "wire_transfer" and policy_target.get("amount", 0) >= 10000:
        return {
            "decision": "escalate",
            "reason": "large_wire_transfer_requires_review",
            "message": "Wire transfers of 10000 or more require a human approval route.",
        }

    if stage == "post_tool_call" and policy_target.get("account_id"):
        # AGT D1.1: single-target replace of account_id mirrors the
        # rego post_tool_call_verdict transform.
        return {
            "decision": "transform",
            "reason": "tool_result_account_identifier_redacted",
            "message": "The account identifier was redacted before the result returned to the agent.",
            "transform": {
                "path": "$policy_target.account_id",
                "value": "ACCOUNT-REDACTED",
            },
        }

    if stage == "output":
        text = policy_target.get("text", "")
        if re.search(r"CHK-[0-9]+", text):
            # AGT D1.1: regex-replace via a single-target transform
            # that replaces `text` with the redacted string, mirroring
            # the rego output_verdict transform.
            return {
                "decision": "transform",
                "reason": "output_account_identifier_redacted",
                "message": "The final response contained an account identifier and was redacted.",
                "transform": {
                    "path": "$policy_target.text",
                    "value": re.sub(r"CHK-[0-9]+", "ACCOUNT-REDACTED", text),
                },
            }

    if stage == "agent_shutdown" and policy_target.get("blocked_actions"):
        return {
            "decision": "warn",
            "reason": "shutdown_audit_contains_blocked_action",
            "message": "Persist the shutdown audit summary with the blocked action record.",
        }

    return {"decision": "allow"}


def enforce(policy_input: dict[str, Any], verdict: dict[str, Any]) -> tuple[bool, Any | None]:
    """Apply the demo's host-side enforcement of an AGT verdict.

    Returns ``(blocked, transformed_policy_target)``.

    AGT D1 strictly rejects ``effects[]``; the canonical mutation
    payload is ``transform`` on a ``transform`` verdict. Non-transform
    decisions MUST NOT carry a transform; this helper asserts that
    invariant so a host-side mistake fails closed.
    """

    decision = verdict["decision"]
    blocked = decision in {"deny", "escalate"}
    if "effects" in verdict:
        raise AssertionError(
            "AGT D1 rejected effects[]; the policy MUST emit a transform decision",
        )
    transform = verdict.get("transform")
    if blocked:
        if transform is not None:
            raise AssertionError("deny/escalate verdicts MUST NOT transform policy_targets")
        return True, None
    if decision == "transform":
        if transform is None:
            raise AssertionError("transform verdicts MUST carry a transform payload")
        return False, apply_transform(policy_input["policy_target"]["value"], transform)
    if transform is not None:
        raise AssertionError(
            f"{decision} verdicts MUST NOT carry a transform payload per AGT D1.1",
        )
    return False, None


def describe_policy_target(policy_input: dict[str, Any], transformed: Any | None) -> str:
    policy_target = transformed if transformed is not None else policy_input["policy_target"]["value"]
    if isinstance(policy_target, dict) and "text" in policy_target:
        return policy_target["text"]
    if isinstance(policy_target, dict) and "messages" in policy_target:
        return f"messages={len(policy_target['messages'])}"
    if isinstance(policy_target, dict) and "account_id" in policy_target:
        return f"account_id={policy_target['account_id']}"
    return policy_input["policy_target"]["kind"]


def main() -> None:
    manifest = (ROOT / "manifest.yaml").read_text(encoding="utf-8")
    for token in ["agent_control_specification_version", "intervention_points", "policy_target", "annotators"]:
        assert token in manifest
    for removed in ["state:", "endpoint:", "hooks:", "variables:", "lifetimes:", "event_bus:", "resolvers:", "guard_policies:", "final_output:"]:
        assert removed not in manifest

    print("Agent Control Specification bank-agent parity demo")
    print("policy=bank_agent_rego")
    saw_block = False
    final_text = None

    for stage, fixture, expected_decision, expected_transform in STAGE_FIXTURES:
        policy_input = load_json(f"policy_input/{fixture}")
        assert policy_input["intervention_point"] == stage
        verdict = evaluate_policy(policy_input)
        blocked, transformed = enforce(policy_input, verdict)
        decision = verdict["decision"]
        assert decision == expected_decision, (stage, decision, expected_decision)
        assert (transformed is not None) == expected_transform, stage
        if blocked:
            saw_block = True
        label = stage
        if stage == "pre_tool_call":
            label += f"/{policy_input['tool']['name']}"
        print(f"{label:34} -> {decision:8} {verdict.get('reason', 'ok')}")
        if transformed is not None:
            print(f"  transformed_policy_target: {describe_policy_target(policy_input, transformed)}")
        if stage == "output" and transformed is not None:
            final_text = transformed["text"]

    assert saw_block, "expected an escalate/blocked path"
    assert final_text and "CHK-" not in final_text and "ACCOUNT-REDACTED" in final_text
    print(f"user_visible_output: {final_text}")
    print("demo verification: PASS")


if __name__ == "__main__":
    main()
