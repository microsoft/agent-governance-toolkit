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
STAGE_FIXTURES = [
    ("agent_startup", "agent_startup.canonical.json", "allow", False),
    ("input", "input.canonical.json", "allow", False),
    ("pre_model_call", "pre_model_call.canonical.json", "warn", True),
    ("post_model_call", "post_model_call.canonical.json", "allow", False),
    ("pre_tool_call", "pre_tool_call.canonical.json", "escalate", False),
    ("pre_tool_call", "pre_tool_call.safe.canonical.json", "allow", False),
    ("post_tool_call", "post_tool_call.canonical.json", "warn", True),
    ("output", "output.canonical.json", "warn", True),
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
    updated = copy.deepcopy(policy_target)
    parent, key = target_parent(updated, effect["path"])
    target = updated if key is None else parent[key]
    effect_type = effect["type"]

    if effect_type == "replace":
        if key is None:
            updated = copy.deepcopy(effect["value"])
        else:
            parent[key] = copy.deepcopy(effect["value"])
    elif effect_type == "append":
        if isinstance(target, list):
            target.append(copy.deepcopy(effect["value"]))
        elif isinstance(target, str):
            parent[key] = target + str(effect["value"])
        else:
            raise ValueError("append target must be a list or string")
    elif effect_type == "prepend":
        if isinstance(target, list):
            target.insert(0, copy.deepcopy(effect["value"]))
        elif isinstance(target, str):
            parent[key] = str(effect["value"]) + target
        else:
            raise ValueError("prepend target must be a list or string")
    elif effect_type == "redact":
        if not isinstance(target, str):
            raise ValueError("redact target must be a string")
        chars = list(target)
        output: list[str] = []
        last_end = 0
        for span in effect["spans"]:
            output.extend(chars[last_end:span["start"]])
            output.append(span["replacement"])
            last_end = span["end"]
        output.extend(chars[last_end:])
        if key is None:
            updated = "".join(output)
        else:
            parent[key] = "".join(output)
    else:
        raise ValueError(f"unsupported effect type: {effect_type}")

    return updated


def apply_effects(policy_target: Any, effects: list[dict[str, Any]]) -> Any:
    updated = copy.deepcopy(policy_target)
    for effect in effects:
        updated = apply_effect(updated, effect)
    return updated


def account_redaction_effect(text: str) -> dict[str, Any] | None:
    match = re.search(r"CHK-[0-9]+", text)
    if not match:
        return None
    return {
        "type": "redact",
        "path": "$policy_target.text",
        "spans": [
            {"start": match.start(), "end": match.end(), "replacement": "ACCOUNT-REDACTED"}
        ],
    }


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
        return {
            "decision": "warn",
            "reason": "large_transfer_instruction_added",
            "message": "A high-value transfer reminder was added before the model call.",
            "effects": [
                {
                    "type": "append",
                    "path": "$policy_target.messages",
                    "value": {
                        "role": "system",
                        "content": "Do not execute high-value transfers without explicit approval.",
                    },
                }
            ],
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
        return {
            "decision": "warn",
            "reason": "tool_result_account_identifier_redacted",
            "message": "The account identifier was redacted before the result returned to the agent.",
            "effects": [
                {"type": "replace", "path": "$policy_target.account_id", "value": "ACCOUNT-REDACTED"}
            ],
        }

    if stage == "output":
        effect = account_redaction_effect(policy_target.get("text", ""))
        if effect:
            return {
                "decision": "warn",
                "reason": "output_account_identifier_redacted",
                "message": "The final response contained an account identifier and was redacted.",
                "effects": [effect],
            }

    if stage == "agent_shutdown" and policy_target.get("blocked_actions"):
        return {
            "decision": "warn",
            "reason": "shutdown_audit_contains_blocked_action",
            "message": "Persist the shutdown audit summary with the blocked action record.",
        }

    return {"decision": "allow"}


def enforce(policy_input: dict[str, Any], verdict: dict[str, Any]) -> tuple[bool, Any | None]:
    blocked = verdict["decision"] in {"deny", "escalate"}
    effects = verdict.get("effects", [])
    if blocked:
        if effects:
            raise AssertionError("deny/escalate verdicts must not transform policy_targets")
        return True, None
    if effects:
        return False, apply_effects(policy_input["policy_target"]["value"], effects)
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
