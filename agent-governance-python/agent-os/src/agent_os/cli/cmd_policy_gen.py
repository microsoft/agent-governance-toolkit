# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Generate native ACS manifest and Rego starter bundles."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


TEMPLATES: dict[str, dict[str, Any]] = {
    "strict": {
        "allow": ["web_search", "read_file"],
        "deny": [],
        "default": "deny",
        "max_tool_calls": 20,
    },
    "permissive": {
        "allow": [],
        "deny": [],
        "default": "allow",
        "max_tool_calls": 100,
    },
    "web-only": {
        "allow": ["web_search", "web_browse"],
        "deny": [],
        "default": "deny",
        "max_tool_calls": 50,
    },
    "read-only": {
        "allow": ["read_file", "list_directory", "web_search"],
        "deny": [],
        "default": "deny",
        "max_tool_calls": 50,
    },
    "custom": {
        "allow": ["REPLACE_ME"],
        "deny": [],
        "default": "deny",
        "max_tool_calls": 50,
    },
}

TEMPLATE_CHOICES = list(TEMPLATES)


def generate_policy(template_name: str) -> str:
    """Return a native ACS manifest for a named starter template."""

    if template_name not in TEMPLATES:
        raise ValueError(
            f"Unknown template {template_name!r}. "
            f"Choose from: {', '.join(TEMPLATE_CHOICES)}"
        )
    policy_id = f"{template_name.replace('-', '_')}_starter"
    document = {
        "agent_control_specification_version": "0.3.1-beta",
        "metadata": {
            "name": f"{template_name}-starter",
            "version": "1.0",
        },
        "extends": [],
        "policies": {
            policy_id: {
                "type": "rego",
                "bundle": ".",
                "query": "data.agt.generated.result",
            }
        },
        "intervention_points": {
            "input": {
                "policy_target": "$.input.body",
                "policy": {"id": policy_id},
            },
            "output": {
                "policy_target": "$.output.content",
                "policy": {"id": policy_id},
            },
        },
    }
    return (
        "# Copyright (c) Microsoft Corporation.\n"
        "# Licensed under the MIT License.\n"
        + yaml.safe_dump(document, sort_keys=False)
    )


def generate_rego(template_name: str) -> str:
    """Return Rego implementing a named starter template."""

    if template_name not in TEMPLATES:
        raise ValueError(f"Unknown template {template_name!r}")
    template = TEMPLATES[template_name]
    allow = json.dumps(template["allow"])
    deny = json.dumps(template["deny"])
    default = template["default"]
    limit = int(template["max_tool_calls"])
    return f"""# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.generated

import rego.v1

body := input.policy_target.value if is_object(input.policy_target.value)
body := {{"content": input.policy_target.value}} if not is_object(input.policy_target.value)

action := object.get(body, "action", "")
content := sprintf("%v", [object.get(body, "content", body)])
allow_actions := {allow}
deny_actions := {deny}

blocked_sensitive if regex.match(`(?i)(\\b\\d{{3}}-\\d{{2}}-\\d{{4}}\\b|\\b\\d{{16}}\\b)`, content)

tool_budget_exceeded if {{
    budgets := object.get(object.get(object.get(input, "snapshot", {{}}), "envelope", {{}}), "budgets", {{}})
    object.get(budgets, "tool_call_count", 0) >= {limit}
}}

result := {{"decision": "deny", "reason": "sensitive_content"}} if blocked_sensitive
result := {{"decision": "deny", "reason": "tool_budget_exceeded"}} if tool_budget_exceeded
result := {{"decision": "deny", "reason": "explicit_deny"}} if action in deny_actions
result := {{"decision": "allow", "reason": "explicit_allow"}} if {{
    not blocked_sensitive
    not tool_budget_exceeded
    not action in deny_actions
    action in allow_actions
}}
result := {{"decision": "{default}", "reason": "default_{default}"}} if {{
    not blocked_sensitive
    not tool_budget_exceeded
    not action in deny_actions
    not action in allow_actions
}}
"""


def write_policy_bundle(template_name: str, output: Path) -> None:
    """Write `manifest.yaml` and `policy.rego` into an output directory."""

    output.mkdir(parents=True, exist_ok=True)
    (output / "manifest.yaml").write_text(
        generate_policy(template_name),
        encoding="utf-8",
    )
    (output / "policy.rego").write_text(
        generate_rego(template_name),
        encoding="utf-8",
    )


def cmd_policy_gen(argv: list[str] | None = None) -> None:
    """CLI entry point for native starter generation."""

    parser = argparse.ArgumentParser(
        prog="agent-os policy generate",
        description="Generate a native ACS starter bundle",
    )
    parser.add_argument(
        "--template",
        choices=TEMPLATE_CHOICES,
        default="strict",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Output directory for manifest.yaml and policy.rego",
    )
    args = parser.parse_args(argv)
    write_policy_bundle(args.template, args.output)


if __name__ == "__main__":
    cmd_policy_gen()
