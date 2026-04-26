# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy Template Loader

Load pre-built YAML policy templates by name and optionally convert
them to GovernancePolicy instances.

Usage:
    from agent_os.templates import load_policy, list_templates, load_policy_yaml

    # Load as GovernancePolicy dataclass
    policy = load_policy("hipaa")

    # Load raw YAML as dict
    config = load_policy_yaml("production")

    # List all available templates
    templates = list_templates()
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

_TEMPLATES_DIR = Path(__file__).parent


def list_templates() -> list[str]:
    """Return names of all available policy templates.

    Returns:
        Sorted list of template names (without .yaml extension).
    """
    return sorted(
        p.stem
        for p in _TEMPLATES_DIR.glob("*.yaml")
    )


def load_policy_yaml(name: str) -> dict[str, Any]:
    """Load a policy template as a raw Python dict.

    Args:
        name: Template name (e.g. ``"hipaa"``, ``"production"``).
              The ``.yaml`` extension is added automatically.

    Returns:
        Parsed YAML content as a dictionary.

    Raises:
        FileNotFoundError: If no template with the given name exists.
        ValueError: If the YAML file is empty or invalid.
    """
    import yaml

    path = _TEMPLATES_DIR / f"{name}.yaml"
    if not path.exists():
        available = ", ".join(list_templates())
        raise FileNotFoundError(
            f"Policy template '{name}' not found. Available: {available}"
        )

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f.read())

    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping in '{name}.yaml', got {type(data).__name__}")

    return data


def load_policy(name: str) -> "GovernancePolicy":
    """Load a policy template and return a GovernancePolicy instance.

    Extracts GovernancePolicy-compatible fields from the YAML template
    and constructs a GovernancePolicy dataclass. Template-specific fields
    (signals, notifications, compliance metadata) are stored in the
    policy name for traceability.

    Args:
        name: Template name (e.g. ``"hipaa"``, ``"production"``).

    Returns:
        A configured GovernancePolicy instance.

    Raises:
        FileNotFoundError: If no template with the given name exists.
    """
    from agent_os.integrations.base import GovernancePolicy, PatternType

    data = load_policy_yaml(name)

    # Extract blocked patterns from all policy rules
    blocked_patterns: list[str | tuple[str, PatternType]] = []
    for policy in data.get("policies", []):
        for deny_rule in policy.get("deny", []):
            if isinstance(deny_rule, dict) and "patterns" in deny_rule:
                for pattern in deny_rule["patterns"]:
                    blocked_patterns.append((pattern, PatternType.REGEX))

    # Extract allowed tools from allow rules
    allowed_tools: list[str] = []
    for policy in data.get("policies", []):
        for allow_rule in policy.get("allow", []):
            if isinstance(allow_rule, dict) and "action" in allow_rule:
                action = allow_rule["action"]
                if action != "*":
                    allowed_tools.append(action)

    # Determine settings from kernel mode and policy metadata
    kernel = data.get("kernel", {})
    mode = kernel.get("mode", "strict")
    settings = data.get("settings", {})

    require_human_approval = settings.get(
        "human_approval_required",
        any(p.get("requires_approval") for p in data.get("policies", [])),
    )

    audit = data.get("audit", {})
    log_all_calls = audit.get("enabled", True)

    # Extract rate limits if present
    max_tool_calls = 10  # default
    for policy in data.get("policies", []):
        for limit in policy.get("limits", []):
            if isinstance(limit, dict) and limit.get("action") == "tool_call":
                if "max_per_session" in limit:
                    max_tool_calls = limit["max_per_session"]
                    break

    return GovernancePolicy(
        name=name,
        max_tokens=4096 if mode == "strict" else 50000,
        max_tool_calls=max_tool_calls,
        allowed_tools=allowed_tools,
        blocked_patterns=blocked_patterns,
        require_human_approval=require_human_approval,
        timeout_seconds=300 if mode == "strict" else 600,
        log_all_calls=log_all_calls,
        checkpoint_frequency=1 if mode == "strict" else 10,
    )
