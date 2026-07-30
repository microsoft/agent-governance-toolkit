# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for native ACS starter generation."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_control_specification import validate_manifest
from agent_control_specification import AgentControl, HostSession
from agent_os.cli.cmd_policy_gen import (
    TEMPLATE_CHOICES,
    cmd_policy_gen,
    generate_policy,
    generate_rego,
)


@pytest.mark.parametrize("template", TEMPLATE_CHOICES)
def test_generated_manifest_is_native(template: str, tmp_path: Path) -> None:
    output = tmp_path / template
    cmd_policy_gen(["--template", template, "--output", str(output)])

    validate_manifest(
        (output / "manifest.yaml").read_text(encoding="utf-8")
    )
    assert "package agt.generated" in (output / "policy.rego").read_text()


def test_unknown_template_rejected() -> None:
    with pytest.raises(ValueError):
        generate_policy("unknown")


def test_strict_runtime_allows_reads_and_denies_unknown(
    tmp_path: Path,
) -> None:
    output = tmp_path / "strict"
    cmd_policy_gen(["--template", "strict", "-o", str(output)])
    control = AgentControl.from_path(str(output / "manifest.yaml"))
    runtime = HostSession(control, agent_id="test")
    try:
        read = runtime.input({"action": "read_file"})
        write = runtime.input({"action": "write_file"})
    finally:
        pass

    assert read.verdict.decision.value == "allow"
    assert write.verdict.decision.value == "deny"


def test_generate_rego_contains_budget_limit() -> None:
    assert "tool_call_count" in generate_rego("strict")
