# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for native ACS starter generation."""

from __future__ import annotations

from pathlib import Path

import pytest

from agt.policies import AgtManifest
from agt.policies.runtime import AgtRuntime
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

    AgtManifest.from_path(output / "manifest.yaml")
    assert "package agt.generated" in (output / "policy.rego").read_text()


def test_unknown_template_rejected() -> None:
    with pytest.raises(ValueError):
        generate_policy("unknown")


def test_strict_runtime_allows_reads_and_denies_unknown(
    tmp_path: Path,
) -> None:
    output = tmp_path / "strict"
    cmd_policy_gen(["--template", "strict", "-o", str(output)])
    runtime = AgtRuntime.from_manifest(output / "manifest.yaml")
    try:
        read = runtime.evaluate(
            "input",
            {
                "envelope": {
                    "agent_id": "test",
                    "budgets": {"tool_call_count": 0},
                },
                "input": {"body": {"action": "read_file"}},
            },
        )
        write = runtime.evaluate(
            "input",
            {
                "envelope": {
                    "agent_id": "test",
                    "budgets": {"tool_call_count": 0},
                },
                "input": {"body": {"action": "write_file"}},
            },
        )
    finally:
        runtime.close()

    assert read.verdict == "allow"
    assert write.verdict == "deny"


def test_generate_rego_contains_budget_limit() -> None:
    assert "tool_call_count" in generate_rego("strict")
