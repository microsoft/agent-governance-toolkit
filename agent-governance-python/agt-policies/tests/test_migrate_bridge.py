# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Translation guarantees for the one-way v4 policy migrator.

``build_migrated_manifest`` is the only remaining code path that reads the v4
policy shape. It used to be covered by a differential test against the runtime
bridge; the bridge is gone, so these tests pin the translation directly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agt.cli._migrate_bridge import MigrationPolicyInput, build_migrated_manifest


def _build(tmp_path: Path, **kwargs: object) -> dict:
    policy = MigrationPolicyInput(**kwargs)  # type: ignore[arg-type]
    return build_migrated_manifest(
        policy,
        bundle_dir=tmp_path / "bundle",
        policy_id="app",
    )


def test_allowed_tools_become_declared_tools(tmp_path: Path) -> None:
    manifest = _build(tmp_path, name="prod", allowed_tools=["search", "read"])

    assert set(manifest["tools"]) == {"search", "read"}


def test_tool_and_token_budgets_survive_translation(tmp_path: Path) -> None:
    """Each budget keeps its v4 scope: consumption points only.

    v4 compared call_count to max_tool_calls at tool interception, so the
    tool-call budget gates pre_tool_call alone; the cumulative token budget
    gates the points about to spend tokens.
    """
    _build(tmp_path, max_tool_calls=3, max_tokens=1000)
    rendered = (tmp_path / "bundle" / "app.rego").read_text(encoding="utf-8")

    assert (
        'input.intervention_point == "pre_tool_call"\n'
        '\tv := budgets.deny_if_budget_exceeded({"tool_call_count": 3})'
    ) in rendered
    assert (
        'input.intervention_point in ["pre_model_call", "pre_tool_call"]\n'
        '\tv := budgets.deny_if_budget_exceeded({"token_count": 1000})'
    ) in rendered


def test_tool_calls_are_mediated_before_the_call(tmp_path: Path) -> None:
    manifest = _build(tmp_path, allowed_tools=["search"])
    pre_tool_call = manifest["intervention_points"]["pre_tool_call"]

    assert pre_tool_call["policy_target_kind"] == "tool_args"
    assert pre_tool_call["policy"]["id"] == "app"


def test_blocked_patterns_are_escaped_into_the_bundle(tmp_path: Path) -> None:
    """A v4 substring pattern becomes an escaped regex, so it cannot widen."""
    _build(tmp_path, blocked_patterns=["secret-token"])
    rendered = (tmp_path / "bundle" / "app.rego").read_text(encoding="utf-8")

    assert "deny_if_pattern" in rendered
    assert r"secret\\-token" in rendered


def test_human_approval_is_carried_over(tmp_path: Path) -> None:
    """The escalation lives in the bundle; the manifest only declares the block."""
    manifest = _build(tmp_path, require_human_approval=True)
    rendered = (tmp_path / "bundle" / "app.rego").read_text(encoding="utf-8")

    assert "approval" in manifest
    # v4 gated approval on tool interception only; the migrated escalation
    # must stay scoped to pre_tool_call rather than fire at every bound point.
    assert (
        'input.intervention_point == "pre_tool_call"\n'
        '\tv := approval.escalate_if_approver_required(["human"])'
    ) in rendered


def test_no_approval_escalation_when_not_required(tmp_path: Path) -> None:
    _build(tmp_path, require_human_approval=False)
    rendered = (tmp_path / "bundle" / "app.rego").read_text(encoding="utf-8")

    assert "escalate_if_approver_required" not in rendered


def test_manifest_records_the_migrator_as_its_source(tmp_path: Path) -> None:
    manifest = _build(tmp_path, name="prod", version="2.1.0")

    assert manifest["metadata"]["name"] == "prod"
    assert manifest["metadata"]["policy_version"] == "2.1.0"
    assert "build_migrated_manifest" in manifest["metadata"]["source"]


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("max_tokens", 0),
        ("max_tokens", -1),
        ("max_tokens", True),
        ("max_tool_calls", -1),
    ],
)
def test_out_of_range_budgets_are_refused(
    tmp_path: Path, field_name: str, value: object
) -> None:
    with pytest.raises(ValueError):
        _build(tmp_path, **{field_name: value})
