# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Differential gate for the one-way GovernancePolicy translator."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import pytest

from agt.cli._migrate_bridge import (
    MigrationPolicyInput,
    build_migrated_manifest,
)
from agt.policies import AgtManifest
from agt.policies.bridge import governance_to_acs_manifest


class _PatternType(Enum):
    SUBSTRING = "substring"
    REGEX = "regex"
    GLOB = "glob"


@dataclass
class _FrozenPolicy:
    name: str = "default"
    max_tokens: int = 4096
    max_tool_calls: int = 10
    allowed_tools: list[str] = field(default_factory=list)
    blocked_patterns: list[Any] = field(default_factory=list)
    require_human_approval: bool = False
    confidence_threshold: float = 0.8
    version: str = "1.0.0"


CASES = [
    pytest.param(_FrozenPolicy(), MigrationPolicyInput(), id="defaults"),
    pytest.param(
        _FrozenPolicy(max_tool_calls=0),
        MigrationPolicyInput(max_tool_calls=0),
        id="deny-all-tools",
    ),
    pytest.param(
        _FrozenPolicy(allowed_tools=["lookup", "fetch"]),
        MigrationPolicyInput(allowed_tools=["lookup", "fetch"]),
        id="allowlist",
    ),
    pytest.param(
        _FrozenPolicy(
            blocked_patterns=[
                "secret",
                ("id-[0-9]+", _PatternType.REGEX),
                ("*.exe", _PatternType.GLOB),
            ]
        ),
        MigrationPolicyInput(
            blocked_patterns=[
                "secret",
                ("id-[0-9]+", "REGEX"),
                ("*.exe", "GLOB"),
            ]
        ),
        id="patterns",
    ),
    pytest.param(
        _FrozenPolicy(require_human_approval=True, confidence_threshold=0.95),
        MigrationPolicyInput(
            require_human_approval=True,
            confidence_threshold=0.95,
        ),
        id="approval-confidence",
    ),
]


@pytest.mark.parametrize(("frozen", "migration"), CASES)
def test_private_migrator_matches_frozen_runtime_bridge(
    tmp_path: Path,
    frozen: _FrozenPolicy,
    migration: MigrationPolicyInput,
) -> None:
    frozen_dir = tmp_path / "frozen"
    migration_dir = tmp_path / "migration"

    expected = governance_to_acs_manifest(
        frozen,
        bundle_dir=frozen_dir,
        policy_id="policy",
    )
    actual = build_migrated_manifest(
        migration,
        bundle_dir=migration_dir,
        policy_id="policy",
    )

    assert AgtManifest.from_document(actual).to_document() == actual
    assert _normalize_manifest(expected) == _normalize_manifest(actual)
    assert _normalize_rego(frozen_dir / "policy.rego") == _normalize_rego(
        migration_dir / "policy.rego"
    )
    assert _stock_files(frozen_dir) == _stock_files(migration_dir)


def _normalize_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        key: value
        for key, value in manifest.items()
        if key != "metadata"
    }
    normalized["metadata"] = {
        "name": manifest["metadata"]["name"],
        "policy_version": manifest["metadata"]["policy_version"],
    }
    normalized["policies"] = {
        name: {
            **definition,
            "bundle": "<bundle>",
        }
        for name, definition in manifest["policies"].items()
    }
    return normalized


def _normalize_rego(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join(
        line
        for line in lines
        if not line.startswith("# AUTO-GENERATED")
        and not line.startswith("# Mirrors a v4")
    )


def _stock_files(path: Path) -> dict[str, str]:
    required = {"approval.rego", "budgets.rego", "confidence.rego", "patterns.rego"}
    return {
        child.name: "\n".join(
            line
            for line in child.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        )
        for child in path.glob("*.rego")
        if child.name in required
    }
