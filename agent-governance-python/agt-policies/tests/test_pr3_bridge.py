# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for bridge temporary bundle cleanup."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

_PACKAGE_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_PACKAGE_SRC) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_SRC))

from agt.policies import bridge as bridge_module  # noqa: E402
from agt.policies.bridge import governance_to_acs_manifest  # noqa: E402


@dataclass
class _PolicyFixture:
    name: str = "bridge_cleanup"
    max_tokens: int = 4096
    max_tool_calls: int = 10
    allowed_tools: list[str] = field(default_factory=list)
    blocked_patterns: list[Any] = field(default_factory=list)
    require_human_approval: bool = False
    confidence_threshold: float = 0.0
    version: str = "1.0.0"


def _stock_rego_root(tmp_path: Path) -> Path:
    stock_root = tmp_path / "stock"
    stock_root.mkdir()
    (stock_root / "budgets.rego").write_text(
        "# Copyright (c) Microsoft Corporation.\n"
        "# Licensed under the MIT License.\n"
        "package agt.budgets\n",
        encoding="utf-8",
    )
    return stock_root


def _capture_bridge_temp_dirs(
    monkeypatch: pytest.MonkeyPatch,
    temp_root: Path,
) -> list[Path]:
    created: list[Path] = []

    def fake_mkdtemp(
        suffix: str | None = None,
        prefix: str | None = None,
        dir: str | None = None,
    ) -> str:
        del dir
        path = temp_root / f"{prefix or ''}{len(created)}{suffix or ''}"
        path.mkdir(parents=True)
        created.append(path)
        return str(path)

    monkeypatch.setattr(bridge_module.tempfile, "mkdtemp", fake_mkdtemp)
    return created


def test_self_created_temp_bundle_dir_is_removed_on_render_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    temp_root = tmp_path / "temp-root"
    temp_root.mkdir()
    created = _capture_bridge_temp_dirs(monkeypatch, temp_root)

    with pytest.raises(ValueError, match="pattern value must be a string"):
        governance_to_acs_manifest(
            _PolicyFixture(blocked_patterns=[(123, "REGEX")]),
            stock_rego_root=_stock_rego_root(tmp_path),
        )

    assert len(created) == 1
    assert not created[0].exists()
    assert list(temp_root.glob("agt_bridge_*")) == []


def test_caller_supplied_bundle_dir_is_not_deleted_on_render_failure(
    tmp_path: Path,
) -> None:
    bundle_dir = tmp_path / "caller-bundle"
    bundle_dir.mkdir()
    sentinel = bundle_dir / "caller-owned.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="pattern value must be a string"):
        governance_to_acs_manifest(
            _PolicyFixture(blocked_patterns=[(123, "REGEX")]),
            bundle_dir=bundle_dir,
            stock_rego_root=_stock_rego_root(tmp_path),
        )

    assert bundle_dir.exists()
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert (bundle_dir / "budgets.rego").exists()
