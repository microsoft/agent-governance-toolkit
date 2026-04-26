# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import pytest

from agent_marketplace.workflow_bundle import (
    BundleComponent,
    BundleRegistry,
    BundleValidationError,
    ComponentType,
    WorkflowBundle,
)


# ---------------------------------------------------------------------------
# BundleComponent
# ---------------------------------------------------------------------------


class TestBundleComponent:
    def test_create_component(self) -> None:
        comp = BundleComponent(ComponentType.AGENT, "my-agent", "1.0.0")
        assert comp.component_type == ComponentType.AGENT
        assert comp.name == "my-agent"
        assert comp.version == "1.0.0"
        assert comp.config == {}

    def test_create_component_with_config(self) -> None:
        cfg = {"model": "gpt-4", "temperature": 0.7}
        comp = BundleComponent(ComponentType.TOOL, "search", "2.1.0", config=cfg)
        assert comp.config == cfg


# ---------------------------------------------------------------------------
# WorkflowBundle
# ---------------------------------------------------------------------------


class TestWorkflowBundle:
    def test_create_bundle_with_components(self) -> None:
        comps = [
            BundleComponent(ComponentType.AGENT, "planner", "1.0.0"),
            BundleComponent(ComponentType.TOOL, "search", "1.0.0"),
            BundleComponent(ComponentType.KNOWLEDGE, "docs", "1.0.0"),
        ]
        bundle = WorkflowBundle("my-bundle", "1.0.0", "A test bundle", comps)
        assert bundle.name == "my-bundle"
        assert bundle.version == "1.0.0"
        assert len(bundle.components) == 3

    def test_empty_bundle_defaults(self) -> None:
        bundle = WorkflowBundle("empty", "0.1.0")
        assert bundle.components == []
        assert bundle.shared_dependencies == []
        assert bundle.governance_policy == ""
        assert bundle.description == ""

    def test_bundle_version_tracking(self) -> None:
        v1 = WorkflowBundle(
            "versioned", "1.0.0",
            components=[BundleComponent(ComponentType.SKILL, "s", "1.0.0")],
        )
        v2 = WorkflowBundle(
            "versioned", "2.0.0",
            components=[BundleComponent(ComponentType.SKILL, "s", "2.0.0")],
        )
        assert v1.version == "1.0.0"
        assert v2.version == "2.0.0"
        assert v1.name == v2.name


# ---------------------------------------------------------------------------
# BundleRegistry — register / get / list
# ---------------------------------------------------------------------------


class TestBundleRegistry:
    @staticmethod
    def _make_bundle(
        name: str = "test-bundle",
        version: str = "1.0.0",
        components: list[BundleComponent] | None = None,
    ) -> WorkflowBundle:
        if components is None:
            components = [BundleComponent(ComponentType.AGENT, "agent-a", "1.0.0")]
        return WorkflowBundle(name, version, components=components)

    def test_register_and_get(self) -> None:
        reg = BundleRegistry()
        bundle = self._make_bundle()
        reg.register(bundle)
        assert reg.get("test-bundle", "1.0.0") is bundle

    def test_get_missing_returns_none(self) -> None:
        reg = BundleRegistry()
        assert reg.get("nonexistent", "1.0.0") is None

    def test_list_bundles(self) -> None:
        reg = BundleRegistry()
        b1 = self._make_bundle("a", "1.0.0")
        b2 = self._make_bundle("b", "1.0.0")
        reg.register(b1)
        reg.register(b2)
        listed = reg.list_bundles()
        assert len(listed) == 2
        assert set(b.name for b in listed) == {"a", "b"}

    def test_count(self) -> None:
        reg = BundleRegistry()
        assert reg.count == 0
        reg.register(self._make_bundle("x", "1.0.0"))
        assert reg.count == 1

    def test_register_multiple_versions(self) -> None:
        reg = BundleRegistry()
        reg.register(self._make_bundle("pkg", "1.0.0"))
        reg.register(self._make_bundle("pkg", "2.0.0"))
        assert reg.count == 2
        assert reg.get("pkg", "1.0.0") is not None
        assert reg.get("pkg", "2.0.0") is not None


# ---------------------------------------------------------------------------
# validate_bundle
# ---------------------------------------------------------------------------


class TestValidateBundle:
    def test_valid_bundle_passes(self) -> None:
        reg = BundleRegistry()
        bundle = WorkflowBundle(
            "ok", "1.0.0",
            components=[BundleComponent(ComponentType.AGENT, "a", "1.0.0")],
        )
        errors = reg.validate_bundle(bundle)
        assert errors == []

    def test_duplicate_component_names_rejected(self) -> None:
        reg = BundleRegistry()
        bundle = WorkflowBundle(
            "dup", "1.0.0",
            components=[
                BundleComponent(ComponentType.AGENT, "same-name", "1.0.0"),
                BundleComponent(ComponentType.TOOL, "same-name", "1.0.0"),
            ],
        )
        errors = reg.validate_bundle(bundle)
        assert any("Duplicate" in e for e in errors)

    def test_empty_bundle_rejected(self) -> None:
        reg = BundleRegistry()
        bundle = WorkflowBundle("empty", "1.0.0", components=[])
        errors = reg.validate_bundle(bundle)
        assert any("at least one component" in e for e in errors)

    def test_register_invalid_raises(self) -> None:
        reg = BundleRegistry()
        bundle = WorkflowBundle("", "1.0.0", components=[])
        with pytest.raises(BundleValidationError):
            reg.register(bundle)

    def test_missing_component_version(self) -> None:
        reg = BundleRegistry()
        bundle = WorkflowBundle(
            "bad-comp", "1.0.0",
            components=[BundleComponent(ComponentType.SKILL, "s", "")],
        )
        errors = reg.validate_bundle(bundle)
        assert any("missing a version" in e for e in errors)


# ---------------------------------------------------------------------------
# search / list by component type
# ---------------------------------------------------------------------------


class TestRegistrySearch:
    def test_search_by_component_type(self) -> None:
        reg = BundleRegistry()
        agent_bundle = WorkflowBundle(
            "agents", "1.0.0",
            components=[BundleComponent(ComponentType.AGENT, "a1", "1.0.0")],
        )
        tool_bundle = WorkflowBundle(
            "tools", "1.0.0",
            components=[BundleComponent(ComponentType.TOOL, "t1", "1.0.0")],
        )
        reg.register(agent_bundle)
        reg.register(tool_bundle)
        results = reg.search(ComponentType.AGENT)
        assert len(results) == 1
        assert results[0].name == "agents"

    def test_search_no_filter_returns_all(self) -> None:
        reg = BundleRegistry()
        reg.register(
            WorkflowBundle(
                "a", "1.0.0",
                components=[BundleComponent(ComponentType.AGENT, "x", "1.0.0")],
            ),
        )
        assert len(reg.search()) == 1
