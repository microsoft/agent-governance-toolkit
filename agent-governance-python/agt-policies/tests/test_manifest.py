# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the native AGT manifest contract."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from agt.policies import (
    AdapterManifestContract,
    AgtManifest,
    ManifestCompatibilityError,
)


def _complex_manifest() -> dict:
    return {
        "agent_control_specification_version": "0.3.1-beta",
        "metadata": {"name": "mail-agent", "owner": "security"},
        "extends": [
            "./base.yaml",
            {
                "url": "https://example.test/base.yaml",
                "sha256": "a" * 64,
            },
        ],
        "policies": {
            "rego_policy": {
                "type": "rego",
                "bundle": "./policy",
                "query": "data.mail.verdict",
                "data_paths": ["./data"],
                "host_extension": {"enabled": True},
                "nullable_extension": None,
            },
            "cedar_policy": {
                "type": "cedar",
                "policy_path": "./policy.cedar",
                "entities_path": "./entities.json",
            },
            "custom_policy": {
                "type": "custom",
                "adapter": "mail_adapter",
                "timeout_ms": 50,
            },
        },
        "intervention_points": {
            "input": {
                "policy_target": "$.input.body",
                "policy": {"id": "rego_policy"},
                "annotations": {
                    "pii": {"from": "$.input.body", "threshold": 0.8}
                },
            },
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "cedar_policy", "data_paths": ["./ip-data"]},
            },
        },
        "tools": {
            "send_mail": {
                "type": "Tool",
                "clearance": ["internal"],
                "content_hash": "sha256:abc",
            }
        },
        "annotators": {
            "pii": {
                "type": "endpoint",
                "endpoint": "https://example.test/pii",
                "system_prompt_file": "./prompt.txt",
                "type_hint": "semantic_classifier",
            }
        },
        "approval": {
            "default_resolver": "ticket",
            "timeout_seconds": 120,
            "on_timeout": "deny",
            "resolvers": {
                "ticket": {"type": "webhook", "url": "https://example.test"}
            },
        },
        "limits": {
            "max_snapshot_bytes": 1_048_576,
            "max_annotators_per_point": 4,
        },
    }


def test_typed_manifest_round_trips_all_schema_surfaces() -> None:
    source = _complex_manifest()

    typed = AgtManifest.model_validate(source)

    assert typed.to_document() == source
    assert typed.policies["rego_policy"].host_extension == {"enabled": True}
    assert typed.policies["rego_policy"].nullable_extension is None
    assert typed.tools["send_mail"].content_hash == "sha256:abc"
    assert typed.annotators["pii"].type_hint == "semantic_classifier"


def test_manifest_model_is_not_a_rebranded_simple_policy_dsl() -> None:
    assert {
        "max_tokens",
        "max_tool_calls",
        "allowed_tools",
        "blocked_patterns",
        "require_human_approval",
        "confidence_threshold",
    }.isdisjoint(AgtManifest.model_fields)


def test_manifest_path_carries_provenance_and_resolves_local_refs(
    tmp_path: Path,
) -> None:
    path = tmp_path / "manifest.yaml"
    path.write_text(
        """
agent_control_specification_version: 0.3.1-beta
metadata:
  name: test
policies:
  p:
    type: rego
    bundle: ./policy
intervention_points:
  input:
    policy_target: $.input.body
    policy:
      id: p
""",
        encoding="utf-8",
    )

    manifest = AgtManifest.from_path(path)
    resolved = manifest.resolved_document()

    assert manifest.provenance.source == str(path.resolve())
    assert manifest.provenance.base_dir == tmp_path.resolve()
    assert resolved["policies"]["p"]["bundle"] == str(
        (tmp_path / "policy").resolve()
    )


def test_mapping_with_relative_refs_requires_explicit_provenance() -> None:
    manifest = AgtManifest.model_validate(_complex_manifest())

    with pytest.raises(ValueError, match="base_dir is required"):
        manifest.resolved_document()


def test_url_sourced_manifest_cannot_access_host_files(tmp_path: Path) -> None:
    manifest = AgtManifest.from_document(
        _complex_manifest(),
        base_dir=tmp_path,
        source="https://example.test/manifest.yaml",
    )

    with pytest.raises(ValueError, match="URL-sourced"):
        manifest.resolved_document()


def test_partial_valid_manifest_can_fail_adapter_preflight() -> None:
    manifest = AgtManifest.model_validate(
        {
            "agent_control_specification_version": "0.3.1-beta",
            "policies": {"p": {"type": "test"}},
            "intervention_points": {
                "pre_tool_call": {
                    "policy_target": "$.tool_call.args",
                    "policy": {"id": "p"},
                }
            },
        }
    )
    contract = AdapterManifestContract(
        name="chat-host",
        required_intervention_points=frozenset({"input", "output"}),
        tool_catalog_mode="manifest",
    )

    with pytest.raises(ManifestCompatibilityError) as caught:
        manifest.validate_for(contract)

    assert caught.value.missing_intervention_points == {"input", "output"}
    assert caught.value.missing_tool_catalog is True


def test_preflight_refuses_to_guess_across_unresolved_extends() -> None:
    manifest = AgtManifest.model_validate(
        {
            "agent_control_specification_version": "0.3.1-beta",
            "extends": ["./base.yaml"],
            "intervention_points": {
                "input": {
                    "policy_target": "$.input.body",
                    # The parent may define this policy, so structural
                    # validation must preserve the unresolved reference.
                    "policy": {"id": "parent_policy"},
                }
            },
        }
    )
    contract = AdapterManifestContract(
        name="chat-host",
        required_intervention_points=frozenset({"input"}),
    )

    with pytest.raises(ValueError, match="requires a resolved manifest"):
        manifest.validate_for(contract)


def test_adapter_preflight_checks_approval_separately() -> None:
    manifest = AgtManifest.model_validate(
        {
            "agent_control_specification_version": "0.3.1-beta",
            "metadata": {"name": "test"},
        }
    )
    contract = AdapterManifestContract(
        name="approval-host",
        required_intervention_points=frozenset(),
        requires_approval_section=True,
    )

    with pytest.raises(ManifestCompatibilityError) as caught:
        manifest.validate_for(contract)

    assert caught.value.missing_approval is True


def test_adapter_preflight_rejects_unsupported_approval() -> None:
    manifest = AgtManifest.model_validate(
        {
            "agent_control_specification_version": "0.3.1-beta",
            "metadata": {"name": "test"},
            "approval": {},
        }
    )
    contract = AdapterManifestContract(
        name="no-approval-host",
        required_intervention_points=frozenset(),
        approval_mode="unsupported",
    )

    with pytest.raises(ManifestCompatibilityError) as caught:
        manifest.validate_for(contract)

    assert caught.value.unsupported_approval is True


@pytest.mark.parametrize(
    "policy",
    [
        {"type": "custom"},
        {"type": "cedar"},
        {"type": "cedar", "policy_set": "permit();", "policy_path": "p.cedar"},
    ],
)
def test_policy_type_specific_requirements_are_validated(policy: dict) -> None:
    with pytest.raises(ValidationError):
        AgtManifest.model_validate(
            {
                "agent_control_specification_version": "0.3.1-beta",
                "policies": {"p": policy},
            }
        )


def test_unknown_top_level_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AgtManifest.model_validate(
            {
                "agent_control_specification_version": "0.3.1-beta",
                "metadata": {},
                "max_tokens": 100,
            }
        )


def test_known_optional_fields_reject_explicit_null() -> None:
    with pytest.raises(ValidationError, match="bundle must not be null"):
        AgtManifest.model_validate(
            {
                "agent_control_specification_version": "0.3.1-beta",
                "policies": {"p": {"type": "rego", "bundle": None}},
            }
        )


def test_extends_rejects_non_https_url_schemes() -> None:
    with pytest.raises(ValidationError, match="https"):
        AgtManifest.model_validate(
            {
                "agent_control_specification_version": "0.3.1-beta",
                "extends": ["http://example.test/base.yaml"],
            }
        )


def test_extends_object_allows_optional_pin_but_bundle_requires_one() -> None:
    manifest = AgtManifest.model_validate(
        {
            "agent_control_specification_version": "0.3.1-beta",
            "extends": [{"url": "https://example.test/base.yaml"}],
        }
    )
    assert manifest.to_document()["extends"] == [
        {"url": "https://example.test/base.yaml"}
    ]

    with pytest.raises(ValidationError, match="bundle_url requires"):
        AgtManifest.model_validate(
            {
                "agent_control_specification_version": "0.3.1-beta",
                "policies": {
                    "p": {
                        "type": "rego",
                        "bundle_url": {
                            "url": "https://example.test/policy.tar.gz"
                        },
                    }
                },
            }
        )


def test_manifest_model_round_trips_repository_acs_corpus() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    candidates = set((repo_root / "policy-engine").glob("**/manifest.yaml"))
    candidates.update((repo_root / "policy-engine").glob("**/*.manifest.yaml"))
    validated = 0
    for path in sorted(candidates):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or "agent_control_specification_version" not in raw:
            continue
        typed = AgtManifest.model_validate(raw)
        assert typed.to_document() == raw, path
        validated += 1

    assert validated >= 30
