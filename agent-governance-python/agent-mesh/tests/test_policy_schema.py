# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for policy schema versioning and migration."""

import warnings

import pytest

from agentmesh.governance.policy import (
    CURRENT_API_VERSION,
    Policy,
    PolicyEngine,
    migrate_policy,
    validate_policy_schema,
)


VALID_V1_YAML = """
apiVersion: governance.toolkit/v1
name: test-policy
description: A test policy
default_action: deny
rules:
  - name: block-exports
    condition: "action.type == 'export'"
    action: deny
    description: Block export actions
"""

LEGACY_YAML = """
name: legacy-policy
version: "1.0"
default_action: allow
rules:
  - name: allow-all
    condition: "agent.role == 'admin'"
    action: allow
"""

UNSUPPORTED_VERSION_YAML = """
apiVersion: governance.toolkit/v99
name: future-policy
default_action: deny
rules: []
"""


class TestApiVersionValidation:
    def test_current_version_accepted(self):
        policy = Policy.from_yaml(VALID_V1_YAML)
        assert policy.apiVersion == CURRENT_API_VERSION
        assert policy.name == "test-policy"

    def test_legacy_version_emits_deprecation(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            policy = Policy.from_yaml(LEGACY_YAML)
            deprecation_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecation_warnings) >= 1
            assert "deprecated" in str(deprecation_warnings[0].message).lower()

    def test_unsupported_version_raises(self):
        with pytest.raises(ValueError, match="Unsupported policy apiVersion"):
            Policy.from_yaml(UNSUPPORTED_VERSION_YAML)

    def test_no_version_defaults_to_current(self):
        yaml_content = """
name: minimal-policy
default_action: allow
rules: []
"""
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            policy = Policy.from_yaml(yaml_content)
            assert policy.apiVersion == CURRENT_API_VERSION

    def test_json_version_validation(self):
        import json
        data = {
            "apiVersion": "governance.toolkit/v1",
            "name": "json-policy",
            "rules": [],
        }
        policy = Policy.from_json(json.dumps(data))
        assert policy.apiVersion == CURRENT_API_VERSION

    def test_json_unsupported_version_raises(self):
        import json
        data = {
            "apiVersion": "governance.toolkit/v99",
            "name": "bad-policy",
            "rules": [],
        }
        with pytest.raises(ValueError):
            Policy.from_json(json.dumps(data))


class TestMigration:
    def test_migrate_legacy_to_v1(self):
        result = migrate_policy(LEGACY_YAML, CURRENT_API_VERSION)
        assert "governance.toolkit/v1" in result
        # version field should be removed
        import yaml
        data = yaml.safe_load(result)
        assert data.get("apiVersion") == CURRENT_API_VERSION
        assert "version" not in data

    def test_migrate_already_current_is_noop(self):
        result = migrate_policy(VALID_V1_YAML, CURRENT_API_VERSION)
        assert result == VALID_V1_YAML

    def test_migrate_to_unknown_version_raises(self):
        with pytest.raises(ValueError, match="Unknown target version"):
            migrate_policy(LEGACY_YAML, "governance.toolkit/v99")


class TestSchemaValidation:
    def test_valid_policy(self):
        errors = validate_policy_schema(VALID_V1_YAML)
        assert errors == []

    def test_missing_name(self):
        yaml_content = """
apiVersion: governance.toolkit/v1
rules: []
"""
        errors = validate_policy_schema(yaml_content)
        assert any("name" in e for e in errors)

    def test_invalid_action(self):
        yaml_content = """
apiVersion: governance.toolkit/v1
name: bad-action-policy
rules:
  - name: rule1
    condition: "true"
    action: explode
"""
        errors = validate_policy_schema(yaml_content)
        assert any("invalid action" in e for e in errors)

    def test_missing_rule_condition(self):
        yaml_content = """
apiVersion: governance.toolkit/v1
name: missing-condition
rules:
  - name: rule1
    action: deny
"""
        errors = validate_policy_schema(yaml_content)
        assert any("condition" in e for e in errors)

    def test_invalid_yaml(self):
        errors = validate_policy_schema("not: valid: yaml: {{}")
        assert len(errors) > 0

    def test_unknown_api_version(self):
        yaml_content = """
apiVersion: unknown/v99
name: test
rules: []
"""
        errors = validate_policy_schema(yaml_content)
        assert any("apiVersion" in e for e in errors)

    def test_invalid_default_action(self):
        yaml_content = """
apiVersion: governance.toolkit/v1
name: test
default_action: maybe
rules: []
"""
        errors = validate_policy_schema(yaml_content)
        assert any("default_action" in e for e in errors)


class TestPolicyEngineWithVersioning:
    def test_engine_loads_versioned_policy(self):
        engine = PolicyEngine()
        policy = engine.load_yaml(VALID_V1_YAML)
        assert policy.apiVersion == CURRENT_API_VERSION
        assert engine.get_policy("test-policy") is not None

    def test_engine_rejects_unsupported_version(self):
        engine = PolicyEngine()
        with pytest.raises(ValueError):
            engine.load_yaml(UNSUPPORTED_VERSION_YAML)
