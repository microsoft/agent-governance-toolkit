# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for JSON schema validation of saga DSL definitions."""

import pytest

from hypervisor.saga.dsl import SagaDSLError, SagaDSLParser
from hypervisor.saga.schema import (
    SAGA_DEFINITION_SCHEMA,
    VALID_ACTION_PREFIXES,
    SagaSchemaError,
    SagaSchemaValidator,
)

# ── Helpers ─────────────────────────────────────────────────────


def _valid_definition(**overrides):
    """Return a minimal valid saga definition dict."""
    defn = {
        "name": "test-saga",
        "session_id": "sess-1",
        "steps": [
            {
                "id": "step-1",
                "action_id": "model.validate",
                "agent": "did:mesh:validator",
                "execute_api": "/api/validate",
                "undo_api": "/api/rollback",
                "timeout": 300,
                "retries": 0,
            },
        ],
    }
    defn.update(overrides)
    return defn


def _valid_step(**overrides):
    step = {
        "id": "s1",
        "action_id": "model.run",
        "agent": "did:mesh:agent",
        "execute_api": "/api/run",
        "undo_api": "/api/undo",
    }
    step.update(overrides)
    return step


# ── Schema Structure Tests ──────────────────────────────────────


class TestSchemaStructure:
    """Tests that the JSON schema itself is well-formed."""

    def test_schema_has_required_fields(self):
        assert "name" in SAGA_DEFINITION_SCHEMA["required"]
        assert "session_id" in SAGA_DEFINITION_SCHEMA["required"]
        assert "steps" in SAGA_DEFINITION_SCHEMA["required"]

    def test_schema_has_title(self):
        assert SAGA_DEFINITION_SCHEMA["title"] == "SagaDefinition"

    def test_step_schema_requires_id_action_agent(self):
        step_schema = SAGA_DEFINITION_SCHEMA["properties"]["steps"]["items"]
        assert "id" in step_schema["required"]
        assert "action_id" in step_schema["required"]
        assert "agent" in step_schema["required"]


# ── Required Fields Validation ──────────────────────────────────


class TestRequiredFields:
    def setup_method(self):
        self.validator = SagaSchemaValidator()

    def test_valid_definition_passes(self):
        errors = self.validator.validate(_valid_definition())
        assert errors == []

    def test_missing_name(self):
        defn = _valid_definition()
        del defn["name"]
        errors = self.validator.validate(defn)
        assert any("name" in e for e in errors)

    def test_missing_session_id(self):
        defn = _valid_definition()
        del defn["session_id"]
        errors = self.validator.validate(defn)
        assert any("session_id" in e for e in errors)

    def test_missing_steps(self):
        defn = _valid_definition()
        del defn["steps"]
        errors = self.validator.validate(defn)
        assert any("steps" in e for e in errors)

    def test_empty_name(self):
        errors = self.validator.validate(_valid_definition(name=""))
        assert any("name" in e for e in errors)

    def test_empty_session_id(self):
        errors = self.validator.validate(_valid_definition(session_id=""))
        assert any("session_id" in e for e in errors)

    def test_empty_steps_list(self):
        errors = self.validator.validate(_valid_definition(steps=[]))
        assert any("steps" in e for e in errors)

    def test_completely_empty_dict(self):
        errors = self.validator.validate({})
        assert len(errors) >= 3  # name, session_id, steps


# ── Step Structure Validation ───────────────────────────────────


class TestStepStructure:
    def setup_method(self):
        self.validator = SagaSchemaValidator()

    def test_step_missing_id(self):
        step = _valid_step()
        del step["id"]
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert any("id" in e for e in errors)

    def test_step_missing_action_id(self):
        step = _valid_step()
        del step["action_id"]
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert any("action_id" in e for e in errors)

    def test_step_missing_agent(self):
        step = _valid_step()
        del step["agent"]
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert any("agent" in e for e in errors)

    def test_step_empty_id(self):
        step = _valid_step(id="")
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert any("id" in e for e in errors)

    def test_step_unknown_property_rejected(self):
        step = _valid_step(unknown_field="bad")
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert any("additional" in e.lower() or "unknown_field" in e for e in errors)


# ── Timeout Range Validation ───────────────────────────────────


class TestTimeoutRanges:
    def setup_method(self):
        self.validator = SagaSchemaValidator()

    def test_valid_timeout(self):
        step = _valid_step(timeout=600)
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert errors == []

    def test_timeout_too_low(self):
        step = _valid_step(timeout=0)
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert any("timeout" in e.lower() or "minimum" in e.lower() for e in errors)

    def test_timeout_too_high(self):
        step = _valid_step(timeout=100000)
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert any("timeout" in e.lower() or "maximum" in e.lower() for e in errors)

    def test_timeout_wrong_type(self):
        step = _valid_step(timeout="fast")
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert any("timeout" in e.lower() or "type" in e.lower() for e in errors)

    def test_retries_negative(self):
        step = _valid_step(retries=-1)
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert any("retries" in e.lower() or "minimum" in e.lower() for e in errors)

    def test_retries_too_high(self):
        step = _valid_step(retries=11)
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert any("retries" in e.lower() or "maximum" in e.lower() for e in errors)

    def test_boundary_timeout_min(self):
        step = _valid_step(timeout=1)
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert errors == []

    def test_boundary_timeout_max(self):
        step = _valid_step(timeout=86400)
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert errors == []


# ── Action Type Validation ──────────────────────────────────────


class TestActionTypes:
    def setup_method(self):
        self.validator = SagaSchemaValidator()

    def test_valid_action_prefixes(self):
        for prefix in VALID_ACTION_PREFIXES:
            step = _valid_step(action_id=f"{prefix}run")
            errors = self.validator.validate(_valid_definition(steps=[step]))
            assert not any("action_id" in e and "prefix" in e for e in errors), \
                f"Prefix '{prefix}' should be valid"

    def test_invalid_action_prefix(self):
        step = _valid_step(action_id="unknown.action")
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert any("action_id" in e and "prefix" in e for e in errors)


# ── Compensation Requirements ───────────────────────────────────


class TestCompensation:
    def setup_method(self):
        self.validator = SagaSchemaValidator()

    def test_step_without_undo_api_warns(self):
        step = _valid_step()
        del step["undo_api"]
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert any("undo_api" in e for e in errors)

    def test_step_with_null_undo_api_warns(self):
        step = _valid_step(undo_api=None)
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert any("undo_api" in e for e in errors)

    def test_step_with_undo_api_passes(self):
        step = _valid_step(undo_api="/api/rollback")
        errors = self.validator.validate(_valid_definition(steps=[step]))
        assert not any("undo_api" in e for e in errors)


# ── Step Ordering and Dependencies ──────────────────────────────


class TestDependencies:
    def setup_method(self):
        self.validator = SagaSchemaValidator()

    def test_valid_dependency(self):
        steps = [
            _valid_step(id="s1"),
            _valid_step(id="s2", depends_on=["s1"]),
        ]
        errors = self.validator.validate(_valid_definition(steps=steps))
        assert not any("depends_on" in e for e in errors)

    def test_unknown_dependency(self):
        steps = [
            _valid_step(id="s1"),
            _valid_step(id="s2", depends_on=["nonexistent"]),
        ]
        errors = self.validator.validate(_valid_definition(steps=steps))
        assert any("nonexistent" in e for e in errors)

    def test_circular_dependency(self):
        steps = [
            _valid_step(id="s1", depends_on=["s2"]),
            _valid_step(id="s2", depends_on=["s1"]),
        ]
        errors = self.validator.validate(_valid_definition(steps=steps))
        assert any("circular" in e.lower() for e in errors)

    def test_self_dependency(self):
        steps = [_valid_step(id="s1", depends_on=["s1"])]
        errors = self.validator.validate(_valid_definition(steps=steps))
        assert any("circular" in e.lower() for e in errors)

    def test_duplicate_step_ids(self):
        steps = [
            _valid_step(id="dup"),
            _valid_step(id="dup", action_id="model.other"),
        ]
        errors = self.validator.validate(_valid_definition(steps=steps))
        assert any("duplicate" in e.lower() for e in errors)


# ── Validate-or-Raise ──────────────────────────────────────────


class TestValidateOrRaise:
    def setup_method(self):
        self.validator = SagaSchemaValidator()

    def test_valid_does_not_raise(self):
        self.validator.validate_or_raise(_valid_definition())

    def test_invalid_raises_schema_error(self):
        with pytest.raises(SagaSchemaError) as exc_info:
            self.validator.validate_or_raise({})
        assert len(exc_info.value.errors) >= 3

    def test_error_message_lists_all_problems(self):
        with pytest.raises(SagaSchemaError, match="validation error"):
            self.validator.validate_or_raise({"name": ""})


# ── Integration with SagaDSLParser ──────────────────────────────


class TestParserSchemaIntegration:
    def test_parser_without_schema_validation(self):
        """Default parser does not enforce schema validation."""
        parser = SagaDSLParser()
        defn = parser.parse({
            "name": "x",
            "session_id": "s1",
            "steps": [{"id": "s", "action_id": "a", "agent": "x"}],
        })
        assert defn.name == "x"

    def test_parser_with_schema_validation_valid(self):
        parser = SagaDSLParser(schema_validation=True)
        defn = parser.parse(_valid_definition())
        assert defn.name == "test-saga"

    def test_parser_with_schema_validation_invalid(self):
        parser = SagaDSLParser(schema_validation=True)
        with pytest.raises(SagaSchemaError):
            parser.parse({"name": "", "session_id": "s", "steps": []})

    def test_parser_existing_behavior_preserved(self):
        """Existing SagaDSLError still raised for structural issues."""
        parser = SagaDSLParser()
        with pytest.raises(SagaDSLError, match="name"):
            parser.parse({"session_id": "s", "steps": [{"id": "s", "action_id": "a", "agent": "x"}]})
