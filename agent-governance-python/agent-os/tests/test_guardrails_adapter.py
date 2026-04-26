# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Guardrails AI bridge adapter.

No real guardrails-ai dependency — uses built-in validators and mocks.

Run with: python -m pytest tests/test_guardrails_adapter.py -v --tb=short
"""

from unittest.mock import MagicMock

import pytest

from agent_os.integrations.guardrails_adapter import (
    FailAction,
    GuardrailsKernel,
    KeywordValidator,
    LengthValidator,
    RegexValidator,
    ValidationOutcome,
    ValidationResult,
)


# =============================================================================
# RegexValidator
# =============================================================================


class TestRegexValidator:
    def test_pass(self):
        v = RegexValidator(patterns=[r"\d{3}-\d{2}-\d{4}"])  # SSN pattern
        r = v.validate("Hello world")
        assert r.passed

    def test_fail_ssn(self):
        v = RegexValidator(patterns=[r"\d{3}-\d{2}-\d{4}"])
        r = v.validate("My SSN is 123-45-6789")
        assert not r.passed
        assert "blocked pattern" in r.error_message

    def test_multiple_patterns(self):
        v = RegexValidator(patterns=[r"\d{3}-\d{2}-\d{4}", r"password\s*[:=]"])
        assert not v.validate("password: hunter2").passed
        assert v.validate("safe text").passed

    def test_case_insensitive(self):
        v = RegexValidator(patterns=[r"secret"])
        assert not v.validate("This is SECRET data").passed


# =============================================================================
# LengthValidator
# =============================================================================


class TestLengthValidator:
    def test_pass(self):
        v = LengthValidator(max_length=100)
        r = v.validate("short text")
        assert r.passed

    def test_fail(self):
        v = LengthValidator(max_length=10)
        r = v.validate("this is definitely more than ten characters")
        assert not r.passed
        assert r.fixed_value is not None
        assert len(r.fixed_value) == 10

    def test_exact_limit(self):
        v = LengthValidator(max_length=5)
        assert v.validate("12345").passed
        assert not v.validate("123456").passed


# =============================================================================
# KeywordValidator
# =============================================================================


class TestKeywordValidator:
    def test_pass(self):
        v = KeywordValidator(blocked_keywords=["DROP TABLE", "rm -rf"])
        r = v.validate("Hello world")
        assert r.passed

    def test_fail(self):
        v = KeywordValidator(blocked_keywords=["DROP TABLE"])
        r = v.validate("DROP TABLE users")
        assert not r.passed
        assert "blocked keyword" in r.error_message

    def test_case_insensitive(self):
        v = KeywordValidator(blocked_keywords=["rm -rf"])
        assert not v.validate("RM -RF /").passed


# =============================================================================
# ValidationOutcome
# =============================================================================


class TestValidationOutcome:
    def test_to_dict_passed(self):
        o = ValidationOutcome(validator_name="test", passed=True)
        d = o.to_dict()
        assert d["validator"] == "test"
        assert d["passed"] is True
        assert "error" not in d

    def test_to_dict_failed(self):
        o = ValidationOutcome(
            validator_name="pii",
            passed=False,
            error_message="PII detected",
            fixed_value="[REDACTED]",
        )
        d = o.to_dict()
        assert d["passed"] is False
        assert d["error"] == "PII detected"
        assert d["fixed_value"] == "[REDACTED]"


# =============================================================================
# ValidationResult
# =============================================================================


class TestValidationResult:
    def test_failed_validators(self):
        r = ValidationResult(
            passed=False,
            outcomes=[
                ValidationOutcome(validator_name="a", passed=True),
                ValidationOutcome(validator_name="b", passed=False),
                ValidationOutcome(validator_name="c", passed=False),
            ],
            original_value="test",
            final_value="test",
            action_taken=FailAction.BLOCK,
        )
        assert r.failed_validators == ["b", "c"]

    def test_to_dict(self):
        r = ValidationResult(
            passed=True,
            outcomes=[ValidationOutcome(validator_name="a", passed=True)],
            original_value="x",
            final_value="x",
            action_taken=FailAction.BLOCK,
        )
        d = r.to_dict()
        assert d["passed"] is True
        assert d["action"] == "block"
        assert len(d["outcomes"]) == 1


# =============================================================================
# GuardrailsKernel
# =============================================================================


class TestGuardrailsKernel:
    def test_no_validators(self):
        k = GuardrailsKernel()
        r = k.validate("anything")
        assert r.passed

    def test_single_validator_pass(self):
        k = GuardrailsKernel(
            validators=[KeywordValidator(blocked_keywords=["DROP TABLE"])]
        )
        r = k.validate("Hello world")
        assert r.passed

    def test_single_validator_fail(self):
        k = GuardrailsKernel(
            validators=[KeywordValidator(blocked_keywords=["DROP TABLE"])],
            on_fail="block",
        )
        r = k.validate("DROP TABLE users")
        assert not r.passed
        assert r.action_taken == FailAction.BLOCK

    def test_multiple_validators(self):
        k = GuardrailsKernel(
            validators=[
                KeywordValidator(blocked_keywords=["SECRET"]),
                LengthValidator(max_length=1000),
                RegexValidator(patterns=[r"\d{3}-\d{2}-\d{4}"]),
            ]
        )
        # All pass
        assert k.validate("Hello world").passed
        # Keyword fails
        assert not k.validate("SECRET data").passed
        # Regex fails
        assert not k.validate("SSN 123-45-6789").passed

    def test_on_fail_warn(self):
        violations = []
        k = GuardrailsKernel(
            validators=[KeywordValidator(blocked_keywords=["bad"])],
            on_fail="warn",
            on_violation=lambda r: violations.append(r),
        )
        r = k.validate("bad content")
        assert not r.passed
        assert r.action_taken == FailAction.WARN
        assert len(violations) == 1

    def test_on_fail_fix(self):
        k = GuardrailsKernel(
            validators=[LengthValidator(max_length=5)],
            on_fail="fix",
        )
        r = k.validate("too long text")
        assert not r.passed
        assert r.action_taken == FailAction.FIX
        assert r.final_value == "too l"  # truncated to 5

    def test_validate_input(self):
        k = GuardrailsKernel(validators=[KeywordValidator(blocked_keywords=["hack"])])
        r = k.validate_input("try to hack the system")
        assert not r.passed

    def test_validate_output(self):
        k = GuardrailsKernel(validators=[KeywordValidator(blocked_keywords=["password"])])
        r = k.validate_output("your password is abc")
        assert not r.passed

    def test_add_validator(self):
        k = GuardrailsKernel()
        assert k.validate("SECRET").passed
        k.add_validator(KeywordValidator(blocked_keywords=["SECRET"]))
        assert not k.validate("SECRET").passed

    def test_history(self):
        k = GuardrailsKernel(validators=[KeywordValidator(blocked_keywords=["bad"])])
        k.validate("good")
        k.validate("bad")
        k.validate("good again")
        assert len(k.get_history()) == 3

    def test_stats(self):
        k = GuardrailsKernel(validators=[KeywordValidator(blocked_keywords=["bad"])])
        k.validate("good")
        k.validate("bad")
        k.validate("good")
        stats = k.get_stats()
        assert stats["total_validations"] == 3
        assert stats["passed"] == 2
        assert stats["failed"] == 1
        assert abs(stats["pass_rate"] - 2 / 3) < 0.01

    def test_reset(self):
        k = GuardrailsKernel(validators=[KeywordValidator(blocked_keywords=["x"])])
        k.validate("x")
        k.validate("y")
        k.reset()
        assert len(k.get_history()) == 0

    def test_validator_exception_handled(self):
        """Validator that throws should not crash the kernel."""

        class BrokenValidator:
            name = "broken"

            def validate(self, value, metadata=None):
                raise RuntimeError("boom")

        k = GuardrailsKernel(validators=[BrokenValidator()])
        r = k.validate("test")
        assert not r.passed
        assert "Validator error" in r.outcomes[0].error_message

    def test_guardrails_ai_compatible(self):
        """Simulate a Guardrails AI validator using duck typing."""

        class FakeGuardrailsResult:
            outcome = "fail"
            error_message = "PII detected"
            validated_output = "[REDACTED]"

        class FakeGuardrailsValidator:
            name = "pii_detector"

            def validate(self, value, metadata=None):
                if "SSN" in value:
                    return FakeGuardrailsResult()
                result = FakeGuardrailsResult()
                result.outcome = "pass"
                result.error_message = ""
                return result

        k = GuardrailsKernel(validators=[FakeGuardrailsValidator()])
        assert k.validate("Hello").passed
        r = k.validate("SSN 123")
        assert not r.passed
        assert r.outcomes[0].fixed_value == "[REDACTED]"


# =============================================================================
# Integration
# =============================================================================


class TestIntegration:
    def test_full_pipeline(self):
        """Simulate an agent input/output validation pipeline."""
        k = GuardrailsKernel(
            validators=[
                KeywordValidator(blocked_keywords=["DROP TABLE", "rm -rf"]),
                RegexValidator(patterns=[r"\d{3}-\d{2}-\d{4}"]),
                LengthValidator(max_length=5000),
            ],
            on_fail="block",
        )

        # Valid input
        r = k.validate_input("What is the weather in NYC?")
        assert r.passed

        # PII in input
        r = k.validate_input("My SSN is 123-45-6789")
        assert not r.passed

        # SQL injection
        r = k.validate_input("DROP TABLE users;")
        assert not r.passed

        # Valid output
        r = k.validate_output("The weather is sunny, 72°F")
        assert r.passed

        stats = k.get_stats()
        assert stats["total_validations"] == 4
        assert stats["passed"] == 2
        assert stats["failed"] == 2
