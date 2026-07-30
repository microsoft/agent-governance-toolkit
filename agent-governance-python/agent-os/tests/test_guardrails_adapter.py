# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Validator and host-behavior tests for the native Guardrails adapter."""

from __future__ import annotations

from typing import Any

from agt.policies import PolicyEvaluation

from agent_os.integrations.guardrails_adapter import (
    FailAction,
    GuardrailsKernel,
    KeywordValidator,
    LengthValidator,
    RegexValidator,
    ValidationOutcome,
    ValidationResult,
)


class _AllowRuntime:
    manifest = None

    def evaluate(
        self, intervention_point: str, snapshot: dict[str, Any]
    ) -> PolicyEvaluation:
        return PolicyEvaluation(
            verdict="allow",
            intervention_point=intervention_point,
        )

    def close(self) -> None:
        pass


def _kernel(*validators: Any, **kwargs: Any) -> GuardrailsKernel:
    return GuardrailsKernel(
        validators=list(validators),
        runtime=_AllowRuntime(),
        **kwargs,
    )


def test_regex_validator_matches_case_insensitively() -> None:
    validator = RegexValidator([r"secret-\d+"], validator_name="secret")

    assert validator.validate("safe").passed
    assert not validator.validate("SECRET-42").passed


def test_length_validator_enforces_maximum() -> None:
    validator = LengthValidator(max_length=5)

    assert validator.validate("12345").passed
    assert not validator.validate("123456").passed


def test_keyword_validator_matches_case_insensitively() -> None:
    validator = KeywordValidator(["blocked"])

    assert validator.validate("safe").passed
    assert not validator.validate("BLOCKED content").passed


def test_validation_result_reports_failed_validators() -> None:
    result = ValidationResult(
        passed=False,
        outcomes=[
            ValidationOutcome(validator_name="ok", passed=True),
            ValidationOutcome(
                validator_name="bad",
                passed=False,
                error_message="failed",
            ),
        ],
        original_value="value",
        final_value="value",
        action_taken=FailAction.BLOCK,
    )

    assert result.failed_validators == ["bad"]
    assert result.to_dict()["passed"] is False


def test_kernel_runs_local_validators_and_native_runtime() -> None:
    kernel = _kernel(KeywordValidator(["blocked"]))

    assert kernel.validate_input("safe").passed
    assert not kernel.validate_input("blocked").passed
    assert kernel.validate_output("safe").passed


def test_warn_mode_returns_failed_result_without_raising() -> None:
    kernel = _kernel(KeywordValidator(["blocked"]), on_fail="warn")

    result = kernel.validate_input("blocked")

    assert not result.passed
    assert result.final_value == "blocked"


def test_fix_mode_uses_validator_fix_value() -> None:
    class _FixingValidator:
        name = "fixer"

        def validate(self, value: str) -> ValidationOutcome:
            return ValidationOutcome(
                validator_name=self.name,
                passed=False,
                fixed_value="redacted",
            )

    result = _kernel(_FixingValidator(), on_fail="fix").validate_input("secret")

    assert result.final_value == "redacted"


def test_violation_callback_and_history_are_recorded() -> None:
    received: list[ValidationResult] = []
    kernel = _kernel(
        KeywordValidator(["blocked"]),
        on_violation=received.append,
    )

    result = kernel.validate_input("blocked")

    assert received == [result]
    assert kernel.get_history() == [result]
    assert kernel.get_stats()["failed"] == 1


def test_validator_exception_fails_closed() -> None:
    class _BrokenValidator:
        name = "broken"

        def validate(self, value: str) -> ValidationOutcome:
            raise RuntimeError("validator failed")

    result = _kernel(_BrokenValidator()).validate_input("value")

    assert not result.passed
    assert result.failed_validators == ["broken"]


def test_add_validator_and_reset() -> None:
    kernel = _kernel()
    kernel.add_validator(KeywordValidator(["blocked"]))
    kernel.validate_input("blocked")

    kernel.reset()

    assert kernel.get_history() == []
