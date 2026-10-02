# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Validator and host-behavior tests for the native Guardrails adapter."""

from __future__ import annotations

from typing import Any

from agent_control_specification import Decision, InterventionPointResult, Verdict

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

    async def evaluate_intervention_point(
        self, intervention_point, snapshot, mode=None
    ):
        return InterventionPointResult(verdict=Verdict(decision=Decision("allow")))

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


def test_validator_returning_none_fails_closed() -> None:
    """A validator that returns ``None`` carries no verdict at all.

    ``_run_validators`` duck-types third-party results. ``None`` must not be
    read as a pass, matching the exception handler that records an unusable
    validator as a failure.
    """

    class _ReturnsNoneValidator:
        name = "returns-none"

        def validate(self, value: str) -> Any:
            return None

    result = _kernel(_ReturnsNoneValidator()).validate_input("unsafe")

    assert not result.passed
    assert result.failed_validators == ["returns-none"]


def test_validator_result_without_outcome_keeps_its_error_message() -> None:
    """A non-conforming result that carries an error must not lose it."""

    class _ErrorOnlyResult:
        error_message = "this content is unsafe"

    class _ErrorOnlyValidator:
        name = "error-only"

        def validate(self, value: str) -> Any:
            return _ErrorOnlyResult()

    result = _kernel(_ErrorOnlyValidator()).validate_input("unsafe")

    assert not result.passed
    assert result.outcomes[0].error_message == "this content is unsafe"


def test_explicit_none_outcome_fails_closed_with_accurate_message() -> None:
    """``outcome`` present but ``None`` is also unusable.

    The attribute exists here, so the diagnostic must not claim it is missing.
    """

    class _NullOutcomeResult:
        outcome = None

    class _NullOutcomeValidator:
        name = "null-outcome"

        def validate(self, value: str) -> Any:
            return _NullOutcomeResult()

    result = _kernel(_NullOutcomeValidator()).validate_input("unsafe")

    assert not result.passed
    assert "missing or None" in result.outcomes[0].error_message


def test_conforming_duck_typed_results_are_unchanged() -> None:
    """Results that do satisfy the protocol keep their existing verdicts."""

    class _Conforming:
        def __init__(self, outcome: str) -> None:
            self.outcome = outcome
            self.error_message = "" if outcome == "pass" else "blocked"

    class _ConformingValidator:
        def __init__(self, outcome: str) -> None:
            self.name = f"conforming-{outcome}"
            self._outcome = outcome

        def validate(self, value: str) -> Any:
            return _Conforming(self._outcome)

    assert _kernel(_ConformingValidator("pass")).validate_input("x").passed
    assert not _kernel(_ConformingValidator("fail")).validate_input("x").passed
