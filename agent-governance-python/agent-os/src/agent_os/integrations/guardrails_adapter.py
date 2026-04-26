# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Guardrails AI Bridge for Agent-OS
===================================

Bridges Guardrails AI validators with Agent-OS policy enforcement.

Agent-OS enforces your Guardrails AI validators at the kernel level —
policy violations trigger Agent-OS signals (SIGKILL, SIGPOLICYVIOLATION).

Works without importing guardrails — uses a Protocol interface so you can
plug in any validator that implements ``validate(value) -> ValidationOutcome``.

Example:
    >>> from agent_os.integrations.guardrails_adapter import GuardrailsKernel
    >>>
    >>> kernel = GuardrailsKernel(
    ...     validators=[PIIValidator(), ToxicityValidator()],
    ...     on_fail="block",  # or "warn", "fix"
    ... )
    >>>
    >>> result = kernel.validate_input("My SSN is 123-45-6789")
    >>> assert not result.passed  # PII detected
    >>>
    >>> result = kernel.validate_output("Safe response text")
    >>> assert result.passed
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Validator Protocol (no guardrails import required)
# ------------------------------------------------------------------


class FailAction(str, Enum):
    """What to do when a validator fails."""

    BLOCK = "block"
    WARN = "warn"
    FIX = "fix"


@runtime_checkable
class ValidatorProtocol(Protocol):
    """
    Protocol for Guardrails AI validators (or any compatible validator).

    A validator must implement ``validate(value, metadata)`` and return
    a ``ValidationResult``-like object with ``outcome`` and ``error_message``.
    """

    @property
    def name(self) -> str: ...

    def validate(self, value: str, metadata: dict[str, Any] | None = None) -> Any: ...


@dataclass
class ValidationOutcome:
    """Result of a single validator check."""

    validator_name: str
    passed: bool
    error_message: str = ""
    fixed_value: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise this outcome to a plain dictionary.

        Returns:
            A dict with validator, passed, and optionally error
            and fixed_value keys.
        """
        d: dict[str, Any] = {
            "validator": self.validator_name,
            "passed": self.passed,
        }
        if self.error_message:
            d["error"] = self.error_message
        if self.fixed_value is not None:
            d["fixed_value"] = self.fixed_value
        return d


@dataclass
class ValidationResult:
    """Aggregated result across all validators."""

    passed: bool
    outcomes: list[ValidationOutcome]
    original_value: str
    final_value: str
    action_taken: FailAction
    timestamp: float = field(default_factory=time.time)

    @property
    def failed_validators(self) -> list[str]:
        """Return the names of all validators that did not pass.

        Returns:
            List of validator name strings where passed is False.
        """
        return [o.validator_name for o in self.outcomes if not o.passed]

    def to_dict(self) -> dict[str, Any]:
        """Serialise this aggregated result to a plain dictionary.

        Returns:
            A dict with passed, action, outcomes, and failed_validators keys.
        """
        return {
            "passed": self.passed,
            "action": self.action_taken.value,
            "outcomes": [o.to_dict() for o in self.outcomes],
            "failed_validators": self.failed_validators,
        }


# ------------------------------------------------------------------
# Built-in simple validators (no guardrails dependency)
# ------------------------------------------------------------------


class RegexValidator:
    """Block content matching regex patterns."""

    def __init__(self, patterns: list[str], validator_name: str = "regex"):
        import re

        self._patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        self._name = validator_name

    @property
    def name(self) -> str:
        """Return the human-readable name of this regex validator.

        Returns:
            The validator name string used in audit logs and outcomes.
        """
        return self._name

    def validate(self, value: str, metadata: dict[str, Any] | None = None) -> ValidationOutcome:
        """Validate a string by checking it against blocked regex patterns.

        Args:
            value: The text to scan.
            metadata: Optional dict of additional context (unused).

        Returns:
            ValidationOutcome indicating pass or fail.
        """

        for pattern in self._patterns:
            match = pattern.search(value)
            if match:
                return ValidationOutcome(
                    validator_name=self._name,
                    passed=False,
                    error_message=f"Content matches blocked pattern: {match.group()}",
                )
        return ValidationOutcome(validator_name=self._name, passed=True)


class LengthValidator:
    """Enforce content length limits."""

    def __init__(self, max_length: int = 10000, validator_name: str = "length"):
        self._max_length = max_length
        self._name = validator_name

    @property
    def name(self) -> str:
        """Return the human-readable name of this length validator.

        Returns:
            The validator name string used in audit logs and outcomes.
        """
        return self._name

    def validate(self, value: str, metadata: dict[str, Any] | None = None) -> ValidationOutcome:
        """Validate that a string does not exceed the configured max length.

        Args:
            value: The text to check.
            metadata: Optional dict of additional context (unused).

        Returns:
            ValidationOutcome with a fixed_value truncated to max_length on fail.
        """
        if len(value) > self._max_length:
            return ValidationOutcome(
                validator_name=self._name,
                passed=False,
                error_message=f"Content length {len(value)} exceeds max {self._max_length}",
                fixed_value=value[: self._max_length],
            )
        return ValidationOutcome(validator_name=self._name, passed=True)


class KeywordValidator:
    """Block content containing specific keywords."""

    def __init__(self, blocked_keywords: list[str], validator_name: str = "keywords"):
        self._keywords = [k.lower() for k in blocked_keywords]
        self._name = validator_name

    @property
    def name(self) -> str:
        """Return the human-readable name of this keyword validator.

        Returns:
            The validator name string used in audit logs and outcomes.
        """
        return self._name

    def validate(self, value: str, metadata: dict[str, Any] | None = None) -> ValidationOutcome:
        """Validate that a string contains none of the blocked keywords.

        Args:
            value: The text to scan (case-insensitive).
            metadata: Optional dict of additional context (unused).

        Returns:
            ValidationOutcome indicating pass or fail.
        """
        value_lower = value.lower()
        for kw in self._keywords:
            if kw in value_lower:
                return ValidationOutcome(
                    validator_name=self._name,
                    passed=False,
                    error_message=f"Content contains blocked keyword: '{kw}'",
                )
        return ValidationOutcome(validator_name=self._name, passed=True)


# ------------------------------------------------------------------
# Guardrails Kernel
# ------------------------------------------------------------------


class GuardrailsKernel:
    """
    Agent-OS governance kernel backed by Guardrails AI validators.

    Validates inputs and outputs against a chain of validators.
    Failed validations are recorded and trigger configurable actions.
    """

    def __init__(
        self,
        validators: list[Any] | None = None,
        on_fail: str = "block",
        on_violation: Callable[[ValidationResult], None] | None = None,
    ):
        self._validators: list[Any] = validators or []
        self.on_fail = FailAction(on_fail)
        self.on_violation = on_violation or self._default_violation_handler
        self._history: list[ValidationResult] = []

    def _default_violation_handler(self, result: ValidationResult) -> None:
        """Default handler called when one or more validators fail.

        Logs a warning for each failed validator name. Override by
        passing a custom on_violation callable to GuardrailsKernel.

        Args:
            result: The aggregated ValidationResult.
        """
        for name in result.failed_validators:
            logger.warning(f"Guardrail violation: {name}")

    def add_validator(self, validator: Any) -> None:
        """Add a validator to the chain."""
        self._validators.append(validator)

    def _run_validators(self, value: str) -> list[ValidationOutcome]:
        """Run all validators against a value."""
        outcomes = []
        for v in self._validators:
            try:
                result = v.validate(value)
                # Handle both our ValidationOutcome and Guardrails AI objects
                if isinstance(result, ValidationOutcome):
                    outcomes.append(result)
                else:
                    # Duck-type: expect .outcome / .validated_output / .error_message
                    passed = getattr(result, "outcome", "pass") == "pass"
                    error_msg = getattr(result, "error_message", "")
                    fixed = getattr(result, "validated_output", None)
                    outcomes.append(
                        ValidationOutcome(
                            validator_name=getattr(v, "name", type(v).__name__),
                            passed=passed,
                            error_message=str(error_msg) if error_msg else "",
                            fixed_value=fixed,
                        )
                    )
            except Exception as e:
                outcomes.append(
                    ValidationOutcome(
                        validator_name=getattr(v, "name", type(v).__name__),
                        passed=False,
                        error_message=f"Validator error: {e}",
                    )
                )
        return outcomes

    def validate(self, value: str) -> ValidationResult:
        """
        Validate a value against all validators.

        Returns a ValidationResult with aggregated outcomes and the action taken.
        """
        outcomes = self._run_validators(value)
        all_passed = all(o.passed for o in outcomes)
        final_value = value

        action = FailAction.BLOCK  # default
        if all_passed:
            action = FailAction.BLOCK  # no action needed
        else:
            action = self.on_fail
            if action == FailAction.FIX:
                # Apply fixes from validators that provide them
                for o in outcomes:
                    if not o.passed and o.fixed_value is not None:
                        final_value = o.fixed_value

        result = ValidationResult(
            passed=all_passed,
            outcomes=outcomes,
            original_value=value,
            final_value=final_value,
            action_taken=action if not all_passed else FailAction.BLOCK,
        )
        self._history.append(result)

        if not all_passed:
            self.on_violation(result)

        return result

    def validate_input(self, text: str) -> ValidationResult:
        """Validate agent input (user query, tool arguments, etc.)."""
        return self.validate(text)

    def validate_output(self, text: str) -> ValidationResult:
        """Validate agent output (response text, tool results, etc.)."""
        return self.validate(text)

    def get_history(self) -> list[ValidationResult]:
        """Return all validation results."""
        return list(self._history)

    def get_stats(self) -> dict[str, Any]:
        """Return guardrails statistics."""
        total = len(self._history)
        passed = sum(1 for r in self._history if r.passed)
        return {
            "total_validations": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate": passed / total if total > 0 else 1.0,
            "validators": [getattr(v, "name", type(v).__name__) for v in self._validators],
        }

    def reset(self) -> None:
        """Clear validation history."""
        self._history.clear()


__all__ = [
    "GuardrailsKernel",
    "ValidationResult",
    "ValidationOutcome",
    "FailAction",
    "ValidatorProtocol",
    "RegexValidator",
    "LengthValidator",
    "KeywordValidator",
]
