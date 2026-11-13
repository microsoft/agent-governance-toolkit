# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trust Policy DSL

Declarative trust policy definitions with rule-based evaluation,
priority ordering, and YAML configuration support.
"""

import re
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from pydantic import BaseModel, Field, model_validator

try:  # Python 3.11+
    from re import _parser as _sre_parse  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - older Pythons
    import sre_parse as _sre_parse  # type: ignore[no-redef]

# V31: longest regex a `matches` condition may carry.
_MAX_PATTERN_LENGTH = 200

# Longest subject a `matches` condition will evaluate against. This does NOT
# bound residual polynomial backtracking (e.g. a*a*a*a*a*b is still slow well
# below any practical cap); it only shrinks the attack surface. Trust-policy
# subjects are agent ids / namespaces, so 1024 is already generous.
_MAX_SUBJECT_LENGTH = 1024

# Most variable-width quantifiers (min != max: *, +, ?, {m,n}) a pattern may
# contain. Exponential blowup does not require nesting: ^a?a?...a?aaa...a$ is
# 2^n against a short subject and passes the nesting guard, and long chains of
# adjacent variable quantifiers (a{1,100}a{1,100}...) drive the polynomial
# degree. 16 comfortably fits real patterns (an IPv4 matcher uses 4).
_MAX_VARIABLE_QUANTIFIERS = 16


class ConditionEvaluationError(ValueError):
    """A condition could not be evaluated safely.

    Raised instead of returning a boolean so the caller can fail closed:
    mapping an unevaluable condition to "no match" would let an oversized
    or malformed input silently disarm a deny rule. ``PolicyEvaluator``
    converts this into a deny decision.
    """


def _contains_ambiguity(subpattern) -> bool:
    """Whether subpattern contains a variable-width repeat, an alternation,
    or a conditional group reference.

    Variable-width means ``min != max`` — this includes ``?`` ({0,1}), which a
    ``max != 1`` test would miss even though ``(a?a?){1,30}`` backtracks
    exponentially. A fixed-width repeat (``{3}``) of unambiguous content is
    fine, so recursion decides for those.
    """
    for op, arg in subpattern:
        name = str(op)
        if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            min_count, max_count, body = arg
            if min_count != max_count or _contains_ambiguity(body):
                return True
        elif name in ("BRANCH", "GROUPREF_EXISTS"):
            return True
        elif name == "SUBPATTERN":
            if _contains_ambiguity(arg[3]):
                return True
        elif name in ("ASSERT", "ASSERT_NOT"):
            if _contains_ambiguity(arg[1]):
                return True
        elif name == "ATOMIC_GROUP":
            if _contains_ambiguity(arg):
                return True
    return False


def _has_catastrophic_repeat(subpattern) -> bool:
    """Whether any repeat with max > 1 has a body that can itself branch.

    That is the structural shape behind catastrophic backtracking: an outer
    quantifier whose body offers more than one way to consume the same text —
    a nested variable-width quantifier (``(a+)+``, ``(a{1,5}){1,5}``,
    ``(\\d{1,3}\\.?){1,40}``, ``(a?a?){1,30}``) or an alternation
    (``(a|aa){1,40}``). A repeat whose body is unambiguous (``[0-9]{4}``,
    ``(ab){2,3}``) is fine.
    """
    for op, arg in subpattern:
        name = str(op)
        if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            _, max_count, body = arg
            if max_count != 1 and _contains_ambiguity(body):
                return True
            if _has_catastrophic_repeat(body):
                return True
        elif name == "BRANCH":
            for branch in arg[1]:
                if _has_catastrophic_repeat(branch):
                    return True
        elif name == "SUBPATTERN":
            if _has_catastrophic_repeat(arg[3]):
                return True
        elif name in ("ASSERT", "ASSERT_NOT"):
            if _has_catastrophic_repeat(arg[1]):
                return True
        elif name == "ATOMIC_GROUP":
            if _has_catastrophic_repeat(arg):
                return True
    return False


def _count_variable_repeats(subpattern) -> int:
    """Count quantifiers whose width is variable (min != max) in the tree."""
    total = 0
    for op, arg in subpattern:
        name = str(op)
        if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            min_count, max_count, body = arg
            if min_count != max_count:
                total += 1
            total += _count_variable_repeats(body)
        elif name == "BRANCH":
            for branch in arg[1]:
                total += _count_variable_repeats(branch)
        elif name == "SUBPATTERN":
            total += _count_variable_repeats(arg[3])
        elif name in ("ASSERT", "ASSERT_NOT"):
            total += _count_variable_repeats(arg[1])
        elif name == "ATOMIC_GROUP":
            total += _count_variable_repeats(arg)
    return total


def validate_matches_pattern(pattern: str) -> None:
    """Validate the regex of a ``matches`` condition, raising ``ValueError``.

    Rejects patterns that cannot work at evaluation time, so a bad policy
    fails when it is loaded instead of its rule silently never firing:
    over-long patterns, invalid regexes, patterns whose structure can
    backtrack catastrophically (see ``_has_catastrophic_repeat``), and
    patterns stacking more variable-width quantifiers than
    ``_MAX_VARIABLE_QUANTIFIERS`` (non-nested exponential/polynomial shapes).

    This is best-effort hardening against the known catastrophic shapes, not
    a proof of linear matching; the subject-length cap at evaluation time
    shrinks, but does not eliminate, the residual polynomial surface.
    """
    if len(pattern) > _MAX_PATTERN_LENGTH:
        raise ValueError(
            f"matches pattern is {len(pattern)} characters; the limit is {_MAX_PATTERN_LENGTH}"
        )
    try:
        parsed = _sre_parse.parse(pattern)
    except re.error as exc:
        raise ValueError(f"matches pattern is not a valid regex: {exc}") from exc
    if _has_catastrophic_repeat(parsed):
        raise ValueError(
            "matches pattern can backtrack catastrophically: a quantifier is"
            " applied to a group that itself contains a quantifier or an"
            " alternation (e.g. (a+)+, (a{1,5}){1,5}, (a|aa){1,40});"
            " rewrite the pattern without the nesting"
        )
    if (count := _count_variable_repeats(parsed)) > _MAX_VARIABLE_QUANTIFIERS:
        raise ValueError(
            f"matches pattern stacks {count} variable-width quantifiers; the"
            f" limit is {_MAX_VARIABLE_QUANTIFIERS}. Long chains of *, +, ?"
            " or {m,n} backtrack exponentially/polynomially even without"
            " nesting (e.g. a?a?...a?aaa...a)"
        )


class ConditionOperator(str, Enum):
    """Supported condition operators for trust rules."""

    eq = "eq"
    ne = "ne"
    gt = "gt"
    gte = "gte"
    lt = "lt"
    lte = "lte"
    in_ = "in"
    not_in = "not_in"
    matches = "matches"


class TrustCondition(BaseModel):
    """A single condition in a trust rule.

    Attributes:
        field: Dot-notated path to a context value
            (e.g. ``"trust_score"``, ``"agent.namespace"``).
        operator: Comparison operator to apply.
        value: Expected value to compare against.
    """

    field: str = Field(..., description="Dot-notated field path (e.g. 'trust_score', 'agent.namespace')")
    operator: ConditionOperator = Field(..., description="Comparison operator")
    value: Any = Field(..., description="Value to compare against")

    @model_validator(mode="after")
    def _validate_matches_value(self) -> "TrustCondition":
        # A rejected pattern used to surface only at evaluation time, as a
        # silent False — a deny rule that never fires. Fail at load instead.
        if self.operator == ConditionOperator.matches:
            validate_matches_pattern(str(self.value))
        return self

    def evaluate(self, context: dict) -> bool:
        """Evaluate this condition against a context dictionary.

        Args:
            context: Runtime context with values accessible via
                dot-notated field paths.

        Returns:
            ``True`` if the condition is satisfied.
        """
        actual = self._resolve_field(context, self.field)
        return self._apply_operator(actual, self.operator, self.value)

    @staticmethod
    def _resolve_field(context: dict, field: str) -> Any:
        """Resolve a dot-notated field path against a context dict."""
        parts = field.split(".")
        current: Any = context
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    @staticmethod
    def _apply_operator(actual: Any, operator: ConditionOperator, expected: Any) -> bool:
        """Apply a comparison operator."""
        if actual is None:
            return False

        if operator == ConditionOperator.eq:
            return actual == expected
        elif operator == ConditionOperator.ne:
            return actual != expected
        elif operator == ConditionOperator.gt:
            return actual > expected
        elif operator == ConditionOperator.gte:
            return actual >= expected
        elif operator == ConditionOperator.lt:
            return actual < expected
        elif operator == ConditionOperator.lte:
            return actual <= expected
        elif operator == ConditionOperator.in_:
            return actual in expected
        elif operator == ConditionOperator.not_in:
            return actual not in expected
        elif operator == ConditionOperator.matches:
            pattern = str(expected)
            # V31: a condition built through the model is validated at load
            # time (_validate_matches_value); re-check here as defense in
            # depth for a value mutated after construction or a direct call.
            # Raise rather than return False: "no match" would silently
            # disarm a deny rule built on this condition (fail-open).
            try:
                validate_matches_pattern(pattern)
            except ValueError as exc:
                raise ConditionEvaluationError(str(exc)) from exc
            # Cap the subject as a mitigation, not a bound: a few adjacent
            # overlapping quantifiers (a*a*a*b) can still be slow well below
            # any practical cap, and exponential shapes are pattern-driven.
            # The pattern-side guards (nesting rejection + the variable-
            # quantifier ceiling) target those; this cap only shrinks the
            # residual polynomial surface, and trust-policy subjects (agent
            # ids, namespaces) are far shorter anyway. Raising (not returning
            # False) keeps an oversized subject from bypassing a deny rule;
            # the evaluator fails closed.
            subject = str(actual)
            if len(subject) > _MAX_SUBJECT_LENGTH:
                raise ConditionEvaluationError(
                    f"matches subject is {len(subject)} characters; the limit is {_MAX_SUBJECT_LENGTH}"
                )
            try:
                return bool(re.search(pattern, subject, flags=re.DOTALL))
            except re.error as exc:  # pragma: no cover - caught by validation above
                raise ConditionEvaluationError(str(exc)) from exc
        return False


class TrustRule(BaseModel):
    """A single trust policy rule with condition, action, and priority.

    Attributes:
        name: Unique rule name.
        description: Human-readable description of what the rule does.
        condition: The ``TrustCondition`` to evaluate.
        action: Action to take when the condition matches
            (allow, deny, warn, or require_approval).
        priority: Evaluation priority (lower number = higher priority).
    """

    name: str = Field(..., description="Rule name")
    description: Optional[str] = Field(None, description="Human-readable description")
    condition: TrustCondition = Field(..., description="Condition to evaluate")
    action: Literal["allow", "deny", "warn", "require_approval"] = Field(
        default="deny", description="Action when condition matches"
    )
    priority: int = Field(default=100, description="Priority (lower number = higher priority)")


class TrustDefaults(BaseModel):
    """Default trust policy parameters applied when no rule matches."""

    min_trust_score: int = Field(default=500, description="Minimum trust score required")
    max_delegation_depth: int = Field(default=3, description="Maximum scope chain depth")
    allowed_namespaces: list[str] = Field(
        default_factory=lambda: ["*"], description="Allowed agent namespaces"
    )
    require_handshake: bool = Field(default=True, description="Require trust handshake")


class TrustPolicy(BaseModel):
    """
    A declarative trust policy with rules and defaults.

    Policies can be loaded from and saved to YAML files for easy configuration.
    """

    name: str = Field(..., description="Policy name")
    version: str = Field(default="1.0", description="Policy version")
    description: Optional[str] = Field(None, description="Policy description")
    rules: list[TrustRule] = Field(default_factory=list, description="Ordered list of trust rules")
    defaults: TrustDefaults = Field(
        default_factory=TrustDefaults, description="Default trust parameters"
    )

    @classmethod
    def from_yaml(cls, path: str | Path) -> "TrustPolicy":
        """Load a TrustPolicy from a YAML file.

        Args:
            path: Path to the YAML policy file.

        Returns:
            A fully-constructed ``TrustPolicy`` instance.
        """
        path = Path(path)
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(**data)

    def to_yaml(self, path: str | Path) -> None:
        """Save this TrustPolicy to a YAML file.

        Args:
            path: Destination file path.
        """
        path = Path(path)
        data = self.model_dump(mode="json")
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def load_policies(directory: str | Path) -> list[TrustPolicy]:
    """Load all YAML trust policies from a directory.

    Scans for ``*.yaml`` and ``*.yml`` files in sorted order.

    Args:
        directory: Path to the directory containing policy files.

    Returns:
        List of ``TrustPolicy`` instances loaded from the directory.
    """
    directory = Path(directory)
    policies: list[TrustPolicy] = []
    for yaml_file in sorted(directory.glob("*.yaml")):
        policies.append(TrustPolicy.from_yaml(yaml_file))
    for yml_file in sorted(directory.glob("*.yml")):
        policies.append(TrustPolicy.from_yaml(yml_file))
    return policies
