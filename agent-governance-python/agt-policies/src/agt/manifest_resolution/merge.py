# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Per AGT-RESOLUTION §2.4 merge.

Merges a chain of pre-loaded governance dictionaries (root-first
order) into a single flat rule list, with two security invariants:

1. **Deny immutability.** A child rule with ``override: true`` whose
   name collides with a parent rule of action ``deny`` is dropped.
   A child ``allow`` whose condition overlaps a parent ``deny`` is also
   dropped, regardless of name or priority. This is the AGT analog of
   Azure Policy's deny-assignment immutability and prevents a
   more-specific manifest from silently neutralising an org-level deny.

2. **Same-name without override is dropped.** Without this, a child
   rule with higher priority would win at engine evaluation time even
   though it never declared an override intent.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .errors import ResolutionError

logger = logging.getLogger(__name__)


def _rule_action(rule: dict[str, Any]) -> str:
    return str(rule.get("action", "")).lower()


def _condition_key(condition: Any) -> str:
    return json.dumps(condition, sort_keys=True, separators=(",", ":"), default=str)


def _condition_parts(condition: dict[str, Any]) -> tuple[str, str, Any] | None:
    field = condition.get("field")
    operator = condition.get("operator")
    if not isinstance(field, str) or not field or not isinstance(operator, str):
        return None
    return field, operator.lower(), condition.get("value")


def _compound_items(condition: dict[str, Any], key: str) -> list[Any] | None:
    value = condition.get(key)
    if isinstance(value, list):
        return value
    return None


_VALUE_TEST_OPERATORS = {
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "not_in",
    "contains",
    "startswith",
    "endswith",
}


def _accepts_value(operator: str, expected: Any, value: Any) -> bool:
    try:
        if operator == "eq":
            return value == expected
        if operator == "ne":
            return value is not None and value != expected
        if operator == "gt":
            return value is not None and value > expected
        if operator == "gte":
            return value is not None and value >= expected
        if operator == "lt":
            return value is not None and value < expected
        if operator == "lte":
            return value is not None and value <= expected
        if operator == "in" and isinstance(expected, list):
            return value is not None and value in expected
        if operator == "not_in" and isinstance(expected, list):
            return value is not None and value not in expected
        if operator == "contains":
            return value is not None and expected in value
        if operator == "startswith":
            return (
                isinstance(value, str)
                and isinstance(expected, str)
                and value.startswith(expected)
            )
        if operator == "endswith":
            return (
                isinstance(value, str)
                and isinstance(expected, str)
                and value.endswith(expected)
            )
    except TypeError:
        return False
    return False


def _range_bounds(operator: str, value: Any) -> tuple[Any, bool, Any, bool] | None:
    if operator == "gt":
        return value, False, None, False
    if operator == "gte":
        return value, True, None, False
    if operator == "lt":
        return None, False, value, False
    if operator == "lte":
        return None, False, value, True
    return None


def _ranges_overlap(
    left: tuple[Any, bool, Any, bool],
    right: tuple[Any, bool, Any, bool],
) -> bool:
    left_lower, left_lower_inclusive, left_upper, left_upper_inclusive = left
    right_lower, right_lower_inclusive, right_upper, right_upper_inclusive = right

    if left_upper is not None and right_lower is not None:
        try:
            if left_upper < right_lower:
                return False
            if left_upper == right_lower and not (
                left_upper_inclusive and right_lower_inclusive
            ):
                return False
        except TypeError:
            return True
    if right_upper is not None and left_lower is not None:
        try:
            if right_upper < left_lower:
                return False
            if right_upper == left_lower and not (
                right_upper_inclusive and left_lower_inclusive
            ):
                return False
        except TypeError:
            return True
    return True


def _all_values_in(values: list[Any], excluded: list[Any]) -> bool:
    return all(
        any(value == excluded_value for excluded_value in excluded) for value in values
    )


def _scalar_conditions_disjoint(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_parts = _condition_parts(left)
    right_parts = _condition_parts(right)
    if left_parts is None or right_parts is None:
        return False

    left_field, left_operator, left_value = left_parts
    right_field, right_operator, right_value = right_parts
    if left_field != right_field:
        return False

    if left_operator == "exists" or right_operator == "exists":
        return False
    if left_operator in {"matches", "regex"} or right_operator in {"matches", "regex"}:
        return False

    if left_operator == "eq":
        if right_operator not in _VALUE_TEST_OPERATORS:
            return False
        return not _accepts_value(right_operator, right_value, left_value)
    if right_operator == "eq":
        if left_operator not in _VALUE_TEST_OPERATORS:
            return False
        return not _accepts_value(left_operator, left_value, right_value)

    if left_operator == "in" and isinstance(left_value, list):
        if not left_value:
            return True
        if right_operator not in _VALUE_TEST_OPERATORS:
            return False
        return not any(
            _accepts_value(right_operator, right_value, value) for value in left_value
        )
    if right_operator == "in" and isinstance(right_value, list):
        if not right_value:
            return True
        if left_operator not in _VALUE_TEST_OPERATORS:
            return False
        return not any(
            _accepts_value(left_operator, left_value, value) for value in right_value
        )

    if left_operator == "not_in" and isinstance(left_value, list):
        if right_operator == "not_in" and isinstance(right_value, list):
            return False
        if right_operator == "in" and isinstance(right_value, list):
            return _all_values_in(right_value, left_value)
    if right_operator == "not_in" and isinstance(right_value, list):
        if left_operator == "in" and isinstance(left_value, list):
            return _all_values_in(left_value, right_value)

    if left_operator == "contains" and right_operator == "contains":
        return False
    if left_operator in {"contains", "startswith", "endswith"} or right_operator in {
        "contains",
        "startswith",
        "endswith",
    }:
        return False

    if left_operator == "ne" and right_operator == "ne":
        return False

    left_range = _range_bounds(left_operator, left_value)
    right_range = _range_bounds(right_operator, right_value)
    if left_range is not None and right_range is not None:
        return not _ranges_overlap(left_range, right_range)

    return False


def _condition_unsatisfiable(condition: Any) -> bool:
    if not isinstance(condition, dict):
        return False
    and_items = _compound_items(condition, "and")
    if and_items is not None:
        return any(_condition_unsatisfiable(item) for item in and_items) or any(
            _conditions_disjoint(left, right)
            for index, left in enumerate(and_items)
            for right in and_items[index + 1 :]
        )
    or_items = _compound_items(condition, "or")
    if or_items is not None:
        return not or_items or all(_condition_unsatisfiable(item) for item in or_items)
    if "not" in condition:
        return False
    parts = _condition_parts(condition)
    return parts is not None and parts[1] == "in" and condition.get("value") == []


def _conditions_disjoint(left: Any, right: Any) -> bool:
    if _condition_unsatisfiable(left) or _condition_unsatisfiable(right):
        return True
    if not isinstance(left, dict) or not isinstance(right, dict):
        return False

    left_or = _compound_items(left, "or")
    if left_or is not None:
        return all(_conditions_disjoint(item, right) for item in left_or)
    right_or = _compound_items(right, "or")
    if right_or is not None:
        return all(_conditions_disjoint(left, item) for item in right_or)

    left_and = _compound_items(left, "and")
    if left_and is not None:
        return any(_conditions_disjoint(item, right) for item in left_and)
    right_and = _compound_items(right, "and")
    if right_and is not None:
        return any(_conditions_disjoint(left, item) for item in right_and)

    if "not" in left or "not" in right:
        return False

    return _scalar_conditions_disjoint(left, right)


def _conditions_overlap(parent_condition: Any, child_condition: Any) -> bool:
    if _condition_key(parent_condition) == _condition_key(child_condition):
        return True
    return not _conditions_disjoint(parent_condition, child_condition)


def merge_documents(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge governance documents into a flat priority-sorted rule list.

    Args:
        documents: Parsed governance documents in **root-first** order.
            The root document is at index 0, the most-specific document
            at index -1.

    Returns:
        Flat rule list sorted by priority descending. Each rule is a
        plain dict carrying its original fields (``name``, ``condition``,
        ``action``, ``priority``, ``message``, ``override``).

    Raises:
        ResolutionError: ``INVALID_GOVERNANCE`` when a document is not
            a dict or any rule is malformed at the merge layer's level
            of inspection. Deeper schema validation is the engine's job.
    """
    if not documents:
        return []

    for level, doc in enumerate(documents):
        if not isinstance(doc, dict):
            raise ResolutionError.invalid_governance(
                f"document at level {level} is not a mapping"
            )
        for rule in doc.get("rules", []):
            if not isinstance(rule, dict) or "name" not in rule:
                raise ResolutionError.invalid_governance(
                    f"rule at level {level} is missing name"
                )

    if len(documents) == 1:
        rules = list(documents[0].get("rules", []))
        rules.sort(key=lambda r: r.get("priority", 0), reverse=True)
        return rules

    rules_by_name: dict[str, tuple[dict[str, Any], int]] = {}
    parent_denies: list[tuple[dict[str, Any], int]] = []
    merged: list[dict[str, Any]] = []

    for level, doc in enumerate(documents):
        for rule in doc.get("rules", []):
            name = str(rule["name"])
            existing = rules_by_name.get(name)
            override = bool(rule.get("override", False))

            blocking_deny = next(
                (
                    deny_rule
                    for deny_rule, deny_level in parent_denies
                    if deny_level < level
                    and _rule_action(rule) == "allow"
                    and _conditions_overlap(
                        deny_rule.get("condition"), rule.get("condition")
                    )
                ),
                None,
            )
            if blocking_deny is not None:
                logger.warning(
                    "allow rule %r at level %d overlaps parent deny %r; dropped",
                    name,
                    level,
                    blocking_deny.get("name"),
                )
                continue

            if existing is not None and override:
                parent_rule, _ = existing
                if _rule_action(parent_rule) == "deny":
                    logger.warning(
                        "rule %r at level %d tried to override parent deny; dropped",
                        name,
                        level,
                    )
                    continue
                merged = [r for r in merged if r.get("name") != name]
                merged.append(rule)
                rules_by_name[name] = (rule, level)
                if _rule_action(rule) == "deny":
                    parent_denies.append((rule, level))
                continue

            if existing is not None:
                logger.debug(
                    "rule %r at level %d duplicates parent without override=true; dropped",
                    name,
                    level,
                )
                continue

            merged.append(rule)
            rules_by_name[name] = (rule, level)
            if _rule_action(rule) == "deny":
                parent_denies.append((rule, level))

    merged.sort(key=lambda r: r.get("priority", 0), reverse=True)
    return merged


def merge_top_level_section(
    section_name: str,
    documents: list[dict[str, Any]],
) -> Any:
    """Merge a top-level governance section across documents (last writer wins).

    Used for sections like ``tools``, ``annotators``, ``policies``,
    ``limits``, ``approval`` where AGT-RESOLUTION specifies the most-
    specific document overrides earlier ones. Non-rule sections do not
    have the deny-immutability invariant.

    Args:
        section_name: Top-level key to merge.
        documents: Documents in root-first order.

    Returns:
        Merged value, or ``None`` when no document carries the section.

    Raises:
        ResolutionError: ``MERGE_CONFLICT`` when the values across
            documents are non-mergeable (e.g., a dict in one and a list
            in another).
    """
    merged: Any = None

    for doc in documents:
        if section_name not in doc:
            continue
        value = doc[section_name]
        if merged is None:
            merged = value
            continue

        if isinstance(merged, dict) and isinstance(value, dict):
            merged = {**merged, **value}
            continue
        if isinstance(merged, list) and isinstance(value, list):
            merged = [*merged, *value]
            continue
        if type(merged) is type(value):
            merged = value
            continue
        raise ResolutionError.merge_conflict(
            f"section '{section_name}' has incompatible types across documents"
        )

    return merged
