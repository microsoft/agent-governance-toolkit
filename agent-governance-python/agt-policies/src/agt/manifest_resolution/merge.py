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


def _accepts_value(operator: str, expected: Any, value: Any) -> bool:
    try:
        if operator == "eq":
            return value == expected
        if operator == "gt":
            return value > expected
        if operator == "gte":
            return value >= expected
        if operator == "lt":
            return value < expected
        if operator == "lte":
            return value <= expected
        if operator == "in" and isinstance(expected, list):
            return value in expected
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
            if left_upper == right_lower and not (left_upper_inclusive and right_lower_inclusive):
                return False
        except TypeError:
            return False
    if right_upper is not None and left_lower is not None:
        try:
            if right_upper < left_lower:
                return False
            if right_upper == left_lower and not (right_upper_inclusive and left_lower_inclusive):
                return False
        except TypeError:
            return False
    return True


def _conditions_overlap(parent_condition: Any, child_condition: Any) -> bool:
    if _condition_key(parent_condition) == _condition_key(child_condition):
        return True
    if not isinstance(parent_condition, dict) or not isinstance(child_condition, dict):
        return False
    if parent_condition.get("field") != child_condition.get("field"):
        return False

    parent_operator = str(parent_condition.get("operator", "")).lower()
    child_operator = str(child_condition.get("operator", "")).lower()
    parent_value = parent_condition.get("value")
    child_value = child_condition.get("value")

    if parent_operator == "eq":
        return _accepts_value(child_operator, child_value, parent_value)
    if child_operator == "eq":
        return _accepts_value(parent_operator, parent_value, child_value)
    if parent_operator == "in" and isinstance(parent_value, list):
        return any(_accepts_value(child_operator, child_value, value) for value in parent_value)
    if child_operator == "in" and isinstance(child_value, list):
        return any(_accepts_value(parent_operator, parent_value, value) for value in child_value)

    parent_range = _range_bounds(parent_operator, parent_value)
    child_range = _range_bounds(child_operator, child_value)
    return parent_range is not None and child_range is not None and _ranges_overlap(parent_range, child_range)


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
                    and _conditions_overlap(deny_rule.get("condition"), rule.get("condition"))
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
