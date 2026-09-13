# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Safe policy DSL evaluator.

The DSL is a pure data structure (parsed from YAML). It NEVER executes Python
and NEVER accesses attributes or calls. Supported nodes:

    all:  [cond, ...]         # logical AND
    any:  [cond, ...]         # logical OR
    not:  cond                # logical NOT

    eq:   [a, b]
    ne:   [a, b]
    gt:   [a, b]
    gte:  [a, b]
    lt:   [a, b]
    lte:  [a, b]
    in:   [needle, haystack]
    nin:  [needle, haystack]

Values are either literals (str, int, float, bool, None, list) or a single-key
mapping {"field": "path.to.value"} which is resolved against a whitelisted set
of roots (action, context, agent_id, timestamp). Path traversal is restricted
to string keys and integer indices — no attribute access, no calls.
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

# Whitelisted roots for `field` lookups
_ROOTS = ("action", "context", "agent_id", "timestamp")

# Maximum depth for path traversal
_MAX_PATH_DEPTH = 8


class PolicyError(ValueError):
    """Raised when a policy condition is malformed or not evaluable."""


def _resolve_field(path: str, env: Mapping[str, Any]) -> Any:
    """Resolve a dotted path against the whitelisted environment.

    Only string keys and integer indices are allowed. Attribute access and
    calls are structurally impossible because we only use Mapping/Sequence
    item access — never getattr().
    """
    if not isinstance(path, str) or not path:
        raise PolicyError(f"field path must be a non-empty string, got {path!r}")

    parts = path.split(".")
    if len(parts) > _MAX_PATH_DEPTH:
        raise PolicyError(f"field path too deep: {path!r}")

    root = parts[0]
    if root not in _ROOTS:
        raise PolicyError(f"unknown root '{root}' in path '{path}'")

    current: Any = env.get(root)
    for part in parts[1:]:
        if current is None:
            return None
        if isinstance(current, Mapping):
            current = current.get(part)
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
            try:
                idx = int(part)
            except ValueError as exc:
                raise PolicyError(
                    f"cannot index sequence with non-integer '{part}' in path '{path}'"
                ) from exc
            if idx < 0 or idx >= len(current):
                return None
            current = current[idx]
        else:
            # Cannot traverse further
            return None
    return current


def _is_field_ref(value: Any) -> bool:
    return isinstance(value, Mapping) and set(value.keys()) == {"field"}


def _resolve_value(value: Any, env: Mapping[str, Any]) -> Any:
    if _is_field_ref(value):
        return _resolve_field(value["field"], env)
    return value


def _as_pair(value: Any, op: str) -> tuple:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or len(value) != 2:
        raise PolicyError(f"operator '{op}' expects a list of exactly 2 items, got {value!r}")
    return value[0], value[1]


def _as_list(value: Any, op: str) -> List[Any]:
    if not isinstance(value, list):
        raise PolicyError(f"operator '{op}' expects a list, got {value!r}")
    return value


def _evaluate(node: Any, env: Mapping[str, Any]) -> bool:
    if not isinstance(node, Mapping):
        raise PolicyError(f"condition node must be a mapping, got {type(node).__name__}")

    if len(node) != 1:
        raise PolicyError(f"condition node must have exactly one key, got {list(node.keys())}")

    (op, operand), = node.items()

    if op == "all":
        return all(_evaluate(child, env) for child in _as_list(operand, op))
    if op == "any":
        return any(_evaluate(child, env) for child in _as_list(operand, op))
    if op == "not":
        return not _evaluate(operand, env)

    if op in ("eq", "ne", "gt", "gte", "lt", "lte", "in", "nin"):
        a_raw, b_raw = _as_pair(operand, op)
        a = _resolve_value(a_raw, env)
        b = _resolve_value(b_raw, env)

        if op == "eq":
            return a == b
        if op == "ne":
            return a != b
        if op == "gt":
            return _cmp(a, b, ">")
        if op == "gte":
            return _cmp(a, b, ">=")
        if op == "lt":
            return _cmp(a, b, "<")
        if op == "lte":
            return _cmp(a, b, "<=")
        if op == "in":
            return a in b
        if op == "nin":
            return a not in b

    raise PolicyError(f"unsupported operator '{op}'")


def _cmp(a: Any, b: Any, symbol: str) -> bool:
    """Comparison that refuses to compare across incompatible types."""
    if a is None or b is None:
        return False
    try:
        if symbol == ">":
            return a > b
        if symbol == ">=":
            return a >= b
        if symbol == "<":
            return a < b
        if symbol == "<=":
            return a <= b
    except TypeError:
        return False
    raise PolicyError(f"unsupported comparison '{symbol}'")


def evaluate_condition(condition: Any, env: Mapping[str, Any]) -> bool:
    """Public entry point. Raises PolicyError on malformed conditions."""
    return _evaluate(condition, env)


def build_env(decision, context: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Build the whitelisted environment passed to the evaluator."""
    return {
        "action": {
            "name": decision.action.name,
            "tool": decision.action.tool,
            "version": decision.action.version,
            "parameters": dict(decision.action.parameters or {}),
            "transaction_amount": decision.action.transaction_amount,
        },
        "context": dict(context or decision.context or {}),
        "agent_id": str(decision.agent_id),
        "timestamp": decision.timestamp,
    }
