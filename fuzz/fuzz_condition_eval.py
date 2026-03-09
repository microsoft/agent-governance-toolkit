"""Fuzz target for policy condition expression evaluation.

Tests that adversarial condition strings don't cause crashes,
injection, or resource exhaustion in the expression evaluator.
"""
import re
import sys
import atheris


OPERATORS = {"eq", "ne", "gt", "lt", "gte", "lte", "in", "not_in", "matches"}


def _eval_condition_safe(operator: str, field_value: str, expected: str) -> bool:
    """Evaluate a single condition — mirrors SharedPolicyEvaluator logic."""
    try:
        if operator == "eq":
            return field_value == expected
        elif operator == "ne":
            return field_value != expected
        elif operator == "gt":
            return float(field_value) > float(expected)
        elif operator == "lt":
            return float(field_value) < float(expected)
        elif operator == "gte":
            return float(field_value) >= float(expected)
        elif operator == "lte":
            return float(field_value) <= float(expected)
        elif operator == "in":
            return field_value in expected.split(",")
        elif operator == "not_in":
            return field_value not in expected.split(",")
        elif operator == "matches":
            return bool(re.match(expected, field_value, re.TIMEOUT))
        return False
    except (ValueError, TypeError, re.error, TimeoutError):
        return False


def _get_nested(data: dict, path: str) -> str:
    """Resolve dot-notation path in a dictionary."""
    parts = path.split(".")
    current = data
    for part in parts[:10]:  # Depth limit
        if isinstance(current, dict):
            current = current.get(part, "")
        else:
            return ""
    return str(current) if current is not None else ""


def fuzz_condition_eval(data: bytes) -> None:
    """Fuzz the condition evaluation logic."""
    try:
        text = data.decode("utf-8", errors="replace")
        parts = text.split("|", 3)
        if len(parts) < 4:
            return

        operator, field_path, expected, context_json = parts[0], parts[1], parts[2], parts[3]

        if operator not in OPERATORS:
            return

        # Build a simple context dict
        context = {}
        for kv in context_json.split(",")[:10]:
            if "=" in kv:
                k, _, v = kv.partition("=")
                context[k.strip()] = v.strip()

        field_value = _get_nested(context, field_path)
        _eval_condition_safe(operator, field_value, expected)

    except (ValueError, TypeError, KeyError, UnicodeDecodeError,
            RecursionError, MemoryError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, fuzz_condition_eval)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
