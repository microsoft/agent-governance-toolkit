# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""No verdict consumer may drop a transform.

``transform`` is a permitting verdict: ``NativeAdapterResult.allowed`` is
``True`` for it. It permits a *rewritten* action though, carrying the
replacement in ``transformed_value``. A gate written as
``if not result.allowed: raise`` therefore forwards the ORIGINAL value while
the policy believes it was rewritten, so a redaction policy silently does not
redact and nothing reports a failure.

Every consumer must do one of two things:

* apply the replacement (read ``transformed_value``), or
* refuse, by gating on ``permits_unchanged`` or checking ``transform``.

The first test below is a census rather than a checklist. An earlier version
listed the known gates by name, which meant it could not catch a consumer
added somewhere new, and two live ones outside ``integrations/``
(``mcp_gateway`` and ``trust_root``) went unnoticed because of exactly that.
This walks the package instead, so a fourteenth site is caught wherever it is
written.

The census is structural and a determined no-op could satisfy it, so the
behavioural tests that follow drive the two sites that had nowhere to put a
replacement and confirm they refuse rather than forward.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "agent_os"

EVAL_METHODS = {
    "evaluate_input",
    "evaluate_output",
    "evaluate_pre_tool_call",
    "evaluate_post_tool_call",
    "evaluate_pre_model_call",
    "evaluate_post_model_call",
}


def _consumers():
    """Every function that evaluates a policy AND branches on the verdict.

    A function that returns the result for someone else to judge is a
    forwarder, not a consumer, and is excluded.
    """
    found = []
    for path in sorted(SRC.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if not any(m in text for m in EVAL_METHODS):
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:  # pragma: no cover - the repo does not ship these
            continue
        lines = text.splitlines()
        for fn in [
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]:
            evaluates = [
                n
                for n in ast.walk(fn)
                if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in EVAL_METHODS
            ]
            if not evaluates:
                continue
            branches = any(
                isinstance(n, ast.Attribute)
                and n.attr in ("allowed", "permits_unchanged")
                for n in ast.walk(fn)
            ) or any(
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "is_allowed"
                for n in ast.walk(fn)
            )
            if not branches:
                continue
            body = "\n".join(lines[fn.lineno - 1 : fn.end_lineno])
            found.append(
                (
                    f"{path.relative_to(SRC)}:{evaluates[0].lineno}",
                    fn.name,
                    body,
                )
            )
    return found


CONSUMERS = _consumers()


def test_the_census_actually_found_the_consumers():
    """Guard against the walk silently matching nothing and passing vacuously."""
    assert len(CONSUMERS) > 50, f"census collapsed to {len(CONSUMERS)} consumers"


@pytest.mark.parametrize(
    "where,funcname,body",
    CONSUMERS,
    ids=[f"{w}::{n}" for w, n, _ in CONSUMERS],
)
def test_consumer_applies_or_refuses_a_transform(where, funcname, body):
    applies = "transformed_value" in body
    refuses = "permits_unchanged" in body or ".transform is not None" in body

    assert applies or refuses, (
        f"{where} {funcname}() branches on a policy verdict but neither "
        "applies a transform nor refuses one. `allowed` is True for a "
        "transform, so this forwards the original value while the policy "
        "believes it was rewritten. Either rewrite from `transformed_value` "
        "or gate on `permits_unchanged`."
    )


# ── behavioural: the two sites with nowhere to put a replacement ──────────


class _TransformEvaluation:
    """A permitting verdict that carries a replacement."""

    reason_code = "pii_redaction"
    verdict = "transform"
    input_identity = None
    enforced_identity = None

    def __init__(self, replacement):
        self.transform = type(
            "_T", (), {"value": replacement, "applied_value": replacement}
        )()

    def is_allowed(self) -> bool:
        return True


def _transform_runtime(replacement):
    """A NativeAdapterRuntime whose session always returns a transform."""
    import types

    from agent_os.integrations._native_adapter_runtime import NativeAdapterRuntime

    runtime = object.__new__(NativeAdapterRuntime)
    runtime._sessions = {}
    evaluation = _TransformEvaluation(replacement)
    runtime._session_for = lambda ctx: types.SimpleNamespace(
        evaluate_pre_tool_call=lambda **kw: evaluation,
        evaluate_input=lambda **kw: evaluation,
        evaluate_output=lambda **kw: evaluation,
    )
    return runtime


def test_mcp_gateway_refuses_a_transform_it_cannot_apply():
    """It answers with a bool, so it has nowhere to put the rewritten args."""
    from agent_os.mcp_gateway import MCPGateway

    gateway = MCPGateway(object(), enable_builtin_sanitization=False)
    gateway._runtime = _transform_runtime({"body": "SSN=[REDACTED]"})

    allowed, reason = gateway.intercept_tool_call(
        "agent-1", "send_email", {"body": "SSN=123-45-6789"}
    )[:2]

    assert allowed is False, "gateway forwarded the un-redacted arguments"
    assert "transform" in reason.lower()


def test_trust_root_refuses_a_transform_it_cannot_apply():
    """TrustDecision carries no replacement, and this is the final authority."""
    from agent_os.trust_root import TrustRoot

    root = object.__new__(TrustRoot)
    root._runtime = _transform_runtime({"path": "/etc/passwd"})
    root._context = type("_C", (), {"call_count": 0})()

    decision = root.validate_action({"tool": "read_file", "arguments": {"path": "/x"}})

    assert decision.allowed is False, "trust root downgraded a transform to allow"
    assert "transform" in decision.reason.lower()
    assert root._context.call_count == 0, "a refused action must not be charged"
