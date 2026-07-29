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
import copy
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


BRANCH_ATTRS = ("allowed", "permits_unchanged")
HANDLES = ("transformed_value", "permits_unchanged", ".transform is not None")


def _called_names(fn):
    """Names of every method/function this function calls."""
    out = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Attribute):
                out.add(n.func.attr)
            elif isinstance(n.func, ast.Name):
                out.add(n.func.id)
    return out


def _code_only(fn) -> str:
    """The function's executable source, with docstrings and comments gone.

    Matching raw source would let a docstring satisfy the census. That is not
    hypothetical: ``base.py``'s ``_tuple_for`` documents ``transformed_value``
    in prose, so a regression that deleted its actual transform check still
    passed until this stripped them.
    """
    node = copy.deepcopy(fn)
    for n in ast.walk(node):
        body = getattr(n, "body", None)
        if (
            isinstance(body, list)
            and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body.pop(0)
    # ast.unparse drops comments, which are not in the tree at all.
    return ast.unparse(node) if node.body else ""


def _branches(fn) -> bool:
    return any(
        isinstance(n, ast.Attribute) and n.attr in BRANCH_ATTRS for n in ast.walk(fn)
    ) or any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "is_allowed"
        for n in ast.walk(fn)
    )


def _consumers():
    """Every function that evaluates a policy AND branches on the verdict.

    A function that returns the result for someone else to judge is a
    forwarder, not a consumer, and is excluded.

    Evaluation and branching are not always in the same function. Four sites
    hand the result to a local helper that does the branching (``_tuple_for``,
    ``_apply_bridge_result``, ``_merge_bridge_verdict``). Those helpers carry
    live transform logic, so the census follows one level of same-file
    delegation and judges the pair together, rather than excluding both halves
    as neither-evaluates-nor-branches.
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
        all_fns = [
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for fn in all_fns:
            evaluates = [
                n
                for n in ast.walk(fn)
                if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in EVAL_METHODS
            ]
            if not evaluates:
                continue
            body = _code_only(fn)
            label = f"{path.relative_to(SRC)}:{evaluates[0].lineno}"

            if _branches(fn):
                found.append((label, fn.name, body))
                continue

            # Not a branching consumer itself. It is still one if it delegates
            # to a same-file helper that branches; judge the pair together.
            called = _called_names(fn)
            helpers = [
                h
                for h in all_fns
                if h.name in called and h is not fn and _branches(h)
            ]
            if helpers:
                joined = body + "\n".join(_code_only(h) for h in helpers)
                names = "+".join([fn.name] + [h.name for h in helpers])
                found.append((label, names, joined))
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
    handled = any(marker in body for marker in HANDLES)

    assert handled, (
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


# ── census 2: a replacement of the wrong shape must not fall through ──────


def _guarded_applications():
    """Every `if X.transform is not None and isinstance(V, T):` application.

    A surface takes one shape. When the policy returns a replacement of
    another shape, the guard is False and, unless something else catches it,
    execution simply continues with the ORIGINAL value the policy meant to
    rewrite. That is the same silent drop as ignoring the verdict, one level
    down, and it is reachable: ACS allows a transform value to be any JSON
    value, so a manifest can legitimately return a dict for a string target.
    """
    found = []
    for path in sorted(SRC.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "transform is not None" not in text:
            continue
        tree = ast.parse(text)
        fns = [
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.If)
                and isinstance(node.test, ast.BoolOp)
                and isinstance(node.test.op, ast.And)
                and len(node.test.values) == 2
            ):
                continue
            left, right = node.test.values
            if not (
                isinstance(left, ast.Compare)
                and isinstance(left.left, ast.Attribute)
                and left.left.attr == "transform"
            ):
                continue
            if not (
                isinstance(right, ast.Call)
                and isinstance(right.func, ast.Name)
                and right.func.id == "isinstance"
            ):
                continue
            enclosing = max(
                (f for f in fns if f.lineno <= node.lineno <= (f.end_lineno or 0)),
                key=lambda f: f.lineno,
                default=None,
            )
            if enclosing is None:
                continue
            found.append(
                (
                    f"{path.relative_to(SRC)}:{node.lineno}",
                    enclosing.name,
                    _code_only(enclosing),
                )
            )
    return found


GUARDED = _guarded_applications()


def test_the_second_census_found_the_guarded_applications():
    assert len(GUARDED) > 10, f"census collapsed to {len(GUARDED)} applications"


@pytest.mark.parametrize(
    "where,funcname,body",
    GUARDED,
    ids=[f"{w}::{n}" for w, n, _ in GUARDED],
)
def test_a_replacement_of_the_wrong_shape_does_not_fall_through(
    where, funcname, body
):
    """Each guarded application needs a path for the shape it cannot take.

    ``applies_to`` folds the check into the deny branch the site already has;
    an explicit refusal or an ``applied`` flag works too. Something must catch
    it, or the original value is forwarded.
    """
    # ``_merge_bridge_verdict`` surfaces a string replacement on
    # ShieldVerdict.modified_value, but it runs AFTER validate_tool_call has
    # already written a dict replacement into params. A non-string there is
    # therefore applied, not dropped, and refusing would reject a correct
    # rewrite. Its caller carries the check instead.
    if funcname == "_merge_bridge_verdict":
        pytest.skip("replacement is applied by the caller before this runs")

    caught = "applies_to(" in body or "applied" in body

    assert caught, (
        f"{where} {funcname}() applies a transform only when the replacement "
        "is the right shape, and does nothing when it is not, so the original "
        "value is forwarded. Fold `applies_to(<type>)` into the deny check, "
        "or track whether the rewrite happened."
    )
