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
import re
import types

import pytest

from agent_os.integrations._native_adapter_runtime import (
    POINT_NOT_CONFIGURED,
    NativeAdapterResult,
    NativeAdapterRuntime,
)
from agent_os.integrations.base import BaseIntegration

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
    "where,func_name,body",
    CONSUMERS,
    ids=[f"{w}::{n}" for w, n, _ in CONSUMERS],
)
def test_consumer_applies_or_refuses_a_transform(where, func_name, body):
    handled = any(marker in body for marker in HANDLES)

    assert handled, (
        f"{where} {func_name}() branches on a policy verdict but neither "
        "applies a transform nor refuses one. `allowed` is True for a "
        "transform, so this forwards the original value while the policy "
        "believes it was rewritten. Either rewrite from `transformed_value` "
        "or gate on `permits_unchanged`."
    )


# ── behavioural: the two sites with nowhere to put a replacement ──────────


class _Transform:
    """The replacement a transform verdict carries."""

    def __init__(self, value):
        self.value = value
        self.applied_value = value


class _Decision(str):
    """A decision that reads as a string and answers ``permits``/``value``."""

    def __new__(cls, value: str, permits: bool):
        obj = super().__new__(cls, value)
        obj.permits = permits
        obj.value = value
        return obj


class _Verdict:
    """The ACS-shaped verdict, carrying decision, reason and transform."""

    def __init__(self, decision: str, permits: bool, reason, transform):
        self.decision = _Decision(decision, permits)
        self.reason = reason
        self.transform = transform

    def __str__(self) -> str:  # earlier layers read the verdict as a string
        return str(self.decision)


class _Evaluation:
    """Stand-in for the native ``PolicyEvaluation`` a session returns.

    Deliberately not a stand-in for ``NativeAdapterResult``: the behaviour
    under test lives on that class, so faking it would test the fake.
    """

    def __init__(self, allowed: bool, reason_code: str | None = None, transform=None):
        self._allowed = allowed
        self.reason_code = reason_code
        # Earlier layers read ``verdict``/``transform``/``reason_code`` off the
        # evaluation; the ACS layer reads them off ``verdict``. Carry both so
        # this reads the same wherever in the stack it runs.
        self.transform = transform
        self.verdict = _Verdict(
            "transform" if transform is not None else ("allow" if allowed else "deny"),
            allowed,
            reason_code,
            transform,
        )
        self.input_identity = None
        self.enforced_identity = None

    def is_allowed(self) -> bool:
        return self._allowed

    def public_error_message(self) -> str:
        return self.reason_code or "policy violation"

    def audit_record(self) -> dict:
        return {"reason": self.reason_code}


class _TransformEvaluation(_Evaluation):
    """A permitting verdict that carries a replacement."""

    def __init__(self, replacement):
        super().__init__(
            True,
            "pii_redaction",
            type("_T", (), {"value": replacement, "applied_value": replacement})(),
        )


def _transform_runtime(replacement):
    """A NativeAdapterRuntime whose session always returns a transform."""
    import types

    from agent_os.integrations._native_adapter_runtime import NativeAdapterRuntime

    runtime = object.__new__(NativeAdapterRuntime)
    runtime._sessions = {}
    evaluation = _TransformEvaluation(replacement)
    runtime._session_for = lambda ctx: types.SimpleNamespace(
        evaluate=lambda *a, **kw: evaluation,
        # The pre-tool-call path charges the attempt through the builder.
        builder=types.SimpleNamespace(record_tool_call=lambda: None),
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
            ):
                continue
            # Any number of ANDed operands, in any order. Requiring exactly
            # two, with the transform check first, is how two live drops hid:
            # both add a third condition (`and last_msg is not None`,
            # `and isinstance(tool_call, dict)`) and so were invisible here.
            ops = node.test.values
            has_transform = any(
                isinstance(o, ast.Compare)
                and isinstance(o.left, ast.Attribute)
                and o.left.attr == "transform"
                for o in ops
            )
            has_isinstance = any(
                isinstance(o, ast.Call)
                and isinstance(o.func, ast.Name)
                and o.func.id == "isinstance"
                for o in ops
            )
            if not (has_transform and has_isinstance):
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
    "where,func_name,body",
    GUARDED,
    ids=[f"{w}::{n}" for w, n, _ in GUARDED],
)
def test_a_replacement_of_the_wrong_shape_does_not_fall_through(
    where, func_name, body
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
    if func_name == "_merge_bridge_verdict":
        pytest.skip("replacement is applied by the caller before this runs")

    caught = "applies_to(" in body or "applied" in body

    assert caught, (
        f"{where} {func_name}() applies a transform only when the replacement "
        "is the right shape, and does nothing when it is not, so the original "
        "value is forwarded. Fold `applies_to(<type>)` into the deny check, "
        "or track whether the rewrite happened."
    )


# ── an unconfigured intervention point is a denial, not an absence ────────
#
# The engine answers a request naming a point the manifest does not configure
# with ``runtime_error:intervention_point_unknown``, and that verdict does not
# permit. A ``post_*`` block still stops the result propagating even though the
# guarded action already ran, which the SDK states in ``AgentControlBlocked``,
# so permitting an unconfigured ``output`` would forward model responses that
# no policy was consulted about. The remedy is to bind the point, which is what
# the Rust MIGRATION_V5 guidance says and what the scenario manifests now do.


STATE = types.SimpleNamespace(agent_id="a", session_id="s")




def _unconfigured():
    """An evaluation whose only fault is that the manifest omits the point."""
    return _Evaluation(False, POINT_NOT_CONFIGURED)


def _adapter(result):
    """A bare BaseIntegration whose runtime returns one fixed result."""
    import types as _t

    adapter = object.__new__(BaseIntegration)
    adapter._adapter_runtime = _t.SimpleNamespace(
        evaluate_output=lambda state, *, content: result
    )
    adapter.completed = []
    adapter.record_host_completion = lambda state, **kw: adapter.completed.append(kw)
    return adapter


def _runtime(evaluation):
    """A runtime whose session returns one fixed evaluation at every point."""
    import types as _t

    runtime = object.__new__(NativeAdapterRuntime)
    runtime._sessions = {}
    runtime._session_for = lambda ctx: _t.SimpleNamespace(
        evaluate=lambda *a, **kw: evaluation,
        builder=_t.SimpleNamespace(record_tool_call=lambda: None),
        evaluate_output=lambda **kw: evaluation,
        evaluate_post_tool_call=lambda **kw: evaluation,
        evaluate_post_model_call=lambda **kw: evaluation,
        evaluate_input=lambda **kw: evaluation,
        evaluate_pre_tool_call=lambda **kw: evaluation,
    )
    return runtime


class TestAnUnconfiguredPointDenies:
    """Uniformly, at every point. No point is exempt."""

    def test_result_does_not_permit(self):
        result = NativeAdapterResult(_unconfigured())

        assert result.allowed is False

    def test_it_reports_which_kind_of_denial_it_is(self):
        """So a host can name the missing point instead of a bare refusal."""
        assert NativeAdapterResult(_unconfigured()).point_not_configured is True

    def test_a_real_denial_is_not_mistaken_for_a_missing_point(self):
        result = NativeAdapterResult(
            _Evaluation(False, "policy:blocked_pattern_output")
        )

        assert result.point_not_configured is False
        assert result.allowed is False

    def test_an_allow_is_not_mistaken_for_a_missing_point(self):
        result = NativeAdapterResult(_Evaluation(True))

        assert result.point_not_configured is False
        assert result.allowed is True

    @pytest.mark.parametrize(
        "point,call",
        [
            ("output", lambda r: r.evaluate_output(STATE, content="x")),
            (
                "post_tool_call",
                lambda r: r.evaluate_post_tool_call(
                    STATE, tool_name="t", args={}, result="r"
                ),
            ),
            (
                "post_model_call",
                lambda r: r.evaluate_post_model_call(
                    STATE, model_name="m", response={}
                ),
            ),
            ("input", lambda r: r.evaluate_input(STATE, body="x")),
            (
                "pre_tool_call",
                lambda r: r.evaluate_pre_tool_call(STATE, tool_name="t", args={}),
            ),
        ],
    )
    def test_every_point_denies(self, point, call):
        """post_* included: a block there still stops the result propagating."""
        result = call(_runtime(_unconfigured()))

        assert result.allowed is False, f"{point} permitted an unconfigured point"
        assert result.point_not_configured is True


class TestPostExecuteHonoursIt:
    """``post_execute`` reads ``allowed``, so it inherits the refusal."""

    def test_unconfigured_output_blocks_and_records_nothing(self):
        adapter = _adapter(NativeAdapterResult(_unconfigured()))

        allowed, reason = adapter.post_execute(STATE, "the model's answer")

        assert allowed is False
        assert reason == POINT_NOT_CONFIGURED
        assert adapter.completed == []

    def test_transform_is_refused_because_it_cannot_be_applied(self):
        adapter = _adapter(
            NativeAdapterResult(_Evaluation(True, transform=object()))
        )

        allowed, reason = adapter.post_execute(STATE, "card 4111111111111111")

        assert allowed is False
        assert reason == "transform_not_applicable"
        # Recording completion here would charge the budget and seed the drift
        # baseline from output the caller is being told not to use.
        assert adapter.completed == []

    def test_allow_passes_and_records_completion(self):
        adapter = _adapter(NativeAdapterResult(_Evaluation(True)))

        allowed, reason = adapter.post_execute(STATE, "fine")

        assert (allowed, reason) == (True, None)
        assert adapter.completed == [{"output_data": "fine"}]


# ── census 3: a rewrite that fails to land must not be swallowed ──────────


def _swallowed_rewrites():
    """Transform rewrites whose failure is discarded with a bare ``pass``.

    The write targets a framework object the adapter does not own: a pydantic
    model, a frozen message, a context whose setter may reject. When it raises
    and the handler only passes, the original value survives and execution
    continues while the policy believes the value was rewritten. It is the
    same silent drop as ignoring the verdict, one level below the shape check.
    """
    found = []
    for path in sorted(SRC.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "transformed_value" not in text:
            continue
        tree = ast.parse(text)
        lines = text.splitlines()
        fns = [
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            body = "\n".join(lines[node.lineno - 1 : node.end_lineno])
            # The replacement may be read straight off the result or held in a
            # local first, so match both spellings.
            if not any(k in body for k in ("transformed_value", "replacement")):
                continue
            if not any(
                len(h.body) == 1 and isinstance(h.body[0], ast.Pass)
                for h in node.handlers
            ):
                continue
            # A bare pass is fine when the enclosing function tracks whether
            # the rewrite landed: the flag stays false and the caller refuses.
            fn = max(
                (f for f in fns if f.lineno <= node.lineno <= (f.end_lineno or 0)),
                key=lambda f: f.lineno,
                default=None,
            )
            enclosing_src = (
                "\n".join(lines[fn.lineno - 1 : fn.end_lineno]) if fn else ""
            )
            if re.search(r"^\s*(applied|rewritten) = ", enclosing_src, re.M):
                continue
            found.append(f"{path.relative_to(SRC)}:{node.lineno}")
    return found


def test_no_transform_rewrite_swallows_its_own_failure():
    swallowed = _swallowed_rewrites()

    assert not swallowed, (
        "these apply a transform inside a try whose handler only passes, so a "
        "write that fails leaves the original value in place and execution "
        "continues: " + ", ".join(swallowed) + ". Refuse instead, by raising "
        "or by tracking whether the rewrite landed."
    )


# ── census 4: a target that takes no write must not be passed over ────────


def _skipped_writes():
    """Transform applications guarded on the TARGET with no refusal.

    The three censuses above look at the verdict, the replacement's shape and
    a failed write. This is the fourth way the same drop happens and the one
    that hid longest: the write is never attempted, because a guard on what
    is being written TO fails. ``hasattr(result, "content")`` on a tool that
    returned a plain string, ``isinstance(msg, dict)`` on a message object,
    ``if fn is not None`` on a malformed tool call. No exception is raised, so
    nothing else here notices, and the original value is forwarded.

    A guard is fine when the branch refuses, tracks a landed-flag, or returns
    the replacement to a caller that uses it.
    """
    found = []
    for path in sorted(SRC.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "transformed_value" not in text:
            continue
        tree = ast.parse(text)
        for outer in ast.walk(tree):
            # `if <result>.transform is not None ...:` blocks
            if not isinstance(outer, ast.If):
                continue
            test_src = ast.unparse(outer.test)
            if "transform is not None" not in test_src:
                continue
            block = "\n".join(ast.unparse(s) for s in outer.body)
            if "transformed_value" not in block:
                continue
            for inner in ast.walk(outer):
                if not isinstance(inner, ast.If) or inner is outer:
                    continue
                guard = ast.unparse(inner.test)
                # a guard on the write TARGET, not on the replacement
                if "transformed_value" in guard or "transform" in guard:
                    continue
                if not any(
                    k in guard for k in ("hasattr", "isinstance", "is not None")
                ):
                    continue
                body = "\n".join(ast.unparse(s) for s in inner.body)
                if "transformed_value" not in body:
                    continue
                whole = ast.unparse(inner)

                # The else branch is whatever this If node holds beyond its
                # test and body. Searching the unparsed source for "else:"
                # would also match an else on a nested for/try/if and mark the
                # site handled when it is not.
                children = list(ast.iter_child_nodes(inner))
                has_else = any(
                    c is not inner.test and c not in inner.body for c in children
                )

                # A raise only handles the SKIPPED write if it is reachable
                # when the guard is false. A raise inside the branch's own
                # except handler fires when the write THROWS, which is the
                # class census 3 covers, and says nothing about the branch
                # never being entered. Counting it here would exempt the
                # repo's most common shape, a guarded write in a try.
                handlers = [
                    h for n in inner.body for h in ast.walk(n)
                    if isinstance(h, ast.ExceptHandler)
                ]
                in_handler = {
                    id(r) for h in handlers for r in ast.walk(h)
                    if isinstance(r, ast.Raise)
                }
                refuses = any(
                    isinstance(n, ast.Raise) and id(n) not in in_handler
                    for stmt in inner.body for n in ast.walk(stmt)
                )

                # Handing the replacement back to the caller also handles it,
                # and that is matched against the whole outer block on purpose.
                # llamaindex and semantic_kernel chain several target guards
                # and end the block with `return <result>.transformed_value`,
                # so a guard falling through reaches that fallback rather than
                # carrying on with the original. Scoping this to the branch
                # would flag those as drops. The cost is that a block with a
                # fallback on one path and a genuine drop on another reads as
                # handled; census 1 still requires the function to apply or
                # refuse, and the branch-level clauses above catch the shape
                # that has no fallback at all.
                returns_replacement = re.search(
                    r"return \w+\.transformed_value", block
                )

                handled = (
                    has_else
                    or refuses
                    or re.search(r"(applied|rewritten) = ", whole)
                    or returns_replacement
                )
                if not handled:
                    found.append(f"{path.relative_to(SRC)}:{inner.lineno}")
    return found


def test_a_target_that_takes_no_write_is_not_passed_over():
    skipped = _skipped_writes()

    assert not skipped, (
        "these apply a transform only when the write target has the right "
        "shape, and do nothing when it does not, so the original value is "
        "forwarded with no exception raised: " + ", ".join(skipped) + ". "
        "Refuse on the other branch, or track whether the write landed."
    )
