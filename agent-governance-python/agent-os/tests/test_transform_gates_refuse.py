# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""A gate that cannot apply a transform must refuse it.

``transform`` is a permitting verdict: ``NativeAdapterResult.allowed`` is
``True`` for it. But it permits a *rewritten* action, carrying the replacement
in ``transformed_value``. A gate written as ``if not result.allowed: raise``
therefore lets the ORIGINAL value through while the policy believes it was
rewritten, so a redaction policy silently does not redact and nothing reports
a failure.

Sites split two ways, and both are correct:

* Sites that can apply the replacement check ``allowed`` for the deny case and
  then rewrite from ``transformed_value`` (``langchain_adapter``,
  ``maf_adapter``, ``anthropic_adapter``, ``semantic_kernel_adapter``'s tool
  path, and others).
* Sites with nowhere to put the replacement gate on ``permits_unchanged``,
  which is false for a transform, and refuse.

This test pins the second group. Thirteen of them read bare ``allowed`` and so
dropped transforms silently. They are listed explicitly rather than discovered,
because the point is that the whole set is covered.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

INTEGRATIONS = (
    pathlib.Path(__file__).resolve().parents[1]
    / "src"
    / "agent_os"
    / "integrations"
)

# (file, class, method). Anchored on names rather than line numbers so the
# test survives edits above the gate. The class matters: two adapters define
# the same method name on different classes, and only one carries the gate.
REFUSING_GATES = [
    ("autogen_adapter.py", "AutoGenKernel", "governed_function"),
    ("autogen_adapter.py", "AutoGenKernel", "governed_select_speaker"),
    ("autogen_adapter.py", "AutoGenKernel", "governed_route"),
    ("autogen_adapter.py", "AutoGenKernel", "governed_update"),
    ("google_adk_adapter.py", "GoogleADKKernel", "before_agent_callback"),
    ("google_adk_adapter.py", "GovernancePlugin", "on_user_message_callback"),
    ("langgraph_adapter.py", "LangGraphKernel", "before_node_execution"),
    ("langgraph_adapter.py", "LangGraphKernel", "before_tool_call"),
    ("openai_agents_sdk.py", "GovernanceRunHooks", "on_agent_start"),
    ("openai_agents_sdk.py", "GovernanceRunHooks", "on_agent_end"),
    ("openai_agents_sdk.py", "GovernanceRunHooks", "on_tool_start"),
    ("openai_agents_sdk.py", "GovernanceRunHooks", "on_tool_end"),
    ("semantic_kernel_adapter.py", "GovernedPlan", "invoke"),
]


def _function_source(filename: str, classname: str, funcname: str) -> str:
    path = INTEGRATIONS / filename
    src = path.read_text(encoding="utf-8")
    lines = src.splitlines()
    tree = ast.parse(src)

    classes = [
        n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == classname
    ]
    assert classes, f"{filename}: no class named {classname}"
    methods = [
        n
        for cls in classes
        for n in ast.walk(cls)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == funcname
    ]
    assert methods, f"{filename}: {classname} has no method {funcname}"
    node = methods[0]
    return chr(10).join(lines[node.lineno - 1 : node.end_lineno])


@pytest.mark.parametrize(
    "filename,classname,funcname",
    REFUSING_GATES,
    ids=[f"{c}.{n}" for _, c, n in REFUSING_GATES],
)
def test_gate_refuses_an_unapplied_transform(filename, classname, funcname):
    """These gates have nowhere to put a replacement, so they must refuse it.

    ``permits_unchanged`` is false for a transform; bare ``allowed`` is true.
    Reading the wrong one here forwards the un-redacted value.
    """
    body = _function_source(filename, classname, funcname)

    assert "permits_unchanged" in body, (
        f"{classname}.{funcname} gates a policy verdict but does not use "
        "permits_unchanged. If it can apply a transform it should rewrite "
        "from transformed_value; if it cannot it must refuse."
    )
    assert ".allowed:" not in body, (
        f"{classname}.{funcname} still branches on bare `allowed`, which is "
        "true for a transform and would forward the original value."
    )


def test_transform_makes_permits_unchanged_false():
    """The property the gates rely on, exercised rather than assumed."""
    from agent_os.integrations._native_adapter_runtime import NativeAdapterResult

    class _Eval:
        reason_code = "pii_redaction"
        verdict = "transform"
        transform = object()
        input_identity = None
        enforced_identity = None

        def is_allowed(self):
            return True

    result = NativeAdapterResult(_Eval())

    assert result.allowed is True, "transform permits, which is the trap"
    assert result.permits_unchanged is False, "but not with the value you have"


def test_refusal_message_names_the_real_problem():
    """Reporting the transform's own reason would describe the policy, not the bug."""
    from agent_os.integrations._native_adapter_runtime import NativeAdapterResult

    class _Eval:
        reason_code = "pii_redaction"
        verdict = "transform"
        transform = object()
        input_identity = None
        enforced_identity = None

        def is_allowed(self):
            return True

    error = NativeAdapterResult(_Eval()).to_policy_violation(RuntimeError)

    assert "cannot apply" in str(error)
    assert "pii_redaction" in str(error), "the policy reason stays available"
