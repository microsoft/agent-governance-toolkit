"""Govern an Azure AI Foundry Agents tool call with ACS, end to end.

This is a *real* integration reference, not a mocked one. It uses the genuine
Azure AI Foundry Agents SDK (``azure-ai-agents``) to declare function tools, and
it makes a real Azure OpenAI call: the ACS policy is backed by an LLM judge that
classifies each tool argument before the tool is allowed to run. Nothing here is
stubbed with canned JSON, so it doubles as a live smoke test.

The governance contract lives in two committed artifacts next to this file, the
way a production integration ships them, rather than in Python:

* ``foundry_governance.acs.yaml`` is the ACS manifest. It declares the
  intervention points, the live Azure OpenAI ``intent_judge`` annotator, and the
  Rego policy that consumes the judge label.
* ``policy/foundry_tool_guard.rego`` is the deterministic decision. It fails
  closed, allowing a tool call only when the judge labels it ``safe``.

``build_control`` loads the manifest and resolves the Rego bundle. The Rego
policy runs through OPA, so ``opa`` must be on ``PATH`` (or ``ACS_OPA_PATH``).

Run it with real credentials set (see ``_common.require_azure``)::

    export AZURE_OPENAI_ENDPOINT=...        # https://<resource>.openai.azure.com
    export AZURE_OPENAI_API_KEY=...
    export AZURE_OPENAI_DEPLOYMENT=...       # e.g. gpt-4o / gpt-5.x
    export AZURE_OPENAI_API_VERSION=...      # e.g. 2025-04-01-preview
    pip install "agent-control-specification" azure-ai-agents
    # opa must be on PATH for the Rego policy bundle
    python foundry_agents.py

It demonstrates two integration styles for the *same* governed seam:

* the short path -- ``control.protect_tool(...)`` returns a drop-in async
  wrapper that evaluates PRE_TOOL_CALL and POST_TOOL_CALL, applies any
  transform, and raises ``AgentControlBlocked`` on a deny; and
* the long path -- you call ``control.evaluate_intervention_point(...)``
  yourself and branch on ``verdict.decision`` (allow / deny / escalate /
  transform), which is what you want when wiring ACS into a framework's own
  tool-dispatch hook.

Security invariant: a destructive tool call is *never* executed. The host policy
fails closed (it allows only an explicit "safe" judge verdict), so a destructive
label, an unexpected label, a missing label, or a fail-closed transient all deny.
That invariant is the assertion this example verifies. Because the judge is a live
model, a transient infrastructure error surfaces as a fail-closed
``annotation_failed`` verdict; the host pattern is to retry that (a real policy
deny is never retried), shown in ``govern``.

Scope and caveats: this example judges tool INPUT on PRE_TOOL_CALL. The judge
annotation is not bound on POST_TOOL_CALL, so tool output is evaluated but not
gated here; add an output-side annotation to govern results. The judge also sees
untrusted tool-argument text, so it is subject to prompt injection (an argument
that tries to talk the judge into "safe"); treat an LLM judge as defense in depth
behind deterministic policy, not as the sole control.

How to wire this into a live Foundry agent: register the same callables with
``FunctionTool``/``ToolSet`` and route the SDK's auto function-call hook (the
point where Foundry invokes your Python tool) through ``protect_tool`` so every
tool the agent decides to call is gated by ACS first.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import yaml

# The genuine Azure AI Foundry Agents SDK. We build real tool definitions from
# the same callables we govern, so the Foundry wiring is not faked.
from azure.ai.agents.models import FunctionTool

from agent_control_specification import (
    AgentControl,
    AgentControlBlocked,
    Decision,
    EnforcementMode,
    InterventionPoint,
    InterventionPointResult,
)

from _common import require_azure

# The committed governance artifacts that make this an actual integration rather
# than a manifest assembled in Python: the ACS manifest and its Rego policy
# bundle. A production integration ships and loads these the same way.
MANIFEST_PATH = Path(__file__).resolve().parent / "foundry_governance.acs.yaml"
POLICY_BUNDLE = Path(__file__).resolve().parent / "policy"


# Verdict reasons that signal a transient judge/infrastructure failure (a timeout
# or an upstream error), as opposed to a real policy decision. The host retries
# these; it never retries a genuine deny.
_TRANSIENT_REASONS = ("runtime_error:annotation_failed", "runtime_error:annotation_timeout")


# --- The Python callables a Foundry agent would invoke as function tools -------
def search_records(query: str) -> str:
    return f"rows matching {query!r}"


def run_sql(query: str) -> str:
    return f"executed {query!r}"


TOOLS = {"search_records": search_records, "run_sql": run_sql}

# Real Foundry tool definitions built from the very callables we govern.
foundry_tools = FunctionTool(set(TOOLS.values()))


def build_control() -> AgentControl:
    """Load the committed ACS manifest and Rego bundle, then bind the runtime.

    The governance contract lives in two committed artifacts next to this file:

    * ``foundry_governance.acs.yaml`` declares the intervention points, the live
      Azure OpenAI ``intent_judge`` annotator, and the policy that consumes it.
    * ``policy/foundry_tool_guard.rego`` is the deterministic decision. It fails
      closed, allowing a tool call only when the judge labels it ``safe``.

    A production integration ships these two files and loads them with
    ``AgentControl.from_path("foundry_governance.acs.yaml")``. This example does
    almost that. It reads the committed manifest and injects three
    per-deployment Azure fields (endpoint, deployment, api_version) from the
    environment, because an Azure resource endpoint is deployment configuration,
    not a committed artifact. The API key stays out of the manifest entirely and
    is referenced by name via ``api_key_env``. The Rego ``bundle`` is resolved to
    an absolute path so the example runs from any working directory.
    """
    azure = require_azure()
    manifest = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    judge = manifest["annotators"]["intent_judge"]
    judge["endpoint"] = azure["AZURE_OPENAI_ENDPOINT"]
    judge["deployment"] = azure["AZURE_OPENAI_DEPLOYMENT"]
    judge["api_version"] = azure["AZURE_OPENAI_API_VERSION"]
    manifest["policies"]["tool_guard"]["bundle"] = str(POLICY_BUNDLE)
    # ACS is stateless: one instance serves unbounded concurrent evaluations.
    return AgentControl.from_native(manifest)


async def govern(
    control: AgentControl,
    point: InterventionPoint,
    snapshot: dict,
    *,
    retries: int = 2,
) -> InterventionPointResult:
    """Evaluate one seam, retrying only on a transient judge failure.

    A live LLM judge can fail closed on a transient infrastructure error
    (``annotation_failed`` / ``annotation_timeout``). The host retries those; a
    real policy deny is returned immediately and never retried.
    """
    # Retry only a transient fail-closed; a real verdict is returned at once.
    for _ in range(retries):
        result = await control.evaluate_intervention_point(point, snapshot, EnforcementMode.ENFORCE)
        if (result.verdict.reason or "") not in _TRANSIENT_REASONS:
            return result
    # Final attempt: return whatever verdict it yields.
    return await control.evaluate_intervention_point(point, snapshot, EnforcementMode.ENFORCE)


async def enforce(
    control: AgentControl,
    point: InterventionPoint,
    result: InterventionPointResult,
    policy_target: dict,
    *,
    approval_resolver=None,
) -> dict:
    """Host-side verdict enforcement for one manual interception point.

    Drop this into your own framework's tool-dispatch hook so every interception
    point shares a single enforcement path instead of re-deriving allow, warn,
    deny, escalate, and transform handling at each seam. It delegates the
    blocking decision to the SDK (``control.enforce`` raises
    ``AgentControlBlocked`` on a deny or an unapproved escalate, and routes an
    escalate to ``approval_resolver``), then returns the target the host must
    propagate: the rewritten target on a transform verdict, otherwise the
    original ``policy_target``.

    This helper lives in the example on purpose. It is a thin composition over
    the stable SDK surface (``control.enforce`` plus
    ``result.transformed_policy_target``), so a host can copy and adapt it
    without waiting on an SDK release.
    """
    await control.enforce(point, result, EnforcementMode.ENFORCE, approval_resolver=approval_resolver)
    if result.verdict.decision is Decision.TRANSFORM and (
        result.transformed_policy_target_applied or result.transformed_policy_target is not None
    ):
        return result.transformed_policy_target
    return policy_target


async def demo_short_path(control: AgentControl) -> None:
    """Short path: protect_tool returns a governed wrapper around the callable.

    The wrapper raises ``AgentControlBlocked`` on a deny. We retry the safe call
    only if the judge transiently fails closed; the destructive call must always
    be blocked.
    """
    print("\n-- short path: control.protect_tool --")
    guarded = control.protect_tool("run_sql", execute=lambda args: run_sql(**args))

    async def call(query: str, *, retries: int = 2):
        args = {"query": query}
        # Retry only a transient fail-closed; a real deny propagates immediately.
        for _ in range(retries):
            try:
                return await guarded(args, tool_call_id="call")
            except AgentControlBlocked as blocked:
                if (blocked.result.verdict.reason or "") not in _TRANSIENT_REASONS:
                    raise
        # Final attempt: let any verdict (allow value or block) propagate.
        return await guarded(args, tool_call_id="call")

    # A safe read is allowed and the underlying Foundry tool actually runs.
    result = await call("SELECT name FROM customers WHERE id = 1")
    print(f"  ALLOW  -> tool ran, value={result.value!r}")
    assert result.value == "executed 'SELECT name FROM customers WHERE id = 1'"

    # A destructive statement is blocked before the tool can run.
    try:
        await call("DROP TABLE customers")
    except AgentControlBlocked as blocked:
        print(f"  DENY   -> tool NOT run, reason={blocked.result.verdict.reason!r}")
    else:
        raise AssertionError("destructive call should have been blocked")


async def demo_long_path(control: AgentControl) -> None:
    """Long path: evaluate the seam yourself, then call ``enforce``.

    This is the shape you drop into a framework's own tool-dispatch hook. The
    reusable ``enforce`` helper above collapses the per-decision branching into
    one call per interception point, so an agent builder wires evaluation once
    and reuses the same enforcement path everywhere.
    """
    print("\n-- long path: control.evaluate_intervention_point + enforce --")

    async def governed_call(tool_name: str, args: dict):
        pre = await govern(
            control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": tool_name, "args": args}}
        )
        try:
            effective_args = await enforce(control, InterventionPoint.PRE_TOOL_CALL, pre, args)
        except AgentControlBlocked as blocked:
            print(f"  {blocked.result.verdict.decision.name:8} -> {tool_name}: {blocked.result.verdict.reason}")
            return None, False

        output = TOOLS[tool_name](**effective_args)

        # Evaluate the output seam. This example binds the judge only on
        # PRE_TOOL_CALL, so POST_TOOL_CALL is not gated here; this is where
        # output governance would attach (bind an annotation on post).
        post = await govern(
            control,
            InterventionPoint.POST_TOOL_CALL,
            {"tool_call": {"name": tool_name, "args": effective_args}, "tool_result": output},
        )
        try:
            output = await enforce(control, InterventionPoint.POST_TOOL_CALL, post, output)
        except AgentControlBlocked as blocked:
            print(f"  {blocked.result.verdict.decision.name:8} (post) -> {tool_name}: {blocked.result.verdict.reason}")
            return None, False
        print(f"  {pre.verdict.decision.name:5} -> {tool_name}: ran, output={output!r}")
        return output, True

    _, ran = await governed_call("search_records", {"query": "SELECT 1"})
    assert ran, "safe read should run"
    _, ran = await governed_call("run_sql", {"query": "DELETE FROM audit_log"})
    assert not ran, "destructive statement must never execute"


async def main() -> None:
    control = build_control()
    print(f"governed Foundry tools: {sorted(d['function']['name'] for d in foundry_tools.definitions)}")
    await demo_short_path(control)
    await demo_long_path(control)
    print("\nOK: both code paths enforced the LLM-judge policy.")


if __name__ == "__main__":
    asyncio.run(main())
