"""Govern an Azure AI Foundry Agents tool call with ACS, end to end.

This is a *real* integration reference, not a mocked one. It uses the genuine
Azure AI Foundry Agents SDK (``azure-ai-agents``) to declare function tools, and
it makes a real Azure OpenAI call: the ACS policy is backed by an LLM judge that
classifies each tool argument before the tool is allowed to run. Nothing here is
stubbed with canned JSON, so it doubles as a live smoke test.

Run it with real credentials set (see ``_common.require_azure``)::

    export AZURE_OPENAI_ENDPOINT=...        # https://<resource>.openai.azure.com
    export AZURE_OPENAI_API_KEY=...
    export AZURE_OPENAI_DEPLOYMENT=...       # e.g. gpt-4o / gpt-5.x
    export AZURE_OPENAI_API_VERSION=...      # e.g. 2025-04-01-preview
    pip install "agent-control-specification" azure-ai-agents
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

# The judge prompt. In production prefer a pinned remote prompt or a
# manifest-relative file over inlining (both shown in `build_control` below).
JUDGE_PROMPT = (
    "You are a security classifier for database tool calls made by an AI agent. "
    "Given the tool argument text, decide whether it is destructive (it drops, "
    "deletes, truncates, or alters data or schema) or safe (it only reads). "
    "Respond with ONLY compact JSON and no markdown, exactly one of "
    '{"label": "destructive"} or {"label": "safe"}.'
)

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


class IntentJudgePolicy:
    """Host-owned policy: allow only an explicit "safe" judge verdict.

    ACS computes the annotation (the real Azure OpenAI judge call) and hands the
    host the decision. Keeping enforcement host-side is the Foundry pattern: the
    runtime stays stateless and the host owns the verdict.

    This fails CLOSED: a tool call is allowed only when the judge is present and
    labels it "safe". A "destructive" label, any unexpected label, or a missing
    label denies, so a flaky or adversarial judge response can never wave a
    destructive call through. The judge annotation is bound only on
    PRE_TOOL_CALL, so POST_TOOL_CALL (no judge annotation) is allowed here; this
    example governs tool input, not output.
    """

    def evaluate(self, invocation):
        judged = invocation["input"]["annotations"].get("intent_judge")
        if judged is None:
            # Not judged (e.g. the post-tool seam). Output is not gated here.
            return {"decision": "allow"}
        label = judged.get("label")
        if label == "safe":
            return {"decision": "allow"}
        reason = (
            f"LLM judge labelled the tool argument {label!r}"
            if label
            else "LLM judge returned no usable label"
        )
        return {"decision": "deny", "reason": reason}


def build_control() -> AgentControl:
    """Build a stateless AgentControl bound to an LLM-judge policy.

    The manifest is assembled in-process so the Azure endpoint comes from the
    environment and no secret is written to disk (the API key is referenced by
    name via ``api_key_env``). A production deployment would instead load a
    committed manifest with ``AgentControl.from_path("governance.acs.yaml")`` or
    a pinned remote one with
    ``AgentControl.from_url("https://policies.example/governance.acs.yaml")``.
    """
    azure = require_azure()
    manifest = {
        "agent_control_specification_version": "0.3.1-beta",
        "metadata": {"name": "foundry-governed-agent"},
        "annotators": {
            "intent_judge": {
                "type": "llm",
                "provider": "azure_openai",
                "endpoint": azure["AZURE_OPENAI_ENDPOINT"],
                "deployment": azure["AZURE_OPENAI_DEPLOYMENT"],
                "api_version": azure["AZURE_OPENAI_API_VERSION"],
                "api_key_env": "AZURE_OPENAI_API_KEY",
                "system_prompt": JUDGE_PROMPT,
                # Production alternatives for the judge prompt:
                #   "system_prompt_file": "prompts/judge.txt"   # manifest-relative
                #   "system_prompt_url": {                       # pinned + HTTPS
                #       "url": "https://policies.example/judge.txt",
                #       "sha256": "<64-hex digest of the bytes>",
                #   }
                "label_field": "label",
                # Give a slow reasoning model room so the judge call does not time
                # out, and make its reply strictly parseable.
                "timeout_ms": 60000,
                # provider_config is merged verbatim into the chat-completions
                # request body. Azure JSON mode forces a valid JSON object and a
                # generous completion budget keeps reasoning models from
                # truncating it.
                "provider_config": {
                    "response_format": {"type": "json_object"},
                    "max_completion_tokens": 2000,
                },
            }
        },
        "policies": {"tool_guard": {"type": "custom", "adapter": "foundry_host"}},
        "intervention_points": {
            "pre_tool_call": {
                "policy_target_kind": "tool_args",
                "policy_target": "$.tool_call.args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "tool_guard"},
                "annotations": {"intent_judge": {"from": "$.tool_call.args.query"}},
            },
            "post_tool_call": {
                "policy_target_kind": "tool_result",
                "policy_target": "$.tool_result",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "tool_guard"},
            },
        },
        "tools": {
            "search_records": {"type": "Tool", "id": "search_records"},
            "run_sql": {"type": "Tool", "id": "run_sql"},
        },
    }
    # ACS is stateless: one instance serves unbounded concurrent evaluations.
    return AgentControl.from_native(manifest, policy_dispatcher=IntentJudgePolicy())


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
    """Long path: evaluate the seam yourself and branch on the decision.

    This is the shape you drop into a framework's own tool-dispatch hook when you
    need to inspect labels, route escalations, or apply a transformed argument.
    """
    print("\n-- long path: control.evaluate_intervention_point --")

    async def governed_call(tool_name: str, args: dict):
        pre = await govern(
            control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": tool_name, "args": args}}
        )
        decision = pre.verdict.decision
        if decision is Decision.DENY:
            print(f"  DENY   -> {tool_name}: {pre.verdict.reason}")
            return None, False
        if decision is Decision.ESCALATE:
            print(f"  ESCALATE -> {tool_name}: route to a human approver, holding the call")
            return None, False
        # ESCALATE and TRANSFORM are shown for completeness; this host policy
        # only emits allow/deny, so those branches illustrate the full decision
        # space a real policy could use.
        # TRANSFORM hands back a rewritten policy target (e.g. redacted args).
        effective_args = args
        if (
            decision is Decision.TRANSFORM
            and isinstance(pre.transformed_policy_target, dict)
        ):
            effective_args = pre.transformed_policy_target

        output = TOOLS[tool_name](**effective_args)

        # Evaluate the output seam. This example binds the judge only on
        # PRE_TOOL_CALL, so POST_TOOL_CALL is not gated here; this is where
        # output governance would attach (bind an annotation on post).
        post = await govern(
            control,
            InterventionPoint.POST_TOOL_CALL,
            {"tool_call": {"name": tool_name, "args": effective_args}, "tool_result": output},
        )
        if post.verdict.decision is not Decision.ALLOW:
            print(f"  {post.verdict.decision.name} (post) -> {tool_name}: {post.verdict.reason}")
            return None, False
        print(f"  {decision.name:5} -> {tool_name}: ran, output={output!r}")
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
