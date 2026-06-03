# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
LlamaIndex Integration

Wraps LlamaIndex query engines, retrievers, and agents with Agent OS governance.

Backend (AGT 5.0): every policy decision is routed through
:class:`agt.policies.runtime.AgtRuntime` (the ACS-backed v5 engine).
The v4 :class:`~agent_os.integrations.base.GovernancePolicy` is
translated to an AGT manifest via
:func:`agt.policies.bridge.governance_to_acs_manifest` at adapter init
time, an :class:`AgtRuntime` is memoised per policy, and a
:class:`agt.policies.snapshot.SnapshotBuilder` mirrors the v4
``ExecutionContext`` budgets between intervention points. The legacy
``pre_execute`` / ``post_execute`` tuple API is preserved so v4 callers
keep working. ``transform`` verdicts (AGT-DELTA D1.1) rewrite the
outbound query or chat message before the LlamaIndex client sees it;
``escalate`` verdicts route through the configured approval resolver
per AGT-DELTA D1.4.

Usage:
    from agent_os.integrations import LlamaIndexKernel

    kernel = LlamaIndexKernel()
    governed_engine = kernel.wrap(my_query_engine)

    # Now all queries go through Agent OS governance
    result = governed_engine.query("What is the meaning of life?")
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from ._v5_runtime_bridge import (
    AdapterRuntimeBridge,
    BridgeResult,
    get_runtime_bridge,
)
from ..exceptions import PolicyViolationError as _CanonicalPolicyViolationError
from .base import BaseIntegration, ExecutionContext, GovernancePolicy


class PolicyViolationError(_CanonicalPolicyViolationError):
    """Raised when a LlamaIndex query/chat violates governance policy.

    Subclass of :class:`agent_os.exceptions.PolicyViolationError` so the
    canonical ``from_check_result`` constructor is available while
    preserving the legacy
    ``agent_os.integrations.llamaindex_adapter.PolicyViolationError``
    import path for v4 callers.
    """

    pass


class LlamaIndexKernel(BaseIntegration):
    """
    LlamaIndex adapter for Agent OS.

    Supports:
    - QueryEngine (query, aquery)
    - RetrieverQueryEngine
    - ChatEngine (chat, achat, stream_chat)
    - AgentRunner (chat, query)
    """

    def __init__(
        self,
        policy: Optional[GovernancePolicy] = None,
        *,
        approval_resolver: Optional[Callable[..., Any]] = None,
        _runtime: Optional[Any] = None,
        _runtime_factory: Optional[Callable[..., Any]] = None,
    ):
        """Initialise the LlamaIndex governance kernel.

        Args:
            policy: Governance policy to enforce. When ``None`` the default
                ``GovernancePolicy`` is used. The policy is translated to
                an AGT manifest and an :class:`agt.policies.runtime.AgtRuntime`
                is constructed over it at init time.
            approval_resolver: Optional callable invoked when the AGT
                engine returns an ``escalate`` verdict. Signature matches
                :data:`agt.policies.runtime.ApprovalCallback`. When
                ``None`` an escalate verdict fails closed to ``deny``.
            _runtime: Test seam — inject a pre-built :class:`AgtRuntime`
                so scenario tests can wire a scripted policy dispatcher
                without OPA on PATH. Not part of the public surface.
            _runtime_factory: Test seam — override the runtime factory
                used by the bridge cache. Not part of the public surface.
        """
        super().__init__(policy)
        self._wrapped_agents: dict[int, Any] = {}
        self._stopped: dict[str, bool] = {}
        self._approval_resolver = approval_resolver
        self._bridge: AdapterRuntimeBridge = get_runtime_bridge(
            self.policy,
            approval_resolver=approval_resolver,
            runtime=_runtime,
            runtime_factory=_runtime_factory,
        )

    @property
    def bridge(self) -> AdapterRuntimeBridge:
        """Return the v5 :class:`AdapterRuntimeBridge` for this kernel."""
        return self._bridge

    def evaluate_input(self, ctx: ExecutionContext, input_data: Any) -> BridgeResult:
        """Public access to the AGT ``input`` intervention point evaluation."""
        return self._bridge.evaluate_input(ctx, body=self._to_body(input_data))

    def evaluate_output(self, ctx: ExecutionContext, output_data: Any) -> BridgeResult:
        """Public access to the AGT ``output`` intervention point evaluation."""
        return self._bridge.evaluate_output(ctx, content=self._to_body(output_data))

    def evaluate_tool_budget(self, ctx: ExecutionContext) -> Optional[BridgeResult]:
        """Return a deny ``BridgeResult`` if the call/token budget is exceeded.

        A governed ``.query()`` / ``.chat()`` is a budgeted operation in the
        v4 contract; this keeps ``max_tool_calls`` / ``max_tokens`` enforced on
        those paths (the v5 input/output checks alone do not count calls).
        """
        return self._bridge.evaluate_tool_budget(ctx)

    @staticmethod
    def _to_body(data: Any) -> Any:
        """Normalise a LlamaIndex payload to a JSON-serialisable body."""
        if isinstance(data, (str, dict)):
            return data
        if hasattr(data, "response"):
            return str(getattr(data, "response"))
        if hasattr(data, "content"):
            return str(getattr(data, "content"))
        return str(data)

    def wrap(self, agent: Any) -> Any:
        """
        Wrap a LlamaIndex query engine, chat engine, or agent with governance.

        Intercepts:
        - query() / aquery()
        - chat() / achat()
        - stream_chat()
        - retrieve()
        """
        agent_id = getattr(agent, 'name', None) or f"llamaindex-{id(agent)}"
        ctx = self.create_context(agent_id)

        self._wrapped_agents[id(agent)] = agent
        self._stopped[agent_id] = False

        original = agent
        kernel = self

        class GovernedLlamaIndexAgent:
            """LlamaIndex engine wrapped with Agent OS governance."""

            def __init__(self):
                self._original = original
                self._ctx = ctx
                self._kernel = kernel
                self._agent_id = agent_id

            def _check_stopped(self):
                if kernel._stopped.get(self._agent_id):
                    raise PolicyViolationError(
                        f"Agent '{self._agent_id}' is stopped (SIGSTOP)"
                    )

            def _pre(self, input_data: Any) -> Any:
                """Evaluate the AGT input intervention point and apply transforms."""
                bridge_result = self._kernel.evaluate_input(self._ctx, input_data)
                if not bridge_result.allowed:
                    raise PolicyViolationError.from_check_result(
                        bridge_result.check_result
                    )
                if bridge_result.transform is not None and isinstance(
                    bridge_result.transform.value, str
                ):
                    return bridge_result.transform.value
                return input_data

            def _post(self, result: Any) -> Any:
                """Evaluate the AGT output intervention point and apply transforms.

                Returns the (possibly rewritten) result so callers see
                the AGT-redacted text per AGT-DELTA D1.1.
                """
                bridge_result = self._kernel.evaluate_output(self._ctx, result)
                if not bridge_result.allowed:
                    raise PolicyViolationError.from_check_result(
                        bridge_result.check_result
                    )
                if bridge_result.transform is not None and isinstance(
                    bridge_result.transform.value, str
                ):
                    # Rewrite the response content if the result exposes one.
                    if hasattr(result, "response"):
                        try:
                            result.response = bridge_result.transform.value
                            return result
                        except Exception:  # noqa: BLE001 — best-effort rewrite
                            pass
                    if hasattr(result, "content"):
                        try:
                            result.content = bridge_result.transform.value
                            return result
                        except Exception:  # noqa: BLE001 — best-effort rewrite
                            pass
                    return bridge_result.transform.value
                return result

            def _enforce_budget(self) -> None:
                """Block the call when the v4 tool-call/token budget is spent.

                A governed ``query``/``chat`` is a budgeted operation, so
                ``max_tool_calls`` / ``max_tokens`` must be enforced here; the
                input/output intervention points alone do not count calls.
                """
                budget = self._kernel.evaluate_tool_budget(self._ctx)
                if budget is not None and not budget.allowed:
                    raise PolicyViolationError.from_check_result(
                        budget.check_result
                    )

            def query(self, query_str: Any, **kwargs) -> Any:
                """Governed query."""
                self._check_stopped()
                self._enforce_budget()
                query_str = self._pre(query_str)
                result = self._original.query(query_str, **kwargs)
                self._ctx.call_count += 1
                return self._post(result)

            async def aquery(self, query_str: Any, **kwargs) -> Any:
                """Governed async query."""
                self._check_stopped()
                self._enforce_budget()
                query_str = self._pre(query_str)
                result = await self._original.aquery(query_str, **kwargs)
                self._ctx.call_count += 1
                return self._post(result)

            def chat(self, message: str, **kwargs) -> Any:
                """Governed chat."""
                self._check_stopped()
                self._enforce_budget()
                message = self._pre(message)
                result = self._original.chat(message, **kwargs)
                self._ctx.call_count += 1
                return self._post(result)

            async def achat(self, message: str, **kwargs) -> Any:
                """Governed async chat."""
                self._check_stopped()
                self._enforce_budget()
                message = self._pre(message)
                result = await self._original.achat(message, **kwargs)
                self._ctx.call_count += 1
                return self._post(result)

            def stream_chat(self, message: str, **kwargs):
                """Governed streaming chat.

                The input is policy-checked before the stream begins.
                Stream chunks are yielded as-is; no per-chunk output
                evaluation is run because LlamaIndex emits a token at
                a time and the AGT output target is the full response.
                """
                self._check_stopped()
                message = self._pre(message)
                response = self._original.stream_chat(message, **kwargs)
                self._kernel.bridge.record_post_execute(self._ctx, tool_calls=0)
                return response

            def retrieve(self, query_str: Any, **kwargs) -> Any:
                """Governed retrieve."""
                self._check_stopped()
                query_str = self._pre(query_str)
                result = self._original.retrieve(query_str, **kwargs)
                self._kernel.post_execute(self._ctx, result)
                return result

            def __getattr__(self, name):
                return getattr(self._original, name)

        return GovernedLlamaIndexAgent()

    def unwrap(self, governed_agent: Any) -> Any:
        """Get original engine from wrapped version."""
        return governed_agent._original

    def signal(self, agent_id: str, signal: str):
        """Send signal to a governed agent."""
        if signal == "SIGSTOP":
            self._stopped[agent_id] = True
        elif signal == "SIGCONT":
            self._stopped[agent_id] = False
        elif signal == "SIGKILL":
            self._stopped[agent_id] = True

        super().signal(agent_id, signal)


# Convenience function
def wrap(agent: Any, policy: Optional[GovernancePolicy] = None) -> Any:
    """Quick wrapper for LlamaIndex engines."""
    return LlamaIndexKernel(policy).wrap(agent)
