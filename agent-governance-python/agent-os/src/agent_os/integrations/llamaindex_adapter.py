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


class _ReplayableStreamResponse:
    """Proxy a stream response when its response_gen cannot be reassigned."""

    def __init__(self, original: Any, chunks: list[Any]) -> None:
        self._original = original
        self.response_gen = iter(chunks)

    def print_response_stream(self) -> None:
        for chunk in self.response_gen:
            print(chunk, end="")

    def __getattr__(self, name: str) -> Any:
        value = getattr(self._original, name)
        if callable(value):
            raise AttributeError(
                f"LlamaIndex stream response method {name!r} is unavailable "
                "after transform replay because it may access the original stream"
            )
        return value


class _ReplayableAsyncStreamResponse:
    """Proxy an async stream response when async_response_gen cannot be reassigned."""

    def __init__(self, original: Any, chunks: list[Any], *, as_method: bool) -> None:
        self._original = original
        if as_method:
            self.async_response_gen = lambda: _async_iterable(chunks)
        else:
            self.async_response_gen = _async_iterable(chunks)

    def __getattr__(self, name: str) -> Any:
        value = getattr(self._original, name)
        if callable(value):
            raise AttributeError(
                f"LlamaIndex async stream response method {name!r} is unavailable "
                "after transform replay because it may access the original stream"
            )
        return value


async def _async_iterable(chunks: list[Any]):
    for chunk in chunks:
        yield chunk


def _with_replayable_response_gen(response: Any, chunks: list[Any]) -> Any:
    try:
        response.response_gen = iter(chunks)
        return response
    except (AttributeError, TypeError):
        return _ReplayableStreamResponse(response, chunks)


def _with_replayable_async_response_gen(
    response: Any, chunks: list[Any], *, as_method: bool
) -> Any:
    replay = (lambda: _async_iterable(chunks)) if as_method else _async_iterable(chunks)
    try:
        response.async_response_gen = replay
        return response
    except (AttributeError, TypeError):
        return _ReplayableAsyncStreamResponse(response, chunks, as_method=as_method)


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
                result = self._post(result)
                self._ctx.call_count += 1
                return result

            async def aquery(self, query_str: Any, **kwargs) -> Any:
                """Governed async query."""
                self._check_stopped()
                self._enforce_budget()
                query_str = self._pre(query_str)
                result = await self._original.aquery(query_str, **kwargs)
                result = self._post(result)
                self._ctx.call_count += 1
                return result

            def chat(self, message: str, **kwargs) -> Any:
                """Governed chat."""
                self._check_stopped()
                self._enforce_budget()
                message = self._pre(message)
                result = self._original.chat(message, **kwargs)
                result = self._post(result)
                self._ctx.call_count += 1
                return result

            async def achat(self, message: str, **kwargs) -> Any:
                """Governed async chat."""
                self._check_stopped()
                self._enforce_budget()
                message = self._pre(message)
                result = await self._original.achat(message, **kwargs)
                result = self._post(result)
                self._ctx.call_count += 1
                return result

            async def astream_chat(self, message: str, **kwargs) -> Any:
                """Governed async streaming chat."""
                self._check_stopped()
                self._enforce_budget()
                message = self._pre(message)
                response = self._original.astream_chat(message, **kwargs)
                if hasattr(response, "__await__"):
                    response = await response
                response = await self._post_async_stream_response(response)
                self._ctx.call_count += 1
                return response

            def stream_chat(self, message: str, **kwargs):
                """Governed streaming chat.

                The input is policy-checked before the stream begins.
                Inspectable stream responses are aggregated and checked
                before any chunks are returned to the caller.
                """
                self._check_stopped()
                self._enforce_budget()
                message = self._pre(message)
                response = self._original.stream_chat(message, **kwargs)
                response = self._post_stream_response(response)
                self._ctx.call_count += 1
                return response

            def _post_stream_response(self, response: Any) -> Any:
                """Evaluate a complete stream response before disclosure."""
                if isinstance(response, str):
                    return self._post(response)
                if hasattr(response, "response_gen"):
                    chunks = list(response.response_gen)
                    aggregated = "".join(str(chunk) for chunk in chunks)
                    checked = self._post(aggregated)
                    replay_chunks = chunks
                    if isinstance(checked, str) and checked != aggregated:
                        replay_chunks = [checked]
                    return _with_replayable_response_gen(response, replay_chunks)
                if (
                    hasattr(response, "__iter__")
                    and not isinstance(response, (dict, bytes, bytearray))
                ):
                    chunks = list(response)
                    aggregated = "".join(str(chunk) for chunk in chunks)
                    checked = self._post(aggregated)
                    if isinstance(checked, str) and checked != aggregated:
                        return iter([checked])
                    return iter(chunks)
                raise PolicyViolationError(
                    "LlamaIndex stream_chat returned an uninspectable stream; "
                    "cannot enforce output mediation before disclosure"
                )

            async def _post_async_stream_response(self, response: Any) -> Any:
                """Evaluate a complete async stream response before disclosure."""
                if hasattr(response, "async_response_gen"):
                    async_response_gen = response.async_response_gen
                    as_method = callable(async_response_gen)
                    stream = async_response_gen() if as_method else async_response_gen
                    chunks = [chunk async for chunk in stream]
                    aggregated = "".join(str(chunk) for chunk in chunks)
                    checked = self._post(aggregated)
                    replay_chunks = chunks
                    if isinstance(checked, str) and checked != aggregated:
                        replay_chunks = [checked]
                    return _with_replayable_async_response_gen(
                        response, replay_chunks, as_method=as_method
                    )
                if hasattr(response, "__aiter__"):
                    chunks = [chunk async for chunk in response]
                    aggregated = "".join(str(chunk) for chunk in chunks)
                    checked = self._post(aggregated)
                    if isinstance(checked, str) and checked != aggregated:
                        return _async_iterable([checked])
                    return _async_iterable(chunks)
                return self._post_stream_response(response)

            def retrieve(self, query_str: Any, **kwargs) -> Any:
                """Governed retrieve."""
                self._check_stopped()
                self._enforce_budget()
                query_str = self._pre(query_str)
                result = self._original.retrieve(query_str, **kwargs)
                result = self._post(result)
                self._ctx.call_count += 1
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
