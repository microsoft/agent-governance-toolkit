# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""LlamaIndex integration backed by a required native ACS runtime.

Queries, tool calls, and outputs are mediated before LlamaIndex receives or
discloses them.
"""

from __future__ import annotations

from typing import Any

from ._native_adapter_runtime import (
    AdapterResult,
    AdapterRuntime,
)
from ..exceptions import PolicyViolationError
from .base import AdapterExecutionState, BaseIntegration, get_adapter_runtime


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
        *,
        runtime: Any,
    ):
        """Initialise the kernel with the required native runtime."""
        super().__init__(runtime=runtime)
        self._wrapped_agents: dict[int, Any] = {}
        self._stopped: dict[str, bool] = {}
        self._bridge: AdapterRuntime = get_adapter_runtime(runtime)

    @property
    def bridge(self) -> AdapterRuntime:
        """Return the v5 :class:`AdapterRuntime` for this kernel."""
        return self._bridge

    def evaluate_input(self, ctx: AdapterExecutionState, input_data: Any) -> AdapterResult:
        """Public access to the AGT ``input`` intervention point evaluation."""
        return self._bridge.evaluate_input(ctx, body=self._to_body(input_data))

    def evaluate_output(self, ctx: AdapterExecutionState, output_data: Any) -> AdapterResult:
        """Public access to the AGT ``output`` intervention point evaluation."""
        return self._bridge.evaluate_output(ctx, content=self._to_body(output_data))

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
                    raise bridge_result.to_policy_violation(PolicyViolationError)
                if bridge_result.transform is not None and isinstance(
                    bridge_result.transformed_value, str
                ):
                    return bridge_result.transformed_value
                return input_data

            def _post(self, result: Any) -> Any:
                """Evaluate the AGT output intervention point and apply transforms.

                Returns the (possibly rewritten) result so callers see
                the AGT-redacted text per AGT-DELTA D1.1.
                """
                bridge_result = self._kernel.evaluate_output(self._ctx, result)
                if not bridge_result.allowed:
                    raise bridge_result.to_policy_violation(PolicyViolationError)
                if bridge_result.transform is not None and isinstance(
                    bridge_result.transformed_value, str
                ):
                    # Rewrite the response content if the result exposes one.
                    if hasattr(result, "response"):
                        try:
                            result.response = bridge_result.transformed_value
                            return result
                        except Exception:  # noqa: BLE001 — best-effort rewrite
                            pass
                    if hasattr(result, "content"):
                        try:
                            result.content = bridge_result.transformed_value
                            return result
                        except Exception:  # noqa: BLE001 — best-effort rewrite
                            pass
                    return bridge_result.transformed_value
                return result

            def query(self, query_str: Any, **kwargs) -> Any:
                """Governed query."""
                self._check_stopped()
                query_str = self._pre(query_str)
                result = self._original.query(query_str, **kwargs)
                result = self._post(result)
                self._ctx.call_count += 1
                return result

            async def aquery(self, query_str: Any, **kwargs) -> Any:
                """Governed async query."""
                self._check_stopped()
                query_str = self._pre(query_str)
                result = await self._original.aquery(query_str, **kwargs)
                result = self._post(result)
                self._ctx.call_count += 1
                return result

            def chat(self, message: str, **kwargs) -> Any:
                """Governed chat."""
                self._check_stopped()
                message = self._pre(message)
                result = self._original.chat(message, **kwargs)
                result = self._post(result)
                self._ctx.call_count += 1
                return result

            async def achat(self, message: str, **kwargs) -> Any:
                """Governed async chat."""
                self._check_stopped()
                message = self._pre(message)
                result = await self._original.achat(message, **kwargs)
                result = self._post(result)
                self._ctx.call_count += 1
                return result

            async def astream_chat(self, message: str, **kwargs) -> Any:
                """Governed async streaming chat."""
                self._check_stopped()
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
def wrap(
    agent: Any,
    *,
    runtime: Any,
) -> Any:
    """Quick wrapper for LlamaIndex engines."""
    return LlamaIndexKernel(runtime=runtime).wrap(agent)
