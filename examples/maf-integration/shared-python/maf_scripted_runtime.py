# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Shared scripted Microsoft Agent Framework runtime helpers for AGT examples."""

from __future__ import annotations

from collections.abc import AsyncIterable, MutableSequence, Sequence
from typing import Any
from uuid import uuid4

from agent_framework import (
    BaseChatClient,
    ChatMiddlewareLayer,
    ChatResponse,
    ChatResponseUpdate,
    Content,
    FunctionInvocationLayer,
    Message,
    ResponseStream,
)
from agent_framework._clients import OptionsCoT
from agent_framework.observability import ChatTelemetryLayer


class ScriptedResponseClient(
    FunctionInvocationLayer[OptionsCoT],
    ChatMiddlewareLayer[OptionsCoT],
    ChatTelemetryLayer[OptionsCoT],
    BaseChatClient[OptionsCoT],
):
    """A deterministic MAF chat client that returns canned responses."""

    def __init__(
        self,
        responses: Sequence[ChatResponse],
        *,
        fallback_text: str = "No scripted response configured.",
    ) -> None:
        super().__init__(middleware=[])
        self.additional_properties: dict[str, Any] = {}
        self.call_count = 0
        self._responses = list(responses)
        self._fallback_text = fallback_text

    def _next_response(self) -> ChatResponse:
        if self._responses:
            return self._responses.pop(0)
        return text_response(self._fallback_text)

    def _inner_get_response(
        self,
        *,
        messages: MutableSequence[Message],
        stream: bool,
        options: dict[str, Any],
        **kwargs: Any,
    ) -> Any:
        if stream:
            return self._get_streaming_response(options)

        async def _get() -> ChatResponse:
            self.call_count += 1
            return self._next_response()

        return _get()

    def _get_streaming_response(
        self,
        options: dict[str, Any],
    ) -> ResponseStream[ChatResponseUpdate, ChatResponse]:
        response = self._next_response()

        async def _stream() -> AsyncIterable[ChatResponseUpdate]:
            self.call_count += 1
            for message in response.messages:
                yield ChatResponseUpdate(role=message.role, contents=message.contents)

        def _finalize(updates: Sequence[ChatResponseUpdate]) -> ChatResponse:
            return ChatResponse.from_updates(updates, output_format_type=options.get("response_format"))

        return ResponseStream(_stream(), finalizer=_finalize)


def text_response(text: str) -> ChatResponse:
    """Build a single assistant text response."""

    return ChatResponse(messages=[Message(role="assistant", contents=[text])])


def function_call_response(
    name: str,
    arguments: dict[str, Any],
    *,
    call_id: str | None = None,
) -> ChatResponse:
    """Build a single assistant function-call response."""

    return ChatResponse(
        messages=[
            Message(
                role="assistant",
                contents=[
                    Content.from_function_call(
                        call_id=call_id or f"call_{uuid4().hex[:8]}",
                        name=name,
                        arguments=arguments,
                    )
                ],
            )
        ]
    )
