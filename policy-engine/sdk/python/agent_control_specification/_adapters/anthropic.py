from __future__ import annotations

from collections.abc import Mapping
from typing import TypeVar

from .._orchestration import AgentControl
from .._types import EnforcementMode, JsonValue
from ._errors import AdapterUnsupportedError
from .openai import _guard_call_request_method
from ._shared import _has_path, _ObjectProxy, _resolve_control_and_target

AgentT = TypeVar("AgentT")


def guard_anthropic_client(
    control_or_client: AgentControl | AgentT,
    client: AgentT | None = None,
    *,
    control: AgentControl | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
) -> AgentT:
    """Guard Anthropic messages calls.

    Anthropic streaming uses typed message events rather than OpenAI chat
    completion SSE chunks. Streamed calls fail closed unless the host wraps a
    faithfully assembled model call explicitly.
    """

    resolved_control, resolved_client = _resolve_control_and_target(
        control_or_client,
        client,
        control=control,
        target_name="Anthropic-style client",
        adapter_name="guard_anthropic_client",
    )
    if not _has_path(resolved_client, ("messages", "create")):
        raise AdapterUnsupportedError("Anthropic-style adapter requires messages.create.")
    messages = resolved_client.messages
    messages_proxy = _ObjectProxy(
        messages,
        overrides={
            "create": _guard_call_request_method(
                resolved_control,
                messages.create,
                snapshot=snapshot,
                mode=mode,
                streaming_unsupported_message=(
                    "Anthropic streaming is not guarded because typed message events "
                    "are not a chat-completion SSE shape."
                ),
            )
        },
    )
    return _ObjectProxy(resolved_client, overrides={"messages": messages_proxy})  # type: ignore[return-value]
