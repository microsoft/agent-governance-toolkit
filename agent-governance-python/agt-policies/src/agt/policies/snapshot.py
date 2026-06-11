# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AGT snapshot builder (public surface).

This module is the canonical replacement for the v4
``agent_os.integrations.base.ExecutionContext`` carrier. It implements the
per-intervention-point snapshot shape documented in
``policy-engine/spec/agt/AGT-SNAPSHOT-1.0.md`` §1 (the common envelope)
and §§2.1-2.8 (the per-intervention-point bodies).

Two surfaces are provided:

- A set of module-level helper functions
  (:func:`input_snapshot`, :func:`pre_model_call_snapshot`, ...) that mint
  a single snapshot from explicit arguments. These are the same helpers
  that used to live under ``agt._harness.snapshot``; the harness module
  is retained as a thin re-export shim so existing scenario tests keep
  importing from there.
- A long-lived :class:`SnapshotBuilder` that wraps a host session: it
  holds ``agent_id``, ``session_id``, optional ``tenant_id`` (per
  AGT-SNAPSHOT §1's envelope), and the four running budgets the host
  tracks between calls (``tool_call_count``, ``token_count``,
  ``elapsed_seconds``, ``cost_usd``). Mutators
  (:meth:`SnapshotBuilder.record_tool_call`,
  :meth:`SnapshotBuilder.record_tokens`,
  :meth:`SnapshotBuilder.record_cost`,
  :meth:`SnapshotBuilder.record_elapsed`) advance the host-side counters
  between intervention points. The ACS engine itself stays stateless per
  ACS §1.1; the budgets surface as
  ``snapshot.envelope.budgets.*`` and are read-only inside the engine.

Each intervention-point method on :class:`SnapshotBuilder` (e.g.
:meth:`SnapshotBuilder.pre_tool_call`) returns the snapshot dict shaped
for that hook. The builder also exposes :meth:`SnapshotBuilder.envelope`
for callers that want to assemble custom intervention points.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


def _utcnow_iso() -> str:
    """ISO-8601 UTC timestamp with second precision, per AGT-SNAPSHOT §1."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _validate_budget_counter(name: str, value: Any) -> None:
    if name in ("tool_call_count", "token_count"):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer, got {value!r}")
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f"{name} must be a non-negative number, got {value!r}")


def _envelope(
    *,
    agent_id: str,
    session_id: str = "session-1",
    intervention_point: str,
    tool_call_count: int = 0,
    token_count: int = 0,
    elapsed_seconds: float = 0.0,
    cost_usd: float = 0.0,
    tenant_id: str | None = None,
    timestamp: str | None = None,
    session_started_at: str | None = None,
    agent_name: str | None = None,
    agent_version: str = "1.0.0",
    trace_id: str | None = None,
    span_id: str | None = None,
) -> dict[str, Any]:
    for name, value in (
        ("tool_call_count", tool_call_count),
        ("token_count", token_count),
        ("elapsed_seconds", elapsed_seconds),
        ("cost_usd", cost_usd),
    ):
        _validate_budget_counter(name, value)
    ts = timestamp or _utcnow_iso()
    envelope: dict[str, Any] = {
        "agent": {
            "id": agent_id,
            "version": agent_version,
            "name": agent_name or agent_id,
        },
        "session": {
            "id": session_id,
            "started_at": session_started_at or ts,
        },
        "intervention_point": intervention_point,
        "timestamp": ts,
        "budgets": {
            "tool_call_count": tool_call_count,
            "token_count": token_count,
            "elapsed_seconds": elapsed_seconds,
            "cost_usd": cost_usd,
        },
    }
    if tenant_id:
        envelope["tenant"] = {"id": tenant_id, "name": tenant_id}
    if trace_id or span_id:
        trace: dict[str, str] = {}
        if trace_id:
            trace["trace_id"] = trace_id
        if span_id:
            trace["span_id"] = span_id
        envelope["trace"] = trace
    return envelope


# ── module-level helpers ───────────────────────────────────────────────


def input_snapshot(
    *,
    agent_id: str,
    body: str | dict[str, Any],
    source: str = "user",
    headers: dict[str, str] | None = None,
    source_labels: Iterable[str] = (),
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    """Snapshot for the ``input`` intervention point (AGT-SNAPSHOT §2.2)."""
    return {
        "envelope": _envelope(agent_id=agent_id, intervention_point="input", **envelope_kwargs),
        "input": {
            "body": body,
            "source": source,
            "headers": dict(headers or {}),
            "ifc": {"source_labels": list(source_labels)},
        },
    }


def pre_model_call_snapshot(
    *,
    agent_id: str,
    model_name: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    request_id: str = "req-1",
    model_vendor: str = "test",
    model_params: dict[str, Any] | None = None,
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    """Snapshot for the ``pre_model_call`` intervention point (§2.3)."""
    return {
        "envelope": _envelope(
            agent_id=agent_id, intervention_point="pre_model_call", **envelope_kwargs
        ),
        "model": {"name": model_name, "vendor": model_vendor, "params": dict(model_params or {})},
        "messages": messages,
        "tools": tools or [],
        "request_id": request_id,
    }


def post_model_call_snapshot(
    *,
    agent_id: str,
    model_name: str,
    response: dict[str, Any],
    usage: dict[str, int] | None = None,
    request_id: str = "req-1",
    model_vendor: str = "test",
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    """Snapshot for the ``post_model_call`` intervention point (§2.4)."""
    return {
        "envelope": _envelope(
            agent_id=agent_id, intervention_point="post_model_call", **envelope_kwargs
        ),
        "model": {"name": model_name, "vendor": model_vendor},
        "request_id": request_id,
        "response": response,
        "usage": usage or {"prompt_tokens": 0, "completion_tokens": 0},
    }


def pre_tool_call_snapshot(
    *,
    agent_id: str,
    tool_name: str,
    args: dict[str, Any],
    call_id: str = "call-1",
    content_hash: str | None = None,
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    """Snapshot for the ``pre_tool_call`` intervention point (§2.5)."""
    tool_call: dict[str, Any] = {"name": tool_name, "args": args, "id": call_id}
    if content_hash is not None:
        tool_call["content_hash"] = content_hash
    return {
        "envelope": _envelope(
            agent_id=agent_id, intervention_point="pre_tool_call", **envelope_kwargs
        ),
        "tool_call": tool_call,
    }


def post_tool_call_snapshot(
    *,
    agent_id: str,
    tool_name: str,
    args: dict[str, Any],
    result: Any,
    error: Any = None,
    duration_ms: float = 0.0,
    call_id: str = "call-1",
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    """Snapshot for the ``post_tool_call`` intervention point (§2.6)."""
    return {
        "envelope": _envelope(
            agent_id=agent_id, intervention_point="post_tool_call", **envelope_kwargs
        ),
        "tool_call": {"name": tool_name, "args": args, "id": call_id},
        "tool_result": {"value": result, "error": error, "duration_ms": duration_ms},
    }


def output_snapshot(
    *,
    agent_id: str,
    content: str | dict[str, Any],
    message_chain: list[dict[str, Any]] | None = None,
    result_labels: Iterable[str] = (),
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    """Snapshot for the ``output`` intervention point (§2.7)."""
    return {
        "envelope": _envelope(agent_id=agent_id, intervention_point="output", **envelope_kwargs),
        "response": {
            "content": content,
            "ifc": {"result_labels": list(result_labels)},
        },
        "message_chain": message_chain or [],
    }


def agent_startup_snapshot(
    *,
    agent_id: str,
    capabilities: Iterable[str] = (),
    model_name: str = "",
    model_vendor: str = "test",
    tools_registered: Iterable[str] = (),
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    """Snapshot for the ``agent_startup`` intervention point (§2.1)."""
    return {
        "envelope": _envelope(
            agent_id=agent_id, intervention_point="agent_startup", **envelope_kwargs
        ),
        "agent_init": {
            "capabilities": list(capabilities),
            "model": {"name": model_name, "vendor": model_vendor},
            "tools_registered": list(tools_registered),
        },
    }


def agent_shutdown_snapshot(
    *,
    agent_id: str,
    tool_calls: int = 0,
    tokens: int = 0,
    errors: int = 0,
    duration_seconds: float = 0.0,
    **envelope_kwargs: Any,
) -> dict[str, Any]:
    """Snapshot for the ``agent_shutdown`` intervention point (§2.8)."""
    return {
        "envelope": _envelope(
            agent_id=agent_id, intervention_point="agent_shutdown", **envelope_kwargs
        ),
        "summary": {
            "tool_calls": tool_calls,
            "tokens": tokens,
            "errors": errors,
            "duration_seconds": duration_seconds,
        },
    }


# ── class-based builder ───────────────────────────────────────────────


@dataclass
class SnapshotBuilder:
    """Long-lived per-session snapshot helper.

    The builder owns the host-side state that the v4
    ``agent_os.integrations.base.ExecutionContext`` previously carried:
    the agent and session identifiers, the optional tenant, and the four
    running budgets the host increments between intervention points. The
    ACS runtime stays stateless per ACS §1.1; this object lives on the
    host side of the boundary and emits a fresh snapshot for each hook.

    Mutators advance host-tracked counters as the agent runs. They are
    additive (``record_tokens(100)`` adds 100), matching the v4
    ``ExecutionContext.total_tokens += usage`` pattern.

    Example::

        builder = SnapshotBuilder(agent_id="bot", session_id="s-42")
        snap = builder.pre_tool_call(tool_name="lookup", args={"q": "x"})
        # ... host runs the tool ...
        builder.record_tool_call()
        builder.record_tokens(120)
    """

    agent_id: str
    session_id: str = "session-1"
    tenant_id: str | None = None
    agent_name: str | None = None
    agent_version: str = "1.0.0"
    session_started_at: str | None = None
    tool_call_count: int = 0
    token_count: int = 0
    elapsed_seconds: float = 0.0
    cost_usd: float = 0.0
    trace_id: str | None = None
    span_id: str | None = None
    extra_envelope: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, str) or not self.agent_id:
            raise ValueError("agent_id must be a non-empty string")
        if not isinstance(self.session_id, str) or not self.session_id:
            raise ValueError("session_id must be a non-empty string")
        for name in ("tool_call_count", "token_count", "elapsed_seconds", "cost_usd"):
            _validate_budget_counter(name, getattr(self, name))
        if self.session_started_at is None:
            self.session_started_at = _utcnow_iso()

    # ── mutators (host-side budget tracking) ──────────────────────────

    def record_tool_call(self, count: int = 1) -> None:
        """Increment the ``tool_call_count`` budget by ``count`` (default 1).

        Hosts call this after a ``post_tool_call`` returns successfully,
        matching the v4 ``ExecutionContext.call_count += 1`` pattern. The
        engine sees the new value on the next intervention point because
        AGT-SNAPSHOT §1 specifies budgets are read at the start of each
        evaluation.
        """
        if not isinstance(count, int) or count < 0:
            raise ValueError(f"count must be a non-negative integer, got {count!r}")
        self.tool_call_count += count

    def record_tokens(self, tokens: int) -> None:
        """Add ``tokens`` to the running ``token_count`` budget."""
        if not isinstance(tokens, int) or tokens < 0:
            raise ValueError(f"tokens must be a non-negative integer, got {tokens!r}")
        self.token_count += tokens

    def record_cost(self, usd: float) -> None:
        """Add ``usd`` to the running ``cost_usd`` budget."""
        if not isinstance(usd, (int, float)) or usd < 0:
            raise ValueError(f"usd must be a non-negative number, got {usd!r}")
        self.cost_usd += float(usd)

    def record_elapsed(self, seconds: float) -> None:
        """Add ``seconds`` to the running ``elapsed_seconds`` budget."""
        if not isinstance(seconds, (int, float)) or seconds < 0:
            raise ValueError(f"seconds must be a non-negative number, got {seconds!r}")
        self.elapsed_seconds += float(seconds)

    def reset_budgets(self) -> None:
        """Zero the four host-tracked budget counters."""
        self.tool_call_count = 0
        self.token_count = 0
        self.elapsed_seconds = 0.0
        self.cost_usd = 0.0

    # ── envelope helpers ──────────────────────────────────────────────

    def _envelope_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "session_id": self.session_id,
            "tool_call_count": self.tool_call_count,
            "token_count": self.token_count,
            "elapsed_seconds": self.elapsed_seconds,
            "cost_usd": self.cost_usd,
            "tenant_id": self.tenant_id,
            "agent_name": self.agent_name,
            "agent_version": self.agent_version,
            "session_started_at": self.session_started_at,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
        }
        kwargs.update(self.extra_envelope)
        return kwargs

    def envelope(self, intervention_point: str) -> dict[str, Any]:
        """Return the bare envelope dict for ``intervention_point``.

        Convenience for callers that want to build a custom intervention
        point payload while still inheriting the builder's identifiers
        and budgets.
        """
        return _envelope(
            agent_id=self.agent_id,
            intervention_point=intervention_point,
            **self._envelope_kwargs(),
        )

    # ── per-intervention-point snapshot helpers ──────────────────────

    def agent_startup(
        self,
        *,
        capabilities: Iterable[str] = (),
        model_name: str = "",
        model_vendor: str = "test",
        tools_registered: Iterable[str] = (),
    ) -> dict[str, Any]:
        return agent_startup_snapshot(
            agent_id=self.agent_id,
            capabilities=capabilities,
            model_name=model_name,
            model_vendor=model_vendor,
            tools_registered=tools_registered,
            **self._envelope_kwargs(),
        )

    def input(
        self,
        *,
        body: str | dict[str, Any],
        source: str = "user",
        headers: dict[str, str] | None = None,
        source_labels: Iterable[str] = (),
    ) -> dict[str, Any]:
        return input_snapshot(
            agent_id=self.agent_id,
            body=body,
            source=source,
            headers=headers,
            source_labels=source_labels,
            **self._envelope_kwargs(),
        )

    def pre_model_call(
        self,
        *,
        model_name: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        request_id: str = "req-1",
        model_vendor: str = "test",
        model_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return pre_model_call_snapshot(
            agent_id=self.agent_id,
            model_name=model_name,
            messages=messages,
            tools=tools,
            request_id=request_id,
            model_vendor=model_vendor,
            model_params=model_params,
            **self._envelope_kwargs(),
        )

    def post_model_call(
        self,
        *,
        model_name: str,
        response: dict[str, Any],
        usage: dict[str, int] | None = None,
        request_id: str = "req-1",
        model_vendor: str = "test",
    ) -> dict[str, Any]:
        return post_model_call_snapshot(
            agent_id=self.agent_id,
            model_name=model_name,
            response=response,
            usage=usage,
            request_id=request_id,
            model_vendor=model_vendor,
            **self._envelope_kwargs(),
        )

    def pre_tool_call(
        self,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str = "call-1",
        content_hash: str | None = None,
    ) -> dict[str, Any]:
        return pre_tool_call_snapshot(
            agent_id=self.agent_id,
            tool_name=tool_name,
            args=args,
            call_id=call_id,
            content_hash=content_hash,
            **self._envelope_kwargs(),
        )

    def post_tool_call(
        self,
        *,
        tool_name: str,
        args: dict[str, Any],
        result: Any,
        error: Any = None,
        duration_ms: float = 0.0,
        call_id: str = "call-1",
    ) -> dict[str, Any]:
        return post_tool_call_snapshot(
            agent_id=self.agent_id,
            tool_name=tool_name,
            args=args,
            result=result,
            error=error,
            duration_ms=duration_ms,
            call_id=call_id,
            **self._envelope_kwargs(),
        )

    def output(
        self,
        *,
        content: str | dict[str, Any],
        message_chain: list[dict[str, Any]] | None = None,
        result_labels: Iterable[str] = (),
    ) -> dict[str, Any]:
        return output_snapshot(
            agent_id=self.agent_id,
            content=content,
            message_chain=message_chain,
            result_labels=result_labels,
            **self._envelope_kwargs(),
        )

    def agent_shutdown(
        self,
        *,
        tool_calls: int | None = None,
        tokens: int | None = None,
        errors: int = 0,
        duration_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Snapshot for the ``agent_shutdown`` hook.

        When ``tool_calls``, ``tokens`` or ``duration_seconds`` are not
        supplied the builder defaults them to the running budget values
        so a host that has been calling the mutators gets a consistent
        summary automatically.
        """
        return agent_shutdown_snapshot(
            agent_id=self.agent_id,
            tool_calls=self.tool_call_count if tool_calls is None else tool_calls,
            tokens=self.token_count if tokens is None else tokens,
            errors=errors,
            duration_seconds=(
                self.elapsed_seconds if duration_seconds is None else duration_seconds
            ),
            **self._envelope_kwargs(),
        )


__all__ = [
    "SnapshotBuilder",
    "agent_shutdown_snapshot",
    "agent_startup_snapshot",
    "input_snapshot",
    "output_snapshot",
    "post_model_call_snapshot",
    "post_tool_call_snapshot",
    "pre_model_call_snapshot",
    "pre_tool_call_snapshot",
]
