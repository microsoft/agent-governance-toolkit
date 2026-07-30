# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Native adapter-facing orchestration over the ACS host session."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol



class _ContextLike(Protocol):
    agent_id: str
    session_id: str
    call_count: int
    total_tokens: int


class AdapterResult(Protocol):
    evaluation: Any
    transform: Any | None

    @property
    def transformed_value(self) -> Any:
        """Return the materialized policy target after transformation."""

    @property
    def allowed(self) -> bool:
        """Return whether the adapter may continue."""

    @property
    def permits_unchanged(self) -> bool:
        """Return whether the caller may proceed with the value it has."""

    def applies_to(self, kind: type | tuple[type, ...]) -> bool:
        """Return whether a transform fits the surface it targets."""

    @property
    def point_not_configured(self) -> bool:
        """Return whether the manifest configures this intervention point."""

    @property
    def verdict(self) -> str:
        """Return the native policy verdict."""

    @property
    def reason(self) -> str:
        """Return the normalized reason code."""

    @property
    def input_identity(self) -> str | None:
        """Return the identity of the evaluated input."""

    @property
    def enforced_identity(self) -> str | None:
        """Return the identity of the enforced action."""

    @property
    def public_message(self) -> str:
        """Return the sanitized public policy message."""

    def to_policy_violation(self, error_type: Any) -> Exception:
        """Create the canonical policy exception for this result."""


class AdapterRuntime(Protocol):
    runtime: Any

    def evaluate_input(self, *args: Any, **kwargs: Any) -> AdapterResult:
        """Evaluate an input intervention point."""

    def evaluate_pre_tool_call(
        self, *args: Any, **kwargs: Any
    ) -> AdapterResult:
        """Evaluate before a tool call."""

    def evaluate_post_tool_call(
        self, *args: Any, **kwargs: Any
    ) -> AdapterResult:
        """Evaluate after a tool call."""

    def evaluate_pre_model_call(
        self, *args: Any, **kwargs: Any
    ) -> AdapterResult:
        """Evaluate before a model call."""

    def evaluate_post_model_call(
        self, *args: Any, **kwargs: Any
    ) -> AdapterResult:
        """Evaluate after a model call."""

    def evaluate_output(self, *args: Any, **kwargs: Any) -> AdapterResult:
        """Evaluate an output intervention point."""

    def record_post_execute(self, *args: Any, **kwargs: Any) -> None:
        """Record host usage after execution."""


# The engine answers a request naming a point the manifest does not configure
# with this reason, and it does not permit. That is deliberate: an adapter
# evaluates a fixed set of points, so a manifest that omits one is a
# configuration gap rather than a decision to allow. A ``post_*`` block still
# prevents the result propagating even though the action already ran, so
# permitting here would forward tool output and model responses no policy was
# consulted about. Bind every point the adapter evaluates.
POINT_NOT_CONFIGURED = "runtime_error:intervention_point_unknown"


@dataclass(frozen=True)
class NativeAdapterResult:
    """Adapter decision backed by an ACS ``InterventionPointResult``."""

    evaluation: Any

    def applies_to(self, kind: type | tuple[type, ...]) -> bool:
        """Whether a transform, if there is one, fits the surface it targets.

        A surface can only carry a replacement of the shape it holds: a
        message body takes a ``str``, tool arguments take a ``dict``. When the
        replacement is another shape the site cannot apply it, and permitting
        would run the original the policy meant to rewrite. Sites fold this
        into the deny check they already have, so an unusable replacement
        takes the same path as a denial.

        True when there is no transform, so a plain allow is unaffected.
        """
        return self.transform is None or isinstance(self.transformed_value, kind)

    @property
    def point_not_configured(self) -> bool:
        """Whether the denial is only that the manifest omits this point.

        Reported so a host can say which point is missing. It does NOT permit:
        a ``post_*`` block stops the result propagating even though the action
        already ran, so an unconfigured point that permitted would forward tool
        output and model responses a policy was never consulted about.
        """
        return self.reason == POINT_NOT_CONFIGURED

    @property
    def allowed(self) -> bool:
        return bool(self.evaluation.verdict.decision.permits)

    @property
    def verdict(self) -> str:
        return str(self.evaluation.verdict.decision.value)

    @property
    def reason(self) -> str:
        reason = str(self.evaluation.verdict.reason or "")
        return reason.removeprefix("policy:")

    @property
    def input_identity(self) -> str | None:
        return self.evaluation.input_identity

    @property
    def enforced_identity(self) -> str | None:
        return self.evaluation.enforced_identity

    @property
    def transform(self) -> Any | None:
        return self.evaluation.verdict.transform

    @property
    def permits_unchanged(self) -> bool:
        """Whether the caller may proceed with the value it already has.

        ``allowed`` is true for ``transform``, but a transform carries a
        replacement the caller is expected to apply. A site that cannot apply
        one must gate on this instead, or it runs the original value while the
        policy believed it had been rewritten, and a redaction policy silently
        does not redact.
        """
        return self.allowed and self.transform is None

    @property
    def transformed_value(self) -> Any:
        """The value the runtime applied, falling back to what it asked for."""
        if self.evaluation.transformed_policy_target_applied:
            return self.evaluation.transformed_policy_target
        transform = self.transform
        return None if transform is None else transform.value

    @property
    def public_message(self) -> str:
        """A denial message that leaks neither policy nor user content."""
        if self.verdict == "escalate":
            return "Request requires policy approval."
        if self.reason.startswith("runtime_error:"):
            return "Policy evaluation failed closed."
        return "Request blocked by policy."

    def audit_record(self) -> dict[str, Any]:
        """The restricted payload adapters attach to a violation."""
        return {
            "schema_version": "agt.policy_evaluation.v1",
            "verdict": self.verdict,
            "reason_code": self.reason,
            "message": str(self.evaluation.verdict.message or ""),
            "input_identity": self.input_identity,
            "enforced_identity": self.enforced_identity,
        }

    def to_policy_violation(self, error_type: Any) -> Exception:
        if self.transform is not None:
            # Reached only from a site gating on ``permits_unchanged``. The
            # verdict permits, so reporting its reason ("pii_redaction") would
            # describe the policy rather than the problem, which is that this
            # integration has nowhere to put the replacement.
            return error_type(
                "policy returned a transform this integration cannot apply, "
                f"so the original value was refused (reason={self.reason})"
            )
        error = error_type(self.public_message, "POLICY_VIOLATION", self.audit_record())
        error.evaluation_result = self.evaluation
        return error


class NativeAdapterRuntime:
    """Shared native runtime/session seam for framework adapters."""

    def __init__(self, runtime: Any) -> None:
        if runtime is None:
            raise TypeError("NativeAdapterRuntime requires an AgentControl")
        self._runtime = runtime
        self._sessions: dict[str, Any] = {}

    @property
    def runtime(self) -> Any:
        return self._runtime

    def _session_for(self, ctx: _ContextLike) -> Any:
        from agent_control_specification import HostSession

        key = ctx.session_id or ctx.agent_id
        session = self._sessions.get(key)
        if session is None:
            session = HostSession(
                self._runtime,
                agent_id=ctx.agent_id,
                session_id=ctx.session_id or f"{ctx.agent_id}-session",
            )
            self._sessions[key] = session
        # Raise the session counters to whatever the host has observed without
        # moving them backward: the session charges attempted tool calls that
        # the adapter context does not know about yet.
        builder = session.builder
        builder.tool_call_count = max(builder.tool_call_count, int(ctx.call_count))
        builder.token_count = max(builder.token_count, int(ctx.total_tokens))
        return session

    def record_post_execute(
        self,
        ctx: _ContextLike,
        *,
        tokens: int = 0,
        tool_calls: int = 0,
    ) -> None:
        """Record tokens while avoiding a second native attempted-call charge."""
        del tool_calls
        self._session_for(ctx).builder.record_tokens(int(tokens))

    def evaluate_input(
        self,
        ctx: _ContextLike,
        *,
        body: Any,
        source: str = "user",
        headers: dict[str, str] | None = None,
    ) -> NativeAdapterResult:
        evaluation = self._session_for(ctx).evaluate(
            "input",
            input={
                "body": body if isinstance(body, str | dict) else str(body),
                "source": source,
                "headers": dict(headers or {}),
                "ifc": {"source_labels": []},
            },
        )
        return NativeAdapterResult(evaluation)

    def evaluate_pre_tool_call(
        self,
        ctx: _ContextLike,
        *,
        tool_name: str,
        args: Mapping[str, Any],
        call_id: str = "call-1",
    ) -> NativeAdapterResult:
        session = self._session_for(ctx)
        snapshot_body = {
            "tool_call": {"name": tool_name, "args": dict(args), "id": call_id}
        }
        # The engine reads budgets as of the start of the evaluation, so the
        # attempt is charged after the snapshot is built and before the next
        # intervention point sees it.
        evaluation = session.evaluate("pre_tool_call", **snapshot_body)
        session.builder.record_tool_call()
        return NativeAdapterResult(evaluation)

    def evaluate_post_tool_call(
        self,
        ctx: _ContextLike,
        *,
        tool_name: str,
        args: Mapping[str, Any],
        result: Any,
        error: Any = None,
        duration_ms: float = 0.0,
        call_id: str = "call-1",
    ) -> NativeAdapterResult:
        evaluation = self._session_for(ctx).evaluate(
            "post_tool_call",
            tool_call={"name": tool_name, "args": dict(args), "id": call_id},
            tool_result={"value": result, "error": error, "duration_ms": duration_ms},
        )
        return NativeAdapterResult(evaluation)

    def evaluate_pre_model_call(
        self,
        ctx: _ContextLike,
        *,
        model_name: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        request_id: str = "req-1",
        model_vendor: str = "test",
    ) -> NativeAdapterResult:
        evaluation = self._session_for(ctx).evaluate(
            "pre_model_call",
            model={"name": model_name, "vendor": model_vendor, "params": {}},
            messages=messages,
            tools=tools or [],
            request_id=request_id,
        )
        return NativeAdapterResult(evaluation)

    def evaluate_post_model_call(
        self,
        ctx: _ContextLike,
        *,
        model_name: str,
        response: dict[str, Any],
        usage: dict[str, int] | None = None,
        request_id: str = "req-1",
        model_vendor: str = "test",
    ) -> NativeAdapterResult:
        evaluation = self._session_for(ctx).evaluate(
            "post_model_call",
            model={"name": model_name, "vendor": model_vendor},
            request_id=request_id,
            response=response,
            usage=usage or {"prompt_tokens": 0, "completion_tokens": 0},
        )
        return NativeAdapterResult(evaluation)

    def evaluate_output(
        self,
        ctx: _ContextLike,
        *,
        content: Any,
        message_chain: list[dict[str, Any]] | None = None,
    ) -> NativeAdapterResult:
        evaluation = self._session_for(ctx).evaluate(
            "output",
            response={
                "content": content if isinstance(content, str | dict) else str(content),
                "ifc": {"result_labels": []},
            },
            message_chain=message_chain or [],
        )
        return NativeAdapterResult(evaluation)

__all__ = [
    "AdapterResult",
    "AdapterRuntime",
    "NativeAdapterResult",
    "NativeAdapterRuntime",
]
