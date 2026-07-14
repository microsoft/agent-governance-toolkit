# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared host lifecycle primitives for native framework adapters."""

from __future__ import annotations

import difflib
import hashlib
import json
import logging
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Literal, Mapping, Protocol

logger = logging.getLogger(__name__)


PII_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b\d{3}[\s.-]?\d{2}[\s.-]?\d{4}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b"),
    re.compile(
        r"\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
)


class GovernanceEventType(Enum):
    """Event types emitted by adapter host lifecycle hooks."""

    POLICY_CHECK = "policy_check"
    POLICY_VIOLATION = "policy_violation"
    TOOL_CALL_BLOCKED = "tool_call_blocked"
    CHECKPOINT_CREATED = "checkpoint_created"
    DRIFT_DETECTED = "drift_detected"


@dataclass
class DriftResult:
    """Result of comparing an adapter output with its session baseline."""

    score: float
    exceeded: bool
    threshold: float
    baseline_hash: str
    current_hash: str

    def __repr__(self) -> str:
        status = "EXCEEDED" if self.exceeded else "OK"
        return (
            f"DriftResult(score={self.score:.4f}, "
            f"threshold={self.threshold}, {status})"
        )


_AGENT_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


@dataclass
class AdapterExecutionState:
    """Policy-free host state retained across native runtime evaluations."""

    agent_id: str
    session_id: str
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    call_count: int = 0
    total_tokens: int = 0
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    checkpoints: list[str] = field(default_factory=list)
    checkpoint_frequency: int = 5
    drift_threshold: float = 0.15
    _baseline_hash: str | None = field(default=None, repr=False)
    _baseline_text: str | None = field(default=None, repr=False)
    _drift_scores: list[float] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, str) or not _AGENT_ID_RE.fullmatch(
            self.agent_id
        ):
            raise ValueError(
                "agent_id must be a non-empty string matching "
                f"^[a-zA-Z0-9_-]+$, got {self.agent_id!r}"
            )
        if not isinstance(self.session_id, str) or not self.session_id:
            raise ValueError(
                f"session_id must be a non-empty string, got {self.session_id!r}"
            )
        if self.call_count < 0 or self.total_tokens < 0:
            raise ValueError("call_count and total_tokens must be non-negative")
        if self.checkpoint_frequency <= 0:
            raise ValueError("checkpoint_frequency must be positive")
        if not 0.0 <= self.drift_threshold <= 1.0:
            raise ValueError("drift_threshold must be between 0.0 and 1.0")


@dataclass
class ToolCallRequest:
    """Vendor-neutral representation of a tool or function call."""

    tool_name: str
    arguments: dict[str, Any]
    call_id: str = ""
    agent_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolCallResult:
    """Result of intercepting a tool call."""

    allowed: bool
    reason: str | None = None
    modified_arguments: dict[str, Any] | None = None
    audit_entry: dict[str, Any] | None = None


@dataclass(frozen=True)
class SkillAuditMetadata:
    """Normalized skill metadata attached to audit events."""

    skill_name: str | None = None
    skill_origin: str | None = None
    provenance_source_trust: Literal["trusted"] | None = None
    context_hash_before: str | None = None
    context_hash_after: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "skill_name": self.skill_name,
            "skill_origin": self.skill_origin,
            "provenance_source_trust": self.provenance_source_trust,
            "context_hash_before": self.context_hash_before,
            "context_hash_after": self.context_hash_after,
        }


@dataclass(frozen=True)
class TrustedSkillMetadataSource:
    """Framework-owned skill metadata that is safe to include in audit."""

    skill_name: str | None = None
    skill_origin: str | None = None


class ToolCallInterceptor(Protocol):
    """Protocol for host-side integrity and trust interceptors."""

    def intercept(self, request: ToolCallRequest) -> ToolCallResult: ...


class ContentHashInterceptor:
    """Verify tool identity through a registered SHA-256 content hash."""

    def __init__(
        self,
        tool_hashes: dict[str, str] | None = None,
        strict: bool = True,
    ) -> None:
        self._tool_hashes = dict(tool_hashes or {})
        self._strict = strict

    def register_hash(self, tool_name: str, content_hash: str) -> None:
        self._tool_hashes[tool_name] = content_hash

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        expected = self._tool_hashes.get(request.tool_name)
        if expected is None:
            if self._strict:
                return ToolCallResult(
                    allowed=False,
                    reason=(
                        f"Tool {request.tool_name!r} has no registered content hash"
                    ),
                )
            logger.warning("No content hash registered for tool %s", request.tool_name)
            return ToolCallResult(allowed=True)

        actual = request.metadata.get("content_hash", "")
        if not actual:
            return ToolCallResult(
                allowed=False,
                reason=f"Tool {request.tool_name!r} is missing content_hash metadata",
            )
        if actual != expected:
            return ToolCallResult(
                allowed=False,
                reason=f"Tool {request.tool_name!r} content hash mismatch",
            )
        return ToolCallResult(allowed=True)


class CompositeInterceptor:
    """Run host-side interceptors in order until one denies."""

    def __init__(self, interceptors: list[Any] | None = None) -> None:
        self.interceptors = interceptors or []

    def add(self, interceptor: Any) -> CompositeInterceptor:
        self.interceptors.append(interceptor)
        return self

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        for interceptor in self.interceptors:
            result = interceptor.intercept(request)
            if not result.allowed:
                return result
        return ToolCallResult(allowed=True)


class BoundedSemaphore:
    """Thread-safe bounded concurrency counter with pressure reporting."""

    def __init__(
        self,
        max_concurrent: int = 10,
        backpressure_threshold: int = 8,
    ) -> None:
        self.max_concurrent = max_concurrent
        self.backpressure_threshold = backpressure_threshold
        self._active = 0
        self._total_acquired = 0
        self._total_rejected = 0
        self._lock = threading.Lock()

    def try_acquire(self) -> tuple[bool, str | None]:
        with self._lock:
            if self._active >= self.max_concurrent:
                self._total_rejected += 1
                return False, f"Max concurrency reached ({self.max_concurrent})"
            self._active += 1
            self._total_acquired += 1
            return True, None

    def release(self) -> None:
        with self._lock:
            if self._active > 0:
                self._active -= 1

    @property
    def is_under_pressure(self) -> bool:
        return self._active >= self.backpressure_threshold

    @property
    def active(self) -> int:
        return self._active

    @property
    def available(self) -> int:
        return max(0, self.max_concurrent - self._active)

    def stats(self) -> dict[str, Any]:
        return {
            "active": self._active,
            "max_concurrent": self.max_concurrent,
            "available": self.available,
            "under_pressure": self.is_under_pressure,
            "total_acquired": self._total_acquired,
            "total_rejected": self._total_rejected,
        }


def get_adapter_runtime(runtime: Any) -> Any:
    """Build the native adapter runtime seam from an ``AgtRuntime``."""

    from ._native_adapter_runtime import NativeAdapterRuntime

    return NativeAdapterRuntime(runtime)


class BaseIntegration:
    """Host lifecycle, audit, checkpoint, drift, and signal behavior."""

    def __init__(
        self,
        *,
        runtime: Any,
        checkpoint_frequency: int = 5,
        drift_threshold: float = 0.15,
        log_all_calls: bool = True,
    ) -> None:
        self.runtime = runtime
        self._adapter_runtime = get_adapter_runtime(runtime)
        self.checkpoint_frequency = checkpoint_frequency
        self.drift_threshold = drift_threshold
        self.log_all_calls = log_all_calls
        self.contexts: dict[str, AdapterExecutionState] = {}
        self._signal_handlers: dict[str, Callable[..., Any]] = {}
        self._event_listeners: dict[
            GovernanceEventType, list[Callable[..., Any]]
        ] = {}

    def pre_execute(
        self,
        state: AdapterExecutionState,
        input_data: Any,
    ) -> tuple[bool, str | None]:
        """Evaluate host input through the native session."""

        result = self._adapter_runtime.evaluate_input(state, body=input_data)
        return result.allowed, result.reason or None

    def post_execute(
        self,
        state: AdapterExecutionState,
        output_data: Any,
    ) -> tuple[bool, str | None]:
        """Evaluate host output and update lifecycle counters."""

        result = self._adapter_runtime.evaluate_output(state, content=output_data)
        if result.allowed:
            self.record_host_completion(state, output_data=output_data)
        return result.allowed, result.reason or None

    def create_context(self, agent_id: str) -> AdapterExecutionState:
        from uuid import uuid4

        state = AdapterExecutionState(
            agent_id=agent_id,
            session_id=str(uuid4())[:8],
            checkpoint_frequency=self.checkpoint_frequency,
            drift_threshold=self.drift_threshold,
        )
        self.contexts[agent_id] = state
        return state

    def on(
        self,
        event_type: GovernanceEventType,
        callback: Callable[..., Any],
    ) -> None:
        self._event_listeners.setdefault(event_type, []).append(callback)

    def emit(self, event_type: GovernanceEventType, data: dict[str, Any]) -> None:
        for callback in self._event_listeners.get(event_type, []):
            try:
                callback(data)
            except Exception:
                logger.warning(
                    "Governance event listener failed for %s",
                    event_type,
                    exc_info=True,
                )

    @staticmethod
    def hash_context(context: Any) -> str | None:
        if context is None:
            return None
        try:
            canonical = json.dumps(
                context,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
        except Exception:
            logger.debug("Unable to canonicalize context", exc_info=True)
            return None
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def trusted_skill_metadata_source(
        *,
        skill_name: Any = None,
        skill_origin: Any = None,
    ) -> TrustedSkillMetadataSource | None:
        def normalized(value: Any) -> str | None:
            if not isinstance(value, str):
                return None
            value = value.strip()
            return value or None

        name = normalized(skill_name)
        origin = normalized(skill_origin)
        if name is None and origin is None:
            return None
        return TrustedSkillMetadataSource(skill_name=name, skill_origin=origin)

    @staticmethod
    def trusted_skill_metadata_from_mapping(
        metadata: Mapping[str, Any] | None,
        *,
        skill_name_key: str = "skill_name",
        skill_origin_key: str = "skill_origin",
    ) -> TrustedSkillMetadataSource | None:
        if not isinstance(metadata, Mapping):
            return None
        return BaseIntegration.trusted_skill_metadata_source(
            skill_name=metadata.get(skill_name_key),
            skill_origin=metadata.get(skill_origin_key),
        )

    @staticmethod
    def trusted_sources(
        *sources: TrustedSkillMetadataSource | None,
    ) -> tuple[TrustedSkillMetadataSource, ...]:
        return tuple(source for source in sources if source is not None)

    @staticmethod
    def trusted_sources_from_attrs(
        *objects: Any,
    ) -> tuple[TrustedSkillMetadataSource, ...]:
        return BaseIntegration.trusted_sources(
            *(
                BaseIntegration.trusted_skill_metadata_source(
                    skill_name=getattr(obj, "skill_name", None),
                    skill_origin=getattr(obj, "skill_origin", None),
                )
                for obj in objects
            )
        )

    @staticmethod
    def extract_skill_metadata(
        *,
        trusted_sources: tuple[TrustedSkillMetadataSource, ...] = (),
        sources: tuple[Any, ...] = (),
        default_origin: str | None = None,
    ) -> SkillAuditMetadata:
        merged = list(trusted_sources)
        merged.extend(
            source
            for source in sources
            if isinstance(source, TrustedSkillMetadataSource)
        )
        name = next((source.skill_name for source in merged if source.skill_name), None)
        origin = next(
            (source.skill_origin for source in merged if source.skill_origin),
            None,
        )
        if name and not origin:
            origin = default_origin
        return SkillAuditMetadata(
            skill_name=name,
            skill_origin=origin,
            provenance_source_trust="trusted" if name else None,
        )

    def build_skill_audit_fields(
        self,
        *,
        trusted_sources: tuple[TrustedSkillMetadataSource, ...] = (),
        sources: tuple[Any, ...] = (),
        default_origin: str | None = None,
        context_before: Any | None = None,
        context_after: Any | None = None,
    ) -> dict[str, str | None]:
        metadata = self.extract_skill_metadata(
            trusted_sources=trusted_sources,
            sources=sources,
            default_origin=default_origin,
        )
        return SkillAuditMetadata(
            skill_name=metadata.skill_name,
            skill_origin=metadata.skill_origin,
            provenance_source_trust=metadata.provenance_source_trust,
            context_hash_before=self.hash_context(context_before),
            context_hash_after=self.hash_context(context_after),
        ).to_dict()

    def emit_skill_audit_event(
        self,
        event_type: GovernanceEventType,
        *,
        agent_id: str,
        action: str,
        trusted_sources: tuple[TrustedSkillMetadataSource, ...] = (),
        sources: tuple[Any, ...] = (),
        default_origin: str | None = None,
        context_before: Any | None = None,
        context_after: Any | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "agent_id": agent_id,
            "action": action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **self.build_skill_audit_fields(
                trusted_sources=trusted_sources,
                sources=sources,
                default_origin=default_origin,
                context_before=context_before,
                context_after=context_after,
            ),
            **extra,
        }
        self.emit(event_type, payload)
        return payload

    @staticmethod
    def compute_drift(
        state: AdapterExecutionState,
        output_data: Any,
    ) -> DriftResult | None:
        current_text = str(output_data)
        current_hash = hashlib.sha256(current_text.encode()).hexdigest()
        if state._baseline_hash is None:
            state._baseline_hash = current_hash
            state._baseline_text = current_text
            return None
        similarity = difflib.SequenceMatcher(
            None,
            state._baseline_text,
            current_text,
        ).ratio()
        score = 1.0 - similarity
        return DriftResult(
            score=score,
            exceeded=score > state.drift_threshold,
            threshold=state.drift_threshold,
            baseline_hash=state._baseline_hash,
            current_hash=current_hash,
        )

    def record_host_completion(
        self,
        state: AdapterExecutionState,
        *,
        output_data: Any | None = None,
        tokens: int = 0,
    ) -> None:
        """Record host counters and emit checkpoint/drift lifecycle events."""

        state.call_count += 1
        state.total_tokens += int(tokens)
        if output_data is not None and state.drift_threshold > 0.0:
            drift_result = self.compute_drift(state, output_data)
            if drift_result is not None:
                state._drift_scores.append(drift_result.score)
                if drift_result.exceeded:
                    self.emit(
                        GovernanceEventType.DRIFT_DETECTED,
                        {
                            "agent_id": state.agent_id,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "drift_score": drift_result.score,
                            "threshold": drift_result.threshold,
                            "baseline_hash": drift_result.baseline_hash,
                            "current_hash": drift_result.current_hash,
                        },
                    )
        if state.call_count % state.checkpoint_frequency == 0:
            checkpoint_id = f"checkpoint-{state.call_count}"
            state.checkpoints.append(checkpoint_id)
            self.emit(
                GovernanceEventType.CHECKPOINT_CREATED,
                {
                    "agent_id": state.agent_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "checkpoint_id": checkpoint_id,
                    "call_count": state.call_count,
                },
            )

    def on_signal(self, signal: str, handler: Callable[..., Any]) -> None:
        self._signal_handlers[signal] = handler

    def signal(self, agent_id: str, signal: str) -> None:
        handler = self._signal_handlers.get(signal)
        if handler is not None:
            handler(agent_id)


from agent_os.exceptions import PolicyViolationError as PolicyViolationError  # noqa: E402, F401
