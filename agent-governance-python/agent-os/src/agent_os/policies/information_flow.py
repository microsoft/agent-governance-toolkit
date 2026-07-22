# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Native AGT information-flow-control primitives.

The model is intentionally small and deterministic: content carries an
integrity axis and the existing AGT confidentiality lattice, labels are joined
with most-restrictive-wins semantics, and sinks are checked before execution.
The metadata shape accepts FIDES-compatible keys without taking a runtime
dependency on Agent Framework.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import Enum
from threading import RLock
from time import monotonic
from typing import Any, Mapping

from .context_envelope import ContextEnvelope, fold
from .data_classification import DataClassification


class IntegrityLabel(str, Enum):
    """Integrity provenance for content participating in IFC."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class InformationFlowRole(str, Enum):
    """Tool-boundary role used by the native IFC metadata schema."""

    SOURCE = "source"
    TRANSFORM = "transform"
    SINK = "sink"


class InformationFlowViolation(str, Enum):
    """Structured IFC violation categories."""

    UNTRUSTED_TO_TRUSTED_SINK = "untrusted_to_trusted_sink"
    CONFIDENTIALITY_EXCEEDED = "confidentiality_exceeded"
    MISSING_SINK_METADATA = "missing_sink_metadata"
    REVEAL_EXCEEDED = "reveal_exceeded"
    REVEAL_FIELD_DENIED = "reveal_field_denied"
    REVEAL_DENIED = "reveal_denied"
    DECLASSIFICATION_DENIED = "declassification_denied"
    ENDORSEMENT_DENIED = "endorsement_denied"


_FIDES_CONFIDENTIALITY_TO_AGT: dict[str, DataClassification] = {
    "public": DataClassification.PUBLIC,
    "internal": DataClassification.INTERNAL,
    "private": DataClassification.CONFIDENTIAL,
    "confidential": DataClassification.CONFIDENTIAL,
    "restricted": DataClassification.RESTRICTED,
    "user_identity": DataClassification.RESTRICTED,
    "top_secret": DataClassification.TOP_SECRET,
}


@dataclass(frozen=True)
class InformationFlowLabel:
    """Native AGT IFC content label.

    ``confidentiality`` reuses the existing ``DataClassification`` lattice so
    data-governance policies and context accumulation continue to compose.
    """

    integrity: IntegrityLabel = IntegrityLabel.UNTRUSTED
    confidentiality: DataClassification = DataClassification.TOP_SECRET
    categories: frozenset[str] = frozenset()
    source: str = ""

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        default_integrity: IntegrityLabel = IntegrityLabel.UNTRUSTED,
        default_confidentiality: DataClassification = DataClassification.TOP_SECRET,
    ) -> InformationFlowLabel:
        """Parse AGT or FIDES-compatible label metadata."""

        label_value = _nested_label_mapping(value)
        integrity = _coerce_integrity(
            label_value.get("integrity", label_value.get("source_integrity", default_integrity))
        )
        confidentiality = _coerce_confidentiality(
            label_value.get(
                "confidentiality",
                label_value.get("classification", default_confidentiality),
            )
        )
        categories = label_value.get("categories", label_value.get("labels", ()))
        return cls(
            integrity=integrity,
            confidentiality=confidentiality,
            categories=frozenset(str(c) for c in _iterable(categories)),
            source=str(label_value.get("source", "")),
        )

    def to_metadata(self) -> dict[str, Any]:
        """Return a FIDES-compatible metadata dictionary."""

        return {
            "integrity": self.integrity.value,
            "confidentiality": self.confidentiality.name.lower(),
            "categories": sorted(self.categories),
            "source": self.source,
        }


@dataclass(frozen=True)
class InformationFlowSinkPolicy:
    """Pre-execution sink policy enforced against the accumulated context."""

    accepts_untrusted: bool
    max_allowed_confidentiality: DataClassification
    name: str = ""

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        default_name: str = "",
    ) -> InformationFlowSinkPolicy:
        """Parse AGT or FIDES-compatible sink metadata."""

        policy = _nested_ifc_mapping(value)
        if "sink" in policy and isinstance(policy["sink"], Mapping):
            policy = dict(policy)
            policy.update(policy["sink"])
        return cls(
            accepts_untrusted=_coerce_bool(policy.get("accepts_untrusted", False)),
            max_allowed_confidentiality=_coerce_confidentiality(
                policy.get("max_allowed_confidentiality", DataClassification.PUBLIC)
            ),
            name=str(policy.get("name", default_name)),
        )


@dataclass(frozen=True)
class InformationFlowDecision:
    """Result of evaluating an IFC sink transition."""

    allowed: bool
    reason: str = ""
    violation: InformationFlowViolation | None = None


@dataclass(frozen=True)
class InformationFlowTransformDecision:
    """Decision for reveal, declassification, or endorsement transforms."""

    allowed: bool
    label: InformationFlowLabel
    value: Any = None
    reason: str = ""
    violation: InformationFlowViolation | None = None
    audit_event: dict[str, Any] | None = None


@dataclass(frozen=True)
class InformationFlowRevealPolicy:
    """Policy for releasing data from a quarantined variable.

    ``allowed_fields`` constrains structured object reveals. ``max_output_chars``
    bounds the observable channel capacity for strings and serialized values.
    The target label is explicit so callers cannot accidentally remove
    confidentiality or integrity through a reveal operation.
    """

    allowed_fields: frozenset[str] = frozenset()
    requested_fields: frozenset[str] = frozenset()
    max_output_chars: int = 4096
    target_confidentiality: DataClassification | None = None
    target_integrity: IntegrityLabel | None = None
    authority: str = ""
    reason: str = ""
    authorization_reference: str = ""
    authorizer: Callable[[InformationFlowLabel], bool] | None = field(
        default=None,
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if self.max_output_chars < 0:
            raise ValueError("max_output_chars must be non-negative")


class QuarantinedInformationFlowStore:
    """In-memory FIDES-style variable store for labeled tool results.

    Values remain hidden behind opaque handles until explicitly revealed through
    an ``InformationFlowRevealPolicy``. This gives hosts a deterministic
    quarantine primitive without depending on an LLM reveal path.
    """

    def __init__(self, *, max_entries: int = 1024, ttl_seconds: float | None = None) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._values: dict[str, tuple[Any, InformationFlowLabel, float]] = {}
        self._lock = RLock()
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds

    def put(self, variable_id: str, value: Any, label: InformationFlowLabel) -> str:
        """Store a labeled value and return its opaque handle."""

        if not variable_id:
            raise ValueError("variable_id must be non-empty")
        with self._lock:
            self._evict_expired_locked()
            if len(self._values) >= self._max_entries:
                oldest = min(self._values.items(), key=lambda item: item[1][2])[0]
                del self._values[oldest]
            self._values[variable_id] = (value, label, monotonic())
        return f"ifcvar://{variable_id}"

    def get_label(self, variable_id: str) -> InformationFlowLabel:
        """Return the label for a quarantined variable without revealing content."""

        return self._lookup(variable_id)[1]

    def delete(self, variable_id: str) -> None:
        """Release a quarantined variable and its raw value."""

        with self._lock:
            del self._values[_normalize_variable_id(variable_id)]

    def reveal(
        self,
        variable_id: str,
        policy: InformationFlowRevealPolicy,
    ) -> InformationFlowTransformDecision:
        """Reveal a bounded view of a quarantined variable."""

        value, label = self._lookup(variable_id)
        if not _is_authorized(policy, label):
            return InformationFlowTransformDecision(
                allowed=False,
                label=label,
                reason="IFC reveal requires explicit authority and reason",
                violation=InformationFlowViolation.REVEAL_DENIED,
            )

        revealed = value
        if isinstance(value, Mapping) and (policy.allowed_fields or policy.requested_fields):
            requested = policy.requested_fields or policy.allowed_fields
            denied = sorted(requested - policy.allowed_fields) if policy.allowed_fields else []
            if denied:
                return InformationFlowTransformDecision(
                    allowed=False,
                    label=label,
                    reason=f"IFC reveal denied fields: {', '.join(denied)}",
                    violation=InformationFlowViolation.REVEAL_FIELD_DENIED,
                )
            revealed = {k: value[k] for k in value if str(k) in requested}

        serialized = str(revealed)
        if len(serialized) > policy.max_output_chars:
            return InformationFlowTransformDecision(
                allowed=False,
                label=label,
                reason=(
                    "IFC reveal exceeded capacity "
                    f"{len(serialized)} > {policy.max_output_chars}"
                ),
                violation=InformationFlowViolation.REVEAL_EXCEEDED,
            )

        target_confidentiality = (
            policy.target_confidentiality
            if policy.target_confidentiality is not None
            else label.confidentiality
        )
        target_integrity = (
            policy.target_integrity
            if policy.target_integrity is not None
            else label.integrity
        )
        target = InformationFlowLabel(
            integrity=target_integrity,
            confidentiality=target_confidentiality,
            categories=label.categories,
            source=label.source,
        )
        if target.confidentiality < label.confidentiality:
            declassified = declassify_label(
                label,
                target.confidentiality,
                authority=policy.authority,
                reason=policy.reason,
                authorization_reference=policy.authorization_reference,
                authorizer=policy.authorizer,
            )
            if not declassified.allowed:
                return declassified
            target = replace(target, confidentiality=declassified.label.confidentiality)

        if target.integrity == IntegrityLabel.TRUSTED and label.integrity == IntegrityLabel.UNTRUSTED:
            endorsed = endorse_label(
                label,
                authority=policy.authority,
                reason=policy.reason,
                authorization_reference=policy.authorization_reference,
                authorizer=policy.authorizer,
            )
            if not endorsed.allowed:
                return endorsed
            target = replace(target, integrity=endorsed.label.integrity)

        return InformationFlowTransformDecision(
            allowed=True,
            value=revealed,
            label=target,
            audit_event={
                "operation": "reveal",
                "variable_id": variable_id,
                "authority": policy.authority,
                "reason": policy.reason,
                "authorization_reference": policy.authorization_reference,
                "source_confidentiality": label.confidentiality.name,
                "target_confidentiality": target.confidentiality.name,
                "source_integrity": label.integrity.value,
                "target_integrity": target.integrity.value,
                "output_chars": len(serialized),
            },
        )

    def _lookup(self, variable_id: str) -> tuple[Any, InformationFlowLabel]:
        normalized = _normalize_variable_id(variable_id)
        with self._lock:
            self._evict_expired_locked()
            if normalized not in self._values:
                raise KeyError(f"Unknown IFC variable: {variable_id}")
            value, label, _created_at = self._values[normalized]
            return value, label

    def _evict_expired_locked(self) -> None:
        if self._ttl_seconds is None:
            return
        cutoff = monotonic() - self._ttl_seconds
        expired = [
            variable_id
            for variable_id, (_value, _label, created_at) in self._values.items()
            if created_at < cutoff
        ]
        for variable_id in expired:
            del self._values[variable_id]


def default_unlabeled_source_label(source: str = "") -> InformationFlowLabel:
    """Return the secure strict-mode label for unlabeled external content."""

    return InformationFlowLabel(
        integrity=IntegrityLabel.UNTRUSTED,
        confidentiality=DataClassification.TOP_SECRET,
        source=source,
    )


def join_labels(labels: list[InformationFlowLabel]) -> InformationFlowLabel:
    """Join labels with most-restrictive-wins IFC semantics."""

    if not labels:
        return default_unlabeled_source_label()
    integrity = (
        IntegrityLabel.UNTRUSTED
        if any(label.integrity == IntegrityLabel.UNTRUSTED for label in labels)
        else IntegrityLabel.TRUSTED
    )
    confidentiality = max(label.confidentiality for label in labels)
    categories = frozenset().union(*(label.categories for label in labels))
    return InformationFlowLabel(
        integrity=integrity,
        confidentiality=confidentiality,
        categories=categories,
    )


def fold_information_flow_label(
    env: ContextEnvelope,
    label: InformationFlowLabel,
) -> ContextEnvelope:
    """Fold an IFC label into an existing context envelope."""

    joined = join_labels(
        [
            InformationFlowLabel(
                integrity=env.integrity,
                confidentiality=env.aggregate_sensitivity,
                categories=env.labels,
            ),
            label,
        ]
    )
    folded = fold(env, label.categories, label.confidentiality)
    return replace(folded, integrity=joined.integrity.value)


def enforce_sink(
    env: ContextEnvelope,
    sink_policy: InformationFlowSinkPolicy,
) -> InformationFlowDecision:
    """Deny flows from accumulated context into an incompatible sink."""

    if env.integrity == IntegrityLabel.UNTRUSTED.value and not sink_policy.accepts_untrusted:
        return InformationFlowDecision(
            allowed=False,
            reason=(
                "IFC blocked sink: untrusted context cannot flow to a trusted-only sink"
            ),
            violation=InformationFlowViolation.UNTRUSTED_TO_TRUSTED_SINK,
        )

    if env.aggregate_sensitivity > sink_policy.max_allowed_confidentiality:
        return InformationFlowDecision(
            allowed=False,
            reason=(
                f"IFC blocked sink: context confidentiality {env.aggregate_sensitivity.name} exceeds "
                f"{sink_policy.max_allowed_confidentiality.name}"
            ),
            violation=InformationFlowViolation.CONFIDENTIALITY_EXCEEDED,
        )

    return InformationFlowDecision(allowed=True)


def declassify_label(
    label: InformationFlowLabel,
    target_confidentiality: DataClassification | str | int,
    *,
    authority: str,
    reason: str,
    authorization_reference: str = "",
    authorizer: Callable[[InformationFlowLabel], bool] | None = None,
) -> InformationFlowTransformDecision:
    """Explicitly lower confidentiality with an auditable authority and reason."""

    target = _coerce_confidentiality(target_confidentiality)
    if (
        not authority
        or not reason
        or not authorization_reference
        or authorizer is None
        or not authorizer(label)
    ):
        return InformationFlowTransformDecision(
            allowed=False,
            label=label,
            reason="IFC declassification requires trusted authorizer approval",
            violation=InformationFlowViolation.DECLASSIFICATION_DENIED,
        )
    if target > label.confidentiality:
        return InformationFlowTransformDecision(
            allowed=False,
            label=label,
            reason=(
                "IFC declassification target cannot be more confidential than "
                "the source label"
            ),
            violation=InformationFlowViolation.DECLASSIFICATION_DENIED,
        )
    return InformationFlowTransformDecision(
        allowed=True,
        label=replace(label, confidentiality=target),
        audit_event={
            "operation": "declassify",
            "authority": authority,
            "reason": reason,
            "authorization_reference": authorization_reference,
            "source_confidentiality": label.confidentiality.name,
            "target_confidentiality": target.name,
        },
    )


def endorse_label(
    label: InformationFlowLabel,
    *,
    authority: str,
    reason: str,
    authorization_reference: str = "",
    authorizer: Callable[[InformationFlowLabel], bool] | None = None,
) -> InformationFlowTransformDecision:
    """Explicitly raise integrity from untrusted to trusted."""

    if (
        not authority
        or not reason
        or not authorization_reference
        or authorizer is None
        or not authorizer(label)
    ):
        return InformationFlowTransformDecision(
            allowed=False,
            label=label,
            reason="IFC endorsement requires trusted authorizer approval",
            violation=InformationFlowViolation.ENDORSEMENT_DENIED,
        )
    return InformationFlowTransformDecision(
        allowed=True,
        label=replace(label, integrity=IntegrityLabel.TRUSTED),
        audit_event={
            "operation": "endorse",
            "authority": authority,
            "reason": reason,
            "authorization_reference": authorization_reference,
            "source_integrity": label.integrity.value,
            "target_integrity": IntegrityLabel.TRUSTED.value,
        },
    )


def normalize_fides_additional_properties(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return canonical AGT IFC metadata from FIDES additional_properties."""

    metadata = _nested_ifc_mapping(payload)
    if not metadata:
        return {}
    if any(k in metadata for k in ("accepts_untrusted", "max_allowed_confidentiality", "sink")):
        policy = InformationFlowSinkPolicy.from_mapping(metadata)
        return {
            "accepts_untrusted": policy.accepts_untrusted,
            "max_allowed_confidentiality": policy.max_allowed_confidentiality.name.lower(),
            "name": policy.name,
        }
    return InformationFlowLabel.from_mapping(metadata).to_metadata()


def acs_information_flow_annotation(
    *,
    label: InformationFlowLabel | None = None,
    envelope: ContextEnvelope | None = None,
    sink_policy: InformationFlowSinkPolicy | None = None,
) -> dict[str, Any]:
    """Build the ACS ``annotations.information_flow`` profile payload."""

    annotation: dict[str, Any] = {"schema": "agt.ifc.annotation.v1"}
    if label is not None:
        annotation["label"] = label.to_metadata()
    if envelope is not None:
        annotation["context"] = {
            "envelope_id": envelope.envelope_id,
            "workflow_id": envelope.workflow_id,
            "aggregate_sensitivity": envelope.aggregate_sensitivity.name.lower(),
            "integrity": envelope.integrity,
            "label_count": len(envelope.labels),
            "version": envelope.version,
        }
    if sink_policy is not None:
        annotation["sink"] = {
            "accepts_untrusted": sink_policy.accepts_untrusted,
            "max_allowed_confidentiality": (
                sink_policy.max_allowed_confidentiality.name.lower()
            ),
            "name": sink_policy.name,
        }
    return annotation


def requires_sink_metadata(payload: Any) -> bool:
    """Return true when a runtime payload represents a governed tool sink."""

    normalized = _payload_mapping(payload)
    if normalized is None:
        return False
    return _information_flow_role(normalized) is InformationFlowRole.SINK


def label_from_payload(
    payload: Any,
    *,
    default_source: str = "",
) -> InformationFlowLabel:
    """Extract a result label or apply the strict unlabeled-source default."""

    if isinstance(payload, Mapping):
        metadata = _nested_ifc_mapping(payload)
        if metadata:
            return InformationFlowLabel.from_mapping(metadata)
    return default_unlabeled_source_label(default_source)


def _nested_ifc_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    for key in ("ifc", "information_flow", "agt_ifc"):
        nested = value.get(key)
        if isinstance(nested, Mapping):
            return dict(nested)
    additional = value.get("additional_properties")
    if isinstance(additional, Mapping):
        nested = _nested_ifc_mapping(additional)
        if nested:
            return nested
    nested_fides = value.get("fides")
    if isinstance(nested_fides, Mapping):
        return dict(nested_fides)
    for key in ("label", "content_label", "security_label"):
        nested = value.get(key)
        if isinstance(nested, Mapping):
            return {key: dict(nested)}
    return {
        key: value[key]
        for key in (
            "integrity",
            "source_integrity",
            "confidentiality",
            "classification",
            "categories",
            "labels",
            "accepts_untrusted",
            "max_allowed_confidentiality",
            "sink",
            "source",
            "role",
        )
        if key in value
    }


def _nested_label_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    if "label" in value and isinstance(value["label"], Mapping):
        nested = dict(value)
        nested.update(value["label"])
        return nested
    if "content_label" in value and isinstance(value["content_label"], Mapping):
        nested = dict(value)
        nested.update(value["content_label"])
        return nested
    if "security_label" in value and isinstance(value["security_label"], Mapping):
        nested = dict(value)
        nested.update(value["security_label"])
        return nested
    return dict(value)


def _coerce_integrity(value: IntegrityLabel | str) -> IntegrityLabel:
    if isinstance(value, IntegrityLabel):
        return value
    normalized = str(value).strip().lower()
    if normalized == IntegrityLabel.TRUSTED.value:
        return IntegrityLabel.TRUSTED
    if normalized == IntegrityLabel.UNTRUSTED.value:
        return IntegrityLabel.UNTRUSTED
    raise ValueError(f"Unknown IFC integrity label: {value!r}")


def _coerce_bool(value: bool | str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
    raise ValueError(f"Unknown IFC boolean value: {value!r}")


def _coerce_confidentiality(value: DataClassification | str | int) -> DataClassification:
    if isinstance(value, DataClassification):
        return value
    if isinstance(value, int):
        return DataClassification(value)
    normalized = str(value).lower()
    if normalized in _FIDES_CONFIDENTIALITY_TO_AGT:
        return _FIDES_CONFIDENTIALITY_TO_AGT[normalized]
    try:
        return DataClassification[normalized.upper()]
    except KeyError as exc:
        raise ValueError(f"Unknown IFC confidentiality label: {value!r}") from exc


def _iterable(value: Any) -> tuple[Any, ...]:
    if value is None or value == "":
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(value)


def _payload_mapping(payload: Any) -> dict[str, Any] | None:
    if isinstance(payload, Mapping):
        return dict(payload)

    tool_name = getattr(payload, "tool_name", None)
    mcp_tool = getattr(payload, "mcp_tool", None)
    metadata = getattr(payload, "metadata", None)
    arguments = getattr(payload, "arguments", None)
    if tool_name is None and mcp_tool is None and not isinstance(metadata, Mapping):
        return None

    normalized: dict[str, Any] = {}
    if tool_name is not None:
        normalized["tool_name"] = tool_name
    if mcp_tool is not None:
        normalized["mcp_tool"] = mcp_tool
    if isinstance(arguments, Mapping):
        normalized["tool_args"] = dict(arguments)
    if isinstance(metadata, Mapping):
        normalized.update(metadata)
    return normalized


def _information_flow_role(payload: Mapping[str, Any]) -> InformationFlowRole | None:
    metadata = _nested_ifc_mapping(payload)
    role = metadata.get("role", payload.get("role"))
    if role is None:
        return None
    normalized = str(role).strip().lower()
    try:
        return InformationFlowRole(normalized)
    except ValueError as exc:
        raise ValueError(f"Unknown IFC role: {role!r}") from exc


def _normalize_variable_id(variable_id: str) -> str:
    if variable_id.startswith("ifcvar://"):
        return variable_id.removeprefix("ifcvar://")
    return variable_id


def _is_authorized(
    policy: InformationFlowRevealPolicy,
    label: InformationFlowLabel,
) -> bool:
    if not policy.authority or not policy.reason:
        return False
    if policy.authorizer is not None:
        return bool(policy.authorizer(label))
    return False
