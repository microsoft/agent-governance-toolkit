# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Typed AGT manifest authoring, provenance, and adapter preflight."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)

InterventionPointName = Literal[
    "agent_startup",
    "input",
    "pre_model_call",
    "post_model_call",
    "pre_tool_call",
    "post_tool_call",
    "output",
    "agent_shutdown",
]
ToolCatalogMode = Literal["manifest", "host_dynamic", "optional"]
ApprovalMode = Literal["runtime", "unsupported"]
BudgetAccounting = Literal["attempted", "successful"]


class _ManifestModel(BaseModel):
    """Base model that distinguishes omitted fields from invalid nulls."""

    @model_validator(mode="after")
    def reject_explicit_nulls(self) -> "_ManifestModel":
        for name in self.model_fields_set:
            if (
                name in type(self).model_fields
                and getattr(self, name, None) is None
            ):
                raise ValueError(f"{name} must not be null")
        return self


class ExtendsUrl(_ManifestModel):
    """HTTPS manifest reference with at most one optional integrity pin."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, pattern=r"^https://")
    integrity: str | None = Field(
        default=None, pattern=r"^sha256-[A-Za-z0-9+/_=-]+$"
    )
    sha256: str | None = Field(default=None, pattern=r"^[A-Fa-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_no_conflicting_pins(self) -> "ExtendsUrl":
        if self.integrity is not None and self.sha256 is not None:
            raise ValueError("integrity and sha256 cannot both be set")
        return self


class BundleUrl(ExtendsUrl):
    """Pinned HTTPS policy bundle reference."""

    @model_validator(mode="after")
    def validate_bundle_pin(self) -> "BundleUrl":
        if self.integrity is None and self.sha256 is None:
            raise ValueError("bundle_url requires integrity or sha256")
        return self


class PolicyDefinition(_ManifestModel):
    """One ACS policy definition with extension fields preserved."""

    model_config = ConfigDict(extra="allow")

    type: Literal["rego", "test", "cedar", "custom"]
    query: str | dict[str, Any] | None = None
    bundle: str | None = None
    bundle_url: BundleUrl | None = None
    data_paths: list[str] = Field(default_factory=list)
    data: dict[str, Any] | list[Any] | str | None = None
    adapter: str | None = None
    policy_set: str | None = None
    policy_path: str | None = None
    entities_path: str | None = None
    schema_path: str | None = None

    @model_validator(mode="after")
    def validate_policy_type(self) -> "PolicyDefinition":
        if self.type == "custom" and not self.adapter:
            raise ValueError("custom policies require adapter")
        if self.type == "cedar" and (self.policy_set is None) == (
            self.policy_path is None
        ):
            raise ValueError(
                "cedar policies require exactly one of policy_set or policy_path"
            )
        return self


class PolicyBinding(_ManifestModel):
    """Intervention-point binding to a named policy."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(min_length=1)
    query: str | None = None
    data_paths: list[str] = Field(default_factory=list)


class AnnotationBinding(_ManifestModel):
    """Projection consumed by one named annotator."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    source: str = Field(alias="from", min_length=1)


class InterventionPointDefinition(_ManifestModel):
    """One intervention-point declaration."""

    model_config = ConfigDict(extra="forbid")

    policy_target: str | None = None
    policy_target_kind: str | None = None
    tool_name_from: str | None = None
    annotations: dict[str, AnnotationBinding] = Field(default_factory=dict)
    policy: PolicyBinding | None = None

    @model_validator(mode="after")
    def validate_non_empty(self) -> "InterventionPointDefinition":
        if (
            self.policy_target is None
            and self.policy is None
            and not self.annotations
        ):
            raise ValueError(
                "an intervention point requires policy_target, policy, or annotations"
            )
        return self


class ToolDefinition(_ManifestModel):
    """Tool catalog entry with host extension fields preserved."""

    model_config = ConfigDict(extra="allow")

    id: str | None = None
    type: str | None = None
    description: str | None = None
    security_labels: str | list[str] | None = None
    clearance: str | list[str] | None = None


class AnnotatorDefinition(_ManifestModel):
    """Annotator definition with provider extension fields preserved."""

    model_config = ConfigDict(extra="allow")

    type: Literal["classifier", "llm", "endpoint"]
    provider: str | None = None
    endpoint: str | None = None
    base_url: str | None = None
    model: str | None = None
    deployment: str | None = None
    api_version: str | None = None
    api_key: str | None = None
    api_key_env: str | None = None
    api_key_header: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    provider_config: dict[str, Any] = Field(default_factory=dict)
    label_field: str | None = None
    prompt: str | None = None
    system_prompt: str | None = None
    system_prompt_file: str | None = None
    system_prompt_url: BundleUrl | None = None
    timeout_ms: int | None = Field(default=None, ge=1)


class ApprovalResolverDefinition(_ManifestModel):
    """Named host approval resolver with extension fields preserved."""

    model_config = ConfigDict(extra="allow")

    type: str = Field(min_length=1)


class ApprovalSection(_ManifestModel):
    """AGT-owned approval configuration."""

    model_config = ConfigDict(extra="forbid")

    default_resolver: str | None = None
    timeout_seconds: int | None = Field(default=None, ge=1)
    on_timeout: Literal["deny", "allow", "suspend"] | None = None
    fatigue_threshold: int | None = Field(default=None, ge=1)
    fatigue_window_seconds: int | None = Field(default=None, ge=1)
    resolvers: dict[str, ApprovalResolverDefinition] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_default_resolver(self) -> "ApprovalSection":
        if (
            self.default_resolver is not None
            and self.resolvers
            and self.default_resolver not in self.resolvers
        ):
            raise ValueError("default_resolver must name an entry in resolvers")
        return self


class RuntimeLimits(_ManifestModel):
    """AGT runtime resource limits."""

    model_config = ConfigDict(extra="forbid")

    max_snapshot_bytes: int | None = Field(default=None, ge=1)
    max_policy_input_bytes: int | None = Field(default=None, ge=1)
    max_annotators_per_point: int | None = Field(default=None, ge=1)
    max_annotator_output_bytes: int | None = Field(default=None, ge=1)
    max_extends_depth: int | None = Field(default=None, ge=1)
    max_intervention_points_per_run: int | None = Field(default=None, ge=1)


@dataclass(frozen=True)
class ManifestProvenance:
    """Location used to resolve relative manifest references."""

    source: str | None = None
    base_dir: Path | None = None


class AdapterManifestContract(_ManifestModel):
    """Deployment requirements an adapter checks before accepting a runtime."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    required_intervention_points: frozenset[InterventionPointName]
    tool_catalog_mode: ToolCatalogMode = "optional"
    approval_mode: ApprovalMode = "runtime"
    requires_approval_section: bool = False
    transform_intervention_points: frozenset[InterventionPointName] = frozenset()
    budget_accounting: BudgetAccounting = "attempted"

    @model_validator(mode="after")
    def validate_approval_contract(self) -> "AdapterManifestContract":
        if self.requires_approval_section and self.approval_mode != "runtime":
            raise ValueError(
                "requires_approval_section requires approval_mode runtime"
            )
        return self


class ManifestCompatibilityError(ValueError):
    """Raised when a valid manifest cannot satisfy an adapter contract."""

    def __init__(
        self,
        adapter: str,
        *,
        missing_intervention_points: frozenset[str] = frozenset(),
        missing_tool_catalog: bool = False,
        missing_approval: bool = False,
        unsupported_approval: bool = False,
    ) -> None:
        self.adapter = adapter
        self.missing_intervention_points = missing_intervention_points
        self.missing_tool_catalog = missing_tool_catalog
        self.missing_approval = missing_approval
        self.unsupported_approval = unsupported_approval
        problems: list[str] = []
        if missing_intervention_points:
            problems.append(
                "missing intervention points "
                + ", ".join(sorted(missing_intervention_points))
            )
        if missing_tool_catalog:
            problems.append("missing manifest tool catalog")
        if missing_approval:
            problems.append("missing approval section")
        if unsupported_approval:
            problems.append("approval section is not supported")
        super().__init__(
            f"manifest is incompatible with adapter {adapter}: "
            + "; ".join(problems)
        )


class AgtManifest(_ManifestModel):
    """Lossless typed representation of AGT-MANIFEST-1.0."""

    model_config = ConfigDict(extra="forbid")

    agent_control_specification_version: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)
    extends: list[str | ExtendsUrl] = Field(default_factory=list)
    policies: dict[str, PolicyDefinition] = Field(default_factory=dict)
    intervention_points: dict[
        InterventionPointName, InterventionPointDefinition
    ] = Field(default_factory=dict)
    tools: dict[str, ToolDefinition] = Field(default_factory=dict)
    annotators: dict[str, AnnotatorDefinition] = Field(default_factory=dict)
    approval: ApprovalSection | None = None
    limits: RuntimeLimits | None = None

    _provenance: ManifestProvenance = PrivateAttr(
        default_factory=ManifestProvenance
    )

    @field_validator("policies", "tools", "annotators")
    @classmethod
    def validate_non_empty_keys(cls, value: dict[str, Any]) -> dict[str, Any]:
        if any(not key for key in value):
            raise ValueError("manifest map keys must be non-empty")
        return value

    @field_validator("extends")
    @classmethod
    def validate_extends_schemes(
        cls, value: list[str | ExtendsUrl]
    ) -> list[str | ExtendsUrl]:
        for entry in value:
            if isinstance(entry, str) and re.match(
                r"^[A-Za-z][A-Za-z0-9+.-]*://", entry
            ) and not entry.startswith("https://"):
                raise ValueError("extends URLs must use https")
        return value

    @model_validator(mode="after")
    def validate_manifest(self) -> "AgtManifest":
        document_fields = {
            "metadata",
            "extends",
            "policies",
            "intervention_points",
            "tools",
            "annotators",
        }
        if not self.model_fields_set.intersection(document_fields):
            raise ValueError(
                "manifest requires metadata, extends, policies, "
                "intervention_points, tools, or annotators"
            )
        if "policies" in self.model_fields_set and not self.policies:
            raise ValueError("policies must not be empty when present")
        if (
            "intervention_points" in self.model_fields_set
            and not self.intervention_points
        ):
            raise ValueError(
                "intervention_points must not be empty when present"
            )
        for name, point in self.intervention_points.items():
            if point.tool_name_from is not None and name not in {
                "pre_tool_call",
                "post_tool_call",
            }:
                raise ValueError(
                    f"tool_name_from is not valid at intervention point {name}"
                )
        return self

    @property
    def provenance(self) -> ManifestProvenance:
        return self._provenance

    @classmethod
    def from_path(cls, path: Path | str) -> "AgtManifest":
        manifest_path = Path(path).resolve()
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, Mapping):
            raise ValueError("manifest document must be a mapping")
        manifest = cls.model_validate(raw)
        manifest._provenance = ManifestProvenance(
            source=str(manifest_path), base_dir=manifest_path.parent
        )
        return manifest

    @classmethod
    def from_document(
        cls,
        document: str | Mapping[str, Any],
        *,
        base_dir: Path | str | None = None,
        source: str | None = None,
    ) -> "AgtManifest":
        raw: Any = yaml.safe_load(document) if isinstance(document, str) else document
        if not isinstance(raw, Mapping):
            raise ValueError("manifest document must be a mapping")
        manifest = cls.model_validate(raw)
        manifest._provenance = ManifestProvenance(
            source=source,
            base_dir=Path(base_dir).resolve() if base_dir is not None else None,
        )
        return manifest

    def to_document(self) -> dict[str, Any]:
        """Return the lossless manifest mapping without provenance."""
        return self.model_dump(
            mode="python", by_alias=True, exclude_none=False, exclude_unset=True
        )

    def relative_references(self) -> tuple[str, ...]:
        """Return local references that need a base directory."""
        return tuple(
            value for value in self.local_references() if _is_relative_reference(value)
        )

    def local_references(self) -> tuple[str, ...]:
        """Return all manifest references that address the host filesystem."""
        refs: list[str] = []
        for entry in self.extends:
            if isinstance(entry, str) and _is_local_reference(entry):
                refs.append(entry)
        for policy in self.policies.values():
            for value in (
                policy.bundle,
                policy.policy_path,
                policy.entities_path,
                policy.schema_path,
            ):
                if value and _is_local_reference(value):
                    refs.append(value)
            refs.extend(
                value
                for value in policy.data_paths
                if _is_local_reference(value)
            )
        for point in self.intervention_points.values():
            if point.policy is not None:
                refs.extend(
                    value
                    for value in point.policy.data_paths
                    if _is_local_reference(value)
                )
        for annotator in self.annotators.values():
            if annotator.system_prompt_file and _is_local_reference(
                annotator.system_prompt_file
            ):
                refs.append(annotator.system_prompt_file)
        return tuple(refs)

    def resolved_document(self, base_dir: Path | str | None = None) -> dict[str, Any]:
        """Return a copy with local references made absolute."""
        effective_base = (
            Path(base_dir).resolve()
            if base_dir is not None
            else self.provenance.base_dir
        )
        if (
            self.provenance.source is not None
            and self.provenance.source.startswith("https://")
            and self.local_references()
        ):
            raise ValueError(
                "URL-sourced manifests cannot reference host-local files"
            )
        references = self.relative_references()
        if references and effective_base is None:
            raise ValueError(
                "base_dir is required for manifest documents with relative "
                f"references: {', '.join(references)}"
            )
        document = copy.deepcopy(self.to_document())
        if effective_base is None:
            return document

        document["extends"] = [
            _resolve_reference(entry, effective_base)
            if isinstance(entry, str)
            else entry
            for entry in document.get("extends", [])
        ]
        for policy in document.get("policies", {}).values():
            for key in ("bundle", "policy_path", "entities_path", "schema_path"):
                value = policy.get(key)
                if isinstance(value, str):
                    policy[key] = _resolve_reference(value, effective_base)
            if isinstance(policy.get("data_paths"), list):
                policy["data_paths"] = [
                    _resolve_reference(value, effective_base)
                    for value in policy["data_paths"]
                ]
        for point in document.get("intervention_points", {}).values():
            binding = point.get("policy")
            if isinstance(binding, dict) and isinstance(
                binding.get("data_paths"), list
            ):
                binding["data_paths"] = [
                    _resolve_reference(value, effective_base)
                    for value in binding["data_paths"]
                ]
        for annotator in document.get("annotators", {}).values():
            value = annotator.get("system_prompt_file")
            if isinstance(value, str):
                annotator["system_prompt_file"] = _resolve_reference(
                    value, effective_base
                )
        return document

    def validate_for(self, contract: AdapterManifestContract) -> None:
        """Fail before execution when an adapter cannot use this manifest."""
        if self.extends:
            raise ValueError(
                "adapter preflight requires a resolved manifest; unresolved "
                "extends may supply intervention points and tools"
            )
        missing_points = frozenset(contract.required_intervention_points).difference(
            self.intervention_points
        )
        missing_tools = contract.tool_catalog_mode == "manifest" and not self.tools
        missing_approval = (
            contract.approval_mode == "runtime"
            and contract.requires_approval_section
            and self.approval is None
        )
        unsupported_approval = (
            contract.approval_mode == "unsupported"
            and self.approval is not None
        )
        if (
            missing_points
            or missing_tools
            or missing_approval
            or unsupported_approval
        ):
            raise ManifestCompatibilityError(
                contract.name,
                missing_intervention_points=frozenset(missing_points),
                missing_tool_catalog=missing_tools,
                missing_approval=missing_approval,
                unsupported_approval=unsupported_approval,
            )


def _is_relative_reference(value: str) -> bool:
    return _is_local_reference(value) and not Path(value).is_absolute()


def _is_local_reference(value: str) -> bool:
    return re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value) is None


def _resolve_reference(value: str, base_dir: Path) -> str:
    if not _is_relative_reference(value):
        return value
    return str((base_dir / value).resolve())


__all__ = [
    "AdapterManifestContract",
    "AgtManifest",
    "ApprovalMode",
    "BudgetAccounting",
    "InterventionPointName",
    "ManifestCompatibilityError",
    "ManifestProvenance",
    "ToolCatalogMode",
]
