# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import _native


@dataclass(frozen=True)
class ValidationDiagnostic:
    component: str
    code: str
    message: str
    source: str
    path: str | None = None
    line: int | None = None
    column: int | None = None
    snippet: str | None = None

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "ValidationDiagnostic":
        return cls(
            component=str(value["component"]),
            code=str(value["code"]),
            message=str(value["message"]),
            source=str(value["source"]),
            path=value.get("path"),
            line=value.get("line"),
            column=value.get("column"),
            snippet=value.get("snippet"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "code": self.code,
            "message": self.message,
            "source": self.source,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
        }


@dataclass(frozen=True)
class ArtifactValidationResult:
    valid: bool
    diagnostics: tuple[ValidationDiagnostic, ...]

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "ArtifactValidationResult":
        return cls(
            valid=bool(value["valid"]),
            diagnostics=tuple(
                ValidationDiagnostic.from_mapping(diagnostic)
                for diagnostic in value.get("diagnostics", [])
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }


def validate_acs_manifest(manifest: str) -> ArtifactValidationResult:
    """Validate one complete or partial ACS manifest."""

    if not isinstance(manifest, str):
        return _input_error(
            "manifest",
            "manifest_input_invalid",
            "Manifest input must be a YAML or JSON string.",
        )
    return ArtifactValidationResult.from_mapping(_native.validate_manifest_artifact(manifest))


def validate_acs_artifacts(
    manifest: str,
    rego: str | dict[str, str],
    *,
    opa_path: str | None = None,
) -> ArtifactValidationResult:
    """Validate ACS manifest and Rego strings through the shared Rust core."""

    if not isinstance(manifest, str):
        return _input_error(
            "manifest",
            "manifest_input_invalid",
            "Manifest input must be a YAML or JSON string.",
        )
    if isinstance(rego, str):
        try:
            rego.encode("utf-8")
        except UnicodeEncodeError as exc:
            return _input_error(
                "rego",
                "rego_encoding_error",
                f"Rego module is not valid UTF-8 text. {exc}",
            )
        modules = {"policy.rego": rego}
    elif type(rego) is dict:
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in rego.items()):
            return _input_error(
                "rego",
                "rego_input_invalid",
                "Rego module names and values must be strings.",
            )
        for source, contents in rego.items():
            try:
                source.encode("utf-8")
                contents.encode("utf-8")
            except UnicodeEncodeError as exc:
                return ArtifactValidationResult(
                    valid=False,
                    diagnostics=(
                        ValidationDiagnostic(
                            component="rego",
                            code="rego_encoding_error",
                            message=f"Rego module is not valid UTF-8 text. {exc}",
                            source=source,
                        ),
                    ),
                )
        modules = rego
    else:
        return _input_error(
            "rego",
            "rego_input_invalid",
            "Rego input must be a string or a dictionary of source names to strings.",
        )
    if opa_path is not None and not isinstance(opa_path, str):
        return _input_error(
            "rego",
            "opa_path_invalid",
            "opa_path must be a string when supplied.",
        )
    return ArtifactValidationResult.from_mapping(
        _native.validate_artifacts(manifest, modules, opa_path)
    )


def _input_error(component: str, code: str, message: str) -> ArtifactValidationResult:
    return ArtifactValidationResult(
        valid=False,
        diagnostics=(
            ValidationDiagnostic(
                component=component,
                code=code,
                message=message,
                source=component,
            ),
        ),
    )
