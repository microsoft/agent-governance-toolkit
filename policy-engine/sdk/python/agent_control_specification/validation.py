# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
import warnings
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

try:
    import jsonschema
except ImportError as exc:
    raise ImportError(
        "Artifact validation requires the validation extra. "
        'Install "agent-control-specification[validation]".'
    ) from exc

from ._client import parse_manifest, validate_manifest, validate_manifest_overlay

OPA_TIMEOUT_SECONDS = 10
SCHEMA_PACKAGE = "agent_control_specification.schema"
SCHEMA_NAME = "manifest.schema.json"
APPROVAL_SCHEMA_NAME = "approval.schema.json"
MAX_MANIFEST_BYTES = 1_048_576
MAX_REGO_BYTES = 1_048_576
MAX_REGO_MODULES = 64
MAX_DIAGNOSTICS = 100
MAX_DIAGNOSTIC_TEXT = 4096
MAX_OPA_OUTPUT_BYTES = 65_536
MAX_SOURCE_LABEL = 512


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

    def __post_init__(self) -> None:
        for field_name, limit in (
            ("message", MAX_DIAGNOSTIC_TEXT),
            ("source", MAX_SOURCE_LABEL),
            ("path", MAX_DIAGNOSTIC_TEXT),
            ("snippet", MAX_DIAGNOSTIC_TEXT),
        ):
            value = getattr(self, field_name)
            if isinstance(value, str) and len(value) > limit:
                object.__setattr__(self, field_name, value[:limit] + "...")

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
    diagnostics: tuple[ValidationDiagnostic, ...] = ()

    @property
    def valid(self) -> bool:
        return not self.diagnostics

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }


def validate_acs_artifacts(
    manifest: str,
    rego: str | dict[str, str],
    *,
    opa_path: str | None = None,
) -> ArtifactValidationResult:
    """Validate ACS manifest and Rego strings without constructing a runtime."""

    diagnostics: list[ValidationDiagnostic] = []
    parsed_manifest, manifest_diagnostic = _parse_manifest_string(manifest)
    if manifest_diagnostic is not None:
        diagnostics.append(manifest_diagnostic)
    elif parsed_manifest is not None:
        schema_diagnostics = list(validate_manifest_schema(parsed_manifest))
        diagnostics.extend(schema_diagnostics)
        if not schema_diagnostics:
            semantic_diagnostic = _manifest_semantic_diagnostic(
                manifest,
                overlay=_manifest_has_extends(parsed_manifest),
            )
            if semantic_diagnostic is not None:
                diagnostics.append(semantic_diagnostic)

    rego_modules, input_diagnostics = _normalize_rego_modules(rego)
    diagnostics.extend(input_diagnostics)
    if (
        parsed_manifest is not None
        and _manifest_declares_rego(parsed_manifest)
        and not rego_modules
        and not input_diagnostics
    ):
        diagnostics.append(
            ValidationDiagnostic(
                component="rego",
                code="rego_missing",
                message="The manifest declares a Rego policy but no Rego module was supplied.",
                source="rego",
            )
        )
    if rego_modules:
        executable = opa_path or shutil.which("opa")
        if executable is None:
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code="opa_unavailable",
                    message="OPA is required to validate Rego. Install opa on PATH or pass opa_path.",
                    source="opa",
                )
            )
        else:
            diagnostics.extend(_validate_rego_modules(executable, rego_modules))
    return ArtifactValidationResult(tuple(_limit_diagnostics(diagnostics)))


def validate_manifest_schema(
    manifest: dict[str, Any],
) -> tuple[ValidationDiagnostic, ...]:
    errors: list[jsonschema.ValidationError] = []
    truncated = False
    try:
        for error in _manifest_validator().iter_errors(manifest):
            if len(errors) >= MAX_DIAGNOSTICS:
                truncated = True
                break
            errors.append(error)
    except RecursionError:
        return (
            ValidationDiagnostic(
                component="manifest",
                code="manifest_resource_limit",
                message="Manifest JSON nesting exceeded the native validation limit.",
                source="manifest",
            ),
        )
    errors.sort(key=lambda error: tuple(str(part) for part in error.absolute_path))
    diagnostics = [
        ValidationDiagnostic(
            component="manifest",
            code="manifest_schema_error",
            message=error.message,
            source="manifest",
            path=_json_path(error.absolute_path),
        )
        for error in errors
    ]
    if truncated:
        diagnostics.append(_diagnostics_truncated())
    return tuple(diagnostics)


def _parse_manifest_string(
    manifest: str,
) -> tuple[dict[str, Any] | None, ValidationDiagnostic | None]:
    if not isinstance(manifest, str):
        return None, ValidationDiagnostic(
            component="manifest",
            code="manifest_input_invalid",
            message="Manifest input must be a YAML or JSON string.",
            source="manifest",
        )
    try:
        encoded = manifest.encode("utf-8")
    except UnicodeEncodeError as exc:
        return None, ValidationDiagnostic(
            component="manifest",
            code="manifest_encoding_error",
            message=f"Manifest is not valid UTF-8 text. {exc}",
            source="manifest",
        )
    if len(encoded) > MAX_MANIFEST_BYTES:
        return None, ValidationDiagnostic(
            component="manifest",
            code="manifest_size_exceeded",
            message=(
                f"Manifest is {len(encoded)} bytes, exceeding the "
                f"{MAX_MANIFEST_BYTES}-byte validation limit."
            ),
            source="manifest",
        )
    try:
        parsed = parse_manifest(manifest)
    except RuntimeError as exc:
        code = (
            "manifest_resource_limit"
            if "runtime_error:resource_limit_exceeded" in str(exc)
            else "manifest_parse_error"
        )
        return None, ValidationDiagnostic(
            component="manifest",
            code=code,
            message=str(exc),
            source="manifest",
        )
    if not isinstance(parsed, dict):
        return None, ValidationDiagnostic(
            component="manifest",
            code="manifest_root_invalid",
            message="Manifest must decode to a YAML or JSON object.",
            source="manifest",
            path="$",
        )
    return parsed, None


def _manifest_semantic_diagnostic(
    manifest: str,
    *,
    overlay: bool,
) -> ValidationDiagnostic | None:
    try:
        if overlay:
            validate_manifest_overlay(manifest)
        else:
            validate_manifest(manifest)
    except RuntimeError as exc:
        return ValidationDiagnostic(
            component="manifest",
            code="manifest_semantic_error",
            message=str(exc),
            source="manifest",
        )
    return None


def _manifest_has_extends(manifest: dict[str, Any]) -> bool:
    extends = manifest.get("extends")
    return isinstance(extends, list) and bool(extends)


def _manifest_declares_rego(manifest: dict[str, Any]) -> bool:
    policies = manifest.get("policies")
    return isinstance(policies, dict) and any(
        isinstance(config, dict) and config.get("type") == "rego"
        for config in policies.values()
    )


def _load_packaged_schema(name: str) -> dict[str, Any]:
    with resources.files(SCHEMA_PACKAGE).joinpath(name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _manifest_validator() -> jsonschema.Draft202012Validator:
    schema = _load_packaged_schema(SCHEMA_NAME)
    approval_schema = _load_packaged_schema(APPROVAL_SCHEMA_NAME)
    try:
        from referencing import Registry, Resource

        registry = Registry().with_resource(
            approval_schema["$id"],
            Resource.from_contents(approval_schema),
        )
        return jsonschema.Draft202012Validator(schema, registry=registry)
    except (ImportError, TypeError):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            resolver = jsonschema.RefResolver.from_schema(
                schema,
                store={approval_schema["$id"]: approval_schema},
            )
        return jsonschema.Draft202012Validator(schema, resolver=resolver)


def _normalize_rego_modules(
    rego: str | dict[str, str],
) -> tuple[list[tuple[str, str]], list[ValidationDiagnostic]]:
    if isinstance(rego, str):
        items: list[tuple[Any, Any]] = [("policy.rego", rego)]
    elif type(rego) is dict:
        items = []
        for index, item in enumerate(rego.items()):
            if index >= MAX_REGO_MODULES:
                return [], [
                    ValidationDiagnostic(
                        component="rego",
                        code="rego_module_limit_exceeded",
                        message=f"Received more than the limit of {MAX_REGO_MODULES} Rego modules.",
                        source="rego",
                    )
                ]
            items.append(item)
    else:
        return [], [
            ValidationDiagnostic(
                component="rego",
                code="rego_input_invalid",
                message="Rego input must be a string or a dictionary of source names to strings.",
                source="rego",
            )
        ]

    modules: list[tuple[str, str]] = []
    diagnostics: list[ValidationDiagnostic] = []
    total_bytes = 0
    for index, (source, contents) in enumerate(items):
        if not isinstance(source, str) or not source.strip():
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code="rego_source_invalid",
                    message="Each Rego module must have a non-empty string source name.",
                    source=f"rego[{index}]",
                )
            )
            continue
        try:
            source.encode("utf-8")
        except UnicodeEncodeError as exc:
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code="rego_source_invalid",
                    message=f"Rego source name is not valid UTF-8 text. {exc}",
                    source=f"rego[{index}]",
                )
            )
            continue
        if len(source) > MAX_SOURCE_LABEL:
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code="rego_source_invalid",
                    message=f"Rego source name exceeds {MAX_SOURCE_LABEL} characters.",
                    source=f"rego[{index}]",
                )
            )
            continue
        if not isinstance(contents, str):
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code="rego_input_invalid",
                    message="Each Rego module value must be a string.",
                    source=source,
                )
            )
            continue
        try:
            encoded = contents.encode("utf-8")
        except UnicodeEncodeError as exc:
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code="rego_encoding_error",
                    message=f"Rego module is not valid UTF-8 text. {exc}",
                    source=source,
                )
            )
            continue
        total_bytes += len(encoded)
        if total_bytes > MAX_REGO_BYTES:
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code="rego_size_exceeded",
                    message=(
                        f"Rego modules exceed the {MAX_REGO_BYTES}-byte "
                        "total validation limit."
                    ),
                    source="rego",
                )
            )
            return [], diagnostics
        if not contents.strip():
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code="rego_empty",
                    message="Rego module must not be empty.",
                    source=source,
                )
            )
            continue
        modules.append((source, contents))
    return modules, diagnostics


def _validate_rego_modules(
    opa: str,
    modules: list[tuple[str, str]],
) -> list[ValidationDiagnostic]:
    deadline = time.monotonic() + OPA_TIMEOUT_SECONDS
    opa_diagnostic = _validate_opa_executable(opa, deadline)
    if opa_diagnostic is not None:
        return [opa_diagnostic]
    try:
        scratch = tempfile.TemporaryDirectory(prefix="acs-validation-")
    except OSError as exc:
        return [
            ValidationDiagnostic(
                component="rego",
                code="rego_staging_error",
                message=f"Could not create temporary storage for OPA validation. {exc}",
                source="rego",
            )
        ]

    with scratch as tmp:
        root = Path(tmp)
        staged: list[tuple[str, Path]] = []
        try:
            for index, (source, contents) in enumerate(modules):
                path = root / f"module-{index:04d}.rego"
                path.write_text(contents, encoding="utf-8")
                staged.append((source, path))
        except OSError as exc:
            return [
                ValidationDiagnostic(
                    component="rego",
                    code="rego_staging_error",
                    message=f"Could not stage Rego modules for OPA validation. {exc}",
                    source="rego",
                )
            ]

        diagnostics: list[ValidationDiagnostic] = []
        for source, path in staged:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                diagnostics.append(_opa_timeout_diagnostic())
                break
            try:
                completed = _run_opa_command(
                    [opa, "parse", str(path), "--format=json"],
                    timeout=remaining,
                    capture_stdout=False,
                )
            except subprocess.TimeoutExpired:
                diagnostics.append(_opa_timeout_diagnostic())
                break
            except (OSError, UnicodeError, ValueError) as exc:
                diagnostics.append(
                    ValidationDiagnostic(
                        component="rego",
                        code="opa_execution_error",
                        message=f"OPA could not parse the Rego module. {exc}",
                        source=source,
                    )
                )
                continue
            if completed.returncode != 0:
                source_by_file = {
                    str(path): source,
                    str(path.resolve()): source,
                    path.name: source,
                }
                diagnostics.extend(_opa_diagnostics(completed, source_by_file))
            if len(diagnostics) > MAX_DIAGNOSTICS:
                return _limit_diagnostics(diagnostics)
        return diagnostics


def _validate_opa_executable(
    opa: str,
    deadline: float,
) -> ValidationDiagnostic | None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return _opa_timeout_diagnostic()
    try:
        completed = _run_opa_command(
            [opa, "version"],
            timeout=remaining,
            capture_stdout=True,
        )
    except subprocess.TimeoutExpired:
        return _opa_timeout_diagnostic()
    except (OSError, UnicodeError, ValueError) as exc:
        return ValidationDiagnostic(
            component="rego",
            code="opa_execution_error",
            message=f"OPA could not be executed. {exc}",
            source="opa",
        )
    version_output = completed.stdout.strip()
    if completed.returncode != 0 or not version_output.startswith("Version:"):
        detail = completed.stderr.strip() or version_output
        return ValidationDiagnostic(
            component="rego",
            code="opa_invalid_executable",
            message=(
                "Configured OPA executable did not return the expected version banner."
                + (f" {detail}" if detail else "")
            ),
            source="opa",
        )
    return None


def _run_opa_command(
    args: list[str],
    *,
    timeout: float,
    capture_stdout: bool,
) -> subprocess.CompletedProcess[str]:
    with (
        tempfile.TemporaryFile(mode="w+b") as stdout_file,
        tempfile.TemporaryFile(mode="w+b") as stderr_file,
    ):
        completed = subprocess.run(
            args,
            check=False,
            stdout=stdout_file if capture_stdout else subprocess.DEVNULL,
            stderr=stderr_file,
            timeout=timeout,
        )
        stdout = (
            completed.stdout
            if isinstance(completed.stdout, str)
            else _read_bounded_process_output(stdout_file)
            if capture_stdout
            else ""
        )
        stderr = (
            completed.stderr
            if isinstance(completed.stderr, str)
            else _read_bounded_process_output(stderr_file)
        )
    return subprocess.CompletedProcess(args, completed.returncode, stdout, stderr)


def _read_bounded_process_output(output: Any) -> str:
    output.seek(0)
    data = output.read(MAX_OPA_OUTPUT_BYTES + 1)
    truncated = len(data) > MAX_OPA_OUTPUT_BYTES
    text = data[:MAX_OPA_OUTPUT_BYTES].decode("utf-8", errors="replace")
    return text + ("..." if truncated else "")


def _opa_timeout_diagnostic() -> ValidationDiagnostic:
    return ValidationDiagnostic(
        component="rego",
        code="opa_timeout",
        message=f"OPA validation exceeded {OPA_TIMEOUT_SECONDS} seconds.",
        source="opa",
    )


def _opa_diagnostics(
    completed: subprocess.CompletedProcess[str],
    source_by_file: dict[str, str],
) -> list[ValidationDiagnostic]:
    payload: dict[str, Any] | None = None
    stdout = completed.stdout if isinstance(completed.stdout, str) else ""
    stderr = completed.stderr if isinstance(completed.stderr, str) else ""
    for candidate in (stderr.strip(), stdout.strip()):
        if not candidate:
            continue
        try:
            decoded = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            payload = decoded
            break

    errors = payload.get("errors") if payload is not None else None
    if isinstance(errors, list) and errors:
        diagnostics: list[ValidationDiagnostic] = []
        for error in errors:
            if not isinstance(error, dict):
                continue
            location = error.get("location")
            location = location if isinstance(location, dict) else {}
            details = error.get("details")
            details = details if isinstance(details, dict) else {}
            file_name = location.get("file")
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code=str(error.get("code") or "rego_validation_error"),
                    message=_replace_opa_paths(
                        str(error.get("message") or "OPA rejected the Rego module."),
                        source_by_file,
                    ),
                    source=_rego_source_label(file_name, source_by_file),
                    line=location.get("row") if isinstance(location.get("row"), int) else None,
                    column=location.get("col") if isinstance(location.get("col"), int) else None,
                    snippet=details.get("line") if isinstance(details.get("line"), str) else None,
                )
            )
        if diagnostics:
            return diagnostics
    detail = stderr.strip() or stdout.strip()
    return [
        ValidationDiagnostic(
            component="rego",
            code="opa_validation_error",
            message=_replace_opa_paths(detail, source_by_file)
            or f"OPA exited with status {completed.returncode} without diagnostics.",
            source="opa",
        )
    ]


def _rego_source_label(file_name: Any, source_by_file: dict[str, str]) -> str:
    if not isinstance(file_name, str):
        return "rego"
    return (
        source_by_file.get(file_name)
        or source_by_file.get(str(Path(file_name).resolve()))
        or source_by_file.get(Path(file_name).name)
        or Path(file_name).name
    )


def _replace_opa_paths(value: str, source_by_file: dict[str, str]) -> str:
    replaced = value
    for path, source in sorted(source_by_file.items(), key=lambda item: len(item[0]), reverse=True):
        replaced = replaced.replace(path, source)
    return replaced


def _json_path(parts: Any) -> str:
    path = "$"
    for part in parts:
        path = (
            f"{path}[{part}]"
            if isinstance(part, int)
            else _append_json_path(path, str(part))
        )
    return path


def _append_json_path(path: str, part: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part):
        return f"{path}.{part}"
    return f"{path}[{json.dumps(part)}]"


def _limit_diagnostics(
    diagnostics: list[ValidationDiagnostic],
) -> list[ValidationDiagnostic]:
    if len(diagnostics) <= MAX_DIAGNOSTICS:
        return diagnostics
    return [*diagnostics[:MAX_DIAGNOSTICS], _diagnostics_truncated()]


def _diagnostics_truncated() -> ValidationDiagnostic:
    return ValidationDiagnostic(
        component="validation",
        code="validation_diagnostics_truncated",
        message=f"Additional diagnostics were omitted after the first {MAX_DIAGNOSTICS}.",
        source="validation",
    )
