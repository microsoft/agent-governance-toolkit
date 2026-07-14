# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Lint native ACS manifests for schema and provenance errors."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class LintMessage:
    """A single lint finding."""

    severity: str
    message: str
    file: str
    line: int

    def __str__(self) -> str:
        return f"{self.file}:{self.line}: {self.severity}: {self.message}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
        }


@dataclass
class LintResult:
    """Aggregated lint results for one or more manifests."""

    messages: list[LintMessage] = field(default_factory=list)

    @property
    def errors(self) -> list[LintMessage]:
        return [message for message in self.messages if message.severity == "error"]

    @property
    def warnings(self) -> list[LintMessage]:
        return [
            message for message in self.messages if message.severity == "warning"
        ]

    @property
    def passed(self) -> bool:
        return not self.errors

    def summary(self) -> str:
        if not self.messages:
            return "No issues found."
        return (
            f"{len(self.errors)} error(s), "
            f"{len(self.warnings)} warning(s) found."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "messages": [message.to_dict() for message in self.messages],
        }


def lint_file(path: str | Path) -> LintResult:
    """Validate one native ACS manifest and its relative references."""

    from agt.policies import AgtManifest

    manifest_path = Path(path)
    result = LintResult()
    if not manifest_path.is_file():
        result.messages.append(
            LintMessage(
                "error",
                f"Manifest file not found: {manifest_path}",
                str(manifest_path),
                1,
            )
        )
        return result

    if manifest_path.suffix.lower() not in {".yaml", ".yml", ".json"}:
        result.messages.append(
            LintMessage(
                "error",
                "Manifest must be YAML or JSON",
                str(manifest_path),
                1,
            )
        )
        return result

    try:
        manifest = AgtManifest.from_path(manifest_path)
        manifest.resolved_document(manifest_path.parent)
    except Exception as exc:
        result.messages.append(
            LintMessage(
                "error",
                str(exc),
                str(manifest_path),
                1,
            )
        )
        return result

    for policy_id, policy in manifest.policies.items():
        references = [
            policy.bundle,
            policy.policy_path,
            policy.entities_path,
            policy.schema_path,
            *policy.data_paths,
        ]
        for reference in references:
            if (
                reference
                and "://" not in reference
                and not (manifest_path.parent / reference).exists()
            ):
                result.messages.append(
                    LintMessage(
                        "error",
                        f"Policy {policy_id!r} references missing path {reference!r}",
                        str(manifest_path),
                        1,
                    )
                )

    if not manifest.intervention_points:
        result.messages.append(
            LintMessage(
                "warning",
                "Manifest defines no intervention points",
                str(manifest_path),
                1,
            )
        )
    return result


def lint_path(path: str | Path) -> LintResult:
    """Lint one manifest or every manifest under a directory."""

    target = Path(path)
    if target.is_file():
        return lint_file(target)
    if not target.exists():
        return LintResult(
            [
                LintMessage(
                    "error",
                    f"Path does not exist: {target}",
                    str(target),
                    0,
                )
            ]
        )
    if not target.is_dir():
        return LintResult(
            [
                LintMessage(
                    "error",
                    f"Unsupported path: {target}",
                    str(target),
                    0,
                )
            ]
        )

    files = sorted(
        file
        for pattern in ("*.yaml", "*.yml", "*.json")
        for file in target.rglob(pattern)
    )
    if not files:
        return LintResult(
            [
                LintMessage(
                    "warning",
                    "No manifest files found",
                    str(target),
                    0,
                )
            ]
        )

    result = LintResult()
    for file in files:
        result.messages.extend(lint_file(file).messages)
    return result
