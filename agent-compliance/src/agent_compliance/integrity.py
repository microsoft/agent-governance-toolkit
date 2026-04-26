# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Bootstrap Integrity Verification.

Verifies that governance module source files have not been tampered
with by comparing SHA-256 hashes against a published manifest. This
answers the "who watches the watcher" question — the governance layer
itself must prove it hasn't been subverted.

Usage::

    from agent_compliance.integrity import IntegrityVerifier

    verifier = IntegrityVerifier()
    report = verifier.verify()
    print(report.passed)     # True/False
    print(report.summary())  # Human-readable summary
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import json
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import ModuleType
from typing import Any, Optional

from agent_compliance.verify import _validate_module_name

logger = logging.getLogger(__name__)

# Governance modules whose integrity we verify
GOVERNANCE_MODULES = [
    "agent_os.integrations.base",
    "agent_os.integrations.escalation",
    "agent_os.integrations.tool_aliases",
    "agent_os.integrations.compat",
    "agentmesh.governance.policy",
    "agentmesh.governance.conflict_resolution",
    "agentmesh.governance.audit",
    "agentmesh.governance.opa",
    "agentmesh.governance.compliance",
    "agentmesh.governance.shadow",
    "agentmesh.identity.agent_id",
    "agentmesh.identity.revocation",
    "agentmesh.identity.rotation",
    "agentmesh.trust.cards",
    "agentmesh.storage.file_trust_store",
]

# Critical functions whose bytecode we hash for runtime tamper detection
CRITICAL_FUNCTIONS = [
    ("agentmesh.governance.policy", "PolicyEngine.evaluate"),
    ("agentmesh.governance.conflict_resolution", "PolicyConflictResolver.resolve"),
    ("agentmesh.governance.audit", "AuditChain.add_entry"),
    ("agentmesh.trust.cards", "CardRegistry.is_verified"),
]


@dataclass
class FileIntegrityResult:
    """Result of verifying a single file."""

    module_name: str
    file_path: str
    expected_hash: Optional[str]
    actual_hash: str
    passed: bool
    error: Optional[str] = None


@dataclass
class FunctionIntegrityResult:
    """Result of verifying a critical function's bytecode."""

    module_name: str
    function_name: str
    expected_hash: Optional[str]
    actual_hash: str
    passed: bool
    error: Optional[str] = None


@dataclass
class IntegrityReport:
    """Complete integrity verification report.

    Attributes:
        passed: Overall pass/fail.
        file_results: Per-file hash check results.
        function_results: Per-function bytecode check results.
        verified_at: Timestamp of verification.
        manifest_path: Path to the manifest used (if any).
        modules_checked: Count of modules verified.
        modules_missing: Modules that couldn't be imported.
    """

    passed: bool = True
    file_results: list[FileIntegrityResult] = field(default_factory=list)
    function_results: list[FunctionIntegrityResult] = field(default_factory=list)
    verified_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    manifest_path: Optional[str] = None
    modules_checked: int = 0
    modules_missing: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """Human-readable summary of the verification."""
        lines = [
            f"Integrity Verification — {'PASSED ✅' if self.passed else 'FAILED ❌'}",
            f"Verified at: {self.verified_at}",
            f"Modules checked: {self.modules_checked}",
        ]
        if self.modules_missing:
            lines.append(f"Modules missing: {', '.join(self.modules_missing)}")

        failed_files = [r for r in self.file_results if not r.passed]
        if failed_files:
            lines.append(f"File hash mismatches: {len(failed_files)}")
            for r in failed_files:
                lines.append(f"  ✗ {r.module_name}: {r.error or 'hash mismatch'}")

        failed_funcs = [r for r in self.function_results if not r.passed]
        if failed_funcs:
            lines.append(f"Function bytecode mismatches: {len(failed_funcs)}")
            for r in failed_funcs:
                lines.append(f"  ✗ {r.module_name}.{r.function_name}")

        if self.passed:
            lines.append(
                f"All {len(self.file_results)} files and "
                f"{len(self.function_results)} critical functions verified."
            )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Serialize to dict for JSON output."""
        return {
            "passed": self.passed,
            "verified_at": self.verified_at,
            "manifest_path": self.manifest_path,
            "modules_checked": self.modules_checked,
            "modules_missing": self.modules_missing,
            "file_results": [
                {
                    "module": r.module_name,
                    "file": r.file_path,
                    "expected": r.expected_hash,
                    "actual": r.actual_hash,
                    "passed": r.passed,
                    "error": r.error,
                }
                for r in self.file_results
            ],
            "function_results": [
                {
                    "module": r.module_name,
                    "function": r.function_name,
                    "expected": r.expected_hash,
                    "actual": r.actual_hash,
                    "passed": r.passed,
                }
                for r in self.function_results
            ],
        }


def _hash_file(path: str) -> str:
    """SHA-256 hash of a file's contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_function_bytecode(func: Callable[..., Any]) -> str:
    """SHA-256 hash of a function's compiled bytecode."""
    code = func.__code__
    h = hashlib.sha256()
    h.update(code.co_code)
    h.update(str(code.co_consts).encode())
    return h.hexdigest()


def _resolve_function(module: ModuleType, dotted_name: str) -> Any | None:
    """Resolve 'ClassName.method' or 'function_name' from a module."""
    parts = dotted_name.split(".")
    obj: Any = module
    for part in parts:
        obj = getattr(obj, part, None)
        if obj is None:
            return None
    return obj


class IntegrityVerifier:
    """Verifies governance module integrity at startup or on demand.

    Args:
        manifest_path: Path to integrity.json manifest. If None,
            generates a baseline instead of verifying against one.
        modules: List of module names to verify. Defaults to
            GOVERNANCE_MODULES.
        critical_functions: List of (module, func_path) tuples for
            bytecode verification.
    """

    def __init__(
        self,
        manifest_path: Optional[str] = None,
        modules: Optional[list[str]] = None,
        critical_functions: Optional[list[tuple[str, str]]] = None,
    ) -> None:
        self.manifest_path = manifest_path
        self.modules = modules or GOVERNANCE_MODULES
        self.critical_functions = critical_functions or CRITICAL_FUNCTIONS
        self._manifest: Optional[dict] = None

        if manifest_path and os.path.exists(manifest_path):
            try:
                with open(manifest_path, encoding="utf-8") as f:
                    self._manifest = json.load(f)
            except json.JSONDecodeError as e:
                import logging
                logging.getLogger(__name__).warning(
                    "Corrupted manifest at %s: %s", manifest_path, e
                )

    def verify(self) -> IntegrityReport:
        """Run full integrity verification.

        Returns:
            An IntegrityReport with per-file and per-function results.
        """
        report = IntegrityReport()

        # Phase 1: File hash verification
        for mod_name in self.modules:
            try:
                _validate_module_name(mod_name)
                mod = importlib.import_module(mod_name)
                source_file = inspect.getfile(mod)
                actual_hash = _hash_file(source_file)
                report.modules_checked += 1

                expected = None
                if self._manifest and mod_name in self._manifest.get("files", {}):
                    expected = self._manifest["files"][mod_name]["sha256"]

                passed = expected is None or expected == actual_hash
                if not passed:
                    report.passed = False

                report.file_results.append(
                    FileIntegrityResult(
                        module_name=mod_name,
                        file_path=source_file,
                        expected_hash=expected,
                        actual_hash=actual_hash,
                        passed=passed,
                        error="hash mismatch" if not passed else None,
                    )
                )
            except (ImportError, ValueError):
                report.modules_missing.append(mod_name)
            except Exception as e:
                report.file_results.append(
                    FileIntegrityResult(
                        module_name=mod_name,
                        file_path="",
                        expected_hash=None,
                        actual_hash="",
                        passed=False,
                        error=str(e),
                    )
                )
                report.passed = False

        # Phase 2: Critical function bytecode verification
        for mod_name, func_path in self.critical_functions:
            try:
                _validate_module_name(mod_name)
                mod = importlib.import_module(mod_name)
                func = _resolve_function(mod, func_path)
                if func is None:
                    report.function_results.append(
                        FunctionIntegrityResult(
                            module_name=mod_name,
                            function_name=func_path,
                            expected_hash=None,
                            actual_hash="",
                            passed=False,
                            error=f"Function {func_path} not found",
                        )
                    )
                    report.passed = False
                    continue

                actual_hash = _hash_function_bytecode(func)
                key = f"{mod_name}:{func_path}"
                expected = None
                if self._manifest and key in self._manifest.get("functions", {}):
                    expected = self._manifest["functions"][key]

                passed = expected is None or expected == actual_hash
                if not passed:
                    report.passed = False

                report.function_results.append(
                    FunctionIntegrityResult(
                        module_name=mod_name,
                        function_name=func_path,
                        expected_hash=expected,
                        actual_hash=actual_hash,
                        passed=passed,
                    )
                )
            except ImportError:
                pass  # Already tracked in modules_missing
            except Exception as e:
                report.function_results.append(
                    FunctionIntegrityResult(
                        module_name=mod_name,
                        function_name=func_path,
                        expected_hash=None,
                        actual_hash="",
                        passed=False,
                        error=str(e),
                    )
                )
                report.passed = False

        report.manifest_path = self.manifest_path
        return report

    def generate_manifest(self, output_path: str) -> dict:
        """Generate an integrity manifest from current module state.

        Writes a JSON file containing SHA-256 hashes of all governance
        module source files and critical function bytecodes.

        Args:
            output_path: Where to write integrity.json.

        Returns:
            The manifest dict.
        """
        manifest = {
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "files": {},
            "functions": {},
        }

        for mod_name in self.modules:
            try:
                _validate_module_name(mod_name)
                mod = importlib.import_module(mod_name)
                source_file = inspect.getfile(mod)
                manifest["files"][mod_name] = {
                    "sha256": _hash_file(source_file),
                    "path": source_file,
                }
            except (ImportError, OSError, TypeError, ValueError) as e:
                logger.warning("Could not hash module %s: %s", mod_name, e)

        for mod_name, func_path in self.critical_functions:
            try:
                _validate_module_name(mod_name)
                mod = importlib.import_module(mod_name)
                func = _resolve_function(mod, func_path)
                if func:
                    key = f"{mod_name}:{func_path}"
                    manifest["functions"][key] = _hash_function_bytecode(func)
            except (ImportError, OSError, TypeError, AttributeError, ValueError) as e:
                logger.warning(
                    "Could not hash function %s.%s: %s", mod_name, func_path, e
                )

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return manifest
