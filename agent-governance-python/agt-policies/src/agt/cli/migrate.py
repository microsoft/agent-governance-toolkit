# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``agt migrate v4-to-v5`` — one-shot project migration tool.

The CLI walks a v4 AGT project, finds every legacy artifact, and
either emits a migration report (the safe default) or rewrites the
project to the v5 shape (``--write``).

The algorithm follows ``plan.md`` §5 / milestone M6.S1:

1. Find legacy artifacts under the project root.
2. For every governance.yaml chain, run
   :func:`agt.manifest_resolution.resolve_manifest` and persist the
   resulting flat ACS manifest + generated Rego bundle.
3. For every ``GovernancePolicy(...)`` constructor call, accept only exact
   literals, translate them through the private one-way migrator, and refuse
   dynamic or host-only fields with a manual-review finding.
4. Flag ``PolicyAction.BLOCK`` references; offer a rewrite when
   ``--write`` is set.
5. Flag ``CedarBackend(...)`` calls with a suggested v5
   ``policies.{id}.type: cedar`` translation.
6. Flag direct ``PolicyInterceptor`` subclasses for manual review.
7. Render a Markdown report (printed to stdout, optionally written
   via ``--write-report``).

The CLI is deliberately stdlib + pyyaml only — the only third-party
imports are the same ones the rest of agt-policies already depends on
through ``manifest_resolution`` and ``policies.bridge``.
"""

from __future__ import annotations

import argparse
import ast
import logging
import os
import re
import shutil
import sys
import tempfile
import tokenize
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agt.manifest_resolution import ResolutionError, resolve_manifest
from agt.policies.manifest import AgtManifest

from ._migrate_bridge import MigrationPolicyInput, build_migrated_manifest

logger = logging.getLogger(__name__)


CLI_DESCRIPTION = (
    "Walk an AGT v4 project, list every legacy artifact, and (with "
    "--write) rewrite the project to the v5 shape: flat ACS manifests "
    "plus generated Rego bundles."
)


# ---------------------------------------------------------------------------
# Findings model — the report is a list of typed records.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Location:
    """A pointer into a source file. Line numbers are 1-based."""

    path: Path
    line: int = 0
    column: int = 0

    def __str__(self) -> str:
        if self.line:
            return f"{self.path}:{self.line}:{self.column}"
        return str(self.path)


@dataclass
class GovernanceChainFinding:
    """A discovered governance.yaml that anchors a v4 policy chain."""

    chain_root: Path
    governance_files: list[Path]
    manifest_path: Path | None = None
    rego_bundle: Path | None = None
    backups: list[Path] = field(default_factory=list)
    error: str | None = None
    applied: bool = False


@dataclass
class GovernancePolicyFinding:
    """A ``GovernancePolicy(...)`` constructor call in Python source."""

    location: Location
    kwargs: dict[str, Any]
    migration_kwargs: dict[str, Any] = field(default_factory=dict)
    manual_review: list[str] = field(default_factory=list)
    manifest_path: Path | None = None
    rewrite_snippet: str = ""
    applied: bool = False


@dataclass
class PolicyActionBlockFinding:
    """A reference to the v4-only ``PolicyAction.BLOCK`` enum value."""

    location: Location
    rewrite_snippet: str = ""


@dataclass
class CedarBackendFinding:
    """An ``add_backend(CedarBackend(...))`` call."""

    location: Location
    rewrite_snippet: str = ""


@dataclass
class PolicyInterceptorFinding:
    """A class that directly subclasses ``PolicyInterceptor``."""

    location: Location
    class_name: str
    note: str = ""


@dataclass
class LegacyImportFinding:
    """A Python file with a ``from agent_os.policies import …`` line."""

    location: Location
    imported_names: tuple[str, ...]


class SourceScanError(ValueError):
    """A Python source file could not be decoded or parsed safely."""


@dataclass
class MigrationReport:
    """All findings produced by a single ``agt migrate v4-to-v5`` run."""

    project_root: Path
    write: bool
    governance_chains: list[GovernanceChainFinding] = field(default_factory=list)
    governance_policies: list[GovernancePolicyFinding] = field(default_factory=list)
    policy_action_blocks: list[PolicyActionBlockFinding] = field(default_factory=list)
    cedar_backends: list[CedarBackendFinding] = field(default_factory=list)
    policy_interceptors: list[PolicyInterceptorFinding] = field(default_factory=list)
    legacy_imports: list[LegacyImportFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def has_findings(self) -> bool:
        return any(
            (
                self.governance_chains,
                self.governance_policies,
                self.policy_action_blocks,
                self.cedar_backends,
                self.policy_interceptors,
                self.legacy_imports,
            )
        )

    def requires_manual_review(self) -> bool:
        return any(finding.manual_review for finding in self.governance_policies)


# ---------------------------------------------------------------------------
# File-system walk
# ---------------------------------------------------------------------------


GOVERNANCE_FILENAMES = ("governance.yaml", "governance.yml")
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".agt",
    }
)


def _iter_files(root: Path) -> Iterable[Path]:
    """Yield every file under *root* skipping the usual junk directories.

    The walk is implemented with ``os.walk`` so we can prune large
    cache directories in-place rather than relying on
    :func:`Path.rglob` which has no pruning hook.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        base = Path(dirpath)
        for name in filenames:
            yield base / name


def _find_governance_chains(root: Path) -> list[Path]:
    """Return every distinct chain root directory that holds a governance file.

    A "chain root" is the directory containing the **most-specific**
    governance file in a path — i.e. the directory we would pass as
    ``action_path`` to :func:`agt.manifest_resolution.resolve_manifest`.
    Directories that already have a v5 ``manifest.yaml`` sitting next to
    the governance file are still reported so the migration is idempotent
    (the run is a no-op when ``--write`` already happened).
    """
    chain_dirs: list[Path] = []
    seen: set[Path] = set()
    for path in _iter_files(root):
        if path.name not in GOVERNANCE_FILENAMES:
            continue
        if path.name.endswith(".v4-backup"):
            continue
        chain_dir = path.parent.resolve()
        if chain_dir in seen:
            continue
        seen.add(chain_dir)
        chain_dirs.append(chain_dir)
    chain_dirs.sort()
    return chain_dirs


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _literal_or_repr(node: ast.AST) -> Any:
    """Convert an AST node to a literal value when possible.

    Non-literal nodes (function calls, names, attribute chains) are
    returned as a short ``ast.unparse`` string so the migration report
    still has something useful to display. We use
    :func:`ast.literal_eval` for safety — ``eval`` on user code is
    explicitly out of scope for this tool.
    """
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError):
        try:
            return f"<expr:{ast.unparse(node)}>"
        except Exception:  # pragma: no cover - very old Python
            return "<expr>"


def _node_qualname(node: ast.AST) -> str:
    """Render a Name/Attribute chain as a dotted string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_node_qualname(node.value)}.{node.attr}"
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover
        return "<node>"


_MIGRATED_POLICY_FIELDS = {
    "name",
    "max_tokens",
    "max_tool_calls",
    "allowed_tools",
    "blocked_patterns",
    "require_human_approval",
    "confidence_threshold",
    "version",
}
_HOST_ONLY_POLICY_FIELDS = {
    "timeout_seconds",
    "drift_threshold",
    "log_all_calls",
    "checkpoint_frequency",
    "max_concurrent",
    "backpressure_threshold",
    "prompt_injection",
    "token_budget",
    "rate_limiter",
    "bounded_semaphore",
    "scope_guard",
    "supply_chain",
    "mcp_security",
    "detection",
}


def _parse_governance_call(
    node: ast.Call,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    captured: dict[str, Any] = {}
    migration: dict[str, Any] = {}
    issues: list[str] = []
    if node.args:
        issues.append(
            "positional GovernancePolicy arguments require manual review"
        )
    for keyword in node.keywords:
        if keyword.arg is None:
            issues.append("**kwargs expansion requires manual review")
            continue
        name = keyword.arg
        captured[name] = _literal_or_repr(keyword.value)
        if name in _HOST_ONLY_POLICY_FIELDS:
            issues.append(
                f"{name} is host configuration and cannot be written to an ACS manifest"
            )
            continue
        if name not in _MIGRATED_POLICY_FIELDS:
            issues.append(f"unsupported GovernancePolicy field {name!r}")
            continue
        try:
            migration[name] = _parse_governance_value(name, keyword.value)
        except ValueError as exc:
            issues.append(f"{name}: {exc}")
    return captured, migration, issues


def _parse_governance_value(name: str, node: ast.AST) -> Any:
    if name == "blocked_patterns":
        return _parse_blocked_patterns(node)
    try:
        value = ast.literal_eval(node)
    except (ValueError, SyntaxError) as exc:
        raise ValueError("dynamic expression cannot be migrated safely") from exc

    expected: type[Any] | tuple[type[Any], ...]
    if name in {"name", "version"}:
        expected = str
    elif name in {"max_tokens", "max_tool_calls"}:
        expected = int
    elif name == "require_human_approval":
        expected = bool
    elif name == "confidence_threshold":
        expected = (int, float)
    elif name == "allowed_tools":
        if not isinstance(value, list) or any(
            not isinstance(tool, str) for tool in value
        ):
            raise ValueError("must be a literal list of strings")
        return value
    else:  # pragma: no cover - guarded by _MIGRATED_POLICY_FIELDS
        raise ValueError("unsupported migration field")

    if isinstance(value, bool) and expected is not bool:
        raise ValueError(f"must be a literal {name} value, not bool")
    if not isinstance(value, expected):
        raise ValueError("literal has the wrong type")
    return value


def _parse_blocked_patterns(node: ast.AST) -> list[str | tuple[str, str]]:
    if not isinstance(node, ast.List):
        raise ValueError("must be a literal list")
    patterns: list[str | tuple[str, str]] = []
    for index, entry in enumerate(node.elts):
        if isinstance(entry, ast.Constant) and isinstance(entry.value, str):
            patterns.append(entry.value)
            continue
        if not isinstance(entry, ast.Tuple) or len(entry.elts) != 2:
            raise ValueError(
                f"entry {index} must be a string or (string, PatternType)"
            )
        value_node, kind_node = entry.elts
        if not (
            isinstance(value_node, ast.Constant)
            and isinstance(value_node.value, str)
        ):
            raise ValueError(f"entry {index} pattern must be a literal string")
        kind_qualname = _node_qualname(kind_node)
        parts = kind_qualname.split(".")
        if len(parts) < 2 or parts[-2] != "PatternType":
            raise ValueError(
                f"entry {index} kind must be PatternType.SUBSTRING, "
                "PatternType.REGEX, or PatternType.GLOB"
            )
        kind = parts[-1]
        if kind not in {"SUBSTRING", "REGEX", "GLOB"}:
            raise ValueError(f"entry {index} uses unsupported PatternType.{kind}")
        patterns.append((value_node.value, kind))
    return patterns


class _LegacyVisitor(ast.NodeVisitor):
    """Collect every legacy v4 marker out of a single Python source file."""

    def __init__(self, path: Path):
        self.path = path
        self.governance_policy_names = {"GovernancePolicy"}
        self.governance_policies: list[GovernancePolicyFinding] = []
        self.policy_action_blocks: list[PolicyActionBlockFinding] = []
        self.cedar_backends: list[CedarBackendFinding] = []
        self.policy_interceptors: list[PolicyInterceptorFinding] = []
        self.legacy_imports: list[LegacyImportFinding] = []

    # — imports ------------------------------------------------------
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module or ""
        if module == "agent_os.integrations.base":
            for alias in node.names:
                if alias.name == "GovernancePolicy":
                    self.governance_policy_names.add(
                        alias.asname or alias.name
                    )
        if module == "agent_os.policies" or module.startswith("agent_os.policies."):
            names = tuple(alias.name for alias in node.names)
            self.legacy_imports.append(
                LegacyImportFinding(
                    location=Location(self.path, node.lineno, node.col_offset),
                    imported_names=names,
                )
            )
        self.generic_visit(node)

    # — calls and attribute access ---------------------------------
    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        callee = _node_qualname(node.func)
        callee_tail = callee.split(".")[-1]

        if callee_tail in self.governance_policy_names:
            kwargs, migration_kwargs, manual_review = _parse_governance_call(
                node
            )
            self.governance_policies.append(
                GovernancePolicyFinding(
                    location=Location(self.path, node.lineno, node.col_offset),
                    kwargs=kwargs,
                    migration_kwargs=migration_kwargs,
                    manual_review=manual_review,
                )
            )

        if callee_tail == "CedarBackend":
            args_repr: list[str] = []
            for arg in node.args:
                args_repr.append(repr(_literal_or_repr(arg)))
            for kw in node.keywords:
                if kw.arg is None:
                    continue
                args_repr.append(f"{kw.arg}={_literal_or_repr(kw.value)!r}")
            self.cedar_backends.append(
                CedarBackendFinding(
                    location=Location(self.path, node.lineno, node.col_offset),
                    rewrite_snippet=_render_cedar_snippet(args_repr),
                )
            )

        self.generic_visit(node)

    # — PolicyAction.BLOCK -----------------------------------------
    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        qual = _node_qualname(node)
        # Match both ``PolicyAction.BLOCK`` and any
        # ``module.PolicyAction.BLOCK`` form.
        if qual.endswith("PolicyAction.BLOCK"):
            self.policy_action_blocks.append(
                PolicyActionBlockFinding(
                    location=Location(self.path, node.lineno, node.col_offset),
                    rewrite_snippet=(
                        "# v4:  action=PolicyAction.BLOCK\n"
                        "# v5:  action=\"deny\"   # AGT-DELTA D-M3.S4 maps BLOCK→deny"
                    ),
                )
            )
        self.generic_visit(node)

    # — class definitions ------------------------------------------
    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        for base in node.bases:
            qual = _node_qualname(base)
            if qual.split(".")[-1] == "PolicyInterceptor":
                self.policy_interceptors.append(
                    PolicyInterceptorFinding(
                        location=Location(self.path, node.lineno, node.col_offset),
                        class_name=node.name,
                        note=(
                            "Direct PolicyInterceptor subclasses are removed in "
                            "v5. Port the per-event logic to either an "
                            "intervention_point binding in your AGT manifest or a "
                            "host-side wrapper around agt.policies.runtime."
                        ),
                    )
                )
                break
        self.generic_visit(node)


def _scan_python_file(path: Path) -> _LegacyVisitor:
    try:
        with tokenize.open(path) as source_file:
            source = source_file.read()
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        raise SourceScanError(f"{path}: cannot decode Python source: {exc}") from exc
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        raise SourceScanError(f"{path}: cannot parse Python source: {exc}") from exc
    visitor = _LegacyVisitor(path)
    visitor.visit(tree)
    return visitor


def _render_cedar_snippet(args_repr: list[str]) -> str:
    """Render a v5 manifest snippet replacing a v4 ``CedarBackend`` call."""
    return (
        "# v4:  registry.add_backend(CedarBackend("
        + ", ".join(args_repr)
        + "))\n"
        "# v5:  add to manifest.yaml:\n"
        "#       policies:\n"
        "#         my_cedar_policy:\n"
        "#           type: cedar\n"
        "#           policy_path: ./policies/my_cedar.cedar\n"
        "#           # Optional: entities_path and schema_path"
    )


# ---------------------------------------------------------------------------
# Side effects (only when --write is set)
# ---------------------------------------------------------------------------


def _migrate_governance_chain(
    chain_root: Path,
    project_root: Path,
    *,
    write: bool,
) -> GovernanceChainFinding:
    """Resolve a v4 governance chain rooted at *chain_root* into v5.

    On --write the function:

    - calls :func:`resolve_manifest` to produce a flat ACS manifest +
      Rego bundle under ``chain_root/manifest.yaml`` +
      ``chain_root/policy/agt_legacy.rego``;
    - moves every governance.yaml(.yml) that lives directly in
      ``chain_root`` to ``<file>.v4-backup`` so re-runs do not
      double-translate. Parent governance files that the resolved chain
      inherits from directories ABOVE ``chain_root`` are left untouched;
      each parent is migrated by its own chain.

    On dry-run the rego bundle is materialised inside a temp dir that
    is dropped on return, so the project on disk is untouched.
    """
    finding = GovernanceChainFinding(chain_root=chain_root, governance_files=[])
    manifest_path = chain_root / "manifest.yaml"
    rego_bundle = chain_root / "policy"
    # ``exists()`` follows symlinks and returns False for a broken one, so a
    # symlink named ``manifest.yaml``/``policy`` (broken or pointing outside
    # chain_root) would slip past this guard and make the migration write its
    # bundle through the link — outside the project — while still unlinking the
    # governance files. Treat any pre-existing path OR symlink as output that
    # must not be overwritten.
    manifest_present = manifest_path.exists() or manifest_path.is_symlink()
    bundle_present = rego_bundle.exists() or rego_bundle.is_symlink()
    if manifest_present or bundle_present:
        finding.error = (
            "migration output already exists; refusing to overwrite "
            f"{manifest_path if manifest_present else rego_bundle}"
        )
        return finding

    if write:
        target_bundle_dir = rego_bundle
    else:
        target_bundle_dir = Path(
            tempfile.mkdtemp(prefix="agt_migrate_dryrun_")
        )

    try:
        manifest = resolve_manifest(
            project_root.resolve(),
            chain_root,
            bundle_dir=target_bundle_dir,
        )
    except ResolutionError as exc:
        finding.error = f"{exc.reason.value}: {exc}"
        _rmtree_silent(target_bundle_dir)
        return finding

    discovered = [
        Path(p) for p in manifest.get("metadata", {}).get("resolved_from", {}).get("chain", [])
    ]
    finding.governance_files = discovered
    # Only back up and remove governance files that live directly in this
    # chain_root. The resolved chain also lists parent governance files ABOVE
    # chain_root; those declare deny rules that ADR-0014 treats as immutable and
    # are shared by every sibling chain under the same parent. Each parent file
    # is migrated by its own chain, so backing it up / unlinking it here would
    # corrupt sibling chains that inherit from it.
    chain_root_resolved = chain_root.resolve()
    local_files = [
        gov_file
        for gov_file in discovered
        if gov_file.parent.resolve() == chain_root_resolved
    ]
    backup_paths = [
        gov_file.with_name(f".{gov_file.name}.v4-backup")
        for gov_file in local_files
    ]
    existing_backups = [path for path in backup_paths if path.exists()]
    if existing_backups:
        finding.error = (
            "migration backup already exists; refusing to overwrite "
            + ", ".join(str(path) for path in existing_backups)
        )
        _rmtree_silent(target_bundle_dir)
        return finding

    if write:
        with tempfile.TemporaryDirectory(
            prefix=".agt_chain_migration_", dir=chain_root
        ) as staging_dir:
            staged_manifest = Path(staging_dir) / "manifest.yaml"
            staged_manifest.write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            # Use os.replace (atomic rename) rather than os.link so the swap
            # works on any filesystem, not just hard-link-capable ones (some
            # Windows volumes and Unix mounts do not support hard links). Each
            # rename both backs
            # up and removes the original in one atomic step, so the data always
            # has exactly one name and a crash cannot lose it. Every path stays
            # inside chain_root (staging dir and backups), so the rename can
            # never cross a filesystem boundary.
            moved_backups: list[tuple[Path, Path]] = []
            manifest_placed = False
            try:
                os.replace(staged_manifest, manifest_path)
                manifest_placed = True
                for gov_file, backup in zip(
                    local_files, backup_paths, strict=True
                ):
                    os.replace(gov_file, backup)
                    moved_backups.append((backup, gov_file))
            except Exception as exc:
                for backup, gov_file in reversed(moved_backups):
                    os.replace(backup, gov_file)
                if manifest_placed:
                    manifest_path.unlink(missing_ok=True)
                _rmtree_silent(rego_bundle)
                finding.error = (
                    f"chain migration failed: {type(exc).__name__}: {exc}"
                )
                return finding
            finding.backups.extend(backup_paths)
    else:
        _rmtree_silent(target_bundle_dir)

    finding.manifest_path = manifest_path
    finding.rego_bundle = rego_bundle
    finding.applied = write
    return finding


def _rmtree_silent(path: Path) -> None:
    """Best-effort recursive delete used by the dry-run path."""
    if not path.exists():
        return
    for child in sorted(path.rglob("*"), reverse=True):
        try:
            if child.is_dir():
                child.rmdir()
            else:
                child.unlink()
        except OSError:
            pass
    try:
        path.rmdir()
    except OSError:
        pass


def _migrate_governance_policy(
    finding: GovernancePolicyFinding,
    *,
    write: bool,
) -> None:
    """Materialise a v5 manifest for a single GovernancePolicy() call."""
    source_dir = finding.location.path.parent
    policies_dir = source_dir / "policies"
    base_name = finding.location.path.stem
    manifest_path = policies_dir / f"{base_name}.manifest.yaml"

    # Render the rewrite snippet unconditionally — users read it from the
    # report whether or not --write was passed.
    finding.rewrite_snippet = _render_governance_rewrite_snippet(
        kwargs=finding.kwargs,
        manifest_path=manifest_path,
        manual_review=finding.manual_review,
    )

    if finding.manual_review:
        return

    try:
        inputs = MigrationPolicyInput(**finding.migration_kwargs)
    except (TypeError, ValueError, re.error) as exc:
        finding.manual_review.append(str(exc))
        finding.rewrite_snippet = _render_governance_rewrite_snippet(
            kwargs=finding.kwargs,
            manifest_path=manifest_path,
            manual_review=finding.manual_review,
        )
        return

    bundle_dir = policies_dir / f"{base_name}_bundle"
    if manifest_path.exists() or bundle_dir.exists():
        finding.manual_review.append(
            "migration output already exists; refusing to overwrite it"
        )
        finding.rewrite_snippet = _render_governance_rewrite_snippet(
            kwargs=finding.kwargs,
            manifest_path=manifest_path,
            manual_review=finding.manual_review,
        )
        return

    if not write:
        finding.manifest_path = manifest_path
        return

    policies_dir.mkdir(parents=True, exist_ok=True)
    policy_id = base_name or "agt_governance_policy"
    with tempfile.TemporaryDirectory(
        prefix=f".{policy_id}_migration_", dir=policies_dir
    ) as staging_dir:
        staging = Path(staging_dir)
        staging_bundle = staging / "bundle"
        bundle_created = False
        try:
            manifest = build_migrated_manifest(
                inputs,
                bundle_dir=staging_bundle,
                policy_id=policy_id,
            )
            manifest["policies"][policy_id]["bundle"] = str(
                bundle_dir.resolve()
            )
            manifest = AgtManifest.from_document(manifest).to_document()
            staged_manifest = staging / "manifest.yaml"
            staged_manifest.write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            bundle_dir.mkdir()
            bundle_created = True
            # Snapshot the entries before moving them, since os.replace mutates
            # staging_bundle as we iterate. os.replace (atomic rename) keeps this
            # portable across filesystems that do not support hard links; every
            # path is under policies_dir, so the rename never crosses a mount.
            for staged_file in list(staging_bundle.iterdir()):
                os.replace(staged_file, bundle_dir / staged_file.name)
            os.replace(staged_manifest, manifest_path)
        except Exception as exc:
            if bundle_created and bundle_dir.exists():
                shutil.rmtree(bundle_dir)
            finding.manual_review.append(
                f"manifest generation failed: {type(exc).__name__}: {exc}"
            )
            finding.rewrite_snippet = _render_governance_rewrite_snippet(
                kwargs=finding.kwargs,
                manifest_path=manifest_path,
                manual_review=finding.manual_review,
            )
            return
    finding.manifest_path = manifest_path
    finding.applied = True


def _render_governance_rewrite_snippet(
    *,
    kwargs: dict[str, Any],
    manifest_path: Path,
    manual_review: list[str],
) -> str:
    """Render the v5 replacement snippet for a v4 ``GovernancePolicy``.

    v4 callers most often replace::

        policy = GovernancePolicy(max_tokens=2048, allowed_tools=[...])
        agent.attach_policy(policy)

    with::

        runtime = AgtRuntime(Path("policies/<file>.manifest.yaml"))
        agent.attach_runtime(runtime)

    The snippet is purely informational — we never auto-rewrite Python
    source even with ``--write`` because the surrounding usage of the
    policy object varies too much across hosts.
    """
    if manual_review:
        reasons = "\n".join(f"#     - {reason}" for reason in manual_review)
        return (
            "# Manual review required. No manifest was written.\n"
            f"{reasons}\n"
            "# Resolve these fields, then run `agt migrate v4-to-v5 --write` again."
        )
    return (
        "# v4:\n"
        "#     from agent_os.integrations.base import GovernancePolicy\n"
        f"#     policy = GovernancePolicy({_pretty_kwargs(kwargs)})\n"
        "#\n"
        "# v5 — replace the construction with:\n"
        "#     from pathlib import Path\n"
        "#     from agt.policies.runtime import AgtRuntime\n"
        f"#     runtime = AgtRuntime.from_manifest(Path({str(manifest_path)!r}))\n"
    )


def _pretty_kwargs(kwargs: dict[str, Any]) -> str:
    if not kwargs:
        return ""
    parts: list[str] = []
    for key, value in kwargs.items():
        if isinstance(value, str) and value.startswith("<expr:"):
            parts.append(f"{key}=...")
        else:
            parts.append(f"{key}={value!r}")
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def _md_escape(text: str) -> str:
    """Escape the small set of Markdown metacharacters we actually emit."""
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "\\`")
    )


def render_report(report: MigrationReport) -> str:
    """Render *report* as a Markdown document.

    The output is plain Markdown 1.0 — no Markdown extensions, no
    HTML, so it parses cleanly with every renderer the test suite
    exercises. The structure is stable across runs so it can be
    diff-reviewed in PRs.
    """
    lines: list[str] = []
    lines.append("# AGT v4 → v5 Migration Report")
    lines.append("")
    lines.append(f"Project root: `{report.project_root}`")
    mode = "write" if report.write else "dry-run"
    lines.append(f"Mode: **{mode}**")
    lines.append("")

    if not report.has_findings():
        lines.append("No v4 artifacts detected — the project already looks v5-clean.")
        lines.append("")
        return "\n".join(lines)

    # — governance chains -----------------------------------------
    lines.append("## 1. Governance chains")
    lines.append("")
    if not report.governance_chains:
        lines.append("_None found._")
    else:
        lines.append(
            "| # | Chain root | Discovered files | Resolved manifest | Rego bundle | Status |"
        )
        lines.append("|---|---|---|---|---|---|")
        for idx, gc in enumerate(report.governance_chains, start=1):
            files = ", ".join(f"`{p}`" for p in gc.governance_files) or "_n/a_"
            manifest = f"`{gc.manifest_path}`" if gc.manifest_path else "_n/a_"
            bundle = f"`{gc.rego_bundle}`" if gc.rego_bundle else "_n/a_"
            status = (
                f"❌ {_md_escape(gc.error)}"
                if gc.error
                else ("✅ migrated" if gc.applied else "🟡 would migrate")
            )
            lines.append(
                f"| {idx} | `{gc.chain_root}` | {files} | {manifest} | {bundle} | {status} |"
            )
            if gc.backups:
                lines.append("")
                lines.append(
                    "    Backups: "
                    + ", ".join(f"`{p}`" for p in gc.backups)
                )
    lines.append("")

    # — GovernancePolicy() ----------------------------------------
    lines.append("## 2. `GovernancePolicy(...)` constructor calls")
    lines.append("")
    if not report.governance_policies:
        lines.append("_None found._")
    else:
        for idx, gp in enumerate(report.governance_policies, start=1):
            lines.append(f"### 2.{idx} `{gp.location}`")
            lines.append("")
            lines.append("**Captured kwargs:**")
            lines.append("")
            lines.append("```python")
            lines.append(f"GovernancePolicy({_pretty_kwargs(gp.kwargs)})")
            lines.append("```")
            lines.append("")
            if gp.manifest_path is not None:
                state = "written" if gp.applied else "would be written"
                lines.append(f"**v5 manifest** ({state}): `{gp.manifest_path}`")
                lines.append("")
            if gp.manual_review:
                lines.append("**Manual review required. No manifest was written.**")
                lines.append("")
                for reason in gp.manual_review:
                    lines.append(f"- {_md_escape(reason)}")
                lines.append("")
            lines.append("**Suggested code rewrite:**")
            lines.append("")
            lines.append("```python")
            lines.append(gp.rewrite_snippet.rstrip())
            lines.append("```")
            lines.append("")
    lines.append("")

    # — PolicyAction.BLOCK ----------------------------------------
    lines.append("## 3. `PolicyAction.BLOCK` references")
    lines.append("")
    if not report.policy_action_blocks:
        lines.append("_None found._")
    else:
        lines.append("| # | Location | Suggested rewrite |")
        lines.append("|---|---|---|")
        for idx, pb in enumerate(report.policy_action_blocks, start=1):
            snippet_inline = pb.rewrite_snippet.replace("\n", "<br>")
            lines.append(f"| {idx} | `{pb.location}` | `{_md_escape(snippet_inline)}` |")
    lines.append("")

    # — CedarBackend ----------------------------------------------
    lines.append("## 4. `CedarBackend(...)` calls")
    lines.append("")
    if not report.cedar_backends:
        lines.append("_None found._")
    else:
        for idx, cb in enumerate(report.cedar_backends, start=1):
            lines.append(f"### 4.{idx} `{cb.location}`")
            lines.append("")
            lines.append("```yaml")
            lines.append(cb.rewrite_snippet.rstrip())
            lines.append("```")
            lines.append("")
    lines.append("")

    # — PolicyInterceptor -----------------------------------------
    lines.append("## 5. Direct `PolicyInterceptor` subclasses")
    lines.append("")
    if not report.policy_interceptors:
        lines.append("_None found._")
    else:
        lines.append("| # | Class | Location | Action |")
        lines.append("|---|---|---|---|")
        for idx, pi in enumerate(report.policy_interceptors, start=1):
            lines.append(
                f"| {idx} | `{pi.class_name}` | `{pi.location}` | {_md_escape(pi.note)} |"
            )
    lines.append("")

    # — legacy imports --------------------------------------------
    lines.append("## 6. Legacy `agent_os.policies` imports")
    lines.append("")
    if not report.legacy_imports:
        lines.append("_None found._")
    else:
        lines.append("| # | Location | Imported names |")
        lines.append("|---|---|---|")
        for idx, li in enumerate(report.legacy_imports, start=1):
            names = ", ".join(f"`{n}`" for n in li.imported_names) or "_n/a_"
            lines.append(f"| {idx} | `{li.location}` | {names} |")
    lines.append("")

    if report.errors:
        lines.append("## 7. Errors")
        lines.append("")
        for err in report.errors:
            lines.append(f"- {_md_escape(err)}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------


def migrate_project(
    project_root: Path,
    *,
    write: bool = False,
) -> MigrationReport:
    """Walk *project_root* and produce a :class:`MigrationReport`.

    The function never raises for individual file errors — those are
    aggregated under ``report.errors`` so users get a complete picture
    of the project. Programmer mistakes (e.g. ``project_root`` does not
    exist) still raise :class:`FileNotFoundError` so the CLI can fail
    with a non-zero exit code.
    """
    project_root = project_root.resolve()
    if not project_root.is_dir():
        raise FileNotFoundError(f"project root {project_root} is not a directory")

    report = MigrationReport(project_root=project_root, write=write)

    chain_roots = _find_governance_chains(project_root)

    # Preflight every governance chain without project side effects.
    for chain_root in chain_roots:
        report.governance_chains.append(
            _migrate_governance_chain(
                chain_root,
                project_root,
                write=False,
            )
        )

    # Scan and preflight every Python constructor before any write.
    for path in _iter_files(project_root):
        if path.suffix != ".py":
            continue
        try:
            visitor = _scan_python_file(path)
        except SourceScanError as exc:
            report.errors.append(str(exc))
            continue
        if len(visitor.governance_policies) > 1:
            for finding in visitor.governance_policies:
                finding.manual_review.append(
                    "multiple GovernancePolicy constructors in one source file "
                    "require explicit manifest and policy identifiers"
                )
        for finding in visitor.governance_policies:
            _migrate_governance_policy(finding, write=False)
            report.governance_policies.append(finding)
        report.policy_action_blocks.extend(visitor.policy_action_blocks)
        report.cedar_backends.extend(visitor.cedar_backends)
        report.policy_interceptors.extend(visitor.policy_interceptors)
        report.legacy_imports.extend(visitor.legacy_imports)

    if not write:
        return report
    if (
        any(chain.error for chain in report.governance_chains)
        or report.requires_manual_review()
        or report.errors
    ):
        return report

    # Apply only after every source and chain passed preflight.
    report.governance_chains = []
    for chain_root in chain_roots:
        chain_finding = _migrate_governance_chain(
            chain_root,
            project_root,
            write=True,
        )
        report.governance_chains.append(chain_finding)
    if any(chain.error for chain in report.governance_chains):
        return report
    for finding in report.governance_policies:
        _migrate_governance_policy(finding, write=True)

    return report


# ---------------------------------------------------------------------------
# argparse glue
# ---------------------------------------------------------------------------


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Wire ``agt migrate`` flags onto *parser*."""
    parser.add_argument(
        "direction",
        choices=("v4-to-v5",),
        help="Migration direction. Only 'v4-to-v5' is supported today.",
    )
    parser.add_argument(
        "project_root",
        nargs="?",
        default=".",
        help="Project root to migrate (defaults to the current directory).",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help=(
            "Apply the migration: move governance.yaml files to "
            ".governance.yaml.v4-backup and write manifest.yaml + Rego "
            "bundles. Without --write the run is a pure dry-run."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Force dry-run mode (the default). Useful in scripts that "
            "want to be explicit even when --write is later added."
        ),
    )
    parser.add_argument(
        "--write-report",
        metavar="MIGRATION.md",
        help=(
            "Write the Markdown report to the given path in addition to "
            "printing it to stdout."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )


def run_from_args(args: argparse.Namespace) -> int:
    """Execute the migrate sub-command from parsed argparse args."""
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.dry_run and args.write:
        print(
            "agt migrate: --dry-run and --write are mutually exclusive",
            file=sys.stderr,
        )
        return 2

    project_root = Path(args.project_root).resolve()
    if not project_root.is_dir():
        print(
            f"agt migrate: project root {project_root} is not a directory",
            file=sys.stderr,
        )
        return 2

    write = bool(args.write) and not args.dry_run
    report = migrate_project(project_root, write=write)
    text = render_report(report)
    print(text)

    if args.write_report:
        out_path = Path(args.write_report)
        out_path.write_text(text, encoding="utf-8")

    # Dry runs remain informational. A write run fails when any artifact could
    # not be migrated exactly, so automation cannot mistake partial output for
    # a completed security-policy migration.
    if write and (
        any(c.error for c in report.governance_chains)
        or report.requires_manual_review()
        or report.errors
    ):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    """``python -m agt.cli.migrate`` direct entry point.

    Equivalent to ``python -m agt.cli migrate``; provided so callers
    can wire the verb up as a console script without going through
    :mod:`agt.cli.__main__`.
    """
    parser = argparse.ArgumentParser(
        prog="agt-migrate",
        description=CLI_DESCRIPTION,
    )
    add_arguments(parser)
    args = parser.parse_args(argv)
    return run_from_args(args)


if __name__ == "__main__":  # pragma: no cover - manual invocation
    sys.exit(main())
