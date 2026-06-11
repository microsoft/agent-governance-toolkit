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
3. For every ``GovernancePolicy(...)`` constructor call, parse the
   keyword arguments out of the source and bridge them through
   :func:`agt.policies.bridge.governance_to_acs_manifest`.
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
import dataclasses
import logging
import os
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agt.manifest_resolution import ResolutionError, resolve_manifest

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


@dataclass
class GovernancePolicyFinding:
    """A ``GovernancePolicy(...)`` constructor call in Python source."""

    location: Location
    kwargs: dict[str, Any]
    manifest_path: Path | None = None
    rewrite_snippet: str = ""


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


class _LegacyVisitor(ast.NodeVisitor):
    """Collect every legacy v4 marker out of a single Python source file."""

    def __init__(self, path: Path):
        self.path = path
        self.governance_policies: list[GovernancePolicyFinding] = []
        self.policy_action_blocks: list[PolicyActionBlockFinding] = []
        self.cedar_backends: list[CedarBackendFinding] = []
        self.policy_interceptors: list[PolicyInterceptorFinding] = []
        self.legacy_imports: list[LegacyImportFinding] = []

    # — imports ------------------------------------------------------
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module or ""
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

        if callee_tail == "GovernancePolicy":
            kwargs: dict[str, Any] = {}
            for kw in node.keywords:
                if kw.arg is None:
                    continue
                kwargs[kw.arg] = _literal_or_repr(kw.value)
            self.governance_policies.append(
                GovernancePolicyFinding(
                    location=Location(self.path, node.lineno, node.col_offset),
                    kwargs=kwargs,
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


def _scan_python_file(path: Path) -> _LegacyVisitor | None:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return None
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
        "#           bundle: ./policies/my_cedar.cedar\n"
        "#           query: my::action::permit"
    )


# ---------------------------------------------------------------------------
# Bridge helpers (v4 GovernancePolicy → v5 manifest)
# ---------------------------------------------------------------------------


@dataclass
class _BridgeInputs:
    """A normalised v4 GovernancePolicy shape used by the bridge."""

    name: str = "migrated_policy"
    max_tokens: int = 0
    max_tool_calls: int = 0
    allowed_tools: list[str] = field(default_factory=list)
    blocked_patterns: list[Any] = field(default_factory=list)
    require_human_approval: bool = False
    confidence_threshold: float = 0.0
    version: str = "1.0.0"


def _coerce_bridge_inputs(kwargs: dict[str, Any]) -> _BridgeInputs:
    """Pull bridge-relevant fields out of the literal-decoded kwargs.

    Anything we cannot literal-decode is silently treated as the
    field's default; the report still records the raw kwargs so the
    user can see what got dropped.
    """
    out = _BridgeInputs()
    scalar_fields = (
        ("name", str),
        ("max_tokens", int),
        ("max_tool_calls", int),
        ("require_human_approval", bool),
        ("confidence_threshold", (int, float)),
        ("version", str),
    )
    for source_key, expected_type in scalar_fields:
        if source_key not in kwargs:
            continue
        value = kwargs[source_key]
        if isinstance(value, str) and value.startswith("<expr:"):
            continue
        if not isinstance(value, expected_type):
            continue
        setattr(out, source_key, value)

    allowed = kwargs.get("allowed_tools")
    if isinstance(allowed, list):
        out.allowed_tools = [str(x) for x in allowed if isinstance(x, str)]

    blocked = kwargs.get("blocked_patterns")
    if isinstance(blocked, list):
        normalised: list[Any] = []
        for entry in blocked:
            if isinstance(entry, str):
                normalised.append(entry)
            elif isinstance(entry, tuple) and len(entry) == 2 and isinstance(entry[0], str):
                normalised.append(entry[0])
        out.blocked_patterns = normalised

    return out


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
    - moves every governance.yaml(.yml) in the discovered chain to
      ``<file>.v4-backup`` so re-runs do not double-translate.

    On dry-run the rego bundle is materialised inside a temp dir that
    is dropped on return, so the project on disk is untouched.
    """
    finding = GovernanceChainFinding(chain_root=chain_root, governance_files=[])

    if write:
        target_bundle_dir = chain_root / "policy"
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
        if not write:
            _rmtree_silent(target_bundle_dir)
        return finding

    discovered = [
        Path(p) for p in manifest.get("metadata", {}).get("resolved_from", {}).get("chain", [])
    ]
    finding.governance_files = discovered

    manifest_path = chain_root / "manifest.yaml"
    rego_bundle = chain_root / "policy"

    if write:
        manifest_path.write_text(
            yaml.safe_dump(manifest, sort_keys=False),
            encoding="utf-8",
        )
        for gov_file in discovered:
            backup = gov_file.with_name(f".{gov_file.name}.v4-backup")
            if gov_file.exists():
                gov_file.replace(backup)
                finding.backups.append(backup)
    else:
        _rmtree_silent(target_bundle_dir)

    finding.manifest_path = manifest_path
    finding.rego_bundle = rego_bundle
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
    inputs = _coerce_bridge_inputs(finding.kwargs)
    source_dir = finding.location.path.parent
    policies_dir = source_dir / "policies"
    base_name = finding.location.path.stem
    manifest_path = policies_dir / f"{base_name}.manifest.yaml"

    # Render the rewrite snippet unconditionally — users read it from the
    # report whether or not --write was passed.
    finding.rewrite_snippet = _render_governance_rewrite_snippet(
        kwargs=finding.kwargs,
        manifest_path=manifest_path,
    )

    if not write:
        finding.manifest_path = manifest_path
        return

    try:
        from agt.policies.bridge import governance_to_acs_manifest
    except Exception as exc:  # pragma: no cover - import error path
        logger.warning("agt.policies.bridge unavailable: %s", exc)
        return

    policies_dir.mkdir(parents=True, exist_ok=True)
    bundle_dir = policies_dir / f"{base_name}_bundle"
    manifest = governance_to_acs_manifest(
        dataclasses.replace(inputs),
        bundle_dir=bundle_dir,
        policy_id=base_name or "agt_governance_policy",
    )
    manifest_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    finding.manifest_path = manifest_path


def _render_governance_rewrite_snippet(
    *,
    kwargs: dict[str, Any],
    manifest_path: Path,
) -> str:
    """Render the v5 replacement snippet for a v4 ``GovernancePolicy``.

    The bridge ships a ``Manifest.from_governance_policy`` helper on the
    v5 surface; v4 callers most often replace::

        policy = GovernancePolicy(max_tokens=2048, allowed_tools=[...])
        agent.attach_policy(policy)

    with::

        runtime = AgtRuntime(Path("policies/<file>.manifest.yaml"))
        agent.attach_runtime(runtime)

    The snippet is purely informational — we never auto-rewrite Python
    source even with ``--write`` because the surrounding usage of the
    policy object varies too much across hosts.
    """
    rel_manifest = manifest_path
    if "name" in kwargs:
        name_literal = repr(kwargs["name"]) if isinstance(kwargs["name"], str) else "..."
    else:
        name_literal = '"migrated_policy"'
    return (
        "# v4:\n"
        "#     from agent_os.integrations.base import GovernancePolicy\n"
        f"#     policy = GovernancePolicy({_pretty_kwargs(kwargs)})\n"
        "#\n"
        "# v5 — replace the construction with:\n"
        "#     from agt.policies.runtime import AgtRuntime\n"
        f"#     runtime = AgtRuntime(Path({str(rel_manifest)!r}))\n"
        "#     # Or, if you want to keep the v4 dataclass surface:\n"
        "#     from agt.policies.bridge import governance_to_acs_manifest\n"
        f"#     manifest = governance_to_acs_manifest(policy)  # name={name_literal}\n"
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
                else ("✅ migrated" if report.write else "🟡 would migrate")
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
                state = "written" if report.write else "would be written"
                lines.append(f"**v5 manifest** ({state}): `{gp.manifest_path}`")
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

    # 1. governance.yaml chains
    for chain_root in _find_governance_chains(project_root):
        chain_finding = _migrate_governance_chain(
            chain_root,
            project_root,
            write=write,
        )
        report.governance_chains.append(chain_finding)

    # 2-6. Python AST scans
    for path in _iter_files(project_root):
        if path.suffix != ".py":
            continue
        visitor = _scan_python_file(path)
        if visitor is None:
            continue
        for gp in visitor.governance_policies:
            _migrate_governance_policy(gp, write=write)
            report.governance_policies.append(gp)
        report.policy_action_blocks.extend(visitor.policy_action_blocks)
        report.cedar_backends.extend(visitor.cedar_backends)
        report.policy_interceptors.extend(visitor.policy_interceptors)
        report.legacy_imports.extend(visitor.legacy_imports)

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

    # Exit zero even when findings exist — the CLI is informational by
    # default. We only fail when a per-chain resolution error blocks a
    # --write migration mid-flight.
    if write and any(c.error for c in report.governance_chains):
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
