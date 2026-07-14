#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""v4 policy-language inventory and removal ratchet.

Phase 0 of removing the legacy v4 policy language so the ACS (v5) policy
layer is the only policy contract in the toolkit. Builds a per-file,
per-symbol inventory of every surviving v4 policy-language marker and
enforces a strict ratchet, so no change may add v4 usage, no v4 marker may
move into a new file, and the count can only move toward zero.

Python detection is AST, import, and dynamic-lookup aware. Unambiguous v4
names are counted as identifiers, attributes, class/function definitions,
import aliases and their uses, keyword and parameter names, string
annotations (including compound and forward-ref forms), and semantic string
constants such as ``getattr`` targets, ``mock.patch`` targets, and dotted
import paths. Names that collide with unrelated code (``ExecutionContext``,
``PolicyEvaluator``) are counted only when bound from a qualifying v4 module,
accessed through a v4 module alias, or defined/used in the canonical v4 file,
with relative imports resolved against the current module so foreign
look-alikes are not miscounted. Ordinary prose strings and comments never
match. A narrow structural check catches renamed intent-policy interpreters
that combine blocked patterns, tool lists, budgets, and pattern modes. Any
Python file that cannot be decoded or parsed fails the gate closed.

Rust and TypeScript use identifier-boundary token matching. Markdown, the
normative AGT spec layer, v4 ``governance.yaml`` artifacts, and declarative v4
``PolicyDocument`` YAML/JSON policy files are scanned so the docs, spec, and
policy-data purge obligations are visible to the zero gate.

v4 policy language may survive only inside the isolated one-way migration
tool and the removal plan doc (``ALLOWED_V4_FILES`` plus the dedicated
``agt-v4-migrate`` package). Those paths are inventoried but never ratcheted.

Usage:
    python scripts/check_v4_ratchet.py                    # gate against baseline
    python scripts/check_v4_ratchet.py --report           # inventory, no gate
    python scripts/check_v4_ratchet.py --json             # machine-readable
    python scripts/check_v4_ratchet.py --update-baseline  # refuses increases
    python scripts/check_v4_ratchet.py --update-baseline --allow-baseline-increase
"""
from __future__ import annotations

import argparse
import ast
import io
import json
import re
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / "scripts" / "v4_ratchet_baseline.json"

# Unambiguous v4 identifiers, counted globally.
UNAMBIGUOUS_SYMBOLS: frozenset[str] = frozenset(
    {
        "GovernancePolicy",
        "PatternType",
        "PolicyInterceptor",
        "ViolationCategory",
        "PolicyCheckResult",
        "PolicyDocument",
        "PolicyAction",
        "CedarBackend",
        "from_cedar",
        "discover_policies",
        "aca_config_from_policy",
        "docker_config_from_policy",
        "governance_to_acs_manifest",
        "governance_to_document",
        "get_runtime_bridge",
        "hyperlight_config_from_policy",
        "mxc_config_from_policy",
        "nono_config_from_policy",
        "PolicyTemplates",
        "compose_policies",
        "override_policy",
        "policy_to_mxc_json",
        "policy_yaml_to_mxc_json",
        "policy_yaml_to_nono_config",
        "AdapterRuntimeBridge",
        "to_v4_check_result",
        "from_check_result",
        "resolution_root",
    }
)

# Names that collide with unrelated classes; counted only when tied to a
# qualifying v4 module or the canonical v4 file.
AMBIGUOUS_MODULES: dict[str, frozenset[str]] = {
    "AgtManifest": frozenset({"agent_os.policies.schema"}),
    "AgtRuntime": frozenset(
        {"agent_os.policies", "agent_os.integrations.base"}
    ),
    "BackendDecision": frozenset(
        {"agent_os.policies", "agent_os.policies.backends"}
    ),
    "ExecutionContext": frozenset({"agent_os.integrations.base"}),
    "ExternalPolicyBackend": frozenset(
        {"agent_os.policies", "agent_os.policies.backends"}
    ),
    "PolicyCondition": frozenset(
        {"agent_os.policies", "agent_os.policies.schema"}
    ),
    "PolicyDefaults": frozenset(
        {"agent_os.policies", "agent_os.policies.schema"}
    ),
    "PolicyOperator": frozenset(
        {"agent_os.policies", "agent_os.policies.schema"}
    ),
    "PolicyRule": frozenset(
        {"agent_os.policies", "agent_os.policies.schema"}
    ),
    "PolicyEvaluator": frozenset(
        {"agent_os.policies", "agent_os.policies.evaluator", "agent_os.compat"}
    ),
}
CANONICAL_DEF_FILES: dict[str, frozenset[str]] = {
    "ExecutionContext": frozenset(
        {"agent-governance-python/agent-os/src/agent_os/integrations/base.py"}
    ),
    "PolicyEvaluator": frozenset(
        {"agent-governance-python/agent-os/src/agent_os/policies/evaluator.py"}
    ),
}

# Module paths whose import marks a v4 consumer.
PYTHON_V4_MODULES: tuple[str, ...] = (
    "agt.policies.bridge",
    "agent_os.compat",
    "agent_os.integrations.policy_compose",
    "agent_os.integrations.templates",
    "agent_os.integrations._v5_runtime_bridge",
    "agent_os.policies.backends",
    "agent_os.policies.bridge",
    "agent_os.policies.budget",
    "agent_os.policies.cli",
    "agent_os.policies.conflict_resolution",
    "agent_os.policies.decision",
    "agent_os.policies.discovery",
    "agent_os.policies.dynamic_conditions",
    "agent_os.policies.evaluator",
    "agent_os.policies.merge",
    "agent_os.policies.schema",
    "agent_os.policies.shared",
    "agt.manifest_resolution",
)
V4_AGENT_OS_POLICY_CLASSES: frozenset[str] = frozenset(
    {
        "BudgetPolicy",
        "DynamicBudgetTracker",
        "DynamicConditionEvaluator",
        "PolicyConflictResolver",
    }
)

# Non-Python source trees use identifier-boundary token matching.
NONPY_V4_TOKENS: frozenset[str] = frozenset({"GovernancePolicy", "PatternType"})

# One authoritative documentation vocabulary derived from the Python symbols
# plus spec literals. Substring matched in Markdown and the AGT spec layer.
DOC_LITERAL_TOKENS: frozenset[str] = frozenset(
    {
        "AGT-RESOLUTION",
        "governance.yaml",
        "agt_legacy",
        "agt.legacy",
        *PYTHON_V4_MODULES,
    }
)
# Ambiguous names are excluded from doc tokens because a document cannot
# qualify them by import, so including them misclassifies unrelated trust
# documentation as v4.
DOC_TOKENS: frozenset[str] = UNAMBIGUOUS_SYMBOLS | DOC_LITERAL_TOKENS

# v4 may survive only in the migration tool and the removal plan doc.
ALLOWED_V4_FILES: frozenset[str] = frozenset(
    {
        "agent-governance-python/agt-policies/src/agt/cli/migrate.py",
        "agent-governance-python/agt-policies/src/agt/cli/__main__.py",
        "agent-governance-python/agt-policies/src/agt/cli/__init__.py",
        "agent-governance-python/agt-policies/src/agt/cli/_migrate_bridge.py",
        "agent-governance-python/agt-policies/tests/test_migrate.py",
        "agent-governance-python/agt-policies/tests/test_migration_boundary.py",
        "agent-governance-python/agt-policies/tests/test_migration_equivalence.py",
        "agent-governance-python/agt-policies/tests/test_migrate_resolution.py",
        "docs/v4-removal.md",
        # The scanner necessarily contains every signature it detects.
        "scripts/check_v4_ratchet.py",
        # The ratchet's own test fixtures reference v4 names deliberately.
        "scripts/tests/test_check_v4_ratchet.py",
        # The baseline inventories v4 names by design and must not inventory itself.
        "scripts/v4_ratchet_baseline.json",
    }
)
ALLOWED_V4_PREFIXES: tuple[str, ...] = (
    "agent-governance-python/agt-v4-migrate/",
    "agent-governance-python/agt-policies/src/agt/cli/_migrate_resolution/",
)

EXCLUDE_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".eggs",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "target",
        "vendor",
        "third_party",
    }
)
# policy-engine is the vendored v5 ACS engine, excluded EXCEPT its normative
# spec layer, which is a confirmed v4 obligation surface.
EXCLUDE_TOP_DIRS: frozenset[str] = frozenset({"policy-engine"})
SPEC_INCLUDE_PREFIX = "policy-engine/spec/"

GOVERNANCE_YAML_NAMES: frozenset[str] = frozenset({"governance.yaml", "governance.yml"})
PACKAGE_MARKERS: tuple[str, ...] = ("pyproject.toml", "Cargo.toml", "package.json")
IDENT_PATH_RE = re.compile(r"^[A-Za-z_][\w.]*$")


@dataclass
class FileHits:
    path: Path
    counts: dict[str, int] = field(default_factory=dict)
    parse_error: str | None = None

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def _in_allowed_root(rel_path: str) -> bool:
    if rel_path in ALLOWED_V4_FILES:
        return True
    return any(rel_path.startswith(prefix) for prefix in ALLOWED_V4_PREFIXES)


def decide_scanner(path: Path) -> str | None:
    """Return the scanner name for a path, or None to skip it."""
    rel = _rel(path)
    parts = path.relative_to(REPO_ROOT).parts
    if any(part in EXCLUDE_DIR_NAMES for part in parts):
        return None
    suffix = path.suffix
    in_excluded_top = bool(parts) and parts[0] in EXCLUDE_TOP_DIRS
    if in_excluded_top:
        if suffix == ".md" and rel.startswith(SPEC_INCLUDE_PREFIX):
            return "spec"
        return None
    if suffix == ".py":
        return "python"
    if suffix in (".rs", ".ts", ".tsx"):
        return "tokens"
    if path.name in GOVERNANCE_YAML_NAMES:
        return "governance_yaml"
    if suffix in (".yaml", ".yml", ".json"):
        return "policy_data"
    if suffix == ".md":
        return "spec"
    return None


def _package_root(path: Path) -> str:
    for parent in path.parents:
        if parent < REPO_ROOT:
            break
        if any((parent / marker).is_file() for marker in PACKAGE_MARKERS):
            return _rel(parent)
        if parent == REPO_ROOT:
            break
    parts = path.relative_to(REPO_ROOT).parts
    return "/".join(parts[:2]) if len(parts) >= 2 else parts[0]


# --------------------------- module resolution ---------------------------


def _module_dotted(rel: str) -> tuple[str, bool]:
    """Best-effort dotted module for a Python file. Returns (module, is_pkg)."""
    parts = rel.split("/")
    if "src" in parts:
        idx = len(parts) - 1 - parts[::-1].index("src")
        mod_parts = parts[idx + 1 :]
    else:
        mod_parts = parts
    is_pkg = bool(mod_parts) and mod_parts[-1] == "__init__.py"
    if mod_parts and mod_parts[-1].endswith(".py"):
        mod_parts = mod_parts[:-1] + [mod_parts[-1][:-3]]
    if mod_parts and mod_parts[-1] == "__init__":
        mod_parts = mod_parts[:-1]
    return ".".join(mod_parts), is_pkg


def _resolve_relative(current: str, is_pkg: bool, level: int, module: str | None) -> str:
    if level == 0:
        return module or ""
    containing = current if is_pkg else (current.rsplit(".", 1)[0] if "." in current else "")
    parts = containing.split(".") if containing else []
    up = level - 1
    if up > 0:
        parts = parts[:-up] if up <= len(parts) else []
    if module:
        parts = parts + module.split(".")
    return ".".join(parts)


# --------------------------- Python scanning -----------------------------


@dataclass
class _PyContext:
    current_module: str = ""
    is_pkg: bool = False
    alias_map: dict[str, str] = field(default_factory=dict)         # asname -> unambiguous symbol
    ambiguous_bind: dict[str, str] = field(default_factory=dict)    # local -> ambiguous symbol
    module_alias: dict[str, str] = field(default_factory=dict)      # local -> dotted module
    seed_counts: dict[str, int] = field(default_factory=dict)
    canonical_syms: frozenset[str] = frozenset()


def _flatten_attr(node: ast.Attribute) -> list[str] | None:
    """Flatten a dotted attribute chain (a.b.c) to ['a','b','c']."""
    parts: list[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return parts
    return None


def _collect_context(tree: ast.AST, rel: str) -> _PyContext:
    current, is_pkg = _module_dotted(rel)
    canon = frozenset(sym for sym, files in CANONICAL_DEF_FILES.items() if rel in files)
    ctx = _PyContext(current_module=current, is_pkg=is_pkg, canonical_syms=canon)
    # Local uses of an ambiguous symbol in its canonical file count as v4.
    for sym in canon:
        ctx.ambiguous_bind[sym] = sym
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            abs_mod = _resolve_relative(current, is_pkg, node.level, node.module)
            for alias in node.names:
                if alias.name in UNAMBIGUOUS_SYMBOLS and alias.asname:
                    ctx.alias_map[alias.asname] = alias.name
                if alias.name in AMBIGUOUS_MODULES and abs_mod in AMBIGUOUS_MODULES[alias.name]:
                    ctx.ambiguous_bind[alias.asname or alias.name] = alias.name
                    ctx.seed_counts[alias.name] = ctx.seed_counts.get(alias.name, 0) + 1
                # Treat every imported name as a potential submodule alias so
                # `from pkg import base as b; b.ExecutionContext` resolves.
                if abs_mod:
                    ctx.module_alias[alias.asname or alias.name] = f"{abs_mod}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    ctx.module_alias[alias.asname] = alias.name
    return ctx


class _PyV4Visitor(ast.NodeVisitor):
    def __init__(self, ctx: _PyContext) -> None:
        self.ctx = ctx
        self.counts: dict[str, int] = dict(ctx.seed_counts)

    def _add(self, sym: str) -> None:
        self.counts[sym] = self.counts.get(sym, 0) + 1

    def _bump(self, name: str | None) -> None:
        if name in UNAMBIGUOUS_SYMBOLS:
            self._add(name)

    def _bump_name(self, name: str) -> None:
        if name in UNAMBIGUOUS_SYMBOLS:
            self._add(name)
        elif name in self.ctx.alias_map:
            self._add(self.ctx.alias_map[name])
        elif name in self.ctx.ambiguous_bind:
            self._add(self.ctx.ambiguous_bind[name])

    def _bump_module(self, module: str | None) -> bool:
        if not module:
            return False
        for frag in PYTHON_V4_MODULES:
            if module == frag or module.startswith(frag + "."):
                self._add(f"import:{frag}")
                return True
        return False

    def _bump_semantic_string(self, raw: str) -> None:
        t = raw.strip()
        if t in UNAMBIGUOUS_SYMBOLS:
            self._add(t)
            return
        if "\n" in raw:
            for symbol in UNAMBIGUOUS_SYMBOLS:
                if re.search(rf"\b{re.escape(symbol)}\b", raw):
                    self._add(symbol)
        if not IDENT_PATH_RE.match(t) or "." not in t:
            return
        mod, _, last = t.rpartition(".")
        if last in UNAMBIGUOUS_SYMBOLS:
            self._add(last)
        elif last in AMBIGUOUS_MODULES and mod in AMBIGUOUS_MODULES[last]:
            self._add(last)
        else:
            self._bump_module(t)

    def visit_Name(self, node: ast.Name) -> None:
        self._bump_name(node.id)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._bump(node.attr)
        self._bump_qualified_attribute(node)
        self.generic_visit(node)

    def _bump_qualified_attribute(self, node: ast.Attribute) -> None:
        parts = _flatten_attr(node)
        if not parts or len(parts) < 2:
            return
        if parts[0] in self.ctx.module_alias:
            resolved = self.ctx.module_alias[parts[0]].split(".") + parts[1:]
        else:
            resolved = parts
        symbol = resolved[-1]
        module = ".".join(resolved[:-1])
        if symbol in AMBIGUOUS_MODULES and module in AMBIGUOUS_MODULES[symbol]:
            self._add(symbol)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._bump(node.name)
        if node.name in self.ctx.canonical_syms:
            self._add(node.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._bump(node.name)
        if node.returns is not None:
            self._bump_compound_annotation(node.returns)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._bump(node.name)
        if node.returns is not None:
            self._bump_compound_annotation(node.returns)
        self.generic_visit(node)

    def visit_arg(self, node: ast.arg) -> None:
        self._bump(node.arg)
        if node.annotation is not None:
            self._bump_compound_annotation(node.annotation)
        self.generic_visit(node)

    def visit_keyword(self, node: ast.keyword) -> None:
        self._bump(node.arg)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._bump_compound_annotation(node.annotation)
        self.generic_visit(node)

    def _bump_compound_annotation(self, node: ast.expr) -> None:
        # Only compound forward-refs like "list[GovernancePolicy]" are handled
        # here; simple "GovernancePolicy" strings are counted by visit_Constant.
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            return
        text = node.value.strip()
        if IDENT_PATH_RE.match(text):
            return
        try:
            sub = ast.parse(text, mode="eval")
        except SyntaxError:
            return
        for inner in ast.walk(sub):
            if isinstance(inner, ast.Name):
                self._bump_name(inner.id)
            elif isinstance(inner, ast.Attribute):
                self._bump(inner.attr)
                self._bump_qualified_attribute(inner)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        abs_mod = _resolve_relative(
            self.ctx.current_module, self.ctx.is_pkg, node.level, node.module
        )
        matched = self._bump_module(abs_mod)
        for alias in node.names:
            self._bump(alias.name)
            if not matched:
                combined = f"{abs_mod}.{alias.name}" if abs_mod else alias.name
                self._bump_module(combined)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._bump_module(alias.name)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self._bump_semantic_string(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        if func_name == "AgtRuntime":
            legacy_keywords = {
                "policies",
                "policy",
                "name",
                "blocked_patterns",
                "allowed_tools",
                "max_tokens",
                "max_tool_calls",
                "require_human_approval",
                "confidence_threshold",
            }
            keyword_names = {keyword.arg for keyword in node.keywords}
            if not node.args or keyword_names.intersection(legacy_keywords):
                self._add("v4_agt_runtime_constructor")
        self.generic_visit(node)


def _scan_python(path: Path, text: str, rel: str) -> FileHits:
    hits = FileHits(path=path)
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        hits.parse_error = f"{rel}: {exc}"
        return hits
    visitor = _PyV4Visitor(_collect_context(tree, rel))
    visitor.visit(tree)
    hits.counts = visitor.counts
    strings = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    rule_document_keys = ("rules", "condition", "operator", "action")
    multiline_rule_document = any(
        all(
            re.search(rf"(?m)^\s*(?:-\s*)?{key}\s*:", value)
            for key in rule_document_keys
        )
        for value in strings
    )
    embedded_policy_document = any(
        "\n" in value and _is_v4_policy_document("embedded.yaml", value)
        for value in strings
    )
    policy_named_class = any(
        isinstance(node, ast.ClassDef) and "Policy" in node.name
        for node in ast.walk(tree)
    )
    intent_fields = {
        "blocked_patterns",
        "allowed_tools",
        "blocked_tools",
        "max_tokens",
        "rate_limit",
    }
    pattern_modes = {"substring", "regex", "glob"}
    if (
        policy_named_class
        and "blocked_patterns" in strings
        and strings.intersection({"allowed_tools", "blocked_tools"})
        and strings.intersection({"max_tokens", "rate_limit"})
        and len(strings.intersection(pattern_modes)) >= 2
        and len(strings.intersection(intent_fields)) >= 3
    ):
        hits.counts["v4_intent_policy_shape"] = 1
    retained_agentmesh_policy = rel.startswith(
        "agent-governance-python/agent-mesh/src/agentmesh/governance/"
    )
    if (
        not retained_agentmesh_policy
        and (
            set(rule_document_keys).issubset(strings)
            or multiline_rule_document
            or embedded_policy_document
        )
    ):
        hits.counts["v4_rule_document_shape"] = 1
    if rel.startswith(
        "agent-governance-python/agent-os/src/agent_os/policies/"
    ):
        defined_classes = {
            node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
        }
        for name in sorted(defined_classes.intersection(V4_AGENT_OS_POLICY_CLASSES)):
            hits.counts[name] = 1
    if rel.startswith(
        "agent-governance-python/agent-sandbox/src/agent_sandbox/"
    ):
        sandbox_fields = {
            "defaults",
            "network_allowlist",
            "sandbox_mounts",
            "tool_allowlist",
        }
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = (
                node.args.posonlyargs
                + node.args.args
                + node.args.kwonlyargs
            )
            if not any(arg.arg == "policy" for arg in args):
                continue
            translated_fields = {
                call.args[1].value
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "getattr"
                and len(call.args) >= 2
                and isinstance(call.args[0], ast.Name)
                and call.args[0].id == "policy"
                and isinstance(call.args[1], ast.Constant)
                and isinstance(call.args[1].value, str)
            }
            if len(translated_fields.intersection(sandbox_fields)) >= 2:
                hits.counts["v4_sandbox_policy_translation"] = 1
                break
    return hits


# --------------------------- token / data scanning -----------------------


def _scan_identifier_tokens(path: Path, text: str, tokens: frozenset[str]) -> FileHits:
    hits = FileHits(path=path)
    for token in tokens:
        pattern = rf"(?<![A-Za-z0-9_$]){re.escape(token)}(?![A-Za-z0-9_$])"
        n = len(re.findall(pattern, text))
        if n:
            hits.counts[token] = n
    return hits


def _scan_substring_tokens(path: Path, text: str, tokens: frozenset[str]) -> FileHits:
    hits = FileHits(path=path)
    for token in tokens:
        n = len(re.findall(re.escape(token), text))
        if n:
            hits.counts[token] = n
    return hits


def _scan_doc(path: Path, text: str) -> FileHits:
    """Scan docs, qualifying ambiguous names by their v4 module context."""
    hits = _scan_substring_tokens(path, text, DOC_TOKENS)
    qualified_patterns: dict[str, tuple[str, ...]] = {}
    for symbol, modules in AMBIGUOUS_MODULES.items():
        patterns: list[str] = []
        for module in modules:
            escaped = re.escape(module)
            patterns.extend(
                (
                    rf"\b{escaped}\.{re.escape(symbol)}\b",
                    rf"\bfrom\s+{escaped}\s+import[^\n]*\b{re.escape(symbol)}\b",
                )
            )
        qualified_patterns[symbol] = tuple(patterns)
    for symbol, patterns in qualified_patterns.items():
        count = sum(len(re.findall(pattern, text)) for pattern in patterns)
        if count:
            hits.counts[symbol] = count
    legacy_runtime_patterns = {
        "v4_agt_runtime_constructor": (
            r"\bAgtRuntime\s*\(\s*\)",
            r"\bAgtRuntime\s*\(\s*policies\s*=",
            r"\bAgtRuntime\s*\([^)]*\bblocked_patterns\s*=",
            r"\bAgtRuntime\s*\([^)]*\ballowed_tools\s*=",
        ),
        "v4_pattern_enum": (
            r"\bPolicyEvaluation\.(?:SUBSTRING|REGEX|GLOB)\b",
        ),
        "v4_policy_model_shape": (
            r"\bPolicyCondition\b[\s\S]{0,1000}\bPolicyOperator\b",
            r"\bPolicyDefaults\b[\s\S]{0,1000}\bPolicyRule\b",
        ),
    }
    for marker, patterns in legacy_runtime_patterns.items():
        count = sum(len(re.findall(pattern, text)) for pattern in patterns)
        if count:
            hits.counts[marker] = count
    fenced_data = re.findall(
        r"```(?:yaml|yml|json)\s*\n(.*?)```",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if any(_is_v4_policy_document("fenced.yaml", block) for block in fenced_data):
        hits.counts["v4_policy_document_fence"] = 1
    return hits


def _yaml_top_level_keys(text: str) -> set[str]:
    return set(re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_-]*)\s*:", text))


def _yaml_block(text: str, key: str) -> str:
    """Return one top-level YAML mapping block without parsing arbitrary YAML."""
    lines = text.splitlines()
    start = None
    initial = ""
    for index, line in enumerate(lines):
        match = re.match(rf"^{re.escape(key)}\s*:(.*)$", line)
        if match:
            start = index + 1
            initial = match.group(1)
            break
    if start is None:
        return ""
    block = [initial]
    for line in lines[start:]:
        if line and not line[0].isspace() and re.match(
            r"^[A-Za-z_][A-Za-z0-9_-]*\s*:", line
        ):
            break
        block.append(line)
    return "\n".join(block)


def _mapping_has_key(text: str, key: str) -> bool:
    """Match a key inside a YAML/JSON mapping fragment."""
    return bool(re.search(rf'(?m)(?:^|[\s{{,"])({re.escape(key)})["\']?\s*:', text))


def _is_v4_policy_document(rel: str, text: str) -> bool:
    """Detect an agent_os v4 PolicyDocument, excluding ACS, Kubernetes, and the
    look-alike AgentMesh trust-rule schema.

    A bare ``rules:`` block is shared with AgentMesh trust policies
    (``condition: {field: trust_score, ...}``), so detection requires a
    v4-distinctive PolicyDocument field rather than shape alone. This favors
    precision, because a false positive can never be removed and would block
    the phase 6 zero gate. The authoritative per-file v4 policy list is built
    from the loader in phase 4.
    """
    parsed_json: dict | None = None
    if rel.endswith(".json"):
        try:
            candidate = json.loads(text)
            if isinstance(candidate, dict):
                parsed_json = candidate
        except json.JSONDecodeError:
            parsed_json = None

    top_keys = set(parsed_json) if parsed_json is not None else _yaml_top_level_keys(text)

    if "agent_control_specification_version" in top_keys:
        return False
    if "apiVersion" in top_keys:
        return False
    if rel.endswith("policy_schema.json"):
        return True
    if '"title": "Agent-OS Policy Document"' in text or "policy-schema" in text:
        return True
    # v4-distinctive PolicyDocument fields (not present in trust-rule policies).
    if top_keys.intersection(
        {"network_allowlist", "tool_allowlist", "a2a_conversation_policy", "sandbox_mounts"}
    ):
        return True
    if "rules" in top_keys and top_keys.intersection({"inherit", "scope"}):
        return True
    if "rules" in top_keys:
        if parsed_json is not None:
            rules = parsed_json.get("rules")
            if isinstance(rules, list) and any(
                isinstance(rule, dict)
                and {"condition", "action", "message"}.issubset(rule)
                for rule in rules
            ):
                return True
        elif (
            re.search(r"(?m)^\s{2,}(?:-\s*)?condition\s*:", text)
            and re.search(r"(?m)^\s{2,}action\s*:", text)
            and re.search(r"(?m)^\s{2,}message\s*:", text)
        ):
            return True
        if re.search(r"(?m)^\s{2,}(?:-\s*)?trigger\s*:", text) and (
            re.search(r"(?m)^\s{2,}check\s*:", text)
            or re.search(r"(?m)^\s{2,}action\s*:", text)
        ):
            return True
    defaults = (
        parsed_json.get("defaults")
        if parsed_json is not None
        else _yaml_block(text, "defaults")
    )
    default_keys = {
        "max_tokens",
        "max_tool_calls",
        "confidence_threshold",
        "max_cpu",
        "max_memory_mb",
        "timeout_seconds",
        "network_default",
    }
    if isinstance(defaults, dict) and set(defaults).intersection(default_keys):
        return True
    if isinstance(defaults, str) and any(
        _mapping_has_key(defaults, key) for key in default_keys
    ):
        return True
    if re.search(r"\b(GovernancePolicy|PolicyDocument)\b", text):
        return True
    return False


def _scan_policy_data(path: Path, text: str, rel: str) -> FileHits:
    hits = FileHits(path=path)
    if not _is_v4_policy_document(rel, text):
        return hits
    hits.counts["v4_policy_document_file"] = 1
    for token in ("GovernancePolicy", "PolicyDocument"):
        n = len(re.findall(re.escape(token), text))
        if n:
            hits.counts[token] = n
    return hits


# --------------------------- reading -------------------------------------


def _read_python(path: Path, rel: str) -> tuple[str | None, str | None]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, f"{rel}: read error {exc}"
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        return data.decode(encoding), None
    except (SyntaxError, UnicodeDecodeError, LookupError) as exc:
        return None, f"{rel}: decode error {exc}"


def _read_text(path: Path, rel: str) -> tuple[str | None, str | None]:
    try:
        return path.read_text(encoding="utf-8-sig"), None
    except (UnicodeDecodeError, OSError) as exc:
        return None, f"{rel}: decode error {exc}"


def scan_repo() -> list[FileHits]:
    results: list[FileHits] = []
    for path in sorted(REPO_ROOT.rglob("*")):
        if not path.is_file():
            continue
        scanner = decide_scanner(path)
        if scanner is None:
            continue
        rel = _rel(path)
        if scanner == "python":
            text, err = _read_python(path, rel)
        else:
            text, err = _read_text(path, rel)
        if err is not None:
            results.append(FileHits(path=path, parse_error=err))
            continue
        if scanner == "python":
            hits = _scan_python(path, text, rel)
        elif scanner == "tokens":
            hits = _scan_identifier_tokens(path, text, NONPY_V4_TOKENS)
        elif scanner == "governance_yaml":
            hits = _scan_substring_tokens(path, text, DOC_TOKENS)
            hits.counts["governance_yaml_file"] = hits.counts.get("governance_yaml_file", 0) + 1
        elif scanner == "policy_data":
            hits = _scan_policy_data(path, text, rel)
        else:  # spec / markdown
            hits = _scan_doc(path, text)
        if hits.total or hits.parse_error:
            results.append(hits)
    return results


# --------------------------- inventory + ratchet -------------------------


def build_inventory(hits: Iterable[FileHits]) -> dict:
    files: dict[str, dict[str, int]] = {}
    allowed_files: dict[str, dict[str, int]] = {}
    parse_errors: list[str] = []
    for fh in hits:
        rel = _rel(fh.path)
        if fh.parse_error:
            parse_errors.append(fh.parse_error)
        if not fh.counts:
            continue
        bucket = allowed_files if _in_allowed_root(rel) else files
        bucket[rel] = dict(sorted(fh.counts.items()))

    package_totals: dict[str, int] = {}
    for rel, syms in files.items():
        pkg = _package_root(REPO_ROOT / rel)
        package_totals[pkg] = package_totals.get(pkg, 0) + sum(syms.values())

    return {
        "grand_total": sum(sum(s.values()) for s in files.values()),
        "package_totals": dict(sorted(package_totals.items())),
        "files": dict(sorted(files.items())),
        "allowed_migration_files": dict(sorted(allowed_files.items())),
        "parse_errors": sorted(parse_errors),
    }


def _load_baseline() -> dict:
    if not BASELINE_PATH.is_file():
        raise SystemExit(
            f"no baseline at {_rel(BASELINE_PATH)}; run --update-baseline first"
        )
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


def check_ratchet(inventory: dict, baseline: dict) -> list[str]:
    """Return violation messages. v4 may only stay equal or drop.

    Enforced per file and per symbol. No non-migration file may acquire a v4
    marker it did not already carry, and no symbol count may rise. Parse or
    decode failures fail closed.
    """
    violations: list[str] = []

    for err in inventory.get("parse_errors", []):
        violations.append(f"unreadable/unparseable file (fails closed): {err}")

    base_files: dict[str, dict[str, int]] = baseline.get("files", {})
    cur_files: dict[str, dict[str, int]] = inventory["files"]

    for rel, cur_syms in cur_files.items():
        base_syms = base_files.get(rel)
        if base_syms is None:
            violations.append(f"{rel}: new file acquired v4 markers {dict(cur_syms)}")
            continue
        for sym, n in cur_syms.items():
            if n > base_syms.get(sym, 0):
                violations.append(f"{rel}: {sym} rose {base_syms.get(sym, 0)} -> {n}")
    if inventory["grand_total"] > baseline.get("grand_total", 0):
        violations.append(
            f"grand total v4 usage rose "
            f"{baseline.get('grand_total', 0)} -> {inventory['grand_total']}"
        )
    return violations


def _print_report(inventory: dict) -> None:
    print(f"v4 policy-language inventory (grand total {inventory['grand_total']})")
    print("=" * 68)
    for pkg, total in inventory["package_totals"].items():
        print(f"{total:>5}  {pkg}")
    if inventory.get("parse_errors"):
        print("-" * 68)
        print("parse/decode errors (fail the gate):")
        for err in inventory["parse_errors"]:
            print(f"        {err}")
    allowed = inventory["allowed_migration_files"]
    if allowed:
        allowed_total = sum(sum(s.values()) for s in allowed.values())
        print("-" * 68)
        print(f"allowed migration files (not ratcheted, total {allowed_total}):")
        for rel in allowed:
            print(f"        {sum(allowed[rel].values()):>4}  {rel}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument(
        "--allow-baseline-increase",
        action="store_true",
        help="permit --update-baseline to raise counts (scanner-semantics changes only)",
    )
    parser.add_argument("--report", action="store_true", help="print inventory, no gate")
    parser.add_argument("--json", action="store_true", help="emit machine-readable inventory")
    args = parser.parse_args(argv)

    inventory = build_inventory(scan_repo())

    if args.json:
        print(json.dumps(inventory, indent=2))
        return 0
    if args.update_baseline:
        if BASELINE_PATH.is_file() and not args.allow_baseline_increase:
            prior = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
            regressions = check_ratchet(inventory, prior)
            if regressions:
                print("refusing to bless a v4 increase; pass --allow-baseline-increase only")
                print("for intentional scanner-semantics expansion. Offending changes:")
                for r in regressions:
                    print(f"  - {r}")
                return 1
        BASELINE_PATH.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
        print(f"wrote baseline to {_rel(BASELINE_PATH)} (grand total {inventory['grand_total']})")
        return 0
    if args.report:
        _print_report(inventory)
        return 0

    violations = check_ratchet(inventory, _load_baseline())
    if violations:
        print("v4 removal ratchet FAILED; v4 policy usage may only decrease:")
        for v in violations:
            print(f"  - {v}")
        print("\nRun scripts/check_v4_ratchet.py --report to inspect the inventory.")
        return 1
    print(f"v4 removal ratchet OK (grand total {inventory['grand_total']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
