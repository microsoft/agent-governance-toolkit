#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""CI check: ensure core packages have no unguarded vendor imports.

Scans agent_os/ and agentmesh/ core source directories for imports from
vendor frameworks (langchain, openai, anthropic, etc.) that are NOT inside
a try/except block. Exits non-zero if any are found.

Usage:
    python scripts/check_vendor_imports.py
"""

import ast
import sys
from pathlib import Path

VENDOR_MODULES = {
    "langchain", "langchain_core", "langchain_community",
    "llama_index", "crewai", "autogen",
    "openai", "anthropic", "google.generativeai", "vertexai",
    "semantic_kernel", "dify",
    "arize", "langfuse", "agentops", "braintrust",
    "wandb", "mlflow", "ddtrace", "langsmith", "helicone",
}

CORE_PATHS = [
    "agent-governance-python/agent-os/src/agent_os",
    "agent-governance-python/agent-mesh/src/agentmesh",
    "agent-governance-python/agent-hypervisor/src/hypervisor",
    "agent-governance-python/agent-sre/src/agent_sre",
    "agent-governance-python/agent-compliance/src/agent_compliance",
]

# Directories where vendor imports are expected (adapters, integrations)
ALLOWED_DIRS = {"integrations", "adapters", "examples"}


def is_vendor_import(node: ast.AST) -> str | None:
    """Return the vendor module name if this is a vendor import, else None."""
    if isinstance(node, ast.Import):
        for alias in node.names:
            root = alias.name.split(".")[0]
            if root in VENDOR_MODULES:
                return alias.name
    elif isinstance(node, ast.ImportFrom):
        if node.module:
            root = node.module.split(".")[0]
            if root in VENDOR_MODULES:
                return node.module
    return None


def is_inside_try(node: ast.AST, tree: ast.Module) -> bool:
    """Check if a node is inside a try/except block."""
    for parent in ast.walk(tree):
        if isinstance(parent, ast.Try):
            for child in ast.walk(parent):
                if child is node:
                    return True
    return False


def is_in_allowed_dir(filepath: Path) -> bool:
    """Check if file is in an integrations/adapters directory."""
    parts = filepath.parts
    return any(d in parts for d in ALLOWED_DIRS)


def check_file(filepath: Path) -> list[str]:
    """Check a single Python file for unguarded vendor imports."""
    violations = []
    try:
        source = filepath.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
    except (SyntaxError, UnicodeDecodeError):
        return []

    for node in ast.walk(tree):
        vendor = is_vendor_import(node)
        if vendor and not is_inside_try(node, tree):
            line = getattr(node, "lineno", "?")
            violations.append(f"  {filepath}:{line} — unguarded import of '{vendor}'")

    return violations


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    all_violations: list[str] = []

    for core_path in CORE_PATHS:
        full_path = repo_root / core_path
        if not full_path.exists():
            continue
        for pyfile in full_path.rglob("*.py"):
            if is_in_allowed_dir(pyfile):
                continue
            violations = check_file(pyfile)
            all_violations.extend(violations)

    if all_violations:
        print("❌ VENDOR IMPORT VIOLATIONS IN CORE PACKAGES:")
        print()
        for v in all_violations:
            print(v)
        print()
        print(f"Found {len(all_violations)} violation(s).")
        print("Fix: wrap vendor imports in try/except or move to integrations/")
        return 1

    print("✅ No unguarded vendor imports in core packages.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
