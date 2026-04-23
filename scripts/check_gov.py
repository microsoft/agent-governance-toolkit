#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governance stack installation checker.

Validates that the Agent Governance Toolkit core packages and
critical dependencies are installed and importable.

Usage:
    python scripts/check_gov.py
"""

import sys


def _check(label: str, import_path: str) -> bool:
    """Try to import a module and report success/failure."""
    try:
        mod = __import__(import_path)
        version = getattr(mod, "__version__", "ok")
        print(f"  ✅  {label:.<40s} {version}")
        return True
    except ImportError:
        print(f"  ❌  {label:.<40s} not installed")
        return False


def verify_installation() -> int:
    """Check all governance toolkit packages and critical dependencies."""
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║   Agent Governance Toolkit — Installation Check     ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    results: list[bool] = []

    # Core packages
    print("Core Packages:")
    results.append(_check("agent-os-kernel", "agent_os"))
    results.append(_check("agentmesh-platform", "agentmesh"))
    results.append(_check("agent-governance-toolkit", "agent_compliance"))
    results.append(_check("agent-sre", "agent_sre"))
    print()

    # Critical security dependencies
    print("Security Dependencies:")
    results.append(_check("cryptography", "cryptography"))
    results.append(_check("pynacl", "nacl"))
    print()

    # AI/ML dependencies
    print("AI/ML Dependencies:")
    _check("langchain-core", "langchain_core")  # optional
    _check("openai", "openai")  # optional
    print()

    # Governance CLI
    print("Governance CLI:")
    try:
        from agent_compliance.cli.main import cmd_verify  # noqa: F401
        print("  ✅  agt verify............ available")
        results.append(True)
    except ImportError:
        print("  ❌  agt verify............ not available")
        results.append(False)
    print()

    passed = sum(results)
    total = len(results)
    status = "READY" if all(results) else "INCOMPLETE"

    print(f"Result: {passed}/{total} checks passed — {status}")
    print()

    if not all(results):
        print("To install missing packages:")
        print("  pip install agent-governance-toolkit[full]")
        print()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(verify_installation())
