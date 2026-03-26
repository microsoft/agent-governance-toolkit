#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pre-commit hook: detect unregistered PyPI package names in pip install commands.

Scans staged files for `pip install <name>` where <name> is not a known
registered package. Prevents dependency confusion attacks.

Usage:
    # Install as pre-commit hook
    cp scripts/check_dependency_confusion.py .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit

    # Or run manually
    python scripts/check_dependency_confusion.py [files...]
"""

import re
import subprocess
import sys

# Known registered PyPI package names for this project
REGISTERED_PACKAGES = {
    # Core packages (on PyPI)
    "agent-os-kernel",
    "agentmesh-platform",
    "agent-hypervisor",
    "agent-runtime",
    "agent-sre",
    "agent-governance-toolkit",
    "agent-lightning",
    "agentmesh-marketplace",
    # Common dependencies
    "pydantic", "pyyaml", "cryptography", "pynacl", "httpx", "aiohttp",
    "fastapi", "uvicorn", "structlog", "click", "rich", "numpy", "scipy",
    "pytest", "pytest-asyncio", "pytest-cov", "ruff", "mypy", "build",
    "openai", "anthropic", "langchain", "langchain-core", "crewai",
    "redis", "sqlalchemy", "asyncpg", "chromadb", "pinecone-client",
    "sentence-transformers", "prometheus-client", "opentelemetry-api",
    "opentelemetry-sdk", "fhir.resources", "hl7apy", "zenpy", "freshdesk",
    "google-adk", "safety", "jupyter", "vitest", "tsup", "typescript",
    # With extras (base name is what matters)
}

# Patterns that are always safe
SAFE_PATTERNS = {
    "-e", "--editable", "-r", "--requirement", "--upgrade", "--no-cache-dir",
    "--quiet", "--require-hashes", "--hash", ".", "..", "../..",
}

PIP_INSTALL_RE = re.compile(
    r'pip\s+install\s+(.+?)(?:\s*\\?\s*$|(?=\s*&&|\s*\||\s*;|\s*#))',
    re.MULTILINE,
)


def extract_package_names(install_args: str) -> list[str]:
    """Extract package names from a pip install argument string."""
    packages = []
    for token in install_args.split():
        # Skip flags
        if token.startswith("-") or token in SAFE_PATTERNS:
            continue
        if token.startswith((".", "/", "\\", "http", "git+")):
            continue
        # Strip extras: package[extra] -> package
        base = re.sub(r'\[.*\]', '', token)
        # Strip version specifiers: package>=1.0 -> package
        base = re.split(r'[><=!~]', base)[0]
        # Strip markdown/quote artifacts
        base = base.strip('`"\'(){}')
        if base and base not in SAFE_PATTERNS:
            packages.append(base)
    return packages


def check_file(filepath: str) -> list[str]:
    """Check a file for potentially unregistered pip install targets."""
    findings = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return findings

    for match in PIP_INSTALL_RE.finditer(content):
        line_num = content[:match.start()].count("\n") + 1
        packages = extract_package_names(match.group(1))
        for pkg in packages:
            if pkg.lower() not in {p.lower() for p in REGISTERED_PACKAGES}:
                findings.append(
                    f"  {filepath}:{line_num}: "
                    f"'{pkg}' may not be registered on PyPI"
                )
    return findings


def main() -> int:
    # Get files to check
    if len(sys.argv) > 1:
        files = sys.argv[1:]
    else:
        # Pre-commit mode: check staged files
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True,
        )
        files = [
            f for f in result.stdout.strip().split("\n")
            if f.endswith((".md", ".py", ".ts", ".txt", ".yaml", ".yml", ".ipynb", ".svg"))
        ]

    all_findings = []
    for f in files:
        all_findings.extend(check_file(f))

    if all_findings:
        print("⚠️  Potential dependency confusion detected:")
        print()
        for finding in all_findings:
            print(finding)
        print()
        print("If the package IS registered on PyPI, add it to REGISTERED_PACKAGES")
        print("in scripts/check_dependency_confusion.py")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
