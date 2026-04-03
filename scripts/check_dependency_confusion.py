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

import argparse
import glob
import json
import re
import subprocess
import sys

# Known registered PyPI package names for this project
REGISTERED_PACKAGES = {
    # Core packages (on PyPI)
    "agent-os-kernel",
    "agentmesh-platform",
    "agent-hypervisor",
    "agentmesh-runtime",
    "agent-sre",
    "agent-governance-toolkit",
    "agentmesh-lightning",
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
    # Dashboard / visualization (used in examples)
    "streamlit", "plotly", "pandas", "networkx", "matplotlib", "pyvis",
    # Async / caching (used in examples)
    "aioredis", "aiofiles", "aiosqlite",
    # Document processing / NLP (used in examples)
    "pypdf", "python-docx", "pdfplumber", "beautifulsoup4", "lxml",
    "spacy", "nltk", "tiktoken", "scikit-learn",
    # Dev tools
    "black", "flake8", "types-PyYAML",
    # Infrastructure / runtime (used in examples)
    "docker", "huggingface-hub", "python-dotenv", "python-dateutil",
    "python-multipart", "python-json-logger", "langchain-openai",
    # Slack / messaging
    "slack-sdk", "slack-bolt",
    # Telemetry
    "opentelemetry-instrumentation-fastapi", "opentelemetry-exporter-otlp",
    "opentelemetry-instrumentation-httpx", "opentelemetry-instrumentation-asyncio",
    # pyproject.toml optional-dependency group names (not real packages)
    "dev", "cli", "all", "server", "storage", "observability",
    "django", "websocket", "websockets", "grpc", "grpcio", "grpcio-tools",
    "agent-os", "test", "docs", "full", "api", "otel", "protocols",
    "runtime", "sandbox", "sre", "hypervisor", "iatp", "keywords",
    "llm", "mcp", "hf", "huggingface", "blockchain", "web3",
    "multi-agent", "broker-agnostic", "pubsub", "kafka", "rabbitmq",
    "sql", "async", "nexus", "caas-core", "message-bus",
    "ai-agents", "amb", "eval_type_backport",
    # Integration packages / real PyPI packages used as deps
    "hypothesis", "fakeredis", "langflow", "langgraph",
    "agentmesh", "pydantic-ai", "haystack", "respx",
    "langfuse", "arize", "llamaindex", "braintrust", "helicone",
    "datadog", "langsmith", "wandb", "mlflow", "agentops",
    "typer", "jsonschema", "anyio", "pre-commit", "import-linter",
    "mkdocs", "mkdocs-material", "mkdocstrings", "datasets", "sqlglot",
    "aio-pika", "aiokafka",
    # Internal module references
    "inter-agent-trust-protocol", "agent-control-plane", "cmvk",
    "agent-tool-registry", "cedar", "opa", "huggingface_hub",
    # Internal cross-package references (local-only, NOT on PyPI)
    # These are flagged as HIGH RISK if found in requirements.txt with version pins
    # instead of path references. See dependency confusion attack vector.
    "agent-primitives", "emk",
    # With extras (base name is what matters)
}

# Local-only packages that should NEVER appear with version pins in
# requirements.txt (they must use path references like -e ../primitives)
LOCAL_ONLY_PACKAGES = {"agent-primitives", "emk"}

# Known npm packages for this project
REGISTERED_NPM_PACKAGES = {
    "@microsoft/agent-os-kernel", "@microsoft/agentmesh-mcp-proxy",
    "@microsoft/agentmesh-api", "@microsoft/agent-os-cursor",
    "@microsoft/agentmesh-mastra", "@microsoft/agentmesh-copilot-governance",
    "@microsoft/agent-os-copilot-extension", "@microsoft/agentos-mcp-server",
    "@microsoft/agent-os-vscode",
    # Common deps
    "typescript", "tsup", "vitest", "express", "zod", "@mastra/core",
    "@modelcontextprotocol/sdk", "ws", "commander", "chalk",
    "@anthropic-ai/sdk", "@types/node", "@types/ws", "@types/express",
    # Common npm dev dependencies
    "eslint", "@typescript-eslint/parser", "@typescript-eslint/eslint-plugin",
    "ts-jest", "@types/jest", "jest", "rimraf", "prettier",
    "axios", "@types/vscode", "@vscode/vsce", "webpack", "webpack-cli",
    "ts-node", "nodemon", "concurrently", "dotenv",
    "esbuild", "@esbuild/linux-x64", "@esbuild/darwin-arm64",
    # npm deps from extensions/copilot
    "@octokit/webhooks", "path-to-regexp", "winston",
    # npm deps from extensions/chrome
    "react", "react-dom", "webextension-polyfill",
    "@types/chrome", "@types/react", "@types/react-dom",
    "copy-webpack-plugin", "css-loader", "eslint-plugin-react",
    "eslint-plugin-react-hooks", "html-webpack-plugin", "style-loader",
    "ts-loader",
    # npm deps from extensions/mcp-server
    "uuid", "yaml", "zod", "@types/uuid", "@vitest/coverage-v8",
    # npm deps from mcp-proxy
    "crypto-js",
    # npm deps from sdks/typescript
    "js-yaml", "@noble/ed25519",
}

# Known Cargo crate names
REGISTERED_CARGO_PACKAGES = {
    "serde", "serde_json", "serde_yaml", "sha2", "ed25519-dalek",
    "rand", "thiserror", "tempfile", "agentmesh",
}

# Patterns that are always safe (not package names)
SAFE_PATTERNS = {
    "-e", "--editable", "-r", "--requirement", "--upgrade", "--no-cache-dir",
    "--quiet", "--require-hashes", "--hash", ".", "..", "../..",
    "pip", "install", "%pip",
}

PIP_INSTALL_RE = re.compile(
    r'(?:%?pip)\s+install\s+(.+?)(?:\s*\\?\s*$|(?=\s*&&|\s*\||\s*;|\s*#))',
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
        # Skip tokens that look like code, not package names
        if any(c in token for c in ('(', ')', '=', '"', "'", ":")):
            continue
        # Strip extras: package[extra] -> package
        base = re.sub(r'\[.*\]', '', token)
        # Strip version specifiers: package>=1.0 -> package
        base = re.split(r'[><=!~]', base)[0]
        # Strip markdown/quote artifacts
        base = base.strip('`"\'(){}%')
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


def check_requirements_file(filepath: str) -> list[str]:
    """Check a requirements*.txt file for unregistered package names."""
    findings = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return findings

    registered_lower = {p.lower() for p in REGISTERED_PACKAGES}
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if line.startswith((".", "/", "\\", "http", "git+")):
            continue
        # Strip extras and version specifiers
        base = re.sub(r'\[.*\]', '', line)
        base = re.split(r'[><=!~;@\s]', base)[0].strip()
        if base and base.lower() not in registered_lower:
            findings.append(
                f"  {filepath}:{line_num}: "
                f"'{base}' may not be registered on PyPI"
            )
    return findings


def check_notebook(filepath: str) -> list[str]:
    """Check a Jupyter notebook for pip install of unregistered packages."""
    findings = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            nb = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return findings

    registered_lower = {p.lower() for p in REGISTERED_PACKAGES}
    for cell in nb.get("cells", []):
        for line in cell.get("source", []):
            if "pip install" in line and not line.strip().startswith("#"):
                packages = extract_package_names(line)
                for pkg in packages:
                    if pkg.lower() not in registered_lower:
                        findings.append(
                            f"  {filepath}: "
                            f"'{pkg}' may not be registered on PyPI"
                        )
    return findings


def check_pyproject_toml(filepath: str) -> list[str]:
    """Check a pyproject.toml for unregistered package dependencies."""
    findings = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return findings

    registered_lower = {p.lower() for p in REGISTERED_PACKAGES}
    # Match dependency lines like: "package>=1.0" or "package[extra]>=1.0,<2.0"
    dep_re = re.compile(r'^[\s"]*([a-zA-Z0-9_-]+)', re.MULTILINE)
    in_deps = False
    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("[project.dependencies]") or \
           stripped.startswith("[project.optional-dependencies"):
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
            continue
        if not in_deps:
            continue
        if not stripped or stripped.startswith("#"):
            continue
        m = dep_re.match(stripped.strip('"').strip("'").strip(","))
        if m:
            pkg = m.group(1)
            if pkg.lower() not in registered_lower and pkg.lower() not in {
                "python", "requires-python",
            }:
                severity = "HIGH RISK" if pkg.lower() in {
                    p.lower() for p in LOCAL_ONLY_PACKAGES
                } else ""
                msg = f"  {filepath}:{line_num}: '{pkg}' may not be registered on PyPI"
                if severity:
                    msg += f" [{severity}: local-only package]"
                findings.append(msg)
    return findings


def check_package_json(filepath: str) -> list[str]:
    """Check a package.json for unregistered npm package dependencies."""
    findings = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return findings

    registered_lower = {p.lower() for p in REGISTERED_NPM_PACKAGES}
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for pkg in data.get(section, {}):
            if pkg.lower() not in registered_lower:
                findings.append(
                    f"  {filepath}: npm '{pkg}' ({section}) may not be registered"
                )
    return findings


def check_cargo_toml(filepath: str) -> list[str]:
    """Check a Cargo.toml for unregistered crate dependencies."""
    findings = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return findings

    registered_lower = {p.lower() for p in REGISTERED_CARGO_PACKAGES}
    in_deps = False
    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped in ("[dependencies]", "[dev-dependencies]",
                        "[build-dependencies]"):
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
            continue
        if not in_deps or not stripped or stripped.startswith("#"):
            continue
        m = re.match(r'^([a-zA-Z0-9_-]+)\s*=', stripped)
        if m:
            crate = m.group(1)
            if crate.lower() not in registered_lower:
                findings.append(
                    f"  {filepath}:{line_num}: crate '{crate}' "
                    f"may not be registered on crates.io"
                )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect unregistered PyPI package names in pip install commands.",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Also scan notebooks and requirements*.txt files; exit 1 on any violation",
    )
    parser.add_argument("files", nargs="*", help="Files to check")
    args = parser.parse_args()

    # Get files to check
    if args.files:
        files = args.files
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

    # --strict: additionally scan all notebooks, requirements, and manifest files
    if args.strict:
        for nb in glob.glob("**/*.ipynb", recursive=True):
            if "node_modules" in nb or ".ipynb_checkpoints" in nb:
                continue
            all_findings.extend(check_notebook(nb))

        for req in glob.glob("**/requirements*.txt", recursive=True):
            if "node_modules" in req:
                continue
            all_findings.extend(check_requirements_file(req))

        for pyproj in glob.glob("**/pyproject.toml", recursive=True):
            if "node_modules" in pyproj:
                continue
            all_findings.extend(check_pyproject_toml(pyproj))

        for pkgjson in glob.glob("**/package.json", recursive=True):
            if "node_modules" in pkgjson:
                continue
            all_findings.extend(check_package_json(pkgjson))

        for cargo in glob.glob("**/Cargo.toml", recursive=True):
            if "node_modules" in cargo:
                continue
            all_findings.extend(check_cargo_toml(cargo))

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
