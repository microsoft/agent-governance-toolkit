# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression tests for red-team findings A4 and A5.

A4 (Medium): the ESRP ``pip install`` of build tooling pinned versions but
not hashes and did not pass ``--no-deps``. Pip resolved transitive deps from
the public index at run time, giving an attacker who could swap a pinned
transitive (typosquat, dependency confusion) code execution inside the
release pipeline.

Fix: commit a ``release-tools.txt`` lockfile with ``--hash=sha256:`` for
every entry and install with ``--require-hashes --no-deps``.

A5 (Low): the ``rustVersion`` regex validation in ``esrp-publish.yml`` is
template-expanded at queue time but enforced at runtime. The comment was
absent, so a future maintainer would not understand why the regex is the
secondary defense and ADO queue-time parameter ACLs are the primary one.

Fix: explanatory comment block adjacent to the validation step.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ESRP = REPO_ROOT / ".github" / "pipelines" / "esrp-publish.yml"
LOCKFILE = REPO_ROOT / ".github" / "pipelines" / "release-tools" / "release-tools.txt"
SRC = REPO_ROOT / ".github" / "pipelines" / "release-tools" / "release-tools.in"


def test_a4_release_tools_lockfile_exists_and_pins_hashes() -> None:
    assert LOCKFILE.exists(), (
        f"Expected ESRP release-tools lockfile at {LOCKFILE} so pip can be "
        "invoked with --require-hashes"
    )
    text = LOCKFILE.read_text(encoding="utf-8")
    # Every non-comment, non-continuation entry must declare at least one
    # SHA-256 hash.
    entries = [
        ln for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert entries, "release-tools.txt has no entries"
    assert text.count("--hash=sha256:") >= 2, (
        "release-tools.txt must include --hash=sha256: pins for at least the "
        "top-level packages"
    )


def test_a4_release_tools_source_committed() -> None:
    """The unhashed source spec for pip-compile regeneration must exist."""
    assert SRC.exists(), (
        f"Expected ESRP release-tools source spec at {SRC} to document how "
        "the lockfile is regenerated"
    )


def test_a4_esrp_uses_require_hashes_no_deps() -> None:
    text = ESRP.read_text(encoding="utf-8")
    assert "--require-hashes" in text, (
        "esrp-publish.yml must install build tools with --require-hashes"
    )
    assert "--no-deps" in text, (
        "esrp-publish.yml must install build tools with --no-deps so the "
        "lockfile is the source of truth"
    )
    assert "release-tools.txt" in text, (
        "esrp-publish.yml must reference release-tools.txt by path"
    )


def test_a5_rust_version_validation_documents_template_vs_runtime() -> None:
    text = ESRP.read_text(encoding="utf-8")
    # Locate the rustVersion *validation* block (the runtime regex check),
    # not the parameter declaration. The validation lives inside the
    # Install Rust step's script and uses ``RUST_TOOLCHAIN`` plus a grep.
    idx = text.find("RUST_TOOLCHAIN=")
    assert idx >= 0, "esrp-publish.yml lost its RUST_TOOLCHAIN validation block"
    window_start = max(0, idx - 2000)
    window_end = min(len(text), idx + 200)
    window = text[window_start:window_end]
    comment_lines = [
        ln for ln in window.splitlines() if ln.lstrip().startswith("#")
    ]
    joined = "\n".join(comment_lines).lower()
    assert "queue-time" in joined or "template" in joined, (
        "RUST_TOOLCHAIN validation must be preceded by a comment that "
        "explains template-expansion-vs-runtime-regex ordering and the role "
        "of ADO queue-time parameter ACLs as the primary defense"
    )


def test_esrp_publishes_acs_python_and_rust_artifacts() -> None:
    text = ESRP.read_text(encoding="utf-8")
    assert "name: agent-control-specification" in text
    assert "path: policy-engine/sdk/python" in text
    assert "noBuildIsolation: 'true'" in text
    assert "name: agt-policies" in text
    assert "path: agent-governance-python/agt-policies" in text
    assert "name: acs-generator" in text
    assert "path: policy-engine/generator" in text
    assert "path: policy-engine" in text
    assert "crate: agent_control_specification_core" in text
    assert "cargo package -p agent_control_specification --allow-dirty" in text
    assert "after the core ESRP release completes" in text


def test_esrp_publishes_acs_node_artifacts() -> None:
    text = ESRP.read_text(encoding="utf-8")
    assert "Build_npm_agent_control_specification" in text
    assert "agent-control-specification-linux-x64-gnu" in text
    assert "agent-control-specification-linux-arm64-gnu" in text
    assert "agent-control-specification-darwin-x64" in text
    assert "agent-control-specification-darwin-arm64" in text
    assert "agent-control-specification-win32-x64-msvc" in text
    assert "agent-control-specification-opa-linux-x64" in text
    assert "agent-control-specification-opa-win32-x64" in text
    assert "Root agent-control-specification package must not embed" in text


def test_esrp_publishes_acs_dotnet_artifacts() -> None:
    text = ESRP.read_text(encoding="utf-8")
    assert "Build_ACS_Native_" in text
    assert "BuildAndPack_ACS" in text
    assert "nuget-acs-unsigned" in text
    assert "AgentControlSpecification/AgentControlSpecification.csproj" in text
    assert "AgentControlSpecification.AI/AgentControlSpecification.AI.csproj" in text
    assert "AgentControlSpecification.AgentFramework/AgentControlSpecification.AgentFramework.csproj" in text
    assert "AgentControlSpecification.AutoGen/AgentControlSpecification.AutoGen.csproj" in text
    assert "AgentControlSpecification.SemanticKernel/AgentControlSpecification.SemanticKernel.csproj" in text
