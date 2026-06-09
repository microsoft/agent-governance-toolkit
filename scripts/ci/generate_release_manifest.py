# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Generate a machine-readable AGT release manifest.

The manifest is intentionally static and reviewable. It records every artifact
family AGT expects to release, whether the current GitHub workflow publishes it
directly, and which compatibility names remain during AAIF contribution
finalization.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


PYPI_PACKAGES = [
    ("agent-governance-toolkit-core", "agent-governance-python/agent-governance-toolkit-core", "github-actions"),
    ("agent-governance-toolkit-integrations", "agent-governance-python/agent-governance-toolkit-integrations", "github-actions"),
    ("agent-governance-toolkit-cli", "agent-governance-python/agent-governance-toolkit-cli", "github-actions"),
    ("agent-governance-toolkit-protocols", "agent-governance-python/agent-governance-toolkit-protocols", "github-actions"),
    ("agent-governance-toolkit", "agent-governance-python/agent-compliance", "github-actions"),
    ("agent-discovery", "agent-governance-python/agent-discovery", "github-actions"),
    ("agent-lightning", "agent-governance-python/agent-lightning", "github-actions"),
    ("agent-marketplace", "agent-governance-python/agent-marketplace", "github-actions"),
    ("agent-rag-governance", "agent-governance-python/agent-rag-governance", "github-actions"),
    ("agt-sandbox", "agent-governance-python/agent-sandbox", "github-actions"),
    ("agent-control-specification", "policy-engine/sdk/python", "github-actions"),
    ("agt-policies", "agent-governance-python/agt-policies", "github-actions"),
    ("acs-generator", "policy-engine/generator", "github-actions"),
]

NPM_PACKAGES = [
    ("agentmesh-copilot-governance", "agent-governance-python/agentmesh-integrations/copilot-governance", "github-actions"),
    ("agentmesh-mastra", "agent-governance-python/agentmesh-integrations/mastra-agentmesh", "github-actions"),
    ("agentmesh-api", "agent-governance-python/agent-mesh/services/api", "github-actions"),
    ("npm-agentmesh-mcp-proxy", "agent-governance-python/agent-mesh/packages/mcp-proxy", "github-actions"),
    ("agent-governance-copilot-cli", "agent-governance-copilot-cli", "github-actions"),
    ("agent-governance-claude-code", "agent-governance-claude-code", "github-actions"),
    ("agent-governance-opencode", "agent-governance-opencode", "github-actions"),
    ("agent-governance-antigravity-cli", "agent-governance-antigravity-cli", "github-actions"),
    ("agentmesh-sdk", "agent-governance-typescript", "github-actions"),
    ("agent-os-copilot-extension", "agent-governance-python/agent-os/extensions/copilot", "github-actions"),
    ("agentos-mcp-server", "agent-governance-python/agent-os/extensions/mcp-server", "github-actions"),
    ("agent-control-specification", "policy-engine/sdk/node", "policy-engine-ci-pack-only"),
    ("agent-control-specification-native-packages", "policy-engine/sdk/node/npm", "policy-engine-ci-pack-only"),
    ("agent-control-specification-opa-packages", "policy-engine/sdk/node/npm", "policy-engine-ci-pack-only"),
]

NUGET_PACKAGES = [
    ("Microsoft.AgentGovernance", "agent-governance-dotnet/src/AgentGovernance", "github-actions"),
    (
        "Microsoft.AgentGovernance.Extensions.ModelContextProtocol",
        "agent-governance-dotnet/src/AgentGovernance.Extensions.ModelContextProtocol",
        "github-actions",
    ),
    (
        "Microsoft.AgentGovernance.Extensions.Microsoft.Agents",
        "agent-governance-dotnet/src/AgentGovernance.Extensions.Microsoft.Agents",
        "github-actions",
    ),
    ("AgentControlSpecification", "policy-engine/sdk/dotnet/src/AgentControlSpecification", "policy-engine-ci-pack-only"),
    ("AgentControlSpecification.AI", "policy-engine/sdk/dotnet/src/AgentControlSpecification.AI", "policy-engine-ci-pack-only"),
    (
        "AgentControlSpecification.AgentFramework",
        "policy-engine/sdk/dotnet/src/AgentControlSpecification.AgentFramework",
        "policy-engine-ci-pack-only",
    ),
    ("AgentControlSpecification.AutoGen", "policy-engine/sdk/dotnet/src/AgentControlSpecification.AutoGen", "policy-engine-ci-pack-only"),
    (
        "AgentControlSpecification.SemanticKernel",
        "policy-engine/sdk/dotnet/src/AgentControlSpecification.SemanticKernel",
        "policy-engine-ci-pack-only",
    ),
]

RUST_CRATES = [
    ("agentmesh", "agent-governance-rust/agentmesh", "manual-publish-needed"),
    ("agentmesh-mcp", "agent-governance-rust/agentmesh-mcp", "manual-publish-needed"),
    ("agent_control_specification_core", "policy-engine/core", "policy-engine-ci-pack-only"),
    ("agent_control_specification", "policy-engine/sdk/rust", "manual-publish-needed"),
]

GO_MODULES = [
    (
        "github.com/microsoft/agent-governance-toolkit/agent-governance-golang",
        "agent-governance-golang",
        "tag-publish-needed",
    )
]

OCI_IMAGES = [
    ("trust-engine", "agent-governance-python/agent-mesh/docker/Dockerfile", "github-actions"),
    ("policy-server", "agent-governance-python/agent-mesh/docker/Dockerfile", "github-actions"),
    ("audit-collector", "agent-governance-python/agent-mesh/docker/Dockerfile", "github-actions"),
    ("api-gateway", "agent-governance-python/agent-mesh/docker/Dockerfile", "github-actions"),
    ("registry", "agent-governance-python/agent-mesh/docker/Dockerfile", "github-actions"),
    ("relay", "agent-governance-python/agent-mesh/docker/Dockerfile", "github-actions"),
    ("governance-sidecar", "agent-governance-python/agent-os/Dockerfile.sidecar", "github-actions"),
]


def artifact(ecosystem: str, name: str, source: str, automation: str) -> dict[str, str]:
    return {
        "ecosystem": ecosystem,
        "name": name,
        "source_path": source,
        "automation": automation,
    }


def parse_bool(value: str | None) -> bool:
    return str(value).lower() in {"1", "true", "yes"}


def build_manifest(args: argparse.Namespace) -> dict[str, Any]:
    release_tag = args.release_tag or args.ref_name or ""
    dry_run = parse_bool(args.dry_run)
    if args.event_name == "release":
        dry_run = False

    artifacts: list[dict[str, str]] = []
    artifacts.extend(artifact("pypi", *entry) for entry in PYPI_PACKAGES)
    artifacts.extend(artifact("npm", *entry) for entry in NPM_PACKAGES)
    artifacts.extend(artifact("nuget", *entry) for entry in NUGET_PACKAGES)
    artifacts.extend(artifact("crates.io", *entry) for entry in RUST_CRATES)
    artifacts.extend(artifact("go", *entry) for entry in GO_MODULES)
    artifacts.extend(artifact("oci", *entry) for entry in OCI_IMAGES)

    return {
        "schema_version": 1,
        "event_name": args.event_name,
        "ref_name": args.ref_name,
        "release_tag": release_tag,
        "requested_package": args.package or "all",
        "dry_run": dry_run,
        "artifacts": artifacts,
        "automation_legend": {
            "github-actions": "Built and published by .github/workflows/publish.yml or publish-containers.yml.",
            "policy-engine-ci-pack-only": "Packaged by policy-engine CI; canonical publish workflow still needs explicit registry release wiring.",
            "manual-publish-needed": "Build/package exists, but canonical registry publication is not automated in publish.yml.",
            "tag-publish-needed": "Published by Go module tag/proxy; release workflow must create or validate tags.",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name", default="")
    parser.add_argument("--ref-name", default="")
    parser.add_argument("--release-tag", default="")
    parser.add_argument("--package", default="all")
    parser.add_argument("--dry-run", default="true")
    parser.add_argument("--output", type=Path, default=Path("release-manifest.json"))
    args = parser.parse_args()

    manifest = build_manifest(args)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
