# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Marketplace — Plugin lifecycle management for the Agent Governance Toolkit.

Discover, install, verify, and manage plugins with Ed25519 signing
and semver-aware version resolution.
"""

from agent_marketplace.exceptions import MarketplaceError
from agent_marketplace.installer import PluginInstaller
from agent_marketplace.manifest import (
    MANIFEST_FILENAME,
    PluginManifest,
    PluginType,
    load_manifest,
    save_manifest,
)
from agent_marketplace.marketplace_policy import (
    ComplianceResult,
    MCPServerPolicy,
    MarketplacePolicy,
    OrgMarketplacePolicy,
    evaluate_plugin_compliance,
    load_marketplace_policy,
)
from agent_marketplace.quality_scoring import (
    PluginQualityProfile,
    QualityBadge,
    QualityDimension,
    QualityScore,
    QualityStore,
)
from agent_marketplace.registry import PluginRegistry
from agent_marketplace.schema_adapters import (
    ClaudePluginManifest,
    CopilotPluginManifest,
    adapt_to_canonical,
    detect_manifest_format,
    extract_capabilities,
    extract_mcp_servers,
)
from agent_marketplace.signing import PluginSigner, verify_signature
from agent_marketplace.trust_tiers import (
    DEFAULT_TIER_CONFIGS,
    TRUST_TIERS,
    PluginTrustConfig,
    PluginTrustStore,
    compute_initial_score,
    filter_capabilities,
    get_tier_config,
    get_trust_tier,
)
from agent_marketplace.quality_assessment import (
    AssessmentDimension,
    AssessmentGrade,
    DimensionResult,
    QualityAssessmentReport,
    QualityAssessor,
)
from agent_marketplace.usage_trust import (
    UsageSignals,
    UsageTrustAdjustment,
    UsageTrustScorer,
)
from agent_marketplace.workflow_bundle import (
    BundleComponent,
    BundleRegistry,
    ComponentType,
    WorkflowBundle,
)

__all__ = [
    "ClaudePluginManifest",
    "ComplianceResult",
    "CopilotPluginManifest",
    "DEFAULT_TIER_CONFIGS",
    "MANIFEST_FILENAME",
    "MCPServerPolicy",
    "MarketplaceError",
    "MarketplacePolicy",
    "OrgMarketplacePolicy",
    "PluginInstaller",
    "PluginManifest",
    "PluginQualityProfile",
    "PluginRegistry",
    "PluginSigner",
    "PluginTrustConfig",
    "PluginTrustStore",
    "PluginType",
    "QualityBadge",
    "QualityDimension",
    "QualityScore",
    "QualityStore",
    "TRUST_TIERS",
    "adapt_to_canonical",
    "compute_initial_score",
    "detect_manifest_format",
    "evaluate_plugin_compliance",
    "extract_capabilities",
    "extract_mcp_servers",
    "filter_capabilities",
    "get_tier_config",
    "get_trust_tier",
    "load_manifest",
    "load_marketplace_policy",
    "save_manifest",
    "verify_signature",
    # Quality Assessment (v3.0.2+)
    "AssessmentDimension",
    "AssessmentGrade",
    "DimensionResult",
    "QualityAssessmentReport",
    "QualityAssessor",
    # Usage Trust (v3.0.2+)
    "UsageSignals",
    "UsageTrustAdjustment",
    "UsageTrustScorer",
    # Workflow Bundles (v3.0.2+)
    "BundleComponent",
    "BundleRegistry",
    "ComponentType",
    "WorkflowBundle",
]
