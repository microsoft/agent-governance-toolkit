# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Microsoft Agent 365 bridge for the Agent Governance Toolkit."""

from agentmesh_agent365.observability import (
    A365_OBO_SCOPE,
    A365_OBSERVABILITY_RESOURCE,
    A365_S2S_SCOPE,
    ExporterSettings,
    GovernanceSpanRecorder,
    check_eligibility,
    eligibility_url,
    governance_attributes,
    otlp_exporter_settings,
    traces_url,
)
from agentmesh_agent365.purview import AgentInfo, PurviewClient, PurviewVerdict
from agentmesh_agent365.registry_sync import EntraRegistrySync, SyncReport, iter_agent_identities
from agentmesh_agent365.threat_detection import (
    ThreatDecision,
    ThreatDetectionHandler,
    ToolExecutionRequest,
    create_app,
    gateway_decider,
)

__all__ = [
    "A365_OBO_SCOPE",
    "A365_OBSERVABILITY_RESOURCE",
    "A365_S2S_SCOPE",
    "AgentInfo",
    "EntraRegistrySync",
    "ExporterSettings",
    "GovernanceSpanRecorder",
    "PurviewClient",
    "PurviewVerdict",
    "SyncReport",
    "ThreatDecision",
    "ThreatDetectionHandler",
    "ToolExecutionRequest",
    "check_eligibility",
    "create_app",
    "eligibility_url",
    "gateway_decider",
    "governance_attributes",
    "iter_agent_identities",
    "otlp_exporter_settings",
    "traces_url",
]
