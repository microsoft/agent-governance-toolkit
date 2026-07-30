# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import warnings
warnings.warn(
    "openshell-agentmesh is deprecated: the OpenShell governance skill "
    "(GovernanceSkill, ShellPolicyViolation, governed_shell) was removed in "
    "the v5 ACS migration and has no OpenShell-specific replacement. Build "
    "an AgentControl from an ACS manifest (agent_control_specification) and "
    "evaluate intervention points in the host. See "
    "https://github.com/microsoft/agent-governance-toolkit/blob/main/BREAKING_CHANGES.md",
    DeprecationWarning,
    stacklevel=2,
)
