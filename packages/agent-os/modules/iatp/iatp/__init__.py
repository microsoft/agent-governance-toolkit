# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Inter-Agent Trust Protocol (IATP).

A sidecar-based service mesh for preventing cascading hallucinations
in autonomous agent networks. IATP provides the missing "governance layer"
for multi-agent LLM systems.

Core Features:
    - **Discovery**: Capability manifest exchange via `/.well-known/agent-manifest`
    - **Trust**: Dynamic trust scoring and security validation
    - **Reversibility**: Enforced transaction rollback requirements
    - **Privacy**: Data retention and handling policy enforcement
    - **Telemetry**: Distributed tracing via Flight Recorder

Quick Start:
    >>> from iatp import CapabilityManifest, TrustLevel, SidecarProxy
    >>> manifest = CapabilityManifest(
    ...     agent_id="my-agent",
    ...     trust_level=TrustLevel.TRUSTED,
    ...     capabilities=AgentCapabilities(reversibility=ReversibilityLevel.FULL),
    ...     privacy_contract=PrivacyContract(retention=RetentionPolicy.EPHEMERAL),
    ... )
    >>> print(f"Trust Score: {manifest.calculate_trust_score()}/10")

CLI Usage:
    .. code-block:: bash

        # Verify a manifest
        iatp verify manifest.json

        # Run the sidecar
        uvicorn iatp.main:app --host 0.0.0.0 --port 8081

Docker:
    .. code-block:: bash

        docker run -p 8081:8081 -e IATP_AGENT_URL=http://my-agent:8000 iatp-sidecar

For more information, see:
    - Documentation: https://github.com/microsoft/agent-governance-toolkit
    - Paper: paper/whitepaper.md

Example:
    Basic trust score calculation::

        from iatp import (
            CapabilityManifest,
            AgentCapabilities,
            PrivacyContract,
            TrustLevel,
            ReversibilityLevel,
            RetentionPolicy,
        )

        manifest = CapabilityManifest(
            agent_id="secure-bank-agent",
            trust_level=TrustLevel.VERIFIED_PARTNER,
            capabilities=AgentCapabilities(
                reversibility=ReversibilityLevel.FULL,
                idempotency=True,
            ),
            privacy_contract=PrivacyContract(
                retention=RetentionPolicy.EPHEMERAL,
            ),
        )

        score = manifest.calculate_trust_score()
        print(f"Trust Score: {score}/10")  # Output: Trust Score: 10/10
"""

from __future__ import annotations

__version__ = "0.5.0"
__author__ = "Imran Siddique"
__license__ = "MIT"

# Core Models
# Attestation & Reputation
from iatp.attestation import AttestationValidator, ReputationManager
from iatp.models import (
    AgentCapabilities,
    AttestationRecord,
    CapabilityManifest,
    PrivacyContract,
    QuarantineSession,
    ReputationEvent,
    ReputationScore,
    RetentionPolicy,
    ReversibilityLevel,
    TracingContext,
    TrustLevel,
)

# Engines
from iatp.policy_engine import IATPPolicyEngine
from iatp.recovery import IATPRecoveryEngine

# Security & Privacy
from iatp.security import PrivacyScrubber, SecurityValidator

# Sidecar Components
from iatp.sidecar import SidecarProxy, create_sidecar

# Telemetry & Tracing
from iatp.telemetry import FlightRecorder, TraceIDGenerator

# IPC Pipes - Typed inter-agent communication (v0.4.0)
from iatp.ipc_pipes import (
    TypedPipe,
    PipeMessage,
    PipeConfig,
    PipeState,
    PolicyCheckPipe,
    Pipeline,
    AgentPipelineStage,
    create_pipeline,
    pipe_agents,
)

# Public API exports - controls what is visible via `from iatp import *`
__all__ = [
    # Package metadata
    "__version__",
    "__author__",
    "__license__",
    # Models - Core data structures for capability manifests
    "CapabilityManifest",
    "AgentCapabilities",
    "PrivacyContract",
    "TrustLevel",
    "ReversibilityLevel",
    "RetentionPolicy",
    "QuarantineSession",
    "TracingContext",
    "AttestationRecord",
    "ReputationScore",
    "ReputationEvent",
    # Sidecar - The proxy that wraps agents
    "SidecarProxy",
    "create_sidecar",
    # Security - Validation and privacy enforcement
    "SecurityValidator",
    "PrivacyScrubber",
    # Attestation & Reputation
    "AttestationValidator",
    "ReputationManager",
    # Telemetry - Distributed tracing and audit logging
    "FlightRecorder",
    "TraceIDGenerator",
    # Policy Engine - Rule-based policy evaluation
    "IATPPolicyEngine",
    # Recovery Engine - Compensating transaction support (scak integration)
    "IATPRecoveryEngine",
    # IPC Pipes - Typed inter-agent communication (v0.4.0)
    "TypedPipe",
    "PipeMessage",
    "PipeConfig",
    "PipeState",
    "PolicyCheckPipe",
    "Pipeline",
    "AgentPipelineStage",
    "create_pipeline",
    "pipe_agents",
]
