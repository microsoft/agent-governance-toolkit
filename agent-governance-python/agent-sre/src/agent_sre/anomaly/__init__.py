# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Behavioral Anomaly Detection for Agent Observability.

Baselines normal agent behavior and automatically flags deviations
using statistical, sequential, and resource-based detection strategies.
Includes rogue-agent detection (OWASP ASI-10) via frequency, entropy,
and capability-profile analysis.
"""

from agent_sre.anomaly.detector import (
    AnomalyAlert,
    AnomalyDetector,
    AnomalySeverity,
    AnomalyType,
    BehaviorBaseline,
    DetectorConfig,
)

# rogue_detector was added after agent-sre v1.1.2; guard the import so
# the anomaly sub-package stays importable with older installed versions.
try:
    from agent_sre.anomaly.rogue_detector import (
        ActionEntropyScorer,
        CapabilityProfileDeviation,
        RiskLevel,
        RogueAgentDetector,
        RogueAssessment,
        RogueDetectorConfig,
        ToolCallFrequencyAnalyzer,
    )
except ImportError:
    ActionEntropyScorer = None  # type: ignore[assignment,misc]
    CapabilityProfileDeviation = None  # type: ignore[assignment,misc]
    RiskLevel = None  # type: ignore[assignment]
    RogueAgentDetector = None  # type: ignore[assignment,misc]
    RogueAssessment = None  # type: ignore[assignment,misc]
    RogueDetectorConfig = None  # type: ignore[assignment,misc]
    ToolCallFrequencyAnalyzer = None  # type: ignore[assignment,misc]

from agent_sre.anomaly.strategies import (
    ResourceStrategy,
    SequentialStrategy,
    StatisticalStrategy,
)

__all__ = [
    "ActionEntropyScorer",
    "AnomalyAlert",
    "AnomalyDetector",
    "AnomalySeverity",
    "AnomalyType",
    "BehaviorBaseline",
    "CapabilityProfileDeviation",
    "DetectorConfig",
    "ResourceStrategy",
    "RiskLevel",
    "RogueAgentDetector",
    "RogueAssessment",
    "RogueDetectorConfig",
    "SequentialStrategy",
    "StatisticalStrategy",
    "ToolCallFrequencyAnalyzer",
]
