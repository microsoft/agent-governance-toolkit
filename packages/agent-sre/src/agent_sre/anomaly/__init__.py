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
from agent_sre.anomaly.rogue_detector import (
    ActionEntropyScorer,
    CapabilityProfileDeviation,
    RiskLevel,
    RogueAgentDetector,
    RogueAssessment,
    RogueDetectorConfig,
    ToolCallFrequencyAnalyzer,
)
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
