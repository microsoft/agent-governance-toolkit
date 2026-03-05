# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic self-correction with retry
"""
Self-Correcting Agent Kernel — Community Edition.

Basic self-correction with simple retry logic.
"""

__version__ = "3.0.0-community"

from .kernel import SelfCorrectingAgentKernel
from .models import (
    AgentFailure, FailureAnalysis, CorrectionPatch,
    AgentOutcome, CompletenessAudit, ClassifiedPatch,
    OutcomeType, GiveUpSignal, PatchDecayType,
    ToolExecutionTelemetry, ToolExecutionStatus,
    SemanticAnalysis, NudgeResult,
)
from .outcome_analyzer import OutcomeAnalyzer
from .triage import FailureTriage, FixStrategy
from .auditor import CompletenessAuditor
from .memory_manager import MemoryManager, LessonType

__all__ = [
    "SelfCorrectingAgentKernel",
    # models
    "AgentFailure",
    "FailureAnalysis",
    "CorrectionPatch",
    "AgentOutcome",
    "CompletenessAudit",
    "ClassifiedPatch",
    "OutcomeType",
    "GiveUpSignal",
    "PatchDecayType",
    "ToolExecutionTelemetry",
    "ToolExecutionStatus",
    "SemanticAnalysis",
    "NudgeResult",
    # components
    "OutcomeAnalyzer",
    "FailureTriage",
    "FixStrategy",
    "CompletenessAuditor",
    "MemoryManager",
    "LessonType",
]
