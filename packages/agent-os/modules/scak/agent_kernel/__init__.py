# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Self-Correcting Agent Kernel

A Dual-Loop Architecture for Enterprise Agents:
- Loop 1 (Runtime): Constraint Engine (Safety)
- Loop 2 (Offline): Alignment Engine (Quality & Efficiency)
  - Completeness Auditor (detects laziness)
  - Semantic Purge (scales by subtraction)

Reference Implementations:
- auditor.py: Simplified soft failure detection
- teacher.py: Shadow Teacher diagnosis
- memory_manager.py: Lesson lifecycle management
"""

__version__ = "2.1.0"

# Reference implementations (simplified examples)
from .auditor import CompletenessAuditor as SimpleCompletenessAuditor
from .completeness_auditor import CompletenessAuditor
from .kernel import SelfCorrectingAgentKernel
from .memory_manager import LessonType, MemoryManager
from .models import (
    AgentFailure,
    AgentOutcome,
    ClassifiedPatch,
    CompletenessAudit,
    CorrectionPatch,
    FailureAnalysis,
    GiveUpSignal,
    NudgeResult,
    OutcomeType,
    PatchDecayType,
    SemanticAnalysis,
    ToolExecutionStatus,
    ToolExecutionTelemetry,
)
from .nudge_mechanism import NudgeMechanism
from .outcome_analyzer import OutcomeAnalyzer
from .semantic_analyzer import SemanticAnalyzer
from .semantic_purge import PatchClassifier, SemanticPurge
from .teacher import diagnose_failure
from .triage import FailureTriage, FixStrategy

__all__ = [
    "SelfCorrectingAgentKernel",
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
    "OutcomeAnalyzer",
    "CompletenessAuditor",
    "SemanticPurge",
    "PatchClassifier",
    "FailureTriage",
    "FixStrategy",
    "SemanticAnalyzer",
    "NudgeMechanism",
    # Reference implementations
    "SimpleCompletenessAuditor",
    "diagnose_failure",
    "MemoryManager",
    "LessonType",
]
