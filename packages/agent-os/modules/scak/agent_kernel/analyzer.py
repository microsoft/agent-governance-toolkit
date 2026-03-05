# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic self-correction with retry
"""
Failure Analyzer — simple pattern matching with known error strings.
"""

import logging
from typing import List, Optional, Dict

from .models import AgentFailure, FailureAnalysis, FailureType

logger = logging.getLogger(__name__)


class FailureAnalyzer:
    """Analyses failures using simple keyword pattern matching."""

    def __init__(self):
        self.analysis_history: List[FailureAnalysis] = []
        self.known_patterns: Dict[str, dict] = self._load_known_patterns()

    def _load_known_patterns(self) -> Dict[str, dict]:
        """Load known failure patterns and their suggested fixes."""
        return {
            FailureType.BLOCKED_BY_CONTROL_PLANE: {
                "root_causes": ["Policy or permission violation"],
                "fixes": ["Add permission checks before actions"],
            },
            FailureType.TIMEOUT: {
                "root_causes": ["Operation exceeded time limit"],
                "fixes": ["Implement timeout handling"],
            },
            FailureType.INVALID_ACTION: {
                "root_causes": ["Invalid input or unsupported action"],
                "fixes": ["Add input validation"],
            },
            FailureType.RESOURCE_EXHAUSTED: {
                "root_causes": ["Resource limit reached"],
                "fixes": ["Implement resource cleanup"],
            },
            FailureType.LOGIC_ERROR: {
                "root_causes": ["Incorrect logic or unhandled edge case"],
                "fixes": ["Fix algorithm logic"],
            },
        }

    def analyze(
        self,
        failure: AgentFailure,
        similar_failures: Optional[List[AgentFailure]] = None,
    ) -> FailureAnalysis:
        """Analyse a failure and return root cause + suggested fixes."""
        patterns = self.known_patterns.get(failure.failure_type, {})
        root_cause = (patterns.get("root_causes") or ["Unknown"])[0]
        fixes = patterns.get("fixes", ["Manual investigation required"])

        confidence = 0.5
        if failure.failure_type in self.known_patterns:
            confidence += 0.2
        if similar_failures:
            confidence += min(0.2, len(similar_failures) * 0.05)
        if failure.context:
            confidence += 0.1
        confidence = min(1.0, confidence)

        analysis = FailureAnalysis(
            failure=failure,
            root_cause=root_cause,
            contributing_factors=[],
            suggested_fixes=fixes[:3],
            confidence_score=confidence,
            similar_failures=[],
        )
        self.analysis_history.append(analysis)
        return analysis

    def find_similar_failures(
        self, failure: AgentFailure, history: List[AgentFailure]
    ) -> List[AgentFailure]:
        """Find failures with the same failure type."""
        return [f for f in history if f.failure_type == failure.failure_type][:10]
