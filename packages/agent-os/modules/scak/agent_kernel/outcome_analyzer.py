# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic self-correction with retry
"""
Outcome Analyzer — detects give-up phrases without semantic analysis.
"""

import logging
import re
from typing import Optional, List
from datetime import datetime

from .models import (
    AgentOutcome,
    OutcomeType,
    GiveUpSignal,
)

logger = logging.getLogger(__name__)


_GIVE_UP_PHRASES = [
    "i cannot",
    "i can't",
    "no data found",
    "no results",
    "not available",
    "unable to",
    "insufficient",
    "i'm sorry",
    "cannot answer",
]


class OutcomeAnalyzer:
    """
    Basic give-up detection via substring matching.

    Flags agent responses that contain common refusal / give-up phrases.
    """

    def __init__(self, use_semantic_analysis: bool = False):
        # use_semantic_analysis accepted for signature compat; ignored
        self.outcome_history: List[AgentOutcome] = []

    def analyze_outcome(
        self,
        agent_id: str,
        user_prompt: str,
        agent_response: str,
        context: Optional[dict] = None,
        tool_telemetry: Optional[list] = None,
    ) -> AgentOutcome:
        """Analyse an agent response for give-up signals."""
        give_up_signal = self._detect_give_up(agent_response)

        if give_up_signal is not None:
            outcome_type = OutcomeType.GIVE_UP
        elif not agent_response or len(agent_response.strip()) < 20:
            outcome_type = OutcomeType.FAILURE
        else:
            outcome_type = OutcomeType.SUCCESS

        outcome = AgentOutcome(
            agent_id=agent_id,
            outcome_type=outcome_type,
            user_prompt=user_prompt,
            agent_response=agent_response,
            give_up_signal=give_up_signal,
            context=context or {},
        )
        self.outcome_history.append(outcome)
        return outcome

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_give_up(response: str) -> Optional[GiveUpSignal]:
        lower = response.lower()
        for phrase in _GIVE_UP_PHRASES:
            if phrase in lower:
                if "data" in phrase or "result" in phrase:
                    return GiveUpSignal.NO_DATA_FOUND
                if "cannot" in phrase or "can't" in phrase or "answer" in phrase:
                    return GiveUpSignal.CANNOT_ANSWER
                if "available" in phrase:
                    return GiveUpSignal.NOT_AVAILABLE
                if "insufficient" in phrase:
                    return GiveUpSignal.INSUFFICIENT_INFO
                return GiveUpSignal.UNKNOWN
        return None

    def should_trigger_audit(self, outcome: AgentOutcome) -> bool:
        return outcome.outcome_type == OutcomeType.GIVE_UP

    def get_give_up_rate(self, agent_id: Optional[str] = None, recent_n: int = 100) -> float:
        outcomes = self.outcome_history[-recent_n:]
        if agent_id:
            outcomes = [o for o in outcomes if o.agent_id == agent_id]
        if not outcomes:
            return 0.0
        return sum(1 for o in outcomes if o.outcome_type == OutcomeType.GIVE_UP) / len(outcomes)

    def get_outcome_history(
        self,
        agent_id: Optional[str] = None,
        outcome_type: Optional[OutcomeType] = None,
        limit: int = 100,
    ) -> List[AgentOutcome]:
        outcomes = self.outcome_history[-limit:]
        if agent_id:
            outcomes = [o for o in outcomes if o.agent_id == agent_id]
        if outcome_type:
            outcomes = [o for o in outcomes if o.outcome_type == outcome_type]
        return outcomes
