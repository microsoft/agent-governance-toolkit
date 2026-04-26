# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Completeness Auditor - Detects and fixes agent "Laziness".

This implements Differential Auditing: instead of auditing every interaction,
we only audit when the agent gives up with a "Negative Result".

The Shadow Teacher Model attempts the same sub-task, and if it succeeds,
we generate a "Competence Patch" to prevent future laziness.
"""

import logging
import uuid
from typing import Optional, List
from datetime import datetime

from .models import AgentOutcome, CompletenessAudit, GiveUpSignal

logger = logging.getLogger(__name__)


class CompletenessAuditor:
    """
    The Shadow Auditor that detects agent laziness.
    
    When an agent outputs a "Negative Result" (e.g., "No data found"),
    the system spins up a "Teacher Model" to attempt the same sub-task.
    
    If the teacher succeeds where the agent gave up, we identify the gap
    and generate a competence patch.
    """
    
    def __init__(self, teacher_model: str = "o1-preview"):
        """
        Initialize the Completeness Auditor.
        
        Args:
            teacher_model: High-reasoning model for auditing (e.g., "o1-preview", "o1", "claude-opus")
        """
        self.teacher_model = teacher_model
        self.audit_history: List[CompletenessAudit] = []
        self.audit_count = 0
        self.lazy_detection_count = 0
    
    def audit_give_up(self, outcome: AgentOutcome) -> CompletenessAudit:
        """
        Audit an agent's give-up outcome using the Teacher Model.
        
        This is "Differential Auditing" - we only audit specific give-up signals,
        not every interaction (which would be too expensive).
        
        Args:
            outcome: The agent outcome with give-up signal
            
        Returns:
            CompletenessAudit with findings
        """
        audit_id = f"audit-{uuid.uuid4().hex[:8]}"
        self.audit_count += 1
        
        logger.info(f"🔍 Completeness Audit {audit_id} started")
        logger.info(f"   Agent said: '{outcome.agent_response[:60]}...'")
        logger.info(f"   Give-up signal: {outcome.give_up_signal.value if outcome.give_up_signal else 'unknown'}")
        
        # Simulate teacher model attempting the same task
        teacher_result = self._run_teacher_model(outcome)
        
        # Compare agent vs teacher
        teacher_found_data = teacher_result["found_data"]
        
        if teacher_found_data:
            # Teacher succeeded where agent gave up - this is LAZINESS
            self.lazy_detection_count += 1
            logger.warning(f"⚠️  LAZINESS DETECTED: Teacher found data that agent missed!")
            
            gap_analysis = self._analyze_gap(outcome, teacher_result)
            competence_patch = self._generate_competence_patch(outcome, gap_analysis, teacher_result)
            confidence = teacher_result["confidence"]
        else:
            # Teacher also couldn't find data - agent was correct
            logger.info(f"✓ Agent was correct: No data available")
            gap_analysis = "Agent response was appropriate. No data available."
            competence_patch = "No patch needed - agent correctly identified unavailability."
            confidence = 0.9
        
        audit = CompletenessAudit(
            audit_id=audit_id,
            agent_outcome=outcome,
            teacher_model=self.teacher_model,
            teacher_response=teacher_result["response"],
            teacher_found_data=teacher_found_data,
            gap_analysis=gap_analysis,
            competence_patch=competence_patch,
            confidence=confidence
        )
        
        self.audit_history.append(audit)
        
        logger.info(f"🏁 Audit complete. Found data: {teacher_found_data}")
        
        return audit
    
    def _run_teacher_model(self, outcome: AgentOutcome) -> dict:
        """
        Simulate running the teacher model on the same task.
        
        In a real system, this would:
        1. Spin up a high-reasoning model (o1-preview, o1, etc.)
        2. Give it the same user prompt
        3. Give it enhanced context/tools
        4. Capture its response
        
        For demonstration, we simulate based on patterns.
        """
        user_prompt = outcome.user_prompt.lower()
        agent_response = outcome.agent_response.lower()
        
        # Simulate teacher model's superior reasoning
        # In reality, this would be an actual API call to o1-preview or similar
        
        # Pattern: Looking for logs
        if any(keyword in user_prompt for keyword in ["log", "error", "trace", "debug"]):
            if "500" in user_prompt or "error" in user_prompt:
                # Teacher checks additional locations
                if outcome.give_up_signal == GiveUpSignal.NO_DATA_FOUND:
                    # Teacher found it by checking archived partitions
                    return {
                        "found_data": True,
                        "response": "Found logs in archived partition /var/log/archive/2024-01/. The agent missed checking archived partitions.",
                        "location": "archived partitions",
                        "confidence": 0.92
                    }
        
        # Pattern: Looking for projects/resources
        if any(keyword in user_prompt for keyword in ["project", "resource", "entity"]):
            if "alpha" in user_prompt or "beta" in user_prompt:
                # Teacher verifies against complete registry
                return {
                    "found_data": True,
                    "response": "Project exists but is archived. Agent should check archived projects registry.",
                    "location": "archived registry",
                    "confidence": 0.88
                }
        
        # Pattern: Database queries
        if any(keyword in user_prompt for keyword in ["user", "customer", "record", "data"]):
            if "recent" in user_prompt or "latest" in user_prompt:
                # Teacher uses proper time window
                return {
                    "found_data": True,
                    "response": "Found 247 records using proper time window. Agent may have used incorrect date filter.",
                    "location": "database with corrected filter",
                    "confidence": 0.85
                }
        
        # Default: Teacher also couldn't find data
        return {
            "found_data": False,
            "response": "After exhaustive search, confirmed no data available.",
            "location": "none",
            "confidence": 0.9
        }
    
    def _analyze_gap(self, outcome: AgentOutcome, teacher_result: dict) -> str:
        """
        Analyze what the agent missed.
        
        This is the key insight: identifying the specific gap in the agent's
        reasoning or search strategy.
        """
        location = teacher_result.get("location", "unknown location")
        
        # Build gap analysis based on give-up signal type
        if outcome.give_up_signal == GiveUpSignal.NO_DATA_FOUND:
            gap = f"Agent didn't check {location}. "
        elif outcome.give_up_signal == GiveUpSignal.INSUFFICIENT_INFO:
            gap = f"Agent gave up too early. Data exists in {location}. "
        else:
            gap = f"Agent failed to search {location}. "
        
        gap += f"Agent response: '{outcome.agent_response[:100]}'. "
        gap += f"Teacher found: '{teacher_result['response'][:100]}'"
        
        return gap
    
    def _generate_competence_patch(
        self,
        outcome: AgentOutcome,
        gap_analysis: str,
        teacher_result: dict
    ) -> str:
        """
        Generate a "Competence Patch" - a lesson to prevent future laziness.
        
        This is NOT just correcting the answer; it's a strategic instruction
        that addresses the systematic gap in the agent's behavior.
        
        Example patches:
        - "When searching logs, always check archived partitions if recent logs are empty."
        - "Before reporting 'not found', verify all registry sources including archived items."
        - "Use proper time windows for 'recent' queries: last 7 days for logs, 30 days for records."
        """
        user_prompt_lower = outcome.user_prompt.lower()
        location = teacher_result.get("location", "additional sources")
        
        # Generate specific, actionable patch based on the pattern
        if "log" in user_prompt_lower:
            patch = f"When searching logs, always check archived partitions ({location}) if recent logs are empty."
        elif "project" in user_prompt_lower or "resource" in user_prompt_lower:
            patch = f"Before reporting 'not found', verify all registry sources including {location}."
        elif "recent" in user_prompt_lower or "latest" in user_prompt_lower:
            patch = f"For 'recent' queries, use proper time windows and check {location}."
        elif outcome.give_up_signal == GiveUpSignal.NO_DATA_FOUND:
            patch = f"Before reporting 'no data found', exhaustively check all sources including {location}."
        else:
            patch = f"Expand search scope to include {location} before concluding data unavailability."
        
        # Add context about the specific failure
        patch += f" This prevents false negatives when data exists but requires deeper search."
        
        return patch
    
    def get_audit_stats(self) -> dict:
        """Get statistics about auditing activity."""
        return {
            "total_audits": self.audit_count,
            "laziness_detected": self.lazy_detection_count,
            "laziness_rate": self.lazy_detection_count / self.audit_count if self.audit_count > 0 else 0.0,
            "audits_with_data": sum(1 for a in self.audit_history if a.teacher_found_data),
            "audits_no_data": sum(1 for a in self.audit_history if not a.teacher_found_data)
        }
    
    def get_audit_history(self, limit: int = 100) -> List[CompletenessAudit]:
        """Get audit history."""
        return self.audit_history[-limit:]
