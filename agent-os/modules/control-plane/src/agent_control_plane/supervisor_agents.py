# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Supervisor Agents - Recursive Governance

Eventually, the Control Plane itself will be too complex for humans to manage
manually. We need Supervisor Agents - specialized, highly constrained agents
whose only job is to watch the logs of worker agents and flag violations to
a human.

Agents watching agents, bound by a constitution of code.

Research Foundations:
    - Hierarchical control patterns from "Multi-Agent Systems: A Survey" 
      (arXiv:2308.05391, 2023) - supervision hierarchies, cascade failure prevention
    - Anomaly detection patterns for monitoring agent behavior
    - Recursive governance inspired by "MAESTRO: A Threat Modeling Framework" 
      (CSA, 2025) - multi-agent security monitoring
    - Human-in-the-loop patterns for escalation and intervention

See docs/RESEARCH_FOUNDATION.md for complete references.
"""

from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from .agent_kernel import ActionType, ExecutionStatus


class ViolationType(Enum):
    """Types of violations a supervisor can detect"""
    EXCESSIVE_RISK = "excessive_risk"
    RATE_LIMIT_APPROACHING = "rate_limit_approaching"
    REPEATED_FAILURES = "repeated_failures"
    POLICY_CIRCUMVENTION = "policy_circumvention"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SUSPICIOUS_PATTERN = "suspicious_pattern"


@dataclass
class Violation:
    """A violation detected by a supervisor"""
    violation_id: str
    violation_type: ViolationType
    agent_id: str
    severity: str  # "low", "medium", "high", "critical"
    description: str
    evidence: Dict[str, Any]
    detected_at: datetime
    requires_human_review: bool = False
    auto_remediation: Optional[str] = None


@dataclass
class SupervisorConfig:
    """Configuration for a supervisor agent"""
    supervisor_id: str
    name: str
    watches: List[str]  # Agent IDs to watch
    detection_rules: List[Callable] = field(default_factory=list)
    escalation_threshold: int = 3  # Number of violations before escalation
    auto_remediate: bool = False  # Can supervisor take automatic action?
    notification_channels: List[str] = field(default_factory=list)


class SupervisorAgent:
    """
    A supervisor agent that watches worker agents and flags violations.
    
    Supervisors are highly constrained agents that:
    1. Only read logs and metrics
    2. Cannot execute actions
    3. Only flag violations to humans
    4. Optionally suggest remediations
    """
    
    def __init__(self, config: SupervisorConfig):
        self.config = config
        self.violations: List[Violation] = []
        self.violation_count_by_agent: Dict[str, int] = {}
        self.last_check: datetime = datetime.now()
    
    def watch_execution_logs(self, execution_log: List[Dict[str, Any]]) -> List[Violation]:
        """
        Watch execution logs and detect violations.
        
        Returns list of new violations detected.
        """
        new_violations = []
        
        # Filter logs for watched agents
        relevant_logs = [
            log for log in execution_log
            if log.get('agent_id') in self.config.watches
        ]
        
        # Apply detection rules
        for rule in self.config.detection_rules:
            violations = rule(relevant_logs, self)
            new_violations.extend(violations)
        
        # Store violations
        self.violations.extend(new_violations)
        
        # Update counts
        for violation in new_violations:
            agent_id = violation.agent_id
            self.violation_count_by_agent[agent_id] = \
                self.violation_count_by_agent.get(agent_id, 0) + 1
        
        # Check for escalation
        self._check_escalation()
        
        self.last_check = datetime.now()
        return new_violations
    
    def watch_audit_logs(self, audit_log: List[Dict[str, Any]]) -> List[Violation]:
        """
        Watch audit logs for policy violations and suspicious patterns.
        """
        new_violations = []
        
        # Filter for watched agents
        relevant_logs = [
            log for log in audit_log
            if log.get('details', {}).get('agent_id') in self.config.watches
        ]
        
        # Look for denied requests
        denials = [log for log in relevant_logs if 'denied' in log.get('event_type', '')]
        if len(denials) > 5:  # Threshold for suspicious behavior
            new_violations.append(Violation(
                violation_id=f"v_{datetime.now().timestamp()}",
                violation_type=ViolationType.POLICY_CIRCUMVENTION,
                agent_id=self.config.watches[0] if self.config.watches else "unknown",
                severity="high",
                description=f"Agent has {len(denials)} denied requests, possible circumvention attempt",
                evidence={"denials": denials},
                detected_at=datetime.now(),
                requires_human_review=True
            ))
        
        self.violations.extend(new_violations)
        return new_violations
    
    def analyze_risk_patterns(self, execution_log: List[Dict[str, Any]]) -> List[Violation]:
        """
        Analyze execution patterns for risk trends.
        """
        new_violations = []
        
        # Group by agent
        for agent_id in self.config.watches:
            agent_logs = [log for log in execution_log if log.get('agent_id') == agent_id]
            
            # Calculate average risk
            risks = [log.get('risk_score', 0) for log in agent_logs if log.get('success')]
            if risks:
                avg_risk = sum(risks) / len(risks)
                
                # Flag if average risk is increasing
                if avg_risk > 0.6:
                    new_violations.append(Violation(
                        violation_id=f"v_{datetime.now().timestamp()}",
                        violation_type=ViolationType.EXCESSIVE_RISK,
                        agent_id=agent_id,
                        severity="medium",
                        description=f"Agent average risk score is {avg_risk:.2f}, exceeds safe threshold",
                        evidence={"average_risk": avg_risk, "sample_size": len(risks)},
                        detected_at=datetime.now(),
                        auto_remediation="reduce_agent_permissions"
                    ))
        
        self.violations.extend(new_violations)
        return new_violations
    
    def _check_escalation(self):
        """Check if any agent needs escalation to human"""
        for agent_id, count in self.violation_count_by_agent.items():
            if count >= self.config.escalation_threshold:
                # Create escalation violation
                escalation = Violation(
                    violation_id=f"escalation_{agent_id}_{datetime.now().timestamp()}",
                    violation_type=ViolationType.ANOMALOUS_BEHAVIOR,
                    agent_id=agent_id,
                    severity="critical",
                    description=f"Agent has {count} violations, exceeds escalation threshold",
                    evidence={"violation_count": count, "threshold": self.config.escalation_threshold},
                    detected_at=datetime.now(),
                    requires_human_review=True
                )
                self.violations.append(escalation)
                
                # Reset count after escalation
                self.violation_count_by_agent[agent_id] = 0
    
    def get_violations(
        self,
        agent_id: Optional[str] = None,
        severity: Optional[str] = None,
        requires_human: Optional[bool] = None
    ) -> List[Violation]:
        """Get violations with optional filters"""
        violations = self.violations
        
        if agent_id:
            violations = [v for v in violations if v.agent_id == agent_id]
        
        if severity:
            violations = [v for v in violations if v.severity == severity]
        
        if requires_human is not None:
            violations = [v for v in violations if v.requires_human_review == requires_human]
        
        return violations
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of supervisor activity"""
        return {
            "supervisor_id": self.config.supervisor_id,
            "watching": self.config.watches,
            "total_violations": len(self.violations),
            "violations_by_type": self._count_by_type(),
            "violations_by_severity": self._count_by_severity(),
            "requires_human_review": len([v for v in self.violations if v.requires_human_review]),
            "last_check": self.last_check.isoformat()
        }
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count violations by type"""
        counts = {}
        for v in self.violations:
            vtype = v.violation_type.value
            counts[vtype] = counts.get(vtype, 0) + 1
        return counts
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count violations by severity"""
        counts = {}
        for v in self.violations:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts


# Detection rule functions

def detect_repeated_failures(logs: List[Dict[str, Any]], supervisor: SupervisorAgent) -> List[Violation]:
    """Detect agents with repeated failures"""
    violations = []
    
    for agent_id in supervisor.config.watches:
        agent_logs = [log for log in logs if log.get('agent_id') == agent_id]
        failures = [log for log in agent_logs if not log.get('success', True)]
        
        if len(failures) >= 5:
            violations.append(Violation(
                violation_id=f"v_{datetime.now().timestamp()}",
                violation_type=ViolationType.REPEATED_FAILURES,
                agent_id=agent_id,
                severity="medium",
                description=f"Agent has {len(failures)} failures in recent history",
                evidence={"failure_count": len(failures), "sample": failures[:3]},
                detected_at=datetime.now(),
                auto_remediation="review_agent_configuration"
            ))
    
    return violations


def detect_rate_limit_approaching(logs: List[Dict[str, Any]], supervisor: SupervisorAgent) -> List[Violation]:
    """Detect agents approaching rate limits"""
    violations = []
    
    # This would need access to quota information
    # Simplified version here
    for agent_id in supervisor.config.watches:
        agent_logs = [log for log in logs if log.get('agent_id') == agent_id]
        
        # Check recent activity
        recent_window = datetime.now() - timedelta(minutes=1)
        recent_logs = []
        for log in agent_logs:
            timestamp_str = log.get('timestamp')
            if timestamp_str:
                try:
                    log_time = datetime.fromisoformat(timestamp_str)
                    if log_time > recent_window:
                        recent_logs.append(log)
                except (ValueError, TypeError):
                    # Skip logs with invalid timestamps
                    continue
        
        if len(recent_logs) > 50:  # High activity
            violations.append(Violation(
                violation_id=f"v_{datetime.now().timestamp()}",
                violation_type=ViolationType.RATE_LIMIT_APPROACHING,
                agent_id=agent_id,
                severity="low",
                description=f"Agent has {len(recent_logs)} requests in last minute, approaching limits",
                evidence={"recent_requests": len(recent_logs)},
                detected_at=datetime.now(),
                auto_remediation="throttle_agent"
            ))
    
    return violations


def detect_suspicious_patterns(logs: List[Dict[str, Any]], supervisor: SupervisorAgent) -> List[Violation]:
    """Detect suspicious behavioral patterns"""
    violations = []
    
    for agent_id in supervisor.config.watches:
        agent_logs = [log for log in logs if log.get('agent_id') == agent_id]
        
        # Look for unusual action patterns
        action_types = [log.get('action_type') for log in agent_logs]
        
        # If agent suddenly starts doing different types of actions
        unique_actions = set(action_types)
        if len(unique_actions) > 5:  # Agent doing many different things
            violations.append(Violation(
                violation_id=f"v_{datetime.now().timestamp()}",
                violation_type=ViolationType.SUSPICIOUS_PATTERN,
                agent_id=agent_id,
                severity="medium",
                description=f"Agent performing {len(unique_actions)} different action types, possible anomaly",
                evidence={"action_types": list(unique_actions)},
                detected_at=datetime.now(),
                requires_human_review=True
            ))
    
    return violations


class SupervisorNetwork:
    """
    Network of supervisor agents with hierarchical oversight.
    
    Enables recursive governance where supervisors can watch other supervisors.
    """
    
    def __init__(self):
        self.supervisors: Dict[str, SupervisorAgent] = {}
        self.hierarchy: Dict[str, List[str]] = {}  # supervisor -> list of watched supervisors
    
    def add_supervisor(self, supervisor: SupervisorAgent):
        """Add a supervisor to the network"""
        self.supervisors[supervisor.config.supervisor_id] = supervisor
    
    def add_supervisor_hierarchy(self, parent_supervisor_id: str, child_supervisor_ids: List[str]):
        """Create hierarchical supervision (supervisors watching supervisors)"""
        self.hierarchy[parent_supervisor_id] = child_supervisor_ids
    
    def run_supervision_cycle(
        self,
        execution_log: List[Dict[str, Any]],
        audit_log: List[Dict[str, Any]]
    ) -> Dict[str, List[Violation]]:
        """
        Run a complete supervision cycle across all supervisors.
        
        Returns violations by supervisor ID.
        """
        all_violations = {}
        
        # First level: Watch worker agents
        for supervisor_id, supervisor in self.supervisors.items():
            violations = []
            violations.extend(supervisor.watch_execution_logs(execution_log))
            violations.extend(supervisor.watch_audit_logs(audit_log))
            violations.extend(supervisor.analyze_risk_patterns(execution_log))
            all_violations[supervisor_id] = violations
        
        # Second level: Supervisors watching supervisors (if hierarchy exists)
        for parent_id, child_ids in self.hierarchy.items():
            parent = self.supervisors.get(parent_id)
            if parent:
                # Collect violations from child supervisors
                child_violations = []
                for child_id in child_ids:
                    child_violations.extend(all_violations.get(child_id, []))
                
                # Parent supervisor analyzes if children are working correctly
                # (Simplified - in reality would have sophisticated checks)
                if len(child_violations) > 100:
                    all_violations[parent_id] = all_violations.get(parent_id, []) + [
                        Violation(
                            violation_id=f"meta_v_{datetime.now().timestamp()}",
                            violation_type=ViolationType.ANOMALOUS_BEHAVIOR,
                            agent_id="supervisor_network",
                            severity="critical",
                            description=f"Child supervisors detected {len(child_violations)} violations",
                            evidence={"child_violations": len(child_violations)},
                            detected_at=datetime.now(),
                            requires_human_review=True
                        )
                    ]
        
        return all_violations
    
    def get_network_summary(self) -> Dict[str, Any]:
        """Get summary of entire supervisor network"""
        return {
            "total_supervisors": len(self.supervisors),
            "hierarchy_levels": len(self.hierarchy),
            "supervisors": {
                sid: supervisor.get_summary()
                for sid, supervisor in self.supervisors.items()
            }
        }


def create_default_supervisor(agent_ids: List[str]) -> SupervisorAgent:
    """Create a supervisor with default detection rules"""
    config = SupervisorConfig(
        supervisor_id=f"supervisor_{datetime.now().timestamp()}",
        name="Default Supervisor",
        watches=agent_ids,
        detection_rules=[
            detect_repeated_failures,
            detect_rate_limit_approaching,
            detect_suspicious_patterns
        ],
        escalation_threshold=3,
        auto_remediate=False
    )
    return SupervisorAgent(config)
