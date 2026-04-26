# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
HR Recruiting Agent with Agent OS Governance

Demonstrates:
- Bias prevention in candidate screening
- Protected characteristic blocking
- Fair and consistent evaluation criteria
- GDPR/CCPA compliant data handling
"""

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum

# Agent OS imports
try:
    from agent_os import Governor, Policy
    from agent_os.policies import create_policy
    AGENT_OS_AVAILABLE = True
except ImportError:
    AGENT_OS_AVAILABLE = False
    print("Note: Install agent-os-kernel for full governance features")


class Decision(Enum):
    ADVANCE = "advance"
    HOLD = "hold"
    REJECT = "reject"


# Protected characteristics that must NEVER influence hiring decisions
PROTECTED_CHARACTERISTICS = {
    "age", "gender", "sex", "race", "ethnicity", "religion",
    "marital_status", "family_status", "disability", "national_origin",
    "genetic_information", "pregnancy", "veteran_status", "citizenship"
}


@dataclass
class Candidate:
    """Candidate profile with separated protected/allowed data."""
    candidate_id: str
    
    # Allowed fields for screening
    skills: list[str] = field(default_factory=list)
    years_experience: int = 0
    education: str = ""
    work_history: list[dict] = field(default_factory=list)
    certifications: list[str] = field(default_factory=list)
    
    # Protected fields - MUST NOT be used in screening
    _protected_data: dict = field(default_factory=dict, repr=False)
    
    # Metadata
    applied_date: datetime = field(default_factory=datetime.utcnow)
    data_consent: bool = False
    retention_until: datetime = None


@dataclass
class JobRequirement:
    """Job requirements for consistent screening."""
    job_id: str
    title: str
    required_skills: list[str]
    min_experience_years: int
    required_education: list[str]
    preferred_certifications: list[str] = field(default_factory=list)
    weight_skills: float = 0.4
    weight_experience: float = 0.3
    weight_education: float = 0.2
    weight_certifications: float = 0.1


class BiasGuard:
    """Prevents access to protected characteristics."""
    
    @staticmethod
    def sanitize_input(data: dict) -> dict:
        """Remove any protected characteristics from input."""
        sanitized = {}
        blocked = []
        
        for key, value in data.items():
            key_lower = key.lower().replace("_", " ").replace("-", " ")
            
            # Check if key relates to protected characteristics
            is_protected = any(
                protected in key_lower 
                for protected in PROTECTED_CHARACTERISTICS
            )
            
            if is_protected:
                blocked.append(key)
            else:
                sanitized[key] = value
        
        if blocked:
            print(f"  🛡️ BiasGuard blocked fields: {blocked}")
        
        return sanitized
    
    @staticmethod
    def check_reason(reason: str) -> tuple[bool, Optional[str]]:
        """Check if rejection reason contains bias indicators."""
        reason_lower = reason.lower()
        
        for protected in PROTECTED_CHARACTERISTICS:
            if protected in reason_lower:
                return False, f"Rejection reason references protected characteristic: {protected}"
        
        # Check for proxy discrimination
        proxies = ["cultural fit", "not a good fit", "overqualified", "too young", "too old"]
        for proxy in proxies:
            if proxy in reason_lower:
                return False, f"Rejection reason may indicate proxy discrimination: '{proxy}'"
        
        return True, None


class HRAuditLog:
    """GDPR-compliant audit logging for hiring decisions."""
    
    def __init__(self):
        self.entries: list[dict] = []
    
    def log(self, action: str, candidate_id: str, job_id: str,
            decision: str = None, reason: str = None, score: float = None):
        # Hash candidate ID for privacy
        hashed_id = hashlib.sha256(candidate_id.encode()).hexdigest()[:12]
        
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "candidate_hash": hashed_id,
            "job_id": job_id,
            "decision": decision,
            "reason": reason,
            "score": score
        }
        self.entries.append(entry)
        return entry


class HRRecruitingAgent:
    """AI agent for fair, governed candidate screening."""
    
    def __init__(self, agent_id: str = "hr-recruiting-agent"):
        self.agent_id = agent_id
        self.bias_guard = BiasGuard()
        self.audit_log = HRAuditLog()
        self.candidates: dict[str, Candidate] = {}
        self.jobs: dict[str, JobRequirement] = {}
        
        # Data retention policy (days)
        self.retention_rejected = 180
        self.retention_hired = 2555  # 7 years
        
        # Initialize governance
        if AGENT_OS_AVAILABLE:
            self.policy = create_policy({
                "name": "fair-hiring-policy",
                "rules": [
                    {
                        "action": "screen_candidate",
                        "block_fields": list(PROTECTED_CHARACTERISTICS),
                        "require": ["consistent_criteria", "documented_reason"]
                    },
                    {
                        "action": "reject_candidate",
                        "require": ["bias_check_passed"]
                    }
                ]
            })
    
    def add_job(self, job: JobRequirement):
        """Add a job with screening criteria."""
        self.jobs[job.job_id] = job
    
    def add_candidate(self, candidate: Candidate):
        """Add a candidate with data consent check."""
        if not candidate.data_consent:
            raise ValueError("Candidate must provide data consent (GDPR requirement)")
        
        # Set retention date
        candidate.retention_until = candidate.applied_date + timedelta(
            days=self.retention_rejected
        )
        
        self.candidates[candidate.candidate_id] = candidate
    
    async def screen_candidate(self, candidate_id: str, job_id: str) -> dict:
        """
        Screen a candidate against job requirements.
        Governance ensures fair, bias-free evaluation.
        """
        if candidate_id not in self.candidates:
            return {"error": "Candidate not found"}
        if job_id not in self.jobs:
            return {"error": "Job not found"}
        
        candidate = self.candidates[candidate_id]
        job = self.jobs[job_id]
        
        # Calculate objective score
        score_breakdown = self._calculate_score(candidate, job)
        total_score = score_breakdown["total"]
        
        # Determine decision based on score thresholds
        if total_score >= 0.7:
            decision = Decision.ADVANCE
            reason = "Candidate meets or exceeds requirements"
        elif total_score >= 0.5:
            decision = Decision.HOLD
            reason = "Candidate partially meets requirements - needs review"
        else:
            decision = Decision.REJECT
            reason = f"Candidate does not meet minimum requirements (score: {total_score:.2f})"
        
        # Bias check on rejection reason
        if decision == Decision.REJECT:
            reason_ok, bias_issue = self.bias_guard.check_reason(reason)
            if not reason_ok:
                # Log attempted biased rejection
                self.audit_log.log(
                    "bias_blocked", candidate_id, job_id,
                    reason=bias_issue
                )
                return {"error": f"Rejection blocked: {bias_issue}"}
        
        # Log decision
        self.audit_log.log(
            "screen_candidate", candidate_id, job_id,
            decision=decision.value, reason=reason, score=total_score
        )
        
        return {
            "candidate_id": candidate_id,
            "job_id": job_id,
            "decision": decision.value,
            "score": round(total_score, 3),
            "breakdown": score_breakdown,
            "reason": reason,
            "next_steps": self._get_next_steps(decision)
        }
    
    def _calculate_score(self, candidate: Candidate, job: JobRequirement) -> dict:
        """Calculate objective score based on job requirements."""
        
        # Skills match
        if job.required_skills:
            skills_match = len(
                set(s.lower() for s in candidate.skills) & 
                set(s.lower() for s in job.required_skills)
            ) / len(job.required_skills)
        else:
            skills_match = 1.0
        
        # Experience match
        if job.min_experience_years > 0:
            exp_ratio = candidate.years_experience / job.min_experience_years
            experience_match = min(1.0, exp_ratio)
        else:
            experience_match = 1.0
        
        # Education match
        if job.required_education:
            edu_match = 1.0 if candidate.education.lower() in [
                e.lower() for e in job.required_education
            ] else 0.5
        else:
            edu_match = 1.0
        
        # Certifications (bonus)
        if job.preferred_certifications:
            cert_match = len(
                set(c.lower() for c in candidate.certifications) &
                set(c.lower() for c in job.preferred_certifications)
            ) / len(job.preferred_certifications)
        else:
            cert_match = 0.0
        
        # Weighted total
        total = (
            skills_match * job.weight_skills +
            experience_match * job.weight_experience +
            edu_match * job.weight_education +
            cert_match * job.weight_certifications
        )
        
        return {
            "skills": round(skills_match, 3),
            "experience": round(experience_match, 3),
            "education": round(edu_match, 3),
            "certifications": round(cert_match, 3),
            "total": round(total, 3)
        }
    
    def _get_next_steps(self, decision: Decision) -> str:
        """Get next steps based on decision."""
        steps = {
            Decision.ADVANCE: "Schedule technical interview",
            Decision.HOLD: "Manager review required",
            Decision.REJECT: "Send rejection email (auto-delete data in 180 days)"
        }
        return steps.get(decision, "Unknown")
    
    def cleanup_expired_data(self) -> int:
        """GDPR: Delete candidate data past retention period."""
        now = datetime.now(timezone.utc)
        expired = [
            cid for cid, c in self.candidates.items()
            if c.retention_until and c.retention_until < now
        ]
        
        for cid in expired:
            del self.candidates[cid]
            self.audit_log.log("data_deleted", cid, "N/A", reason="retention_expired")
        
        return len(expired)


async def demo():
    """Demonstrate the HR recruiting agent."""
    print("=" * 60)
    print("HR Recruiting Agent - Agent OS Demo")
    print("=" * 60)
    
    # Initialize agent
    agent = HRRecruitingAgent()
    
    # Add job requirement
    job = JobRequirement(
        job_id="JOB-2024-001",
        title="Senior Software Engineer",
        required_skills=["Python", "AWS", "Kubernetes", "SQL"],
        min_experience_years=5,
        required_education=["Bachelor's", "Master's", "PhD"],
        preferred_certifications=["AWS Solutions Architect", "CKA"]
    )
    agent.add_job(job)
    print(f"\n✓ Added job: {job.title}")
    print(f"  Required: {job.required_skills}")
    print(f"  Min experience: {job.min_experience_years} years")
    
    # Add candidates
    candidates = [
        Candidate(
            candidate_id="CAND-001",
            skills=["Python", "AWS", "Kubernetes", "SQL", "Docker"],
            years_experience=7,
            education="Master's",
            certifications=["AWS Solutions Architect"],
            data_consent=True
        ),
        Candidate(
            candidate_id="CAND-002",
            skills=["Python", "SQL"],
            years_experience=3,
            education="Bachelor's",
            data_consent=True
        ),
        Candidate(
            candidate_id="CAND-003",
            skills=["Python", "AWS", "GCP"],
            years_experience=5,
            education="Bachelor's",
            certifications=["CKA"],
            data_consent=True
        )
    ]
    
    for c in candidates:
        agent.add_candidate(c)
        print(f"✓ Added candidate: {c.candidate_id}")
    
    # Screen candidates
    print("\n--- Screening Results ---")
    for c in candidates:
        result = await agent.screen_candidate(c.candidate_id, job.job_id)
        
        icon = {"advance": "✅", "hold": "⏸️", "reject": "❌"}.get(result["decision"], "?")
        print(f"\n{icon} {result['candidate_id']}: {result['decision'].upper()}")
        print(f"   Score: {result['score']}")
        print(f"   Breakdown: Skills={result['breakdown']['skills']}, "
              f"Exp={result['breakdown']['experience']}, "
              f"Edu={result['breakdown']['education']}")
        print(f"   Next: {result['next_steps']}")
    
    # Demonstrate bias prevention
    print("\n--- Bias Prevention Demo ---")
    biased_data = {
        "skills": ["Python"],
        "age": 45,  # Protected!
        "gender": "female",  # Protected!
        "experience": 5
    }
    print(f"Input with protected fields: {list(biased_data.keys())}")
    sanitized = BiasGuard.sanitize_input(biased_data)
    print(f"Sanitized output: {list(sanitized.keys())}")
    
    # Show audit trail
    print("\n--- Audit Trail (GDPR Compliant) ---")
    for entry in agent.audit_log.entries[-5:]:
        print(f"  [{entry['timestamp'][:19]}] {entry['action']}: "
              f"candidate={entry['candidate_hash']} decision={entry['decision']}")
    
    print("\n" + "=" * 60)
    print("Demo complete - Fair hiring with bias prevention")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(demo())
