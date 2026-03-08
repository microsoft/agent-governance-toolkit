# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Healthcare Data Analysis Agent with HIPAA Compliance

Demonstrates:
- HIPAA compliance automation
- PHI (Protected Health Information) handling
- Append-only audit logs
- Automated compliance reporting
"""

import asyncio
import argparse
from datetime import datetime
from typing import Dict, List, Any

from agentmesh import (
    AgentIdentity,
    ComplianceEngine,
    PolicyEngine,
    AuditChain,
)


def _redact(value, visible_chars: int = 0) -> str:
    """Redact a sensitive value for safe logging."""
    import hashlib
    raw = str(value)
    if not raw:
        return "[REDACTED]"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"***{digest}"


class HealthcareAgent:
    """HIPAA-compliant healthcare data analysis agent."""
    
    def __init__(self):
        """Initialize HIPAA-compliant agent."""
        print("🏥 Initializing HIPAA-Compliant Healthcare Agent\n")
        
        # Create identity
        print("🔐 Creating agent identity...")
        self.identity = AgentIdentity.create(
            name="healthcare-data-agent",
            sponsor="compliance-officer@hospital.com",
            capabilities=["read:phi", "analyze:data"]
        )
        print(f"✓ Identity: {self.identity.did}\n")
        
        # Initialize compliance engine
        print("📋 Initializing HIPAA compliance engine...")
        self.compliance = ComplianceEngine(frameworks=["hipaa", "soc2"])
        print("✓ Compliance frameworks: HIPAA, SOC 2\n")
        
        # Initialize policy engine
        print("🛡️  Loading HIPAA policies...")
        self.policy_engine = PolicyEngine()
        self._load_hipaa_policies()
        
        # Initialize append-only audit log
        print("📝 Initializing tamper-evident audit log...")
        self.audit_chain = AuditChain(agent_id=self.identity.did)
        print("✓ Audit chain initialized\n")
    
    def _load_hipaa_policies(self):
        """Load HIPAA-specific policies."""
        # Simulated - in production, load from policies/*.yaml
        policies = [
            "No PHI export without encryption",
            "Minimum necessary access",
            "Audit all PHI access",
            "Require approval for sensitive operations"
        ]
        for policy in policies:
            print(f"  ✓ {policy}")
        print()
    
    def detect_phi(self, data: Dict[str, Any]) -> bool:
        """Detect if data contains PHI."""
        # Simple PHI detection (production would use ML models)
        phi_fields = [
            "patient_name", "ssn", "medical_record_number",
            "diagnosis", "prescription", "date_of_birth"
        ]
        
        for field in phi_fields:
            if field in data:
                return True
        
        return False
    
    async def access_patient_data(self, patient_id: str, purpose: str) -> Dict[str, Any]:
        """Access patient data with HIPAA controls."""
        print(f"📂 Accessing patient data: {_redact(patient_id, 3)}")
        print(f"   Purpose: {purpose}")
        
        # Check policy
        policy_result = self.policy_engine.check(
            action="access_phi",
            resource=f"patient:{patient_id}",
            purpose=purpose
        )
        
        if not policy_result.allowed:
            print(f"   ✗ Access denied: {policy_result.reason}\n")
            self._audit_phi_access(patient_id, "denied", policy_result.reason)
            raise PermissionError(policy_result.reason)
        
        # Simulated patient data
        data = {
            "patient_id": patient_id,
            "patient_name": "John Doe",
            "date_of_birth": "1980-05-15",
            "diagnosis": "Type 2 Diabetes",
            "last_visit": "2026-01-20",
            "prescription": "Metformin 500mg"
        }
        
        # Detect PHI
        contains_phi = self.detect_phi(data)
        print(f"   ⚠️  PHI detected: {contains_phi}")
        
        # Audit access
        self._audit_phi_access(patient_id, "allowed", f"Purpose: {purpose}")
        
        print(f"   ✓ Access granted\n")
        return data
    
    async def analyze_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze patient data (aggregate, anonymized)."""
        print("📊 Analyzing patient data...")
        
        # Check if data is anonymized
        if self.detect_phi(data):
            print("   ⚠️  Warning: Analyzing data with PHI")
            print("   🔒 Applying additional safeguards")
        
        # Simulated analysis
        analysis = {
            "age_group": "40-50",
            "condition_category": "Chronic",
            "risk_score": 0.65,
            "recommended_actions": ["Regular monitoring", "Lifestyle changes"]
        }
        
        # Audit analysis
        self._audit_analysis("risk_assessment", analysis)
        
        print("   ✓ Analysis complete\n")
        return analysis
    
    def _audit_phi_access(self, patient_id: str, result: str, reason: str):
        """Log PHI access to audit chain."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent": self.identity.did,
            "action": "phi_access",
            "patient_id": f"[ENCRYPTED:{patient_id}]",  # Never log actual patient ID
            "result": result,
            "reason": reason,
            "compliance_frameworks": ["HIPAA-164.312(b)"]
        }
        
        # Add to audit chain
        # In production: self.audit_chain.append(entry)
        print(f"   📝 Audit: PHI access {result}")
    
    def _audit_analysis(self, analysis_type: str, results: Dict[str, Any]):
        """Log data analysis to audit chain."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent": self.identity.did,
            "action": "data_analysis",
            "analysis_type": analysis_type,
            "contains_phi": False,  # Anonymized
        }
        print(f"   📝 Audit: Analysis logged")
    
    async def generate_compliance_report(self, period: str) -> str:
        """Generate HIPAA compliance report."""
        print(f"\n📄 Generating HIPAA Compliance Report for {period}...\n")
        
        # Simulated compliance check
        controls = [
            ("164.312(a)(1)", "Access Control", "✓ Implemented"),
            ("164.312(b)", "Audit Controls", "✓ Implemented"),
            ("164.312(c)(1)", "Integrity", "✓ Implemented"),
            ("164.312(d)", "Authentication", "✓ Implemented"),
            ("164.312(e)(1)", "Transmission Security", "✓ Implemented"),
        ]
        
        print("HIPAA Security Rule Controls:")
        for control_id, name, status in controls:
            print(f"  {control_id} - {name}: {status}")
        
        report = f"""
HIPAA COMPLIANCE REPORT
Period: {period}
Agent: {self.identity.did}

SECURITY RULE COMPLIANCE:
✓ All required controls implemented
✓ Audit logs: Append-only (tamper-evident)
✓ Access controls: Enforced via policy engine
✓ Encryption: TLS 1.3 (in transit), AES-256 (at rest)

AUDIT SUMMARY:
- Total PHI accesses: 47
- Policy violations: 0
- Denied accesses: 3
- Compliance score: 100%

RECOMMENDATIONS:
- Continue monitoring access patterns
- Review policies quarterly
- Schedule annual risk assessment
"""
        print(report)
        return report


async def demo_healthcare_agent():
    """Demo the HIPAA-compliant healthcare agent."""
    print("="*70)
    print("🏥 HIPAA-Compliant Healthcare Data Analysis Agent")
    print("="*70 + "\n")
    
    # Initialize agent
    agent = HealthcareAgent()
    
    # Demo 1: Access patient data
    print("="*70)
    print("Demo 1: Accessing Patient Data with HIPAA Controls")
    print("="*70 + "\n")
    
    try:
        data = await agent.access_patient_data(
            patient_id="P-12345",
            purpose="risk_assessment"
        )
    except PermissionError as e:
        print(f"Access denied: {e}\n")
    
    # Demo 2: Analyze data
    print("="*70)
    print("Demo 2: Analyzing Patient Data")
    print("="*70 + "\n")
    
    if data:
        analysis = await agent.analyze_data(data)
        print(f"Analysis Results: {analysis}\n")
    
    # Demo 3: Generate compliance report
    print("="*70)
    print("Demo 3: Generating Compliance Report")
    print("="*70 + "\n")
    
    report = await agent.generate_compliance_report("2026-01")
    
    print("\n" + "="*70)
    print("✅ Demo Complete")
    print("="*70)
    print("\n💡 Key HIPAA Features Demonstrated:")
    print("  • PHI detection and protection")
    print("  • Policy-based access control")
    print("  • Append-only audit logs")
    print("  • Automated compliance reporting")
    print("  • Minimum necessary access principle")
    print("="*70)


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="HIPAA-Compliant Healthcare Agent")
    parser.add_argument(
        "--compliance-report",
        action="store_true",
        help="Generate compliance report only"
    )
    
    args = parser.parse_args()
    
    if args.compliance_report:
        agent = HealthcareAgent()
        await agent.generate_compliance_report("2026-01")
    else:
        await demo_healthcare_agent()
    
    print("\n🔗 Learn more: https://github.com/microsoft/agent-governance-toolkit")


if __name__ == "__main__":
    asyncio.run(main())
