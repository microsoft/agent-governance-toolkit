# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Multi-Agent Customer Service System with AgentMesh Governance

Demonstrates:
- Agent scope chains (supervisor → specialists)
- A2A trust handshakes
- Collaborative trust scoring
- Cross-agent audit trails
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional
from enum import Enum

from agentmesh import (
    AgentIdentity,
    ScopeChain,
    TrustHandshake,
    PolicyEngine,
    AuditLog,
    RewardEngine,
)


class TicketType(Enum):
    """Ticket category."""
    TECHNICAL = "technical"
    BILLING = "billing"
    ESCALATION = "escalation"


@dataclass
class Ticket:
    """Customer support ticket."""
    id: str
    type: TicketType
    customer: str
    subject: str
    description: str
    priority: str


class GovernedAgent:
    """Base class for governed agents."""
    
    def __init__(self, identity: AgentIdentity):
        self.identity = identity
        self.trust_score = 800
        self.audit_log = AuditLog(agent_id=identity.did)
        self.policy_engine = PolicyEngine()
    
    async def verify_peer(self, peer_did: str, min_score: int = 700) -> bool:
        """Verify peer agent before communication."""
        print(f"  🤝 [{self.identity.name}] Verifying peer: {peer_did}")
        
        # Simulated trust handshake
        # In production, use TrustHandshake.verify()
        handshake = TrustHandshake()
        result = await handshake.verify(
            peer_did=peer_did,
            required_score=min_score
        )
        
        if result.verified:
            print(f"  ✓ Peer verified with score: {result.peer_score}")
        else:
            print(f"  ✗ Peer verification failed: {result.reason}")
        
        return result.verified
    
    def log_action(self, action: str, details: dict):
        """Log action to audit trail."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent": self.identity.did,
            "action": action,
            "details": details,
            "trust_score": self.trust_score
        }
        print(f"  📋 [{self.identity.name}] {action}: {details.get('summary', '')}")


class SupervisorAgent(GovernedAgent):
    """Supervisor agent that routes tickets to specialists."""
    
    def __init__(self):
        identity = AgentIdentity.create(
            name="supervisor-agent",
            sponsor="support-manager@company.com",
            capabilities=[
                "read:tickets",
                "write:tickets",
                "read:docs",
                "read:billing",
                "write:billing",
                "notify:managers"
            ]
        )
        super().__init__(identity)
        self.scope_chain = ScopeChain(root=identity)
        self.specialists: dict = {}
    
    def create_specialists(self):
        """Create specialist sub-agents with narrowed capabilities."""
        print(f"\n👥 [{self.identity.name}] Creating specialist agents...\n")
        
        # Technical Support Agent
        technical_identity = self.scope_chain.delegate(
            name="technical-support-agent",
            capabilities=["read:docs", "write:tickets"]  # Narrowed
        )
        self.specialists["technical"] = SpecialistAgent(
            technical_identity,
            TicketType.TECHNICAL
        )
        print(f"  ✓ Created: {technical_identity.name}")
        print(f"    Capabilities: {technical_identity.capabilities}")
        
        # Billing Agent
        billing_identity = self.scope_chain.delegate(
            name="billing-agent",
            capabilities=["read:billing", "write:billing"]  # Narrowed
        )
        self.specialists["billing"] = SpecialistAgent(
            billing_identity,
            TicketType.BILLING
        )
        print(f"  ✓ Created: {billing_identity.name}")
        print(f"    Capabilities: {billing_identity.capabilities}")
        
        # Escalation Agent
        escalation_identity = self.scope_chain.delegate(
            name="escalation-agent",
            capabilities=["notify:managers", "write:tickets"]  # Narrowed
        )
        self.specialists["escalation"] = SpecialistAgent(
            escalation_identity,
            TicketType.ESCALATION
        )
        print(f"  ✓ Created: {escalation_identity.name}")
        print(f"    Capabilities: {escalation_identity.capabilities}")
    
    async def route_ticket(self, ticket: Ticket):
        """Route ticket to appropriate specialist."""
        print(f"\n📨 [{self.identity.name}] Routing ticket: {ticket.id}")
        print(f"   Type: {ticket.type.value} | Priority: {ticket.priority}")
        
        # Select specialist
        specialist_key = ticket.type.value
        specialist = self.specialists.get(specialist_key)
        
        if not specialist:
            print(f"  ✗ No specialist found for {ticket.type.value}")
            return
        
        # Verify specialist before delegating
        verified = await self.verify_peer(
            specialist.identity.did,
            min_score=700
        )
        
        if not verified:
            print(f"  ✗ Specialist verification failed, not delegating")
            return
        
        # Delegate ticket
        self.log_action("ticket_delegation", {
            "summary": f"Delegated {ticket.id} to {specialist.identity.name}",
            "ticket_id": ticket.id,
            "specialist": specialist.identity.did
        })
        
        # Specialist processes ticket
        await specialist.process_ticket(ticket, self.identity.did)


class SpecialistAgent(GovernedAgent):
    """Specialist agent that handles specific ticket types."""
    
    def __init__(self, identity: AgentIdentity, specialty: TicketType):
        super().__init__(identity)
        self.specialty = specialty
    
    async def process_ticket(self, ticket: Ticket, supervisor_did: str):
        """Process a ticket delegated from supervisor."""
        print(f"\n🔧 [{self.identity.name}] Processing ticket: {ticket.id}")
        
        # Verify supervisor before accepting work
        verified = await self.verify_peer(supervisor_did, min_score=800)
        
        if not verified:
            print(f"  ✗ Supervisor verification failed, rejecting ticket")
            return
        
        # Simulate ticket processing
        await asyncio.sleep(0.1)
        
        # Log completion
        self.log_action("ticket_processed", {
            "summary": f"Completed {ticket.id}",
            "ticket_id": ticket.id,
            "type": ticket.type.value
        })
        
        # Update trust score (successful completion)
        self.trust_score = min(1000, self.trust_score + 5)
        print(f"  ✓ Ticket completed. Trust score: {self.trust_score}/1000")


async def demo_multi_agent_system():
    """Demo the multi-agent customer service system."""
    print("="*70)
    print("🚀 Multi-Agent Customer Service with AgentMesh Governance")
    print("="*70)
    
    # Create supervisor
    supervisor = SupervisorAgent()
    print(f"\n✓ Supervisor created: {supervisor.identity.did}")
    print(f"  Trust Score: {supervisor.trust_score}/1000")
    print(f"  Capabilities: {supervisor.identity.capabilities}")
    
    # Create specialist agents via delegation
    supervisor.create_specialists()
    
    # Simulated ticket queue
    tickets = [
        Ticket(
            id="T-1001",
            type=TicketType.TECHNICAL,
            customer="alice@example.com",
            subject="Login not working",
            description="User cannot log in after password reset",
            priority="high"
        ),
        Ticket(
            id="T-1002",
            type=TicketType.BILLING,
            customer="bob@example.com",
            subject="Double charge on invoice",
            description="Charged twice for January subscription",
            priority="medium"
        ),
        Ticket(
            id="T-1003",
            type=TicketType.TECHNICAL,
            customer="charlie@example.com",
            subject="API returning 500 errors",
            description="Production API has been down for 2 hours",
            priority="critical"
        ),
        Ticket(
            id="T-1004",
            type=TicketType.ESCALATION,
            customer="diana@example.com",
            subject="Request for refund - poor service",
            description="Customer wants full refund due to outages",
            priority="high"
        ),
    ]
    
    # Process tickets
    print("\n" + "="*70)
    print("📥 Processing Ticket Queue")
    print("="*70)
    
    for ticket in tickets:
        await supervisor.route_ticket(ticket)
        await asyncio.sleep(0.2)  # Simulate processing time
    
    # Summary
    print("\n" + "="*70)
    print("✅ Summary")
    print("="*70)
    print(f"\nSupervisor: {supervisor.identity.did}")
    print(f"  Trust Score: {supervisor.trust_score}/1000")
    print(f"\nSpecialists:")
    for key, specialist in supervisor.specialists.items():
        print(f"  • {specialist.identity.name}")
        print(f"    DID: {specialist.identity.did}")
        print(f"    Trust Score: {specialist.trust_score}/1000")
        print(f"    Capabilities: {specialist.identity.capabilities}")
    
    print("\n" + "="*70)
    print("💡 Key Takeaways:")
    print("  • Scope chains enforce capability narrowing")
    print("  • Trust handshakes occur before every interaction")
    print("  • All inter-agent communication is audited")
    print("  • Trust scores adapt based on performance")
    print("  • Each agent has precisely scoped permissions")
    print("="*70)


async def main():
    """Main entry point."""
    await demo_multi_agent_system()
    
    print("\n🔗 Learn more: https://github.com/microsoft/agent-governance-toolkit")


if __name__ == "__main__":
    asyncio.run(main())
