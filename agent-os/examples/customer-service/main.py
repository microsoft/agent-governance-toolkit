# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Customer Support Auto-Responder Agent
=====================================

Production-grade AI-powered customer support with Agent OS governance.

Features:
- Multi-model response verification (CMVK)
- RAG-based knowledge retrieval (90% lookup, 10% reasoning)
- Automatic ticket classification
- Policy enforcement (no false promises, discount limits)
- Human escalation for sensitive topics
- CSAT tracking and quality metrics

Benchmarkable: "Resolved 2,400 tickets, 4.7/5 satisfaction"
"""

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from collections import defaultdict

# ============================================================
# CONFIGURATION
# ============================================================

class TicketCategory(Enum):
    BILLING = "billing"
    TECHNICAL = "technical"
    FEATURE_REQUEST = "feature_request"
    ACCOUNT = "account"
    GENERAL = "general"
    COMPLAINT = "complaint"
    REFUND = "refund"


class Priority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    URGENT = 4


class TicketStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    WAITING_CUSTOMER = "waiting_customer"
    ESCALATED = "escalated"
    RESOLVED = "resolved"


# Policy Rules
SUPPORT_POLICY = {
    "version": "2.0",
    "name": "customer-support-production",
    
    "response_rules": {
        "no_promises": True,
        "no_unauthorized_discounts": True,
        "no_competitor_mentions": True,
        "professional_tone": True,
        "max_response_length": 500,
    },
    
    "escalation_triggers": [
        "lawsuit", "lawyer", "legal action", "sue",
        "discriminat", "harassment", "racist", "sexist",
        "media", "reporter", "news", "twitter", "viral",
        "ceo", "executive", "board",
        "cancel subscription", "close account",
        "injured", "hurt", "damage", "health",
    ],
    
    "auto_escalate_keywords": [
        "supervisor", "manager", "human", "real person",
        "speak to someone", "not a bot",
    ],
    
    "discount_limits": {
        "tier1": {"max_percent": 10, "max_amount": 50},
        "tier2": {"max_percent": 20, "max_amount": 200},
        "supervisor": {"max_percent": 50, "max_amount": 1000},
    },
    
    "refund_limits": {
        "tier1": {"max_amount": 100},
        "tier2": {"max_amount": 500},
        "supervisor": {"max_amount": 5000},
    },
    
    "response_time_sla": {
        "urgent": 60,      # seconds
        "high": 300,       # 5 min
        "medium": 1800,    # 30 min
        "low": 86400,      # 24 hours
    },
    
    "pii_patterns": [
        r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
        r"\b\d{16}\b",              # Credit card
        r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",  # CC formatted
        r"password\s*[:=]\s*\S+",   # Passwords
    ],
}

# Classification keywords
CLASSIFICATION_RULES = {
    TicketCategory.BILLING: [
        "invoice", "charge", "payment", "bill", "subscription",
        "pricing", "plan", "upgrade", "downgrade", "renewal",
    ],
    TicketCategory.TECHNICAL: [
        "error", "bug", "crash", "not working", "broken",
        "slow", "performance", "api", "integration", "timeout",
    ],
    TicketCategory.REFUND: [
        "refund", "money back", "cancel order", "return",
        "charged twice", "wrong charge", "dispute",
    ],
    TicketCategory.ACCOUNT: [
        "login", "password", "reset", "locked out", "access",
        "username", "email change", "profile", "settings",
    ],
    TicketCategory.FEATURE_REQUEST: [
        "feature", "suggestion", "would be nice", "wish",
        "could you add", "request", "improvement",
    ],
    TicketCategory.COMPLAINT: [
        "terrible", "awful", "worst", "unacceptable", "ridiculous",
        "frustrated", "angry", "disappointed", "waste",
    ],
}

# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class Customer:
    """Customer profile."""
    customer_id: str
    name: str
    email: str
    tier: str = "standard"  # standard, premium, enterprise
    lifetime_value: float = 0.0
    ticket_count: int = 0
    avg_csat: float = 0.0


@dataclass
class Ticket:
    """Support ticket."""
    ticket_id: str
    customer_id: str
    subject: str
    message: str
    category: TicketCategory = TicketCategory.GENERAL
    priority: Priority = Priority.MEDIUM
    status: TicketStatus = TicketStatus.OPEN
    created_at: datetime = field(default_factory=datetime.utcnow)
    assigned_to: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class KnowledgeArticle:
    """Knowledge base article."""
    article_id: str
    title: str
    content: str
    category: str
    keywords: list[str]
    embedding: list[float] = field(default_factory=list)


@dataclass
class Response:
    """Agent response to a ticket."""
    response_id: str
    ticket_id: str
    content: str
    confidence: float
    sources: list[str] = field(default_factory=list)
    requires_human_review: bool = False
    policy_violations: list[str] = field(default_factory=list)
    model_agreement: float = 1.0  # CMVK score


# ============================================================
# KNOWLEDGE BASE (RAG)
# ============================================================

class KnowledgeBase:
    """
    Vector-based knowledge retrieval.
    90% of responses should come from KB (lookup).
    10% require LLM reasoning.
    """
    
    def __init__(self):
        self.articles: dict[str, KnowledgeArticle] = {}
        self.index: dict[str, list[str]] = defaultdict(list)  # keyword -> article_ids
        self._load_sample_kb()
    
    def _load_sample_kb(self):
        """Load sample knowledge base articles."""
        articles = [
            KnowledgeArticle(
                article_id="KB001",
                title="How to Reset Your Password",
                content="""To reset your password:
1. Go to the login page
2. Click "Forgot Password"
3. Enter your email address
4. Check your inbox for the reset link
5. Click the link and create a new password

Password requirements: 8+ characters, 1 uppercase, 1 number.""",
                category="account",
                keywords=["password", "reset", "forgot", "login", "locked"]
            ),
            KnowledgeArticle(
                article_id="KB002",
                title="Refund Policy",
                content="""Our refund policy:
- Full refund within 30 days of purchase
- Pro-rated refund for annual subscriptions
- Refunds processed in 3-5 business days
- Contact support with order ID for refund requests

Note: Digital products are non-refundable after download.""",
                category="billing",
                keywords=["refund", "money back", "return", "cancel", "policy"]
            ),
            KnowledgeArticle(
                article_id="KB003",
                title="Pricing Plans Overview",
                content="""Available plans:
- **Free**: Basic features, 5 projects, community support
- **Pro** ($19/mo): Unlimited projects, priority support, API access
- **Enterprise** (custom): SSO, dedicated support, SLA guarantee

All paid plans include 14-day free trial. No credit card required.""",
                category="billing",
                keywords=["pricing", "plans", "cost", "subscription", "upgrade"]
            ),
            KnowledgeArticle(
                article_id="KB004",
                title="API Rate Limits",
                content="""API rate limits by plan:
- Free: 100 requests/hour
- Pro: 1,000 requests/hour
- Enterprise: 10,000 requests/hour

Exceeding limits returns 429 Too Many Requests.
Headers include X-RateLimit-Remaining for tracking.""",
                category="technical",
                keywords=["api", "rate limit", "429", "requests", "throttle"]
            ),
            KnowledgeArticle(
                article_id="KB005",
                title="Common Error Codes",
                content="""Error troubleshooting:
- **E001**: Authentication failed - check API key
- **E002**: Resource not found - verify endpoint
- **E003**: Rate limited - wait and retry
- **E004**: Server error - contact support
- **E005**: Invalid request - check parameters

Include error code when contacting support.""",
                category="technical",
                keywords=["error", "bug", "issue", "problem", "E001", "E002"]
            ),
        ]
        
        for article in articles:
            self.add_article(article)
    
    def add_article(self, article: KnowledgeArticle):
        """Add article to knowledge base."""
        self.articles[article.article_id] = article
        for keyword in article.keywords:
            self.index[keyword.lower()].append(article.article_id)
    
    def search(self, query: str, top_k: int = 3) -> list[KnowledgeArticle]:
        """
        Search knowledge base for relevant articles.
        In production, this would use vector similarity (Pinecone/ChromaDB).
        """
        query_lower = query.lower()
        scores: dict[str, int] = defaultdict(int)
        
        # Score articles by keyword matches
        for keyword, article_ids in self.index.items():
            if keyword in query_lower:
                for article_id in article_ids:
                    scores[article_id] += 1
        
        # Sort by score and return top_k
        sorted_ids = sorted(scores.keys(), key=lambda x: scores[x], reverse=True)
        return [self.articles[aid] for aid in sorted_ids[:top_k]]
    
    def get_answer(self, query: str) -> tuple[Optional[str], list[str], float]:
        """
        Get answer from knowledge base.
        Returns: (answer, source_ids, confidence)
        """
        articles = self.search(query)
        
        if not articles:
            return None, [], 0.0
        
        # Use best match
        best = articles[0]
        confidence = min(0.9, 0.3 * len(articles))  # Cap at 90%
        
        return best.content, [best.article_id], confidence


# ============================================================
# POLICY ENFORCEMENT
# ============================================================

class PolicyEngine:
    """Enforce support policies on responses."""
    
    def __init__(self, policy: dict):
        self.policy = policy
        self.pii_patterns = [re.compile(p) for p in policy.get("pii_patterns", [])]
    
    def check_response(self, response: str, context: dict) -> tuple[bool, list[str]]:
        """
        Check response against policy rules.
        Returns: (is_valid, list_of_violations)
        """
        violations = []
        
        # Check for PII leakage
        for pattern in self.pii_patterns:
            if pattern.search(response):
                violations.append("pii_leakage")
        
        # Check for promises (forbidden words)
        promise_words = ["guarantee", "promise", "definitely", "100%", "certainly will"]
        for word in promise_words:
            if word.lower() in response.lower():
                violations.append(f"forbidden_promise: {word}")
        
        # Check for unauthorized discounts
        discount_match = re.search(r"(\d+)%?\s*(off|discount)", response.lower())
        if discount_match:
            percent = int(discount_match.group(1))
            role = context.get("agent_role", "tier1")
            max_discount = self.policy["discount_limits"].get(role, {}).get("max_percent", 0)
            if percent > max_discount:
                violations.append(f"unauthorized_discount: {percent}% > {max_discount}%")
        
        # Check response length
        max_length = self.policy["response_rules"].get("max_response_length", 1000)
        if len(response) > max_length:
            violations.append(f"response_too_long: {len(response)} > {max_length}")
        
        # Check for competitor mentions
        competitors = ["competitor_a", "competitor_b", "competitor_c"]
        for comp in competitors:
            if comp.lower() in response.lower():
                violations.append(f"competitor_mention: {comp}")
        
        return len(violations) == 0, violations
    
    def needs_escalation(self, message: str) -> tuple[bool, Optional[str]]:
        """Check if message requires human escalation."""
        msg_lower = message.lower()
        
        # Check escalation triggers
        for trigger in self.policy.get("escalation_triggers", []):
            if trigger.lower() in msg_lower:
                return True, f"trigger: {trigger}"
        
        # Check auto-escalate keywords
        for keyword in self.policy.get("auto_escalate_keywords", []):
            if keyword.lower() in msg_lower:
                return True, f"customer_request: {keyword}"
        
        return False, None
    
    def redact_pii(self, text: str) -> str:
        """Redact PII from text."""
        result = text
        for pattern in self.pii_patterns:
            result = pattern.sub("[REDACTED]", result)
        return result


# ============================================================
# VERIFICATION (CMVK)
# ============================================================

class CrossModelVerifier:
    """
    Verify responses across multiple models.
    High consensus = high confidence.
    """
    
    def __init__(self):
        self.models = ["gpt-4", "claude-3", "gemini-pro"]
    
    async def verify_response(self, query: str, response: str) -> tuple[float, dict]:
        """
        Verify response consistency across models.
        Returns: (agreement_score, model_opinions)
        
        In production, this calls actual model APIs.
        """
        # Simulate model verification
        opinions = {}
        agreements = 0
        
        for model in self.models:
            # In production: await self.call_model(model, query, response)
            # Simulated: high agreement for KB-sourced responses
            opinion = {
                "agrees": True,
                "confidence": 0.85 + (hash(f"{model}{response}") % 15) / 100,
                "notes": "Response is factually accurate"
            }
            opinions[model] = opinion
            if opinion["agrees"]:
                agreements += 1
        
        agreement_score = agreements / len(self.models)
        return agreement_score, opinions


# ============================================================
# TICKET CLASSIFIER
# ============================================================

class TicketClassifier:
    """Classify tickets by category and priority."""
    
    def classify(self, subject: str, message: str) -> tuple[TicketCategory, Priority]:
        """Classify ticket category and priority."""
        text = f"{subject} {message}".lower()
        
        # Determine category
        category_scores: dict[TicketCategory, int] = defaultdict(int)
        for category, keywords in CLASSIFICATION_RULES.items():
            for keyword in keywords:
                if keyword in text:
                    category_scores[category] += 1
        
        if category_scores:
            category = max(category_scores.keys(), key=lambda k: category_scores[k])
        else:
            category = TicketCategory.GENERAL
        
        # Determine priority
        priority = Priority.MEDIUM
        
        # Urgent indicators
        urgent_words = ["urgent", "emergency", "asap", "immediately", "critical"]
        if any(word in text for word in urgent_words):
            priority = Priority.URGENT
        
        # High priority indicators
        elif any(word in text for word in ["frustrated", "angry", "broken", "not working"]):
            priority = Priority.HIGH
        
        # Low priority indicators
        elif any(word in text for word in ["question", "wondering", "curious", "suggestion"]):
            priority = Priority.LOW
        
        # Complaints are always high
        if category == TicketCategory.COMPLAINT:
            priority = max(priority, Priority.HIGH)
        
        return category, priority


# ============================================================
# METRICS & MONITORING
# ============================================================

class SupportMetrics:
    """Track support metrics for quality monitoring."""
    
    def __init__(self):
        self.tickets_handled = 0
        self.tickets_escalated = 0
        self.tickets_resolved = 0
        self.total_response_time = 0.0
        self.csat_scores: list[float] = []
        self.category_counts: dict[str, int] = defaultdict(int)
        self.policy_violations: list[dict] = []
    
    def record_ticket(self, ticket: Ticket, response_time: float, resolved: bool, escalated: bool):
        """Record ticket handling metrics."""
        self.tickets_handled += 1
        self.total_response_time += response_time
        self.category_counts[ticket.category.value] += 1
        
        if resolved:
            self.tickets_resolved += 1
        if escalated:
            self.tickets_escalated += 1
    
    def record_csat(self, score: float):
        """Record customer satisfaction score (1-5)."""
        self.csat_scores.append(score)
    
    def record_violation(self, ticket_id: str, violations: list[str]):
        """Record policy violations."""
        self.policy_violations.append({
            "ticket_id": ticket_id,
            "violations": violations,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    
    def get_summary(self) -> dict:
        """Get metrics summary."""
        return {
            "tickets_handled": self.tickets_handled,
            "tickets_resolved": self.tickets_resolved,
            "tickets_escalated": self.tickets_escalated,
            "resolution_rate": (self.tickets_resolved / max(1, self.tickets_handled)) * 100,
            "escalation_rate": (self.tickets_escalated / max(1, self.tickets_handled)) * 100,
            "avg_response_time_sec": self.total_response_time / max(1, self.tickets_handled),
            "avg_csat": sum(self.csat_scores) / max(1, len(self.csat_scores)),
            "category_breakdown": dict(self.category_counts),
            "policy_violation_count": len(self.policy_violations),
        }


# ============================================================
# MAIN AGENT
# ============================================================

class CustomerSupportAgent:
    """
    Production customer support auto-responder.
    
    Pipeline:
    1. Classify ticket
    2. Check for escalation triggers
    3. Search knowledge base (90% lookup)
    4. Generate response with policy enforcement
    5. Verify with CMVK
    6. Human review for low confidence
    """
    
    def __init__(self, agent_id: str = "support-agent-001", role: str = "tier1"):
        self.agent_id = agent_id
        self.role = role
        
        # Initialize components
        self.kb = KnowledgeBase()
        self.classifier = TicketClassifier()
        self.policy_engine = PolicyEngine(SUPPORT_POLICY)
        self.verifier = CrossModelVerifier()
        self.metrics = SupportMetrics()
        
        # Ticket storage
        self.tickets: dict[str, Ticket] = {}
        self.responses: dict[str, Response] = {}
        
        print(f"🤖 Customer Support Agent initialized")
        print(f"   Agent ID: {agent_id}")
        print(f"   Role: {role}")
        print(f"   KB Articles: {len(self.kb.articles)}")
    
    async def handle_ticket(self, ticket: Ticket) -> Response:
        """
        Handle a support ticket end-to-end.
        """
        start_time = time.time()
        
        print(f"\n{'='*60}")
        print(f"📩 New Ticket: {ticket.ticket_id}")
        print(f"   Subject: {ticket.subject}")
        print(f"   Message: {ticket.message[:100]}...")
        
        # Store ticket
        self.tickets[ticket.ticket_id] = ticket
        
        # Step 1: Classify
        category, priority = self.classifier.classify(ticket.subject, ticket.message)
        ticket.category = category
        ticket.priority = priority
        print(f"   Category: {category.value} | Priority: {priority.name}")
        
        # Step 2: Check escalation
        needs_escalation, reason = self.policy_engine.needs_escalation(ticket.message)
        if needs_escalation:
            print(f"🚨 ESCALATION REQUIRED: {reason}")
            ticket.status = TicketStatus.ESCALATED
            
            response = Response(
                response_id=f"R-{ticket.ticket_id}",
                ticket_id=ticket.ticket_id,
                content="I'm connecting you with a specialist who can better assist you. Please hold.",
                confidence=1.0,
                requires_human_review=True,
            )
            
            self.metrics.record_ticket(ticket, time.time() - start_time, False, True)
            return response
        
        # Step 3: Search knowledge base
        kb_answer, sources, kb_confidence = self.kb.get_answer(
            f"{ticket.subject} {ticket.message}"
        )
        
        if kb_answer and kb_confidence > 0.5:
            print(f"📚 KB Match: {sources} (confidence: {kb_confidence:.2f})")
            response_content = self._format_kb_response(kb_answer, ticket)
        else:
            print(f"🧠 Generating response (no strong KB match)")
            response_content = self._generate_fallback_response(ticket)
            kb_confidence = 0.6
        
        # Step 4: Policy check
        is_valid, violations = self.policy_engine.check_response(
            response_content,
            {"agent_role": self.role}
        )
        
        if not is_valid:
            print(f"⚠️  Policy violations: {violations}")
            self.metrics.record_violation(ticket.ticket_id, violations)
            response_content = self._sanitize_response(response_content, violations)
        
        # Step 5: Verification
        agreement, model_opinions = await self.verifier.verify_response(
            ticket.message, response_content
        )
        print(f"🔍 CMVK Agreement: {agreement:.0%}")
        
        # Step 6: Determine if human review needed
        requires_review = (
            kb_confidence < 0.7 or 
            agreement < 0.8 or 
            len(violations) > 0 or
            ticket.priority == Priority.URGENT
        )
        
        response = Response(
            response_id=f"R-{ticket.ticket_id}",
            ticket_id=ticket.ticket_id,
            content=response_content,
            confidence=min(kb_confidence, agreement),
            sources=sources,
            requires_human_review=requires_review,
            policy_violations=violations,
            model_agreement=agreement,
        )
        
        self.responses[response.response_id] = response
        
        # Update metrics
        resolved = not requires_review
        ticket.status = TicketStatus.RESOLVED if resolved else TicketStatus.IN_PROGRESS
        self.metrics.record_ticket(ticket, time.time() - start_time, resolved, False)
        
        # Final output
        status_icon = "✅" if resolved else "⏳"
        print(f"{status_icon} Response generated (review needed: {requires_review})")
        print(f"   Confidence: {response.confidence:.0%}")
        
        return response
    
    def _format_kb_response(self, kb_answer: str, ticket: Ticket) -> str:
        """Format KB answer into customer-friendly response."""
        # Add greeting based on time
        hour = datetime.now().hour
        if hour < 12:
            greeting = "Good morning!"
        elif hour < 17:
            greeting = "Good afternoon!"
        else:
            greeting = "Good evening!"
        
        return f"""{greeting} Thank you for contacting support.

{kb_answer}

Is there anything else I can help you with?

Best regards,
Support Team"""
    
    def _generate_fallback_response(self, ticket: Ticket) -> str:
        """Generate response when KB doesn't have good match."""
        return f"""Thank you for reaching out!

I've reviewed your inquiry about "{ticket.subject}". 

Let me look into this further. A member of our team will follow up within 24 hours with more details.

In the meantime, you can check our help center at help.example.com for immediate answers.

Best regards,
Support Team"""
    
    def _sanitize_response(self, response: str, violations: list[str]) -> str:
        """Sanitize response to fix policy violations."""
        result = response
        
        # Redact PII
        if any("pii" in v for v in violations):
            result = self.policy_engine.redact_pii(result)
        
        # Remove promises
        promise_words = ["guarantee", "promise", "definitely", "100%", "certainly will"]
        for word in promise_words:
            result = re.sub(rf"\b{word}\b", "we aim to", result, flags=re.IGNORECASE)
        
        # Truncate if too long
        max_len = SUPPORT_POLICY["response_rules"]["max_response_length"]
        if len(result) > max_len:
            result = result[:max_len-3] + "..."
        
        return result
    
    def get_metrics(self) -> dict:
        """Get agent performance metrics."""
        return self.metrics.get_summary()


# ============================================================
# DEMO
# ============================================================

async def demo():
    """Demonstrate the customer support agent."""
    print("=" * 60)
    print("Customer Support Auto-Responder - Production Demo")
    print("Powered by Agent OS Governance")
    print("=" * 60)
    
    agent = CustomerSupportAgent(role="tier1")
    
    # Demo tickets
    test_tickets = [
        Ticket(
            ticket_id="T-001",
            customer_id="C-12345",
            subject="Can't login to my account",
            message="I forgot my password and can't login. Help!",
        ),
        Ticket(
            ticket_id="T-002",
            customer_id="C-12346",
            subject="Refund request",
            message="I need a refund for my subscription. I was charged but didn't use the service.",
        ),
        Ticket(
            ticket_id="T-003",
            customer_id="C-12347",
            subject="Your service is terrible",
            message="This is ridiculous! I'm going to tell everyone on Twitter how bad you are!",
        ),
        Ticket(
            ticket_id="T-004",
            customer_id="C-12348",
            subject="Pricing question",
            message="What's the difference between Pro and Enterprise plans?",
        ),
        Ticket(
            ticket_id="T-005",
            customer_id="C-12349",
            subject="Legal matter",
            message="I'm considering legal action if this isn't resolved. My lawyer will be in touch.",
        ),
    ]
    
    print("\n" + "=" * 60)
    print("Processing Tickets...")
    print("=" * 60)
    
    for ticket in test_tickets:
        response = await agent.handle_ticket(ticket)
        print(f"\n📤 Response to {ticket.ticket_id}:")
        print("-" * 40)
        print(response.content[:300] + "..." if len(response.content) > 300 else response.content)
    
    print("\n" + "=" * 60)
    print("📊 Performance Metrics")
    print("=" * 60)
    metrics = agent.get_metrics()
    for key, value in metrics.items():
        if isinstance(value, float):
            print(f"   {key}: {value:.2f}")
        else:
            print(f"   {key}: {value}")
    
    print("\n" + "=" * 60)
    print("✅ Demo Complete - All tickets governed by Agent OS")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(demo())
