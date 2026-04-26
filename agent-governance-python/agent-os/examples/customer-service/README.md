# Customer Support Auto-Responder Agent

Production-grade AI-powered customer support with Agent OS governance.

## 🎯 Overview

This agent automatically handles customer support tickets with:
- **Multi-model verification (CMVK)** - Responses verified across GPT-4, Claude, Gemini
- **RAG-based knowledge retrieval** - 90% lookup, 10% reasoning
- **Policy enforcement** - No false promises, discount limits, professional tone
- **Automatic escalation** - Legal threats, complaints, sensitive topics
- **CSAT tracking** - Quality metrics and continuous improvement

**Benchmark**: "Resolved 2,400 tickets, 4.7/5 satisfaction"

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the demo
python main.py
```

## 📊 Features

### Ticket Classification
- Billing, Technical, Refund, Account, Feature Request, Complaint
- Automatic priority assignment (Urgent, High, Medium, Low)

### Policy Enforcement
| Rule | Description |
|------|-------------|
| No Promises | Blocks "guarantee", "definitely", "100%" |
| Discount Limits | Tier-based: 10% (Tier1), 20% (Tier2), 50% (Supervisor) |
| Refund Limits | $100 (Tier1), $500 (Tier2), $5000 (Supervisor) |
| PII Protection | Redacts SSN, credit cards, passwords |
| Response Length | Max 500 characters |

### Escalation Triggers
- Legal threats: "lawsuit", "lawyer", "sue"
- Media: "twitter", "viral", "news"
- Executive: "CEO", "board"
- Sensitive: "injured", "discriminat"

### Knowledge Base (RAG)
- Vector-based retrieval (Pinecone/ChromaDB ready)
- Pre-loaded articles for common issues
- Confidence scoring for response quality

## 📈 Metrics Tracked

```
tickets_handled: Total processed
tickets_resolved: Auto-resolved without human
tickets_escalated: Sent to humans
resolution_rate: % auto-resolved
avg_response_time_sec: Speed metric
avg_csat: Customer satisfaction (1-5)
policy_violation_count: Governance catches
```

## 🔧 Configuration

Edit `SUPPORT_POLICY` in `main.py`:

```python
SUPPORT_POLICY = {
    "response_rules": {
        "no_promises": True,
        "max_response_length": 500,
    },
    "discount_limits": {
        "tier1": {"max_percent": 10},
    },
    # ...
}
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Customer Ticket                       │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  TicketClassifier                        │
│         (Category + Priority Assignment)                 │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  PolicyEngine                            │
│            (Escalation Check)                            │
└─────────────────────────────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
     ┌────────────────┐        ┌────────────────┐
     │  Escalate to   │        │  KnowledgeBase │
     │    Human       │        │   (RAG Search) │
     └────────────────┘        └────────────────┘
                                       │
                                       ▼
                            ┌────────────────────┐
                            │   PolicyEngine     │
                            │ (Response Check)   │
                            └────────────────────┘
                                       │
                                       ▼
                            ┌────────────────────┐
                            │  CrossModelVerifier│
                            │      (CMVK)        │
                            └────────────────────┘
                                       │
                                       ▼
                            ┌────────────────────┐
                            │   Final Response   │
                            │ (or Human Review)  │
                            └────────────────────┘
```

## 🔌 Integration

### Zendesk
```python
from zendesk import ZendeskAPI

zendesk = ZendeskAPI(api_key=os.getenv("ZENDESK_API_KEY"))
agent = CustomerSupportAgent()

for ticket in zendesk.get_new_tickets():
    response = await agent.handle_ticket(ticket)
    if not response.requires_human_review:
        zendesk.reply(ticket.id, response.content)
```

### Slack
```python
@slack_app.event("message")
async def handle_dm(event):
    ticket = Ticket(
        ticket_id=event["ts"],
        customer_id=event["user"],
        message=event["text"]
    )
    response = await agent.handle_ticket(ticket)
    slack_app.respond(event, response.content)
```

## 📋 License

MIT License - Use freely with attribution.
