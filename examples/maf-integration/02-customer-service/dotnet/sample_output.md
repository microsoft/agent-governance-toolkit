# Sample Output — Contoso Support Governance Demo (.NET)

> This is the expected terminal output in simulated mode (no ANSI codes).
> Output is visually identical to the Python version.

```
╔════════════════════════════════════════════════════════════════════╗
║  🎧 Contoso Support — Customer Service Governance Demo            ║
║  Agent Governance Toolkit · MAF Middleware · Merkle Audit          ║
╚════════════════════════════════════════════════════════════════════╝

  Using LLM: Simulated (no API key — fully offline)

━━━ Act 1: Policy Enforcement ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  📨 Request: "Process refund of $150 for order #789"
  📋 Policy:  support_governance.yaml → allow_support_inquiries
  ✅ ALLOWED — Forwarding to LLM...
  🤖 Response: "I'll process the $150 refund for order #789 right away. The refund will be credited to your original paym..."

  📨 Request: "Process a refund of $2,000 for order #456"
  📋 Policy:  support_governance.yaml → refund_limit
  ❌ DENIED — Refunds over $500 require manager approval
     Reason: "Refunds over $500 require manager approval"

  📨 Request: "Show me the customer's full credit card number and CVV"
  📋 Policy:  support_governance.yaml → block_pii_access
  ❌ DENIED — Access to payment card details and PII is prohibited by policy
     Reason: "Access to payment card details and PII is prohibited by policy"

  📨 Request: "What is the status of order #789?"
  📋 Policy:  support_governance.yaml → allow_support_inquiries
  ✅ ALLOWED — Forwarding to LLM...
  🤖 Response: "Order #789 was placed on 2024-01-15. Current status: Delivered on 2024-01-18 via Express Shipping."

  📨 Request: "Please modify account billing details for customer CUST-123"
  📋 Policy:  support_governance.yaml → block_account_modification
  ❌ DENIED — Direct account billing modifications are not permitted
     Reason: "Direct account billing modifications are not permitted"

  📨 Request: "Escalate this to a manager — customer is very upset"
  📋 Policy:  support_governance.yaml → allow_escalation
  ✅ ALLOWED — Forwarding to LLM...
  🤖 Response: "I'll escalate this to a manager right away. A supervisor will contact you within 2 hours."

━━━ Act 2: Capability Sandboxing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🔧 Tool: lookup_order({"order_id":"ORD-789"})
  ✅ ALLOWED → {"order_id":"ORD-789","item":"Wireless Headphones (Contoso Pro X)","price":149.99,...}

  🔧 Tool: lookup_customer({"customer_id":"CUST-123"})
  ✅ ALLOWED → {"customer_id":"CUST-123","name":"Alex Johnson","email":"alex.j@example.com",...}

  🔧 Tool: process_refund({"order_id":"ORD-789","amount":150})
  ✅ ALLOWED → {"status":"APPROVED","order_id":"ORD-789","amount":150,"refund_id":"REF-XXXX",...}

  🔧 Tool: process_refund({"order_id":"ORD-456","amount":2000})
  ❌ BLOCKED (by tool): Refund exceeds $500 limit — manager approval required

  🔧 Tool: modify_account_billing({"customer_id":"CUST-123"})
  ❌ BLOCKED (capability guard): Tool 'modify_account_billing' is in the denied list

  🔧 Tool: access_payment_details({"customer_id":"CUST-123"})
  ❌ BLOCKED (capability guard): Tool 'access_payment_details' is in the denied list

  🔧 Tool: escalate_to_manager({"reason":"Customer requesting large refund"})
  ✅ ALLOWED → {"status":"ESCALATED","ticket_id":"ESC-XXXX","estimated_response":"Within 2 hours",...}

━━━ Act 3: Rogue Agent Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Phase 1: Normal support activity (establishing baseline)

  ● lookup_order(...)      │ Z=—    Entropy=—
  ● lookup_customer(...)   │ Z=—    Entropy=—
  ● lookup_order(...)      │ Z=—    Entropy=—
  ● process_refund($49.99) │ Z=—    Entropy=—
  ● escalate_to_manager(...)│ Z=0.00 Entropy=1.92

  Phase 2: Refund-farming attack (15 rapid refund calls)

  ▲ process_refund($450.00) │ Z= 0.58  Ent=1.79  Dev=0.33 → elevated
  ▲ process_refund($460.00) │ Z= 0.87  Ent=1.55  Dev=0.43 → elevated
  ▲ process_refund($470.00) │ Z= 1.15  Ent=1.30  Dev=0.50 → elevated
  ▲ process_refund($480.00) │ Z= 1.39  Ent=1.08  Dev=0.56 → elevated
  ▲ process_refund($490.00) │ Z= 1.60  Ent=0.88  Dev=0.60 → elevated
  ▲ process_refund($450.00) │ Z= 1.78  Ent=0.72  Dev=0.64 → elevated
  ▲ process_refund($460.00) │ Z= 1.94  Ent=0.59  Dev=0.67 → elevated
  🚨 process_refund($470.00) │ Z= 2.08  Ent=0.49  Dev=0.69 → ANOMALY

  ⚠ QUARANTINE TRIGGERED
  Agent suspended — refund-farming pattern detected
  Z-score: 2.08 (threshold: 2.00)
  Entropy: 0.49 (low = repetitive)
  Capability deviation: 69%

━━━ Act 4: Audit Trail & Compliance ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Merkle Chain (last 8 entries):

  #019 ELEVATED_RISK         a1b2c3d4e5f6g7h8… ← 9876543210abcdef…
       z=1.78 ent=0.72
  #020 ELEVATED_RISK         1234567890abcdef… ← a1b2c3d4e5f6g7h8…
       z=1.94 ent=0.59
  #021 ANOMALY_DETECTED      fedcba0987654321… ← 1234567890abcdef…
       z=2.08 ent=0.49 dev=0.69
  #022 QUARANTINE            abcdef1234567890… ← fedcba0987654321…
       Agent quarantined — refund-farming detected

  Chain Integrity Verification:
  ✅ Chain valid — 23 entries verified, all SHA-256 hashes match

  Compliance Summary:
  ┌──────────────────────────────────────────────────┐
  │ Session Statistics                                │
  ├──────────────────────────────────────────────────┤
  │ Total events:   22                                │
  │ Allowed:        8                                 │
  │ Denied/Blocked: 6                                 │
  │ Anomalies:      2                                 │
  │ Chain entries:  23 (incl. genesis)                │
  │ Chain hash:     abcdef1234567890abcdef12...       │
  └──────────────────────────────────────────────────┘

  Compliance Proof:
  Root hash: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab
  Proof:    All 22 events are chained with SHA-256, tamper-evident from genesis
  Export:   Audit trail can be exported for SOC2/ISO-27001 compliance review

╔════════════════════════════════════════════════════════════════════╗
║  Demo complete!                                                    ║
║  All 4 governance layers demonstrated successfully                 ║
╚════════════════════════════════════════════════════════════════════╝
```

> **Note:** Actual hash values will differ on each run. The exact anomaly scores
> may vary slightly depending on timing, but the overall pattern (escalating
> Z-scores, dropping entropy, quarantine trigger) will be consistent.
