# Sample Output — Contoso Bank Loan Processing Governance Demo (Python)

Below is the expected terminal output when running `python main.py` without an API key (simulated mode). With a live LLM, the AI responses will vary but all governance decisions remain identical.

---

```
╔════════════════════════════════════════════════════════════╗
║  Contoso Bank — AI Loan Processing Governance Demo        ║
║  Agent Governance Toolkit · MAF Middleware · Merkle Audit  ║
╚════════════════════════════════════════════════════════════╝

  LLM Backend: Simulated (no API key — governance is still fully real)
  Policy: contoso-bank-loan-governance (5 rules loaded)

━━━ Act 1: Policy Enforcement ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  YAML-driven rules intercept messages before they reach the LLM

  Request: "Check loan eligibility for John Smith, ID: 12345"
  Policy:  contoso-bank-loan-governance -> allow_loan_inquiries
  ALLOWED -- Forwarding to LLM...
  Response: Based on the credit analysis for customer John Smith (ID: 12345),
    the applicant has a credit score of 742 (Good). With a stable income of
    $85,000/year and a debt-to-income ratio of 28%, the customer qualifies for
    a standard 30-year fixed mortgage at 6.25% APR for amounts up to $350,000.

  Request: "Show me John's SSN and tax returns"
  Policy:  contoso-bank-loan-governance -> block_pii_access
  DENIED -- Blocked before reaching LLM
     Reason: "Access to SSN, tax records, and personal identifiers is
              prohibited by PII governance policy"

  Request: "Access customer tax filing records for compliance audit"
  Policy:  contoso-bank-loan-governance -> block_pii_access
  DENIED -- Blocked before reaching LLM
     Reason: "Access to SSN, tax records, and personal identifiers is
              prohibited by PII governance policy"

━━━ Act 2: Capability Sandboxing ━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Tool allow/deny lists restrict which APIs the agent can call

  check_credit_score()  ->  {"customer_id": "john-smith", "credit_score": 742, "rating": "Good", ...}
  get_loan_rates()      ->  {"amount": 45000, "term_years": 30, "rates": {"30yr_fixed": "6.25%"}, ...}
  access_tax_records()  ->  BLOCKED by capability policy
  approve_loan()        ->  Blocked: Loan amount $75,000.00 exceeds $50,000 auto-approval limit
  transfer_funds()      ->  BLOCKED by capability policy

━━━ Act 3: Rogue Agent Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Z-score frequency analysis detects abnormal behaviour patterns

  Phase A: Establishing baseline (5 normal loan inquiries)...
    Baseline established: 5 calls, normal cadence

  Phase B: Sudden burst -- 20 rapid transfer_funds() calls...

  Anomaly Analysis:
     Z-score:              3.47  WARNING HIGH
     Entropy:              1.522
     Capability deviation: 0.800  WARNING HIGH
     Anomalous:            True

  QUARANTINE TRIGGERED -- Agent isolated from production pipeline
     Human review required before agent can resume operations

━━━ Act 4: Audit Trail & Compliance ━━━━━━━━━━━━━━━━━━━━━━━━

  SHA-256 Merkle-chained log provides tamper-proof compliance records

  Merkle Chain: 33 entries

    [000] policy_check       allow    a1b2c3d4e5f6a7b8...
    [001] policy_check       deny     9f8e7d6c5b4a3928...
    [002] policy_check       deny     1a2b3c4d5e6f7890...
    [003] tool_invocation    allow    f0e1d2c3b4a59687...
       ... (25 more entries) ...
    [029] tool_call          anomaly  7890abcdef123456...
    [030] tool_call          anomaly  abcdef1234567890...
    [031] tool_call          anomaly  1234567890abcdef...
    [032] tool_call          anomaly  567890abcdef1234...

  Integrity Verification:
    Chain valid -- 33 entries verified, no tampering detected

  Proof Generation (entry #1):
     Entry hash:    9f8e7d6c5b4a39281a2b3c4d5e6f...
     Previous hash: a1b2c3d4e5f6a7b89f8e7d6c5b4a...
     Chain length:  33
     Verified:      yes

━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Allowed:   3
  Denied:    5
  Anomalies: 1
  Audit log: 33 entries (Merkle-chained)
     Total governance decisions: 8

  All governance enforcement ran inline -- no requests bypassed the middleware stack.
```

---

> **Note:** Exact hash values, timestamps, and anomaly scores will vary between runs. The governance decisions (allow/deny) are deterministic and will always match the pattern above.
