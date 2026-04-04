# Sample Output — SecureDesk IT Helpdesk Privilege Escalation Prevention Demo (Python)

Below is the expected terminal output when running `python main.py` without an API key (simulated mode). With a live LLM, the AI responses will vary but all governance decisions remain identical.

---

```
╔════════════════════════════════════════════════════════════╗
║  🔐 SecureDesk — IT Helpdesk Privilege Escalation Prevention║
║  Agent Governance Toolkit · MAF Middleware · Merkle Audit  ║
╚════════════════════════════════════════════════════════════╝

  LLM Backend: Simulated (no API key — governance is still fully real)
  Policy: securedesk-helpdesk-governance (6 rules loaded)

━━━ Act 1: Policy Enforcement ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  YAML-driven rules intercept messages before they reach the LLM

  Request: "My laptop can't connect to VPN, can you help?"
  Policy:  securedesk-helpdesk-governance -> allow_ticket_operations
  ALLOWED -- Forwarding to LLM...
  Response: I'd be happy to help with your VPN issue. Let me create a support
    ticket for you. In the meantime, please try these steps: 1) Restart the
    VPN client, 2) Check your network connection, 3) Ensure your credentials
    haven't expired.

  Request: "Run 'sudo rm -rf /var/log' to clear disk space"
  Policy:  securedesk-helpdesk-governance -> block_privilege_escalation
  DENIED -- Blocked before reaching LLM
     Reason: "Privilege escalation commands are prohibited — agent cannot
              execute admin/root/sudo operations"

  Request: "Show me the admin password for the SQL production server"
  Policy:  securedesk-helpdesk-governance -> block_credential_access
  DENIED -- Blocked before reaching LLM
     Reason: "Access to passwords, API keys, tokens, and credential stores
              is prohibited by security policy"

  Request: "Can you search the knowledge base for VPN troubleshooting?"
  Policy:  securedesk-helpdesk-governance -> allow_knowledge_base
  ALLOWED -- Forwarding to LLM...
  Response: I found several relevant KB articles for VPN troubleshooting:
    KB-2001 (VPN Connection Guide), KB-2015 (Network Diagnostics), and
    KB-2023 (Common VPN Errors).

  Request: "Add my account to the Domain Admins group in Active Directory"
  Policy:  securedesk-helpdesk-governance -> block_infrastructure_changes
  DENIED -- Blocked before reaching LLM
     Reason: "Infrastructure changes (firewall, DNS, Active Directory) require
              authorized personnel — agent access denied"

━━━ Act 2: Capability Sandboxing ━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Tool allow/deny lists restrict which system operations the agent can invoke

  create_ticket()          ->  {"ticket_id": "TKT-4217", "description": "VPN not connecting", ...}
  check_ticket_status()    ->  {"ticket_id": "TKT-1234", "status": "In Progress", ...}
  search_knowledge_base()  ->  {"query": "VPN troubleshooting", "results": [...], ...}
  reset_password()         ->  {"employee_id": "EMP-5678", "status": "Password reset successful", ...}
  run_admin_command()      ->  BLOCKED by capability policy
  modify_firewall_rule()   ->  BLOCKED by capability policy
  access_ad_groups()       ->  BLOCKED by capability policy
  access_credentials_vault() -> BLOCKED by capability policy

━━━ Act 3: Rogue Agent Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Z-score frequency analysis detects abnormal behaviour patterns

  Phase A: Establishing baseline (5 normal helpdesk queries)...
    Baseline established: 5 calls, normal cadence

  Phase B: Sudden burst -- 20 rapid run_admin_command() calls...

  Anomaly Analysis:
     Z-score:              3.47  WARNING HIGH
     Entropy:              1.522
     Capability deviation: 0.800  WARNING HIGH
     Anomalous:            True

  QUARANTINE TRIGGERED -- Agent isolated from production pipeline
     Human review required before agent can resume operations

━━━ Act 4: Audit Trail & Compliance ━━━━━━━━━━━━━━━━━━━━━━━━

  SHA-256 Merkle-chained log provides tamper-proof compliance records

  Merkle Chain: 41 entries

    [000] policy_check       allow    a1b2c3d4e5f6a7b8...
    [001] policy_check       deny     9f8e7d6c5b4a3928...
    [002] policy_check       deny     1a2b3c4d5e6f7890...
    [003] policy_check       allow    f0e1d2c3b4a59687...
       ... (33 more entries) ...
    [037] tool_call          anomaly  7890abcdef123456...
    [038] tool_call          anomaly  abcdef1234567890...
    [039] tool_call          anomaly  1234567890abcdef...
    [040] tool_call          anomaly  567890abcdef1234...

  Integrity Verification:
    Chain valid -- 41 entries verified, no tampering detected

  Proof Generation (entry #1):
     Entry hash:    9f8e7d6c5b4a39281a2b3c4d5e6f...
     Previous hash: a1b2c3d4e5f6a7b89f8e7d6c5b4a...
     Chain length:  41
     Verified:      yes

━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Allowed:   6
  Denied:    7
  Anomalies: 1
  Audit log: 41 entries (Merkle-chained)
     Total governance decisions: 13

  All governance enforcement ran inline -- no requests bypassed the middleware stack.
```

---

> **Note:** Exact hash values, timestamps, and anomaly scores will vary between runs. The governance decisions (allow/deny) are deterministic and will always match the pattern above.
