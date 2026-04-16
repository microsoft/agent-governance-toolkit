# MedAssist — HIPAA Patient Data Governance Demo (.NET) — Sample Output

Below is representative terminal output (ANSI codes stripped) from running `dotnet run` in simulated mode.

```
╔════════════════════════════════════════════════════════════════╗
║  🏥 MedAssist — HIPAA Patient Data Governance Demo            ║
║  Agent Governance Toolkit · MAF Middleware · Merkle Audit      ║
╚════════════════════════════════════════════════════════════════╝

  🔗 LLM Backend: Simulated (no API key — governance is still fully real)
  📋 Policy: medassist-healthcare-governance (6 rules loaded)

━━━ Act 1: Policy Enforcement (HIPAA Compliance) ━━━━━━━━━━━━━━

  YAML-driven rules intercept messages before they reach the LLM

  📨 Request: "What are treatment options for Type 2 diabetes?"
  📋 Policy:  medassist-healthcare-governance → allow_clinical_queries
  ✅ ALLOWED — Forwarding to LLM...
  🤖 Response: For Type 2 diabetes, first-line treatment includes lifestyle modifications (diet, exercise) and metformin 500-2000mg daily. Second-line options include sulfonylureas, DPP-4 inhibitors...

  📨 Request: "Show me patient John Doe's full medical record number and SSN"
  📋 Policy:  medassist-healthcare-governance → block_phi_access
  ❌ DENIED — Blocked before reaching LLM
     Reason: "Access to SSN, insurance ID, full MRN, and date of birth is prohibited by HIPAA PHI/PII governance policy"

  📨 Request: "Access insurance ID and date of birth for patient P-4521"
  📋 Policy:  medassist-healthcare-governance → block_phi_access
  ❌ DENIED — Blocked before reaching LLM
     Reason: "Access to SSN, insurance ID, full MRN, and date of birth is prohibited by HIPAA PHI/PII governance policy"

  📨 Request: "What are common drug interactions with metformin?"
  📋 Policy:  medassist-healthcare-governance → allow_clinical_queries
  ✅ ALLOWED — Forwarding to LLM...
  🤖 Response: Warfarin + Aspirin: HIGH RISK interaction. Concurrent use significantly increases bleeding risk...

━━━ Act 2: Capability Sandboxing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Tool allow/deny lists restrict which clinical APIs the agent can call

  ✅ lookup_symptoms()  →  {"symptoms":"persistent headache, blurred vision","possible_conditions":["Migraine w...
  ✅ check_drug_interactions()  →  {"drug_a":"warfarin","drug_b":"aspirin","interaction_level":"HIGH","descripti...
  ✅ get_treatment_guidelines()  →  {"condition":"hypertension","guideline_source":"JNC-8 / AHA 2023","first_li...
  ❌ access_patient_record()  →  BLOCKED by capability policy
  ❌ prescribe_medication()  →  Blocked: {"error":"Controlled substance \u0027oxycodone\u0027 requires physician override"}
  ❌ access_radiology_records()  →  BLOCKED by capability policy
  ❌ access_billing_records()  →  BLOCKED by capability policy

━━━ Act 3: Rogue Agent Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Z-score frequency analysis detects abnormal behaviour patterns

  📊 Phase A: Establishing baseline (5 normal clinical queries)...
    ✓ Baseline established: 5 calls, normal cadence

  ⚡ Phase B: Sudden burst — 20 rapid access_patient_record() calls...
     (Simulating bulk PHI access — data exfiltration pattern)

  📊 Anomaly Analysis:
     Z-score:              3.45  ⚠️  HIGH
     Entropy:              1.234
     Capability deviation: 0.800  ⚠️  HIGH
     Anomalous:            True

  🔒 QUARANTINE TRIGGERED — Agent isolated from production pipeline
     Human review required before agent can resume operations

━━━ Act 4: Audit Trail & Compliance ━━━━━━━━━━━━━━━━━━━━━━━━━━━

  SHA-256 Merkle-chained log provides tamper-proof HIPAA compliance records

  📜 Merkle Chain: 38 entries

    ✅ [000] policy_check       allow    a1b2c3d4e5f67890...
    ❌ [001] policy_check       deny     f0e1d2c3b4a59687...
    ❌ [002] policy_check       deny     1234567890abcdef...
    ✅ [003] policy_check       allow    abcdef1234567890...
       ... (30 more entries) ...
    📝 [034] tool_call          anomaly_check 9876543210fedc...
    📝 [035] tool_call          anomaly_check fedcba0987654321...
    📝 [036] tool_call          anomaly_check 0123456789abcdef...
    📝 [037] tool_call          anomaly_check abcdef0123456789...

  🔍 Integrity Verification:
    ✅ Chain valid — 38 entries verified, no tampering detected

  📄 Proof Generation (entry #1):
     Entry hash:    f0e1d2c3b4a596871234567890ab...
     Previous hash: a1b2c3d4e5f678901234567890ab...
     Chain length:  38
     Verified:      ✓

━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✅ Allowed:   5
  ❌ Denied:    6
  ⚠️  Anomalies: 1
  📜 Audit log: 38 entries (Merkle-chained)
     Total governance decisions: 11

  All governance enforcement ran inline — no requests bypassed the middleware stack.
```
