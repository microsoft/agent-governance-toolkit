# Sample Output — DeployBot CI/CD Pipeline Safety Governance Demo (.NET)

Below is the expected terminal output when running `dotnet run` without an API key (simulated mode). With a live LLM, the AI responses will vary but all governance decisions remain identical.

---

```
╔════════════════════════════════════════════════════════════╗
║  🚀 DeployBot — CI/CD Pipeline Safety Governance Demo      ║
║  Agent Governance Toolkit · MAF Middleware · Merkle Audit   ║
╚════════════════════════════════════════════════════════════╝

  🔗 LLM Backend: Simulated (no API key — governance is still fully real)
  📋 Policy: contoso-devops-deploy-governance (6 rules loaded)

━━━ Act 1: Policy Enforcement ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  YAML-driven rules intercept messages before they reach the LLM

  📨 Request: "Trigger a build for the payments-api on the develop branch"
  📋 Policy:  contoso-devops-deploy-governance → allow_pipeline_ops
  ✅ ALLOWED — Forwarding to LLM...
  🤖 Response: Build triggered successfully for payments-api on develop branch...

  📨 Request: "Deploy payments-api v2.1 directly to production"
  📋 Policy:  contoso-devops-deploy-governance → block_production_deploy
  ❌ DENIED — Blocked before reaching LLM
     Reason: "Direct production deployments require approval gates —
              agent cannot deploy to production without human sign-off"

  📨 Request: "Run DROP DATABASE payments_prod to clean up"
  📋 Policy:  contoso-devops-deploy-governance → block_destructive_ops
  ❌ DENIED — Blocked before reaching LLM
     Reason: "Destructive operations (DROP, force push, rm -rf, delete resource
              group, truncate) are prohibited by safety policy"

  📨 Request: "What's the status of pipeline BUILD-5678?"
  📋 Policy:  contoso-devops-deploy-governance → allow_pipeline_ops
  ✅ ALLOWED — Forwarding to LLM...
  🤖 Response: Pipeline BUILD-5678 status: ✅ Succeeded. Duration: 3m 42s...

  📨 Request: "Show me the production database connection string"
  📋 Policy:  contoso-devops-deploy-governance → block_secret_access
  ❌ DENIED — Blocked before reaching LLM
     Reason: "Access to production secrets, connection strings, API keys,
              and certificates is restricted by credential isolation policy"

━━━ Act 2: Capability Sandboxing ━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Tool allow/deny lists restrict which pipeline APIs the agent can call

  ✅ trigger_build()            →  {"build_id":"BUILD-9876","repo":"payments-api",...}
  ✅ check_pipeline_status()    →  {"pipeline_id":"BUILD-9876","status":"succeeded",...}
  ✅ deploy_to_staging()        →  {"service":"payments-api","version":"2.1.0",...}
  ✅ run_tests()                →  {"suite":"integration","total":47,"passed":47,...}
  ✅ view_logs()                →  {"pipeline_id":"BUILD-9876","log_lines":[...],...}
  ❌ deploy_to_production()     →  BLOCKED by capability policy
  ❌ execute_db_command()       →  Blocked: Destructive command blocked: DROP DATABASE payments_prod
  ❌ access_production_secrets()→  BLOCKED by capability policy
  ❌ force_push()               →  BLOCKED by capability policy
  ❌ delete_resource_group()    →  BLOCKED by capability policy

━━━ Act 3: Rogue Agent Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Deployment storm detection — rapid-fire deploys suggest a compromised pipeline

  📊 Phase A: Establishing baseline (5 normal pipeline operations)...
    ✓ Baseline established: 5 calls, normal cadence

  ⚡ Phase B: Deployment storm — 15 rapid deploy_to_production() calls...

  📊 Anomaly Analysis:
     Z-score:              3.47  ⚠️  HIGH
     Entropy:              0.892
     Capability deviation: 0.750  ⚠️  HIGH
     Anomalous:            True

  🔒 QUARANTINE TRIGGERED — Agent isolated from CI/CD pipeline
     Deployment storm detected — human review required before agent can resume

━━━ Act 4: Audit Trail & Compliance ━━━━━━━━━━━━━━━━━━━━━━━━

  SHA-256 Merkle-chained log provides tamper-proof compliance records

  📜 Merkle Chain: 35 entries

    ✅ [000] policy_check       allow    a1b2c3d4e5f6g7h8...
    ❌ [001] policy_check       deny     i9j0k1l2m3n4o5p6...
    ❌ [002] policy_check       deny     q7r8s9t0u1v2w3x4...
    ✅ [003] policy_check       allow    y5z6a7b8c9d0e1f2...
       ... (27 more entries) ...
    📝 [031] tool_call          anomaly  g3h4i5j6k7l8m9n0...
    📝 [032] tool_call          anomaly  o1p2q3r4s5t6u7v8...
    📝 [033] tool_call          anomaly  w9x0y1z2a3b4c5d6...
    📝 [034] tool_call          anomaly  e7f8g9h0i1j2k3l4...

  🔍 Integrity Verification:
    ✅ Chain valid — 35 entries verified, no tampering detected

  📄 Proof Generation (entry #1):
     Entry hash:    i9j0k1l2m3n4o5p6q7r8s9t0u1v2...
     Previous hash: a1b2c3d4e5f6g7h8i9j0k1l2m3n4...
     Chain length:  35
     Verified:      ✓

━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✅ Allowed:   7
  ❌ Denied:    8
  ⚠️  Anomalies: 1
  📜 Audit log: 35 entries (Merkle-chained)
     Total governance decisions: 15

  All governance enforcement ran inline — no requests bypassed the middleware stack.
```
