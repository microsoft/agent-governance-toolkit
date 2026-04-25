# Agent Governance Toolkit × Microsoft Agent Framework — Demo Scenarios

End-to-end scenario folders showing how the **Agent Governance Toolkit (AGT)**
layers onto the real [Microsoft Agent Framework (MAF)](https://github.com/microsoft/agent-framework)
Python and .NET agent patterns.

Each Python example now uses:

- a real `agent_framework.Agent`
- a real `agent_framework.openai.OpenAIChatClient`
- real AGT middleware from `agent_os.integrations.maf_adapter`
- the same scenario stories used in `docs\tutorials\34-maf-integration.md` and `demo\maf-integration`

The examples stay self-contained by scenario, but the Python implementations now
bootstrap the repo-local AGT packages so you can run them directly from this checkout.

## Scenarios

| # | Scenario | Industry | What it demonstrates |
|---|----------|----------|----------------------|
| 01 | [**Loan Processing**](.\01-loan-processing\) | Banking | PII blocking, approval gating, tool sandboxing, rogue transfer detection |
| 02 | [**Customer Service**](.\02-customer-service\) | Retail | Refund fraud prevention, payment-data protection, escalation rules |
| 03 | [**Healthcare**](.\03-healthcare\) | Healthcare | HIPAA PHI blocking, prescription safety, cross-department isolation |
| 04 | [**IT Helpdesk**](.\04-it-helpdesk\) | Enterprise IT | Privilege escalation prevention, credential isolation, infrastructure protection |
| 05 | [**DevOps Deploy**](.\05-devops-deploy\) | DevOps | Production deployment gates, destructive-operation blocking, deployment-storm detection |

## Python quick start

```bash
cd examples/maf-integration/01-loan-processing/python
pip install -r requirements.txt

# Optional: use a live model backend
export GITHUB_TOKEN=$(gh auth token)

python main.py
```

The walkthrough always runs. If a supported model credential is configured, the
example also performs a small live `Agent.run(...)` preview before the scripted
governance acts. Without credentials, it skips the live call and still exercises
the real AGT middleware objects locally.

## LLM backend detection

Python demos detect backends in this order:

| Priority | Backend | Configuration |
|----------|---------|---------------|
| 1 | **GitHub Models** | `GITHUB_TOKEN` |
| 2 | **OpenAI** | `OPENAI_API_KEY` |
| 3 | **Azure OpenAI** | `AZURE_OPENAI_API_KEY` plus `AZURE_OPENAI_ENDPOINT` or `AZURE_OPENAI_BASE_URL` |
| 4 | **Offline walkthrough** | No model credentials required |

## Governance flow

Each Python demo wires the same runtime shape:

1. `AuditTrailMiddleware` records request and tool events.
2. `GovernancePolicyMiddleware` evaluates YAML policies with the real `PolicyEvaluator`.
3. `CapabilityGuardMiddleware` enforces allow/deny tool lists.
4. `RogueDetectionMiddleware` records behavior against a real `RogueAgentDetector`.
5. The scenario script prints policy blocks, capability decisions, rogue detection, and audit integrity results.

## Policy format

The example policy documents use the real AGT schema and operator set. For example:

```yaml
- name: "block_high_value_approval"
  condition:
    field: "message"
    operator: "matches"
    value: '(?i)(approve.*loan|loan approval|\$\s*(?:[5-9]\d{4,}|[1-9]\d{5,}))'
  action: "deny"
  priority: 95
  message: "Loan approvals above the delegated threshold require human review"
```

## Related resources

- [docs\tutorials\34-maf-integration.md](..\..\docs\tutorials\34-maf-integration.md)
- [demo\maf-integration](..\..\demo\maf-integration)
- [packages\agent-os\src\agent_os\integrations\maf_adapter.py](..\..\packages\agent-os\src\agent_os\integrations\maf_adapter.py)
- [Microsoft Agent Framework](https://github.com/microsoft/agent-framework)
