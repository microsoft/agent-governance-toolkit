# How Agent-SRE Differs

## vs LangSmith / Arize / Langfuse (Agent Observability)

These tools show you **what happened** — traces, evaluations, drift.
Agent-SRE tells you **if it's within budget** and **what to do about it**.

| | Observability Tools | Agent-SRE |
|---|---|---|
| Tracing | ✅ Core strength | ✅ Trace capture + replay |
| Evaluation | ✅ LLM-as-judge | ✅ SLI recording |
| **SLOs & Error Budgets** | ❌ | ✅ Define reliability targets |
| **Canary Deployments** | ❌ | ✅ Compare agent versions |
| **Chaos Testing** | ❌ | ✅ Inject faults, measure resilience |
| **Cost Guardrails** | ❌ (cost tracking only) | ✅ Per-task limits, auto-block |
| **Incident Detection** | ❌ | ✅ SLO breach → auto-incident |
| **Progressive Rollout** | ❌ | ✅ Preview mode, traffic splitting |

**Use both together:** LangSmith for deep trace debugging. Agent-SRE for production reliability operations.

## vs Cleric / Resolve / SRE.ai (AI-Powered SRE)

These tools use AI to **help humans do infrastructure SRE** — incident investigation, triage, root cause analysis for servers and services.

Agent-SRE applies SRE principles **to AI agent systems** — completely different target.

| | AI-Powered SRE Tools | Agent-SRE |
|---|---|---|
| **What they monitor** | Servers, pods, databases | Agent decisions, trust, costs |
| **Who uses them** | DevOps / SRE teams | Agent developers, ML teams |
| **SLOs for** | Uptime, latency, error rate | Decision accuracy, hallucination rate |
| **Chaos tests** | Network partition, pod crash | Tool timeout, LLM degradation |
| **Incidents about** | "Pod crashed" | "Agent made wrong decision" |

**Not competitive.** AI-powered SRE tools monitor your infrastructure. Agent-SRE monitors the agents running on that infrastructure.

## vs Traditional APM (Prometheus, Grafana, Jaeger)

Traditional APM says "HTTP 200, latency 150ms, everything looks green."

Meanwhile your agent just approved a $10K fraudulent transaction.

Agent-SRE catches the failures that infrastructure monitoring can't see — because they're **reasoning failures**, not infrastructure failures.
