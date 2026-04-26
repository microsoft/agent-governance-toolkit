# Agent OS Examples

> **Production-ready demos** showcasing Agent OS governance in real industry contexts.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://www.docker.com/)

## 🚀 Quick Start

```bash
# Quickstart (instant)
python examples/quickstart/my_first_agent.py

# Full demo
cd examples/demo-app && python agent.py
```

---

## 📚 All Examples

### Getting Started

| Example | Description | Complexity |
|---------|-------------|------------|
| [**quickstart**](./quickstart/) | ⭐ **START HERE** - Single-file example | ⭐ Beginner |
| [**hello-world**](./hello-world/) | Minimal example - 15 lines | ⭐ Beginner |
| [**chat-agent**](./chat-agent/) | Interactive chatbot with memory | ⭐⭐ Intermediate |
| [**tool-using-agent**](./tool-using-agent/) | Agent with safe tools | ⭐⭐ Intermediate |
| [**demo-app**](./demo-app/) | Full demo application with UI | ⭐⭐ Intermediate |

### Industry Examples (Governance Patterns)

| Example | Industry | Governance Features | Compliance |
|---------|----------|---------------------|------------|
| [**healthcare-hipaa**](./healthcare-hipaa/) | Healthcare | PHI protection, consent, audit trails | HIPAA |
| [**finance-soc2**](./finance-soc2/) | Finance | Approval workflows, rate limiting, sanctions | SOC2 |
| [**legal-review**](./legal-review/) | Legal | Attorney-client privilege, PII redaction | ABA Rules |
| [**hr-recruiting**](./hr-recruiting/) | HR | Bias prevention, protected field blocking | EEOC, GDPR |
| [**ecommerce-support**](./ecommerce-support/) | E-commerce | PCI-DSS card masking, fraud detection | PCI-DSS |
| [**iot-smart-home**](./iot-smart-home/) | IoT | Safety constraints, privacy, emergency overrides | UL 2900 |
| [**customer-service**](./customer-service/) | Support | Escalation rules, sentiment analysis | - |
| [**devops-safe**](./devops-safe/) | DevOps | Safe deployments, rollback policies | - |

### Production Demos (with Observability)

| Example | Description | Stack |
|---------|-------------|-------|
| [**carbon-auditor**](./carbon-auditor/) | Carbon credit fraud detection | CMVK + Prometheus + Grafana |
| [**defi-sentinel**](./defi-sentinel/) | DeFi attack detection (<50ms) | AMB + Jaeger + Prometheus |
| [**grid-balancing**](./grid-balancing/) | 100-agent energy trading | IATP + Prometheus + Grafana |
| [**pharma-compliance**](./pharma-compliance/) | FDA document analysis | CMVK + Prometheus |

### Framework Integrations

| Example | Framework | Description |
|---------|-----------|-------------|
| [**crewai-safe-mode**](./crewai-safe-mode/) | CrewAI | Governed multi-agent crew |
| [**self-evaluating**](./self-evaluating/) | Research | Self-improving agents |

---

## 🐳 Running Production Demos

Each production demo includes full observability:

```bash
cd examples/carbon-auditor && docker-compose up
```

| Demo | UI | Grafana | Jaeger |
|------|-----|---------|--------|
| carbon-auditor | :8080 | :3000 | :16686 |
| defi-sentinel | :8081 | :3001 | :16687 |
| grid-balancing | :8082 | :3002 | :16688 |
| pharma-compliance | :8083 | :3003 | :16689 |

**Grafana login:** admin / admin

---

## 📊 Architecture

All examples use the Agent OS kernel stack:

```
┌─────────────────────────────────────────────────────────┐
│                   Your Application                       │
├─────────────────────────────────────────────────────────┤
│                   Agent OS Kernel                        │
│  ┌─────────────┬─────────────┬─────────────────────┐    │
│  │   Signals   │    VFS      │   Policy Engine     │    │
│  │ SIGKILL/STOP│ /mem /audit │ Deterministic       │    │
│  └─────────────┴─────────────┴─────────────────────┘    │
│  ┌─────────────┬─────────────┬─────────────────────┐    │
│  │    IATP     │    AMB      │      CMVK           │    │
│  │ Agent Trust │ Message Bus │ Multi-Model Verify  │    │
│  └─────────────┴─────────────┴─────────────────────┘    │
├─────────────────────────────────────────────────────────┤
│                    Observability                         │
│    Prometheus │ Grafana │ Jaeger │ OpenTelemetry        │
└─────────────────────────────────────────────────────────┘
```

## License

MIT
