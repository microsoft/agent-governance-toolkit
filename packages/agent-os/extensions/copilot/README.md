# AgentOS for GitHub Copilot

> **Note:** GitHub also supports extending Copilot via the Model Context Protocol (MCP).
> See [`extensions/mcp-server`](../mcp-server/) for the MCP-based alternative.

---

> **Build safe AI agents with natural language and 0% policy violations**

[![npm version](https://badge.fury.io/js/@agent-os%2Fcopilot-extension.svg)](https://www.npmjs.com/package/@agent-os/copilot-extension)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

## Overview

AgentOS brings safety-first AI agent development directly into GitHub Copilot. Create policy-compliant autonomous agents with natural language, backed by a 0% policy violation guarantee.

```
┌─────────────────────────────────────────────────────┐
│              "Create agent for..."                  │
└────────────────────┬────────────────────────────────┘
                     │
         ┌───────────▼───────────┐
         │  🛡️ AgentOS Extension │
         │                       │
         │  • Agent Generation   │
         │  • Policy Enforcement │
         │  • CMVK Verification  │
         │  • Compliance Check   │
         └───────────┬───────────┘
                     │
    ┌────────────────┼────────────────┐
    │                │                │
┌───▼───┐    ┌───────▼───────┐   ┌───▼───┐
│ Code  │    │ GitHub Actions│   │ Tests │
│Python │    │   Workflow    │   │       │
│TS/Go  │    └───────────────┘   └───────┘
└───────┘
```

## ✨ Features

### 🤖 Agent Creation from Natural Language

```
@agentos create agent for processing customer feedback from Slack
```

Instantly generates:
- Agent code (Python, TypeScript, or Go)
- Safety policies
- GitHub Actions workflow
- Test suite

### 📚 50+ Pre-built Templates

Browse templates by category:
- **Data Processing**: ETL pipelines, CSV processors, data sync
- **DevOps**: Deployment automation, monitoring, incident response
- **Customer Support**: Ticket routing, sentiment analysis, FAQ bots
- **Content Management**: Moderation, SEO, social media
- **Security**: Access audits, compliance checks, secret scanning

### 🛡️ Policy Enforcement

Automatic policy detection and enforcement:
- Rate limiting for APIs
- PII protection and redaction
- Authentication requirements
- Retry with backoff
- Audit logging

### 📋 Compliance Frameworks

Built-in support for:
- **GDPR** - EU data protection
- **HIPAA** - Healthcare data
- **SOC 2** - Security & availability
- **PCI DSS** - Payment card data

### 🔍 Multi-Model Verification (CMVK)

Code reviewed by multiple AI models for consensus-based safety.

## 🚀 Quick Start

### Chat Commands

| Command | Description |
|---------|-------------|
| `@agentos create agent for [task]` | Create agent from description |
| `@agentos design workflow to [goal]` | Design multi-step workflow |
| `@agentos templates [category]` | Browse agent templates |
| `@agentos test` | Test agent with scenarios |
| `@agentos debug` | Debug agent failures |
| `@agentos compliance [framework]` | Check compliance (gdpr, hipaa, soc2, pci-dss) |
| `@agentos security` | Run security audit |
| `@agentos deploy` | Deploy to GitHub Actions |
| `@agentos review` | Review code with CMVK |
| `@agentos policy` | Show active policies |
| `@agentos audit` | View audit log |
| `@agentos help` | Show all commands |

### Example: Create a Monitoring Agent

```
User: @agentos create agent for monitoring API uptime and alerting on failures

AgentOS: 🤖 Agent Created: ApiUptimeMonitoringAgent

### Tasks
- Check API endpoint health
- Record response times
- Detect outages
- Send Slack alerts

### 🛡️ Safety Policies Applied
✅ API Rate Limiting (rate_limit): Limits API calls to prevent quota exhaustion
✅ Retry with Backoff (retry): Retries failed operations with exponential backoff
✅ Audit Logging (logging): Logs all agent actions for audit trail

[Generated Code]
[Deploy to GitHub Actions] [Test Agent]
```

## Installation

### As a Copilot Extension

1. Go to GitHub Settings → Copilot → Extensions
2. Search for "AgentOS"
3. Enable the extension

### Self-Hosted

```bash
git clone https://github.com/microsoft/agent-governance-toolkit
cd agent-os/extensions/copilot

npm install
npm run build
npm start
```

## Configuration

### Environment Variables

```bash
# .env
PORT=3000
LOG_LEVEL=info
CMVK_API_ENDPOINT=https://api.agent-os.dev/cmvk
```

### Repository Policy

Create `.github/agent-os.json`:

```json
{
  "policies": {
    "blockDestructiveSQL": true,
    "blockFileDeletes": true,
    "blockSecretExposure": true,
    "blockPrivilegeEscalation": true
  },
  "compliance": ["gdpr", "soc2"],
  "deployment": {
    "requireApproval": true,
    "allowedEnvironments": ["staging", "production"]
  }
}
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/copilot` | POST | Handle @agentos chat commands |
| `/api/webhook` | POST | GitHub webhook endpoint |
| `/api/templates` | GET | List agent templates |
| `/api/templates/:id` | GET | Get template by ID |
| `/api/compliance` | GET | List compliance frameworks |
| `/api/compliance/validate` | POST | Validate against framework |
| `/api/audit` | GET | Get audit log |
| `/api/policy` | GET/POST | Manage policies |
| `/api/status` | GET | Service status |
| `/health` | GET | Health check |
| `/setup` | GET | Setup page |
| `/auth/callback` | GET | OAuth callback |

## Generated Agent Structure

When you create an agent, AgentOS generates:

```
agents/
├── customer_feedback_agent.py  # Agent code
├── customer-feedback-agent/
│   └── README.md               # Documentation
policies/
└── customer-feedback-agent.yaml # Safety policies
tests/
└── test_customer_feedback_agent.py
.github/workflows/
└── customer-feedback-agent.yml  # GitHub Actions
```

## Security

- All policy checks run locally
- CMVK is opt-in (code sent only when explicitly requested)
- Audit logs stored locally only
- No telemetry or analytics
- Secrets never logged or transmitted

## Performance

- Chat response: <2 seconds
- Inline suggestions: <100ms
- Policy evaluation: <50ms
- Code generation: <5 seconds

## Docker Deployment

```bash
docker build -t agentos-copilot .
docker run -p 3000:3000 agentos-copilot
```

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](../../LICENSE).

---

<div align="center">

**Build safe AI agents with AgentOS**

[GitHub](https://github.com/microsoft/agent-governance-toolkit) · [Documentation](../../docs/) · [Templates](../../templates/)

</div>
