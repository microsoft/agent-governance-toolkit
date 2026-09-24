# AgentOS MCP Server

> [!IMPORTANT]
> **Public Preview** — This npm package is a public preview release. APIs may change before GA.

> **Build safe AI agents with natural language and 0% policy violations**

<a href="https://glama.ai/mcp/servers/@microsoft/agentos-mcp-server">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/@microsoft/agentos-mcp-server/badge" />
</a>

[![npm version](https://badge.fury.io/js/agentos-mcp-server.svg)](https://www.npmjs.com/package/agentos-mcp-server)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-io.github.imran--siddique%2Fagentos-blue)](https://registry.modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

## 🚀 Quick Install

```bash
npx agentos-mcp-server
```

**npm:** [`agentos-mcp-server`](https://www.npmjs.com/package/agentos-mcp-server)  
**MCP Registry:** `io.github.microsoft/agentos`

## Overview

AgentOS MCP Server brings the complete Agent OS safety framework to any MCP-compatible AI assistant including **Claude Desktop**, **GitHub Copilot**, **Cursor**, and more. Create, deploy, and manage policy-compliant autonomous agents through natural conversation.

```
┌─────────────────────────────────────────────────────────────┐
│           Claude Desktop / Copilot / Cursor                  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │            "Create an agent that..."                    │ │
│  └──────────────────────┬─────────────────────────────────┘ │
└─────────────────────────┼───────────────────────────────────┘
                          │ MCP Protocol
            ┌─────────────▼─────────────┐
            │   🛡️ AgentOS MCP Server   │
            │                           │
            │  • 10 Tools              │
            │  • Policy Engine         │
            │  • Approval Workflows    │
            │  • Audit Logging         │
            │  • Template Library      │
            └─────────────┬─────────────┘
                          │
      ┌───────────────────┼───────────────────┐
      │                   │                   │
┌─────▼─────┐      ┌──────▼──────┐     ┌─────▼─────┐
│  Agents   │      │  Policies   │     │  Audit    │
│  (Local)  │      │  (Enforced) │     │  (Logged) │
└───────────┘      └─────────────┘     └───────────┘
```

## ✨ Features

### 🤖 Natural Language Agent Creation
```
User: Create an agent that processes customer feedback from support emails daily

Claude: ✅ Agent Created Successfully!

Agent: customer-feedback-processor
✅ Data Source: Email inbox via IMAP
✅ Processing: Sentiment analysis + categorization
✅ Output: Daily summary to Slack
✅ Schedule: Every day at 9 AM

Safety Policies Applied:
🛡️ PII Protection: Customer emails/names anonymized
🛡️ Rate Limiting: Max 1000 emails per run
🛡️ Human Review: Negative sentiment cases flagged
```

### 🛡️ Policy Enforcement with 0% Violations
- 6 built-in policies (PII, rate-limiting, cost-control, data-deletion, secrets, human-review)
- Real-time policy evaluation
- Automatic blocking of violations
- Clear explanations and alternatives

### ✅ Human-in-the-Loop Approval Workflows
- Risk-based approval requirements
- Multi-party approval for critical actions
- Email/Slack notifications
- Expiration handling

### 📊 Complete Audit Trail
- Every action logged immutably
- Policy evaluations recorded
- Compliance report generation
- Export for auditors

### 📋 Template Library
- 10+ agent templates (data processor, email assistant, backup, scraper, etc.)
- 6+ policy templates (GDPR, SOC 2, HIPAA, PCI DSS, etc.)
- Industry-specific compliance frameworks

### 🏛️ Compliance Ready
- **SOC 2** - Security & availability controls
- **GDPR** - EU data protection
- **HIPAA** - Healthcare data privacy
- **PCI DSS** - Payment card security
- **CCPA** - California privacy
- **NIST** - Cybersecurity framework
- **ISO 27001** - Information security
- **FedRAMP** - Federal authorization

## 🚀 Quick Start

### Step 1: Configure Claude Desktop

Add to your `claude_desktop_config.json`:

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Linux:** `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "agentos": {
      "command": "npx",
      "args": ["-y", "agentos-mcp-server"],
      "env": {
        "AGENTOS_POLICY_MODE": "strict"
      }
    }
  }
}
```

### Step 2: Restart Claude Desktop

Close and reopen Claude Desktop to load the MCP server.

### Step 3: Start Building Agents!

Just ask Claude naturally:

```
"Create an agent that backs up my Documents folder to Google Drive every night"
```

Claude will:
1. Create the agent with appropriate configuration
2. Suggest safety policies based on the task
3. Let you test before deployment
4. Deploy with monitoring enabled

## 💬 Example Conversations

### Creating a Data Processing Agent

```
User: I need an agent that processes customer feedback from support emails daily

Claude: ✅ Agent Created Successfully!

Agent: customer-feedback-processor
ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Status: draft
Language: python

Task:
Process customer feedback from support emails daily

Workflow Steps:
1. connect_email: email.connect
2. process_data: execute
3. output_results: output

Safety Policies Applied:
🛡️ PII Protection: Customer emails/names anonymized
🛡️ Rate Limiting: Max 1000 emails per run
🛡️ Human Review: Negative sentiment cases flagged

Next Steps:
1. Use `test_agent` to run a dry-run test
2. Use `attach_policy` to add more safety policies
3. Use `deploy_agent` when ready to run
```

### Testing Before Deployment

```
User: Test this agent with a scenario of processing 100 emails

Claude: ✅ Test PASSED

Agent: customer-feedback-processor
Scenario: Process 100 customer emails
Mode: Dry Run (no changes)

Configuration Check: ✅ Valid
Workflow Check: ✅ Valid (3 steps)

Policy Evaluation: ✅ No violations detected

Warnings:
⚠️  PII access logged

Resource Estimates:
- Duration: ~30 seconds
- Cost: $0.05

Next Step: Use `deploy_agent` to deploy this agent.
```

### Checking Compliance

```
User: Check if this agent is SOC 2 compliant

Claude: # Compliance Report: SOC2

Agent: customer-feedback-processor
Framework: SOC2
Date: 2026-01-30

## Summary
✅ COMPLIANT
Score: 100% (4/4 controls passed)

## Control Assessment

✅ CC6.1: Logical Access Controls
   Restrict logical access to information assets
   Evidence: Policy enforcement enabled, Access logging active

✅ CC6.6: Security Event Monitoring
   Detect and respond to security events
   Evidence: Audit logging enabled, Event timestamps recorded

✅ CC7.2: Incident Response
   Respond to security incidents
   Evidence: Human review enabled, Escalation procedures in place

✅ CC8.1: Change Management
   Manage changes to system components
   Evidence: Deployment approval required, Version control enabled
```

### Creating Custom Policies

```
User: Create a policy that blocks access to customer credit card data

Claude: ✅ Custom Policy Created

Policy: Block Access To Customer
ID: custom-a1b2c3d4
Category: security

Description:
Block access to customer credit card data

Rules Generated (1):

🟠 custom_block_rule [high]
   Block actions based on: block access to customer credit card data
   Action: deny

Usage:
1. Attach to agent: `attach_policy` with policyId "custom-a1b2c3d4"
2. Test enforcement: `test_agent` with policy scenarios
3. View active policies: `get_agent_status`
```

## 🔧 Available Tools

| Tool | Description |
|------|-------------|
| `create_agent` | Create agent from natural language description |
| `attach_policy` | Attach safety policies to agents |
| `test_agent` | Dry-run test before deployment |
| `deploy_agent` | Deploy agent locally or to cloud |
| `get_agent_status` | Get agent status and metrics |
| `list_templates` | Browse agent and policy templates |
| `request_approval` | Create approval request for sensitive actions |
| `audit_log` | Query audit trail |
| `create_policy` | Create custom policy from description |
| `check_compliance` | Check against compliance frameworks |

### Tool Details

#### `create_agent`
Create a new AI agent from a natural language description with automatic policy recommendations.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `description` | string | ✅ | Natural language description of agent task |
| `policies` | string[] | | Policy templates to apply |
| `approvalRequired` | boolean | | Require human approval before execution |
| `language` | string | | `python`, `typescript`, `javascript`, `go` |
| `schedule` | string | | Cron schedule for recurring execution |

#### `attach_policy`
Attach safety policies to an agent with conflict detection.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agentId` | string | ✅ | Agent ID to attach policy to |
| `policyId` | string | ✅ | Policy template ID |
| `customRules` | object[] | | Additional custom rules |

#### `test_agent`
Run a dry-run test with simulated scenarios.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agentId` | string | ✅ | Agent ID to test |
| `scenario` | string | ✅ | Test scenario description |
| `mockData` | object | | Mock data for testing |
| `dryRun` | boolean | | Run without side effects (default: true) |

#### `deploy_agent`
Deploy an agent to local or cloud environment.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agentId` | string | ✅ | Agent ID to deploy |
| `environment` | string | | `local` or `cloud` |
| `autoStart` | boolean | | Start immediately after deployment |

#### `check_compliance`
Check an agent against regulatory frameworks.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agentId` | string | ✅ | Agent ID to check |
| `framework` | string | ✅ | `SOC2`, `GDPR`, `HIPAA`, `PCI_DSS`, `CCPA`, `NIST`, `ISO27001`, `FEDRAMP` |
| `generateReport` | boolean | | Generate detailed report |

## 📋 Policy Templates

### Built-in Security Policies

| Policy ID | Name | Description |
|-----------|------|-------------|
| `pii-protection` | PII Protection | Protects personally identifiable information (GDPR) |
| `rate-limiting` | Rate Limiting | Prevents resource abuse through rate limits |
| `cost-control` | Cost Control | Prevents runaway costs from automation |
| `data-deletion` | Data Deletion Safety | Prevents accidental data loss |
| `secrets-protection` | Secrets Protection | Prevents exposure of credentials |
| `human-review` | Human Review Required | Requires approval for sensitive actions |

### Compliance Templates

| Template ID | Framework | Description |
|-------------|-----------|-------------|
| `gdpr-compliance` | GDPR | EU General Data Protection Regulation |
| `soc2-security` | SOC 2 | SOC 2 Type II security controls |
| `hipaa-healthcare` | HIPAA | Healthcare data privacy (PHI protection) |
| `pci-dss-payments` | PCI DSS | Payment card data security |
| `read-only-access` | Security | Restricts database to read-only |
| `production-safety` | Operations | Extra safeguards for production |

## 🤖 Agent Templates

### Data Processing
| Template | Description | Default Policies |
|----------|-------------|------------------|
| `data-processor` | Processes and transforms data files | rate-limiting, cost-control |
| `web-scraper` | Scrapes websites for data collection | rate-limiting, cost-control |
| `report-generator` | Generates periodic reports | pii-protection, rate-limiting |

### Communication
| Template | Description | Default Policies |
|----------|-------------|------------------|
| `email-assistant` | Monitors and processes emails | pii-protection, human-review |
| `slack-bot` | Automated Slack notifications | human-review, rate-limiting |

### Infrastructure
| Template | Description | Default Policies |
|----------|-------------|------------------|
| `backup-agent` | Backs up files to cloud storage | cost-control |
| `api-monitor` | Monitors API health and performance | rate-limiting |
| `file-organizer` | Organizes files based on rules | data-deletion |

### Analytics
| Template | Description | Default Policies |
|----------|-------------|------------------|
| `database-analyst` | Queries databases and generates reports | data-deletion, pii-protection |
| `content-moderator` | Moderates user-generated content | human-review, pii-protection |

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENTOS_API_KEY` | API key for cloud features | (none) |
| `AGENTOS_POLICY_MODE` | `strict` or `permissive` | `strict` |
| `AGENTOS_DATA_DIR` | Local data directory | `.agentos` |
| `AGENTOS_LOG_LEVEL` | `debug`, `info`, `warn`, `error` | `info` |

### Policy Modes

| Mode | Behavior |
|------|----------|
| **strict** | Any policy violation blocks the action |
| **permissive** | Only critical violations block (warnings logged) |

### Data Storage

All data is stored locally in the `AGENTOS_DATA_DIR`:

```
.agentos/
├── agents/           # Agent configurations
│   └── {id}.json
├── approvals/        # Approval requests
│   └── {id}.json
└── audit/            # Audit logs (JSONL format)
    └── {date}.jsonl
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Claude Desktop                           │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                    Claude AI Model                      │ │
│  │     Natural language understanding & orchestration      │ │
│  └──────────────────────┬─────────────────────────────────┘ │
│                         │ MCP Protocol                       │
│  ┌──────────────────────▼─────────────────────────────────┐ │
│  │                    MCP Client                           │ │
│  │          Tool discovery & request handling              │ │
│  └──────────────────────┬─────────────────────────────────┘ │
└─────────────────────────┼───────────────────────────────────┘
                          │ stdio
┌─────────────────────────▼───────────────────────────────────┐
│               @agentos/mcp-server (Node.js)                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                    MCP Server                           │ │
│  │            Tool/Resource/Prompt handlers                │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  │
│  │  Agent   │ │  Policy  │ │ Approval │ │    Audit      │  │
│  │ Manager  │ │  Engine  │ │ Workflow │ │   Logger      │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────────────┘  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              Template Library (50+ templates)           │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                          │ HTTPS (optional)
┌─────────────────────────▼───────────────────────────────────┐
│              AgentOS Cloud Platform (Future)                │
│     • Persistent storage  • Multi-tenant  • Enterprise      │
└─────────────────────────────────────────────────────────────┘
```

## 🔒 Security

| Feature | Description |
|---------|-------------|
| **Policy Enforcement** | All actions validated against policies before execution |
| **Data Redaction** | Sensitive data automatically redacted from logs |
| **Secret Protection** | Secrets never stored in plain text |
| **Audit Trail** | Complete immutable log for compliance |
| **Human Approval** | Required for high-risk operations |
| **Local-First** | All data stored locally by default |

## 💻 Development

### Local Development

```bash
# Clone the repository
git clone https://github.com/microsoft/agent-governance-toolkit
cd agent-governance-python/agent-os/extensions/mcp-server

# Install dependencies
npm install

# Build
npm run build

# Run in stdio mode (for Claude Desktop)
npm start -- --stdio

# Run in HTTP mode (for development)
npm start -- --http --port 3000
```

Build, watch, and typecheck invoke `node node_modules/@typescript/native/bin/tsc`
directly, avoiding npm's ambiguous `tsc` bin-link order. ESLint uses the
TypeScript 6 API compatibility alias until tooling supports TypeScript 7's new
API. Run `npm run typecheck` and `npm run lint` after changes.

### Project Structure

```
agent-governance-python/agent-os/extensions/mcp-server/
├── src/
│   ├── index.ts              # Main entry point
│   ├── cli.ts                # CLI with --stdio/--http modes
│   ├── server.ts             # MCP server implementation
│   ├── tools/                # 10 MCP tools
│   │   ├── create-agent.ts
│   │   ├── attach-policy.ts
│   │   ├── test-agent.ts
│   │   ├── deploy-agent.ts
│   │   ├── get-agent-status.ts
│   │   ├── list-templates.ts
│   │   ├── request-approval.ts
│   │   ├── audit-log.ts
│   │   ├── create-policy.ts
│   │   └── check-compliance.ts
│   ├── services/             # Core business logic
│   │   ├── agent-manager.ts
│   │   ├── policy-engine.ts
│   │   ├── approval-workflow.ts
│   │   ├── audit-logger.ts
│   │   └── template-library.ts
│   ├── prompts/              # MCP prompts
│   └── types/                # TypeScript definitions
├── package.json
├── tsconfig.json
└── README.md
```

### Running Tests

```bash
npm test
npm run test:coverage
```

## 📊 Performance

| Metric | Target |
|--------|--------|
| MCP server startup | <2 seconds |
| Tool response time | <500ms (p95) |
| Memory footprint | <100MB |
| Policy evaluation | <50ms |

## 📜 License

MIT License - see [LICENSE](../../LICENSE).

---

<div align="center">

**Build safe AI agents with AgentOS**

[GitHub](https://github.com/microsoft/agent-governance-toolkit) · [Documentation](../../docs/) · [Report Issue](https://github.com/microsoft/agent-governance-toolkit/issues)

**Made with 🛡️ by the Agent OS team**

</div>
