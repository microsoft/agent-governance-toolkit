# Agent OS for VS Code

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

**Kernel-level safety for AI coding assistants.**

![Agent OS Banner](images/banner.png)

## The Problem

AI coding assistants (GitHub Copilot, Cursor, Claude) generate code without safety guarantees. They can suggest:
- `DROP TABLE users` - deleting production data
- Hardcoded API keys and secrets
- `rm -rf /` - destructive file operations
- Code with SQL injection vulnerabilities

**73% of developers are hesitant to trust AI for critical code.**

## The Solution

Agent OS wraps your AI assistant with a kernel that provides:

- 🛡️ **Real-time policy enforcement** - Block destructive operations before they execute
- 🔍 **Multi-model code review (CMVK)** - Verify code with GPT-4, Claude, and Gemini
- 📋 **Complete audit trail** - Log every AI suggestion and your decisions
- 👥 **Team-shared policies** - Consistent safety across your organization
- 🏢 **Enterprise ready** - SSO, RBAC, compliance frameworks

## What's New in v1.0.0 (GA Release)

### Policy Management Studio
Visual interface for creating, editing, and testing policies with:
- Syntax highlighting and validation
- Policy template library (SOC 2, GDPR, HIPAA, PCI DSS)
- Real-time testing against sample scenarios
- Import/export support (YAML, JSON, Rego)

### Workflow Designer
Drag-and-drop canvas for building agent workflows:
- Visual workflow builder
- Policy attachment at workflow/step level
- Simulation and dry-run capabilities
- Code export (Python, TypeScript, Go)

### Enhanced IntelliSense
AI-powered development assistance:
- Context-aware code completion for AgentOS APIs
- Real-time diagnostics with quick fixes
- 14+ code snippets for common patterns
- Inline policy suggestions

### Metrics Dashboard
Real-time monitoring of agent activity:
- Policy violation tracking
- Activity visualization by hour
- Compliance reporting
- Export to JSON/CSV

### Enterprise Features
- **SSO Integration**: Azure AD, Okta, Google, GitHub
- **Role-Based Access Control**: Granular permissions
- **CI/CD Integration**: GitHub Actions, GitLab CI, Jenkins, Azure Pipelines
- **Compliance Frameworks**: SOC 2, GDPR, HIPAA, PCI DSS templates

## What's New in v1.1.0

### Governance Visualization Hub
Unified dashboard for real-time governance monitoring:
- **SLO Dashboard** -- Availability, latency P50/P95/P99, policy compliance, trust scores with error budgets and burn rates
- **Agent Topology** -- Force-directed graph of agent mesh, trust rings, bridge status, delegation chains
- **Audit Stream** -- Filterable event log with drill-down
- **3-Slot Sidebar** -- Configurable panel system with 8 available views, panel picker for slot assignment
- **Scanning Mode** -- Auto-rotates visual focus through slots (4s cadence), pauses on hover/focus, respects prefers-reduced-motion
- **Priority Engine** -- Auto-reorders slots by health urgency in Auto mode (critical > warning > healthy)
- **Attention Toggle** -- Manual/Auto switch in sidebar header; manual locks to user config
- **Browser Experience** -- Open dashboard in external browser via local server

### Server Security Hardening
The Governance Server that powers the browser dashboard includes defense-in-depth security controls:
- **Session token authentication** -- WebSocket connections require a cryptographically random token generated per server session. Connections without a valid token are rejected with close code 4001.
- **Rate limiting** -- HTTP requests are limited to 100 per minute per client IP. Excess requests receive HTTP 429 with `Retry-After` header.
- **Local asset bundling** -- D3.js and Chart.js vendored locally (no CDN dependency). Eliminates supply-chain risk from external script loading.
- **Content Security Policy (CSP)** -- Restricts script execution to nonce-only (`'nonce-...'`). No CDN allowlisting, no `unsafe-eval`. WebSocket connect-src explicitly scoped to `ws://127.0.0.1:*`.
- **HTML escaping** -- Shared `escapeHtml` utility applied to all dynamic data in innerHTML assignments across legacy panels. Prevents XSS from agent DIDs, policy names, and audit data.
- **Loopback-only binding** -- Server binds exclusively to `127.0.0.1`. Remote connections are structurally impossible.
- **Python path validation** -- Rejects shell metacharacters before subprocess spawn to prevent command injection.
- **Dependency pinning** -- Production dependencies (axios, ws) pinned to exact versions for reproducible builds.

For the full security model, threat analysis, and accepted risks, see [SECURITY.md](SECURITY.md).

### Live Governance Data
The extension automatically detects and starts [agent-failsafe](https://pypi.org/project/agent-failsafe/) to populate dashboards with real governance data:
- On first activation, the extension checks for `agent-failsafe` and offers to install it if missing (`pip install agent-failsafe[server]`)
- Once installed, a local REST server starts automatically on `127.0.0.1:9377` — no manual configuration required
- SLO dashboard, agent topology, and audit stream populate with live policy compliance, fleet health, and audit events
- Status bar shows connection state: Live (green), Stale (yellow), Disconnected (red)
- All REST responses validated with type checking, size caps, and string truncation
- Advanced: override with `agentOS.governance.endpoint` to connect to an existing server

### Policy Diagnostics
- Real-time governance rule validation on Python/TypeScript/YAML files
- Code actions: safe alternatives for flagged patterns
- Status bar with governance mode and execution ring indicator

### Report Export
- Export governance snapshot as self-contained HTML report
- Metrics exporter pushes dashboard data to configured observability endpoints

## Quick Start

1. Install from VS Code Marketplace
2. Run **"Agent OS: Getting Started"** from command palette
3. Start coding - Agent OS protects you automatically

```
⚠️  Agent OS Warning

Blocked: Destructive SQL operation detected

The AI suggested: DELETE FROM users WHERE ...
This violates your safety policy.

[Review Policy] [Allow Once] [Suggest Alternative]
```

## Features

### 1. Real-Time Code Safety

Agent OS analyzes code as you type/paste and blocks dangerous patterns:

| Policy | Default | Description |
|--------|---------|-------------|
| Destructive SQL | ✅ On | Block DROP, DELETE, TRUNCATE |
| File Deletes | ✅ On | Block rm -rf, unlink, rmtree |
| Secret Exposure | ✅ On | Block hardcoded API keys, passwords |
| Privilege Escalation | ✅ On | Block sudo, chmod 777 |
| Unsafe Network | ❌ Off | Block HTTP (non-HTTPS) calls |

### 2. CMVK Multi-Model Review

Right-click on code and select **"Agent OS: Review Code with CMVK"** to get a consensus review from multiple AI models:

```
🛡️ Agent OS Code Review

Consensus: 66% Agreement

✅ GPT-4:     No issues
✅ Claude:    No issues  
⚠️  Gemini:   Potential SQL injection (Line 42)

Recommendations:
1. Use parameterized queries to prevent SQL injection
```

### 3. Audit Log Sidebar

Click the shield icon in the activity bar to see:
- Blocked operations today/this week
- Warning history
- CMVK review results
- Export capability for compliance

### 4. Team Policies

Share policies via `.vscode/agent-os.json`:

```json
{
  "policies": {
    "blockDestructiveSQL": true,
    "blockFileDeletes": true,
    "blockSecretExposure": true
  },
  "customRules": [
    {
      "name": "no_console_log",
      "pattern": "console\\.log",
      "message": "Remove console.log before committing",
      "severity": "low"
    }
  ]
}
```

## Commands

| Command | Description |
|---------|-------------|
| `Agent OS: Getting Started` | Interactive onboarding tutorial |
| `Agent OS: Open Policy Editor` | Visual policy management studio |
| `Agent OS: Open Workflow Designer` | Drag-and-drop workflow builder |
| `Agent OS: Show Metrics Dashboard` | Real-time monitoring |
| `Agent OS: Review Code with CMVK` | Multi-model code review |
| `Agent OS: Toggle Safety Mode` | Enable/disable protection |
| `Agent OS: Configure Policies` | Open policy configuration |
| `Agent OS: Export Audit Log` | Export logs to JSON |
| `Agent OS: Setup CI/CD Integration` | Generate CI/CD configuration |
| `Agent OS: Check Compliance` | Run compliance validation |
| `Agent OS: Sign In (Enterprise)` | Enterprise SSO authentication |
| `Agent OS: SLO Dashboard (Visual)` | Rich webview SLO dashboard |
| `Agent OS: Agent Topology Graph` | Force-directed agent topology graph |
| `Agent OS: Refresh SLO Data` | Refresh SLO metrics |
| `Agent OS: Refresh Agent Topology` | Refresh topology data |
| `Agent OS: Open Governance Hub` | Unified governance dashboard |
| `Agent OS: Open SLO Dashboard in Browser` | SLO dashboard in external browser |
| `Agent OS: Open Topology Graph in Browser` | Topology graph in external browser |
| `Agent OS: Open Governance Hub in Browser` | Governance Hub in external browser |
| `Agent OS: Export Governance Report` | Export HTML governance report |

## Configuration

Open Settings (Ctrl+,) and search for "Agent OS":

| Setting | Default | Description |
|---------|---------|-------------|
| `agentOS.enabled` | true | Enable/disable Agent OS |
| `agentOS.mode` | basic | basic, enhanced (CMVK), enterprise |
| `agentOS.cmvk.enabled` | false | Enable multi-model verification |
| `agentOS.cmvk.models` | ["gpt-4", "claude-sonnet-4", "gemini-pro"] | Models for CMVK |
| `agentOS.audit.retentionDays` | 7 | Days to keep audit logs |
| `agentOS.diagnostics.enabled` | true | Real-time diagnostics |
| `agentOS.enterprise.sso.enabled` | false | Enterprise SSO |
| `agentOS.enterprise.compliance.framework` | - | Default compliance framework |
| `agentOS.export.localPath` | "" | Local directory for exported reports |
| `agentOS.observability.endpoint` | "" | Metrics push endpoint (OTEL compatible) |
| `agentOS.diagnostics.severity` | "warning" | Minimum diagnostic severity |
| `agentOS.governance.pythonPath` | "python" | Python interpreter with agent-failsafe installed |
| `agentOS.governance.endpoint` | "" | Override: connect to existing agent-failsafe server (auto-start if empty) |
| `agentOS.governance.refreshIntervalMs` | 10000 | Polling interval for governance data (minimum 5000ms) |

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | Local policies, 7-day audit, 10 CMVK/day |
| **Pro** | $9/mo | Unlimited CMVK, 90-day audit, priority support |
| **Enterprise** | Custom | Self-hosted, SSO, RBAC, compliance reports |

## Privacy and Security

- **Local-first**: Policy checks run entirely in the extension
- **No network**: Basic mode never sends code anywhere
- **Opt-in CMVK**: You choose when to use cloud verification
- **Loopback server**: The browser dashboard server binds to `127.0.0.1` only and requires session token authentication
- **No telemetry**: The Governance Server does not send data to external endpoints unless you explicitly configure an observability endpoint
- **Open source**: Inspect the code yourself

See [SECURITY.md](SECURITY.md) for the full server security model and threat analysis.

## Requirements

- VS Code 1.85.0 or later
- Node.js 18+ (for development)
- Python 3.10+ (for Agent OS SDK)

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE).

---

**Made with 🛡️ by the Agent OS team**

[GitHub](https://github.com/microsoft/agent-governance-toolkit) | [Documentation](https://agent-os.dev/docs) | [Report Issue](https://github.com/microsoft/agent-governance-toolkit/issues)
