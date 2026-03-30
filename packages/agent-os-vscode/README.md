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

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | Local policies, 7-day audit, 10 CMVK/day |
| **Pro** | $9/mo | Unlimited CMVK, 90-day audit, priority support |
| **Enterprise** | Custom | Self-hosted, SSO, RBAC, compliance reports |

## Privacy

- **Local-first**: Policy checks run entirely in the extension
- **No network**: Basic mode never sends code anywhere
- **Opt-in CMVK**: You choose when to use cloud verification
- **Open source**: Inspect the code yourself

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
