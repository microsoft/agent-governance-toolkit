# Agent OS for Cursor

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

**The AI IDE with a Safety Kernel**

![Agent OS Banner](images/banner.png)

> "The only AI IDE with kernel-level safety" - Making Cursor the safest AI coding experience.

## Why Agent OS for Cursor?

Cursor is the AI-first IDE. With Agent OS, it becomes the **safest** AI-first IDE.

### The Problem

Cursor's powerful AI (Composer, Copilot++) can suggest code that:
- `DROP TABLE users` - deletes production data
- Hardcoded API keys and secrets
- `rm -rf /` - destructive file operations  
- Code with SQL injection vulnerabilities

**Your AI won't accidentally destroy your production database.**

### The Solution

Agent OS wraps Cursor's AI with a safety kernel that provides:

- 🛡️ **Real-time policy enforcement** - Block destructive operations before they execute
- 🔍 **Multi-model code review (CMVK)** - Verify code with GPT-4, Claude, and Gemini
- 📋 **Complete audit trail** - Log every AI suggestion for SOC 2 compliance
- 🤖 **Cursor Integration** - Ask Cursor AI for safe alternatives when code is blocked
- 🏢 **Enterprise Ready** - SOC 2 mode, approval workflows, webhook streaming

## Quick Start

1. Install Agent OS for Cursor
2. Start coding - your AI is now protected

```
⚠️  Agent OS Warning

Blocked: Destructive SQL operation detected

Cursor Composer suggested: DELETE FROM users WHERE ...
This violates your safety policy.

[Review Policy] [Allow Once] [Ask Cursor for Alternative]
```

## Features

### 1. Real-Time Cursor AI Safety

Agent OS monitors all code from Cursor Composer and AI suggestions:

| Policy | Default | Description |
|--------|---------|-------------|
| Destructive SQL | ✅ On | Block DROP, DELETE, TRUNCATE |
| File Deletes | ✅ On | Block rm -rf, unlink, rmtree |
| Secret Exposure | ✅ On | Block hardcoded API keys, passwords |
| Privilege Escalation | ✅ On | Block sudo, chmod 777 |
| Unsafe Network | ❌ Off | Block HTTP (non-HTTPS) calls |

### 2. Ask Cursor for Safe Alternative

When code is blocked, Agent OS can automatically ask Cursor AI for a safe alternative:

```
⚠️ Blocked: DROP TABLE users

Would you like Cursor to suggest a safe alternative?

[Ask Cursor] → Cursor suggests: "-- Archive users to users_archive instead"
```

### 3. CMVK Multi-Model Review

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

### 4. Enterprise Features

**SOC 2 Compliance Mode:**
- Complete audit trails with retention policies
- Webhook streaming to your SIEM
- Approval workflows for high-risk operations

```json
{
  "agentOS.enterprise.soc2Mode": true,
  "agentOS.enterprise.requireApproval": true,
  "agentOS.enterprise.webhookUrl": "https://your-siem.example.com/agent-os"
}
```

### 5. Audit Log Sidebar

Click the shield icon in the activity bar to see:
- Blocked operations today/this week
- Warning history
- CMVK review results
- Export capability for compliance

### 6. Team Policies

Share policies via `.cursor/agent-os.json` (or `.vscode/agent-os.json`):

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

Commit to your repo - all team members get the same policies.

## Configuration

Open Settings (Ctrl+,) and search for "Agent OS":

| Setting | Default | Description |
|---------|---------|-------------|
| `agentOS.enabled` | true | Enable/disable Agent OS |
| `agentOS.mode` | basic | basic, enhanced (CMVK), enterprise |
| `agentOS.cursor.interceptComposer` | true | Intercept Cursor Composer suggestions |
| `agentOS.cursor.askForAlternative` | true | Offer safe alternatives from Cursor AI |
| `agentOS.cmvk.enabled` | false | Enable multi-model verification |
| `agentOS.cmvk.models` | ["gpt-4", "claude-sonnet-4", "gemini-pro"] | Models for CMVK |
| `agentOS.enterprise.soc2Mode` | false | Enable SOC 2 compliant logging |
| `agentOS.enterprise.requireApproval` | false | Require approval for high-risk ops |
| `agentOS.audit.retentionDays` | 7 | Days to keep audit logs |

## Commands

| Command | Description |
|---------|-------------|
| `Agent OS: Review Code with CMVK` | Multi-model code review |
| `Agent OS: Toggle Safety Mode` | Enable/disable protection |
| `Agent OS: Show Audit Log` | Open audit log sidebar |
| `Agent OS: Configure Policies` | Open policy configuration |
| `Agent OS: Export Audit Log` | Export logs to JSON |
| `Agent OS: Ask Cursor for Safe Alternative` | Get safe code from Cursor AI |
| `Agent OS: Enterprise Features` | View enterprise capabilities |

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | Local policies, 7-day audit, 10 CMVK/day |
| **Pro** | $9/mo | Unlimited CMVK, 90-day audit, priority support |
| **Enterprise** | Custom | Self-hosted, SSO, SOC 2 mode, approval workflows |

## Why Cursor + Agent OS?

| Feature | Other IDEs | Cursor + Agent OS |
|---------|------------|-------------------|
| AI Coding | ✅ | ✅ Best-in-class |
| Safety Guarantees | ❌ | ✅ Kernel-level |
| SOC 2 Ready | ❌ | ✅ Out of box |
| Multi-model Review | ❌ | ✅ CMVK |
| Audit Trail | ❌ | ✅ Complete |

**"Cursor won't delete your production code."**

## Privacy

- **Local-first**: Policy checks run entirely in the extension
- **No network**: Basic mode never sends code anywhere
- **Opt-in CMVK**: You choose when to use cloud verification
- **Open source**: Inspect the code yourself

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE).

---

**Made with 🛡️ by the Agent OS team**

**Making Cursor the safest AI IDE.**

[GitHub](https://github.com/microsoft/agent-governance-toolkit) | [Documentation](https://agent-os.dev/docs) | [Report Issue](https://github.com/microsoft/agent-governance-toolkit/issues)
