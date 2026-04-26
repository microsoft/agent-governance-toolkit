# Agent OS for JetBrains IDEs

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

**Enterprise-grade AI agent safety for IntelliJ, PyCharm, WebStorm, and all JetBrains IDEs.**

## What's New in v1.0

- 🤖 **Agent Creation Wizard** - Build agents with a few clicks using templates
- ⚙️ **.agentos.yml Support** - Git-tracked project configuration
- ▶️ **Run/Debug Agents** - Native IDE run configurations
- 📋 **Enhanced Tool Window** - Tabbed UI with agent management
- 🎯 **Context Menu Actions** - Create agents from selected code

## The Problem

AI coding assistants can suggest dangerous code:
- `DROP TABLE users` - deleting production data
- Hardcoded API keys and secrets
- `rm -rf /` - destructive file operations
- Code with security vulnerabilities

## The Solution

Agent OS wraps your AI assistant with a kernel that provides:

- 🛡️ **Real-time policy enforcement** - Block destructive operations before they execute
- 🔍 **Multi-model code review (CMVK)** - Verify code with GPT-4, Claude, and Gemini
- 📋 **Complete audit trail** - Log every AI suggestion and your decisions
- 👥 **Team-shared policies** - Consistent safety across your organization
- 🤖 **Agent management** - Create, run, and monitor AI agents from the IDE

## Installation

### From JetBrains Marketplace

1. Open Settings/Preferences → Plugins
2. Search for "Agent OS"
3. Click Install

### Manual Installation

1. Download the latest `.zip` from [Releases](https://github.com/microsoft/agent-governance-toolkit/releases)
2. Open Settings/Preferences → Plugins → ⚙️ → Install Plugin from Disk
3. Select the downloaded file

## Quick Start

1. **Open Agent OS Tool Window**: View → Tool Windows → Agent OS
2. **Create Your First Agent**: Click "+ Create Agent" and follow the wizard
3. **Configure Policies**: Settings → Tools → Agent OS
4. **Generate Config File**: Tools → Agent OS → Generate .agentos.yml

## Features

### 1. Agent Creation Wizard

Build agents in minutes with templates:

- 🔄 **Data Processing** - Process files and streams
- 🌐 **API Integration** - Connect to external APIs
- 🧪 **Test Generator** - Auto-generate unit tests
- 🔍 **Code Reviewer** - Review PRs for quality
- 📦 **Deployment** - CI/CD automation
- 🛡️ **Security Scanner** - Scan for vulnerabilities

### 2. Project Configuration (.agentos.yml)

```yaml
# .agentos.yml - Git-tracked agent configuration
organization: acme-corp
policies:
  - production-safety
  - secret-exposure

agents:
  code-reviewer:
    language: kotlin
    trigger: git_push
    policies:
      - code-quality
    approval: auto

  test-generator:
    language: java
    trigger: on_file_save
    approval: none
```

### 3. Run/Debug Agents

Native IDE integration:
- Create run configurations for agents
- Debug agents with breakpoints
- View agent output in console
- Stop/pause agents from toolbar

### 4. Real-Time Code Analysis

| Policy | Default | Description |
|--------|---------|-------------|
| Destructive SQL | ✅ On | Block DROP, DELETE, TRUNCATE |
| File Deletes | ✅ On | Block rm -rf, unlink, rmtree |
| Secret Exposure | ✅ On | Block hardcoded API keys, passwords |
| Privilege Escalation | ✅ On | Block sudo, chmod 777 |
| Unsafe Network | ❌ Off | Block HTTP (non-HTTPS) calls |

### 5. Context Menu Actions

Right-click on code to access:
- **Create Agent from Selection** - Turn code into an agent
- **Convert to Safe Agent** - Add safety checks
- **Add Policy Check Here** - Insert validation
- **Review with CMVK** - Multi-model verification

### 6. Enhanced Tool Window

Three tabs for complete visibility:
- **Agents** - List, start, stop, pause agents
- **Audit Log** - See all actions and policy checks
- **Policies** - View and configure safety rules

### 7. CMVK Multi-Model Review

Get consensus from multiple AI models:

```
🛡️ Agent OS Code Review

Consensus: 100% Agreement

✅ GPT-4:   No issues
✅ Claude:  No issues  
✅ Gemini:  No issues

Code appears safe.
```

## Configuration

Open Settings/Preferences → Tools → Agent OS:

| Setting | Default | Description |
|---------|---------|-------------|
| Enable Agent OS | true | Enable/disable all checks |
| API Key | - | Your AgentOS API key |
| API Endpoint | api.agent-os.dev | API server URL |
| CMVK Enabled | false | Enable multi-model verification |
| Auto-sync Agents | true | Sync with cloud backend |
| Agent Run Confirmation | true | Confirm before running agents |

## Supported IDEs

- IntelliJ IDEA (Community & Ultimate)
- PyCharm (Community & Professional)
- WebStorm
- PhpStorm
- GoLand
- RubyMine
- CLion
- Rider
- DataGrip
- Android Studio

**Requires IDE version 2024.1 or later**

## Actions & Shortcuts

| Action | Shortcut | Description |
|--------|----------|-------------|
| Create New Agent | `Ctrl+Shift+N` | Open agent wizard |
| Review with CMVK | `Ctrl+Shift+R` | Multi-model code review |
| Toggle Agent OS | `Ctrl+Shift+A` | Enable/disable protection |
| Show Audit Log | - | Open audit log tool window |
| Generate .agentos.yml | - | Create config file |

## Privacy

- **Local-first**: Policy checks run entirely in the plugin
- **No network**: Basic mode never sends code anywhere
- **Opt-in CMVK**: You choose when to use cloud verification
- **Open source**: Inspect the code yourself

## Building from Source

```bash
cd extensions/jetbrains

# Build the plugin
./gradlew build

# Run in sandbox IDE
./gradlew runIde

# Create distribution
./gradlew buildPlugin
```

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](../../LICENSE).

---

**Made with 🛡️ by the Agent OS team**

[GitHub](https://github.com/microsoft/agent-governance-toolkit) | [Documentation](https://agent-os.dev/docs) | [Report Issue](https://github.com/microsoft/agent-governance-toolkit/issues)
