# AgentOS VS Code Extension Tutorial

This guide walks you through all features of the AgentOS VS Code Extension, the visual development environment for building safe, policy-compliant AI agents.

## Table of Contents

1. [Installation](#installation)
2. [Getting Started](#getting-started)
3. [Policy Editor](#policy-editor)
4. [Workflow Designer](#workflow-designer)
5. [Security Diagnostics](#security-diagnostics)
6. [Metrics Dashboard](#metrics-dashboard)
7. [IntelliSense & Snippets](#intellisense--snippets)
8. [Enterprise Features](#enterprise-features)
9. [CI/CD Integration](#cicd-integration)
10. [Troubleshooting](#troubleshooting)

---

## Installation

### From VS Code Marketplace

1. Open VS Code
2. Press `Ctrl+Shift+X` to open Extensions
3. Search for **"Agent OS"**
4. Click **Install**

### From Command Line

```powershell
code --install-extension agent-os.agent-os-vscode
```

### Verify Installation

Press `Ctrl+Shift+P` and type `Agent OS` — you should see available commands:

- Agent OS: Getting Started
- Agent OS: Open Policy Editor
- Agent OS: Open Workflow Designer
- Agent OS: Show Metrics Dashboard
- And more...

---

## Getting Started

The onboarding experience helps you get productive quickly.

### Launch Onboarding

```
Ctrl+Shift+P → "Agent OS: Getting Started"
```

### Onboarding Steps

| Step | Description | Action |
|------|-------------|--------|
| 1. Install Extension | Automatic check | ✅ Auto-completed |
| 2. Configure Policies | Set up safety rules | Opens Policy Editor |
| 3. Create First Agent | Build your first agent | Creates template project |
| 4. Run Safety Test | Verify policy enforcement | Runs validation |

### First Agent in 5 Minutes

1. Open Getting Started panel
2. Click **"Create First Agent"**
3. Choose a template (e.g., "Data Processor")
4. The extension creates a project with:
   - `agent.py` - Main agent code
   - `policy.yaml` - Safety policy
   - `README.md` - Documentation

5. Run with `python agent.py`

---

## Policy Editor

The Policy Editor provides a visual interface for creating and managing safety policies.

### Open Policy Editor

```
Ctrl+Shift+P → "Agent OS: Open Policy Editor"
```

### Interface Overview

```
┌──────────────────────────────────────────────────────────────┐
│  Policy Editor                                               │
├──────────────────────────────────────────────────────────────┤
│  Template: [Strict Security ▼]                               │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ policy:                                                  ││
│  │   name: "Strict Security Policy"                         ││
│  │   version: "1.0"                                         ││
│  │   rules:                                                 ││
│  │     - name: "Block file writes"                          ││
│  │       condition: "agent.action == 'file.write'"          ││
│  │       constraint: "path.startsWith('/tmp/')"             ││
│  │       action: "deny"                                     ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  [Validate] [Save Policy] [Export]                           │
└──────────────────────────────────────────────────────────────┘
```

### Available Templates

| Template | Use Case |
|----------|----------|
| **Strict Security** | Production environments, high-security |
| **SOC 2 Compliance** | Enterprise compliance requirements |
| **GDPR Data Handling** | EU data protection requirements |
| **Development** | Permissive for local development |
| **Rate Limiting** | API call restrictions |

### Creating a Custom Policy

1. Select a template as starting point
2. Modify the YAML in the editor
3. Click **Validate** to check syntax
4. Click **Save Policy** to save to your workspace

### Policy Rule Structure

```yaml
rules:
  - name: "Rule name"
    condition: "when to apply"      # e.g., "agent.action == 'http.request'"
    constraint: "what to check"     # e.g., "url.host in allowed_domains"
    action: "deny | warn | allow"   # what to do
    message: "User-facing message"  # shown when triggered
```

### Example: Block External API Calls

```yaml
policy:
  name: "Internal Only"
  rules:
    - name: "Block external APIs"
      condition: "agent.action == 'http.request'"
      constraint: "not url.host.endsWith('.internal.company.com')"
      action: "deny"
      message: "External API calls are not allowed"
```

---

## Workflow Designer

The visual workflow builder lets you design agent workflows without writing code.

### Open Workflow Designer

```
Ctrl+Shift+P → "Agent OS: Open Workflow Designer"
```

### Interface Overview

```
┌─────────────┬───────────────────────────────┬──────────────┐
│ Components  │          Canvas               │  Properties  │
├─────────────┼───────────────────────────────┼──────────────┤
│             │                               │              │
│ ⚡ Action   │    ┌─────┐    ┌─────────┐    │  Label:      │
│             │    │Start├───▶│ Action  │    │  [Read File] │
│ 🔀 Condition│    └─────┘    └────┬────┘    │              │
│             │                    │         │  Action Type:│
│ 🔄 Loop     │              ┌─────▼────┐    │  [file_read] │
│             │              │Transform │    │              │
│ ⚔️ Parallel │              └────┬─────┘    │  Policy:     │
│             │                   │          │  [strict ▼]  │
│             │              ┌────▼───┐      │              │
│             │              │  End   │      │  [🗑️ Delete] │
│             │              └────────┘      │              │
└─────────────┴───────────────────────────────┴──────────────┘
```

### Node Types

| Node | Icon | Description |
|------|------|-------------|
| **Action** | ⚡ | Execute an operation (file, API, database) |
| **Condition** | 🔀 | Branch based on a condition |
| **Loop** | 🔄 | Repeat a sequence of actions |
| **Parallel** | ⚔️ | Execute multiple actions concurrently |

### Action Types

When you place an Action node, configure its type:

- `file_read` - Read a file
- `file_write` - Write a file
- `http_request` - Make HTTP call
- `database_query` - Query database
- `database_write` - Write to database
- `llm_call` - Call LLM API
- `send_email` - Send email
- `code_execution` - Execute code

### Building a Workflow

1. **Drag nodes** from the left panel onto the canvas
2. **Connect nodes** by dragging from output port (right) to input port (left)
3. **Configure nodes** by clicking them and editing properties
4. **Attach policies** to individual nodes for fine-grained control

### Exporting Code

Click the **Export Code** button to generate:

| Language | Output |
|----------|--------|
| Python | `workflow.py` with async functions |
| TypeScript | `workflow.ts` with AgentOS SDK |
| Go | `workflow.go` with kernel integration |

### Example: Data Processing Workflow

1. Add **Action** node → Set type: `file_read`
2. Add **Action** node → Set type: `llm_call`
3. Add **Action** node → Set type: `file_write`
4. Connect: Start → file_read → llm_call → file_write → End
5. Attach "strict" policy to `file_write` node
6. Export to Python

Generated code:

```python
from agent_os import KernelSpace, Policy

kernel = KernelSpace(policy="strict")

async def file_read(context):
    """Read input file"""
    # TODO: Implement file_read
    return {"status": "success"}

async def llm_call(context):
    """Process with LLM"""
    # TODO: Implement llm_call
    return {"status": "success"}

async def file_write(context):
    """Write output file"""
    # Policy: strict
    # TODO: Implement file_write
    return {"status": "success"}

@kernel.register
async def run_workflow(task: str):
    context = {"task": task}
    result = await file_read(context)
    result = await llm_call(context)
    result = await file_write(context)
    return result
```

---

## Security Diagnostics

Real-time security analysis of your code with automatic issue detection.

### How It Works

The extension analyzes your Python, TypeScript, and JavaScript files as you type, highlighting potential security issues.

### Detected Issues

| Pattern | Risk Level | Description |
|---------|------------|-------------|
| `os.system()` | 🔴 High | Arbitrary command execution |
| `eval()` | 🔴 High | Code injection risk |
| `exec()` | 🔴 High | Dynamic code execution |
| `subprocess.call(shell=True)` | 🟡 Medium | Shell injection risk |
| `pickle.load()` | 🟡 Medium | Deserialization attacks |
| Hardcoded credentials | 🔴 High | Secret exposure |
| SQL string concatenation | 🟡 Medium | SQL injection risk |

### Example

When you write:

```python
import os

user_input = input("Enter command: ")
os.system(user_input)  # ⚠️ Warning: os.system() can execute arbitrary commands
```

You'll see:
- Yellow squiggle under `os.system(user_input)`
- Hover shows: "Security: os.system() can execute arbitrary commands. Use subprocess with explicit arguments instead."
- Quick fix available: "Replace with subprocess.run()"

### Quick Fixes

Click the lightbulb (💡) to see available fixes:

- **Replace os.system with subprocess.run**
- **Add input validation**
- **Use parameterized queries** (for SQL)
- **Use environment variables** (for secrets)

---

## Metrics Dashboard

Monitor agent activity and policy enforcement in real-time.

### Open Dashboard

```
Ctrl+Shift+P → "Agent OS: Show Metrics Dashboard"
```

### Dashboard Panels

#### 1. Summary Cards

```
┌──────────────┬──────────────┬──────────────┬──────────────┐
│ Total Checks │  Violations  │ Success Rate │   Latency    │
│    12,847    │   Blocked: 23│    99.8%     │    42ms      │
└──────────────┴──────────────┴──────────────┴──────────────┘
```

#### 2. Policy Checks Over Time

Line chart showing:
- Total policy evaluations
- Passed checks (green)
- Blocked violations (red)
- Warnings (yellow)

#### 3. Activity Feed

```
┌─────────────────────────────────────────────────────────────┐
│ Recent Activity                                             │
├─────────────────────────────────────────────────────────────┤
│ 🟢 14:32:15  Agent "data_processor" - file.read - ALLOWED   │
│ 🔴 14:32:14  Agent "web_scraper" - http.request - BLOCKED   │
│              Reason: External domain not in allowlist       │
│ 🟢 14:32:12  Agent "data_processor" - transform - ALLOWED   │
│ 🟡 14:32:10  Agent "code_gen" - code.execute - WARNING      │
│              Reason: Execution in non-sandboxed environment │
└─────────────────────────────────────────────────────────────┘
```

### Exporting Data

Click **Export** to download:
- **CSV** - For spreadsheet analysis
- **JSON** - For programmatic processing

---

## IntelliSense & Snippets

Intelligent code completion and pre-built templates for faster development.

### Code Completion

When working with AgentOS APIs, you get automatic suggestions:

```python
from agentos import Agent, Policy, Kernel, CMVKClient
#                   ↑ Autocomplete shows all available imports

agent = Agent(
    name="",       # ↑ Parameter hints shown
    permissions=[] # ↑ Valid permission values suggested
)
```

### Snippets

Type the prefix and press `Tab` to expand:

| Prefix | Description |
|--------|-------------|
| `aos-agent` | Create a simple agent |
| `aos-policy` | Policy YAML template |
| `aos-kernel` | Kernel setup code |
| `aos-workflow` | Workflow function template |
| `aos-cmvk` | CMVK review integration |
| `aos-langchain` | LangChain integration |
| `aos-github-action` | GitHub Actions workflow |

### Example: aos-agent

Type `aos-agent` and press Tab:

```python
from agent_os import KernelSpace, Policy
from agent_os.tools import create_safe_toolkit

# Initialize kernel with safety guarantees
kernel = KernelSpace(policy="strict")
toolkit = create_safe_toolkit("standard")

@kernel.agent
async def my_agent(task: str):
    """Agent with full safety guarantees"""
    result = await kernel.execute(task, toolkit=toolkit)
    return result

if __name__ == "__main__":
    import asyncio
    asyncio.run(my_agent("your task here"))
```

---

## Enterprise Features

Advanced features for teams and organizations.

### SSO Sign-In

```
Ctrl+Shift+P → "Agent OS: Sign In (Enterprise)"
```

Supported providers:
- Azure Active Directory
- Okta
- Google Workspace
- GitHub Enterprise

### Role-Based Access Control (RBAC)

| Role | Permissions |
|------|-------------|
| **Admin** | Full access to all features |
| **Security Officer** | Manage policies, view audit logs |
| **Policy Admin** | Create/edit policies |
| **Developer** | Use policies, deploy agents |
| **Viewer** | Read-only access |

### Compliance Check

```
Ctrl+Shift+P → "Agent OS: Check Compliance"
```

Available frameworks:
- **SOC 2 Type II** - Security, availability, processing integrity
- **GDPR** - EU data protection
- **HIPAA** - Healthcare data protection
- **PCI DSS** - Payment card security

The compliance report shows:
- Controls evaluated
- Pass/fail status
- Remediation recommendations

---

## CI/CD Integration

Integrate AgentOS policy checks into your build pipeline.

### Setup

```
Ctrl+Shift+P → "Agent OS: Setup CI/CD Integration"
```

Choose your platform:
- GitHub Actions
- GitLab CI
- Jenkins
- Azure Pipelines
- CircleCI

### GitHub Actions Example

Generated `.github/workflows/agentos.yml`:

```yaml
name: AgentOS Policy Check

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install AgentOS
        run: pip install agent-os-kernel
      
      - name: Run Policy Validation
        run: agent-os validate --policy policies/ --strict
        env:
          AGENT_OS_KEY: ${{ secrets.AGENT_OS_KEY }}
      
      - name: Security Scan
        run: agent-os scan --path src/ --output sarif
      
      - name: Upload Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: agentos-results.sarif
```

### Git Hooks

Install pre-commit hooks to validate policies locally:

```
Ctrl+Shift+P → "Agent OS: Install Git Hooks"
```

This adds:
- **pre-commit**: Validates changed policy files
- **pre-push**: Runs full policy compliance check

---

## Troubleshooting

### Extension Not Activating

1. Check VS Code version (requires 1.85.0+)
2. Reload window: `Ctrl+Shift+P` → "Developer: Reload Window"
3. Check Output panel: `View` → `Output` → Select "Agent OS"

### Snippets Not Appearing

1. Ensure you're in a supported file type (`.py`, `.ts`, `.js`, `.yaml`)
2. Press `Ctrl+Space` to manually trigger suggestions
3. Check that snippets are enabled in settings

### Policy Validation Errors

Common issues:

| Error | Solution |
|-------|----------|
| "Invalid YAML syntax" | Check indentation (use spaces, not tabs) |
| "Unknown rule action" | Use: `deny`, `allow`, or `warn` |
| "Missing required field" | Ensure `name`, `condition`, `action` are present |

### Performance Issues

If the extension feels slow:

1. Check memory usage in Task Manager
2. Disable unused features in settings
3. Exclude large directories from analysis

### Getting Help

- **Documentation**: [github.com/microsoft/agent-governance-toolkit/docs](https://github.com/microsoft/agent-governance-toolkit/docs)
- **Issues**: [github.com/microsoft/agent-governance-toolkit/issues](https://github.com/microsoft/agent-governance-toolkit/issues)
- **Discord**: Join our community for real-time help

---

## Summary

The AgentOS VS Code Extension provides everything you need to build safe AI agents:

| Feature | Benefit |
|---------|---------|
| **Policy Editor** | Visual policy creation with templates |
| **Workflow Designer** | No-code agent workflow building |
| **Security Diagnostics** | Real-time vulnerability detection |
| **Metrics Dashboard** | Monitor policy enforcement |
| **IntelliSense** | Faster development with smart completions |
| **Enterprise SSO** | Secure team authentication |
| **CI/CD Integration** | Automated policy checks in pipelines |

Start with `Ctrl+Shift+P` → **"Agent OS: Getting Started"** and build your first safe agent in minutes!
