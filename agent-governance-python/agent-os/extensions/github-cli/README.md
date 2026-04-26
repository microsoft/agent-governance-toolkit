# Agent OS GitHub CLI Extension

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

**GitHub CLI extension for Agent OS - The Linux Kernel for AI Agents**

## Installation

```bash
gh extension install microsoft/gh-agent-os
```

## Commands

### Run a task with governance

```bash
gh agent-os run "analyze this codebase for security issues"
```

### Audit your codebase

```bash
gh agent-os audit --policy strict
```

### Initialize Agent OS

```bash
gh agent-os init
```

### Check status

```bash
gh agent-os status
```

## Policy Levels

- **strict**: Maximum safety, requires human approval
- **standard**: Balanced safety and autonomy (default)
- **permissive**: Minimal restrictions

## Configuration

After running `gh agent-os init`, customize `.agent-governance-python/agent-os/policy.yaml`:

```yaml
version: 1
name: my-policy

governance:
  max_tokens: 4096
  max_tool_calls: 10
  timeout_seconds: 300

safety:
  confidence_threshold: 0.8
  require_human_approval: false

blocked_patterns:
  - "rm -rf"
  - "DROP TABLE"

allowed_tools:
  - read_file
  - write_file
```

## Learn More

- [Agent OS Documentation](https://github.com/microsoft/agent-governance-toolkit)
- [Integration Guide](https://github.com/microsoft/agent-governance-toolkit/blob/master/docs/integrations.md)
