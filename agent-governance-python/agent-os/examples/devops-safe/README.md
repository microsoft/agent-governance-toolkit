# DevOps Agent (Safe Deployments)

A deployment agent with guardrails to prevent dangerous operations.

## What it demonstrates

- **Command Blocking**: Blocks dangerous shell commands (rm -rf, chmod 777, etc.)
- **Environment Protection**: Prevents production changes without approval
- **Rollback Capability**: Automatic rollback on failures
- **Change Windows**: Only allows deployments during approved times

## Quick Start

```bash
pip install agent-os-kernel
python main.py
```

## Policy Configuration

```yaml
# policy.yaml - DevOps Safety Policy
version: "1.0"
name: devops-safe-agent

dangerous_commands:
  - "rm -rf /"
  - "rm -rf /*"
  - "chmod 777"
  - "chmod -R 777"
  - "> /dev/sda"
  - "mkfs"
  - "dd if=/dev/zero"
  - ":(){:|:&};:"  # fork bomb
  
protected_paths:
  - /etc
  - /usr
  - /var/log
  - /home

rules:
  - name: block-dangerous-commands
    trigger: action
    condition:
      action_type: shell_command
    check: not_in_dangerous_list
    action: block
    message: "Dangerous command blocked for safety"

  - name: protect-production
    trigger: action
    condition:
      environment: production
      action_type: [deploy, delete, modify]
    action: require_approval
    approvers: [devops-lead, sre-oncall]

  - name: change-window
    trigger: action
    condition:
      action_type: deploy
      environment: production
    check: within_change_window
    change_window:
      days: [tuesday, wednesday, thursday]
      hours: [10, 16]  # 10 AM - 4 PM
    action: block
    message: "Deployments only allowed during change window"

  - name: require-rollback-plan
    trigger: action
    condition:
      action_type: deploy
    check: has_rollback_plan
    action: warn
```

## Example Usage

```python
from agent_os import Kernel
from agent_os.presets import DevOpsSafetyPolicy

kernel = Kernel(policy=DevOpsSafetyPolicy())

agent = kernel.create_agent(
    name="DeployBot",
    environment="production"
)

# Safe command - allowed
result = agent.execute("kubectl get pods")
# ✅ Executed successfully

# Dangerous command - blocked
result = agent.execute("rm -rf /")
# ❌ BLOCKED: Dangerous command blocked for safety

# Production deploy - requires approval
result = agent.execute("kubectl apply -f deployment.yaml")
# ⏳ Pending approval from devops-lead or sre-oncall
```

## Safety Features

| Risk | Protection |
|------|------------|
| Destructive commands | Pattern-based blocking |
| Production changes | Multi-person approval |
| Wrong environment | Environment isolation |
| Failed deploys | Automatic rollback |
| Off-hours changes | Change window enforcement |

## Files

- `main.py` - DevOps agent implementation
- `policy.yaml` - Safety policy
- `README.md` - This file
