# DevOps Automation Agent

Secure a DevOps agent that deploys infrastructure, manages secrets, and executes privileged operations with short-lived credentials and delegation.

## What This Example Shows

- **Narrow Delegation:** Sub-agents for different infrastructure tasks
- **Short-Lived Credentials:** Ephemeral credentials for privileged operations
- **Resource-Specific Capability Grants:** Fine-grained permissions
- **Behavioral Scoring:** Trust score adapts to behavior

## Use Case

A DevOps automation agent that:
- Deploys applications to production
- Manages infrastructure secrets
- Executes database migrations
- **Never** allows unrestricted access to production
- Requires approval for destructive operations

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│           DevOps Automation Supervisor                      │
│           Trust Score: 920/1000                             │
└────────────────┬────────────────────────────────────────────┘
                 │ Narrow Delegation
     ┌───────────┼───────────┬────────────────┐
     │           │           │                │
┌────▼─────┐ ┌──▼────────┐ ┌▼──────────┐  ┌─▼─────────────┐
│ Deploy   │ │ Secret    │ │ Database  │  │ Monitoring    │
│ Agent    │ │ Manager   │ │ Agent     │  │ Agent         │
│ (read)   │ │ (secrets) │ │ (migrate) │  │ (read-only)   │
└──────────┘ └───────────┘ └───────────┘  └───────────────┘
```

## Key Features

### 1. Short-Lived Credentials

```python
# Request temporary credentials for deployment
cred = credential_manager.issue_credential(
    agent_id=deploy_agent.did,
    scope=["deploy:production"],
    ttl_minutes=15  # Expires in 15 minutes
)
```

### 2. Narrow Delegation

```python
# Deploy agent can only deploy, not manage secrets
deploy_agent = supervisor.delegate(
    name="deploy-agent",
    capabilities=["deploy:staging", "deploy:production"]
)

# Secret manager can only read/write secrets
secret_agent = supervisor.delegate(
    name="secret-manager",
    capabilities=["read:secrets", "write:secrets"]
)
```

### 3. Require Approval for Destructive Operations

```yaml
policies:
  - name: "approve-production-deployments"
    rules:
      - condition: "action == 'deploy' and environment == 'production'"
        action: "require_approval"
        approvers: ["sre-team@company.com"]
```

### 4. Behavioral Scoring

Agent trust score decreases on:
- Failed deployments
- Policy violations
- Unusual access patterns
- Credential misuse

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the DevOps agent
python main.py
```

## Security Features

| Feature | Implementation |
|---------|----------------|
| **Short-Lived Credentials** | 15-minute TTL, auto-rotation |
| **Narrow Delegation** | Each sub-agent has minimal capabilities |
| **Approval Workflows** | Destructive operations require human approval |
| **Audit Trail** | All operations logged |
| **Risk Scoring** | Trust score adapts to behavior |
| **Secret Management** | Integration with HashiCorp Vault |

## Example Output

```
🚀 DevOps Automation Agent

Supervisor: did:agentmesh:devops-supervisor
Trust Score: 920/1000

Sub-Agents:
  • deploy-agent (capabilities: deploy:staging, deploy:production)
  • secret-manager (capabilities: read:secrets, write:secrets)
  • database-agent (capabilities: migrate:database)

📋 Deployment Task: Deploy app-v2.0 to production

  1. ✓ Credentials issued (TTL: 15min)
  2. ✓ Approval requested from SRE team
  3. ⏳ Waiting for approval...
  4. ✓ Approval granted by john@company.com
  5. ✓ Deployment successful
  6. ✓ Trust score updated: 925/1000
```

## Best Practices

1. **Always use short-lived credentials** for production access
2. **Require approval** for destructive operations
3. **Monitor trust scores** and set alerts
4. **Rotate secrets** automatically
5. **Test in staging** before production

## Learn More

- [AgentMesh Delegation](../../docs/delegation.md)
- [Credentials](../../docs/credentials.md)
- [Risk Scoring](../../docs/risk-scoring.md)

---

**Production Ready:** Yes, with proper secret management and approval workflows.
