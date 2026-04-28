# AutoGPT Integration with AgentMesh

Govern AutoGPT instances with AgentMesh identity, policies, and trust scoring.

## Why Integrate AgentMesh with AutoGPT?

AutoGPT provides autonomous agent capabilities, but AgentMesh adds critical governance:
- **Cryptographic identity** for each AutoGPT instance
- **Policy enforcement** on tool usage and actions
- **Audit logging** for compliance
- **Trust scoring** to prevent runaway agents

## Quick Start

### Installation

```bash
pip install agentmesh-platform autogpt
```

### Basic Integration

```python
import autogpt
from autogpt.agents import Agent as AutoGPTAgent
from agentmesh import AgentIdentity, PolicyEngine, AuditLog, RewardEngine

# Create AgentMesh identity for AutoGPT instance
identity = AgentIdentity.create(
    name="autogpt-instance-1",
    sponsor="automation@company.com",
    capabilities=[
        "tool:web_search",
        "tool:file_ops",
        "tool:code_execution"
    ]
)

# Initialize governance
policy_engine = PolicyEngine.from_file("policies/autogpt.yaml")
audit_log = AuditLog(agent_id=identity.did)
reward_engine = RewardEngine()

class GovernedAutoGPT(AutoGPTAgent):
    """AutoGPT with AgentMesh governance."""
    
    # Trust score adjustment constants
    TRUST_SCORE_SUCCESS_INCREMENT = 1
    TRUST_SCORE_FAILURE_DECREMENT = 5
    TRUST_SCORE_MIN_THRESHOLD = 500
    TRUST_SCORE_MAX = 1000
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.agentmesh_identity = identity
        self.policy_engine = policy_engine
        self.audit_log = audit_log
        self.trust_score = 800
    
    def execute_command(self, command_name: str, arguments: dict):
        """Execute command with governance."""
        
        # Policy check before execution
        policy_result = self.policy_engine.check(
            action="execute_command",
            command=command_name,
            params=arguments
        )
        
        if not policy_result.allowed:
            self.audit_log.log(
                "blocked",
                command=command_name,
                reason=policy_result.reason
            )
            raise PermissionError(f"Policy violation: {policy_result.reason}")
        
        # Execute command
        try:
            result = super().execute_command(command_name, arguments)
            
            # Log success
            self.audit_log.log(
                "success",
                command=command_name,
                result=result
            )
            
            # Update trust score (successful execution)
            self.trust_score = min(
                self.TRUST_SCORE_MAX,
                self.trust_score + self.TRUST_SCORE_SUCCESS_INCREMENT
            )
            
            return result
            
        except Exception as e:
            # Log failure
            self.audit_log.log(
                "failed",
                command=command_name,
                error=str(e)
            )
            
            # Decrease trust score on failure
            self.trust_score = max(
                0,
                self.trust_score - self.TRUST_SCORE_FAILURE_DECREMENT
            )
            
            raise
    
    def check_trust_score(self):
        """Check if trust score is above threshold."""
        if self.trust_score < self.TRUST_SCORE_MIN_THRESHOLD:
            print(f"⚠️  Trust score critical: {self.trust_score}/{self.TRUST_SCORE_MAX}")
            print("Revoking credentials and stopping agent.")
            self.agentmesh_identity.revoke_credentials()
            raise SecurityError("Trust score below minimum threshold")

# Create governed AutoGPT instance
agent = GovernedAutoGPT(
    ai_name="ResearchAssistant",
    ai_role="Research and summarize information",
    ai_goals=[
        "Research AI governance trends",
        "Summarize findings in a report",
        "Save report to file"
    ]
)

# Run with governance
agent.start_interaction_loop()
```

## Advanced Features

### 1. Prevent Infinite Loops

```yaml
# policies/autogpt.yaml
policies:
  - name: "prevent-infinite-loops"
    rules:
      - condition: "count(action='execute_command', window='1m') > 100"
        action: "block"
        message: "Too many commands in 1 minute (possible infinite loop)"
```

### 2. Limit Resource Usage

```yaml
policies:
  - name: "limit-file-operations"
    rules:
      - condition: "command == 'write_file' and file_size > 10485760"
        action: "block"
        message: "File size exceeds 10MB limit"
```

### 3. Require Approval for Destructive Actions

```yaml
policies:
  - name: "approve-destructive-actions"
    rules:
      - condition: "command in ['delete_file', 'execute_shell']"
        action: "require_approval"
        approvers: ["admin@company.com"]
```

### 4. Trust Score Decay on Bad Behavior

```python
# Update trust score based on AutoGPT behavior
def update_autogpt_trust_score(agent, action_result):
    if action_result.halted_due_to_loop:
        # Infinite loop detected
        agent.trust_score -= 50
    
    if action_result.violated_constraint:
        # Constraint violation
        agent.trust_score -= 20
    
    if action_result.succeeded:
        # Good behavior
        agent.trust_score = min(1000, agent.trust_score + 2)
    
    # Auto-revoke if score too low
    if agent.trust_score < 400:
        agent.agentmesh_identity.revoke_credentials()
```

## Real-World Example: Governed Research Agent

```python
from autogpt import AutoGPT
from agentmesh import AgentIdentity, PolicyEngine, AuditLog

# Create identity
identity = AgentIdentity.create(
    name="research-agent",
    sponsor="research-team@company.com",
    capabilities=["tool:web_search", "tool:file_ops"]
)

# Load policies
policy_engine = PolicyEngine.from_file("policies/research.yaml")
audit_log = AuditLog(agent_id=identity.did)

# Configure AutoGPT with governance
agent = GovernedAutoGPT(
    ai_name="ResearchBot",
    ai_role="Academic research assistant",
    ai_goals=[
        "Search for papers on AI governance",
        "Download and analyze top 10 papers",
        "Generate a summary report"
    ],
    # AgentMesh governance
    agentmesh_identity=identity,
    policy_engine=policy_engine,
    audit_log=audit_log
)

# Run with monitoring
agent.run()

# Generate compliance report
print(f"\nGovernance Report:")
print(f"  Agent: {identity.did}")
print(f"  Trust Score: {agent.trust_score}/1000")
print(f"  Commands Executed: {len(audit_log.entries)}")
print(f"  Policy Violations: {audit_log.count_violations()}")
```

## Policy Examples for AutoGPT

### Prevent Credential Leakage

```yaml
policies:
  - name: "no-credentials-in-files"
    rules:
      - condition: "command == 'write_file' and content contains 'api_key'"
        action: "redact"
        message: "API keys detected and redacted"
```

### Limit Web Scraping

```yaml
policies:
  - name: "limit-web-requests"
    rules:
      - condition: "command == 'web_search'"
        limit: "500/hour"
        action: "block"
```

### Block Dangerous Shell Commands

```yaml
policies:
  - name: "block-dangerous-shell"
    rules:
      - condition: "command == 'execute_shell' and args contains 'rm -rf'"
        action: "block"
        message: "Dangerous shell command blocked"
```

## Monitoring and Alerts

```python
# Set up trust score monitoring
def monitor_autogpt_trust(agent):
    if agent.trust_score < 600:
        # Send alert
        send_alert(
            f"AutoGPT trust score low: {agent.trust_score}/1000",
            severity="warning"
        )
    
    if agent.trust_score < 500:
        # Critical alert and auto-stop
        send_alert(
            f"AutoGPT stopped due to low trust score",
            severity="critical"
        )
        agent.stop()

# Run monitoring in background
import threading
monitor_thread = threading.Thread(
    target=lambda: monitor_autogpt_trust(agent),
    daemon=True
)
monitor_thread.start()
```

## Best Practices

1. **Always set trust score thresholds** and auto-revoke below threshold
2. **Limit command execution rate** to prevent infinite loops
3. **Require approval** for destructive actions
4. **Monitor audit logs** for unusual patterns
5. **Test policies** in shadow mode before enforcement

## Troubleshooting

**Issue:** AutoGPT keeps getting blocked

**Solution:** Review policies and adjust for your use case. Start with `shadow_mode: true`

---

**Issue:** Trust score drops rapidly

**Solution:** Check audit logs for repeated failures or policy violations

---

**Issue:** Agent stops unexpectedly

**Solution:** Check if trust score dropped below threshold (default: 500)

## Learn More

- [AutoGPT Documentation](https://docs.agpt.co/)
- [AgentMesh Policy Engine](../../docs/policy-engine.md)
- [Trust Scoring](../../docs/trust-scoring.md)

---

**Production Ready:** Yes, with proper monitoring and approval workflows.

**Safety Note:** AutoGPT can be unpredictable. Always run with AgentMesh governance in production.
