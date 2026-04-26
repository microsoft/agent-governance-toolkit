# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
DevOps Agent with Safety Guardrails
====================================

Demonstrates Agent OS blocking dangerous shell commands.
"""

from agent_os import Kernel, Policy

# Dangerous command patterns
DANGEROUS_PATTERNS = [
    "rm -rf /",
    "rm -rf /*",
    "rm -rf .",
    "chmod 777",
    "chmod -R 777",
    "> /dev/sda",
    "mkfs.",
    "dd if=/dev/zero",
    ":(){:|:&};:",  # fork bomb
    "wget | sh",
    "curl | bash",
    "sudo rm",
]

PROTECTED_PATHS = ["/etc", "/usr", "/var", "/home", "/root", "/boot"]

DEVOPS_POLICY = """
version: "1.0"
name: devops-safe-agent

environments:
  development:
    allow_destructive: true
    require_approval: false
  staging:
    allow_destructive: false
    require_approval: false
  production:
    allow_destructive: false
    require_approval: true
    approvers: [devops-lead, sre-oncall]

rules:
  - name: block-dangerous
    description: Block dangerous shell commands
    trigger: action
    condition:
      action_type: shell
    check: safe_command
    action: block
    
  - name: protect-paths
    description: Protect system paths
    trigger: action
    condition:
      action_type: file_operation
      path_in: [/etc, /usr, /var, /boot]
    action: block
    
  - name: production-approval
    description: Require approval for production changes
    trigger: action
    condition:
      environment: production
      action_type: [deploy, modify, delete]
    action: require_approval
"""


class DevOpsAgent:
    """Safe deployment agent with guardrails."""
    
    def __init__(self, environment: str = "development"):
        self.kernel = Kernel()
        self.policy = Policy.from_yaml(DEVOPS_POLICY)
        self.kernel.load_policy(self.policy)
        self.environment = environment
        
        self.agent = self.kernel.create_agent(
            name="DeployBot",
            context={"environment": environment}
        )
        
    def is_dangerous(self, command: str) -> bool:
        """Check if command matches dangerous patterns."""
        command_lower = command.lower()
        for pattern in DANGEROUS_PATTERNS:
            if pattern.lower() in command_lower:
                return True
        return False
        
    def affects_protected_path(self, command: str) -> bool:
        """Check if command affects protected paths."""
        for path in PROTECTED_PATHS:
            if path in command:
                return True
        return False
    
    def execute(self, command: str):
        """Execute a shell command with safety checks."""
        print(f"Command: {command}")
        
        # Check for dangerous commands
        if self.is_dangerous(command):
            print(f"❌ BLOCKED: Dangerous command detected")
            print(f"   Pattern matched safety blocklist")
            return {"status": "blocked", "reason": "dangerous_command"}
            
        # Check for protected paths
        if self.affects_protected_path(command):
            if self.environment == "production":
                print(f"⏳ PENDING: Requires approval for protected path")
                return {"status": "pending_approval"}
            else:
                print(f"⚠️  WARNING: Operating on protected path")
        
        # Production approval
        if self.environment == "production" and any(
            kw in command for kw in ["deploy", "apply", "delete", "rm"]
        ):
            print(f"⏳ PENDING APPROVAL: Production change detected")
            print(f"   Approvers: devops-lead, sre-oncall")
            return {"status": "pending_approval"}
        
        # Execute
        print(f"✅ EXECUTED: Command ran successfully")
        print(f"📝 Logged to audit trail")
        return {"status": "success", "output": "[simulated output]"}


def main():
    print("=" * 60)
    print("DevOps Agent Demo - Safe Deployments with Agent OS")
    print("=" * 60)
    
    # Development environment
    print("\n[DEVELOPMENT ENVIRONMENT]")
    dev_agent = DevOpsAgent(environment="development")
    
    print("\n1. Safe command (ALLOWED)")
    print("-" * 40)
    dev_agent.execute("kubectl get pods")
    
    print("\n2. Dangerous command (BLOCKED)")
    print("-" * 40)
    dev_agent.execute("rm -rf /")
    
    print("\n3. Another dangerous command (BLOCKED)")
    print("-" * 40)
    dev_agent.execute("chmod -R 777 /etc")
    
    # Production environment
    print("\n[PRODUCTION ENVIRONMENT]")
    prod_agent = DevOpsAgent(environment="production")
    
    print("\n4. Production deploy (REQUIRES APPROVAL)")
    print("-" * 40)
    prod_agent.execute("kubectl apply -f deployment.yaml")
    
    print("\n5. Safe read command (ALLOWED)")
    print("-" * 40)
    prod_agent.execute("kubectl get services")
    
    print("\n" + "=" * 60)
    print("Safety guardrails protected against dangerous operations")
    print("=" * 60)


if __name__ == "__main__":
    main()
