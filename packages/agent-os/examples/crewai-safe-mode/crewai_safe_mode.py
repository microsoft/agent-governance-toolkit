#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
🛡️ Agent OS Safe Mode Demo for CrewAI
=======================================

This script demonstrates Agent OS blocking dangerous operations
from a CrewAI agent in real-time.

What happens:
1. A CrewAI agent tries to delete files
2. Agent OS intercepts the operation
3. The kernel BLOCKS the action and logs the violation
4. Your data stays safe ✓

Run:
    pip install agent-os crewai
    python crewai_safe_mode.py

Perfect for recording a 15-second GIF showing "Access Denied"!
"""

import os
import sys
from datetime import datetime
from typing import Any

# ============================================================================
# ANSI Colors for Terminal Output (the visual "wow" factor)
# ============================================================================

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_banner():
    """Print the Agent OS banner"""
    print(f"""
{Colors.CYAN}{Colors.BOLD}
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   🛡️  AGENT OS - Safe Mode Demo for CrewAI              ║
    ║                                                           ║
    ║   Kernel-level safety for autonomous AI agents            ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}""")

def print_section(title: str):
    print(f"\n{Colors.BLUE}{Colors.BOLD}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD}  {title}{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD}{'─' * 60}{Colors.RESET}\n")

def print_blocked(action: str, reason: str):
    """Print a blocked action with dramatic effect"""
    print(f"""
{Colors.RED}{Colors.BOLD}
    ╔═══════════════════════════════════════════════════════════╗
    ║  🚫 ACCESS DENIED - POLICY VIOLATION                      ║
    ╠═══════════════════════════════════════════════════════════╣
    ║                                                           ║
    ║  Action:  {action:<47} ║
    ║  Reason:  {reason:<47} ║
    ║  Status:  BLOCKED BY KERNEL                               ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}""")

def print_allowed(action: str):
    """Print an allowed action"""
    print(f"{Colors.GREEN}  ✅ ALLOWED:{Colors.RESET} {action}")

def print_log(level: str, message: str):
    """Print a kernel log message"""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    color = {
        "INFO": Colors.CYAN,
        "WARN": Colors.YELLOW,
        "ERROR": Colors.RED,
        "BLOCK": Colors.RED + Colors.BOLD,
    }.get(level, Colors.WHITE)
    print(f"  {Colors.WHITE}[{timestamp}]{Colors.RESET} {color}[{level}]{Colors.RESET} {message}")


# ============================================================================
# Agent OS Kernel - The Safety Layer
# ============================================================================

class SafetyPolicy:
    """
    Defines what operations are allowed/blocked.
    This is the "kernel" that protects your system.
    """
    
    # Dangerous file patterns
    BLOCKED_FILE_OPS = [
        "rm -rf",
        "rmdir",
        "unlink",
        "shutil.rmtree",
        "os.remove",
        "os.unlink",
        "pathlib.Path.unlink",
        "DELETE FROM",
        "DROP TABLE",
        "TRUNCATE",
    ]
    
    # Dangerous commands
    BLOCKED_COMMANDS = [
        "sudo",
        "chmod 777",
        "curl | bash",
        "wget | sh",
        "eval(",
        "exec(",
        "__import__",
    ]
    
    # Restricted paths
    RESTRICTED_PATHS = [
        "/",
        "/etc",
        "/usr",
        "/var",
        "/home",
        "/root",
        "C:\\Windows",
        "C:\\Program Files",
        "~",
    ]
    
    @classmethod
    def check_action(cls, action: str, params: dict = None) -> tuple[bool, str]:
        """
        Check if an action is allowed.
        Returns (allowed, reason).
        """
        action_lower = action.lower()
        params = params or {}
        
        # Check for blocked file operations
        for blocked in cls.BLOCKED_FILE_OPS:
            if blocked.lower() in action_lower:
                return False, f"Destructive file operation detected: {blocked}"
        
        # Check for blocked commands
        for blocked in cls.BLOCKED_COMMANDS:
            if blocked.lower() in action_lower:
                return False, f"Dangerous command detected: {blocked}"
        
        # Check for restricted paths
        path = params.get("path", "") or params.get("file", "") or ""
        for restricted in cls.RESTRICTED_PATHS:
            if path.startswith(restricted):
                return False, f"Access to restricted path: {restricted}"
        
        return True, "Action permitted"


class AgentOSKernel:
    """
    The Agent OS Kernel - intercepts all agent actions.
    
    This is a simplified version showing the core concept:
    - Every action goes through the kernel
    - The kernel checks against policies
    - Violations are BLOCKED, not just logged
    """
    
    def __init__(self, agent_id: str = "crew-agent"):
        self.agent_id = agent_id
        self.audit_log = []
        self.blocked_count = 0
        self.allowed_count = 0
        
        print_log("INFO", f"Kernel initialized for agent: {agent_id}")
        print_log("INFO", "Safety policies loaded: file_ops, commands, paths")
    
    def execute(self, action: str, params: dict = None) -> Any:
        """
        Execute an action through the kernel.
        
        The kernel:
        1. Intercepts the action
        2. Checks against policies
        3. Blocks or allows
        4. Logs everything
        """
        params = params or {}
        
        # Log the attempt
        print_log("INFO", f"Agent requested: {action}")
        
        # Check policy
        allowed, reason = SafetyPolicy.check_action(action, params)
        
        # Record in audit log
        self.audit_log.append({
            "timestamp": datetime.now().isoformat(),
            "agent_id": self.agent_id,
            "action": action,
            "params": params,
            "allowed": allowed,
            "reason": reason,
        })
        
        if not allowed:
            self.blocked_count += 1
            print_log("BLOCK", f"DENIED: {reason}")
            print_blocked(action[:45], reason[:45])
            raise PermissionError(f"🛡️ Agent OS: {reason}")
        
        self.allowed_count += 1
        print_allowed(action)
        return f"Executed: {action}"
    
    def get_stats(self) -> dict:
        """Get kernel statistics"""
        return {
            "agent_id": self.agent_id,
            "total_requests": len(self.audit_log),
            "allowed": self.allowed_count,
            "blocked": self.blocked_count,
            "violation_rate": f"{(self.blocked_count / max(1, len(self.audit_log))) * 100:.1f}%"
        }


# ============================================================================
# Simulated CrewAI Agent (for demo without actual CrewAI dependency)
# ============================================================================

class SimulatedCrewAIAgent:
    """
    Simulates a CrewAI agent that tries to perform dangerous operations.
    
    In a real scenario, this would be an actual CrewAI agent.
    The Agent OS kernel wraps it the same way.
    """
    
    def __init__(self, name: str, role: str, kernel: AgentOSKernel):
        self.name = name
        self.role = role
        self.kernel = kernel
        print_log("INFO", f"Created agent: {name} ({role})")
    
    def execute_task(self, task: str) -> str:
        """
        Execute a task - ALL actions go through the kernel.
        """
        print(f"\n{Colors.YELLOW}  🤖 Agent '{self.name}' executing: {task}{Colors.RESET}")
        
        # Simulate the agent "thinking" and choosing actions
        if "clean" in task.lower() or "delete" in task.lower():
            # Agent decides to delete files (DANGEROUS!)
            actions = [
                ("os.remove('/tmp/cache/*')", {"path": "/tmp/cache"}),
                ("shutil.rmtree('/var/log/old')", {"path": "/var/log/old"}),
                ("rm -rf /home/user/Downloads/*", {"path": "/home/user/Downloads"}),
            ]
        elif "analyze" in task.lower():
            # Agent decides to read data (SAFE)
            actions = [
                ("read_file('data.csv')", {"path": "data.csv"}),
                ("pandas.read_csv('report.csv')", {"path": "report.csv"}),
            ]
        elif "deploy" in task.lower():
            # Agent tries dangerous deploy commands
            actions = [
                ("sudo systemctl restart app", {}),
                ("chmod 777 /var/www", {"path": "/var/www"}),
            ]
        else:
            # Default safe actions
            actions = [
                ("print('Hello from agent')", {}),
                ("calculate_metrics()", {}),
            ]
        
        results = []
        for action, params in actions:
            try:
                result = self.kernel.execute(action, params)
                results.append(result)
            except PermissionError as e:
                results.append(f"BLOCKED: {e}")
        
        return "\n".join(results)


class SimulatedCrew:
    """
    Simulates a CrewAI Crew with multiple agents.
    """
    
    def __init__(self, agents: list, kernel: AgentOSKernel):
        self.agents = agents
        self.kernel = kernel
    
    def kickoff(self, inputs: dict = None) -> str:
        """Run the crew - simulates CrewAI's kickoff()"""
        print_section("CREW KICKOFF")
        print_log("INFO", f"Starting crew with {len(self.agents)} agents")
        
        results = []
        for agent in self.agents:
            task = inputs.get("task", "default task") if inputs else "default task"
            try:
                result = agent.execute_task(task)
                results.append(f"{agent.name}: {result}")
            except Exception as e:
                results.append(f"{agent.name}: ERROR - {e}")
        
        return "\n\n".join(results)


# ============================================================================
# Main Demo
# ============================================================================

def run_demo():
    """
    Run the complete demo showing Agent OS protecting against dangerous ops.
    """
    print_banner()
    
    # Initialize the kernel
    print_section("INITIALIZING AGENT OS KERNEL")
    kernel = AgentOSKernel(agent_id="demo-crew")
    
    # Create agents (simulating CrewAI)
    print_section("CREATING CREWAI AGENTS")
    
    cleanup_agent = SimulatedCrewAIAgent(
        name="Cleanup Bot",
        role="System Cleaner",
        kernel=kernel
    )
    
    analyst_agent = SimulatedCrewAIAgent(
        name="Data Analyst",
        role="Analytics",
        kernel=kernel
    )
    
    deploy_agent = SimulatedCrewAIAgent(
        name="Deploy Bot",
        role="DevOps",
        kernel=kernel
    )
    
    # Create the crew
    crew = SimulatedCrew(
        agents=[cleanup_agent, analyst_agent, deploy_agent],
        kernel=kernel
    )
    
    # ========================================================================
    # DEMO 1: Cleanup task (BLOCKED - tries to delete files)
    # ========================================================================
    print_section("DEMO 1: CLEANUP TASK (Agent tries to delete files)")
    print(f"{Colors.MAGENTA}  Task: 'Clean up old files and free disk space'{Colors.RESET}")
    
    try:
        result = cleanup_agent.execute_task("Clean up old cache files")
    except Exception as e:
        print(f"\n{Colors.RED}  Crew task failed safely: {e}{Colors.RESET}")
    
    # ========================================================================
    # DEMO 2: Analysis task (ALLOWED - safe read operations)
    # ========================================================================
    print_section("DEMO 2: ANALYSIS TASK (Safe read operations)")
    print(f"{Colors.MAGENTA}  Task: 'Analyze sales data'{Colors.RESET}")
    
    try:
        result = analyst_agent.execute_task("Analyze Q4 sales data")
        print(f"\n{Colors.GREEN}  ✅ Task completed successfully!{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}  Task failed: {e}{Colors.RESET}")
    
    # ========================================================================
    # DEMO 3: Deploy task (BLOCKED - tries sudo/chmod)
    # ========================================================================
    print_section("DEMO 3: DEPLOY TASK (Agent tries privilege escalation)")
    print(f"{Colors.MAGENTA}  Task: 'Deploy new version to production'{Colors.RESET}")
    
    try:
        result = deploy_agent.execute_task("Deploy app to production")
    except Exception as e:
        print(f"\n{Colors.RED}  Crew task failed safely: {e}{Colors.RESET}")
    
    # ========================================================================
    # Final Statistics
    # ========================================================================
    print_section("KERNEL STATISTICS")
    
    stats = kernel.get_stats()
    print(f"""
{Colors.CYAN}  📊 Agent OS Kernel Report
  ─────────────────────────────────────────
  Agent ID:        {stats['agent_id']}
  Total Requests:  {stats['total_requests']}
  ✅ Allowed:      {stats['allowed']}
  🚫 Blocked:      {stats['blocked']}
  Violation Rate:  {stats['violation_rate']}
  ─────────────────────────────────────────{Colors.RESET}
""")
    
    print(f"""
{Colors.GREEN}{Colors.BOLD}
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   ✅ DEMO COMPLETE - Your system stayed safe!            ║
  ║                                                           ║
  ║   Agent OS blocked {stats['blocked']} dangerous operations            ║
  ║   while allowing {stats['allowed']} safe ones.                        ║
  ║                                                           ║
  ║   This is kernel-level safety, not prompt engineering.   ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}""")
    
    print(f"\n{Colors.CYAN}  🔗 Learn more: https://github.com/microsoft/agent-governance-toolkit{Colors.RESET}\n")


if __name__ == "__main__":
    run_demo()
