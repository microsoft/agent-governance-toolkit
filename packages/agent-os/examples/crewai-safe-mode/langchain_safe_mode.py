#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
🛡️ Agent OS Safe Mode Demo for LangChain
==========================================

This script demonstrates Agent OS blocking dangerous operations
from a LangChain agent in real-time.

What happens:
1. A LangChain agent with tools tries dangerous operations
2. Agent OS intercepts tool calls
3. The kernel BLOCKS dangerous actions
4. Your data stays safe ✓

Run:
    pip install agent-os langchain
    python langchain_safe_mode.py

For PyPI package: pip install langchain-agent-os
"""

import os
import sys
from datetime import datetime
from typing import Any, Callable

# ============================================================================
# ANSI Colors for Terminal Output
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
    print(f"""
{Colors.CYAN}{Colors.BOLD}
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   🛡️  AGENT OS - Safe Mode Demo for LangChain           ║
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
    print(f"""
{Colors.RED}{Colors.BOLD}
    ╔═══════════════════════════════════════════════════════════╗
    ║  🚫 ACCESS DENIED - POLICY VIOLATION                      ║
    ╠═══════════════════════════════════════════════════════════╣
    ║                                                           ║
    ║  Tool:    {action:<48} ║
    ║  Reason:  {reason:<48} ║
    ║  Status:  BLOCKED BY KERNEL                               ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}""")

def print_allowed(action: str):
    print(f"{Colors.GREEN}  ✅ ALLOWED:{Colors.RESET} {action}")

def print_log(level: str, message: str):
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    color = {
        "INFO": Colors.CYAN,
        "WARN": Colors.YELLOW,
        "ERROR": Colors.RED,
        "BLOCK": Colors.RED + Colors.BOLD,
    }.get(level, Colors.WHITE)
    print(f"  {Colors.WHITE}[{timestamp}]{Colors.RESET} {color}[{level}]{Colors.RESET} {message}")


# ============================================================================
# Agent OS Kernel
# ============================================================================

class SafetyPolicy:
    """Policy engine for LangChain tools"""
    
    BLOCKED_TOOLS = {
        "delete_file": "File deletion not permitted",
        "execute_sql": "Raw SQL execution requires approval",
        "shell": "Shell access is restricted",
        "run_command": "System commands are restricted",
        "write_file": "File write requires explicit path approval",
    }
    
    BLOCKED_PATTERNS = [
        ("DROP", "Destructive SQL operation"),
        ("DELETE FROM", "Bulk deletion requires approval"),
        ("rm -rf", "Recursive delete blocked"),
        ("sudo", "Privilege escalation blocked"),
        ("chmod", "Permission changes blocked"),
        ("eval(", "Code execution blocked"),
        ("exec(", "Code execution blocked"),
    ]
    
    ALLOWED_TOOLS = [
        "search",
        "calculator",
        "read_file",
        "web_search",
        "get_weather",
    ]
    
    @classmethod
    def check_tool(cls, tool_name: str, tool_input: str) -> tuple[bool, str]:
        """Check if a tool invocation is allowed"""
        
        # Check blocked tools
        if tool_name.lower() in cls.BLOCKED_TOOLS:
            return False, cls.BLOCKED_TOOLS[tool_name.lower()]
        
        # Check blocked patterns in input
        for pattern, reason in cls.BLOCKED_PATTERNS:
            if pattern.lower() in tool_input.lower():
                return False, reason
        
        # Allow safe tools
        if tool_name.lower() in cls.ALLOWED_TOOLS:
            return True, "Safe tool"
        
        # Default: allow with logging
        return True, "Allowed (default policy)"


class AgentOSKernel:
    """
    Agent OS Kernel for LangChain.
    
    Wraps tool execution with safety checks.
    """
    
    def __init__(self, agent_id: str = "langchain-agent"):
        self.agent_id = agent_id
        self.audit_log = []
        self.blocked_count = 0
        self.allowed_count = 0
        
        print_log("INFO", f"Kernel initialized for agent: {agent_id}")
        print_log("INFO", "LangChain tool governance enabled")
    
    def wrap_tool(self, tool_func: Callable, tool_name: str) -> Callable:
        """Wrap a LangChain tool with safety checks"""
        kernel = self
        
        def governed_tool(input_str: str) -> str:
            return kernel.execute_tool(tool_name, input_str, tool_func)
        
        governed_tool.__name__ = tool_func.__name__ if hasattr(tool_func, '__name__') else tool_name
        governed_tool.__doc__ = tool_func.__doc__ if hasattr(tool_func, '__doc__') else ""
        
        return governed_tool
    
    def execute_tool(self, tool_name: str, tool_input: str, tool_func: Callable) -> str:
        """Execute a tool through the kernel"""
        
        print_log("INFO", f"Tool invocation: {tool_name}({tool_input[:50]}...)")
        
        # Check policy
        allowed, reason = SafetyPolicy.check_tool(tool_name, tool_input)
        
        # Audit log
        self.audit_log.append({
            "timestamp": datetime.now().isoformat(),
            "agent_id": self.agent_id,
            "tool": tool_name,
            "input": tool_input,
            "allowed": allowed,
            "reason": reason,
        })
        
        if not allowed:
            self.blocked_count += 1
            print_log("BLOCK", f"DENIED: {reason}")
            print_blocked(tool_name, reason)
            raise PermissionError(f"🛡️ Agent OS: {reason}")
        
        self.allowed_count += 1
        print_allowed(f"{tool_name}({tool_input[:30]}...)")
        
        # Execute the actual tool
        return tool_func(tool_input)
    
    def get_stats(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "total_requests": len(self.audit_log),
            "allowed": self.allowed_count,
            "blocked": self.blocked_count,
        }


# ============================================================================
# Simulated LangChain Tools (for demo without actual LangChain)
# ============================================================================

class SimulatedTools:
    """Simulates LangChain tools for the demo"""
    
    @staticmethod
    def search(query: str) -> str:
        return f"Search results for: {query}"
    
    @staticmethod
    def calculator(expression: str) -> str:
        return f"Calculated: {expression} = 42"
    
    @staticmethod
    def read_file(path: str) -> str:
        return f"Contents of {path}: [file data]"
    
    @staticmethod
    def delete_file(path: str) -> str:
        return f"Deleted: {path}"  # Would never actually run!
    
    @staticmethod
    def execute_sql(query: str) -> str:
        return f"SQL result: {query}"
    
    @staticmethod
    def shell(command: str) -> str:
        return f"Shell output: {command}"


class SimulatedLangChainAgent:
    """Simulates a LangChain ReAct agent"""
    
    def __init__(self, tools: dict, kernel: AgentOSKernel):
        self.tools = tools
        self.kernel = kernel
        
        # Wrap all tools with kernel governance
        self.governed_tools = {
            name: kernel.wrap_tool(func, name)
            for name, func in tools.items()
        }
    
    def run(self, query: str) -> str:
        """Simulates agent execution with tool use"""
        print(f"\n{Colors.YELLOW}  🤖 Agent processing: {query}{Colors.RESET}")
        
        results = []
        
        # Simulate the agent's reasoning and tool selection
        if "delete" in query.lower() or "remove" in query.lower():
            # Agent tries to use delete tool
            try:
                result = self.governed_tools["delete_file"]("/important/data.txt")
                results.append(result)
            except PermissionError as e:
                results.append(f"Tool blocked: {e}")
        
        if "sql" in query.lower() or "database" in query.lower():
            # Agent tries SQL
            try:
                result = self.governed_tools["execute_sql"]("DROP TABLE users;")
                results.append(result)
            except PermissionError as e:
                results.append(f"Tool blocked: {e}")
        
        if "search" in query.lower() or "find" in query.lower():
            # Safe search operation
            result = self.governed_tools["search"](query)
            results.append(result)
        
        if "calculate" in query.lower() or "math" in query.lower():
            # Safe calculator
            result = self.governed_tools["calculator"]("2 + 2")
            results.append(result)
        
        if "shell" in query.lower() or "command" in query.lower():
            # Agent tries shell access
            try:
                result = self.governed_tools["shell"]("rm -rf /")
                results.append(result)
            except PermissionError as e:
                results.append(f"Tool blocked: {e}")
        
        return "\n".join(results) if results else "No tools needed"


# ============================================================================
# Main Demo
# ============================================================================

def run_demo():
    print_banner()
    
    # Initialize kernel
    print_section("INITIALIZING AGENT OS KERNEL")
    kernel = AgentOSKernel(agent_id="langchain-demo")
    
    # Create tools
    print_section("REGISTERING LANGCHAIN TOOLS")
    tools = {
        "search": SimulatedTools.search,
        "calculator": SimulatedTools.calculator,
        "read_file": SimulatedTools.read_file,
        "delete_file": SimulatedTools.delete_file,
        "execute_sql": SimulatedTools.execute_sql,
        "shell": SimulatedTools.shell,
    }
    
    for tool_name in tools:
        print_log("INFO", f"Registered tool: {tool_name}")
    
    # Create agent
    agent = SimulatedLangChainAgent(tools, kernel)
    
    # Demo 1: Safe search
    print_section("DEMO 1: SAFE SEARCH (Allowed)")
    agent.run("Search for Python tutorials")
    
    # Demo 2: File deletion attempt
    print_section("DEMO 2: FILE DELETION (Blocked)")
    agent.run("Delete the old log files")
    
    # Demo 3: SQL injection attempt
    print_section("DEMO 3: DESTRUCTIVE SQL (Blocked)")
    agent.run("Run this SQL: DROP TABLE users")
    
    # Demo 4: Shell access attempt
    print_section("DEMO 4: SHELL ACCESS (Blocked)")
    agent.run("Execute shell command to clean disk")
    
    # Demo 5: Safe calculation
    print_section("DEMO 5: SAFE CALCULATION (Allowed)")
    agent.run("Calculate the sum of 2 + 2")
    
    # Statistics
    print_section("KERNEL STATISTICS")
    stats = kernel.get_stats()
    
    print(f"""
{Colors.CYAN}  📊 Agent OS Kernel Report
  ─────────────────────────────────────────
  Agent ID:        {stats['agent_id']}
  Total Requests:  {stats['total_requests']}
  ✅ Allowed:      {stats['allowed']}
  🚫 Blocked:      {stats['blocked']}
  ─────────────────────────────────────────{Colors.RESET}
""")
    
    print(f"""
{Colors.GREEN}{Colors.BOLD}
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   ✅ DEMO COMPLETE - LangChain agent safely governed!    ║
  ║                                                           ║
  ║   Install the package: pip install langchain-agent-os     ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}""")
    
    print(f"\n{Colors.CYAN}  🔗 GitHub: https://github.com/microsoft/agent-governance-toolkit{Colors.RESET}\n")


if __name__ == "__main__":
    run_demo()
