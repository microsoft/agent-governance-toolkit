#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh MCP Proxy Demo

This script demonstrates the AgentMesh proxy intercepting and governing
MCP tool calls. It simulates various operations to show how policies work.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

def print_header(text):
    """Print a formatted header."""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70 + "\n")

def print_section(text):
    """Print a section header."""
    print(f"\n--- {text} ---\n")

def send_tool_call(process, tool_name, arguments, call_id=1):
    """Send a tool call to the proxy."""
    message = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": call_id,
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }
    
    print(f"📤 Sending tool call: {tool_name}")
    print(f"   Arguments: {arguments}")
    
    # Write to stdin
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()
    
    # Wait a moment for response
    time.sleep(0.5)
    
    # Try to read response (non-blocking would be better in production)
    # For demo purposes, we'll just show the request

def main():
    print_header("AgentMesh MCP Proxy Demo")
    
    print("""
This demo shows how AgentMesh acts as a governance layer between
an MCP client (like Claude Desktop) and MCP tools.

Key Features:
  🔒 Policy Enforcement - Blocks dangerous operations
  📊 Trust Scoring - Tracks behavioral patterns  
  📝 Audit Logging - Records all activity
  ✅ Verification - Adds trust footers to outputs
""")
    
    print_section("Demo Scenarios")
    
    scenarios = [
        {
            "name": "Safe Read Operation",
            "tool": "filesystem_read",
            "args": {"path": "/home/user/document.txt"},
            "expected": "✅ ALLOWED - Safe read operation"
        },
        {
            "name": "Dangerous Write Operation",
            "tool": "filesystem_write",
            "args": {"path": "/home/user/file.txt", "content": "data"},
            "expected": "🔒 BLOCKED - Strict policy blocks writes"
        },
        {
            "name": "Sensitive Path Access",
            "tool": "filesystem_read",
            "args": {"path": "/etc/passwd"},
            "expected": "🔒 BLOCKED - Access to /etc is blocked"
        },
        {
            "name": "Root Directory Access",
            "tool": "filesystem_read",
            "args": {"path": "/root/.ssh"},
            "expected": "🔒 BLOCKED - Access to /root is blocked"
        },
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"\n{i}. {scenario['name']}")
        print(f"   Tool: {scenario['tool']}")
        print(f"   Args: {scenario['args']}")
        print(f"   Expected: {scenario['expected']}")
    
    print_section("Starting Proxy")
    
    print("""
To see the proxy in action, run:

    # Terminal 1: Start the proxy with strict policy
    agentmesh proxy --policy strict \\
      --target python \\
      --target examples/demo_mcp_server.py

    # Terminal 2: Send test requests
    echo '{"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {"name": "filesystem_read", "arguments": {"path": "/home/user/file.txt"}}}' | nc localhost 3000

Or integrate with Claude Desktop using:

    agentmesh init-integration --claude

Then ask Claude: "Read my home directory" or "Delete a file"
AgentMesh will enforce policies and show verification in responses!
""")
    
    print_section("Trust Score Tracking")
    
    print("""
The proxy maintains a trust score (800-1000):
  
  ✅ Allowed operations   → +1 point
  🔒 Blocked operations   → -10 points
  
If the score drops below 500, credentials may be revoked.

Trust scores are shown in verification footers:

    > 🔒 Verified by AgentMesh (Trust Score: 980/1000)
    > Agent: did:agentmesh:mcp-proxy:abc123...
    > Policy: strict | Audit: Enabled
""")
    
    print_section("Policy Levels")
    
    print("""
Strict (Default):
  • Blocks all write/delete operations
  • Blocks access to sensitive paths (/etc, /root)
  • Allows read operations only

Moderate:
  • Warns on write operations but allows them
  • Blocks critical system paths
  • Good for development

Permissive:
  • Allows all operations
  • Logs everything for audit
  • Good for testing

Change with: --policy [strict|moderate|permissive]
""")
    
    print_header("Demo Complete!")
    print("""
Next steps:
  1. Run: agentmesh init-integration --claude
  2. Restart Claude Desktop
  3. Try asking Claude to manipulate files
  4. Watch AgentMesh protect your system!

Learn more: https://github.com/microsoft/agent-governance-toolkit
""")

if __name__ == "__main__":
    main()
