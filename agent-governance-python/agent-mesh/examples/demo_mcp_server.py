#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Demo script to show AgentMesh MCP proxy in action.

This creates a simple mock MCP server and demonstrates how the proxy
intercepts and governs tool calls.
"""

import json
import sys
import time

def mock_mcp_server():
    """
    Simple mock MCP server that responds to tool calls.
    Reads JSON-RPC from stdin, writes responses to stdout.
    """
    print("Mock MCP Server started", file=sys.stderr)
    
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            
            message = json.loads(line.strip())
            print(f"Received: {message}", file=sys.stderr)
            
            # Handle tools/call
            if message.get("method") == "tools/call":
                params = message.get("params", {})
                tool_name = params.get("name", "unknown")
                arguments = params.get("arguments", {})
                
                # Simulate tool execution
                response = {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Tool '{tool_name}' executed with args: {arguments}"
                            }
                        ]
                    }
                }
                
                print(json.dumps(response))
                sys.stdout.flush()
        
        except json.JSONDecodeError:
            continue
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    mock_mcp_server()
