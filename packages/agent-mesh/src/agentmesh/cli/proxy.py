# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh MCP Proxy

A transparent proxy for MCP (Model Context Protocol) servers that adds:
- Policy enforcement on tool calls
- Trust score tracking
- Audit logging
- Verification footers

Usage:
    agentmesh proxy --target npx -y @modelcontextprotocol/server-filesystem /path
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, Optional, List
import subprocess

import logging

import click

from agentmesh import PolicyEngine, AuditLog, RewardEngine
from agentmesh.identity import AgentIdentity

logger = logging.getLogger(__name__)

# Allowlist of binaries the proxy may spawn as MCP targets.
# Extend via AGENTMESH_PROXY_ALLOWED_TARGETS env var (comma-separated).
_DEFAULT_ALLOWED_TARGETS = frozenset({
    "npx", "node", "python", "python3", "uvx", "uv",
    "npx.cmd", "node.exe", "python.exe", "python3.exe",
    "echo", "cat", "test",  # Common for testing
})


class MCPProxy:
    """
    MCP Proxy that intercepts tool calls and enforces governance.

    Sits between an MCP client (like Claude Desktop) and an MCP server,
    intercepting JSON-RPC messages and enforcing policies.
    """

    def __init__(
        self,
        target_command: List[str],
        policy: str = "strict",
        identity_name: str = "mcp-proxy",
        enable_footer: bool = True,
    ):
        """
        Initialize the MCP proxy.

        Args:
            target_command: Command to spawn the target MCP server
            policy: Policy level (strict, moderate, permissive)
            identity_name: Name for the proxy agent identity
            enable_footer: Whether to add verification footers to outputs
        """
        self.target_command = target_command
        self.policy_level = policy
        self.enable_footer = enable_footer

        # V11: Validate target command against allowlist
        self._validate_target_command(target_command)

        # Create proxy identity
        logger.info("Initializing AgentMesh proxy identity...")
        self.identity = AgentIdentity.create(
            name=identity_name,
            sponsor="proxy@agentmesh.ai",
            capabilities=["tool:*"]
        )

        # Initialize governance components
        self.policy_engine = PolicyEngine()
        self._load_default_policies()

        self.audit_log = AuditLog()

        self.reward_engine = RewardEngine()
        self.trust_score = 800  # Starting score

        # Process handle
        self.target_process: Optional[subprocess.Popen] = None

        logger.info("Proxy initialized with trust score: %d/1000", self.trust_score)

    @staticmethod
    def _validate_target_command(target_command: List[str]) -> None:
        """Validate target command binary against the allowlist (V11)."""
        if not target_command:
            raise ValueError("target_command must not be empty")
        binary = os.path.basename(target_command[0])
        env_extra = os.environ.get("AGENTMESH_PROXY_ALLOWED_TARGETS", "")
        allowed = _DEFAULT_ALLOWED_TARGETS | frozenset(
            t.strip() for t in env_extra.split(",") if t.strip()
        )
        if binary not in allowed:
            raise ValueError(
                f"Target binary '{binary}' is not in the allowed list: "
                f"{sorted(allowed)}. Set AGENTMESH_PROXY_ALLOWED_TARGETS "
                f"to extend the allowlist."
            )

    def _load_default_policies(self):
        """Load default policies based on policy level."""
        if self.policy_level == "strict":
            policy_yaml = """
version: "1.0"
name: "strict-mcp-policy"
description: "Strict policy for MCP tool calls"
agents: ["*"]
default_action: "deny"
rules:
  - name: "block-etc-access"
    description: "Block access to /etc"
    condition: "action.path == '/etc/passwd' or action.path == '/etc/shadow'"
    action: "deny"
    priority: 100
    enabled: true

  - name: "block-root-access"
    description: "Block access to /root"
    condition: "action.path == '/root/.ssh'"
    action: "deny"
    priority: 100
    enabled: true

  - name: "block-dangerous-filesystem-ops"
    description: "Block dangerous filesystem operations"
    condition: "action.tool == 'filesystem_write' or action.tool == 'filesystem_delete'"
    action: "deny"
    priority: 90
    enabled: true

  - name: "allow-read-operations"
    description: "Allow filesystem read operations"
    condition: "action.tool == 'filesystem_read'"
    action: "allow"
    priority: 50
    enabled: true
"""
        elif self.policy_level == "moderate":
            policy_yaml = """
version: "1.0"
name: "moderate-mcp-policy"
description: "Moderate policy for MCP tool calls"
agents: ["*"]
default_action: "allow"
rules:
  - name: "warn-on-write"
    description: "Warn on write operations"
    condition: "action.tool == 'filesystem_write'"
    action: "warn"
    priority: 50
    enabled: true
"""
        else:  # permissive
            policy_yaml = """
version: "1.0"
name: "permissive-mcp-policy"
description: "Permissive policy for MCP tool calls"
agents: ["*"]
default_action: "allow"
rules: []
"""

        try:
            self.policy_engine.load_yaml(policy_yaml)
        except Exception as e:
            logger.warning("Could not load policy: %s", e)

    async def start(self):
        """Start the proxy server."""
        logger.info("Starting MCP proxy...")
        logger.info("Target: %s", " ".join(self.target_command))
        logger.info("Policy: %s", self.policy_level)
        logger.info("Agent DID: %s", self.identity.did)

        # Start target MCP server as subprocess
        self.target_process = subprocess.Popen(
            self.target_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )

        logger.info("Target server started (PID: %d)", self.target_process.pid)
        logger.info("AgentMesh governance active")

        # Start message handling loops
        read_task = asyncio.create_task(self._read_from_target())
        write_task = asyncio.create_task(self._read_from_client())

        try:
            await asyncio.gather(read_task, write_task)
        except KeyboardInterrupt:
            logger.info("Shutting down proxy...")
        finally:
            if self.target_process:
                self.target_process.terminate()
                self.target_process.wait()

    async def _read_from_client(self):
        """Read JSON-RPC messages from stdin (MCP client)."""
        loop = asyncio.get_event_loop()

        while True:
            try:
                # Read a line from stdin
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line:
                    break

                # Parse JSON-RPC message
                try:
                    message = json.loads(line.strip())
                except json.JSONDecodeError:
                    # V14: Drop non-JSON messages — never forward unvalidated content
                    logger.warning("Dropping non-JSON client message (potential smuggling)")
                    continue

                # Intercept tool calls
                if message.get("method") == "tools/call":
                    message = await self._handle_tool_call(message)

                # V15: Don't forward blocked tool calls to target
                if isinstance(message, dict) and message.get("_agentmesh_blocked"):
                    continue

                # Forward to target
                self._write_to_target(json.dumps(message) + "\n")

            except Exception as e:
                logger.error("Error reading from client: %s", e)
                break

    async def _read_from_target(self):
        """Read responses from target MCP server."""
        loop = asyncio.get_event_loop()

        while True:
            try:
                # Read from target stdout
                line = await loop.run_in_executor(
                    None,
                    self.target_process.stdout.readline
                )

                if not line:
                    break

                # Parse JSON-RPC response
                try:
                    message = json.loads(line.decode().strip())

                    # Add verification footer if enabled
                    if self.enable_footer and "result" in message:
                        message = self._add_verification_footer(message)

                    sys.stdout.write(json.dumps(message) + "\n")
                    sys.stdout.flush()
                except json.JSONDecodeError:
                    # Not JSON, pass through
                    sys.stdout.write(line.decode())
                    sys.stdout.flush()

            except Exception as e:
                logger.error("Error reading from target: %s", e)
                break

    def _write_to_target(self, data: str):
        """Write data to target server stdin."""
        try:
            self.target_process.stdin.write(data.encode())
            self.target_process.stdin.flush()
        except Exception as e:
            logger.error("Error writing to target: %s", e)

    async def _handle_tool_call(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle a tools/call request - enforce policy.

        Args:
            message: The JSON-RPC message

        Returns:
            Modified message (allowed) or error response (blocked)
        """
        params = message.get("params", {})
        tool_name = params.get("name", "unknown")
        arguments = params.get("arguments", {})

        # Build policy context
        context = {
            "action": {
                "tool": tool_name,
                "path": arguments.get("path", ""),
            }
        }

        # Check policy
        decision = self.policy_engine.evaluate(self.identity.did, context)

        # Log the decision
        self._audit_log_tool_call(tool_name, arguments, decision)

        if not decision.allowed:
            logger.warning("BLOCKED: %s - %s", tool_name, decision.reason)

            # Return error response
            error_response = {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {
                    "code": -32001,
                    "message": f"Policy violation: {decision.reason}",
                    "data": {
                        "agentmesh": {
                            "blocked": True,
                            "policy": decision.policy_name,
                            "rule": decision.matched_rule,
                            "trust_score": self.trust_score,
                        }
                    }
                }
            }

            # Don't forward to target, return error directly
            sys.stdout.write(json.dumps(error_response) + "\n")
            sys.stdout.flush()

            # Return a marker to skip forwarding
            return {"_agentmesh_blocked": True}

        if decision.action == "warn":
            logger.warning("%s - %s", tool_name, decision.reason)
        else:
            logger.debug("Allowed: %s", tool_name)

        # Update trust score
        self._update_trust_score(tool_name, allowed=True)

        return message

    def _add_verification_footer(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Add AgentMesh verification footer to tool output."""
        result = message.get("result", {})

        # Check if result has content we can append to
        if isinstance(result, dict) and "content" in result:
            content_list = result.get("content", [])

            # Get DID as string
            did_str = str(self.identity.did) if hasattr(self.identity.did, '__str__') else self.identity.did

            # Add footer as a new content item
            footer = {
                "type": "text",
                "text": (
                    f"\n\n> 🔒 Verified by AgentMesh (Trust Score: {self.trust_score}/1000)\n"
                    f"> Agent: {did_str[:40]}...\n"
                    f"> Policy: {self.policy_level} | Audit: Enabled"
                )
            }

            if isinstance(content_list, list):
                content_list.append(footer)

            result["content"] = content_list
            message["result"] = result

        return message

    def _audit_log_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        decision: Any
    ):
        """Log tool call to audit trail."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent": str(self.identity.did),
            "action": "mcp_tool_call",
            "tool": tool_name,
            "arguments": arguments,
            "decision": decision.action,
            "allowed": decision.allowed,
            "policy": decision.policy_name,
            "rule": decision.matched_rule,
            "trust_score": self.trust_score,
        }

        # V13: Actually persist to audit log
        self.audit_log.log(
            event_type="mcp_tool_call",
            agent_did=str(self.identity.did),
            action=tool_name,
            data=entry,
            outcome="allowed" if decision.allowed else "denied",
        )
        logger.debug("Audit: %s - %s", tool_name, decision.action)

    def _update_trust_score(self, tool_name: str, allowed: bool):
        """Update trust score based on tool usage."""
        if allowed:
            # Small increase for allowed actions
            self.trust_score = min(1000, self.trust_score + 1)
        else:
            # Larger decrease for blocked actions
            self.trust_score = max(0, self.trust_score - 10)


@click.command()
@click.option(
    "--target",
    "-t",
    multiple=True,
    required=True,
    help="Target MCP server command (can specify multiple times for args)",
)
@click.option(
    "--policy",
    "-p",
    type=click.Choice(["strict", "moderate", "permissive"]),
    default="strict",
    help="Policy enforcement level",
)
@click.option(
    "--no-footer",
    is_flag=True,
    help="Disable verification footers in output",
)
@click.option(
    "--identity",
    "-i",
    default="mcp-proxy",
    help="Agent identity name",
)
def proxy(target: tuple, policy: str, no_footer: bool, identity: str):
    """
    Start an AgentMesh MCP proxy.

    Wraps an existing MCP server with governance, policy enforcement,
    and trust scoring.

    Examples:

        # Proxy a filesystem server
        agentmesh proxy --target npx --target -y \\
            --target @modelcontextprotocol/server-filesystem --target /Users/me

        # Moderate policy with no footers
        agentmesh proxy --policy moderate --no-footer \\
            --target python --target my_mcp_server.py
    """
    # Convert tuple to list
    target_cmd = list(target)

    if not target_cmd:
        click.echo("Error: --target is required", err=True)
        sys.exit(1)

    # Create and start proxy
    proxy_server = MCPProxy(
        target_command=target_cmd,
        policy=policy,
        identity_name=identity,
        enable_footer=not no_footer,
    )

    try:
        asyncio.run(proxy_server.start())
    except KeyboardInterrupt:
        logger.info("Proxy stopped")
        sys.exit(0)
