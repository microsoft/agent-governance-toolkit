# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP Tool Server with AgentMesh Governance

This example demonstrates how to build a Model Context Protocol (MCP) server
secured with AgentMesh identity, policies, and audit logging.

MCP is Anthropic's protocol for connecting AI models to tools and data sources.
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from agentmesh import (
    AgentIdentity,
    PolicyEngine,
    AuditLog,
    RewardEngine,
    CapabilityScope,
)

# Simulated MCP server framework (in production, use actual MCP SDK)
class MCPServer:
    """Minimal MCP server implementation for demonstration."""
    
    def __init__(self, name: str):
        self.name = name
        self.tools: Dict[str, Any] = {}
    
    def tool(self, name: str):
        """Decorator to register a tool."""
        def decorator(func):
            self.tools[name] = func
            return func
        return decorator
    
    async def handle_request(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle an MCP tool invocation."""
        if tool_name not in self.tools:
            return {"error": f"Tool {tool_name} not found"}
        
        try:
            result = await self.tools[tool_name](params)
            return {"result": result}
        except Exception as e:
            return {"error": str(e)}


class GovernedMCPServer:
    """MCP server wrapped with AgentMesh governance."""
    
    def __init__(self, config_path: str = "agentmesh.yaml"):
        """Initialize governed MCP server."""
        self.config_path = config_path
        
        # Create AgentMesh identity
        print("🔐 Creating AgentMesh identity...")
        self.identity = AgentIdentity.create(
            name="mcp-tool-server",
            sponsor="devops@company.com",
            capabilities=["tool:filesystem:read", "tool:database:query", "tool:api:call"]
        )
        print(f"✓ Identity created: {self.identity.did}")
        print(f"✓ Public key: {self.identity.public_key[:32]}...")
        
        # Load policies
        print("\n📋 Loading governance policies...")
        self.policy_engine = PolicyEngine()
        self._load_policies()
        
        # Initialize audit log
        print("\n📝 Initializing audit log...")
        self.audit_log = AuditLog(
            agent_id=self.identity.did,
        )
        
        # Initialize reward engine (trust scoring)
        print("\n⭐ Initializing reward engine...")
        self.reward_engine = RewardEngine()
        self.trust_score = 800  # Starting score
        
        # Create MCP server
        self.mcp_server = MCPServer("agentmesh-example")
        self._register_tools()
        
        print(f"\n✓ MCP server initialized with trust score: {self.trust_score}/1000")
    
    def _load_policies(self):
        """Load policy files."""
        policies_dir = Path(__file__).parent / "policies"
        
        for policy_file in policies_dir.glob("*.yaml"):
            try:
                # In real implementation, PolicyEngine.load_from_file()
                print(f"  ✓ Loaded policy: {policy_file.name}")
            except Exception as e:
                print(f"  ✗ Failed to load {policy_file.name}: {e}")
    
    def _register_tools(self):
        """Register MCP tools with governance."""
        
        @self.mcp_server.tool("filesystem_read")
        async def filesystem_read(params: Dict[str, Any]) -> str:
            """Read a file from the filesystem (with governance)."""
            path = params.get("path")
            
            # Policy check
            policy_result = self._check_policy(
                action="filesystem_read",
                params={"path": path}
            )
            
            if not policy_result["allowed"]:
                raise PermissionError(f"Policy violation: {policy_result['reason']}")
            
            # Simulate file read (in production, actually read file)
            content = f"[Simulated content of {path}]"
            
            # Log to audit trail
            self._audit_log_event("filesystem_read", params, "success")
            
            # Update trust score
            self._update_trust_score("filesystem_read", success=True)
            
            return content
        
        @self.mcp_server.tool("database_query")
        async def database_query(params: Dict[str, Any]) -> list:
            """Query a database (with governance)."""
            query = params.get("query")
            
            # Policy check
            policy_result = self._check_policy(
                action="database_query",
                params={"query": query}
            )
            
            if not policy_result["allowed"]:
                raise PermissionError(f"Policy violation: {policy_result['reason']}")
            
            # Simulate database query
            results = [
                {"id": 1, "name": "Alice", "email": "alice@example.com"},
                {"id": 2, "name": "Bob", "email": "bob@example.com"},
            ]
            
            # Check for PII in output (output sanitization)
            sanitized_results = self._sanitize_output(results)
            
            # Log to audit trail
            self._audit_log_event("database_query", params, "success")
            
            # Update trust score
            self._update_trust_score("database_query", success=True)
            
            return sanitized_results
        
        @self.mcp_server.tool("api_call")
        async def api_call(params: Dict[str, Any]) -> Dict[str, Any]:
            """Call an external API (with rate limiting)."""
            endpoint = params.get("endpoint")
            method = params.get("method", "GET")
            
            # Policy check (includes rate limiting)
            policy_result = self._check_policy(
                action="api_call",
                params={"endpoint": endpoint, "method": method}
            )
            
            if not policy_result["allowed"]:
                raise PermissionError(f"Policy violation: {policy_result['reason']}")
            
            # Simulate API call
            response = {
                "status": 200,
                "data": {"message": f"Response from {endpoint}"}
            }
            
            # Log to audit trail
            self._audit_log_event("api_call", params, "success")
            
            # Update trust score
            self._update_trust_score("api_call", success=True)
            
            return response
    
    def _check_policy(self, action: str, params: Dict[str, Any]) -> Dict[str, bool]:
        """Check if action is allowed by policies."""
        # Simulated policy engine (in production, use PolicyEngine.check())
        
        # Example policies:
        # 1. Rate limiting
        if action == "api_call":
            # In production, track actual rate limits
            pass
        
        # 2. Path restrictions for filesystem
        if action == "filesystem_read":
            path = params.get("path", "")
            # Block access to sensitive paths
            sensitive_paths = ["/etc/passwd", "/etc/shadow", "/.ssh"]
            if any(path.startswith(p) for p in sensitive_paths):
                return {
                    "allowed": False,
                    "reason": f"Access to {path} is blocked by policy"
                }
        
        # 3. SQL injection prevention
        if action == "database_query":
            query = params.get("query", "")
            # Comprehensive dangerous SQL keywords (case-insensitive)
            dangerous_keywords = [
                "DROP", "DELETE", "TRUNCATE", "ALTER", 
                "UPDATE", "INSERT", "EXEC", "EXECUTE",
                "CREATE", "GRANT", "REVOKE"
            ]
            query_upper = query.upper()
            if any(keyword in query_upper for keyword in dangerous_keywords):
                return {
                    "allowed": False,
                    "reason": f"Dangerous SQL keywords detected in query"
                }
        
        return {"allowed": True, "reason": None}
    
    def _sanitize_output(self, data: Any) -> Any:
        """Sanitize output to remove sensitive data."""
        # Simulated output sanitization
        # In production, use PolicyEngine output filters
        
        if isinstance(data, list):
            return [self._sanitize_output(item) for item in data]
        
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                # Redact fields that might contain PII
                if key.lower() in ["password", "api_key", "secret", "token"]:
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = value
            return sanitized
        
        return data
    
    def _audit_log_event(self, action: str, params: Dict[str, Any], result: str):
        """Log event to audit trail."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent": self.identity.did,
            "action": action,
            "params": params,
            "result": result,
            "trust_score": self.trust_score
        }
        
        # In production, use AuditLog.log()
        print(f"\n📋 Audit: {action} - {result} (trust score: {self.trust_score})")
    
    def _update_trust_score(self, action: str, success: bool):
        """Update trust score based on action."""
        # Simulated reward engine
        # In production, use RewardEngine.update_score()
        
        if success:
            # Small increase for successful actions
            self.trust_score = min(1000, self.trust_score + 1)
        else:
            # Larger decrease for failures
            self.trust_score = max(0, self.trust_score - 10)
        
        # If trust score drops too low, revoke credentials
        if self.trust_score < 500:
            print(f"\n⚠️  WARNING: Trust score dropped to {self.trust_score}. Credentials may be revoked.")
    
    async def run(self):
        """Run the MCP server."""
        print("\n" + "="*70)
        print("🚀 MCP Tool Server with AgentMesh Governance")
        print("="*70)
        print(f"\nAgent DID: {self.identity.did}")
        print(f"Trust Score: {self.trust_score}/1000")
        print(f"\nAvailable tools:")
        for tool_name in self.mcp_server.tools.keys():
            print(f"  • {tool_name}")
        print("\n" + "="*70)
        
        # Demo: Simulate some tool invocations
        await self.demo_tool_invocations()
    
    async def demo_tool_invocations(self):
        """Demo tool invocations to show governance in action."""
        print("\n🧪 Demo: Testing tool invocations with governance\n")
        
        # Test 1: Allowed filesystem read
        print("\n1️⃣  Test: Reading allowed file")
        result = await self.mcp_server.handle_request(
            "filesystem_read",
            {"path": "/data/users.json"}
        )
        print(f"   Result: {result}")
        
        # Test 2: Blocked filesystem read
        print("\n2️⃣  Test: Reading blocked file")
        result = await self.mcp_server.handle_request(
            "filesystem_read",
            {"path": "/etc/passwd"}
        )
        print(f"   Result: {result}")
        
        # Test 3: Database query
        print("\n3️⃣  Test: Database query")
        result = await self.mcp_server.handle_request(
            "database_query",
            {"query": "SELECT * FROM users"}
        )
        print(f"   Result: {result}")
        
        # Test 4: Blocked dangerous query
        print("\n4️⃣  Test: Dangerous SQL query (blocked)")
        result = await self.mcp_server.handle_request(
            "database_query",
            {"query": "DROP TABLE users"}
        )
        print(f"   Result: {result}")
        
        # Test 5: API call
        print("\n5️⃣  Test: API call")
        result = await self.mcp_server.handle_request(
            "api_call",
            {"endpoint": "https://api.weather.com/current", "method": "GET"}
        )
        print(f"   Result: {result}")
        
        print("\n" + "="*70)
        print(f"✓ Demo complete. Final trust score: {self.trust_score}/1000")
        print("="*70)


async def main():
    """Main entry point."""
    # Initialize governed MCP server
    server = GovernedMCPServer()
    
    # Run the server
    await server.run()
    
    print("\n💡 In production, this MCP server would:")
    print("   • Connect to Claude Desktop or other MCP clients")
    print("   • Enforce real policies from YAML files")
    print("   • Write to persistent audit logs")
    print("   • Integrate with SPIFFE for mTLS")
    print("   • Report compliance metrics to dashboards")
    print("\n🔗 Learn more: https://github.com/microsoft/agent-governance-toolkit")


if __name__ == "__main__":
    asyncio.run(main())
