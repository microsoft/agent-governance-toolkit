#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AgentMesh MCP Proxy Demo — Claude Desktop Security.

Simulates the MCP governance proxy flow without requiring Claude Desktop.
Demonstrates policy enforcement, audit logging, and trust scoring for
MCP tool calls.

Usage:
    python demo.py
"""

from __future__ import annotations

import hashlib
import json
import textwrap
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class Decision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass
class PolicyRule:
    """A single governance rule."""

    id: str
    name: str
    action: Decision
    tools: list[str]
    severity: str = "info"
    message: str = ""


@dataclass
class PolicyResult:
    """Outcome of a policy evaluation."""

    allowed: bool
    action: Decision
    matched_rule: str
    reason: str


@dataclass
class AuditEntry:
    """A single hash-chained audit log entry."""

    seq: int
    event_id: str
    timestamp: str
    tool: str
    params: dict[str, Any]
    decision: Decision
    matched_rule: str
    reason: str
    chain_hash: str
    prev_hash: str


@dataclass
class AgentIdentity:
    """Minimal agent identity (DID-based)."""

    did: str
    name: str
    trust_score: int = 800

    @classmethod
    def create(cls, name: str) -> AgentIdentity:
        raw = hashlib.sha256(f"{name}-{uuid.uuid4()}".encode()).hexdigest()[:16]
        return cls(did=f"did:mesh:{raw}", name=name)


# ---------------------------------------------------------------------------
# Mock MCP server
# ---------------------------------------------------------------------------

class MockMCPServer:
    """Simulates an upstream MCP server exposing filesystem/shell tools."""

    TOOLS = {
        "read_file": "Read a file from disk",
        "write_file": "Write content to a file",
        "search_files": "Search files by pattern",
        "list_directory": "List directory contents",
        "delete_file": "Delete a file from disk",
        "execute_command": "Run a shell command",
        "shell_exec": "Execute arbitrary shell command",
        "modify_system": "Modify system configuration",
        "browse_web": "Fetch a URL",
    }

    def call_tool(self, tool: str, params: dict[str, Any]) -> dict[str, Any]:
        if tool not in self.TOOLS:
            return {"error": f"Unknown tool: {tool}"}
        return {"status": "ok", "tool": tool, "result": f"[mock result for {tool}]"}


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """Evaluates tool calls against governance rules."""

    def __init__(self, rules: list[PolicyRule]) -> None:
        self._rules = rules

    @classmethod
    def from_yaml_dict(cls, data: dict[str, Any]) -> PolicyEngine:
        rules: list[PolicyRule] = []
        for policy in data.get("policies", []):
            for rule in policy.get("rules", []):
                tools: list[str] = []
                for cond in rule.get("conditions", []):
                    if "tool in [" in cond or "tool in [" in cond.replace("'", "'"):
                        # Parse tool list from condition string
                        start = cond.index("[")
                        end = cond.index("]") + 1
                        tools = json.loads(cond[start:end].replace("'", '"'))
                rules.append(
                    PolicyRule(
                        id=rule["id"],
                        name=rule.get("name", rule["id"]),
                        action=Decision(rule["action"]),
                        tools=tools,
                        severity=rule.get("severity", "info"),
                        message=rule.get("message", ""),
                    )
                )
        return cls(rules)

    def evaluate(self, tool: str) -> PolicyResult:
        for rule in self._rules:
            if tool in rule.tools:
                allowed = rule.action == Decision.ALLOW
                reason = rule.message or f"Tool '{tool}' matched rule '{rule.id}'"
                return PolicyResult(
                    allowed=allowed,
                    action=rule.action,
                    matched_rule=rule.id,
                    reason=reason,
                )
        # Default deny for unrecognized tools
        return PolicyResult(
            allowed=False,
            action=Decision.DENY,
            matched_rule="default-deny",
            reason=f"Tool '{tool}' not covered by any policy rule",
        )


# ---------------------------------------------------------------------------
# Audit logger (hash-chained)
# ---------------------------------------------------------------------------

@dataclass
class AuditLogger:
    """Tamper-evident, hash-chained audit log."""

    agent_did: str
    entries: list[AuditEntry] = field(default_factory=list)
    _prev_hash: str = "genesis"

    def log(
        self,
        tool: str,
        params: dict[str, Any],
        decision: Decision,
        matched_rule: str,
        reason: str,
    ) -> AuditEntry:
        seq = len(self.entries) + 1
        event_id = f"evt-{seq:04d}"
        timestamp = datetime.now(timezone.utc).isoformat()

        payload = f"{self._prev_hash}:{event_id}:{tool}:{decision.value}"
        chain_hash = hashlib.sha256(payload.encode()).hexdigest()[:12]

        entry = AuditEntry(
            seq=seq,
            event_id=event_id,
            timestamp=timestamp,
            tool=tool,
            params=params,
            decision=decision,
            matched_rule=matched_rule,
            reason=reason,
            chain_hash=chain_hash,
            prev_hash=self._prev_hash,
        )
        self.entries.append(entry)
        self._prev_hash = chain_hash
        return entry

    def verify_chain(self) -> tuple[bool, int]:
        """Verify hash chain integrity. Returns (valid, count)."""
        prev = "genesis"
        for entry in self.entries:
            payload = f"{prev}:{entry.event_id}:{entry.tool}:{entry.decision.value}"
            expected = hashlib.sha256(payload.encode()).hexdigest()[:12]
            if expected != entry.chain_hash:
                return False, entry.seq
            prev = entry.chain_hash
        return True, len(self.entries)


# ---------------------------------------------------------------------------
# MCP Governance Proxy
# ---------------------------------------------------------------------------

class MCPGovernanceProxy:
    """Wraps an MCP server with policy enforcement and audit logging."""

    def __init__(
        self,
        upstream: MockMCPServer,
        engine: PolicyEngine,
        identity: AgentIdentity,
    ) -> None:
        self.upstream = upstream
        self.engine = engine
        self.identity = identity
        self.audit = AuditLogger(agent_did=identity.did)

    def call_tool(self, tool: str, params: dict[str, Any]) -> dict[str, Any]:
        decision = self.engine.evaluate(tool)

        self.audit.log(
            tool=tool,
            params=params,
            decision=decision.action,
            matched_rule=decision.matched_rule,
            reason=decision.reason,
        )

        if decision.action == Decision.DENY:
            self.identity.trust_score = max(0, self.identity.trust_score - 10)
            return {"error": decision.reason, "decision": "deny"}

        if decision.action == Decision.REQUIRE_APPROVAL:
            return {
                "status": "pending_approval",
                "decision": "require_approval",
                "tool": tool,
            }

        # Allowed — forward to upstream
        result = self.upstream.call_tool(tool, params)
        return {**result, "decision": "allow"}


# ---------------------------------------------------------------------------
# Demo policies (matches policies/mcp-governance.yaml)
# ---------------------------------------------------------------------------

DEMO_POLICIES: dict[str, Any] = {
    "policies": [
        {
            "id": "mcp-claude-desktop",
            "name": "Claude Desktop MCP Governance",
            "version": "1.0",
            "enabled": True,
            "rules": [
                {
                    "id": "allow-reads",
                    "name": "Allow safe read operations",
                    "action": "allow",
                    "conditions": [
                        "tool in ['read_file', 'search_files', 'list_directory', 'browse_web']"
                    ],
                    "severity": "info",
                },
                {
                    "id": "approve-writes",
                    "name": "Require approval for write operations",
                    "action": "require_approval",
                    "conditions": [
                        "tool in ['write_file', 'execute_command']"
                    ],
                    "severity": "high",
                    "message": "Write/execute operations require human approval",
                },
                {
                    "id": "block-destructive",
                    "name": "Block destructive operations",
                    "action": "deny",
                    "conditions": [
                        "tool in ['delete_file', 'modify_system', 'shell_exec']"
                    ],
                    "severity": "critical",
                    "message": "Destructive operations are blocked by governance policy",
                },
            ],
        }
    ]
}


# ---------------------------------------------------------------------------
# Demo runner
# ---------------------------------------------------------------------------

DECISION_ICONS = {
    Decision.ALLOW: "✅",
    Decision.REQUIRE_APPROVAL: "⏳",
    Decision.DENY: "🚫",
}

TOOL_CALLS = [
    ("read_file", {"path": "/home/user/notes.txt"}),
    ("search_files", {"pattern": "TODO"}),
    ("write_file", {"path": "/home/user/output.txt", "content": "result data"}),
    ("delete_file", {"path": "/etc/passwd"}),
    ("shell_exec", {"command": "rm -rf /"}),
    ("browse_web", {"url": "https://example.com"}),
]


def format_params(params: dict[str, Any]) -> str:
    parts = [f"{v}" for v in params.values()]
    return ", ".join(parts)


def run_demo() -> None:
    separator = "═" * 54
    print(f"\n{separator}")
    print("  AgentMesh MCP Proxy Demo — Claude Desktop Security")
    print(f"{separator}\n")

    # 1. Identity
    identity = AgentIdentity.create("claude-desktop-proxy")
    print(f"[1] Agent identity created")
    print(f"    DID:  {identity.did}")
    print(f"    Name: {identity.name}")
    print(f"    Trust: {identity.trust_score}/1000\n")

    # 2. Policy engine
    engine = PolicyEngine.from_yaml_dict(DEMO_POLICIES)
    rule_count = sum(
        len(p.get("rules", [])) for p in DEMO_POLICIES["policies"]
    )
    print(f"[2] Governance policies loaded")
    print(f"    Rules: {rule_count} active")
    print(f"    Mode:  enforce (not shadow)\n")

    # 3. Proxy
    upstream = MockMCPServer()
    proxy = MCPGovernanceProxy(upstream, engine, identity)

    print("[3] Simulating MCP tool calls...\n")

    for tool, params in TOOL_CALLS:
        result = proxy.call_tool(tool, params)
        decision_str = result.get("decision", "unknown")
        decision = Decision(decision_str)
        icon = DECISION_ICONS.get(decision, "❓")
        seq = len(proxy.audit.entries)

        matched = proxy.audit.entries[-1].matched_rule
        label = decision.value.upper().replace("_", " ")
        suffix = ""
        if decision == Decision.DENY:
            suffix = " (blocked)"
        elif decision == Decision.REQUIRE_APPROVAL:
            suffix = " (pending approval)"

        print(f"    {icon} {tool}({format_params(params)})")
        print(f"       Policy: {label:20s} (rule: {matched})")
        print(f"       Audit:  logged #{seq:04d}{suffix}\n")

    # 4. Audit trail table
    print("[4] Audit trail (tamper-evident, hash-chained)")
    hdr = f"    {'#':>4}  {'Tool':<16} {'Decision':<12} {'Hash':<14}"
    print(f"    {'─' * 50}")
    print(hdr)
    print(f"    {'─' * 50}")
    for e in proxy.audit.entries:
        label = e.decision.value
        print(f"    {e.seq:>4}  {e.tool:<16} {label:<12} {e.chain_hash}…")
    print(f"    {'─' * 50}")

    valid, count = proxy.audit.verify_chain()
    status = "✅ verified" if valid else "❌ TAMPERED"
    print(f"\n    Chain integrity: {status} ({count}/{count} entries)\n")

    # 5. Trust score
    print("[5] Trust score impact")
    print(f"    Initial:  800 (trusted)")
    print(f"    After:    {identity.trust_score} (blocked calls reduced score)")
    if identity.trust_score >= 800:
        level = "✅ trusted"
    elif identity.trust_score >= 600:
        level = "⚠  within warning threshold"
    else:
        level = "🚨 below warning threshold"
    print(f"    Status:   {level}\n")

    # 6. Sample audit entry (CloudEvents format)
    print("[6] Sample audit entry (CloudEvents format)\n")
    sample = proxy.audit.entries[3]  # The delete_file entry
    cloud_event = {
        "specversion": "1.0",
        "type": "agentmesh.mcp.tool_call",
        "source": identity.did,
        "id": sample.event_id,
        "time": sample.timestamp,
        "data": {
            "tool": sample.tool,
            "params": sample.params,
            "decision": sample.decision.value,
            "matched_rule": sample.matched_rule,
            "reason": sample.reason,
            "trust_score": identity.trust_score,
            "chain_hash": sample.chain_hash,
        },
    }
    print(textwrap.indent(json.dumps(cloud_event, indent=2), "    "))
    print()


if __name__ == "__main__":
    run_demo()
