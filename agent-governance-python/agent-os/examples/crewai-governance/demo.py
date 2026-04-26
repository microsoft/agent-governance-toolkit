#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent OS — CrewAI Governance Demo
==================================

Demonstrates per-role policy enforcement and audit logging for a
CrewAI-style crew **without** requiring API keys or the crewai package.

Three mock agents — researcher, writer, reviewer — each operate under
distinct governance policies loaded from policies.yaml.  The demo shows
allowed actions, blocked actions, and a full audit trail.

Run:
    cd examples/crewai-governance
    python demo.py
"""

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── YAML loader (PyYAML optional — falls back to a tiny parser) ──────────

def _load_yaml(path: str) -> dict:
    """Load a YAML file. Uses PyYAML when available, else a minimal parser."""
    try:
        import yaml  # type: ignore
        with open(path) as f:
            return yaml.safe_load(f)
    except ImportError:
        pass
    # Minimal parser: handles the flat structure of policies.yaml
    data: dict = {}
    stack: list = [data]
    indent_stack: list = [-1]
    with open(path) as f:
        for raw in f:
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip())
            while indent <= indent_stack[-1]:
                stack.pop()
                indent_stack.pop()
            if stripped.startswith("- "):
                val = stripped[2:].strip().strip('"').strip("'")
                parent = stack[-1]
                if isinstance(parent, dict):
                    last_key = list(parent.keys())[-1]
                    if not isinstance(parent[last_key], list):
                        parent[last_key] = []
                    parent[last_key].append(val)
                elif isinstance(parent, list):
                    parent.append(val)
            elif ":" in stripped:
                key, _, val = stripped.partition(":")
                key = key.strip().strip('"').strip("'")
                val = val.strip().strip('"').strip("'")
                current = stack[-1]
                if val:
                    try:
                        val = int(val)  # type: ignore[assignment]
                    except ValueError:
                        pass
                    current[key] = val
                else:
                    current[key] = {}
                    stack.append(current[key])
                    indent_stack.append(indent)
    return data


# ── ANSI helpers ─────────────────────────────────────────────────────────

class C:
    """ANSI colour shortcuts."""
    R  = "\033[91m"; G  = "\033[92m"; Y  = "\033[93m"
    B  = "\033[94m"; M  = "\033[95m"; CY = "\033[96m"
    W  = "\033[97m"; BD = "\033[1m";  RS = "\033[0m"

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def _log(level: str, msg: str):
    colour = {"INFO": C.CY, "WARN": C.Y, "BLOCK": C.R + C.BD,
              "ALLOW": C.G, "AUDIT": C.M}.get(level, C.W)
    print(f"  {C.W}[{_ts()}]{C.RS} {colour}[{level:5s}]{C.RS} {msg}")

def _banner(title: str):
    print(f"\n{C.CY}{C.BD}{'─' * 64}{C.RS}")
    print(f"{C.CY}{C.BD}  {title}{C.RS}")
    print(f"{C.CY}{C.BD}{'─' * 64}{C.RS}\n")

def _blocked_box(action: str, reason: str):
    a = action[:50].ljust(50)
    r = reason[:50].ljust(50)
    print(f"""
{C.R}{C.BD}  ╔══════════════════════════════════════════════════════════╗
  ║  🚫 BLOCKED — POLICY VIOLATION                           ║
  ╠══════════════════════════════════════════════════════════╣
  ║  Action: {a} ║
  ║  Reason: {r} ║
  ╚══════════════════════════════════════════════════════════╝{C.RS}
""")


# ── Audit log ────────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    timestamp: str
    agent_id: str
    role: str
    tool: str
    input_hash: str
    decision: str          # ALLOWED | BLOCKED
    reason: str

class AuditLog:
    """Append-only, hash-redacted audit log."""

    def __init__(self):
        self.entries: List[AuditEntry] = []

    def record(self, *, agent_id: str, role: str, tool: str,
               raw_input: str, decision: str, reason: str):
        self.entries.append(AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            role=role,
            tool=tool,
            input_hash=hashlib.sha256(raw_input.encode()).hexdigest()[:16],
            decision=decision,
            reason=reason,
        ))

    def print_report(self):
        _banner("📋 AUDIT LOG")
        for i, e in enumerate(self.entries, 1):
            icon = "✅" if e.decision == "ALLOWED" else "🚫"
            colour = C.G if e.decision == "ALLOWED" else C.R
            print(f"  {C.W}{i:>3}.{C.RS} {icon} {colour}{e.decision:7s}{C.RS} "
                  f"| {e.role:<10s} | {e.tool:<18s} | hash={e.input_hash}")
        allowed = sum(1 for e in self.entries if e.decision == "ALLOWED")
        blocked = len(self.entries) - allowed
        print(f"\n  {C.CY}Total: {len(self.entries)}  "
              f"{C.G}Allowed: {allowed}  {C.R}Blocked: {blocked}{C.RS}\n")

    def to_json(self) -> str:
        return json.dumps([asdict(e) for e in self.entries], indent=2)


# ── Policy engine ────────────────────────────────────────────────────────

@dataclass
class PolicyResult:
    allowed: bool
    reason: str

class RolePolicyEngine:
    """Enforces per-role governance loaded from policies.yaml."""

    def __init__(self, policy_path: str):
        self.cfg = _load_yaml(policy_path)
        self.shared_blocked = self.cfg.get("shared", {}).get("blocked_patterns", [])
        self.roles: Dict[str, dict] = self.cfg.get("roles", {})
        self._action_counts: Dict[str, int] = {}

    def check(self, role: str, tool: str, params: str) -> PolicyResult:
        role_cfg = self.roles.get(role)
        if role_cfg is None:
            return PolicyResult(False, f"Unknown role: {role}")

        # Shared blocked patterns
        combined = f"{tool} {params}".lower()
        for pat in self.shared_blocked:
            if pat.lower() in combined:
                return PolicyResult(False, f"Shared blocked pattern: {pat}")

        # Role-specific blocked patterns
        for pat in role_cfg.get("blocked_patterns", []):
            if pat.lower() in combined:
                return PolicyResult(False, f"Role '{role}' blocks: {pat}")

        # Tool allowlist
        allowed_tools = role_cfg.get("allowed_tools", [])
        if tool not in allowed_tools:
            return PolicyResult(False,
                f"Tool '{tool}' not in allowlist for role '{role}'")

        # Action budget
        max_actions = role_cfg.get("max_actions")
        if max_actions:
            count = self._action_counts.get(role, 0)
            if count >= max_actions:
                return PolicyResult(False,
                    f"Role '{role}' exceeded action budget ({max_actions})")

        self._action_counts[role] = self._action_counts.get(role, 0) + 1
        return PolicyResult(True, "Policy check passed")


# ── Governed kernel wrapper ──────────────────────────────────────────────

class GovernedKernel:
    """Wraps every tool call with policy check + audit."""

    def __init__(self, engine: RolePolicyEngine, audit: AuditLog):
        self.engine = engine
        self.audit = audit

    def execute(self, *, agent_id: str, role: str,
                tool: str, params: str) -> str:
        _log("INFO", f"[{agent_id}] requesting  {tool}({params})")
        result = self.engine.check(role, tool, params)

        self.audit.record(
            agent_id=agent_id, role=role, tool=tool,
            raw_input=params, decision="ALLOWED" if result.allowed else "BLOCKED",
            reason=result.reason,
        )

        if not result.allowed:
            _log("BLOCK", f"DENIED → {result.reason}")
            _blocked_box(f"{tool}({params})", result.reason)
            raise PermissionError(f"Agent OS: {result.reason}")

        _log("ALLOW", f"✅ {tool}  →  OK")
        return f"[mock result] {tool} executed"


# ── Mock CrewAI agents ───────────────────────────────────────────────────

class MockCrewAgent:
    """Simulates a CrewAI agent bound to a role."""

    def __init__(self, agent_id: str, role: str, kernel: GovernedKernel):
        self.agent_id = agent_id
        self.role = role
        self.kernel = kernel

    def run(self, tasks: List[tuple]):
        """Execute a sequence of (tool, params) through the kernel."""
        print(f"\n{C.Y}{C.BD}  🤖 [{self.role.upper()}] {self.agent_id}{C.RS}")
        for tool, params in tasks:
            try:
                self.kernel.execute(
                    agent_id=self.agent_id, role=self.role,
                    tool=tool, params=params)
            except PermissionError:
                pass  # already logged


# ── Demo scenarios ───────────────────────────────────────────────────────

def run_demo():
    policy_path = str(Path(__file__).parent / "policies.yaml")
    engine = RolePolicyEngine(policy_path)
    audit  = AuditLog()
    kernel = GovernedKernel(engine, audit)

    # ── Header ───────────────────────────────────────────────────────────
    print(f"""
{C.CY}{C.BD}
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   🛡️  Agent OS — CrewAI Governance Demo                 ║
    ║                                                          ║
    ║   Per-role policies · Tool allow-lists · Audit logging   ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
{C.RS}""")

    researcher = MockCrewAgent("agent-researcher", "researcher", kernel)
    writer     = MockCrewAgent("agent-writer",     "writer",     kernel)
    reviewer   = MockCrewAgent("agent-reviewer",   "reviewer",   kernel)

    # ── Scenario 1: Researcher ───────────────────────────────────────────
    _banner("SCENARIO 1 — Researcher agent")
    print(f"  {C.M}The researcher can search the web and read files,")
    print(f"  but must NOT write files or run shell commands.{C.RS}\n")
    researcher.run([
        ("web_search",       "latest AI governance frameworks"),
        ("read_file",        "data/report.csv"),
        ("write_file",       "output/notes.txt"),         # BLOCKED
        ("execute_command",  "curl http://example.com"),  # BLOCKED
    ])

    # ── Scenario 2: Writer ───────────────────────────────────────────────
    _banner("SCENARIO 2 — Writer agent")
    print(f"  {C.M}The writer can read and write files,")
    print(f"  but must NOT access the web or run commands.{C.RS}\n")
    writer.run([
        ("read_file",        "data/report.csv"),
        ("write_file",       "output/article.md"),
        ("web_search",       "plagiarism check"),          # BLOCKED
        ("execute_command",  "rm -rf /tmp/cache"),         # BLOCKED (shared)
    ])

    # ── Scenario 3: Reviewer ─────────────────────────────────────────────
    _banner("SCENARIO 3 — Reviewer agent")
    print(f"  {C.M}The reviewer is read-only — can inspect artefacts")
    print(f"  but must NOT modify anything.{C.RS}\n")
    reviewer.run([
        ("read_file",        "output/article.md"),
        ("list_directory",   "output/"),
        ("write_file",       "output/article.md"),         # BLOCKED
        ("delete_file",      "output/article.md"),         # BLOCKED
    ])

    # ── Scenario 4: Shared blocked patterns ──────────────────────────────
    _banner("SCENARIO 4 — Shared safety net")
    print(f"  {C.M}These patterns are blocked for ALL roles,")
    print(f"  regardless of individual role policies.{C.RS}\n")
    researcher.run([
        ("web_search",       "find api_key in .env"),      # BLOCKED (shared)
    ])
    writer.run([
        ("write_file",       "DROP TABLE users;"),         # BLOCKED (shared)
    ])

    # ── Audit report ─────────────────────────────────────────────────────
    audit.print_report()

    # ── Summary ──────────────────────────────────────────────────────────
    allowed = sum(1 for e in audit.entries if e.decision == "ALLOWED")
    blocked = len(audit.entries) - allowed
    print(f"""
{C.G}{C.BD}
  ╔══════════════════════════════════════════════════════════╗
  ║                                                          ║
  ║  ✅  DEMO COMPLETE                                       ║
  ║                                                          ║
  ║  {blocked} dangerous actions blocked · {allowed} safe actions allowed    ║
  ║  Full audit trail with SHA-256 input hashes              ║
  ║                                                          ║
  ║  Governance is a kernel concern, not a prompt concern.   ║
  ║                                                          ║
  ╚══════════════════════════════════════════════════════════╝
{C.RS}""")
    print(f"  {C.CY}🔗 https://github.com/microsoft/agent-governance-toolkit{C.RS}\n")


if __name__ == "__main__":
    run_demo()
