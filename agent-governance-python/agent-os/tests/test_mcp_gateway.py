# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the native MCP security gateway."""
from __future__ import annotations
import threading
import time
from typing import Any
from agt.policies import PolicyEvaluation
from agent_os.mcp_gateway import ApprovalStatus, GatewayConfig, MCPGateway
from agent_os.mcp_protocols import InMemoryAuditSink, InMemoryRateLimitStore

class _Runtime:
    manifest = None

    def __init__(self, verdict: str='allow') -> None:
        self.verdict = verdict
        self.snapshots: list[dict[str, Any]] = []

    def evaluate(self, intervention_point: str, snapshot: dict[str, Any]) -> PolicyEvaluation:
        self.snapshots.append(snapshot)
        return PolicyEvaluation(verdict=self.verdict, reason_code='blocked' if self.verdict == 'deny' else '', message='runtime blocked request' if self.verdict == 'deny' else '', intervention_point=intervention_point)

class _ConcurrentStore:

    def __init__(self) -> None:
        self.value = 0
        self.active = 0
        self.max_active = 0
        self.lock = threading.Lock()

    def get_bucket(self, _agent_id: str) -> int:
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        time.sleep(0.005)
        value = self.value
        with self.lock:
            self.active -= 1
        return value

    def set_bucket(self, _agent_id: str, bucket: int) -> None:
        self.value = bucket

def test_native_runtime_can_allow_and_deny_calls() -> None:
    assert MCPGateway(_Runtime(), enable_builtin_sanitization=False).intercept_tool_call('agent', 'read', {})[0]
    allowed, reason = MCPGateway(_Runtime('deny'), enable_builtin_sanitization=False).intercept_tool_call('agent', 'delete', {})
    assert allowed is False
    assert reason == 'blocked'

def test_host_deny_list_and_sanitization_run_before_runtime() -> None:
    runtime = _Runtime()
    gateway = MCPGateway(runtime, denied_tools=['exec'])
    assert gateway.intercept_tool_call('agent', 'exec', {})[0] is False
    assert gateway.intercept_tool_call('agent', 'read', {'ssn': '123-45-6789'})[0] is False
    assert runtime.snapshots == []

def test_sensitive_tool_approval_is_fail_closed() -> None:
    gateway = MCPGateway(_Runtime(), sensitive_tools=['deploy'], enable_builtin_sanitization=False)
    allowed, reason = gateway.intercept_tool_call('agent', 'deploy', {})
    assert allowed is False
    assert 'Awaiting' in reason
    approved = MCPGateway(_Runtime(), sensitive_tools=['deploy'], approval_callback=lambda *_: ApprovalStatus.APPROVED, enable_builtin_sanitization=False)
    assert approved.intercept_tool_call('agent', 'deploy', {})[0] is True

def test_rate_limit_is_atomic_and_resettable() -> None:
    store = _ConcurrentStore()
    gateway = MCPGateway(_Runtime(), rate_limit=1, rate_limit_store=store, enable_builtin_sanitization=False)
    barrier = threading.Barrier(6)
    results: list[bool] = []

    def worker() -> None:
        barrier.wait()
        results.append(gateway.intercept_tool_call('agent', 'read', {})[0])
    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1
    assert store.max_active == 1
    gateway.reset_agent_budget('agent')
    assert gateway.get_agent_call_count('agent') == 0

def test_audit_is_redacted_and_persisted() -> None:
    sink = InMemoryAuditSink()
    buckets = InMemoryRateLimitStore()
    gateway = MCPGateway(_Runtime(), audit_sink=sink, rate_limit_store=buckets, enable_builtin_sanitization=False, clock=lambda: 123.0)
    gateway.intercept_tool_call('agent', 'read', {'token': 'sk-test_abcdefghijklmnopqrstuvwxyz'})
    assert gateway.audit_log[0].parameters == {'token': '[REDACTED]'}
    assert sink.entries()[0]['timestamp'] == 123.0
    assert buckets.get_bucket('agent') == 1

def test_wrap_server_config_uses_explicit_host_controls() -> None:
    config = MCPGateway.wrap_mcp_server({'host': 'localhost'}, denied_tools=['exec'], sensitive_tools=['deploy'], rate_limit=20)
    assert isinstance(config, GatewayConfig)
    assert config.denied_tools == ['exec']
    assert config.sensitive_tools == ['deploy']
    assert config.rate_limit == 20
