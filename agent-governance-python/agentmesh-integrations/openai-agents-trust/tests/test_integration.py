# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for OpenAI Agents SDK integration (guardrails, hooks, handoffs).

Uses the real openai-agents SDK types since it's installed as a dependency.
"""
from openai_agents_trust.guardrails import trust_input_guardrail, TrustGuardrailConfig
from openai_agents_trust.trust import TrustScorer
from openai_agents_trust.audit import AuditLog
from openai_agents_trust.identity import AgentIdentity
from agents import Agent, InputGuardrail
from agents.guardrail import GuardrailFunctionOutput

def make_agent(name: str='test-agent') -> Agent:
    return Agent(name=name, instructions='Test agent')

class TestTrustInputGuardrail:

    def test_creates_input_guardrail(self):
        config = TrustGuardrailConfig(scorer=TrustScorer())
        guardrail = trust_input_guardrail(config)
        assert isinstance(guardrail, InputGuardrail)
        assert guardrail.name == 'agentmesh_trust_guardrail'

    def test_allows_trusted_agent(self):
        audit = AuditLog()
        config = TrustGuardrailConfig(scorer=TrustScorer(), min_score=0.5, audit_log=audit)
        guardrail = trust_input_guardrail(config)
        result = guardrail.guardrail_function(None, make_agent('trusted'), 'test')
        assert isinstance(result, GuardrailFunctionOutput)
        assert result.tripwire_triggered is False
        assert result.output_info['passed'] is True
        assert len(audit) == 1

    def test_blocks_untrusted_agent(self):
        audit = AuditLog()
        config = TrustGuardrailConfig(scorer=TrustScorer(default_score=0.3), min_score=0.5, audit_log=audit)
        guardrail = trust_input_guardrail(config)
        result = guardrail.guardrail_function(None, make_agent('untrusted'), 'test')
        assert result.tripwire_triggered is True
        assert result.output_info['passed'] is False
        assert len(audit.get_entries(decision='deny')) == 1

    def test_requires_identity_blocks_unregistered(self):
        config = TrustGuardrailConfig(scorer=TrustScorer(), require_identity=True, audit_log=AuditLog())
        guardrail = trust_input_guardrail(config)
        result = guardrail.guardrail_function(None, make_agent('no-id'), 'test')
        assert result.tripwire_triggered is True

    def test_requires_identity_allows_registered(self):
        identity = AgentIdentity(agent_id='a1', name='Agent 1', secret_key='key')
        config = TrustGuardrailConfig(scorer=TrustScorer(), require_identity=True, identities={'a1': identity})
        guardrail = trust_input_guardrail(config)
        result = guardrail.guardrail_function(None, make_agent('a1'), 'test')
        assert result.tripwire_triggered is False
