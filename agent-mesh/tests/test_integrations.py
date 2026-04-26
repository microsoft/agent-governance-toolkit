# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""Tests for Langflow, Flowise, and Haystack integrations."""

import pytest

# ── Langflow ────────────────────────────────────────────────────────

from agentmesh.integrations.langflow import (
    ComponentIdentity,
    ConnectionRecord,
    IdentityComponent,
    TrustGatedFlow,
    TrustVerificationComponent,
    TrustVerificationError,
)


class TestLangflowIdentity:
    """Tests for Langflow ComponentIdentity."""

    def test_generate_identity(self):
        identity = ComponentIdentity.generate("test-agent", capabilities=["search"])
        assert identity.component_name == "test-agent"
        assert identity.did.startswith("did:langflow:")
        assert "search" in identity.capabilities
        assert identity.trust_score == 0.5

    def test_unique_dids(self):
        id1 = ComponentIdentity.generate("agent-a")
        id2 = ComponentIdentity.generate("agent-b")
        assert id1.did != id2.did

    def test_custom_trust_score(self):
        identity = ComponentIdentity.generate("agent", trust_score=0.9)
        assert identity.trust_score == 0.9


class TestLangflowVerification:
    """Tests for Langflow TrustVerificationComponent."""

    def test_verify_passes(self):
        verifier = TrustVerificationComponent(min_trust_score=0.5)
        source = ComponentIdentity.generate("src", trust_score=0.8)
        target = ComponentIdentity.generate("tgt", trust_score=0.7)
        assert verifier.verify(source, target) is True

    def test_verify_fails_low_trust(self):
        verifier = TrustVerificationComponent(min_trust_score=0.8)
        source = ComponentIdentity.generate("src")
        target = ComponentIdentity.generate("tgt", trust_score=0.3)
        with pytest.raises(TrustVerificationError, match="below required"):
            verifier.verify(source, target)

    def test_verify_fails_missing_capability(self):
        verifier = TrustVerificationComponent(
            required_capabilities=["execute_code"],
        )
        source = ComponentIdentity.generate("src")
        target = ComponentIdentity.generate("tgt", capabilities=["search"])
        with pytest.raises(TrustVerificationError, match="Missing required"):
            verifier.verify(source, target)

    def test_sensitive_data_escalates_trust(self):
        verifier = TrustVerificationComponent(
            min_trust_score=0.3,
            sensitive_trust_score=0.9,
        )
        source = ComponentIdentity.generate("src")
        target = ComponentIdentity.generate("tgt", trust_score=0.5)
        # Normal data passes
        assert verifier.verify(source, target, {"query": "hello"}) is True
        # Sensitive data fails
        with pytest.raises(TrustVerificationError):
            verifier.verify(source, target, {"api_key": "secret"})

    def test_audit_log_recorded(self):
        verifier = TrustVerificationComponent()
        source = ComponentIdentity.generate("src", trust_score=0.8)
        target = ComponentIdentity.generate("tgt", trust_score=0.7)
        verifier.verify(source, target)
        log = verifier.get_audit_log()
        assert len(log) == 1
        assert log[0].verified is True

    def test_warn_mode_does_not_raise(self):
        verifier = TrustVerificationComponent(
            min_trust_score=0.9, on_failure="warn"
        )
        source = ComponentIdentity.generate("src")
        target = ComponentIdentity.generate("tgt", trust_score=0.1)
        result = verifier.verify(source, target)
        assert result is False


class TestLangflowTrustGatedFlow:
    """Tests for TrustGatedFlow."""

    def test_register_and_verify(self):
        flow = TrustGatedFlow(min_trust_score=0.4)
        flow.register_node("retriever", capabilities=["search"], trust_score=0.8)
        flow.register_node("generator", capabilities=["generate"], trust_score=0.7)
        assert flow.verify_connection("retriever", "generator") is True

    def test_unregistered_node_raises(self):
        flow = TrustGatedFlow()
        flow.register_node("node-a")
        with pytest.raises(TrustVerificationError, match="not registered"):
            flow.verify_connection("node-a", "node-b")

    def test_flow_report(self):
        flow = TrustGatedFlow()
        flow.register_node("a", trust_score=0.8)
        flow.register_node("b", trust_score=0.7)
        flow.verify_connection("a", "b")
        report = flow.get_flow_report()
        assert report["total_connections"] == 1
        assert report["verified"] == 1
        assert "a" in report["nodes"]

    def test_langflow_config_export(self):
        flow = TrustGatedFlow(min_trust_score=0.6)
        flow.register_node("agent", trust_score=0.9)
        config = flow.to_langflow_config()
        assert config["type"] == "agentmesh_trust_flow"
        assert config["min_trust_score"] == 0.6
        assert "agent" in config["nodes"]


# ── Flowise ─────────────────────────────────────────────────────────

from agentmesh.integrations.flowise import (
    FlowiseNodeDefinition,
    FlowiseNodeIdentity,
    FlowiseTrustError,
    FlowiseTrustPolicy,
    TrustGatedFlowiseClient,
)


class TestFlowiseIdentity:
    """Tests for FlowiseNodeIdentity."""

    def test_generate_identity(self):
        identity = FlowiseNodeIdentity.generate("test-node", node_type="chatflow")
        assert identity.node_name == "test-node"
        assert identity.node_type == "chatflow"
        assert identity.did.startswith("did:flowise:")

    def test_unique_dids(self):
        id1 = FlowiseNodeIdentity.generate("a")
        id2 = FlowiseNodeIdentity.generate("b")
        assert id1.did != id2.did


class TestFlowiseClient:
    """Tests for TrustGatedFlowiseClient policy checks."""

    def _make_client(self, trust_score=0.5, **policy_kwargs):
        identity = FlowiseNodeIdentity.generate("test", trust_score=trust_score)
        policy = FlowiseTrustPolicy(**policy_kwargs)
        return TrustGatedFlowiseClient(
            base_url="http://localhost:3000",
            identity=identity,
            policy=policy,
        )

    def test_low_trust_blocked(self):
        client = self._make_client(trust_score=0.2, min_trust_score=0.5)
        with pytest.raises(FlowiseTrustError, match="below required"):
            client.predict("flow-1", "hello")

    def test_blocked_flow(self):
        client = self._make_client(
            trust_score=0.9, blocked_flows=["bad-flow"]
        )
        with pytest.raises(FlowiseTrustError, match="blocked"):
            client.predict("bad-flow", "hello")

    def test_allowed_flow_only(self):
        client = self._make_client(
            trust_score=0.9, allowed_flows=["good-flow"]
        )
        with pytest.raises(FlowiseTrustError, match="not in allowed"):
            client.predict("other-flow", "hello")

    def test_https_required(self):
        identity = FlowiseNodeIdentity.generate("test", trust_score=0.9)
        policy = FlowiseTrustPolicy(require_https=True)
        client = TrustGatedFlowiseClient(
            base_url="http://external-server.com:3000",
            identity=identity,
            policy=policy,
        )
        with pytest.raises(FlowiseTrustError, match="HTTPS required"):
            client.predict("flow-1", "hello")

    def test_localhost_https_exempt(self):
        # localhost should not raise HTTPS error — will fail on actual HTTP call
        client = self._make_client(trust_score=0.9, require_https=True)
        # Policy check passes, actual HTTP will fail (no server)
        with pytest.raises(FlowiseTrustError, match="API error"):
            client.predict("flow-1", "hello")

    def test_rate_limiting(self):
        client = self._make_client(
            trust_score=0.9, max_calls_per_minute=2
        )
        # First 2 calls: policy passes, fails on HTTP (no server)
        for _ in range(2):
            with pytest.raises(FlowiseTrustError, match="API error"):
                client.predict("flow-1", "hello")
        # 3rd call: rate limited before HTTP
        with pytest.raises(FlowiseTrustError, match="Rate limit"):
            client.predict("flow-1", "hello")

    def test_trust_report(self):
        client = self._make_client(trust_score=0.8)
        report = client.get_trust_report()
        assert report["identity"]["trust_score"] == 0.8
        assert report["total_calls"] == 0

    def test_headers_include_trust(self):
        client = self._make_client(trust_score=0.7)
        headers = client._build_headers()
        assert headers["X-AgentMesh-DID"].startswith("did:flowise:")
        assert headers["X-AgentMesh-TrustScore"] == "0.7"


class TestFlowiseNodeDefinition:
    """Tests for FlowiseNodeDefinition."""

    def test_trust_gate_node(self):
        node = FlowiseNodeDefinition.trust_gate_node()
        assert node["label"] == "AgentMesh Trust Gate"
        assert node["category"] == "Security"
        assert len(node["inputs"]) == 3

    def test_identity_node(self):
        node = FlowiseNodeDefinition.identity_node()
        assert node["label"] == "AgentMesh Identity"
        assert any(i["name"] == "agentName" for i in node["inputs"])

    def test_export_all(self):
        nodes = FlowiseNodeDefinition.export_all()
        assert len(nodes) == 2


# ── Haystack ────────────────────────────────────────────────────────

from agentmesh.integrations.haystack import (
    HaystackTrustError,
    PipelineAuditEntry,
    PipelineIdentity,
    TrustAgentComponent,
    TrustGateComponent,
    TrustedPipeline,
)


class TestHaystackIdentity:
    """Tests for Haystack PipelineIdentity."""

    def test_generate_identity(self):
        identity = PipelineIdentity.generate("retriever", component_type="retriever")
        assert identity.component_name == "retriever"
        assert identity.did.startswith("did:haystack:")

    def test_unique_dids(self):
        id1 = PipelineIdentity.generate("a")
        id2 = PipelineIdentity.generate("b")
        assert id1.did != id2.did


class TestHaystackTrustGate:
    """Tests for Haystack TrustGateComponent."""

    def test_verify_passes(self):
        gate = TrustGateComponent(min_trust_score=0.5)
        identity = PipelineIdentity.generate("comp", trust_score=0.8)
        gate.register_component("comp", identity)
        result = gate.run("comp", {"query": "test"})
        assert result["verified"] is True
        assert result["data"]["query"] == "test"

    def test_verify_fails_low_trust(self):
        gate = TrustGateComponent(min_trust_score=0.8)
        identity = PipelineIdentity.generate("comp", trust_score=0.3)
        gate.register_component("comp", identity)
        with pytest.raises(HaystackTrustError, match="below required"):
            gate.run("comp", {"query": "test"})

    def test_verify_fails_missing_capability(self):
        gate = TrustGateComponent(required_capabilities=["execute"])
        identity = PipelineIdentity.generate("comp", capabilities=["search"])
        gate.register_component("comp", identity)
        with pytest.raises(HaystackTrustError, match="Missing capability"):
            gate.run("comp", {})

    def test_unregistered_component(self):
        gate = TrustGateComponent()
        with pytest.raises(HaystackTrustError, match="not registered"):
            gate.run("missing", {})

    def test_audit_log(self):
        gate = TrustGateComponent()
        identity = PipelineIdentity.generate("comp", trust_score=0.8)
        gate.register_component("comp", identity)
        gate.run("comp", {"key": "val"})
        log = gate.get_audit_log()
        assert len(log) == 1
        assert log[0].verified is True
        assert "key" in log[0].input_keys


class TestHaystackTrustAgent:
    """Tests for Haystack TrustAgentComponent."""

    def test_agent_with_handler(self):
        identity = PipelineIdentity.generate("agent", trust_score=0.8)
        agent = TrustAgentComponent(identity=identity, min_trust_score=0.5)
        result = agent.run("hello", handler=lambda q: f"echo: {q}")
        assert result["result"] == "echo: hello"
        assert result["verified"] is True

    def test_agent_low_trust_blocked(self):
        identity = PipelineIdentity.generate("agent", trust_score=0.2)
        agent = TrustAgentComponent(identity=identity, min_trust_score=0.5)
        with pytest.raises(HaystackTrustError, match="below required"):
            agent.run("hello", handler=lambda q: q)

    def test_agent_missing_capability(self):
        identity = PipelineIdentity.generate("agent", capabilities=["search"])
        agent = TrustAgentComponent(
            identity=identity, required_capabilities=["execute"]
        )
        with pytest.raises(HaystackTrustError, match="Missing capability"):
            agent.run("hello")

    def test_agent_audit_log(self):
        identity = PipelineIdentity.generate("agent", trust_score=0.8)
        agent = TrustAgentComponent(identity=identity)
        agent.run("query", handler=lambda q: "result")
        log = agent.get_audit_log()
        assert len(log) == 1
        assert log[0].duration_ms >= 0


class TestHaystackTrustedPipeline:
    """Tests for TrustedPipeline."""

    def test_add_and_verify(self):
        pipeline = TrustedPipeline(min_trust_score=0.4)
        pipeline.add_component("retriever", capabilities=["search"], trust_score=0.8)
        result = pipeline.verify_stage("retriever", {"query": "test"})
        assert result["verified"] is True

    def test_update_trust(self):
        pipeline = TrustedPipeline()
        pipeline.add_component("comp", trust_score=0.5)
        pipeline.update_trust("comp", 0.3)
        report = pipeline.get_pipeline_report()
        assert report["components"]["comp"]["trust_score"] == pytest.approx(0.8)

    def test_update_trust_clamped(self):
        pipeline = TrustedPipeline()
        pipeline.add_component("comp", trust_score=0.9)
        pipeline.update_trust("comp", 0.5)  # would be 1.4, clamped to 1.0
        report = pipeline.get_pipeline_report()
        assert report["components"]["comp"]["trust_score"] == 1.0

    def test_pipeline_report(self):
        pipeline = TrustedPipeline()
        pipeline.add_component("a", trust_score=0.8)
        pipeline.add_component("b", trust_score=0.7)
        pipeline.verify_stage("a", {})
        pipeline.verify_stage("b", {})
        report = pipeline.get_pipeline_report()
        assert report["total_verifications"] == 2
        assert report["passed"] == 2
        assert report["blocked"] == 0
