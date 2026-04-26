# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for P2 features: trace replay, gitops, chaos library, cost anomaly, postmortems."""

import pytest

from agent_sre.chaos.library import ChaosLibrary, ExperimentTemplate
from agent_sre.cost.anomaly import CostAnomalyDetector
from agent_sre.delivery.gitops import AgentRef, RolloutSpec, SpecVersion
from agent_sre.incidents.detector import Incident, IncidentSeverity, Signal, SignalType
from agent_sre.incidents.postmortem import Postmortem, PostmortemGenerator, PostmortemStatus
from agent_sre.replay.capture import Span, SpanKind, Trace
from agent_sre.replay.distributed import DistributedReplayEngine

# --- Trace Replay ---

class TestDistributedReplay:
    def _make_trace(self, agent_id, trace_id="t1"):
        trace = Trace(trace_id=trace_id, agent_id=agent_id, task_input="test")
        span = Span(span_id="s1", trace_id=trace_id, kind=SpanKind.AGENT_TASK, name="task")
        span.finish(output={"result": "ok"})
        trace.add_span(span)
        trace.finish(output="ok", success=True)
        return trace

    def test_add_and_replay(self):
        engine = DistributedReplayEngine()
        engine.add_agent_trace("agent-a", self._make_trace("agent-a", "t1"), role="initiator")
        engine.add_agent_trace("agent-b", self._make_trace("agent-b", "t2"), role="responder")
        result = engine.replay()
        assert result.agents_completed == 2
        assert result.state.value == "completed"

    def test_execution_order(self):
        engine = DistributedReplayEngine()
        engine.add_agent_trace("agent-a", self._make_trace("agent-a"), role="initiator")
        engine.add_agent_trace("agent-b", self._make_trace("agent-b"), role="responder")
        engine.link_delegation("agent-a", "agent-b", "s1", "t2")
        order = engine.execution_order()
        assert order[0] == "agent-a"

    def test_to_dict(self):
        engine = DistributedReplayEngine()
        engine.add_agent_trace("agent-a", self._make_trace("agent-a"))
        d = engine.to_dict()
        assert "agents" in d
        assert "agent-a" in d["agents"]

    def test_discover_links(self):
        engine = DistributedReplayEngine()
        trace = Trace(trace_id="t1", agent_id="agent-a")
        span = Span(
            span_id="d1", trace_id="t1", kind=SpanKind.DELEGATION, name="delegate",
            attributes={"target_agent": "agent-b", "target_trace_id": "t2"},
        )
        span.finish(output={"delegated_trace_id": "t2"})
        trace.add_span(span)
        trace.finish()
        engine.add_agent_trace("agent-a", trace)
        engine.add_agent_trace("agent-b", self._make_trace("agent-b", "t2"))
        links = engine.discover_links()
        assert len(links) >= 1
        assert any(l.from_agent == "agent-a" and l.to_agent == "agent-b" for l in links)


# --- GitOps Rollout Spec ---

class TestGitOpsSpec:
    def test_default_canary(self):
        spec = RolloutSpec.default_canary("my-rollout", "v1.0", "v1.1")
        assert spec.strategy.value == "canary"
        assert len(spec.steps) == 4
        errors = spec.validate()
        assert len(errors) == 0

    def test_default_shadow(self):
        spec = RolloutSpec.default_shadow("my-shadow", "v1.0", "v1.1")
        assert spec.strategy.value == "shadow"
        assert len(spec.steps) == 1

    def test_validation_errors(self):
        spec = RolloutSpec()
        errors = spec.validate()
        assert "metadata.name is required" in errors
        assert "spec.candidate.name is required" in errors

    def test_to_dict_structure(self):
        spec = RolloutSpec.default_canary("my-rollout", "v1.0", "v1.1")
        d = spec.to_dict()
        assert d["apiVersion"] == SpecVersion.V1ALPHA1.value
        assert d["kind"] == "AgentRollout"
        assert "metadata" in d
        assert "spec" in d

    def test_agent_ref(self):
        ref = AgentRef(name="my-agent", version="v2.0", model="gpt-4")
        d = ref.to_dict()
        assert d["name"] == "my-agent"
        assert d["model"] == "gpt-4"

    def test_step_weights_validation(self):
        from agent_sre.delivery.rollout import RolloutStep
        spec = RolloutSpec(
            name="test",
            candidate=AgentRef(name="agent", version="v1"),
            steps=[
                RolloutStep(weight=0.5),
                RolloutStep(weight=0.1),  # Out of order
            ],
        )
        errors = spec.validate()
        assert any("increasing order" in e for e in errors)


# --- Chaos Library ---

class TestChaosLibrary:
    def test_builtin_templates(self):
        lib = ChaosLibrary()
        templates = lib.list_templates()
        assert len(templates) >= 3

    def test_get_template(self):
        lib = ChaosLibrary()
        t = lib.get("timeout-injection")
        assert t is not None

    def test_instantiate(self):
        lib = ChaosLibrary()
        exp = lib.instantiate("timeout-injection", "agent-1")
        assert exp is not None
        assert exp.target_agent == "agent-1"

    def test_filter_by_category(self):
        lib = ChaosLibrary()
        tool_templates = lib.list_templates(category="tool")
        assert all(t.category == "tool" for t in tool_templates)
        assert len(tool_templates) >= 2

    def test_filter_by_severity(self):
        lib = ChaosLibrary()
        critical = lib.list_templates(severity="critical")
        assert all(t.severity == "critical" for t in critical)

    def test_filter_by_tag(self):
        lib = ChaosLibrary()
        latency = lib.list_templates(tag="latency")
        assert all("latency" in t.tags for t in latency)

    def test_register_custom(self):
        lib = ChaosLibrary()
        custom = ExperimentTemplate(
            template_id="custom-test",
            name="Custom Test",
            description="A custom test",
            category="custom",
        )
        lib.register(custom)
        assert lib.get("custom-test") is not None

    def test_categories(self):
        lib = ChaosLibrary()
        cats = lib.categories()
        assert "tool" in cats
        assert "llm" in cats

    def test_to_dict(self):
        lib = ChaosLibrary()
        d = lib.to_dict()
        assert d["template_count"] >= 3

    def test_nonexistent_template(self):
        lib = ChaosLibrary()
        assert lib.instantiate("nonexistent", "agent-1") is None


# --- Cost Anomaly Detection ---

class TestCostAnomalyDetector:
    def test_needs_min_samples(self):
        detector = CostAnomalyDetector(min_samples=10)
        for _i in range(9):
            result = detector.ingest(1.0)
            assert result is None

    def test_detects_spike(self):
        detector = CostAnomalyDetector(min_samples=10, z_threshold=2.0)
        # Normal baseline
        for _ in range(20):
            detector.ingest(1.0)
        # Spike
        result = detector.ingest(100.0)
        assert result is not None
        assert result.is_anomaly

    def test_no_anomaly_for_normal(self):
        detector = CostAnomalyDetector(min_samples=10)
        for _ in range(20):
            result = detector.ingest(1.0)
        # Should not trigger on normal value
        assert result is None or not result.is_anomaly

    def test_baseline_stats(self):
        detector = CostAnomalyDetector()
        for i in range(20):
            detector.ingest(float(i))
        stats = detector.baseline
        assert stats.sample_count == 20
        assert stats.mean > 0

    def test_severity_levels(self):
        detector = CostAnomalyDetector(min_samples=10, z_threshold=2.0)
        for _ in range(20):
            detector.ingest(1.0)
        result = detector.ingest(1000.0)
        assert result is not None
        assert result.severity.value in ("low", "medium", "high", "critical")

    def test_summary(self):
        detector = CostAnomalyDetector(min_samples=5)
        for _ in range(10):
            detector.ingest(1.0)
        detector.ingest(100.0)
        s = detector.summary()
        assert "baseline" in s
        assert "total_anomalies" in s

    def test_anomaly_result_to_dict(self):
        detector = CostAnomalyDetector(min_samples=5, z_threshold=1.5)
        for _ in range(10):
            detector.ingest(1.0)
        result = detector.ingest(100.0)
        if result:
            d = result.to_dict()
            assert "is_anomaly" in d
            assert "method" in d


# --- Postmortems ---

class TestPostmortem:
    def _make_incident(self):
        signal = Signal(
            signal_type=SignalType.SLO_BREACH,
            source="agent-1",
            value=0.90,
            threshold=0.99,
            message="Task success rate below SLO",
        )
        incident = Incident(
            title="SLO breach on agent-1",
            severity=IncidentSeverity.P2,
            signals=[signal],
            agent_id="agent-1",
        )
        incident.add_action("circuit_breaker", "agent isolated")
        incident.resolve("Fixed by rollback")
        return incident

    def test_generate_postmortem(self):
        gen = PostmortemGenerator()
        pm = gen.generate(self._make_incident())
        assert pm is not None
        assert pm.title != ""

    def test_postmortem_summary(self):
        gen = PostmortemGenerator()
        pm = gen.generate(self._make_incident())
        assert pm.summary != ""

    def test_postmortem_has_action_items(self):
        gen = PostmortemGenerator()
        pm = gen.generate(self._make_incident())
        assert len(pm.action_items) > 0

    def test_postmortem_to_markdown(self):
        gen = PostmortemGenerator()
        pm = gen.generate(self._make_incident())
        md = pm.to_markdown()
        assert "# Postmortem" in md or pm.title in md

    def test_postmortem_publish(self):
        pm = Postmortem(title="test")
        assert pm.status == PostmortemStatus.DRAFT
        pm.publish()
        assert pm.status == PostmortemStatus.PUBLISHED

    def test_add_timeline_entry(self):
        pm = Postmortem(title="test")
        pm.add_timeline_entry("something happened", "human", "details")
        assert len(pm.timeline) == 1

    def test_add_action_item(self):
        pm = Postmortem(title="test")
        item = pm.add_action_item("Fix the thing", "Do it right", "high")
        assert item.priority == "high"
        assert len(pm.action_items) == 1

    def test_to_dict(self):
        gen = PostmortemGenerator()
        pm = gen.generate(self._make_incident())
        d = pm.to_dict()
        assert "title" in d
        assert "timeline" in d

    def test_generator_summary(self):
        gen = PostmortemGenerator()
        gen.generate(self._make_incident())
        s = gen.summary()
        assert s["total"] >= 1

    def test_lessons_learned(self):
        gen = PostmortemGenerator()
        pm = gen.generate(self._make_incident())
        assert pm.lessons_learned is not None

    def test_contributing_factors(self):
        gen = PostmortemGenerator()
        pm = gen.generate(self._make_incident())
        assert pm.contributing_factors is not None
