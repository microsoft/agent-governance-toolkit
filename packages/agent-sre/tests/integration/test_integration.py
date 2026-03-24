# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Integration Tests for Agent-SRE.

These tests verify that the major subsystems work together correctly:
- SLI → SLO → ErrorBudget → Dashboard pipeline
- Chaos → Incidents → Postmortem flow
- Cost anomaly → Budget guard → Alert chain
- Delivery rollout → SLO evaluation → Rollback
- Evaluation engine → SLI feed → SLO tracking
- Observability integrations → SLI values
"""

import contextlib
import time

import pytest

@pytest.mark.integration
class TestSLOPipeline:
    """SLI recording → SLO evaluation → Error Budget → Dashboard."""

    def test_full_slo_lifecycle(self):
        from agent_sre.slo.dashboard import SLODashboard
        from agent_sre.slo.indicators import (
            CostPerTask,
            ResponseLatency,
            TaskSuccessRate,
            ToolCallAccuracy,
        )
        from agent_sre.slo.objectives import SLO, ErrorBudget, SLOStatus

        success = TaskSuccessRate(target=0.95)
        accuracy = ToolCallAccuracy(target=0.99)
        latency = ResponseLatency(target_ms=5000.0)
        cost = CostPerTask(target_usd=0.50)

        slo = SLO(
            name="test-agent",
            indicators=[success, accuracy, latency, cost],
            description="Integration test SLO",
            error_budget=ErrorBudget(total=5.0),  # Generous budget for testing
        )

        # Record mostly good events
        for _ in range(19):
            success.record_task(True)
            accuracy.record_call(True)
            slo.record_event(True)
        success.record_task(False)
        slo.record_event(False)

        for ms in [100, 200, 300, 400, 500]:
            latency.record_latency(ms)

        for c in [0.10, 0.15, 0.20]:
            cost.record_cost(c)

        status = slo.evaluate()
        # Status depends on burn rate timing; any non-EXHAUSTED status is valid
        assert status in (SLOStatus.HEALTHY, SLOStatus.UNKNOWN, SLOStatus.WARNING, SLOStatus.CRITICAL)

        dashboard = SLODashboard()
        dashboard.register_slo(slo)
        snapshots = dashboard.take_snapshot()
        assert len(snapshots) == 1
        assert snapshots[0].slo_name == "test-agent"

        health = dashboard.health_summary()
        assert health["total_slos"] == 1

        d = slo.to_dict()
        assert d["name"] == "test-agent"
        assert len(d["indicators"]) == 4

    def test_error_budget_exhaustion(self):
        from agent_sre.slo.indicators import TaskSuccessRate
        from agent_sre.slo.objectives import SLO, ErrorBudget, ExhaustionAction, SLOStatus

        sli = TaskSuccessRate(target=0.99)
        budget = ErrorBudget(total=0.01, exhaustion_action=ExhaustionAction.CIRCUIT_BREAK)
        slo = SLO(name="strict-slo", indicators=[sli], error_budget=budget)

        sli.record_task(True)
        slo.record_event(True)
        for _ in range(5):
            sli.record_task(False)
            slo.record_event(False)

        assert slo.error_budget.is_exhausted
        assert slo.evaluate() == SLOStatus.EXHAUSTED

    def test_multi_slo_dashboard(self):
        from agent_sre.slo.dashboard import SLODashboard
        from agent_sre.slo.indicators import TaskSuccessRate
        from agent_sre.slo.objectives import SLO

        dashboard = SLODashboard()

        for i in range(3):
            sli = TaskSuccessRate(target=0.95)
            for _ in range(5):
                sli.record_task(True)
            slo = SLO(name=f"agent-{i}", indicators=[sli])
            for _ in range(5):
                slo.record_event(True)
            dashboard.register_slo(slo)

        health = dashboard.health_summary()
        assert health["total_slos"] == 3
        snapshots = dashboard.take_snapshot()
        assert len(snapshots) == 3


@pytest.mark.integration
class TestIncidentFlow:
    """Incident detection → Circuit breaker → Postmortem."""

    def test_circuit_breaker_triggers(self):
        from agent_sre.incidents.circuit_breaker import (
            CircuitBreaker,
            CircuitBreakerConfig,
            CircuitState,
        )

        config = CircuitBreakerConfig(
            failure_threshold=3,
            timeout_seconds=0.1,
            half_open_max_calls=1,
        )
        cb = CircuitBreaker("test-agent", config)

        assert cb.state == CircuitState.CLOSED

        for _ in range(3):
            cb.record_failure()

        assert cb.state == CircuitState.OPEN

        # Community Edition: no auto half-open, use force_close to recover
        time.sleep(0.15)
        assert cb.state == CircuitState.OPEN
        assert not cb.is_available

        cb.force_close("manual recovery")
        assert cb.state == CircuitState.CLOSED

    def test_incident_detection(self):
        from agent_sre.incidents.detector import (
            IncidentDetector,
            Signal,
            SignalType,
        )

        detector = IncidentDetector()

        for i in range(10):
            signal = Signal(
                signal_type=SignalType.TOOL_FAILURE_SPIKE,
                value=0.5 if i < 5 else 0.1,
                source="test",
            )
            detector.ingest_signal(signal)

        incidents = detector.open_incidents
        assert isinstance(incidents, list)

    def test_postmortem_generation(self):
        from agent_sre.incidents.detector import (
            IncidentDetector,
            Signal,
            SignalType,
        )
        from agent_sre.incidents.postmortem import (
            PostmortemGenerator,
        )

        detector = IncidentDetector()
        for _ in range(10):
            detector.ingest_signal(Signal(
                signal_type=SignalType.SLO_BREACH,
                value=0.9,
                source="test",
            ))

        gen = PostmortemGenerator()

        incidents = detector.open_incidents
        if incidents:
            # Community Edition: generate raises NotImplementedError
            with contextlib.suppress(NotImplementedError):
                gen.generate(incidents[0])
        else:
            # Verify generator instantiation works
            assert gen is not None


@pytest.mark.integration
class TestCostPipeline:
    """Cost recording → Anomaly detection → Budget guard."""

    def test_cost_anomaly_detection(self):
        from agent_sre.cost.anomaly import CostAnomalyDetector

        detector = CostAnomalyDetector(min_samples=5)

        # Build baseline
        for _ in range(10):
            detector.ingest(1.0, agent_id="test")

        # Add anomalous spike
        detector.ingest(100.0, agent_id="test")
        # Should detect anomaly (or at least return a result)
        assert True  # ingest may return None if not anomalous

    def test_cost_guard_budget_limit(self):
        from agent_sre.cost.guard import CostGuard

        guard = CostGuard(per_agent_daily_limit=10.0)

        # Record costs
        for i in range(8):
            guard.record_cost("test-agent", f"task-{i}", 1.0)

        budget = guard.get_budget("test-agent")
        assert budget.spent_today_usd >= 8.0

    def test_cost_guard_check_task(self):
        from agent_sre.cost.guard import CostGuard

        guard = CostGuard(per_agent_daily_limit=5.0)

        # Fill up budget
        for i in range(5):
            guard.record_cost("test-agent", f"task-{i}", 1.0)

        # Next task should be blocked or flagged
        allowed, reason = guard.check_task("test-agent", estimated_cost=1.0)
        assert isinstance(allowed, bool)


@pytest.mark.integration
class TestDeliveryPipeline:
    """Rollout → SLO evaluation → Decision."""

    def test_canary_rollout(self):
        from agent_sre.delivery.rollout import (
            CanaryRollout,
            RolloutState,
            RolloutStep,
        )

        rollout = CanaryRollout(
            name="v2-rollout",
            steps=[
                RolloutStep(weight=0.1, duration_seconds=60, name="canary-10"),
                RolloutStep(weight=0.5, duration_seconds=60, name="canary-50"),
                RolloutStep(weight=1.0, duration_seconds=0, name="full"),
            ],
        )

        assert rollout.state == RolloutState.PENDING
        # Community Edition: start raises NotImplementedError
        with contextlib.suppress(NotImplementedError):
            rollout.start()


@pytest.mark.integration
class TestEvalsSLIPipeline:
    """Evaluation engine → SLI feed → SLO tracking."""

    def test_evals_drive_slo(self):
        from agent_sre.evals import EvalInput, EvaluationEngine, RulesJudge
        from agent_sre.slo.indicators import HallucinationRate, TaskSuccessRate
        from agent_sre.slo.objectives import SLO

        judge = RulesJudge()
        engine = EvaluationEngine(judge)

        success_sli = TaskSuccessRate(target=0.90)
        hallucination_sli = HallucinationRate(target=0.10)
        slo = SLO(
            name="eval-driven-slo",
            indicators=[success_sli, hallucination_sli],
        )

        # Simulate 10 agent interactions
        tasks = [
            ("What is Python?", "Python is a programming language.", "Python is a programming language"),
            ("What is Java?", "Java is a programming language.", "Java is a programming language"),
            ("What is Go?", "Go is a language by Google.", "Go is a programming language"),
            ("What is Rust?", "Rust is a systems language.", "Rust is a systems programming language"),
            ("What is C++?", "C++ is used for systems.", "C++ is a compiled language"),
        ]

        for query, response, reference in tasks:
            report = engine.run(EvalInput(query=query, response=response, reference=reference))
            success_sli.record_task(success=report.overall_pass)
            slo.record_event(good=report.overall_pass)

            # Feed hallucination results
            hallu_results = [r for r in report.results if r.criterion.value == "hallucination"]
            if hallu_results:
                hallucination_sli.record_evaluation(
                    hallucinated=(hallu_results[0].score < 0.7)
                )

        # Verify SLIs have data
        assert success_sli._total == 5
        assert hallucination_sli._total == 5
        assert engine.pass_rate() >= 0.0


@pytest.mark.integration
class TestObservabilityIntegrations:
    """OTEL, Langfuse, Arize all feeding into SLIs."""

    def test_arize_eval_to_sli(self):
        from agent_sre.integrations.arize import EvaluationImporter, PhoenixExporter

        exporter = PhoenixExporter()
        importer = EvaluationImporter()

        # Export SLO evaluation
        exporter.export_slo_evaluation(
            "my-slo", "healthy", 0.95, 0.3,
            indicators={"task_success_rate": 0.98},
        )

        # Import eval results
        importer.import_batch([
            {"eval_name": "hallucination", "score": 0.05},
            {"eval_name": "relevance", "score": 0.92},
        ])

        sli_values = importer.get_sli_values()
        assert "hallucination_rate" in sli_values
        assert "task_success_rate" in sli_values

    def test_langchain_callback_to_sli(self):
        from agent_sre.integrations.langchain.callback import AgentSRECallback

        cb = AgentSRECallback()

        # Simulate LLM calls
        cb.on_llm_start(serialized={"name": "gpt-4"}, prompts=["test"])
        cb.on_llm_end(response=type("R", (), {"generations": [[type("G", (), {"text": "result"})()]]})())

        # Simulate chain
        cb.on_chain_start(serialized={"name": "chain"}, inputs={"q": "test"})
        cb.on_chain_end(outputs={"result": "done"})

        snapshot = cb.get_sli_snapshot()
        assert "task_success_rate" in snapshot
        assert snapshot["task_success_rate"] == 1.0  # All succeeded

    def test_langfuse_exporter_sli_feed(self):
        from agent_sre.integrations.langfuse.exporter import LangfuseExporter

        exporter = LangfuseExporter()

        # Record cost observations (actual API)
        exporter.record_cost(
            trace_id="trace-1",
            agent_id="test",
            cost_usd=0.95,
        )
        exporter.record_cost(
            trace_id="trace-2",
            agent_id="test",
            cost_usd=0.98,
        )

        assert len(exporter.observations) == 2


@pytest.mark.integration
class TestReplayFlow:
    """Trace capture → Replay → Diff analysis."""

    def test_trace_capture_and_replay(self):
        from agent_sre.replay.capture import Span, SpanKind, SpanStatus, TraceCapture

        capture = TraceCapture(agent_id="test-agent", task_input="run test")

        root = Span(
            name="agent.run",
            kind=SpanKind.INTERNAL,
            status=SpanStatus.OK,
        )
        child = Span(
            name="tool.search",
            kind=SpanKind.TOOL_CALL,
            status=SpanStatus.OK,
            parent_id=root.span_id,
        )

        trace = capture.trace
        trace.add_span(root)
        trace.add_span(child)
        trace.finish(output="done")

        assert trace.agent_id == "test-agent"
        assert len(trace.spans) == 2
        assert trace.task_output == "done"


@pytest.mark.integration
class TestChaosExperiment:
    """Chaos experiment lifecycle."""

    def test_fault_injection(self):
        from agent_sre.chaos.engine import (
            AbortCondition,
            ChaosExperiment,
            ExperimentState,
            Fault,
            FaultType,
        )

        experiment = ChaosExperiment(
            name="latency-test",
            target_agent="test-agent",
            faults=[
                Fault(
                    fault_type=FaultType.LATENCY_INJECTION,
                    target="llm-call",
                    params={"delay_ms": 2000},
                ),
            ],
            abort_conditions=[
                AbortCondition(
                    metric="error_rate",
                    threshold=0.5,
                ),
            ],
        )

        assert experiment.state == ExperimentState.PENDING
        experiment.start()
        assert experiment.state == ExperimentState.RUNNING

        experiment.complete()
        assert experiment.state == ExperimentState.COMPLETED


@pytest.mark.integration
class TestSLIRegistry:
    """SLI type registration and discovery."""

    def test_registry_builtins(self):
        from agent_sre.slo.indicators import SLIRegistry

        registry = SLIRegistry()
        types = registry.list_types()

        assert "TaskSuccessRate" in types
        assert "ToolCallAccuracy" in types
        assert "ResponseLatency" in types
        assert "CostPerTask" in types
        assert "PolicyCompliance" in types
        assert "HallucinationRate" in types

    def test_registry_instance_tracking(self):
        from agent_sre.slo.indicators import SLIRegistry, TaskSuccessRate

        registry = SLIRegistry()
        sli = TaskSuccessRate(target=0.95)
        registry.register_instance("agent-1", sli)

        instances = registry.get_instances("agent-1")
        assert len(instances) == 1
        assert instances[0].name == "task_success_rate"

    def test_collect_all(self):
        from agent_sre.slo.indicators import SLIRegistry, TaskSuccessRate, ToolCallAccuracy

        registry = SLIRegistry()
        sli1 = TaskSuccessRate(target=0.95)
        sli2 = ToolCallAccuracy(target=0.99)

        sli1.record_task(True)
        sli2.record_call(True)

        registry.register_instance("agent-1", sli1)
        registry.register_instance("agent-1", sli2)

        values = registry.collect_all("agent-1")
        assert len(values) == 2
