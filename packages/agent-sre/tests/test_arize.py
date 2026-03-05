# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Arize/Phoenix integration.

Covers: PhoenixExporter, PhoenixSpan, EvaluationImporter, EvaluationRecord.
No external dependencies.
"""


from agent_sre.integrations.arize import (
    EvaluationImporter,
    EvaluationRecord,
    PhoenixExporter,
    PhoenixSpan,
)

# =============================================================================
# PhoenixSpan
# =============================================================================


class TestPhoenixSpan:
    def test_basic(self):
        s = PhoenixSpan(name="test", span_kind="LLM")
        assert s.name == "test"
        assert s.span_kind == "LLM"

    def test_to_dict(self):
        s = PhoenixSpan(
            trace_id="t1",
            name="eval",
            span_kind="EVALUATOR",
            status="OK",
            attributes={"key": "val"},
        )
        d = s.to_dict()
        assert d["name"] == "eval"
        assert d["span_kind"] == "EVALUATOR"
        assert d["context"]["trace_id"] == "t1"
        assert d["attributes"]["key"] == "val"

    def test_parent_id(self):
        s = PhoenixSpan(parent_id="p1")
        d = s.to_dict()
        assert d["parent_id"] == "p1"

    def test_no_parent(self):
        s = PhoenixSpan()
        d = s.to_dict()
        assert "parent_id" not in d


# =============================================================================
# PhoenixExporter
# =============================================================================


class TestPhoenixExporter:
    def test_offline_mode(self):
        e = PhoenixExporter()
        assert e.is_offline

    def test_live_mode(self):
        received = []
        e = PhoenixExporter(on_span=lambda s: received.append(s))
        assert not e.is_offline
        e.export_slo_evaluation("test-slo", "healthy", 0.95, 0.5)
        assert len(received) == 1

    def test_export_slo_healthy(self):
        e = PhoenixExporter()
        span = e.export_slo_evaluation(
            slo_name="my-slo",
            status="healthy",
            budget_remaining=0.95,
            burn_rate=0.3,
            indicators={"task_success_rate": 0.98},
        )
        assert span.span_kind == "EVALUATOR"
        assert span.status == "OK"
        assert span.attributes["slo.name"] == "my-slo"
        assert span.attributes["slo.budget_remaining"] == 0.95
        assert span.attributes["sli.task_success_rate"] == 0.98

    def test_export_slo_critical(self):
        e = PhoenixExporter()
        span = e.export_slo_evaluation("slo", "critical", 0.01, 5.0)
        assert span.status == "ERROR"

    def test_export_cost_record(self):
        e = PhoenixExporter()
        span = e.export_cost_record(
            agent_id="agent-1",
            task_id="task-1",
            cost_usd=0.42,
            breakdown={"llm": 0.40, "api": 0.02},
        )
        assert span.attributes["cost.total_usd"] == 0.42
        assert span.attributes["cost.llm_usd"] == 0.40
        assert span.attributes["agent.id"] == "agent-1"

    def test_export_incident(self):
        e = PhoenixExporter()
        span = e.export_incident(
            incident_id="inc-1",
            severity="critical",
            description="SLO breach",
            agent_id="agent-1",
        )
        assert span.status == "ERROR"
        assert span.attributes["incident.severity"] == "critical"
        assert span.attributes["agent.id"] == "agent-1"

    def test_spans_list(self):
        e = PhoenixExporter()
        e.export_slo_evaluation("a", "healthy", 0.9, 0.1)
        e.export_cost_record("agent", "task", 0.5)
        assert len(e.spans) == 2

    def test_clear(self):
        e = PhoenixExporter()
        e.export_slo_evaluation("a", "healthy", 0.9, 0.1)
        e.clear()
        assert len(e.spans) == 0

    def test_stats(self):
        e = PhoenixExporter(project_name="test")
        e.export_slo_evaluation("a", "healthy", 0.9, 0.1)
        e.export_slo_evaluation("b", "critical", 0.01, 5.0)
        e.export_incident("i1", "high", "desc")
        stats = e.get_stats()
        assert stats["total_spans"] == 3
        assert stats["evaluator_spans"] == 2
        assert stats["error_spans"] == 2
        assert stats["project"] == "test"

    def test_live_error_does_not_crash(self):
        def bad_callback(span):
            raise RuntimeError("fail")

        e = PhoenixExporter(on_span=bad_callback)
        span = e.export_slo_evaluation("a", "healthy", 0.9, 0.1)
        assert span is not None  # Should not raise

    def test_trace_id_auto_generated(self):
        e = PhoenixExporter()
        span = e.export_slo_evaluation("a", "healthy", 0.9, 0.1)
        assert span.trace_id != ""

    def test_trace_id_explicit(self):
        e = PhoenixExporter()
        span = e.export_slo_evaluation("a", "healthy", 0.9, 0.1, trace_id="custom-trace")
        assert span.trace_id == "custom-trace"


# =============================================================================
# EvaluationRecord
# =============================================================================


class TestEvaluationRecord:
    def test_basic(self):
        r = EvaluationRecord(eval_name="hallucination", score=0.85)
        assert r.eval_name == "hallucination"
        assert r.score == 0.85

    def test_to_dict(self):
        r = EvaluationRecord(
            eval_name="relevance",
            label="relevant",
            score=0.92,
            trace_id="t1",
        )
        d = r.to_dict()
        assert d["eval_name"] == "relevance"
        assert d["score"] == 0.92


# =============================================================================
# EvaluationImporter
# =============================================================================


class TestEvaluationImporter:
    def test_import_single(self):
        imp = EvaluationImporter()
        record = imp.import_evaluation({
            "eval_name": "hallucination",
            "label": "hallucinated",
            "score": 0.85,
        })
        assert record.eval_name == "hallucination"
        assert len(imp.get_records()) == 1

    def test_import_batch(self):
        imp = EvaluationImporter()
        records = imp.import_batch([
            {"eval_name": "hallucination", "score": 0.9},
            {"eval_name": "relevance", "score": 0.8},
            {"eval_name": "correctness", "score": 0.95},
        ])
        assert len(records) == 3
        assert len(imp.get_records()) == 3

    def test_get_sli_values(self):
        imp = EvaluationImporter()
        imp.import_batch([
            {"eval_name": "hallucination", "score": 0.9},
            {"eval_name": "hallucination", "score": 0.7},
            {"eval_name": "relevance", "score": 0.85},
        ])
        sli = imp.get_sli_values()
        assert "hallucination_rate" in sli
        assert len(sli["hallucination_rate"]) == 2
        assert "task_success_rate" in sli
        assert len(sli["task_success_rate"]) == 1

    def test_unmapped_eval_name(self):
        imp = EvaluationImporter()
        imp.import_evaluation({"eval_name": "custom_eval", "score": 0.5})
        sli = imp.get_sli_values()
        assert "custom_eval" not in sli  # Not mapped

    def test_filter_by_eval_name(self):
        imp = EvaluationImporter()
        imp.import_batch([
            {"eval_name": "hallucination", "score": 0.9},
            {"eval_name": "relevance", "score": 0.8},
        ])
        hallu = imp.get_records(eval_name="hallucination")
        assert len(hallu) == 1

    def test_stats(self):
        imp = EvaluationImporter()
        imp.import_batch([
            {"eval_name": "hallucination", "score": 0.9},
            {"eval_name": "hallucination", "score": 0.7},
            {"eval_name": "relevance", "score": 0.85},
        ])
        stats = imp.get_stats()
        assert stats["total_evaluations"] == 3
        assert stats["by_eval_name"]["hallucination"] == 2
        assert stats["by_eval_name"]["relevance"] == 1

    def test_clear(self):
        imp = EvaluationImporter()
        imp.import_evaluation({"eval_name": "x", "score": 0.5})
        imp.clear()
        assert len(imp.get_records()) == 0


# =============================================================================
# Integration
# =============================================================================


class TestIntegration:
    def test_export_then_import(self):
        """Full round-trip: export SLO eval, import Phoenix eval, get SLI values."""
        # Export side
        exporter = PhoenixExporter()
        exporter.export_slo_evaluation(
            "my-slo", "healthy", 0.95, 0.3,
            indicators={"task_success_rate": 0.98},
            trace_id="trace-001",
        )

        # Import side (Phoenix would have run evaluations)
        importer = EvaluationImporter()
        importer.import_batch([
            {"eval_name": "hallucination", "score": 0.05, "trace_id": "trace-001"},
            {"eval_name": "relevance", "score": 0.95, "trace_id": "trace-001"},
            {"eval_name": "correctness", "score": 0.92, "trace_id": "trace-001"},
        ])

        # Get SLI values for SLO calculation
        sli = importer.get_sli_values()
        assert sli["hallucination_rate"] == [0.05]
        assert len(sli["task_success_rate"]) == 2  # relevance + correctness

    def test_imports_from_package(self):
        from agent_sre.integrations.arize import (
            EvaluationImporter,
            EvaluationRecord,
            PhoenixExporter,
            PhoenixSpan,
        )
        assert all(c is not None for c in [
            PhoenixExporter, PhoenixSpan, EvaluationImporter, EvaluationRecord,
        ])
