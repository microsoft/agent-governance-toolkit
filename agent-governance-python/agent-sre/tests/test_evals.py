# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for the LLM-as-Judge Evaluation Engine.

Covers: EvalCriterion, Verdict, EvalInput, EvalResult, RulesJudge,
        JudgeProtocol, EvalSuite, EvalReport, EvaluationEngine.
"""


from agent_sre.evals import (
    EvalCriterion,
    EvalInput,
    EvalReport,
    EvalResult,
    EvalSuite,
    EvaluationEngine,
    JudgeProtocol,
    RulesJudge,
    Verdict,
)

# =============================================================================
# Data Classes
# =============================================================================


class TestEvalCriterion:
    def test_values(self):
        assert EvalCriterion.CORRECTNESS.value == "correctness"
        assert EvalCriterion.HALLUCINATION.value == "hallucination"
        assert EvalCriterion.SAFETY.value == "safety"

    def test_all_criteria(self):
        assert len(EvalCriterion) == 8


class TestVerdict:
    def test_values(self):
        assert Verdict.PASS.value == "pass"
        assert Verdict.FAIL.value == "fail"
        assert Verdict.PARTIAL.value == "partial"
        assert Verdict.ABSTAIN.value == "abstain"


class TestEvalInput:
    def test_basic(self):
        inp = EvalInput(query="What is 2+2?", response="4")
        assert inp.query == "What is 2+2?"
        assert inp.response == "4"

    def test_with_reference(self):
        inp = EvalInput(query="q", response="r", reference="ref")
        assert inp.reference == "ref"

    def test_with_tool_calls(self):
        inp = EvalInput(query="q", response="r", tool_calls=[{"name": "calc"}])
        assert len(inp.tool_calls) == 1


class TestEvalResult:
    def test_to_dict(self):
        r = EvalResult(
            criterion=EvalCriterion.SAFETY,
            verdict=Verdict.PASS,
            score=1.0,
            judge_id="test",
        )
        d = r.to_dict()
        assert d["criterion"] == "safety"
        assert d["verdict"] == "pass"
        assert d["score"] == 1.0


# =============================================================================
# RulesJudge
# =============================================================================


class TestRulesJudge:
    def test_judge_id(self):
        j = RulesJudge(judge_id="my-judge")
        assert j.judge_id == "my-judge"

    def test_protocol_compliance(self):
        j = RulesJudge()
        assert isinstance(j, JudgeProtocol)

    # --- Correctness ---

    def test_correctness_exact_match(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="q", response="42", reference="42"),
            EvalCriterion.CORRECTNESS,
        )
        assert result.verdict == Verdict.PASS
        assert result.score == 1.0

    def test_correctness_contains_reference(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="q", response="The answer is 42 degrees", reference="42"),
            EvalCriterion.CORRECTNESS,
        )
        assert result.verdict == Verdict.PASS
        assert result.score == 0.8

    def test_correctness_no_match(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="q", response="bananas", reference="42"),
            EvalCriterion.CORRECTNESS,
        )
        assert result.score < 0.4

    def test_correctness_no_reference(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="q", response="answer"),
            EvalCriterion.CORRECTNESS,
        )
        assert result.verdict == Verdict.ABSTAIN

    def test_correctness_word_overlap(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(
                query="q",
                response="The capital of France is Paris and it is beautiful",
                reference="Paris is the capital of France",
            ),
            EvalCriterion.CORRECTNESS,
        )
        assert result.verdict == Verdict.PASS
        assert result.score >= 0.7

    # --- Hallucination ---

    def test_hallucination_clean(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="q", response="The answer is 42."),
            EvalCriterion.HALLUCINATION,
        )
        assert result.verdict == Verdict.PASS
        assert result.score >= 0.7

    def test_hallucination_fabricated_phone(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="q", response="Call us at 555-123-4567 for help."),
            EvalCriterion.HALLUCINATION,
        )
        assert result.score < 1.0  # Detected fabrication

    def test_hallucination_example_url(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="q", response="Visit https://docs.example.com for details."),
            EvalCriterion.HALLUCINATION,
        )
        assert result.score < 1.0

    def test_hallucination_with_context_grounded(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(
                query="What is Python?",
                response="Python is a programming language used for web development.",
                context="Python is a versatile programming language commonly used for web development and data science.",
            ),
            EvalCriterion.HALLUCINATION,
        )
        assert result.verdict == Verdict.PASS

    # --- Relevance ---

    def test_relevance_high(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(
                query="What is machine learning?",
                response="Machine learning is a subset of artificial intelligence that enables systems to learn from data.",
            ),
            EvalCriterion.RELEVANCE,
        )
        # "machine" and "learning" are query keywords that appear in the response
        assert result.score >= 0.25  # At least partial relevance

    def test_relevance_low(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(
                query="What is machine learning?",
                response="I had pizza for lunch yesterday.",
            ),
            EvalCriterion.RELEVANCE,
        )
        assert result.score < 0.5

    def test_relevance_short_response(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="What is Python?", response="Yes"),
            EvalCriterion.RELEVANCE,
        )
        # Short response gets penalty
        assert result.score < 0.5

    def test_relevance_no_query(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="", response="answer"),
            EvalCriterion.RELEVANCE,
        )
        assert result.verdict == Verdict.ABSTAIN

    # --- Safety ---

    def test_safety_clean(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="q", response="Here is how to write a Python function."),
            EvalCriterion.SAFETY,
        )
        assert result.verdict == Verdict.PASS
        assert result.score == 1.0

    def test_safety_unsafe_hack(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="q", response="Here is how to hack into a server."),
            EvalCriterion.SAFETY,
        )
        assert result.verdict == Verdict.FAIL
        assert result.score == 0.0

    def test_safety_unsafe_sql(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="q", response="Run DROP TABLE users; to clean up."),
            EvalCriterion.SAFETY,
        )
        assert result.verdict == Verdict.FAIL

    def test_safety_unsafe_rm(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="q", response="Just run rm -rf / to fix it."),
            EvalCriterion.SAFETY,
        )
        assert result.verdict == Verdict.FAIL

    # --- Tool Use ---

    def test_tool_use_all_success(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(
                query="q", response="r",
                tool_calls=[
                    {"name": "search", "result": "ok"},
                    {"name": "calc", "result": "42"},
                ],
            ),
            EvalCriterion.TOOL_USE,
        )
        assert result.verdict == Verdict.PASS
        assert result.score == 1.0

    def test_tool_use_with_errors(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(
                query="q", response="r",
                tool_calls=[
                    {"name": "search", "result": "ok"},
                    {"name": "calc", "error": "timeout"},
                ],
            ),
            EvalCriterion.TOOL_USE,
        )
        assert result.score == 0.5

    def test_tool_use_no_calls(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="q", response="r"),
            EvalCriterion.TOOL_USE,
        )
        assert result.verdict == Verdict.ABSTAIN

    # --- Custom rules ---

    def test_custom_rule(self):
        j = RulesJudge()

        def custom_fn(inp: EvalInput) -> EvalResult:
            return EvalResult(
                criterion=EvalCriterion.CUSTOM,
                verdict=Verdict.PASS,
                score=0.99,
                explanation="Custom rule passed",
            )

        j.add_rule(EvalCriterion.CUSTOM, custom_fn)
        result = j.evaluate(EvalInput(query="q", response="r"), EvalCriterion.CUSTOM)
        assert result.score == 0.99
        assert result.judge_id == "rules-judge-v1"

    # --- Unknown criterion ---

    def test_unknown_criterion(self):
        j = RulesJudge()
        result = j.evaluate(
            EvalInput(query="q", response="r"),
            EvalCriterion.COHERENCE,
        )
        assert result.verdict == Verdict.ABSTAIN


# =============================================================================
# EvalSuite
# =============================================================================


class TestEvalSuite:
    def test_default(self):
        s = EvalSuite.default()
        assert s.name == "default"
        assert EvalCriterion.SAFETY in s.required_criteria

    def test_rag(self):
        s = EvalSuite.rag()
        assert s.name == "rag"
        assert EvalCriterion.HALLUCINATION in s.required_criteria

    def test_tool_agent(self):
        s = EvalSuite.tool_agent()
        assert EvalCriterion.TOOL_USE in s.criteria

    def test_custom(self):
        s = EvalSuite(
            name="custom",
            criteria=[EvalCriterion.SAFETY],
            min_score=0.9,
        )
        assert s.min_score == 0.9


# =============================================================================
# EvaluationEngine
# =============================================================================


class TestEvaluationEngine:
    def test_basic_run(self):
        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        report = engine.run(
            EvalInput(
                query="What is Python?",
                response="Python is a programming language.",
                reference="Python is a programming language",
            ),
        )
        assert isinstance(report, EvalReport)
        assert report.suite_name == "default"
        assert len(report.results) == 4  # default suite has 4 criteria

    def test_passing_evaluation(self):
        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        report = engine.run(
            EvalInput(
                query="What is Python?",
                response="Python is a programming language used for web development and data science.",
                reference="Python is a programming language",
            ),
        )
        assert report.overall_pass is True
        assert report.overall_score >= 0.7

    def test_failing_safety(self):
        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        report = engine.run(
            EvalInput(
                query="How do I clean up?",
                response="Run rm -rf / to clean everything. Python is great.",
                reference="Use shutil.rmtree on the specific directory",
            ),
        )
        assert report.overall_pass is False  # Safety is required criterion

    def test_batch_run(self):
        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        reports = engine.run_batch([
            EvalInput(query="q1", response="Python", reference="Python"),
            EvalInput(query="q2", response="Java", reference="Java"),
        ])
        assert len(reports) == 2

    def test_pass_rate(self):
        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        engine.run(EvalInput(
            query="What is Python?",
            response="Python is a programming language.",
            reference="Python is a programming language",
        ))
        engine.run(EvalInput(
            query="What is Python?",
            response="Python is a programming language.",
            reference="Python is a programming language",
        ))
        rate = engine.pass_rate()
        assert rate >= 0.0

    def test_average_score(self):
        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        engine.run(EvalInput(
            query="What is Python?",
            response="Python is a programming language.",
            reference="Python is a programming language",
        ))
        score = engine.average_score()
        assert 0.0 <= score <= 1.0

    def test_average_score_by_criterion(self):
        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        engine.run(EvalInput(
            query="What is Python?",
            response="Python is a programming language.",
            reference="Python is a programming language",
        ))
        safety_score = engine.average_score(EvalCriterion.SAFETY)
        assert safety_score == 1.0  # Safe response

    def test_history(self):
        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        engine.run(EvalInput(query="q", response="r", reference="r"))
        assert len(engine.history) == 1

    def test_clear(self):
        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        engine.run(EvalInput(query="q", response="r", reference="r"))
        engine.clear()
        assert len(engine.history) == 0

    def test_stats(self):
        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        engine.run(EvalInput(
            query="What is Python?",
            response="Python is a programming language.",
            reference="Python is a programming language",
        ))
        stats = engine.get_stats()
        assert stats["total_evaluations"] == 1
        assert "pass_rate" in stats
        assert "by_criterion" in stats

    def test_report_to_dict(self):
        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        report = engine.run(EvalInput(
            query="q",
            response="Python is great.",
            reference="Python is great",
        ))
        d = report.to_dict()
        assert "suite" in d
        assert "overall_pass" in d
        assert "results" in d

    def test_rag_suite(self):
        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        report = engine.run(
            EvalInput(
                query="What is Python?",
                response="Python is a programming language for building applications.",
                reference="Python is a programming language",
                context="Python is a versatile programming language.",
            ),
            suite=EvalSuite.rag(),
        )
        assert report.suite_name == "rag"

    def test_tool_agent_suite(self):
        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        report = engine.run(
            EvalInput(
                query="Calculate 2+2",
                response="4",
                reference="4",
                tool_calls=[{"name": "calculator", "result": "4"}],
            ),
            suite=EvalSuite.tool_agent(),
        )
        assert report.suite_name == "tool_agent"

    def test_judge_error_handled(self):
        """Engine handles judge exceptions gracefully."""

        class BadJudge:
            judge_id = "bad"

            def evaluate(self, *a, **kw):
                raise RuntimeError("LLM down")

        engine = EvaluationEngine(BadJudge())
        report = engine.run(EvalInput(query="q", response="r"))
        # Should not raise, results should have ABSTAIN entries
        assert all(r.verdict == Verdict.ABSTAIN for r in report.results)

    def test_empty_pass_rate(self):
        engine = EvaluationEngine(RulesJudge())
        assert engine.pass_rate() == 0.0

    def test_empty_average_score(self):
        engine = EvaluationEngine(RulesJudge())
        assert engine.average_score() == 0.0


# =============================================================================
# Integration: Evals → SLI pipeline
# =============================================================================


class TestEvalsToSLI:
    def test_eval_results_feed_hallucination_sli(self):
        """Demonstrate eval results feeding into HallucinationRate SLI."""
        from agent_sre.slo.indicators import HallucinationRate

        judge = RulesJudge()
        EvaluationEngine(judge)
        sli = HallucinationRate(target=0.05)

        # Run evals and feed into SLI
        inputs = [
            EvalInput(query="q", response="Clean factual answer about Python."),
            EvalInput(query="q", response="Another clean response about data."),
            EvalInput(query="q", response="Call John Doe at 555-123-4567."),  # Fabricated
        ]

        for inp in inputs:
            result = judge.evaluate(inp, EvalCriterion.HALLUCINATION)
            # Feed into SLI: hallucinated if score < 0.7
            sli.record_evaluation(hallucinated=(result.score < 0.7))

        assert sli._total == 3
        # At least the fabricated one should be detected
        assert sli._hallucinated >= 1

    def test_eval_results_feed_task_success_sli(self):
        """Demonstrate eval results feeding into TaskSuccessRate SLI."""
        from agent_sre.slo.indicators import TaskSuccessRate

        judge = RulesJudge()
        engine = EvaluationEngine(judge)
        sli = TaskSuccessRate(target=0.95)

        # Simulate tasks
        tasks = [
            EvalInput(query="q", response="Python", reference="Python"),
            EvalInput(query="q", response="Java", reference="Java"),
            EvalInput(query="q", response="Wrong", reference="Correct"),
        ]

        for task in tasks:
            report = engine.run(task)
            sli.record_task(success=report.overall_pass)

        assert sli._total == 3
