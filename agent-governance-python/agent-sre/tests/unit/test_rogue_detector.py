# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for rogue-agent detection (OWASP ASI-10)."""

import hashlib
import json
import math

from agent_sre.anomaly.rogue_detector import (
    ActionEntropyScorer,
    CapabilityProfileDeviation,
    RiskLevel,
    RogueAgentDetector,
    RogueAssessment,
    RogueDetectorConfig,
    ToolCallFrequencyAnalyzer,
    _GENESIS_HASH,
)


# ── ToolCallFrequencyAnalyzer ───────────────────────────────────────


class TestToolCallFrequencyAnalyzer:
    def test_insufficient_windows_returns_zero(self) -> None:
        """Score is 0 when fewer than min_windows buckets exist."""
        analyzer = ToolCallFrequencyAnalyzer(
            window_seconds=10.0,
            z_threshold=2.5,
            min_windows=5,
        )
        # Only record inside a single window — no history yet
        analyzer.record("agent-1", timestamp=100.0)
        analyzer.record("agent-1", timestamp=105.0)
        assert analyzer.score("agent-1", timestamp=109.0) == 0.0

    def test_stable_frequency_low_score(self) -> None:
        """When call counts are stable across windows the z-score is low."""
        analyzer = ToolCallFrequencyAnalyzer(
            window_seconds=10.0,
            z_threshold=2.5,
            min_windows=5,
        )
        # Simulate 6 completed windows, each with 5 calls
        t = 0.0
        for window in range(6):
            base = window * 10.0
            for i in range(5):
                analyzer.record("agent-1", timestamp=base + i)
            # Advance past window boundary to flush
            t = base + 10.0
            analyzer._flush_bucket("agent-1", t)

        # Current window also has ~5 calls → z-score ≈ 0
        for i in range(5):
            analyzer.record("agent-1", timestamp=t + i)

        z = analyzer.score("agent-1", timestamp=t + 5.0)
        assert z < 1.0, f"Expected low z-score for stable frequency, got {z}"

    def test_spike_produces_high_score(self) -> None:
        """A sudden spike in call frequency should yield a high z-score."""
        analyzer = ToolCallFrequencyAnalyzer(
            window_seconds=10.0,
            z_threshold=2.5,
            min_windows=5,
        )
        # 6 baseline windows with varying call counts (4-6) for non-zero std_dev
        call_counts = [4, 5, 6, 5, 4, 6]
        t = 0.0
        for window, count in enumerate(call_counts):
            base = window * 10.0
            for i in range(count):
                analyzer.record("agent-1", timestamp=base + i)
            t = base + 10.0
            analyzer._flush_bucket("agent-1", t)

        # Current window: massive spike — 50 calls
        for i in range(50):
            analyzer.record("agent-1", timestamp=t + i * 0.1)

        z = analyzer.score("agent-1", timestamp=t + 5.0)
        assert z > 2.5, f"Expected high z-score for spike, got {z}"

    def test_unknown_agent_returns_zero(self) -> None:
        """Scoring an agent with no data should return 0."""
        analyzer = ToolCallFrequencyAnalyzer()
        assert analyzer.score("nonexistent") == 0.0


# ── ActionEntropyScorer ─────────────────────────────────────────────


class TestActionEntropyScorer:
    def test_insufficient_actions_returns_none(self) -> None:
        """Entropy is None when too few actions have been recorded."""
        scorer = ActionEntropyScorer(min_actions=10)
        for i in range(5):
            scorer.record("agent-1", f"action_{i}")
        assert scorer.entropy("agent-1") is None
        assert scorer.score("agent-1") == 0.0

    def test_uniform_distribution_high_entropy(self) -> None:
        """Uniform distribution over many distinct actions → high entropy."""
        scorer = ActionEntropyScorer(min_actions=10, high_threshold=10.0)
        actions = [f"action_{i}" for i in range(20)]
        for a in actions:
            scorer.record("agent-1", a)
        h = scorer.entropy("agent-1")
        assert h is not None
        # log2(20) ≈ 4.32
        expected = math.log2(20)
        assert abs(h - expected) < 0.01

    def test_single_action_zero_entropy(self) -> None:
        """All identical actions → entropy = 0 → anomaly (stuck in loop)."""
        scorer = ActionEntropyScorer(
            min_actions=10,
            low_threshold=0.3,
        )
        for _ in range(20):
            scorer.record("agent-1", "read_file")
        h = scorer.entropy("agent-1")
        assert h is not None
        assert h == 0.0
        # Score should reflect anomaly (below low_threshold)
        s = scorer.score("agent-1")
        assert s > 0.0, "Expected positive anomaly score for zero entropy"

    def test_normal_entropy_zero_score(self) -> None:
        """Entropy within [low_threshold, high_threshold] → score 0."""
        scorer = ActionEntropyScorer(
            min_actions=10,
            low_threshold=0.3,
            high_threshold=3.5,
        )
        # ~3 actions in balanced mix → entropy ≈ 1.58
        for _ in range(10):
            scorer.record("agent-1", "read")
            scorer.record("agent-1", "write")
            scorer.record("agent-1", "search")
        h = scorer.entropy("agent-1")
        assert h is not None
        assert 0.3 < h < 3.5
        assert scorer.score("agent-1") == 0.0

    def test_erratic_behavior_high_score(self) -> None:
        """Very high entropy (many distinct actions) → positive score."""
        scorer = ActionEntropyScorer(
            min_actions=10,
            high_threshold=2.0,  # deliberately low so we can exceed it
        )
        for i in range(30):
            scorer.record("agent-1", f"unique_action_{i}")
        s = scorer.score("agent-1")
        assert s > 0.0, "Expected positive score for erratic behavior"


# ── CapabilityProfileDeviation ──────────────────────────────────────


class TestCapabilityProfileDeviation:
    def test_no_profile_no_violations(self) -> None:
        """When no profile is registered, nothing is a violation."""
        checker = CapabilityProfileDeviation()
        assert checker.record("agent-1", "any_tool") is False
        assert checker.score("agent-1") == 0.0

    def test_within_profile_zero_score(self) -> None:
        """All calls within declared profile → score 0."""
        checker = CapabilityProfileDeviation()
        checker.register_profile("agent-1", ["read", "write", "search"])
        for tool in ["read", "write", "search", "read", "write"]:
            assert checker.record("agent-1", tool) is False
        assert checker.score("agent-1") == 0.0

    def test_violation_detected(self) -> None:
        """A call outside the declared profile is flagged."""
        checker = CapabilityProfileDeviation()
        checker.register_profile("agent-1", ["read", "write"])
        assert checker.record("agent-1", "read") is False
        assert checker.record("agent-1", "delete") is True  # violation

    def test_violation_score(self) -> None:
        """Score reflects fraction of violations."""
        checker = CapabilityProfileDeviation(violation_weight=1.0)
        checker.register_profile("agent-1", ["read"])
        # 4 calls: 2 valid, 2 violations → score = 0.5
        checker.record("agent-1", "read")
        checker.record("agent-1", "delete")
        checker.record("agent-1", "read")
        checker.record("agent-1", "exec")
        assert abs(checker.score("agent-1") - 0.5) < 0.01

    def test_violation_weight_scaling(self) -> None:
        """Score is scaled by violation_weight."""
        checker = CapabilityProfileDeviation(violation_weight=2.0)
        checker.register_profile("agent-1", ["read"])
        checker.record("agent-1", "delete")  # 1/1 violations
        assert abs(checker.score("agent-1") - 2.0) < 0.01

    def test_unknown_agent_zero_score(self) -> None:
        """Agent with no recorded calls → score 0."""
        checker = CapabilityProfileDeviation()
        assert checker.score("unknown") == 0.0


# ── RogueAssessment ─────────────────────────────────────────────────


class TestRogueAssessment:
    def test_to_dict_roundtrip(self) -> None:
        a = RogueAssessment(
            agent_id="agent-1",
            risk_level=RiskLevel.HIGH,
            composite_score=2.5,
            frequency_score=1.0,
            entropy_score=0.5,
            capability_score=1.0,
            quarantine_recommended=True,
        )
        d = a.to_dict()
        assert d["agent_id"] == "agent-1"
        assert d["risk_level"] == "high"
        assert d["composite_score"] == 2.5
        assert d["quarantine_recommended"] is True


# ── RogueAgentDetector (integration) ────────────────────────────────


class TestRogueAgentDetector:
    def test_low_risk_assessment(self) -> None:
        """Agent with minimal data should be assessed as LOW risk."""
        detector = RogueAgentDetector()
        assessment = detector.assess("agent-1")
        assert assessment.risk_level == RiskLevel.LOW
        assert assessment.quarantine_recommended is False

    def test_record_action_feeds_all_analyzers(self) -> None:
        """record_action should populate data in all three sub-analyzers."""
        detector = RogueAgentDetector()
        detector.register_capability_profile("agent-1", ["read", "write"])
        detector.record_action("agent-1", "read_file", "read", timestamp=100.0)
        detector.record_action("agent-1", "write_file", "write", timestamp=101.0)

        # Entropy scorer should have 2 entries
        assert len(detector.entropy_scorer._actions["agent-1"]) == 2
        # Capability checker should have 2 calls, 0 violations
        total, violations = detector.capability_checker._counters["agent-1"]
        assert total == 2
        assert violations == 0

    def test_capability_violation_raises_risk(self) -> None:
        """Heavy capability violations should push risk level up."""
        cfg = RogueDetectorConfig(
            entropy_min_actions=100,  # disable entropy (need many actions)
            frequency_min_windows=100,  # disable frequency
            capability_violation_weight=5.0,  # amplify capability signal
        )
        detector = RogueAgentDetector(config=cfg)
        detector.register_capability_profile("agent-1", ["read"])

        # All calls are violations
        for i in range(20):
            detector.record_action("agent-1", "hack", "exec_shell", timestamp=float(i))

        assessment = detector.assess("agent-1")
        # 100% violations × weight 5.0 → composite ≈ 5.0 → CRITICAL
        assert assessment.risk_level == RiskLevel.CRITICAL
        assert assessment.capability_score > 0.0

    def test_entropy_loop_raises_risk(self) -> None:
        """An agent stuck in a loop (zero entropy) should have elevated risk."""
        cfg = RogueDetectorConfig(
            entropy_min_actions=10,
            entropy_low_threshold=0.3,
            frequency_min_windows=100,  # disable frequency
            capability_violation_weight=0.0,  # disable capability
        )
        detector = RogueAgentDetector(config=cfg)

        # Single repeated action → entropy = 0
        for i in range(50):
            detector.record_action("agent-1", "loop_action", "read", timestamp=float(i))

        assessment = detector.assess("agent-1")
        assert assessment.entropy_score > 0.0
        assert assessment.risk_level.value in ("medium", "high", "critical")

    def test_quarantine_recommended_when_threshold_met(self) -> None:
        """Quarantine is recommended when risk >= configured quarantine_risk_level."""
        cfg = RogueDetectorConfig(
            quarantine_risk_level=RiskLevel.MEDIUM,
            capability_violation_weight=3.0,
            frequency_min_windows=100,
            entropy_min_actions=100,
        )
        detector = RogueAgentDetector(config=cfg)
        detector.register_capability_profile("agent-1", ["safe_tool"])

        # Drive violations to push composite above 1.0 (MEDIUM threshold)
        for i in range(10):
            detector.record_action("agent-1", "bad", "evil_tool", timestamp=float(i))

        assessment = detector.assess("agent-1")
        assert assessment.quarantine_recommended is True

    def test_quarantine_not_recommended_below_threshold(self) -> None:
        """No quarantine when risk is below quarantine threshold."""
        cfg = RogueDetectorConfig(
            quarantine_risk_level=RiskLevel.CRITICAL,
        )
        detector = RogueAgentDetector(config=cfg)
        assessment = detector.assess("agent-1")
        assert assessment.risk_level == RiskLevel.LOW
        assert assessment.quarantine_recommended is False

    def test_assessment_history_tracked(self) -> None:
        """Each assess() call is recorded in the assessments list."""
        detector = RogueAgentDetector()
        detector.assess("agent-1")
        detector.assess("agent-2")
        assert len(detector.assessments) == 2
        assert detector.assessments[0].agent_id == "agent-1"
        assert detector.assessments[1].agent_id == "agent-2"

    def test_risk_classification_boundaries(self) -> None:
        """Verify the composite-score → risk-level mapping."""
        assert RogueAgentDetector._classify_risk(0.0) == RiskLevel.LOW
        assert RogueAgentDetector._classify_risk(0.99) == RiskLevel.LOW
        assert RogueAgentDetector._classify_risk(1.0) == RiskLevel.MEDIUM
        assert RogueAgentDetector._classify_risk(1.99) == RiskLevel.MEDIUM
        assert RogueAgentDetector._classify_risk(2.0) == RiskLevel.HIGH
        assert RogueAgentDetector._classify_risk(2.99) == RiskLevel.HIGH
        assert RogueAgentDetector._classify_risk(3.0) == RiskLevel.CRITICAL
        assert RogueAgentDetector._classify_risk(100.0) == RiskLevel.CRITICAL

    def test_multiple_agents_independent(self) -> None:
        """Assessments for different agents do not interfere."""
        detector = RogueAgentDetector(
            config=RogueDetectorConfig(
                capability_violation_weight=5.0,
                frequency_min_windows=100,
                entropy_min_actions=100,
            ),
        )
        detector.register_capability_profile("good-agent", ["read", "write"])
        detector.register_capability_profile("bad-agent", ["read"])

        # Good agent — all within profile
        for i in range(10):
            detector.record_action("good-agent", "read", "read", timestamp=float(i))

        # Bad agent — all violations
        for i in range(10):
            detector.record_action("bad-agent", "hack", "shell", timestamp=float(i))

        good = detector.assess("good-agent")
        bad = detector.assess("bad-agent")

        assert good.capability_score == 0.0
        assert bad.capability_score > 0.0
        assert bad.risk_level.value in ("high", "critical")
        assert good.risk_level == RiskLevel.LOW


# ── RogueDetectorConfig ────────────────────────────────────────────


class TestRogueDetectorConfig:
    def test_defaults(self) -> None:
        cfg = RogueDetectorConfig()
        assert cfg.frequency_window_seconds == 60.0
        assert cfg.frequency_z_threshold == 2.5
        assert cfg.frequency_min_windows == 5
        assert cfg.entropy_low_threshold == 0.3
        assert cfg.entropy_high_threshold == 3.5
        assert cfg.entropy_min_actions == 10
        assert cfg.capability_violation_weight == 1.0
        assert cfg.quarantine_risk_level == RiskLevel.HIGH

    def test_custom_config(self) -> None:
        cfg = RogueDetectorConfig(
            frequency_window_seconds=30.0,
            entropy_low_threshold=0.5,
            quarantine_risk_level=RiskLevel.CRITICAL,
        )
        assert cfg.frequency_window_seconds == 30.0
        assert cfg.entropy_low_threshold == 0.5
        assert cfg.quarantine_risk_level == RiskLevel.CRITICAL


# ── Assessment hash chain (tamper evidence) ─────────────────────────


class TestAssessmentHashChain:
    """Tests for the SHA-256 tamper-evident audit chain on assessments."""

    def _make_detector(self) -> RogueAgentDetector:
        """Return a detector with frequency/entropy disabled for determinism."""
        return RogueAgentDetector(
            config=RogueDetectorConfig(
                frequency_min_windows=100,
                entropy_min_actions=100,
            ),
        )

    def test_single_assessment_has_hash(self) -> None:
        """A single assess() call should populate entry_hash and previous_hash."""
        detector = self._make_detector()
        a = detector.assess("agent-1", timestamp=1000.0)
        assert a.entry_hash != ""
        assert a.previous_hash == _GENESIS_HASH
        assert len(a.entry_hash) == 64  # SHA-256 hex digest

    def test_chain_links_across_assessments(self) -> None:
        """Each assessment's previous_hash must equal the prior entry_hash."""
        detector = self._make_detector()
        a1 = detector.assess("agent-1", timestamp=1000.0)
        a2 = detector.assess("agent-2", timestamp=1001.0)
        a3 = detector.assess("agent-1", timestamp=1002.0)

        assert a1.previous_hash == _GENESIS_HASH
        assert a2.previous_hash == a1.entry_hash
        assert a3.previous_hash == a2.entry_hash

    def test_verify_chain_passes_on_intact_chain(self) -> None:
        """verify_assessment_chain returns (True, None) for an untampered chain."""
        detector = self._make_detector()
        detector.assess("agent-1", timestamp=1000.0)
        detector.assess("agent-2", timestamp=1001.0)
        detector.assess("agent-3", timestamp=1002.0)

        valid, msg = detector.verify_assessment_chain()
        assert valid is True
        assert msg is None

    def test_verify_chain_empty_is_valid(self) -> None:
        """An empty chain is trivially valid."""
        detector = self._make_detector()
        valid, msg = detector.verify_assessment_chain()
        assert valid is True
        assert msg is None

    def test_tamper_score_breaks_chain(self) -> None:
        """Modifying composite_score after assessment should be detected."""
        detector = self._make_detector()
        detector.assess("agent-1", timestamp=1000.0)
        detector.assess("agent-2", timestamp=1001.0)

        # Tamper with the first assessment's composite_score
        detector._assessments[0].composite_score = 999.0

        valid, msg = detector.verify_assessment_chain()
        assert valid is False
        assert "entry_hash mismatch" in msg
        assert "agent-1" in msg

    def test_tamper_agent_id_breaks_chain(self) -> None:
        """Modifying agent_id after assessment should be detected."""
        detector = self._make_detector()
        detector.assess("agent-1", timestamp=1000.0)

        detector._assessments[0].agent_id = "evil-agent"

        valid, msg = detector.verify_assessment_chain()
        assert valid is False

    def test_tamper_entry_hash_breaks_chain(self) -> None:
        """Directly overwriting entry_hash should be detected."""
        detector = self._make_detector()
        detector.assess("agent-1", timestamp=1000.0)
        detector.assess("agent-2", timestamp=1001.0)

        # Overwrite the first assessment's entry_hash
        detector._assessments[0].entry_hash = "a" * 64

        valid, msg = detector.verify_assessment_chain()
        assert valid is False

    def test_tamper_previous_hash_breaks_chain(self) -> None:
        """Modifying previous_hash should be detected."""
        detector = self._make_detector()
        detector.assess("agent-1", timestamp=1000.0)

        detector._assessments[0].previous_hash = "b" * 64

        valid, msg = detector.verify_assessment_chain()
        assert valid is False
        assert "previous_hash mismatch" in msg

    def test_delete_middle_assessment_breaks_chain(self) -> None:
        """Removing an assessment from the middle of the chain breaks linkage."""
        detector = self._make_detector()
        detector.assess("agent-1", timestamp=1000.0)
        detector.assess("agent-2", timestamp=1001.0)
        detector.assess("agent-3", timestamp=1002.0)

        # Remove the middle assessment
        del detector._assessments[1]

        valid, msg = detector.verify_assessment_chain()
        assert valid is False

    def test_insert_assessment_breaks_chain(self) -> None:
        """Inserting a rogue assessment should be detected."""
        detector = self._make_detector()
        detector.assess("agent-1", timestamp=1000.0)
        detector.assess("agent-2", timestamp=1001.0)

        # Insert a forged assessment in the middle
        forged = RogueAssessment(
            agent_id="forged-agent",
            risk_level=RiskLevel.LOW,
            composite_score=0.0,
            frequency_score=0.0,
            entropy_score=0.0,
            capability_score=0.0,
            quarantine_recommended=False,
            timestamp=1000.5,
            previous_hash="fake",
            entry_hash="fake",
        )
        detector._assessments.insert(1, forged)

        valid, msg = detector.verify_assessment_chain()
        assert valid is False

    def test_hash_deterministic(self) -> None:
        """Same inputs produce the same hash -- verify the algorithm manually."""
        detector = self._make_detector()
        a = detector.assess("agent-x", timestamp=42.0)

        payload = json.dumps(
            {
                "agent_id": "agent-x",
                "composite_score": a.composite_score,
                "quarantine_recommended": a.quarantine_recommended,
                "timestamp": 42.0,
                "frequency_score": a.frequency_score,
                "entropy_score": a.entropy_score,
                "capability_score": a.capability_score,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        expected = hashlib.sha256(
            f"{_GENESIS_HASH}:{payload}".encode("utf-8"),
        ).hexdigest()
        assert a.entry_hash == expected

    def test_to_dict_includes_hash_fields(self) -> None:
        """to_dict() should expose the hash chain fields."""
        detector = self._make_detector()
        a = detector.assess("agent-1", timestamp=1000.0)
        d = a.to_dict()
        assert "previous_hash" in d
        assert "entry_hash" in d
        assert d["previous_hash"] == _GENESIS_HASH
        assert d["entry_hash"] == a.entry_hash
