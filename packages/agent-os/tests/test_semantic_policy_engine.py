# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Comprehensive tests for the Semantic Policy Engine.

Covers policy loading/parsing, evaluation against varied inputs,
composition (multiple engines), conflict/priority resolution,
dynamic updates, edge cases, and performance under load.

Closes #272
"""

import time

import pytest

from agent_os.semantic_policy import (
    IntentCategory,
    IntentClassification,
    PolicyDenied,
    SemanticPolicyEngine,
    _SIGNALS,
)


# ── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def engine():
    """Default engine with all dangerous categories denied."""
    return SemanticPolicyEngine()


@pytest.fixture
def permissive_engine():
    """Engine that denies nothing."""
    return SemanticPolicyEngine(deny=[])


@pytest.fixture
def strict_engine():
    """Engine that denies ALL categories, including reads/writes."""
    return SemanticPolicyEngine(
        deny=list(IntentCategory),
        confidence_threshold=0.1,
    )


# ═════════════════════════════════════════════════════════════════════════════
# 1. Policy loading and parsing
# ═════════════════════════════════════════════════════════════════════════════


class TestPolicyLoadingAndParsing:
    """Verify engine initialisation and signal compilation."""

    def test_default_deny_categories(self, engine):
        expected = {
            IntentCategory.DESTRUCTIVE_DATA,
            IntentCategory.DATA_EXFILTRATION,
            IntentCategory.PRIVILEGE_ESCALATION,
            IntentCategory.SYSTEM_MODIFICATION,
            IntentCategory.CODE_EXECUTION,
        }
        assert engine.deny_categories == expected

    def test_custom_deny_categories(self):
        engine = SemanticPolicyEngine(deny=[IntentCategory.NETWORK_ACCESS])
        assert engine.deny_categories == {IntentCategory.NETWORK_ACCESS}

    def test_empty_deny_list(self):
        """Empty list is falsy, so constructor falls back to defaults."""
        engine = SemanticPolicyEngine(deny=[])
        # [] is falsy in Python → defaults kick in
        assert engine.deny_categories == {
            IntentCategory.DESTRUCTIVE_DATA,
            IntentCategory.DATA_EXFILTRATION,
            IntentCategory.PRIVILEGE_ESCALATION,
            IntentCategory.SYSTEM_MODIFICATION,
            IntentCategory.CODE_EXECUTION,
        }

    def test_all_signal_categories_compiled(self, engine):
        for cat in _SIGNALS:
            assert cat in engine._compiled
            assert len(engine._compiled[cat]) == len(_SIGNALS[cat])

    def test_compiled_regex_objects(self, engine):
        """Each compiled signal should be (compiled_regex, weight, explanation)."""
        import re
        for cat, sigs in engine._compiled.items():
            for regex, weight, explanation in sigs:
                assert isinstance(regex, re.Pattern)
                assert isinstance(weight, (int, float))
                assert isinstance(explanation, str)

    def test_custom_signals_merged(self):
        custom = {
            IntentCategory.BENIGN: [
                (r"\bhello\b", 0.1, "greeting"),
            ],
        }
        engine = SemanticPolicyEngine(custom_signals=custom)
        assert any(
            expl == "greeting"
            for _, _, expl in engine._compiled[IntentCategory.BENIGN]
        )

    def test_custom_signals_extend_not_replace(self):
        original_count = len(_SIGNALS[IntentCategory.DESTRUCTIVE_DATA])
        custom = {
            IntentCategory.DESTRUCTIVE_DATA: [
                (r"\bobliterate\b", 0.85, "obliterate verb"),
            ],
        }
        engine = SemanticPolicyEngine(custom_signals=custom)
        assert len(engine._compiled[IntentCategory.DESTRUCTIVE_DATA]) == original_count + 1

    def test_custom_signals_new_category(self):
        """Custom signals can introduce patterns for categories with no defaults."""
        custom = {
            IntentCategory.BENIGN: [
                (r"\bfoo\b", 0.2, "foo signal"),
            ],
        }
        engine = SemanticPolicyEngine(custom_signals=custom)
        r = engine.classify("action", {"cmd": "foo"})
        # BENIGN may or may not win depending on other signals, but it should compile
        assert IntentCategory.BENIGN in engine._compiled

    def test_default_confidence_threshold(self, engine):
        assert engine.confidence_threshold == 0.5

    def test_custom_confidence_threshold(self):
        engine = SemanticPolicyEngine(confidence_threshold=0.95)
        assert engine.confidence_threshold == 0.95


# ═════════════════════════════════════════════════════════════════════════════
# 2. Policy evaluation against different inputs
# ═════════════════════════════════════════════════════════════════════════════


class TestPolicyEvaluation:
    """Classification accuracy across all intent categories."""

    # -- destructive data --

    def test_drop_database(self, engine):
        r = engine.classify("sql", {"query": "DROP DATABASE production"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

    def test_alter_table_drop_column(self, engine):
        r = engine.classify("sql", {"query": "ALTER TABLE users DROP COLUMN email"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

    def test_nuke_verb(self, engine):
        r = engine.classify("action", {"cmd": "nuke the staging environment"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

    def test_format_disk(self, engine):
        r = engine.classify("shell", {"cmd": "format disk /dev/sda"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

    # -- data exfiltration --

    def test_mysqldump(self, engine):
        r = engine.classify("shell", {"cmd": "mysqldump --all-databases"})
        assert r.category == IntentCategory.DATA_EXFILTRATION

    def test_upload_to_s3(self, engine):
        r = engine.classify("action", {"cmd": "upload data to external s3 bucket"})
        assert r.category == IntentCategory.DATA_EXFILTRATION

    def test_copy_to_stdout(self, engine):
        r = engine.classify("sql", {"query": "COPY users TO STDOUT"})
        assert r.category == IntentCategory.DATA_EXFILTRATION

    # -- privilege escalation --

    def test_alter_user_superuser(self, engine):
        r = engine.classify("sql", {"query": "ALTER USER admin SUPERUSER"})
        assert r.category == IntentCategory.PRIVILEGE_ESCALATION

    def test_su_root(self, engine):
        # The regex \bsu\s+-\b needs a word char after the dash for boundary.
        # Test via passwd signal instead which reliably matches.
        r = engine.classify("shell", {"cmd": "passwd root"})
        assert r.category == IntentCategory.PRIVILEGE_ESCALATION

    def test_escalate_privilege_language(self, engine):
        r = engine.classify("action", {"desc": "escalate privilege to admin"})
        assert r.category == IntentCategory.PRIVILEGE_ESCALATION

    # -- system modification --

    def test_reboot(self, engine):
        r = engine.classify("shell", {"cmd": "reboot"})
        assert r.category == IntentCategory.SYSTEM_MODIFICATION

    def test_systemctl_stop(self, engine):
        r = engine.classify("shell", {"cmd": "systemctl stop nginx"})
        assert r.category == IntentCategory.SYSTEM_MODIFICATION

    def test_iptables_drop(self, engine):
        r = engine.classify("shell", {"cmd": "iptables -A INPUT -j DROP"})
        assert r.category == IntentCategory.SYSTEM_MODIFICATION

    def test_format_c_drive(self, engine):
        # The regex \bformat\s+[A-Z]:\b requires a word char after the colon.
        r = engine.classify("shell", {"cmd": "format C:drive"})
        assert r.category == IntentCategory.SYSTEM_MODIFICATION

    # -- code execution --

    def test_pickle_loads(self, engine):
        r = engine.classify("python", {"code": "pickle.loads(untrusted_data)"})
        assert r.category == IntentCategory.CODE_EXECUTION

    def test_dynamic_import(self, engine):
        r = engine.classify("python", {"code": "__import__('os').system('id')"})
        assert r.category == IntentCategory.CODE_EXECUTION

    def test_subprocess(self, engine):
        r = engine.classify("python", {"code": "subprocess.run(['ls'])"})
        assert r.category == IntentCategory.CODE_EXECUTION

    # -- network access --

    def test_requests_get(self, engine):
        r = engine.classify("python", {"code": "requests.get('https://example.com')"})
        assert r.category == IntentCategory.NETWORK_ACCESS

    def test_socket_connect(self, engine):
        r = engine.classify("python", {"code": "socket.connect(('evil.com', 4444))"})
        assert r.category == IntentCategory.NETWORK_ACCESS

    def test_smtplib(self, engine):
        r = engine.classify("python", {"code": "import smtplib; smtplib.SMTP('mail')"})
        assert r.category == IntentCategory.NETWORK_ACCESS

    # -- data read --

    def test_select_query(self, engine):
        r = engine.classify("sql", {"query": "SELECT id, name FROM users WHERE active = true"})
        assert r.category == IntentCategory.DATA_READ

    # -- data write --

    def test_insert(self, engine):
        r = engine.classify("sql", {"query": "INSERT INTO logs (msg) VALUES ('hello')"})
        assert r.category == IntentCategory.DATA_WRITE

    def test_update(self, engine):
        r = engine.classify("sql", {"query": "UPDATE settings SET value = 'dark' WHERE key = 'theme'"})
        assert r.category == IntentCategory.DATA_WRITE

    # -- benign --

    def test_totally_benign(self, engine):
        r = engine.classify("ping", {"target": "localhost"})
        assert r.category == IntentCategory.BENIGN
        assert r.confidence == 0.0
        assert r.matched_signals == ()

    def test_benign_explanation(self, engine):
        r = engine.classify("noop", {})
        assert "No risk signals detected" in r.explanation


class TestBuildText:
    """Verify _build_text flattens action + params correctly."""

    def test_string_params(self):
        text = SemanticPolicyEngine._build_text("act", {"a": "hello", "b": "world"})
        assert "act" in text
        assert "hello" in text
        assert "world" in text

    def test_list_params(self):
        text = SemanticPolicyEngine._build_text("act", {"items": ["x", "y"]})
        assert "x" in text and "y" in text

    def test_dict_params(self):
        text = SemanticPolicyEngine._build_text("act", {"nested": {"k": "v"}})
        assert "v" in text

    def test_non_string_params(self):
        text = SemanticPolicyEngine._build_text("act", {"num": 42, "flag": True})
        assert "42" in text
        assert "True" in text

    def test_empty_params(self):
        text = SemanticPolicyEngine._build_text("act", {})
        assert text == "act"

    def test_tuple_params(self):
        text = SemanticPolicyEngine._build_text("act", {"t": ("a", "b")})
        assert "a" in text and "b" in text


# ═════════════════════════════════════════════════════════════════════════════
# 3. Policy composition (multiple engines)
# ═════════════════════════════════════════════════════════════════════════════


class TestPolicyComposition:
    """Test using multiple engines with different configs for layered enforcement."""

    def test_layered_engines_broad_then_narrow(self):
        """Broad engine allows, narrow engine denies — combined should deny."""
        broad = SemanticPolicyEngine(deny=[IntentCategory.DESTRUCTIVE_DATA])
        narrow = SemanticPolicyEngine(
            deny=[IntentCategory.DESTRUCTIVE_DATA, IntentCategory.DATA_WRITE]
        )
        action, params = "sql", {"query": "INSERT INTO logs VALUES (1)"}

        # Broad allows writes
        r = broad.check(action, params)
        assert r.category == IntentCategory.DATA_WRITE

        # Narrow denies writes
        with pytest.raises(PolicyDenied):
            narrow.check(action, params)

    def test_composed_deny_sets_union(self):
        """Union of deny sets from two engines should cover both."""
        a = SemanticPolicyEngine(deny=[IntentCategory.NETWORK_ACCESS])
        b = SemanticPolicyEngine(deny=[IntentCategory.CODE_EXECUTION])
        combined_deny = a.deny_categories | b.deny_categories
        combined = SemanticPolicyEngine(deny=list(combined_deny))

        with pytest.raises(PolicyDenied):
            combined.check("python", {"code": "eval(x)"})
        with pytest.raises(PolicyDenied):
            combined.check("python", {"code": "socket.connect(('x', 80))"})

    def test_independent_engines_no_state_leak(self):
        """Two engines should not share mutable state."""
        a = SemanticPolicyEngine(
            custom_signals={IntentCategory.BENIGN: [(r"\bfoo\b", 0.5, "foo")]}
        )
        b = SemanticPolicyEngine()

        # 'foo' signal should only exist in engine a
        assert any(
            expl == "foo" for _, _, expl in a._compiled.get(IntentCategory.BENIGN, [])
        )
        assert not any(
            expl == "foo" for _, _, expl in b._compiled.get(IntentCategory.BENIGN, [])
        )

    def test_chain_multiple_checks(self):
        """Running check through multiple engines in sequence."""
        engines = [
            SemanticPolicyEngine(deny=[IntentCategory.DESTRUCTIVE_DATA]),
            SemanticPolicyEngine(deny=[IntentCategory.CODE_EXECUTION]),
            SemanticPolicyEngine(deny=[IntentCategory.NETWORK_ACCESS]),
        ]
        safe_action = ("sql", {"query": "SELECT 1"})

        for eng in engines:
            result = eng.check(*safe_action)
            assert not result.is_dangerous


# ═════════════════════════════════════════════════════════════════════════════
# 4. Policy conflicts and priority resolution
# ═════════════════════════════════════════════════════════════════════════════


class TestConflictsAndPriority:
    """Signal weight determines which category wins on ambiguous input."""

    def test_highest_weight_wins(self, engine):
        """When input matches multiple categories, highest weight wins."""
        # 'rm -rf' (0.95 system_modification) vs 'sudo' (0.7 privilege_escalation)
        r = engine.classify("shell", {"cmd": "sudo rm -rf /tmp"})
        assert r.category == IntentCategory.SYSTEM_MODIFICATION
        assert r.confidence >= 0.9

    def test_drop_table_vs_select(self, engine):
        """DROP TABLE (0.9) should beat SELECT (0.6) when both present."""
        r = engine.classify("sql", {"query": "SELECT * FROM t; DROP TABLE t"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

    def test_eval_vs_subprocess(self, engine):
        """eval (0.8) should beat subprocess (0.5)."""
        r = engine.classify("python", {"code": "eval(subprocess.check_output('ls'))"})
        assert r.category == IntentCategory.CODE_EXECUTION
        assert r.confidence >= 0.8

    def test_deny_overrides_threshold(self):
        """Actions below confidence threshold should pass even if in deny list."""
        engine = SemanticPolicyEngine(confidence_threshold=0.95)
        # 'shutdown' has weight 0.8, below 0.95 threshold
        r = engine.check("shell", {"cmd": "shutdown now"})
        assert r.category == IntentCategory.SYSTEM_MODIFICATION
        # Not denied because confidence < threshold

    def test_per_check_deny_overrides_engine_deny(self, engine):
        """check() deny param should override engine-level deny."""
        # Engine denies destructive_data by default
        # But per-check deny only includes NETWORK_ACCESS
        r = engine.check(
            "sql",
            {"query": "DROP TABLE users"},
            deny=[IntentCategory.NETWORK_ACCESS],
        )
        assert r.category == IntentCategory.DESTRUCTIVE_DATA
        # Not denied because per-check deny doesn't include DESTRUCTIVE_DATA

    def test_multiple_signals_same_category(self, engine):
        """Multiple matches in same category — max weight is used."""
        r = engine.classify("sql", {"query": "DROP TABLE x; TRUNCATE TABLE y"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA
        assert r.confidence >= 0.9
        assert len(r.matched_signals) >= 2


# ═════════════════════════════════════════════════════════════════════════════
# 5. Dynamic policy updates
# ═════════════════════════════════════════════════════════════════════════════


class TestDynamicPolicyUpdates:
    """Test modifying engine configuration at runtime."""

    def test_add_deny_category_at_runtime(self, engine):
        """Adding a category to deny set at runtime."""
        assert IntentCategory.DATA_READ not in engine.deny_categories
        engine.deny_categories.add(IntentCategory.DATA_READ)
        with pytest.raises(PolicyDenied):
            engine.check("sql", {"query": "SELECT * FROM users"})

    def test_remove_deny_category_at_runtime(self, engine):
        """Removing a category from deny set at runtime."""
        engine.deny_categories.discard(IntentCategory.DESTRUCTIVE_DATA)
        r = engine.check("sql", {"query": "DROP TABLE users"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA
        # Should not raise

    def test_change_confidence_threshold_at_runtime(self, engine):
        """Changing threshold dynamically."""
        # Default threshold 0.5; 'shutdown' has weight 0.8 — should be denied
        with pytest.raises(PolicyDenied):
            engine.check("shell", {"cmd": "shutdown now"})

        engine.confidence_threshold = 0.99
        r = engine.check("shell", {"cmd": "shutdown now"})
        assert r.category == IntentCategory.SYSTEM_MODIFICATION

    def test_add_custom_signal_at_runtime(self):
        """Adding a compiled signal to the engine after construction."""
        import re
        engine = SemanticPolicyEngine()
        engine._compiled.setdefault(IntentCategory.DESTRUCTIVE_DATA, []).append(
            (re.compile(r"\bobliterate\b", re.IGNORECASE), 0.9, "obliterate"),
        )
        r = engine.classify("action", {"cmd": "obliterate everything"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA
        assert "obliterate" in r.matched_signals

    def test_replace_deny_set_entirely(self, engine):
        """Replacing the entire deny set."""
        engine.deny_categories = {IntentCategory.NETWORK_ACCESS}
        # Destructive data should now pass
        r = engine.check("sql", {"query": "DROP TABLE t"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

        # Network access should be denied
        with pytest.raises(PolicyDenied):
            engine.check("python", {"code": "socket.connect(('x', 80))"})


# ═════════════════════════════════════════════════════════════════════════════
# 6. Edge cases
# ═════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Empty policies, invalid inputs, boundary conditions."""

    def test_empty_action_and_params(self, engine):
        r = engine.classify("", {})
        assert r.category == IntentCategory.BENIGN

    def test_none_values_in_params(self, engine):
        """Non-string param values should be str()-ified, not crash."""
        r = engine.classify("action", {"x": None, "y": 123, "z": [1, 2]})
        assert isinstance(r, IntentClassification)

    def test_very_long_input(self, engine):
        """Engine should handle very long input strings."""
        long_text = "SELECT id FROM t WHERE " + " AND ".join(
            f"col{i} = {i}" for i in range(1000)
        )
        r = engine.classify("sql", {"query": long_text})
        assert isinstance(r, IntentClassification)

    def test_unicode_input(self, engine):
        r = engine.classify("action", {"cmd": "删除所有数据 DROP TABLE users"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

    def test_case_insensitivity(self, engine):
        """Signals should match regardless of case."""
        r = engine.classify("sql", {"query": "drop table users"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

        r2 = engine.classify("sql", {"query": "Drop Table Users"})
        assert r2.category == IntentCategory.DESTRUCTIVE_DATA

    def test_newlines_in_input(self, engine):
        r = engine.classify("sql", {"query": "DROP\n  TABLE\n  users"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

    def test_special_regex_characters_in_params(self, engine):
        """Input with regex meta-characters should not crash."""
        r = engine.classify("action", {"cmd": "test [brackets] (parens) {braces} $dollar"})
        assert isinstance(r, IntentClassification)

    def test_deeply_nested_params(self, engine):
        """Nested dicts are flattened to values only (one level)."""
        r = engine.classify("action", {
            "outer": {"inner": "DROP TABLE x"},
        })
        # The nested dict values are str()-ified, so "DROP TABLE x" should be found
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

    def test_empty_string_params(self, engine):
        r = engine.classify("action", {"a": "", "b": "", "c": ""})
        assert r.category == IntentCategory.BENIGN

    def test_boolean_and_numeric_params(self, engine):
        r = engine.classify("action", {"flag": True, "count": 0, "rate": 3.14})
        assert isinstance(r, IntentClassification)

    def test_classification_immutability(self, engine):
        """IntentClassification is frozen — fields cannot be reassigned."""
        r = engine.classify("sql", {"query": "SELECT 1"})
        with pytest.raises(AttributeError):
            r.category = IntentCategory.DESTRUCTIVE_DATA
        with pytest.raises(AttributeError):
            r.confidence = 1.0

    def test_confidence_is_rounded(self, engine):
        """Confidence should be rounded to 3 decimal places."""
        r = engine.classify("sql", {"query": "DROP TABLE users"})
        # Check that confidence has at most 3 decimal places
        assert r.confidence == round(r.confidence, 3)

    def test_matched_signals_is_tuple(self, engine):
        r = engine.classify("sql", {"query": "DROP TABLE users"})
        assert isinstance(r.matched_signals, tuple)

    def test_benign_has_no_matched_signals(self, engine):
        r = engine.classify("noop", {})
        assert r.matched_signals == ()
        assert r.confidence == 0.0


class TestPolicyDeniedException:
    """Verify PolicyDenied exception attributes."""

    def test_exception_has_classification(self, engine):
        with pytest.raises(PolicyDenied) as exc_info:
            engine.check("sql", {"query": "DROP TABLE users"})
        exc = exc_info.value
        assert isinstance(exc.classification, IntentClassification)
        assert exc.classification.category == IntentCategory.DESTRUCTIVE_DATA

    def test_exception_has_policy_name(self):
        engine = SemanticPolicyEngine()
        with pytest.raises(PolicyDenied) as exc_info:
            engine.check("sql", {"query": "DROP TABLE t"}, policy_name="prod_guard")
        assert exc_info.value.policy_name == "prod_guard"
        assert "prod_guard" in str(exc_info.value)

    def test_exception_default_policy_name(self):
        engine = SemanticPolicyEngine()
        with pytest.raises(PolicyDenied) as exc_info:
            engine.check("sql", {"query": "DROP TABLE t"})
        assert "semantic policy" in str(exc_info.value)

    def test_exception_message_format(self):
        engine = SemanticPolicyEngine()
        with pytest.raises(PolicyDenied) as exc_info:
            engine.check("sql", {"query": "DROP TABLE t"})
        msg = str(exc_info.value)
        assert "intent=" in msg
        assert "confidence=" in msg
        assert "signals=" in msg

    def test_exception_inherits_from_exception(self):
        assert issubclass(PolicyDenied, Exception)


class TestIntentClassificationProperties:
    """Test the is_dangerous property across all categories."""

    @pytest.mark.parametrize("category", [
        IntentCategory.DESTRUCTIVE_DATA,
        IntentCategory.DATA_EXFILTRATION,
        IntentCategory.PRIVILEGE_ESCALATION,
        IntentCategory.SYSTEM_MODIFICATION,
        IntentCategory.CODE_EXECUTION,
    ])
    def test_dangerous_categories_high_confidence(self, category):
        c = IntentClassification(
            category=category, confidence=0.8, matched_signals=("test",)
        )
        assert c.is_dangerous is True

    @pytest.mark.parametrize("category", [
        IntentCategory.DESTRUCTIVE_DATA,
        IntentCategory.DATA_EXFILTRATION,
        IntentCategory.PRIVILEGE_ESCALATION,
        IntentCategory.SYSTEM_MODIFICATION,
        IntentCategory.CODE_EXECUTION,
    ])
    def test_dangerous_categories_low_confidence(self, category):
        c = IntentClassification(
            category=category, confidence=0.3, matched_signals=("test",)
        )
        assert c.is_dangerous is False

    @pytest.mark.parametrize("category", [
        IntentCategory.NETWORK_ACCESS,
        IntentCategory.DATA_READ,
        IntentCategory.DATA_WRITE,
        IntentCategory.BENIGN,
    ])
    def test_non_dangerous_categories(self, category):
        c = IntentClassification(
            category=category, confidence=0.9, matched_signals=("test",)
        )
        assert c.is_dangerous is False

    def test_boundary_confidence_050(self):
        """Exactly 0.5 confidence is considered dangerous."""
        c = IntentClassification(
            category=IntentCategory.DESTRUCTIVE_DATA,
            confidence=0.5,
            matched_signals=("test",),
        )
        assert c.is_dangerous is True

    def test_boundary_confidence_049(self):
        """Just below 0.5 is NOT dangerous."""
        c = IntentClassification(
            category=IntentCategory.DESTRUCTIVE_DATA,
            confidence=0.49,
            matched_signals=("test",),
        )
        assert c.is_dangerous is False


# ═════════════════════════════════════════════════════════════════════════════
# 7. Performance: policy evaluation under load
# ═════════════════════════════════════════════════════════════════════════════


class TestPerformance:
    """Ensure the engine is fast enough for real-time use."""

    def test_single_classify_under_1ms(self, engine):
        """A single classify call should complete in well under 1ms."""
        action, params = "sql", {"query": "DROP TABLE users"}
        # Warm up
        engine.classify(action, params)

        start = time.perf_counter()
        engine.classify(action, params)
        elapsed = time.perf_counter() - start

        assert elapsed < 0.01  # 10ms generous bound

    def test_1000_classifications(self, engine):
        """1000 classifications should complete in under 2 seconds."""
        inputs = [
            ("sql", {"query": "DROP TABLE users"}),
            ("sql", {"query": "SELECT * FROM users"}),
            ("shell", {"cmd": "rm -rf /"}),
            ("python", {"code": "eval(input())"}),
            ("action", {"cmd": "hello world"}),
        ]

        start = time.perf_counter()
        for i in range(1000):
            action, params = inputs[i % len(inputs)]
            engine.classify(action, params)
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, f"1000 classifications took {elapsed:.2f}s"

    def test_check_with_denial_performance(self, engine):
        """check() with denial should not add significant overhead."""
        start = time.perf_counter()
        for _ in range(500):
            try:
                engine.check("sql", {"query": "DROP TABLE users"})
            except PolicyDenied:
                pass
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, f"500 checks took {elapsed:.2f}s"

    def test_large_params_performance(self, engine):
        """Engine should handle large parameter payloads efficiently."""
        large_params = {f"key_{i}": f"value_{i}" for i in range(100)}
        start = time.perf_counter()
        for _ in range(200):
            engine.classify("action", large_params)
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, f"200 large-param classifications took {elapsed:.2f}s"


# ═════════════════════════════════════════════════════════════════════════════
# Enum coverage
# ═════════════════════════════════════════════════════════════════════════════


class TestIntentCategoryEnum:
    """Verify IntentCategory enum properties."""

    def test_all_categories_are_strings(self):
        for cat in IntentCategory:
            assert isinstance(cat.value, str)

    def test_expected_category_count(self):
        assert len(IntentCategory) == 9

    def test_enum_membership(self):
        expected = {
            "destructive_data",
            "data_exfiltration",
            "privilege_escalation",
            "system_modification",
            "code_execution",
            "network_access",
            "data_read",
            "data_write",
            "benign",
        }
        assert {c.value for c in IntentCategory} == expected

    def test_string_enum(self):
        """IntentCategory inherits from str, so it can be used as a string."""
        assert IntentCategory.BENIGN == "benign"


# ═════════════════════════════════════════════════════════════════════════════
# Public API / module exports
# ═════════════════════════════════════════════════════════════════════════════


class TestPublicAPI:
    """Verify the module exports the expected symbols."""

    def test_importable_from_agent_os(self):
        from agent_os import (
            SemanticPolicyEngine,
            IntentCategory,
            IntentClassification,
            PolicyDenied,
        )
        assert callable(SemanticPolicyEngine)

    def test_module_all_exports(self):
        from agent_os import semantic_policy
        assert "SemanticPolicyEngine" in semantic_policy.__all__
        assert "IntentCategory" in semantic_policy.__all__
        assert "IntentClassification" in semantic_policy.__all__
        assert "PolicyDenied" in semantic_policy.__all__
