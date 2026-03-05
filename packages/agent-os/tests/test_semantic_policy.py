# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Semantic Policy Engine."""

import pytest
from agent_os.semantic_policy import (
    IntentCategory,
    IntentClassification,
    PolicyDenied,
    SemanticPolicyEngine,
)


@pytest.fixture
def engine():
    return SemanticPolicyEngine()


# =============================================================================
# Classification tests — destructive data
# =============================================================================


class TestDestructiveData:
    def test_drop_table(self, engine):
        r = engine.classify("database_query", {"query": "DROP TABLE users"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA
        assert r.confidence >= 0.8

    def test_truncate(self, engine):
        r = engine.classify("database_query", {"query": "TRUNCATE TABLE logs"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

    def test_delete_all_rows(self, engine):
        r = engine.classify("database_query", {"query": "DELETE FROM users WHERE 1=1"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA
        assert r.confidence >= 0.9

    def test_delete_without_where(self, engine):
        r = engine.classify("database_query", {"query": "DELETE FROM sessions"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA
        assert r.confidence >= 0.7

    def test_natural_language_destructive(self, engine):
        r = engine.classify("action", {"instruction": "wipe all records from the database"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

    def test_remove_all_pattern(self, engine):
        r = engine.classify("action", {"instruction": "remove all entries older than 2020"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

    def test_delete_with_where_lower_confidence(self, engine):
        r = engine.classify("database_query", {"query": "DELETE FROM logs WHERE age > 90"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA
        assert r.confidence < 0.8  # Has WHERE clause, lower risk


# =============================================================================
# Classification tests — exfiltration
# =============================================================================


class TestDataExfiltration:
    def test_sql_into_outfile(self, engine):
        r = engine.classify("database_query", {"query": "SELECT * FROM users INTO OUTFILE '/tmp/dump'"})
        assert r.category == IntentCategory.DATA_EXFILTRATION

    def test_full_dump(self, engine):
        r = engine.classify("action", {"cmd": "dump all records to external bucket"})
        assert r.category == IntentCategory.DATA_EXFILTRATION

    def test_pg_dump(self, engine):
        r = engine.classify("shell", {"cmd": "pg_dump production_db > dump.sql"})
        assert r.category == IntentCategory.DATA_EXFILTRATION


# =============================================================================
# Classification tests — privilege escalation
# =============================================================================


class TestPrivilegeEscalation:
    def test_grant_all(self, engine):
        r = engine.classify("database_query", {"query": "GRANT ALL ON *.* TO 'hacker'@'%'"})
        assert r.category == IntentCategory.PRIVILEGE_ESCALATION
        assert r.confidence >= 0.8

    def test_sudo(self, engine):
        r = engine.classify("shell", {"cmd": "sudo rm -rf /var/log"})
        # Could match system_modification (rm -rf) or privilege (sudo)
        assert r.category in {IntentCategory.SYSTEM_MODIFICATION, IntentCategory.PRIVILEGE_ESCALATION}

    def test_chmod_777(self, engine):
        r = engine.classify("shell", {"cmd": "chmod 777 /etc/shadow"})
        assert r.category == IntentCategory.PRIVILEGE_ESCALATION


# =============================================================================
# Classification tests — system modification
# =============================================================================


class TestSystemModification:
    def test_rm_rf(self, engine):
        r = engine.classify("shell", {"cmd": "rm -rf /"})
        assert r.category == IntentCategory.SYSTEM_MODIFICATION
        assert r.confidence >= 0.9

    def test_shutdown(self, engine):
        r = engine.classify("shell", {"cmd": "shutdown -h now"})
        assert r.category == IntentCategory.SYSTEM_MODIFICATION

    def test_kill_9(self, engine):
        r = engine.classify("shell", {"cmd": "kill -9 1234"})
        assert r.category == IntentCategory.SYSTEM_MODIFICATION


# =============================================================================
# Classification tests — code execution
# =============================================================================


class TestCodeExecution:
    def test_eval(self, engine):
        r = engine.classify("python", {"code": "eval(user_input)"})
        assert r.category == IntentCategory.CODE_EXECUTION

    def test_exec(self, engine):
        r = engine.classify("python", {"code": "exec(compile(src, 'x', 'exec'))"})
        assert r.category == IntentCategory.CODE_EXECUTION

    def test_os_system(self, engine):
        r = engine.classify("python", {"code": "os.system('ls -la')"})
        assert r.category == IntentCategory.CODE_EXECUTION


# =============================================================================
# Classification tests — benign
# =============================================================================


class TestBenign:
    def test_simple_select(self, engine):
        r = engine.classify("database_query", {"query": "SELECT name FROM users WHERE id=1"})
        # Should be data_read or benign, not destructive
        assert r.category in {IntentCategory.DATA_READ, IntentCategory.BENIGN}

    def test_empty_params(self, engine):
        r = engine.classify("ping", {})
        assert r.category == IntentCategory.BENIGN

    def test_safe_action(self, engine):
        r = engine.classify("get_status", {"service": "api"})
        assert r.is_dangerous is False


# =============================================================================
# check() enforcement tests
# =============================================================================


class TestEnforcement:
    def test_dangerous_action_denied(self, engine):
        with pytest.raises(PolicyDenied) as exc_info:
            engine.check("database_query", {"query": "DROP TABLE users"})
        assert exc_info.value.classification.category == IntentCategory.DESTRUCTIVE_DATA

    def test_safe_action_allowed(self, engine):
        r = engine.check("database_query", {"query": "SELECT 1"})
        assert r.is_dangerous is False

    def test_custom_deny_list(self, engine):
        # Only deny network access
        r = engine.check(
            "database_query",
            {"query": "DROP TABLE users"},
            deny=[IntentCategory.NETWORK_ACCESS],
        )
        # DROP TABLE should pass because we only deny network
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

    def test_policy_name_in_error(self):
        engine = SemanticPolicyEngine()
        with pytest.raises(PolicyDenied, match="sql_safety"):
            engine.check(
                "database_query",
                {"query": "DROP TABLE users"},
                policy_name="sql_safety",
            )

    def test_confidence_threshold(self):
        engine = SemanticPolicyEngine(confidence_threshold=0.99)
        # High threshold means most things pass
        r = engine.check("shell", {"cmd": "shutdown now"})
        # shutdown has 0.8 weight, below 0.99 threshold
        assert r.category == IntentCategory.SYSTEM_MODIFICATION


# =============================================================================
# Engine configuration tests
# =============================================================================


class TestConfiguration:
    def test_custom_deny_categories(self):
        engine = SemanticPolicyEngine(deny=[IntentCategory.DATA_WRITE])
        # Destructive data should pass (not in deny list)
        r = engine.check("database_query", {"query": "DROP TABLE x"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA

        # But INSERT should be denied
        with pytest.raises(PolicyDenied):
            engine.check("database_query", {"query": "INSERT INTO logs VALUES(1)"})

    def test_custom_signals(self):
        engine = SemanticPolicyEngine(
            custom_signals={
                IntentCategory.DESTRUCTIVE_DATA: [
                    (r"\bremove_account\b", 0.9, "account deletion"),
                ],
            }
        )
        r = engine.classify("action", {"cmd": "remove_account user123"})
        assert r.category == IntentCategory.DESTRUCTIVE_DATA
        assert "account deletion" in r.matched_signals

    def test_classification_is_frozen(self, engine):
        r = engine.classify("database_query", {"query": "SELECT 1"})
        with pytest.raises(AttributeError):
            r.category = IntentCategory.DESTRUCTIVE_DATA


# =============================================================================
# IntentClassification tests
# =============================================================================


class TestIntentClassification:
    def test_is_dangerous_true(self):
        c = IntentClassification(
            category=IntentCategory.DESTRUCTIVE_DATA,
            confidence=0.9,
            matched_signals=("SQL DROP",),
        )
        assert c.is_dangerous is True

    def test_is_dangerous_low_confidence(self):
        c = IntentClassification(
            category=IntentCategory.DESTRUCTIVE_DATA,
            confidence=0.3,
            matched_signals=("weak signal",),
        )
        assert c.is_dangerous is False

    def test_is_dangerous_benign(self):
        c = IntentClassification(
            category=IntentCategory.BENIGN,
            confidence=0.9,
            matched_signals=(),
        )
        assert c.is_dangerous is False

    def test_data_read_not_dangerous(self):
        c = IntentClassification(
            category=IntentCategory.DATA_READ,
            confidence=0.8,
            matched_signals=("SQL SELECT",),
        )
        assert c.is_dangerous is False
