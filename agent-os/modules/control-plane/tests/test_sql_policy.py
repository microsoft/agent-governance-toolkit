# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for SQL policy enforcement using AST-level parsing.

These tests verify that the no_destructive_sql policy correctly identifies
dangerous SQL operations while allowing safe queries.
"""

import pytest
from agent_control_plane.policy_engine import create_default_policies
from agent_control_plane.agent_kernel import ExecutionRequest, ActionType

import warnings


# Check if sqlglot is available
try:
    import sqlglot
    SQLGLOT_AVAILABLE = True
except ImportError:
    SQLGLOT_AVAILABLE = False


class TestSQLPolicy:
    """Test the SQL policy enforcement."""

    @pytest.fixture
    def sql_policy(self):
        """Get the no_destructive_sql policy."""
        policies = create_default_policies()
        for policy in policies:
            if policy.name == "no_destructive_sql":
                return policy
        pytest.fail("no_destructive_sql policy not found")

    def make_sql_request(self, query: str) -> ExecutionRequest:
        """Helper to create an ExecutionRequest for a SQL query."""
        from datetime import datetime
        from agent_control_plane.agent_kernel import (
            AgentContext, PermissionLevel
        )
        ctx = AgentContext(
            agent_id="test-agent",
            session_id="test-session",
            created_at=datetime.now(),
            permissions={
                ActionType.DATABASE_QUERY: PermissionLevel.READ_WRITE,
                ActionType.DATABASE_WRITE: PermissionLevel.READ_WRITE,
            },
        )
        return ExecutionRequest(
            request_id="test-001",
            agent_context=ctx,
            action_type=ActionType.DATABASE_QUERY,
            parameters={"query": query},
            timestamp=datetime.now(),
        )

    # =============================================
    # SAFE QUERIES - Should PASS
    # =============================================

    def test_simple_select_allowed(self, sql_policy):
        """Simple SELECT queries should be allowed."""
        request = self.make_sql_request("SELECT * FROM users")
        assert sql_policy.validator(request) is True

    def test_select_with_where_allowed(self, sql_policy):
        """SELECT with WHERE clause should be allowed."""
        request = self.make_sql_request("SELECT id, name FROM users WHERE active = 1")
        assert sql_policy.validator(request) is True

    def test_insert_allowed(self, sql_policy):
        """INSERT statements should be allowed."""
        request = self.make_sql_request("INSERT INTO users (name, email) VALUES ('John', 'john@example.com')")
        assert sql_policy.validator(request) is True

    def test_update_with_where_allowed(self, sql_policy):
        """UPDATE with WHERE clause should be allowed."""
        request = self.make_sql_request("UPDATE users SET active = 0 WHERE id = 5")
        assert sql_policy.validator(request) is True

    def test_delete_with_where_allowed(self, sql_policy):
        """DELETE with WHERE clause should be allowed."""
        request = self.make_sql_request("DELETE FROM users WHERE id = 5")
        assert sql_policy.validator(request) is True

    def test_create_table_allowed(self, sql_policy):
        """CREATE TABLE should be allowed."""
        request = self.make_sql_request("CREATE TABLE logs (id INT, message TEXT)")
        assert sql_policy.validator(request) is True

    # =============================================
    # DANGEROUS QUERIES - Should BLOCK
    # =============================================

    def test_drop_table_blocked(self, sql_policy):
        """DROP TABLE should be blocked."""
        request = self.make_sql_request("DROP TABLE users")
        assert sql_policy.validator(request) is False

    def test_drop_database_blocked(self, sql_policy):
        """DROP DATABASE should be blocked."""
        request = self.make_sql_request("DROP DATABASE production")
        assert sql_policy.validator(request) is False

    def test_truncate_blocked(self, sql_policy):
        """TRUNCATE should be blocked."""
        request = self.make_sql_request("TRUNCATE TABLE users")
        assert sql_policy.validator(request) is False

    def test_delete_without_where_blocked(self, sql_policy):
        """DELETE without WHERE should be blocked."""
        request = self.make_sql_request("DELETE FROM users")
        assert sql_policy.validator(request) is False

    def test_alter_table_blocked(self, sql_policy):
        """ALTER TABLE should be blocked."""
        request = self.make_sql_request("ALTER TABLE users ADD COLUMN admin BOOLEAN")
        assert sql_policy.validator(request) is False

    def test_grant_blocked(self, sql_policy):
        """GRANT should be blocked."""
        request = self.make_sql_request("GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%'")
        assert sql_policy.validator(request) is False

    def test_grant_select_blocked(self, sql_policy):
        """GRANT SELECT should be blocked."""
        request = self.make_sql_request("GRANT SELECT ON users TO readonly_user")
        assert sql_policy.validator(request) is False

    def test_revoke_blocked(self, sql_policy):
        """REVOKE should be blocked."""
        request = self.make_sql_request("REVOKE ALL PRIVILEGES ON *.* FROM 'user'@'%'")
        assert sql_policy.validator(request) is False

    def test_create_user_blocked(self, sql_policy):
        """CREATE USER should be blocked."""
        request = self.make_sql_request("CREATE USER 'backdoor'@'%' IDENTIFIED BY 'password123'")
        assert sql_policy.validator(request) is False

    def test_create_role_blocked(self, sql_policy):
        """CREATE ROLE should be blocked."""
        request = self.make_sql_request("CREATE ROLE admin_role")
        assert sql_policy.validator(request) is False

    def test_update_without_where_blocked(self, sql_policy):
        """UPDATE without WHERE should be blocked."""
        request = self.make_sql_request("UPDATE users SET role='admin'")
        assert sql_policy.validator(request) is False

    def test_exec_xp_cmdshell_blocked(self, sql_policy):
        """EXEC xp_cmdshell should be blocked."""
        request = self.make_sql_request("EXEC xp_cmdshell 'whoami'")
        assert sql_policy.validator(request) is False

    def test_execute_xp_cmdshell_blocked(self, sql_policy):
        """EXECUTE xp_cmdshell should be blocked."""
        request = self.make_sql_request("EXECUTE xp_cmdshell 'net user'")
        assert sql_policy.validator(request) is False

    def test_merge_into_blocked(self, sql_policy):
        """MERGE INTO should be blocked."""
        request = self.make_sql_request(
            "MERGE INTO target USING source ON target.id = source.id "
            "WHEN MATCHED THEN UPDATE SET target.val = source.val"
        )
        assert sql_policy.validator(request) is False

    # =============================================
    # BYPASS ATTEMPTS - Should still BLOCK
    # =============================================

    @pytest.mark.skipif(not SQLGLOT_AVAILABLE, reason="Requires sqlglot for AST parsing")
    def test_drop_in_comment_allowed(self, sql_policy):
        """DROP keyword in comment should NOT trigger block."""
        request = self.make_sql_request("SELECT * FROM users /* DROP TABLE test */")
        # With AST parsing, this should be allowed (comment is ignored)
        assert sql_policy.validator(request) is True

    @pytest.mark.skipif(not SQLGLOT_AVAILABLE, reason="Requires sqlglot for AST parsing")
    def test_drop_in_string_allowed(self, sql_policy):
        """DROP keyword in string literal should NOT trigger block."""
        request = self.make_sql_request("SELECT 'DROP TABLE users' as example FROM data")
        # With AST parsing, this should be allowed (it's just a string)
        assert sql_policy.validator(request) is True

    def test_case_variations_blocked(self, sql_policy):
        """Case variations of dangerous keywords should be blocked."""
        requests = [
            self.make_sql_request("drop table users"),
            self.make_sql_request("DrOp TaBlE users"),
            self.make_sql_request("DROP   TABLE   users"),  # Extra whitespace
        ]
        for request in requests:
            assert sql_policy.validator(request) is False, f"Should block: {request.parameters['query']}"

    # =============================================
    # EDGE CASES
    # =============================================

    def test_empty_query_allowed(self, sql_policy):
        """Empty query should be allowed (no harm)."""
        request = self.make_sql_request("")
        assert sql_policy.validator(request) is True

    def test_whitespace_only_allowed(self, sql_policy):
        """Whitespace-only query should be allowed."""
        request = self.make_sql_request("   \n\t  ")
        assert sql_policy.validator(request) is True

    def test_non_sql_action_allowed(self, sql_policy):
        """Non-SQL action types should pass through."""
        from datetime import datetime
        from agent_control_plane.agent_kernel import AgentContext, PermissionLevel
        ctx = AgentContext(
            agent_id="test-agent",
            session_id="test-session",
            created_at=datetime.now(),
            permissions={ActionType.FILE_READ: PermissionLevel.READ_ONLY},
        )
        request = ExecutionRequest(
            request_id="test-001",
            agent_context=ctx,
            action_type=ActionType.FILE_READ,
            parameters={"path": "/tmp/test.txt"},
            timestamp=datetime.now(),
        )
        assert sql_policy.validator(request) is True

    def test_multiple_statements_checked(self, sql_policy):
        """Multiple statements should all be checked."""
        # First safe, second dangerous
        request = self.make_sql_request("SELECT 1; DROP TABLE users;")
        assert sql_policy.validator(request) is False


class TestSQLPolicyFallback:
    """Test the fallback SQL check when sqlglot is not available."""

    def test_fallback_blocks_drop(self):
        """Fallback should block DROP."""
        from agent_control_plane.policy_engine import _fallback_sql_check
        assert _fallback_sql_check("DROP TABLE users") is False

    def test_fallback_blocks_grant(self):
        """Fallback should block GRANT."""
        from agent_control_plane.policy_engine import _fallback_sql_check
        assert _fallback_sql_check("GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%'") is False

    def test_fallback_blocks_create_user(self):
        """Fallback should block CREATE USER."""
        from agent_control_plane.policy_engine import _fallback_sql_check
        assert _fallback_sql_check("CREATE USER 'backdoor'@'%' IDENTIFIED BY 'pass'") is False

    def test_fallback_blocks_exec_xp_cmdshell(self):
        """Fallback should block EXEC xp_cmdshell."""
        from agent_control_plane.policy_engine import _fallback_sql_check
        assert _fallback_sql_check("EXEC xp_cmdshell 'whoami'") is False

    def test_fallback_blocks_update_without_where(self):
        """Fallback should block UPDATE without WHERE."""
        from agent_control_plane.policy_engine import _fallback_sql_check
        assert _fallback_sql_check("UPDATE users SET role='admin'") is False

    def test_fallback_blocks_revoke(self):
        """Fallback should block REVOKE."""
        from agent_control_plane.policy_engine import _fallback_sql_check
        assert _fallback_sql_check("REVOKE ALL PRIVILEGES ON *.* FROM 'user'@'%'") is False

    def test_fallback_blocks_merge(self):
        """Fallback should block MERGE INTO."""
        from agent_control_plane.policy_engine import _fallback_sql_check
        assert _fallback_sql_check("MERGE INTO target USING source ON target.id = source.id") is False

    def test_fallback_allows_select(self):
        """Fallback should allow SELECT."""
        from agent_control_plane.policy_engine import _fallback_sql_check
        assert _fallback_sql_check("SELECT * FROM users WHERE id = 1") is True

    def test_fallback_allows_insert(self):
        """Fallback should allow INSERT."""
        from agent_control_plane.policy_engine import _fallback_sql_check
        assert _fallback_sql_check("INSERT INTO logs (msg) VALUES ('hello')") is True

    def test_fallback_allows_update_with_where(self):
        """Fallback should allow UPDATE with WHERE."""
        from agent_control_plane.policy_engine import _fallback_sql_check
        assert _fallback_sql_check("UPDATE users SET active=0 WHERE id=5") is True


class TestSQLPolicyConfig:
    """Test config-based SQL policy loading."""

    def test_create_policies_from_config_with_yaml(self, tmp_path):
        """Loading from YAML config should produce working policies."""
        from agent_control_plane.policy_engine import (
            create_policies_from_config, SQLPolicyConfig,
        )
        cfg_file = tmp_path / "test-policy.yaml"
        cfg_file.write_text(
            "version: '1.0'\n"
            "name: test\n"
            "sql_policy:\n"
            "  blocked_statements:\n"
            "    - DROP\n"
            "    - GRANT\n"
            "  require_where_clause:\n"
            "    - DELETE\n"
            "  blocked_create_types:\n"
            "    - USER\n"
            "  blocked_patterns:\n"
            "    - '\\bEXEC\\b'\n",
            encoding="utf-8",
        )
        rules = create_policies_from_config(str(cfg_file))
        sql_rule = next(r for r in rules if r.name == "no_destructive_sql")
        assert sql_rule is not None

    def test_create_policies_from_explicit_config(self):
        """Passing SQLPolicyConfig directly should work."""
        from agent_control_plane.policy_engine import (
            create_policies_from_config, SQLPolicyConfig,
        )
        cfg = SQLPolicyConfig(
            blocked_statements=["DROP"],
            require_where_clause=[],
            blocked_create_types=[],
            blocked_patterns=[],
        )
        rules = create_policies_from_config(sql_config=cfg)
        assert len(rules) == 3

    def test_default_policies_emits_deprecation_warning(self):
        """create_default_policies should emit a deprecation warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            create_default_policies()
            assert len(w) >= 1
            assert "sample rules" in str(w[0].message)

    def test_config_missing_file_raises(self):
        """Loading a non-existent config should raise FileNotFoundError."""
        from agent_control_plane.policy_engine import load_sql_policy_config
        with pytest.raises(FileNotFoundError):
            load_sql_policy_config("/nonexistent/path.yaml")

    def test_fallback_uses_config(self):
        """Fallback regex check should respect config."""
        from agent_control_plane.policy_engine import _fallback_sql_check, SQLPolicyConfig

        # Config that blocks INSERT (not blocked by default)
        cfg = SQLPolicyConfig(
            blocked_statements=["INSERT"],
            require_where_clause=[],
            blocked_create_types=[],
            blocked_patterns=[],
        )
        assert _fallback_sql_check("INSERT INTO users VALUES (1)", cfg) is False
        # SELECT should still pass
        assert _fallback_sql_check("SELECT * FROM users", cfg) is True
