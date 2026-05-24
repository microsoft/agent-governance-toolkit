# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for wire-protocol facet extraction (issue #2483)."""

import pytest

from agentmesh.governance.protocol_facets import (
    FacetRegistry,
    default_registry,
    extract_protocol_facets,
    _extract_sql_facets,
    _extract_k8s_facets,
)

try:
    import sqlglot  # noqa: F401
    SQLGLOT_AVAILABLE = True
except ImportError:
    SQLGLOT_AVAILABLE = False

needs_sqlglot = pytest.mark.skipif(not SQLGLOT_AVAILABLE, reason="sqlglot not installed")


class TestSqlVerbExtraction:

    @needs_sqlglot
    def test_select(self):
        assert _extract_sql_facets({"query": "SELECT * FROM users"})["verb"] == "SELECT"

    @needs_sqlglot
    def test_insert(self):
        assert _extract_sql_facets({"query": "INSERT INTO logs (msg) VALUES ('hi')"})["verb"] == "INSERT"

    @needs_sqlglot
    def test_update(self):
        assert _extract_sql_facets({"query": "UPDATE users SET active=0 WHERE id=1"})["verb"] == "UPDATE"

    @needs_sqlglot
    def test_delete(self):
        assert _extract_sql_facets({"query": "DELETE FROM users WHERE id=1"})["verb"] == "DELETE"

    @needs_sqlglot
    def test_drop(self):
        assert _extract_sql_facets({"query": "DROP TABLE users"})["verb"] == "DROP"

    @needs_sqlglot
    def test_truncate(self):
        verb = _extract_sql_facets({"query": "TRUNCATE TABLE users"})["verb"]
        assert verb in ("TRUNCATE", "UNKNOWN")

    @needs_sqlglot
    def test_alter(self):
        assert _extract_sql_facets({"query": "ALTER TABLE users ADD COLUMN x INT"})["verb"] == "ALTER"

    @needs_sqlglot
    def test_grant(self):
        assert _extract_sql_facets({"query": "GRANT SELECT ON users TO readonly"})["verb"] == "GRANT"

    @needs_sqlglot
    def test_merge(self):
        q = "MERGE INTO target USING source ON target.id = source.id WHEN MATCHED THEN UPDATE SET target.val = source.val"
        assert _extract_sql_facets({"query": q})["verb"] == "MERGE"

    @needs_sqlglot
    def test_create_table(self):
        assert _extract_sql_facets({"query": "CREATE TABLE logs (id INT)"})["verb"] == "CREATE"

    def test_empty_query(self):
        assert _extract_sql_facets({"query": ""})["verb"] == ""

    def test_whitespace_only(self):
        assert _extract_sql_facets({"query": "   "})["verb"] == ""

    def test_missing_query_key(self):
        assert _extract_sql_facets({})["verb"] == ""

    def test_no_sqlglot_returns_unknown(self, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "sqlglot":
                raise ImportError("mocked")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        assert _extract_sql_facets({"query": "SELECT 1"})["verb"] == "UNKNOWN"


class TestSqlTableAndFunctionExtraction:

    @needs_sqlglot
    def test_single_table(self):
        assert "users" in _extract_sql_facets({"query": "SELECT * FROM users"})["tables"]

    @needs_sqlglot
    def test_multiple_tables(self):
        result = _extract_sql_facets({"query": "SELECT * FROM orders JOIN users ON orders.user_id = users.id"})
        assert "orders" in result["tables"]
        assert "users" in result["tables"]

    @needs_sqlglot
    def test_drop_table_name_extracted(self):
        assert "production_data" in _extract_sql_facets({"query": "DROP TABLE production_data"})["tables"]

    @needs_sqlglot
    def test_function_extraction(self):
        assert "COUNT" in _extract_sql_facets({"query": "SELECT COUNT(*) FROM users"})["functions"]

    @needs_sqlglot
    def test_no_functions(self):
        assert _extract_sql_facets({"query": "SELECT id FROM users"})["functions"] == ""


class TestSqlFailClosed:

    @needs_sqlglot
    def test_invalid_sql_returns_string_verb(self):
        result = _extract_sql_facets({"query": "NOT VALID SQL @@##"})
        assert isinstance(result["verb"], str)

    @needs_sqlglot
    def test_all_fields_are_strings(self):
        result = _extract_sql_facets({"query": "SELECT 1"})
        for field in ("verb", "target", "tables", "functions"):
            assert isinstance(result[field], str)


class TestSqlTargetExtraction:

    @needs_sqlglot
    def test_select_target_is_first_table(self):
        assert _extract_sql_facets({"query": "SELECT * FROM users"})["target"] == "users"

    @needs_sqlglot
    def test_drop_target_is_table_name(self):
        assert _extract_sql_facets({"query": "DROP TABLE production_data"})["target"] == "production_data"

    @needs_sqlglot
    def test_delete_target_is_table_name(self):
        assert _extract_sql_facets({"query": "DELETE FROM orders WHERE id=1"})["target"] == "orders"

    @needs_sqlglot
    def test_update_target_is_table_name(self):
        assert _extract_sql_facets({"query": "UPDATE users SET active=0 WHERE id=1"})["target"] == "users"

    @needs_sqlglot
    def test_join_target_is_first_table(self):
        q = "SELECT * FROM orders JOIN users ON orders.user_id = users.id"
        assert _extract_sql_facets({"query": q})["target"] == "orders"

    @needs_sqlglot
    def test_no_table_gives_empty_target(self):
        assert _extract_sql_facets({"query": "SELECT 1"})["target"] == ""

    def test_empty_query_gives_empty_target(self):
        assert _extract_sql_facets({"query": ""})["target"] == ""

    @needs_sqlglot
    def test_target_works_in_policy_condition(self):
        from agentmesh.governance.policy import Policy, PolicyEngine

        policy = Policy.model_validate({
            "name": "test-target-policy",
            "agents": ["*"],
            "rules": [{
                "name": "deny-drop-production",
                "condition": "sql.verb in ['DROP', 'TRUNCATE', 'DELETE'] and sql.target == 'production'",
                "action": "deny",
                "stage": "pre_tool",
            }],
            "default_action": "allow",
        })
        engine = PolicyEngine()
        engine.load_policy(policy)

        denied = engine.evaluate(
            agent_did="did:example:agent1",
            context={"sql": {"query": "DROP TABLE production"}},
            stage="pre_tool",
        )
        assert not denied.allowed

        allowed = engine.evaluate(
            agent_did="did:example:agent1",
            context={"sql": {"query": "DROP TABLE staging"}},
            stage="pre_tool",
        )
        assert allowed.allowed


class TestFacetRegistry:

    def test_register_and_extract_custom_protocol(self):
        registry = FacetRegistry()
        registry.register("redis", lambda ctx: {"verb": (ctx.get("command") or "").upper()})
        ctx = {"redis": {"command": "flushall"}}
        registry.extract(ctx)
        assert ctx["redis"]["verb"] == "FLUSHALL"

    def test_non_dict_context_key_skipped(self):
        registry = FacetRegistry()
        called = []
        registry.register("sql", lambda ctx: called.append(True) or {})
        registry.extract({"sql": "not-a-dict"})
        assert not called

    def test_extractor_exception_is_swallowed(self):
        registry = FacetRegistry()

        def bad_extractor(ctx):
            raise RuntimeError("boom")

        registry.register("sql", bad_extractor)
        ctx = {"sql": {"query": "SELECT 1"}}
        registry.extract(ctx)
        assert ctx["sql"]["query"] == "SELECT 1"

    def test_multiple_extractors_all_run_in_order(self):
        registry = FacetRegistry()
        order = []
        registry.register("a", lambda ctx: order.append("a") or {})
        registry.register("b", lambda ctx: order.append("b") or {})
        registry.extract({"a": {}, "b": {}})
        assert order == ["a", "b"]

    def test_default_registry_has_sql_and_k8s(self):
        keys = [key for key, _ in default_registry._extractors]
        assert "sql" in keys
        assert "k8s" in keys

    def test_custom_registry_passed_to_extract_protocol_facets(self):
        registry = FacetRegistry()
        registry.register("redis", lambda ctx: {"verb": "CUSTOM"})
        ctx = {"redis": {"command": "get"}}
        extract_protocol_facets(ctx, registry=registry)
        assert ctx["redis"]["verb"] == "CUSTOM"


class TestK8sVerbMapping:

    def test_get_named_resource(self):
        result = _extract_k8s_facets({"method": "GET", "path": "/api/v1/namespaces/default/pods/mypod"})
        assert result["verb"] == "get"

    def test_get_collection(self):
        result = _extract_k8s_facets({"method": "GET", "path": "/api/v1/namespaces/default/pods"})
        assert result["verb"] == "list"

    def test_delete_named(self):
        result = _extract_k8s_facets({"method": "DELETE", "path": "/api/v1/namespaces/production/pods/mypod"})
        assert result["verb"] == "delete"

    def test_post_collection(self):
        result = _extract_k8s_facets({"method": "POST", "path": "/api/v1/namespaces/default/pods"})
        assert result["verb"] == "create"

    def test_put_named(self):
        result = _extract_k8s_facets({"method": "PUT", "path": "/api/v1/namespaces/default/deployments/myapp"})
        assert result["verb"] == "update"

    def test_patch_named(self):
        result = _extract_k8s_facets({"method": "PATCH", "path": "/api/v1/namespaces/default/deployments/myapp"})
        assert result["verb"] == "patch"

    def test_delete_collection(self):
        result = _extract_k8s_facets({"method": "DELETE", "path": "/api/v1/namespaces/default/pods"})
        assert result["verb"] == "deletecollection"


class TestK8sPathParsing:

    def test_namespaced_named_resource(self):
        result = _extract_k8s_facets({"method": "GET", "path": "/api/v1/namespaces/production/pods/mypod"})
        assert result["namespace"] == "production"
        assert result["resource"] == "pods"
        assert result["name"] == "mypod"
        assert result["subresource"] == ""

    def test_namespaced_collection(self):
        result = _extract_k8s_facets({"method": "GET", "path": "/api/v1/namespaces/staging/deployments"})
        assert result["namespace"] == "staging"
        assert result["resource"] == "deployments"
        assert result["name"] == ""

    def test_subresource_exec(self):
        result = _extract_k8s_facets({"method": "POST", "path": "/api/v1/namespaces/default/pods/mypod/exec"})
        assert result["resource"] == "pods"
        assert result["name"] == "mypod"
        assert result["subresource"] == "exec"

    def test_subresource_log(self):
        result = _extract_k8s_facets({"method": "GET", "path": "/api/v1/namespaces/default/pods/mypod/log"})
        assert result["subresource"] == "log"

    def test_cluster_scoped_named(self):
        result = _extract_k8s_facets({"method": "DELETE", "path": "/api/v1/namespaces/mynamespace"})
        assert result["resource"] == "namespaces"
        assert result["name"] == "mynamespace"
        assert result["namespace"] == ""

    def test_cluster_scoped_collection(self):
        result = _extract_k8s_facets({"method": "GET", "path": "/api/v1/nodes"})
        assert result["resource"] == "nodes"
        assert result["namespace"] == ""
        assert result["name"] == ""

    def test_apis_group_namespaced(self):
        result = _extract_k8s_facets({"method": "DELETE", "path": "/apis/apps/v1/namespaces/production/deployments/myapp"})
        assert result["namespace"] == "production"
        assert result["resource"] == "deployments"
        assert result["name"] == "myapp"
        assert result["verb"] == "delete"

    def test_empty_path(self):
        result = _extract_k8s_facets({"method": "GET", "path": ""})
        assert result["verb"] == ""
        assert result["resource"] == ""

    def test_missing_method(self):
        result = _extract_k8s_facets({"path": "/api/v1/namespaces/default/pods"})
        assert result["resource"] == "pods"
        assert result["verb"] == ""


class TestExtractProtocolFacets:

    @needs_sqlglot
    def test_sql_context_enriched(self):
        ctx = {"sql": {"query": "DROP TABLE users"}}
        assert extract_protocol_facets(ctx)["sql"]["verb"] == "DROP"

    def test_k8s_context_enriched(self):
        ctx = {"k8s": {"method": "DELETE", "path": "/api/v1/namespaces/production/pods/mypod"}}
        result = extract_protocol_facets(ctx)
        assert result["k8s"]["verb"] == "delete"
        assert result["k8s"]["namespace"] == "production"

    @needs_sqlglot
    def test_both_contexts_enriched(self):
        ctx = {
            "sql": {"query": "SELECT * FROM users"},
            "k8s": {"method": "GET", "path": "/api/v1/namespaces/default/pods"},
        }
        result = extract_protocol_facets(ctx)
        assert result["sql"]["verb"] == "SELECT"
        assert result["k8s"]["verb"] == "list"

    def test_unrelated_context_untouched(self):
        ctx = {"action": {"type": "http", "method": "POST"}}
        result = extract_protocol_facets(ctx)
        assert "sql" not in result
        assert "k8s" not in result

    def test_sql_without_query_key_returns_empty_facets(self):
        ctx = {"sql": {"dialect": "postgres"}}
        extract_protocol_facets(ctx)
        assert ctx["sql"].get("verb", "") == ""

    def test_k8s_without_path_returns_empty_facets(self):
        ctx = {"k8s": {"method": "GET"}}
        extract_protocol_facets(ctx)
        assert ctx["k8s"].get("verb", "") == ""

    def test_returns_same_dict(self):
        ctx = {"sql": {"query": "SELECT 1"}}
        assert extract_protocol_facets(ctx) is ctx

    def test_non_dict_sql_value_ignored(self):
        ctx = {"sql": "not-a-dict"}
        extract_protocol_facets(ctx)
        assert ctx["sql"] == "not-a-dict"


class TestPolicyEngineIntegration:

    @needs_sqlglot
    def test_sql_drop_denied_by_rule(self):
        from agentmesh.governance.policy import Policy, PolicyEngine

        policy = Policy.model_validate({
            "name": "test-sql-policy",
            "agents": ["*"],
            "rules": [{
                "name": "deny-drop",
                "condition": "sql.verb in ['DROP', 'TRUNCATE']",
                "action": "deny",
                "stage": "pre_tool",
            }],
        })
        engine = PolicyEngine()
        engine.load_policy(policy)

        decision = engine.evaluate(
            agent_did="did:example:agent1",
            context={"sql": {"query": "DROP TABLE users"}},
            stage="pre_tool",
        )
        assert not decision.allowed
        assert decision.matched_rule == "deny-drop"

    @needs_sqlglot
    def test_sql_select_not_matched_by_drop_rule(self):
        from agentmesh.governance.policy import Policy, PolicyEngine

        policy = Policy.model_validate({
            "name": "test-sql-policy",
            "agents": ["*"],
            "rules": [{
                "name": "deny-drop",
                "condition": "sql.verb in ['DROP', 'TRUNCATE']",
                "action": "deny",
                "stage": "pre_tool",
            }],
            "default_action": "allow",
        })
        engine = PolicyEngine()
        engine.load_policy(policy)

        assert engine.evaluate(
            agent_did="did:example:agent1",
            context={"sql": {"query": "SELECT * FROM users"}},
            stage="pre_tool",
        ).allowed

    def test_k8s_delete_prod_denied(self):
        from agentmesh.governance.policy import Policy, PolicyEngine

        policy = Policy.model_validate({
            "name": "test-k8s-policy",
            "agents": ["*"],
            "rules": [{
                "name": "deny-k8s-delete-prod",
                "condition": "k8s.verb == 'delete' and k8s.namespace == 'production'",
                "action": "deny",
                "stage": "pre_tool",
            }],
        })
        engine = PolicyEngine()
        engine.load_policy(policy)

        decision = engine.evaluate(
            agent_did="did:example:agent1",
            context={"k8s": {"method": "DELETE", "path": "/api/v1/namespaces/production/pods/mypod"}},
            stage="pre_tool",
        )
        assert not decision.allowed
        assert decision.matched_rule == "deny-k8s-delete-prod"

    def test_k8s_delete_staging_allowed(self):
        from agentmesh.governance.policy import Policy, PolicyEngine

        policy = Policy.model_validate({
            "name": "test-k8s-policy",
            "agents": ["*"],
            "rules": [{
                "name": "deny-k8s-delete-prod",
                "condition": "k8s.verb == 'delete' and k8s.namespace == 'production'",
                "action": "deny",
                "stage": "pre_tool",
            }],
            "default_action": "allow",
        })
        engine = PolicyEngine()
        engine.load_policy(policy)

        assert engine.evaluate(
            agent_did="did:example:agent1",
            context={"k8s": {"method": "DELETE", "path": "/api/v1/namespaces/staging/pods/mypod"}},
            stage="pre_tool",
        ).allowed

    def test_k8s_exec_denied(self):
        from agentmesh.governance.policy import Policy, PolicyEngine

        policy = Policy.model_validate({
            "name": "test-k8s-exec-policy",
            "agents": ["*"],
            "rules": [{
                "name": "deny-exec",
                "condition": "k8s.subresource == 'exec'",
                "action": "deny",
                "stage": "pre_tool",
            }],
        })
        engine = PolicyEngine()
        engine.load_policy(policy)

        decision = engine.evaluate(
            agent_did="did:example:agent1",
            context={"k8s": {"method": "POST", "path": "/api/v1/namespaces/default/pods/mypod/exec"}},
            stage="pre_tool",
        )
        assert not decision.allowed
