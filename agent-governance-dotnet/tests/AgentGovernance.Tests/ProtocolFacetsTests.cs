// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Policy;
using Xunit;

namespace AgentGovernance.Tests;

public class ProtocolFacetsTests
{
    // ── FacetRegistry ─────────────────────────────────────────────────────

    [Fact]
    public void Registry_RunsCustomExtractor_AndMergesIntoSubDict()
    {
        var r = new FacetRegistry();
        r.Register("redis", sub =>
        {
            var cmd = sub.TryGetValue("command", out var v) ? v?.ToString() ?? string.Empty : string.Empty;
            return new Dictionary<string, object> { ["verb"] = cmd.ToUpperInvariant() };
        });

        var ctx = new Dictionary<string, object>
        {
            ["redis"] = new Dictionary<string, object> { ["command"] = "flushall" }
        };
        r.Extract(ctx);

        var sub = Assert.IsType<Dictionary<string, object>>(ctx["redis"]);
        Assert.Equal("FLUSHALL", sub["verb"]);
    }

    [Fact]
    public void Registry_SkipsMissingOrWrongTypeSubContexts()
    {
        var r = new FacetRegistry();
        r.Register("sql", ProtocolFacets.ExtractSqlFacets);

        var empty = new Dictionary<string, object>();
        r.Extract(empty);
        Assert.Empty(empty);

        var wrong = new Dictionary<string, object> { ["sql"] = "not a dictionary" };
        r.Extract(wrong);
        Assert.Equal("not a dictionary", wrong["sql"]);
    }

    [Fact]
    public void Registry_IsolatesThrowingExtractor()
    {
        var r = new FacetRegistry();
        r.Register("bad", _ => throw new InvalidOperationException("boom"));
        r.Register("good", _ => new Dictionary<string, object> { ["ok"] = true });

        var ctx = new Dictionary<string, object>
        {
            ["bad"] = new Dictionary<string, object>(),
            ["good"] = new Dictionary<string, object>(),
        };
        r.Extract(ctx);

        var good = Assert.IsType<Dictionary<string, object>>(ctx["good"]);
        Assert.True((bool)good["ok"]);
    }

    [Fact]
    public void DefaultRegistry_HasSqlAndK8s()
    {
        Assert.True(ProtocolFacets.DefaultRegistry.Count >= 2);
    }

    // ── SQL ───────────────────────────────────────────────────────────────

    private static Dictionary<string, object> Sql(string query) =>
        (Dictionary<string, object>)ProtocolFacets.ExtractSqlFacets(
            new Dictionary<string, object> { ["query"] = query });

    [Fact]
    public void Sql_EmptyOrMissingQuery_AllEmptyFields()
    {
        var none = (Dictionary<string, object>)ProtocolFacets.ExtractSqlFacets(
            new Dictionary<string, object>());
        Assert.Equal(string.Empty, none["verb"]);

        Assert.Equal(string.Empty, Sql("")["verb"]);
        Assert.Equal(string.Empty, Sql("   ")["verb"]);
    }

    [Theory]
    [InlineData("SELECT * FROM users", "SELECT", "users")]
    [InlineData("select id from users", "SELECT", "users")]
    [InlineData("INSERT INTO orders (id) VALUES (1)", "INSERT", "orders")]
    [InlineData("UPDATE accounts SET balance = 0 WHERE id = 1", "UPDATE", "accounts")]
    [InlineData("DELETE FROM sessions WHERE expired = true", "DELETE", "sessions")]
    [InlineData("DROP TABLE production", "DROP", "production")]
    [InlineData("DROP TABLE IF EXISTS staging.payments", "DROP", "payments")]
    [InlineData("TRUNCATE TABLE audit_log", "TRUNCATE", "audit_log")]
    [InlineData("ALTER TABLE users ADD COLUMN age INT", "ALTER", "users")]
    [InlineData("CREATE TABLE foo (id INT)", "CREATE", "foo")]
    [InlineData("GRANT SELECT ON users TO bob", "GRANT", "users")]
    [InlineData("MERGE INTO dst USING src ON dst.id = src.id", "MERGE", "dst")]
    public void Sql_BasicVerbsAndTargets(string query, string verb, string target)
    {
        var f = Sql(query);
        Assert.Equal(verb, f["verb"]);
        Assert.Equal(target, f["target"]);
    }

    [Fact]
    public void Sql_UnknownVerbForGarbage()
    {
        Assert.Equal("UNKNOWN", Sql("WAT IS THIS")["verb"]);
    }

    [Fact]
    public void Sql_MultiStatementFailsClosed()
    {
        Assert.Equal("UNKNOWN", Sql("SELECT 1; DROP TABLE production")["verb"]);
    }

    [Fact]
    public void Sql_TrailingSemicolonOk()
    {
        var f = Sql("SELECT * FROM users;");
        Assert.Equal("SELECT", f["verb"]);
        Assert.Equal("users", f["target"]);
    }

    [Fact]
    public void Sql_SemicolonInStringIsNotABoundary()
    {
        Assert.Equal("SELECT", Sql("SELECT * FROM users WHERE name = 'a;b'")["verb"]);
    }

    [Fact]
    public void Sql_DoubleDashInsideString_DoesNotHideInjection()
    {
        Assert.Equal("UNKNOWN", Sql("SELECT '--'; DROP TABLE production")["verb"]);
    }

    [Fact]
    public void Sql_BlockCommentInsideStringPreserved()
    {
        var f = Sql("SELECT '/* not a comment */' FROM users");
        Assert.Equal("SELECT", f["verb"]);
        Assert.Equal("users", f["target"]);
    }

    [Fact]
    public void Sql_CteClassifiesInnerVerb()
    {
        Assert.Equal("DELETE", Sql(
            "WITH stale AS (SELECT id FROM users WHERE inactive) DELETE FROM users WHERE id IN (SELECT id FROM stale)")["verb"]);
        Assert.Equal("INSERT", Sql(
            "WITH new_rows AS (SELECT 1 AS id) INSERT INTO audit (id) SELECT id FROM new_rows")["verb"]);
        Assert.Equal("SELECT", Sql("WITH x AS (SELECT 1) SELECT * FROM x")["verb"]);
    }

    [Fact]
    public void Sql_InsertTargetIsWrittenObject()
    {
        var f = Sql("INSERT INTO protected SELECT * FROM source");
        Assert.Equal("protected", f["target"]);
        var tables = ((string)f["tables"]).Split(',');
        Assert.Contains("protected", tables);
        Assert.Contains("source", tables);
    }

    [Fact]
    public void Sql_UpdateWithFromTargetIsWrittenObject()
    {
        var f = Sql("UPDATE protected SET val = src.val FROM source AS src WHERE protected.id = src.id");
        Assert.Equal("protected", f["target"]);
    }

    [Fact]
    public void Sql_DeleteFromTarget()
    {
        var f = Sql("DELETE FROM protected WHERE id IN (SELECT id FROM staging)");
        Assert.Equal("DELETE", f["verb"]);
        Assert.Equal("protected", f["target"]);
    }

    [Fact]
    public void Sql_FunctionsDedupAndDenylist()
    {
        var f = Sql("SELECT COUNT(id), Count(name), NOW() FROM users");
        var fns = ((string)f["functions"]).Split(',');
        Assert.Contains("COUNT", fns);
        Assert.Contains("NOW", fns);
        Assert.Equal(1, fns.Count(x => x == "COUNT"));

        var g = Sql("INSERT INTO t VALUES (CAST('1' AS INT))");
        var gfns = ((string)g["functions"]).Split(',').Where(s => s.Length > 0).ToArray();
        Assert.DoesNotContain("VALUES", gfns);
        Assert.DoesNotContain("CAST", gfns);
    }

    [Fact]
    public void Sql_StripsComments()
    {
        var f = Sql("/* hi */ -- comment\n SELECT id FROM users -- tail");
        Assert.Equal("SELECT", f["verb"]);
        Assert.Equal("users", f["target"]);
    }

    [Theory]
    [InlineData("SELECT * FROM \"public\".\"users\"", "users")]
    [InlineData("SELECT * FROM `db`.`orders`", "orders")]
    [InlineData("SELECT * FROM [dbo].[items]", "items")]
    public void Sql_StripsQuoting(string query, string expectedTable)
    {
        var tables = ((string)Sql(query)["tables"]).Split(',');
        Assert.Contains(expectedTable, tables);
    }

    // ── K8s ───────────────────────────────────────────────────────────────

    private static Dictionary<string, object> K8s(string method, string path) =>
        (Dictionary<string, object>)ProtocolFacets.ExtractK8sFacets(
            new Dictionary<string, object> { ["method"] = method, ["path"] = path });

    [Fact]
    public void K8s_EmptyPath_AllEmpty()
    {
        var f = (Dictionary<string, object>)ProtocolFacets.ExtractK8sFacets(
            new Dictionary<string, object>());
        Assert.Equal(string.Empty, f["verb"]);
    }

    [Fact]
    public void K8s_ClusterList()
    {
        var f = K8s("GET", "/api/v1/nodes");
        Assert.Equal("list", f["verb"]);
        Assert.Equal("nodes", f["resource"]);
    }

    [Fact]
    public void K8s_NamespacedCollectionList()
    {
        var f = K8s("GET", "/api/v1/namespaces/prod/pods");
        Assert.Equal("list", f["verb"]);
        Assert.Equal("pods", f["resource"]);
        Assert.Equal("prod", f["namespace"]);
    }

    [Fact]
    public void K8s_NamedObjectGet()
    {
        var f = K8s("GET", "/api/v1/namespaces/prod/pods/mypod");
        Assert.Equal("get", f["verb"]);
        Assert.Equal("mypod", f["name"]);
    }

    [Fact]
    public void K8s_ExecSubresource()
    {
        var f = K8s("POST", "/api/v1/namespaces/prod/pods/mypod/exec");
        Assert.Equal("exec", f["subresource"]);
        Assert.Equal("create", f["verb"]);
    }

    [Fact]
    public void K8s_DeleteCollectionVsNamed()
    {
        Assert.Equal("deletecollection", K8s("DELETE", "/api/v1/namespaces/prod/pods")["verb"]);
        Assert.Equal("delete", K8s("DELETE", "/api/v1/namespaces/prod/pods/p1")["verb"]);
    }

    [Fact]
    public void K8s_ApisGroup()
    {
        var f = K8s("GET", "/apis/apps/v1/namespaces/prod/deployments/web");
        Assert.Equal("deployments", f["resource"]);
        Assert.Equal("web", f["name"]);
        Assert.Equal("get", f["verb"]);
    }

    [Fact]
    public void K8s_TrailingSlash()
    {
        var f = K8s("GET", "/api/v1/namespaces/prod/pods/");
        Assert.Equal("pods", f["resource"]);
    }

    [Fact]
    public void K8s_UnknownMethodLowercased()
    {
        Assert.Equal("options", K8s("OPTIONS", "/api/v1/namespaces/prod/pods")["verb"]);
    }

    [Fact]
    public void K8s_MissingMethod_NoVerb()
    {
        var f = (Dictionary<string, object>)ProtocolFacets.ExtractK8sFacets(
            new Dictionary<string, object> { ["path"] = "/api/v1/namespaces/prod/pods" });
        Assert.Equal(string.Empty, f["verb"]);
        Assert.Equal("pods", f["resource"]);
    }

    [Fact]
    public void K8s_WatchPathPatterns()
    {
        Assert.Equal("watch", K8s("GET", "/api/v1/watch/pods")["verb"]);
        var f = K8s("GET", "/api/v1/watch/namespaces/prod/pods");
        Assert.Equal("watch", f["verb"]);
        Assert.Equal("prod", f["namespace"]);
        var g = K8s("GET", "/api/v1/watch/namespaces/prod/pods/web");
        Assert.Equal("watch", g["verb"]);
        Assert.Equal("web", g["name"]);
    }

    [Fact]
    public void K8s_ProxyTail()
    {
        var f = K8s("GET", "/api/v1/namespaces/prod/pods/web/proxy/healthz");
        Assert.Equal("proxy", f["subresource"]);
        Assert.Equal("pods", f["resource"]);
        Assert.Equal("web", f["name"]);
    }

    [Fact]
    public void K8s_LogAndStatusSubresources()
    {
        Assert.Equal("log", K8s("GET", "/api/v1/namespaces/prod/pods/web/log")["subresource"]);
        var f = K8s("PATCH", "/apis/apps/v1/namespaces/prod/deployments/web/status");
        Assert.Equal("status", f["subresource"]);
        Assert.Equal("patch", f["verb"]);
    }

    [Fact]
    public void K8s_QueryStringStrippedBeforePathMatch()
    {
        var f = K8s("GET", "/api/v1/namespaces/prod/pods?fieldManager=test");
        Assert.Equal("pods", f["resource"]);
        Assert.Equal("list", f["verb"]);
    }

    [Fact]
    public void K8s_WatchQueryParamSignalsWatch()
    {
        var f = K8s("GET", "/api/v1/namespaces/prod/pods?watch=true");
        Assert.Equal("watch", f["verb"]);
    }

    [Fact]
    public void K8s_ResourceNamedWatchDoesNotFalseTrigger()
    {
        var f = K8s("GET", "/api/v1/namespaces/watch-test/pods");
        Assert.Equal("list", f["verb"]);
        Assert.Equal("watch-test", f["namespace"]);
    }

    [Fact]
    public void K8s_FragmentStripped()
    {
        Assert.Equal("pods", K8s("GET", "/api/v1/namespaces/prod/pods#anchor")["resource"]);
    }

    // ── Regression: cluster-scoped subresources/proxy and watch gating ────

    [Fact]
    public void K8s_ClusterScopedSubresource_Status()
    {
        // /api/v1/nodes/node1/status is cluster-scoped — previously only
        // namespaced subresource patterns existed and this fell through to
        // the (resource, name) cluster pattern, dropping `status`.
        var f = K8s("PATCH", "/api/v1/nodes/node1/status");
        Assert.Equal("nodes", f["resource"]);
        Assert.Equal("node1", f["name"]);
        Assert.Equal("status", f["subresource"]);
    }

    [Fact]
    public void K8s_ClusterScopedSubresource_Proxy()
    {
        var f = K8s("GET", "/api/v1/nodes/node1/proxy/metrics");
        Assert.Equal("nodes", f["resource"]);
        Assert.Equal("node1", f["name"]);
        Assert.Equal("proxy", f["subresource"]);
    }

    [Fact]
    public void K8s_WatchQueryParamWithWriteMethod_DoesNotEmitWatchVerb()
    {
        // ?watch=true on POST is nonsense; intent is a write, not a watch.
        // Verb should reflect the HTTP method, not the spoofed query.
        var f = K8s("POST", "/api/v1/namespaces/prod/pods?watch=true");
        Assert.NotEqual("watch", f["verb"]);
        Assert.Equal("create", f["verb"]);
    }

    [Fact]
    public void Sql_InsertWithoutIntoTargetIsWrittenObject()
    {
        // Some dialects allow `INSERT <table> (...) VALUES (...)` without
        // the INTO keyword.
        var f = Sql("INSERT protected (id) VALUES (1)");
        Assert.Equal("INSERT", f["verb"]);
        Assert.Equal("protected", f["target"]);
    }

    // ── ExtractProtocolFacets default flow ────────────────────────────────

    [Fact]
    public void Default_Extract_PopulatesNestedSqlFields()
    {
        var ctx = new Dictionary<string, object>
        {
            ["sql"] = new Dictionary<string, object> { ["query"] = "DROP TABLE production" }
        };
        ProtocolFacets.ExtractProtocolFacets(ctx);

        var sql = Assert.IsType<Dictionary<string, object>>(ctx["sql"]);
        Assert.Equal("DROP", sql["verb"]);
        Assert.Equal("production", sql["target"]);
    }

    [Fact]
    public void Default_Extract_PopulatesNestedK8sFields()
    {
        var ctx = new Dictionary<string, object>
        {
            ["k8s"] = new Dictionary<string, object>
            {
                ["method"] = "DELETE",
                ["path"] = "/api/v1/namespaces/prod/pods/p1",
            }
        };
        ProtocolFacets.ExtractProtocolFacets(ctx);

        var k8s = Assert.IsType<Dictionary<string, object>>(ctx["k8s"]);
        Assert.Equal("delete", k8s["verb"]);
        Assert.Equal("prod", k8s["namespace"]);
    }

    [Fact]
    public void Extract_WithCustomRegistry_DoesNotTouchDefault()
    {
        var r = new FacetRegistry();
        r.Register("sql", _ => new Dictionary<string, object> { ["verb"] = "CUSTOM" });

        var ctx = new Dictionary<string, object>
        {
            ["sql"] = new Dictionary<string, object> { ["query"] = "SELECT 1" }
        };
        ProtocolFacets.ExtractProtocolFacets(ctx, r);

        var sql = Assert.IsType<Dictionary<string, object>>(ctx["sql"]);
        Assert.Equal("CUSTOM", sql["verb"]);
    }

    // ── PolicyEngine integration ──────────────────────────────────────────

    [Fact]
    public void PolicyEngine_DeniesDestructiveSqlViaSqlVerb()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
apiVersion: governance.toolkit/v1
name: sql-guard
scope: global
default_action: allow
rules:
  - name: deny-destructive-sql
    condition: ""sql.verb == 'DROP'""
    action: deny
    priority: 100
");
        var decision = engine.Evaluate("did:mesh:agent1", new Dictionary<string, object>
        {
            ["sql"] = new Dictionary<string, object> { ["query"] = "DROP TABLE production" }
        });
        Assert.False(decision.Allowed);
        Assert.Equal("deny-destructive-sql", decision.MatchedRule);
    }

    [Fact]
    public void PolicyEngine_DeniesPodExecViaK8sSubresource()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
apiVersion: governance.toolkit/v1
name: k8s-guard
scope: global
default_action: allow
rules:
  - name: deny-exec
    condition: ""k8s.subresource == 'exec'""
    action: deny
    priority: 100
");
        var decision = engine.Evaluate("did:mesh:agent1", new Dictionary<string, object>
        {
            ["k8s"] = new Dictionary<string, object>
            {
                ["method"] = "POST",
                ["path"] = "/api/v1/namespaces/prod/pods/web/exec",
            }
        });
        Assert.False(decision.Allowed);
        Assert.Equal("deny-exec", decision.MatchedRule);
    }

    [Fact]
    public void PolicyEngine_SqlTargetCanBeReferenced()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
apiVersion: governance.toolkit/v1
name: sql-target-guard
scope: global
default_action: allow
rules:
  - name: deny-writes-to-protected
    condition: ""sql.target == 'protected'""
    action: deny
    priority: 100
");
        var decision = engine.Evaluate("did:mesh:agent1", new Dictionary<string, object>
        {
            ["sql"] = new Dictionary<string, object>
            {
                ["query"] = "INSERT INTO protected SELECT * FROM staging"
            }
        });
        Assert.False(decision.Allowed);
        Assert.Equal("deny-writes-to-protected", decision.MatchedRule);
    }

    [Fact]
    public void PolicyEngine_CallerContextNotMutated()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
apiVersion: governance.toolkit/v1
name: noop
scope: global
default_action: allow
rules: []
");
        var sub = new Dictionary<string, object> { ["query"] = "SELECT 1" };
        var ctx = new Dictionary<string, object> { ["sql"] = sub };

        engine.Evaluate("did:mesh:agent1", ctx);

        // The caller's sub-dictionary should not have facet fields injected.
        Assert.Single(sub);
        Assert.True(sub.ContainsKey("query"));
        Assert.False(sub.ContainsKey("verb"));
    }
}

