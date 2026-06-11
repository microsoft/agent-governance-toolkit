// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"sort"
	"strings"
	"testing"
)

// ── FacetRegistry ────────────────────────────────────────────────────────────

func TestFacetRegistry_CustomExtractor_FlattensAndMerges(t *testing.T) {
	r := NewFacetRegistry()
	r.Register("redis", func(sub map[string]any) map[string]any {
		cmd, _ := sub["command"].(string)
		return map[string]any{"verb": strings.ToUpper(cmd)}
	})

	ctx := map[string]any{
		"redis": map[string]any{"command": "flushall"},
	}
	r.Extract(ctx)

	if got := ctx["redis.verb"]; got != "FLUSHALL" {
		t.Fatalf("redis.verb = %v, want FLUSHALL", got)
	}
	sub, ok := ctx["redis"].(map[string]any)
	if !ok {
		t.Fatalf("ctx['redis'] is not a map")
	}
	if sub["verb"] != "FLUSHALL" {
		t.Fatalf("nested redis.verb = %v, want FLUSHALL", sub["verb"])
	}
}

func TestFacetRegistry_SkipsMissingOrWrongType(t *testing.T) {
	r := NewFacetRegistry()
	r.Register("sql", ExtractSQLFacets)

	empty := map[string]any{}
	r.Extract(empty)
	if len(empty) != 0 {
		t.Fatalf("expected empty, got %v", empty)
	}

	wrong := map[string]any{"sql": "not a map"}
	r.Extract(wrong)
	if _, ok := wrong["sql.verb"]; ok {
		t.Fatalf("should not flatten for non-map sub")
	}
}

func TestFacetRegistry_IsolatesPanickingExtractor(t *testing.T) {
	r := NewFacetRegistry()
	r.Register("bad", func(_ map[string]any) map[string]any { panic("boom") })
	r.Register("good", func(_ map[string]any) map[string]any {
		return map[string]any{"ok": true}
	})

	ctx := map[string]any{
		"bad":  map[string]any{},
		"good": map[string]any{},
	}
	r.Extract(ctx)
	if ctx["good.ok"] != true {
		t.Fatalf("good extractor should have run; got %v", ctx["good.ok"])
	}
}

func TestDefaultRegistry_HasSQLAndK8s(t *testing.T) {
	if DefaultRegistry().Len() < 2 {
		t.Fatalf("expected at least 2 extractors, got %d", DefaultRegistry().Len())
	}
}

// ── SQL ──────────────────────────────────────────────────────────────────────

func sql(query string) map[string]any {
	return ExtractSQLFacets(map[string]any{"query": query})
}

func TestSQL_EmptyOrBlankQuery(t *testing.T) {
	cases := []map[string]any{{}, {"query": ""}, {"query": "   "}}
	for _, c := range cases {
		f := ExtractSQLFacets(c)
		if f["verb"] != "" {
			t.Fatalf("expected empty verb for %v, got %v", c, f["verb"])
		}
	}
}

func TestSQL_BasicVerbsAndTargets(t *testing.T) {
	cases := []struct {
		q, verb, target string
	}{
		{"SELECT * FROM users", "SELECT", "users"},
		{"select id from users", "SELECT", "users"},
		{"INSERT INTO orders (id) VALUES (1)", "INSERT", "orders"},
		{"UPDATE accounts SET balance = 0 WHERE id = 1", "UPDATE", "accounts"},
		{"DELETE FROM sessions WHERE expired = true", "DELETE", "sessions"},
		{"DROP TABLE production", "DROP", "production"},
		{"DROP TABLE IF EXISTS staging.payments", "DROP", "payments"},
		{"TRUNCATE TABLE audit_log", "TRUNCATE", "audit_log"},
		{"ALTER TABLE users ADD COLUMN age INT", "ALTER", "users"},
		{"CREATE TABLE foo (id INT)", "CREATE", "foo"},
		{"GRANT SELECT ON users TO bob", "GRANT", "users"},
		{"MERGE INTO dst USING src ON dst.id = src.id", "MERGE", "dst"},
	}
	for _, c := range cases {
		f := sql(c.q)
		if f["verb"] != c.verb {
			t.Errorf("%s: verb = %v, want %s", c.q, f["verb"], c.verb)
		}
		if f["target"] != c.target {
			t.Errorf("%s: target = %v, want %s", c.q, f["target"], c.target)
		}
	}
}

func TestSQL_UnknownVerbForGarbage(t *testing.T) {
	if sql("WAT IS THIS")["verb"] != "UNKNOWN" {
		t.Fatalf("expected UNKNOWN")
	}
}

func TestSQL_MultiStatementFailsClosed(t *testing.T) {
	if sql("SELECT 1; DROP TABLE production")["verb"] != "UNKNOWN" {
		t.Fatalf("expected UNKNOWN for multi-statement")
	}
}

func TestSQL_TrailingSemicolonOK(t *testing.T) {
	f := sql("SELECT * FROM users;")
	if f["verb"] != "SELECT" || f["target"] != "users" {
		t.Fatalf("got verb=%v target=%v", f["verb"], f["target"])
	}
}

func TestSQL_SemicolonInsideStringLiteral(t *testing.T) {
	if sql("SELECT * FROM users WHERE name = 'a;b'")["verb"] != "SELECT" {
		t.Fatalf("expected SELECT (semicolon inside literal should not split)")
	}
}

func TestSQL_DoubleDashInsideStringDoesNotHideInjection(t *testing.T) {
	if sql("SELECT '--'; DROP TABLE production")["verb"] != "UNKNOWN" {
		t.Fatalf("quote-aware comment stripper should preserve the second statement")
	}
}

func TestSQL_BlockCommentInsideStringPreserved(t *testing.T) {
	f := sql("SELECT '/* not a comment */' FROM users")
	if f["verb"] != "SELECT" || f["target"] != "users" {
		t.Fatalf("got %+v", f)
	}
}

func TestSQL_CTE_ClassifiesInnerVerb(t *testing.T) {
	cases := []struct {
		q, want string
	}{
		{"WITH stale AS (SELECT id FROM users WHERE inactive) DELETE FROM users WHERE id IN (SELECT id FROM stale)", "DELETE"},
		{"WITH new_rows AS (SELECT 1 AS id) INSERT INTO audit (id) SELECT id FROM new_rows", "INSERT"},
		{"WITH x AS (SELECT 1) SELECT * FROM x", "SELECT"},
	}
	for _, c := range cases {
		if got := sql(c.q)["verb"]; got != c.want {
			t.Errorf("CTE %s: got %v, want %s", c.q, got, c.want)
		}
	}
}

func TestSQL_InsertTargetIsWrittenObject(t *testing.T) {
	f := sql("INSERT INTO protected SELECT * FROM source")
	if f["target"] != "protected" {
		t.Fatalf("target = %v, want protected", f["target"])
	}
	tables := strings.Split(f["tables"].(string), ",")
	sort.Strings(tables)
	want := []string{"protected", "source"}
	for _, w := range want {
		found := false
		for _, t2 := range tables {
			if t2 == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s in tables=%v", w, tables)
		}
	}
}

func TestSQL_UpdateWithFromTargetIsWrittenObject(t *testing.T) {
	f := sql("UPDATE protected SET val = src.val FROM source AS src WHERE protected.id = src.id")
	if f["target"] != "protected" {
		t.Fatalf("target = %v, want protected", f["target"])
	}
}

func TestSQL_DeleteFromTarget(t *testing.T) {
	f := sql("DELETE FROM protected WHERE id IN (SELECT id FROM staging)")
	if f["verb"] != "DELETE" || f["target"] != "protected" {
		t.Fatalf("got %+v", f)
	}
}

func TestSQL_InsertWithoutInto(t *testing.T) {
	f := sql("INSERT protected (id) VALUES (1)")
	if f["verb"] != "INSERT" || f["target"] != "protected" {
		t.Fatalf("got %+v", f)
	}
}

func TestSQL_FunctionsDedupAndDenylist(t *testing.T) {
	f := sql("SELECT COUNT(id), Count(name), NOW() FROM users")
	fns := strings.Split(f["functions"].(string), ",")
	if !contains(fns, "COUNT") || !contains(fns, "NOW") {
		t.Fatalf("expected COUNT and NOW in %v", fns)
	}
	n := 0
	for _, x := range fns {
		if x == "COUNT" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected COUNT once, got %d in %v", n, fns)
	}

	g := sql("INSERT INTO t VALUES (CAST('1' AS INT))")
	gfns := strings.Split(g["functions"].(string), ",")
	if contains(gfns, "VALUES") || contains(gfns, "CAST") {
		t.Fatalf("denylist failed: %v", gfns)
	}
}

func TestSQL_StripsComments(t *testing.T) {
	f := sql("/* hi */ -- comment\n SELECT id FROM users -- tail")
	if f["verb"] != "SELECT" || f["target"] != "users" {
		t.Fatalf("got %+v", f)
	}
}

func TestSQL_StripsQuoting(t *testing.T) {
	cases := []struct{ q, want string }{
		{`SELECT * FROM "public"."users"`, "users"},
		{"SELECT * FROM `db`.`orders`", "orders"},
		{"SELECT * FROM [dbo].[items]", "items"},
	}
	for _, c := range cases {
		tables := strings.Split(sql(c.q)["tables"].(string), ",")
		if !contains(tables, c.want) {
			t.Errorf("%s: expected %s in %v", c.q, c.want, tables)
		}
	}
}

// ── K8s ──────────────────────────────────────────────────────────────────────

func k8s(method, path string) map[string]any {
	return ExtractK8sFacets(map[string]any{"method": method, "path": path})
}

func TestK8s_EmptyPath(t *testing.T) {
	f := ExtractK8sFacets(map[string]any{})
	if f["verb"] != "" {
		t.Fatalf("empty path should produce empty verb, got %v", f["verb"])
	}
}

func TestK8s_ClusterList(t *testing.T) {
	f := k8s("GET", "/api/v1/nodes")
	if f["verb"] != "list" || f["resource"] != "nodes" {
		t.Fatalf("got %+v", f)
	}
}

func TestK8s_NamespacedCollectionAndNamed(t *testing.T) {
	f := k8s("GET", "/api/v1/namespaces/prod/pods")
	if f["verb"] != "list" || f["namespace"] != "prod" || f["resource"] != "pods" {
		t.Fatalf("collection: %+v", f)
	}
	g := k8s("GET", "/api/v1/namespaces/prod/pods/mypod")
	if g["verb"] != "get" || g["name"] != "mypod" {
		t.Fatalf("named: %+v", g)
	}
}

func TestK8s_Subresources(t *testing.T) {
	exec := k8s("POST", "/api/v1/namespaces/prod/pods/mypod/exec")
	if exec["subresource"] != "exec" || exec["verb"] != "create" {
		t.Fatalf("exec: %+v", exec)
	}
	logs := k8s("GET", "/api/v1/namespaces/prod/pods/mypod/log")
	if logs["subresource"] != "log" {
		t.Fatalf("log: %+v", logs)
	}
	status := k8s("PATCH", "/apis/apps/v1/namespaces/prod/deployments/web/status")
	if status["subresource"] != "status" || status["verb"] != "patch" {
		t.Fatalf("status: %+v", status)
	}
}

func TestK8s_DeleteCollectionVsNamed(t *testing.T) {
	if k8s("DELETE", "/api/v1/namespaces/prod/pods")["verb"] != "deletecollection" {
		t.Fatalf("expected deletecollection")
	}
	if k8s("DELETE", "/api/v1/namespaces/prod/pods/p1")["verb"] != "delete" {
		t.Fatalf("expected delete")
	}
}

func TestK8s_ApisGroup(t *testing.T) {
	f := k8s("GET", "/apis/apps/v1/namespaces/prod/deployments/web")
	if f["resource"] != "deployments" || f["name"] != "web" || f["verb"] != "get" {
		t.Fatalf("got %+v", f)
	}
}

func TestK8s_TrailingSlash(t *testing.T) {
	if k8s("GET", "/api/v1/namespaces/prod/pods/")["resource"] != "pods" {
		t.Fatalf("trailing slash not tolerated")
	}
}

func TestK8s_MissingMethod_NoVerb(t *testing.T) {
	f := ExtractK8sFacets(map[string]any{"path": "/api/v1/namespaces/prod/pods"})
	if f["verb"] != "" || f["resource"] != "pods" {
		t.Fatalf("got %+v", f)
	}
}

func TestK8s_WatchPaths(t *testing.T) {
	if k8s("GET", "/api/v1/watch/pods")["verb"] != "watch" {
		t.Fatalf("cluster watch")
	}
	if k8s("GET", "/api/v1/watch/namespaces/prod/pods")["verb"] != "watch" {
		t.Fatalf("namespaced collection watch")
	}
	if k8s("GET", "/api/v1/watch/namespaces/prod/pods/web")["verb"] != "watch" {
		t.Fatalf("namespaced named watch")
	}
}

func TestK8s_ProxyTail(t *testing.T) {
	f := k8s("GET", "/api/v1/namespaces/prod/pods/web/proxy/healthz")
	if f["subresource"] != "proxy" || f["name"] != "web" {
		t.Fatalf("got %+v", f)
	}
	c := k8s("GET", "/api/v1/nodes/n1/proxy/metrics")
	if c["subresource"] != "proxy" || c["resource"] != "nodes" {
		t.Fatalf("cluster proxy: %+v", c)
	}
}

func TestK8s_ClusterSubresource_Status(t *testing.T) {
	f := k8s("PATCH", "/api/v1/nodes/node1/status")
	if f["subresource"] != "status" || f["resource"] != "nodes" || f["name"] != "node1" {
		t.Fatalf("got %+v", f)
	}
}

func TestK8s_QueryStringStripped(t *testing.T) {
	f := k8s("GET", "/api/v1/namespaces/prod/pods?fieldManager=test")
	if f["resource"] != "pods" || f["verb"] != "list" {
		t.Fatalf("got %+v", f)
	}
}

func TestK8s_WatchQueryParam_GetOnly(t *testing.T) {
	if k8s("GET", "/api/v1/namespaces/prod/pods?watch=true")["verb"] != "watch" {
		t.Fatalf("watch=true on GET should yield watch")
	}
	// On POST, ?watch=true must not downgrade to a misleading watch verb.
	if got := k8s("POST", "/api/v1/namespaces/prod/pods?watch=true")["verb"]; got == "watch" {
		t.Fatalf("watch=true on POST must not yield watch (got %v)", got)
	}
}

func TestK8s_ResourceNamedWatchDoesNotFalseTrigger(t *testing.T) {
	f := k8s("GET", "/api/v1/namespaces/watch-test/pods")
	if f["verb"] != "list" || f["namespace"] != "watch-test" {
		t.Fatalf("got %+v", f)
	}
}

func TestK8s_FragmentStripped(t *testing.T) {
	if k8s("GET", "/api/v1/namespaces/prod/pods#anchor")["resource"] != "pods" {
		t.Fatalf("# fragment not stripped")
	}
}

// ── extract_protocol_facets default flow ─────────────────────────────────────

func TestExtract_FlattensSQLAtTopLevel(t *testing.T) {
	ctx := map[string]any{
		"sql": map[string]any{"query": "DROP TABLE production"},
	}
	ExtractProtocolFacets(ctx)
	if ctx["sql.verb"] != "DROP" || ctx["sql.target"] != "production" {
		t.Fatalf("got %+v", ctx)
	}
}

func TestExtract_FlattensK8sAtTopLevel(t *testing.T) {
	ctx := map[string]any{
		"k8s": map[string]any{
			"method": "DELETE",
			"path":   "/api/v1/namespaces/prod/pods/p1",
		},
	}
	ExtractProtocolFacets(ctx)
	if ctx["k8s.verb"] != "delete" || ctx["k8s.namespace"] != "prod" {
		t.Fatalf("got %+v", ctx)
	}
}

func TestExtractWith_CustomRegistry(t *testing.T) {
	r := NewFacetRegistry()
	r.Register("sql", func(_ map[string]any) map[string]any {
		return map[string]any{"verb": "CUSTOM"}
	})
	ctx := map[string]any{"sql": map[string]any{"query": "SELECT 1"}}
	ExtractProtocolFacetsWith(ctx, r)
	if ctx["sql.verb"] != "CUSTOM" {
		t.Fatalf("custom registry not respected: %+v", ctx)
	}
}

// ── PolicyEngine integration ─────────────────────────────────────────────────

func TestPolicyEngine_DeniesDestructiveSQL(t *testing.T) {
	engine := NewPolicyEngine([]PolicyRule{
		{
			Action: "db.exec",
			Effect: Deny,
			Conditions: map[string]any{
				"sql.verb": map[string]any{
					"$in": []any{"DROP", "TRUNCATE", "DELETE"},
				},
			},
		},
	})
	ctx := map[string]any{
		"sql": map[string]any{"query": "DROP TABLE production"},
	}
	if got := engine.Evaluate("db.exec", ctx); got != Deny {
		t.Fatalf("expected Deny, got %v", got)
	}
}

func TestPolicyEngine_AllowsSelectWhenNotInDestructiveSet(t *testing.T) {
	engine := NewPolicyEngine([]PolicyRule{
		{
			Action: "db.exec",
			Effect: Deny,
			Conditions: map[string]any{
				"sql.verb": map[string]any{
					"$in": []any{"DROP", "TRUNCATE", "DELETE"},
				},
			},
		},
		{Action: "db.exec", Effect: Allow},
	})
	ctx := map[string]any{
		"sql": map[string]any{"query": "SELECT * FROM users"},
	}
	if got := engine.Evaluate("db.exec", ctx); got != Allow {
		t.Fatalf("expected Allow, got %v", got)
	}
}

func TestPolicyEngine_DeniesK8sExec(t *testing.T) {
	engine := NewPolicyEngine([]PolicyRule{
		{
			Action: "k8s.request",
			Effect: Deny,
			Conditions: map[string]any{
				"k8s.subresource": "exec",
			},
		},
	})
	ctx := map[string]any{
		"k8s": map[string]any{
			"method": "POST",
			"path":   "/api/v1/namespaces/prod/pods/web/exec",
		},
	}
	if got := engine.Evaluate("k8s.request", ctx); got != Deny {
		t.Fatalf("expected Deny, got %v", got)
	}
}

func TestPolicyEngine_DeniesProductionNamespace(t *testing.T) {
	engine := NewPolicyEngine([]PolicyRule{
		{
			Action: "k8s.request",
			Effect: Deny,
			Conditions: map[string]any{
				"k8s.namespace": "production",
			},
		},
	})
	ctx := map[string]any{
		"k8s": map[string]any{
			"method": "DELETE",
			"path":   "/api/v1/namespaces/production/pods/web",
		},
	}
	if got := engine.Evaluate("k8s.request", ctx); got != Deny {
		t.Fatalf("expected Deny, got %v", got)
	}
}

func TestPolicyEngine_SQLTargetReferenceable(t *testing.T) {
	engine := NewPolicyEngine([]PolicyRule{
		{
			Action: "db.exec",
			Effect: Deny,
			Conditions: map[string]any{
				"sql.target": "protected",
			},
		},
	})
	ctx := map[string]any{
		"sql": map[string]any{"query": "INSERT INTO protected SELECT * FROM staging"},
	}
	if got := engine.Evaluate("db.exec", ctx); got != Deny {
		t.Fatalf("expected Deny, got %v", got)
	}
}

func TestPolicyEngine_DoesNotMutateCallerContext(t *testing.T) {
	engine := NewPolicyEngine(nil)
	sub := map[string]any{"query": "SELECT 1"}
	ctx := map[string]any{"sql": sub}

	_ = engine.Evaluate("anything", ctx)

	if len(sub) != 1 {
		t.Fatalf("caller sub-map mutated; size=%d, contents=%+v", len(sub), sub)
	}
	if _, ok := sub["verb"]; ok {
		t.Fatalf("caller sub-map mutated; got verb=%v", sub["verb"])
	}
	if _, ok := ctx["sql.verb"]; ok {
		t.Fatalf("caller top-level map mutated; got sql.verb=%v", ctx["sql.verb"])
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

// ── Regressions for dialect modifiers and example loader ────────────────────

func TestSQL_InsertOrReplaceIntoTarget(t *testing.T) {
	cases := []string{
		"INSERT OR REPLACE INTO protected (id) VALUES (1)",
		"INSERT OR IGNORE INTO protected (id) VALUES (1)",
		"INSERT IGNORE INTO protected (id) VALUES (1)",
	}
	for _, q := range cases {
		f := sql(q)
		if f["verb"] != "INSERT" || f["target"] != "protected" {
			t.Errorf("%s: got %+v", q, f)
		}
	}
}

func TestSQL_UpdateOnlyTarget(t *testing.T) {
	f := sql("UPDATE ONLY protected SET v = 1 WHERE id = 2")
	if f["target"] != "protected" {
		t.Fatalf("got %+v", f)
	}
}

func TestSQL_DeleteFromOnlyTarget(t *testing.T) {
	f := sql("DELETE FROM ONLY protected WHERE id = 2")
	if f["verb"] != "DELETE" || f["target"] != "protected" {
		t.Fatalf("got %+v", f)
	}
}

func TestSQL_CreateOrReplaceTarget(t *testing.T) {
	f := sql("CREATE OR REPLACE VIEW protected AS SELECT 1")
	if f["verb"] != "CREATE" || f["target"] != "protected" {
		t.Fatalf("got %+v", f)
	}
}

func TestExampleYAML_LoadsCleanly(t *testing.T) {
	path := "../../examples/wire-protocol-rules.yaml"
	engine := NewPolicyEngine(nil)
	if err := engine.LoadFromYAML(path); err != nil {
		t.Fatalf("LoadFromYAML failed: %v", err)
	}
	// A DROP must be denied by the loaded ruleset.
	ctx := map[string]any{
		"sql": map[string]any{"query": "DROP TABLE production"},
	}
	if got := engine.Evaluate("db.exec", ctx); got != Deny {
		t.Fatalf("example yaml did not deny DROP: got %v", got)
	}
}
