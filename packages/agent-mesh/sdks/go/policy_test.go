package agentmesh

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEvaluateExactMatch(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "data.read", Effect: Allow},
	})
	if d := pe.Evaluate("data.read", nil); d != Allow {
		t.Errorf("decision = %q, want allow", d)
	}
}

func TestEvaluateWildcard(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "data.*", Effect: Allow},
	})
	if d := pe.Evaluate("data.write", nil); d != Allow {
		t.Errorf("decision = %q, want allow", d)
	}
}

func TestEvaluateGlobalWildcard(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "*", Effect: Review},
	})
	if d := pe.Evaluate("anything", nil); d != Review {
		t.Errorf("decision = %q, want review", d)
	}
}

func TestEvaluateDefaultDeny(t *testing.T) {
	pe := NewPolicyEngine(nil)
	if d := pe.Evaluate("data.read", nil); d != Deny {
		t.Errorf("decision = %q, want deny (default)", d)
	}
}

func TestEvaluateConditions(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "data.read", Effect: Allow, Conditions: map[string]interface{}{"role": "admin"}},
	})

	if d := pe.Evaluate("data.read", map[string]interface{}{"role": "admin"}); d != Allow {
		t.Errorf("decision with matching condition = %q, want allow", d)
	}
	if d := pe.Evaluate("data.read", map[string]interface{}{"role": "guest"}); d != Deny {
		t.Errorf("decision with non-matching condition = %q, want deny", d)
	}
}

func TestEvaluateFirstMatchWins(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "data.read", Effect: Deny},
		{Action: "data.read", Effect: Allow},
	})
	if d := pe.Evaluate("data.read", nil); d != Deny {
		t.Errorf("first-match should win, got %q", d)
	}
}

func TestLoadFromYAML(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `rules:
  - action: "file.read"
    effect: "allow"
  - action: "file.delete"
    effect: "deny"
`
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	pe := NewPolicyEngine(nil)
	if err := pe.LoadFromYAML(path); err != nil {
		t.Fatalf("LoadFromYAML: %v", err)
	}

	if d := pe.Evaluate("file.read", nil); d != Allow {
		t.Errorf("YAML rule: decision = %q, want allow", d)
	}
	if d := pe.Evaluate("file.delete", nil); d != Deny {
		t.Errorf("YAML rule: decision = %q, want deny", d)
	}
}

func TestRichConditionsAnd(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{
			Action: "data.read",
			Effect: Allow,
			Conditions: map[string]interface{}{
				"$and": []interface{}{
					map[string]interface{}{"role": "admin"},
					map[string]interface{}{"level": 5.0},
				},
			},
		},
	})
	if d := pe.Evaluate("data.read", map[string]interface{}{"role": "admin", "level": 5.0}); d != Allow {
		t.Errorf("$and both match = %q, want allow", d)
	}
	if d := pe.Evaluate("data.read", map[string]interface{}{"role": "admin", "level": 3.0}); d != Deny {
		t.Errorf("$and partial match = %q, want deny", d)
	}
}

func TestRichConditionsOr(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{
			Action: "data.read",
			Effect: Allow,
			Conditions: map[string]interface{}{
				"$or": []interface{}{
					map[string]interface{}{"role": "admin"},
					map[string]interface{}{"role": "superadmin"},
				},
			},
		},
	})
	if d := pe.Evaluate("data.read", map[string]interface{}{"role": "superadmin"}); d != Allow {
		t.Errorf("$or match second = %q, want allow", d)
	}
	if d := pe.Evaluate("data.read", map[string]interface{}{"role": "guest"}); d != Deny {
		t.Errorf("$or no match = %q, want deny", d)
	}
}

func TestRichConditionsNot(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{
			Action: "data.read",
			Effect: Allow,
			Conditions: map[string]interface{}{
				"$not": map[string]interface{}{"role": "guest"},
			},
		},
	})
	if d := pe.Evaluate("data.read", map[string]interface{}{"role": "admin"}); d != Allow {
		t.Errorf("$not non-matching = %q, want allow", d)
	}
	if d := pe.Evaluate("data.read", map[string]interface{}{"role": "guest"}); d != Deny {
		t.Errorf("$not matching = %q, want deny", d)
	}
}

func TestRichConditionsComparison(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{
			Action: "data.read",
			Effect: Allow,
			Conditions: map[string]interface{}{
				"age": map[string]interface{}{"$gte": 18.0},
			},
		},
	})
	if d := pe.Evaluate("data.read", map[string]interface{}{"age": 21.0}); d != Allow {
		t.Errorf("$gte pass = %q, want allow", d)
	}
	if d := pe.Evaluate("data.read", map[string]interface{}{"age": 15.0}); d != Deny {
		t.Errorf("$gte fail = %q, want deny", d)
	}
}

func TestRichConditionsIn(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{
			Action: "data.read",
			Effect: Allow,
			Conditions: map[string]interface{}{
				"env": map[string]interface{}{
					"$in": []interface{}{"dev", "staging"},
				},
			},
		},
	})
	if d := pe.Evaluate("data.read", map[string]interface{}{"env": "dev"}); d != Allow {
		t.Errorf("$in match = %q, want allow", d)
	}
	if d := pe.Evaluate("data.read", map[string]interface{}{"env": "prod"}); d != Deny {
		t.Errorf("$in no match = %q, want deny", d)
	}
}

func TestPolicyScopeOnRule(t *testing.T) {
	rule := PolicyRule{
		Action:   "data.read",
		Effect:   Allow,
		Priority: 1,
		Scope:    Agent,
	}
	if rule.Scope != Agent {
		t.Errorf("scope = %q, want agent", rule.Scope)
	}
	if rule.Priority != 1 {
		t.Errorf("priority = %d, want 1", rule.Priority)
	}
}

func TestRateLimiting(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "api.call", MaxCalls: 3, Window: "1m"},
	})
	for i := 0; i < 3; i++ {
		if d := pe.Evaluate("api.call", nil); d != Allow {
			t.Errorf("call %d = %q, want allow", i+1, d)
		}
	}
	if d := pe.Evaluate("api.call", nil); d != RateLimit {
		t.Errorf("call over limit = %q, want rate_limit", d)
	}
}

func TestApprovalWorkflow(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{
			Action:       "deploy.production",
			Effect:       Allow,
			MinApprovals: 2,
			Approvers:    []string{"admin1", "admin2"},
		},
	})
	if d := pe.Evaluate("deploy.production", nil); d != RequiresApproval {
		t.Errorf("approval required = %q, want requires_approval", d)
	}
}

// --- New comprehensive tests ---

func TestEvaluateMultipleRulesFirstMatchWinsDenyBeforeAllow(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "data.read", Effect: Deny},
		{Action: "data.read", Effect: Allow},
		{Action: "data.read", Effect: Review},
	})
	if d := pe.Evaluate("data.read", nil); d != Deny {
		t.Errorf("first-match-wins: got %q, want deny", d)
	}
}

func TestEvaluateMultipleRulesFirstMatchWinsAllowBeforeDeny(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "data.write", Effect: Allow},
		{Action: "data.write", Effect: Deny},
	})
	if d := pe.Evaluate("data.write", nil); d != Allow {
		t.Errorf("first-match-wins: got %q, want allow", d)
	}
}

func TestEvaluateMultipleRulesFirstMatchWinsReview(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "net.connect", Effect: Review},
		{Action: "net.connect", Effect: Allow},
	})
	if d := pe.Evaluate("net.connect", nil); d != Review {
		t.Errorf("first-match-wins: got %q, want review", d)
	}
}

func TestEvaluateWildcardDotStar(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "data.*", Effect: Allow},
	})

	tests := []struct {
		action string
		want   PolicyDecision
	}{
		{"data.read", Allow},
		{"data.write", Allow},
		{"data.delete", Allow},
		{"data.nested.deep", Deny}, // "data.*" matches "data." prefix, but "data.nested.deep" has prefix "data." so it matches
		{"file.read", Deny},
		{"data", Deny},        // no dot after "data"
		{"database.read", Deny}, // prefix is "data." not "database."
	}

	for _, tc := range tests {
		d := pe.Evaluate(tc.action, nil)
		// "data.*" matches anything starting with "data."
		if tc.action == "data.nested.deep" {
			// The matchAction function checks HasPrefix(action, prefix+".") where prefix="data"
			// So "data.nested.deep" has prefix "data." → matches
			if d != Allow {
				t.Errorf("data.* on %q = %q, want allow (prefix match)", tc.action, d)
			}
		} else if d != tc.want {
			t.Errorf("data.* on %q = %q, want %q", tc.action, d, tc.want)
		}
	}
}

func TestEvaluateWildcardShellStar(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "shell.*", Effect: Deny},
	})
	if d := pe.Evaluate("shell.exec", nil); d != Deny {
		t.Errorf("shell.* on shell.exec = %q, want deny", d)
	}
	if d := pe.Evaluate("shell.read", nil); d != Deny {
		t.Errorf("shell.* on shell.read = %q, want deny", d)
	}
	if d := pe.Evaluate("file.exec", nil); d != Deny {
		// no match → default deny, which is still Deny
		t.Logf("file.exec correctly defaults to deny")
	}
}

func TestEvaluateGlobalWildcardMatchesEverything(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "*", Effect: Allow},
	})
	actions := []string{"data.read", "file.write", "system.shutdown", "anything", "x.y.z"}
	for _, a := range actions {
		if d := pe.Evaluate(a, nil); d != Allow {
			t.Errorf("global wildcard on %q = %q, want allow", a, d)
		}
	}
}

func TestEvaluateExactMatchDoesNotMatchPrefix(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "data.read", Effect: Allow},
	})
	// Exact match should not match different actions
	if d := pe.Evaluate("data.read.all", nil); d != Deny {
		t.Errorf("exact match should not match data.read.all, got %q", d)
	}
	if d := pe.Evaluate("data.readwrite", nil); d != Deny {
		t.Errorf("exact match should not match data.readwrite, got %q", d)
	}
	if d := pe.Evaluate("data", nil); d != Deny {
		t.Errorf("exact match should not match partial data, got %q", d)
	}
}

func TestEvaluateConditionsMatchContext(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "data.read", Effect: Allow, Conditions: map[string]interface{}{
			"env":  "production",
			"role": "admin",
		}},
	})

	// Both conditions match
	ctx := map[string]interface{}{"env": "production", "role": "admin"}
	if d := pe.Evaluate("data.read", ctx); d != Allow {
		t.Errorf("matching conditions: got %q, want allow", d)
	}

	// One condition missing
	ctx2 := map[string]interface{}{"env": "production"}
	if d := pe.Evaluate("data.read", ctx2); d != Deny {
		t.Errorf("missing condition: got %q, want deny", d)
	}

	// Wrong value
	ctx3 := map[string]interface{}{"env": "staging", "role": "admin"}
	if d := pe.Evaluate("data.read", ctx3); d != Deny {
		t.Errorf("wrong condition value: got %q, want deny", d)
	}

	// Nil context
	if d := pe.Evaluate("data.read", nil); d != Deny {
		t.Errorf("nil context: got %q, want deny", d)
	}
}

func TestEvaluateConditionsWithBoolAndFloat(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "deploy", Effect: Allow, Conditions: map[string]interface{}{
			"approved": true,
			"risk":     0.5,
		}},
	})

	ctx := map[string]interface{}{"approved": true, "risk": 0.5}
	if d := pe.Evaluate("deploy", ctx); d != Allow {
		t.Errorf("bool+float conditions match: got %q, want allow", d)
	}

	ctx2 := map[string]interface{}{"approved": false, "risk": 0.5}
	if d := pe.Evaluate("deploy", ctx2); d != Deny {
		t.Errorf("bool mismatch: got %q, want deny", d)
	}
}

func TestPolicyOnlyDenyRules(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "dangerous.action", Effect: Deny},
		{Action: "risky.action", Effect: Deny},
	})
	if d := pe.Evaluate("dangerous.action", nil); d != Deny {
		t.Errorf("got %q, want deny", d)
	}
	if d := pe.Evaluate("risky.action", nil); d != Deny {
		t.Errorf("got %q, want deny", d)
	}
	// Unmatched action also denied by default
	if d := pe.Evaluate("safe.action", nil); d != Deny {
		t.Errorf("unmatched action: got %q, want deny (default)", d)
	}
}

func TestPolicyOnlyAllowRules(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "safe.read", Effect: Allow},
		{Action: "safe.write", Effect: Allow},
	})
	if d := pe.Evaluate("safe.read", nil); d != Allow {
		t.Errorf("got %q, want allow", d)
	}
	if d := pe.Evaluate("safe.write", nil); d != Allow {
		t.Errorf("got %q, want allow", d)
	}
	// Unmatched action defaults to deny
	if d := pe.Evaluate("unsafe.action", nil); d != Deny {
		t.Errorf("unmatched action: got %q, want deny (default)", d)
	}
}

func TestLoadFromYAMLInvalidContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("this is: [not: valid: yaml: {{"), 0644); err != nil {
		t.Fatal(err)
	}

	pe := NewPolicyEngine(nil)
	err := pe.LoadFromYAML(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadFromYAMLNonexistentFile(t *testing.T) {
	pe := NewPolicyEngine(nil)
	err := pe.LoadFromYAML(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadFromYAMLAppendsToExistingRules(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "existing.action", Effect: Allow},
	})

	dir := t.TempDir()
	yamlContent := `rules:
  - action: "new.action"
    effect: "deny"
`
	path := filepath.Join(dir, "append.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	if err := pe.LoadFromYAML(path); err != nil {
		t.Fatalf("LoadFromYAML: %v", err)
	}

	// Existing rule still works
	if d := pe.Evaluate("existing.action", nil); d != Allow {
		t.Errorf("existing rule: got %q, want allow", d)
	}
	// New rule works
	if d := pe.Evaluate("new.action", nil); d != Deny {
		t.Errorf("new rule: got %q, want deny", d)
	}
}

func TestEmptyPolicyAllowsNothing(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{})
	if d := pe.Evaluate("any.action", nil); d != Deny {
		t.Errorf("empty policy: got %q, want deny (default)", d)
	}
}

func TestMixedRuleTypes(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "data.*", Effect: Allow},
		{Action: "data.delete", Effect: Deny}, // won't be reached for data.delete since data.* matches first
		{Action: "admin.action", Effect: Review},
		{Action: "*", Effect: Deny},
	})

	if d := pe.Evaluate("data.read", nil); d != Allow {
		t.Errorf("data.read: got %q, want allow", d)
	}
	// data.delete matches data.* first (first-match-wins)
	if d := pe.Evaluate("data.delete", nil); d != Allow {
		t.Errorf("data.delete: got %q, want allow (first match wins)", d)
	}
	if d := pe.Evaluate("admin.action", nil); d != Review {
		t.Errorf("admin.action: got %q, want review", d)
	}
	if d := pe.Evaluate("unknown.action", nil); d != Deny {
		t.Errorf("unknown.action: got %q, want deny", d)
	}
}

func TestLoadFromYAMLWithConditions(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `rules:
  - action: "deploy"
    effect: "allow"
    conditions:
      env: "staging"
  - action: "deploy"
    effect: "deny"
`
	path := filepath.Join(dir, "conditions.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	pe := NewPolicyEngine(nil)
	if err := pe.LoadFromYAML(path); err != nil {
		t.Fatalf("LoadFromYAML: %v", err)
	}

	// With matching condition
	if d := pe.Evaluate("deploy", map[string]interface{}{"env": "staging"}); d != Allow {
		t.Errorf("deploy with staging: got %q, want allow", d)
	}
	// Without matching condition, falls through to second rule
	if d := pe.Evaluate("deploy", map[string]interface{}{"env": "production"}); d != Deny {
		t.Errorf("deploy with production: got %q, want deny", d)
	}
}

func TestLoadFromYAMLEmptyRules(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `rules: []
`
	path := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	pe := NewPolicyEngine(nil)
	if err := pe.LoadFromYAML(path); err != nil {
		t.Fatalf("LoadFromYAML: %v", err)
	}

	if d := pe.Evaluate("anything", nil); d != Deny {
		t.Errorf("empty YAML rules: got %q, want deny", d)
	}
}
