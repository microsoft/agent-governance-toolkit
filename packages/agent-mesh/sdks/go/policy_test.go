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
