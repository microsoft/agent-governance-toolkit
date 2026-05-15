// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type failingBackend struct{}

type staticBackend struct {
	name   string
	result BackendDecision
}

func (f failingBackend) Name() string {
	return "failing"
}

func (f failingBackend) Evaluate(context map[string]interface{}) (BackendDecision, error) {
	return BackendDecision{}, fmt.Errorf("backend failure")
}

func (s staticBackend) Name() string {
	return s.name
}

func (s staticBackend) Evaluate(context map[string]interface{}) (BackendDecision, error) {
	return s.result, nil
}

func TestPolicyEngineUsesOPABuiltinBackend(t *testing.T) {
	pe := NewPolicyEngine(nil)
	pe.LoadRego(OPAOptions{
		Mode: OPABuiltin,
		RegoContent: `package agentmesh
default allow = false
allow {
  input.tool_name == "data.read"
}`,
	})

	if decision := pe.Evaluate("data.read", nil); decision != Allow {
		t.Fatalf("decision = %q, want allow", decision)
	}
	if decision := pe.Evaluate("data.write", nil); decision != Deny {
		t.Fatalf("decision = %q, want deny", decision)
	}
}

func TestPolicyEngineUsesCedarBuiltinBackend(t *testing.T) {
	pe := NewPolicyEngine(nil)
	pe.LoadCedar(CedarOptions{
		Mode: CedarBuiltin,
		PolicyContent: `permit(
    principal,
    action == Action::"DataRead",
    resource
);`,
	})

	if decision := pe.Evaluate("data.read", nil); decision != Allow {
		t.Fatalf("decision = %q, want allow", decision)
	}
	if decision := pe.Evaluate("data.delete", nil); decision != Deny {
		t.Fatalf("decision = %q, want deny", decision)
	}
}

func TestPolicyEngineNativeRulesWinBeforeBackend(t *testing.T) {
	pe := NewPolicyEngine([]PolicyRule{
		{Action: "data.read", Effect: Review},
	})
	pe.LoadRego(OPAOptions{
		Mode: OPABuiltin,
		RegoContent: `package agentmesh
default allow = true`,
	})

	if decision := pe.Evaluate("data.read", nil); decision != Review {
		t.Fatalf("decision = %q, want review", decision)
	}
}

func TestPolicyEngineBackendFailureFailsClosed(t *testing.T) {
	pe := NewPolicyEngine(nil)
	pe.AddBackend(failingBackend{})

	if decision := pe.Evaluate("data.read", nil); decision != Deny {
		t.Fatalf("decision = %q, want deny", decision)
	}
}

func TestPolicyEngineAllBackendsMustAllow(t *testing.T) {
	pe := NewPolicyEngine(nil)
	pe.AddBackend(staticBackend{
		name: "opa",
		result: BackendDecision{
			Allowed:  true,
			Decision: Allow,
		},
	})
	pe.AddBackend(staticBackend{
		name: "cedar",
		result: BackendDecision{
			Allowed:  true,
			Decision: Allow,
		},
	})

	if decision := pe.Evaluate("data.read", nil); decision != Allow {
		t.Fatalf("decision = %q, want allow", decision)
	}
}

func TestPolicyEngineBackendDenyFailsClosed(t *testing.T) {
	pe := NewPolicyEngine(nil)
	pe.AddBackend(staticBackend{
		name: "opa",
		result: BackendDecision{
			Allowed:  true,
			Decision: Allow,
		},
	})
	pe.AddBackend(staticBackend{
		name: "cedar",
		result: BackendDecision{
			Allowed:  false,
			Decision: Deny,
		},
	})

	if decision := pe.Evaluate("data.read", nil); decision != Deny {
		t.Fatalf("decision = %q, want deny", decision)
	}
}

func TestPolicyEngineLaterBackendFailureFailsClosed(t *testing.T) {
	pe := NewPolicyEngine(nil)
	pe.AddBackend(staticBackend{
		name: "opa",
		result: BackendDecision{
			Allowed:  true,
			Decision: Allow,
		},
	})
	pe.AddBackend(failingBackend{})

	if decision := pe.Evaluate("data.read", nil); decision != Deny {
		t.Fatalf("decision = %q, want deny", decision)
	}
}

func TestOPABackendRemote(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"result": true})
	}))
	defer server.Close()

	backend := NewOPABackend(OPAOptions{
		Mode:   OPARemote,
		OPAURL: server.URL,
		Query:  "data.agentmesh.allow",
	})

	result, err := backend.Evaluate(map[string]interface{}{"tool_name": "data.read"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !result.Allowed || result.Decision != Allow {
		t.Fatalf("result = %+v, want allow", result)
	}
}

func TestOPABackendAutoFailsClosedWithoutCLI(t *testing.T) {
	previous := opaLookPath
	opaLookPath = func(file string) (string, error) {
		return "", fmt.Errorf("%s not found", file)
	}
	t.Cleanup(func() {
		opaLookPath = previous
	})

	backend := NewOPABackend(OPAOptions{
		Mode: OPAAuto,
		RegoContent: `package agentmesh
default allow = false
allow {
  input.tool_name == "data.read"
}`,
	})

	result, err := backend.Evaluate(map[string]interface{}{"tool_name": "data.read"})
	if err == nil {
		t.Fatalf("Evaluate error = nil, want error")
	}
	if result.Decision != "" || result.Allowed {
		t.Fatalf("result = %+v, want zero decision on error", result)
	}
	if !strings.Contains(err.Error(), "AllowBuiltinFallback") {
		t.Fatalf("error = %q, want AllowBuiltinFallback guidance", err)
	}
}

func TestOPABackendAutoUsesBuiltinWhenFallbackExplicitlyEnabled(t *testing.T) {
	previous := opaLookPath
	opaLookPath = func(file string) (string, error) {
		return "", fmt.Errorf("%s not found", file)
	}
	t.Cleanup(func() {
		opaLookPath = previous
	})

	backend := NewOPABackend(OPAOptions{
		Mode:                 OPAAuto,
		AllowBuiltinFallback: true,
		RegoContent: `package agentmesh
default allow = false
allow {
  input.tool_name == "data.read"
}`,
	})

	result, err := backend.Evaluate(map[string]interface{}{"tool_name": "data.read"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !result.Allowed || result.Decision != Allow {
		t.Fatalf("result = %+v, want allow", result)
	}
	if !strings.Contains(result.Reason, "auto fallback enabled") {
		t.Fatalf("reason = %q, want explicit fallback marker", result.Reason)
	}
}

func TestCedarBackendAutoFailsClosedWithoutCLI(t *testing.T) {
	previous := cedarLookPath
	cedarLookPath = func(file string) (string, error) {
		return "", fmt.Errorf("%s not found", file)
	}
	t.Cleanup(func() {
		cedarLookPath = previous
	})

	backend := NewCedarBackend(CedarOptions{
		Mode: CedarAuto,
		PolicyContent: `permit(
    principal,
    action == Action::"DataRead",
    resource
);`,
	})

	result, err := backend.Evaluate(map[string]interface{}{"tool_name": "data.read"})
	if err == nil {
		t.Fatalf("Evaluate error = nil, want error")
	}
	if result.Decision != "" || result.Allowed {
		t.Fatalf("result = %+v, want zero decision on error", result)
	}
	if !strings.Contains(err.Error(), "AllowBuiltinFallback") {
		t.Fatalf("error = %q, want AllowBuiltinFallback guidance", err)
	}
}

func TestCedarBackendAutoUsesBuiltinWhenFallbackExplicitlyEnabled(t *testing.T) {
	previous := cedarLookPath
	cedarLookPath = func(file string) (string, error) {
		return "", fmt.Errorf("%s not found", file)
	}
	t.Cleanup(func() {
		cedarLookPath = previous
	})

	backend := NewCedarBackend(CedarOptions{
		Mode:                 CedarAuto,
		AllowBuiltinFallback: true,
		PolicyContent: `permit(
    principal,
    action == Action::"DataRead",
    resource
);`,
	})

	result, err := backend.Evaluate(map[string]interface{}{"tool_name": "data.read"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !result.Allowed || result.Decision != Allow {
		t.Fatalf("result = %+v, want allow", result)
	}
	if !strings.Contains(result.Reason, "auto fallback enabled") {
		t.Fatalf("reason = %q, want explicit fallback marker", result.Reason)
	}
}

func TestCedarDecisionFromCLIOutput(t *testing.T) {
	tests := []struct {
		name        string
		stdout      string
		wantAllowed bool
		wantParsed  bool
	}{
		{name: "bare allow", stdout: "ALLOW\n", wantAllowed: true, wantParsed: true},
		{name: "bare deny", stdout: "DENY\n", wantAllowed: false, wantParsed: true},
		{name: "lowercase allow", stdout: "allow", wantAllowed: true, wantParsed: true},
		{name: "lowercase deny", stdout: "deny", wantAllowed: false, wantParsed: true},
		{name: "allow with trailing whitespace", stdout: "  ALLOW  \n", wantAllowed: true, wantParsed: true},
		{name: "leading blank lines then deny", stdout: "\n\nDENY\n", wantAllowed: false, wantParsed: true},
		// The substring approach this PR removes would have mis-classified
		// the following outputs. The first-line parse refuses them rather
		// than guessing.
		{name: "deny with allow inside reason — must not coincide", stdout: "DENY (request disallowed by policy)\n", wantParsed: false},
		{name: "allow with deny mentioned in caveat — must not coincide", stdout: "ALLOW: caveats reference the deny-list scoping\n", wantParsed: false},
		// Genuine garbage.
		{name: "garbage", stdout: "I am not a Cedar decision\n", wantParsed: false},
		{name: "empty", stdout: "", wantParsed: false},
		{name: "only whitespace", stdout: "   \n\n", wantParsed: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, parsed := cedarDecisionFromCLIOutput(tt.stdout)
			if parsed != tt.wantParsed {
				t.Fatalf("parsed = %v, want %v (stdout = %q)", parsed, tt.wantParsed, tt.stdout)
			}
			if parsed && allowed != tt.wantAllowed {
				t.Fatalf("allowed = %v, want %v", allowed, tt.wantAllowed)
			}
		})
	}
}
