// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
