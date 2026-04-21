// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import "testing"

func TestDenyOverrides(t *testing.T) {
	r := &PolicyConflictResolver{Strategy: DenyOverrides}
	candidates := []CandidateDecision{
		{Rule: PolicyRule{Action: "data.read", Effect: Allow}, Decision: Allow},
		{Rule: PolicyRule{Action: "data.read", Effect: Deny}, Decision: Deny},
	}
	if d := r.Resolve(candidates); d != Deny {
		t.Errorf("DenyOverrides = %q, want deny", d)
	}
}

func TestDenyOverridesAllAllow(t *testing.T) {
	r := &PolicyConflictResolver{Strategy: DenyOverrides}
	candidates := []CandidateDecision{
		{Rule: PolicyRule{Action: "data.read", Effect: Allow}, Decision: Allow},
		{Rule: PolicyRule{Action: "data.read", Effect: Review}, Decision: Review},
	}
	if d := r.Resolve(candidates); d != Allow {
		t.Errorf("DenyOverrides with no deny = %q, want allow", d)
	}
}

func TestAllowOverrides(t *testing.T) {
	r := &PolicyConflictResolver{Strategy: AllowOverrides}
	candidates := []CandidateDecision{
		{Rule: PolicyRule{Action: "data.read", Effect: Deny}, Decision: Deny},
		{Rule: PolicyRule{Action: "data.read", Effect: Allow}, Decision: Allow},
	}
	if d := r.Resolve(candidates); d != Allow {
		t.Errorf("AllowOverrides = %q, want allow", d)
	}
}

func TestAllowOverridesNoneAllow(t *testing.T) {
	r := &PolicyConflictResolver{Strategy: AllowOverrides}
	candidates := []CandidateDecision{
		{Rule: PolicyRule{Action: "data.read", Effect: Deny}, Decision: Deny},
		{Rule: PolicyRule{Action: "data.read", Effect: Review}, Decision: Review},
	}
	if d := r.Resolve(candidates); d != Deny {
		t.Errorf("AllowOverrides with no allow = %q, want deny", d)
	}
}

func TestPriorityFirstMatch(t *testing.T) {
	r := &PolicyConflictResolver{Strategy: PriorityFirstMatch}
	candidates := []CandidateDecision{
		{Rule: PolicyRule{Action: "data.read", Effect: Deny, Priority: 10}, Decision: Deny},
		{Rule: PolicyRule{Action: "data.read", Effect: Allow, Priority: 1}, Decision: Allow},
	}
	if d := r.Resolve(candidates); d != Allow {
		t.Errorf("PriorityFirstMatch = %q, want allow (priority 1)", d)
	}
}

func TestMostSpecificWins(t *testing.T) {
	r := &PolicyConflictResolver{Strategy: MostSpecificWins}
	candidates := []CandidateDecision{
		{
			Rule:     PolicyRule{Action: "*", Effect: Deny, Scope: Global},
			Decision: Deny,
		},
		{
			Rule: PolicyRule{
				Action:     "data.read",
				Effect:     Allow,
				Scope:      Agent,
				Conditions: map[string]interface{}{"role": "admin"},
			},
			Decision: Allow,
		},
	}
	if d := r.Resolve(candidates); d != Allow {
		t.Errorf("MostSpecificWins = %q, want allow (more specific)", d)
	}
}

func TestResolveEmptyCandidates(t *testing.T) {
	r := &PolicyConflictResolver{Strategy: DenyOverrides}
	if d := r.Resolve(nil); d != Deny {
		t.Errorf("empty candidates = %q, want deny", d)
	}
}
