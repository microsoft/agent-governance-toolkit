// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"reflect"
	"testing"
)

var contextGovernanceRules = AggregationRuleSet{
	Rules: []AggregationRule{
		{
			Name:             "pii_financial_restricted",
			AllLabels:        []string{"pii", "financial"},
			SetsSensitivity:  DataClassificationRestricted,
			AddsRestrictions: []string{"no_external_export"},
		},
	},
}

func TestFoldContextJoinsLabelsAndRaisesSensitivity(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"pii"},
		AggregateSensitivity: DataClassificationInternal,
	}

	out := FoldContext(env, []string{"financial"}, DataClassificationConfidential)

	if !reflect.DeepEqual(out.Labels, []string{"financial", "pii"}) {
		t.Fatalf("labels = %#v, want financial+pii", out.Labels)
	}
	if out.AggregateSensitivity != DataClassificationConfidential {
		t.Fatalf("aggregate sensitivity = %v, want confidential", out.AggregateSensitivity)
	}
	if out.Version != env.Version+1 {
		t.Fatalf("version = %d, want %d", out.Version, env.Version+1)
	}
	if !reflect.DeepEqual(env.Labels, []string{"pii"}) {
		t.Fatalf("original labels mutated: %#v", env.Labels)
	}
}

func TestFoldContextIsIdempotentAndNeverLowersSensitivity(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"pii"},
		AggregateSensitivity: DataClassificationRestricted,
	}

	out := FoldContext(env, []string{"pii"}, DataClassificationPublic)

	if !reflect.DeepEqual(out.Labels, []string{"pii"}) {
		t.Fatalf("labels = %#v, want pii only", out.Labels)
	}
	if out.AggregateSensitivity != DataClassificationRestricted {
		t.Fatalf("aggregate sensitivity = %v, want restricted", out.AggregateSensitivity)
	}
}

func TestApplyContextRestrictionsIsGrowOnly(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:   "env-1",
		WorkflowID:   "wf-1",
		Restrictions: []string{"no_external_export"},
	}

	out := ApplyContextRestrictions(env, nil)
	if !reflect.DeepEqual(out.Restrictions, []string{"no_external_export"}) {
		t.Fatalf("restrictions = %#v, want original restriction", out.Restrictions)
	}

	out = ApplyContextRestrictions(out, []string{"no_memory_write"})
	if !reflect.DeepEqual(out.Restrictions, []string{"no_external_export", "no_memory_write"}) {
		t.Fatalf("restrictions = %#v, want both restrictions", out.Restrictions)
	}
}

func TestContextEnvelopeReferenceOmitsEnvelopeContents(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"pii", "financial"},
		AggregateSensitivity: DataClassificationRestricted,
		Restrictions:         []string{"no_external_export"},
		Version:              7,
		ParentEnvelopeID:     "parent-1",
	}

	ref := ContextEnvelopeReference(env)

	if ref.EnvelopeID != env.EnvelopeID {
		t.Fatalf("envelope id = %q, want %q", ref.EnvelopeID, env.EnvelopeID)
	}
	if ref.Sensitivity != env.AggregateSensitivity {
		t.Fatalf("sensitivity = %v, want %v", ref.Sensitivity, env.AggregateSensitivity)
	}

	refFields := reflect.TypeOf(ref)
	if refFields.NumField() != 2 {
		t.Fatalf("reference exposes %d fields, want 2", refFields.NumField())
	}
}

func TestEvaluateAggregationRuleAndBackstop(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"financial", "pii"},
		AggregateSensitivity: DataClassificationInternal,
	}

	result := EvaluateAggregation(env, contextGovernanceRules, 99)

	if result.AggregateSensitivity != DataClassificationRestricted {
		t.Fatalf("aggregate sensitivity = %v, want restricted", result.AggregateSensitivity)
	}
	if !reflect.DeepEqual(result.Restrictions, []string{"no_external_export"}) {
		t.Fatalf("restrictions = %#v, want no_external_export", result.Restrictions)
	}
	if !reflect.DeepEqual(result.RulesApplied, []string{"pii_financial_restricted"}) {
		t.Fatalf("rules applied = %#v, want pii_financial_restricted", result.RulesApplied)
	}
	if result.Escalate {
		t.Fatal("escalate = true, want false for governed combination")
	}

	unknown := EvaluateAggregation(ContextEnvelope{
		EnvelopeID:           "env-2",
		WorkflowID:           "wf-1",
		Labels:               []string{"a", "b", "c"},
		AggregateSensitivity: DataClassificationInternal,
	}, contextGovernanceRules, 3)
	if !unknown.Escalate {
		t.Fatal("escalate = false, want true for unknown combination at threshold")
	}
}

func TestAccumulateContextFoldsAndAppliesAggregationRestrictions(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"pii"},
		AggregateSensitivity: DataClassificationInternal,
	}

	out := AccumulateContext(env, []string{"financial"}, DataClassificationConfidential, contextGovernanceRules, 99)

	if !reflect.DeepEqual(out.Labels, []string{"financial", "pii"}) {
		t.Fatalf("labels = %#v, want financial+pii", out.Labels)
	}
	if out.AggregateSensitivity != DataClassificationRestricted {
		t.Fatalf("aggregate sensitivity = %v, want restricted", out.AggregateSensitivity)
	}
	if !reflect.DeepEqual(out.Restrictions, []string{"no_external_export"}) {
		t.Fatalf("restrictions = %#v, want no_external_export", out.Restrictions)
	}
	if out.Version != env.Version+2 {
		t.Fatalf("version = %d, want %d", out.Version, env.Version+2)
	}
}

func TestDecideNextContextGatesRestrictedActions(t *testing.T) {
	env := AccumulateContext(ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"pii"},
		AggregateSensitivity: DataClassificationInternal,
	}, []string{"financial"}, DataClassificationConfidential, contextGovernanceRules, 99)

	decision := DecideNextContext(env, "export", contextGovernanceRules, 99)

	if decision.Outcome != ContextOutcomeConstrain {
		t.Fatalf("outcome = %q, want constrain", decision.Outcome)
	}
	if len(decision.Obligations.Obligations) != 1 || decision.Obligations.Obligations[0].Key != "no_external_export" {
		t.Fatalf("obligations = %#v, want no_external_export", decision.Obligations.Obligations)
	}
	if decision.PolicyDecision(false) != Deny {
		t.Fatalf("policy decision without channel = %q, want deny", decision.PolicyDecision(false))
	}
	if decision.PolicyDecision(true) != Allow {
		t.Fatalf("policy decision with channel = %q, want allow", decision.PolicyDecision(true))
	}
}

func TestDecideNextContextExplicitRestrictionGatesBelowFloor(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"pii"},
		AggregateSensitivity: DataClassificationConfidential,
		Restrictions:         []string{"no_external_export"},
	}

	decision := DecideNextContext(env, "export", contextGovernanceRules, 99)
	if decision.Outcome != ContextOutcomeConstrain {
		t.Fatalf("outcome = %q, want constrain", decision.Outcome)
	}
}

func TestDecideNextContextFloorGatesFlowActionWithoutExplicitRestriction(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"pii"},
		AggregateSensitivity: DataClassificationRestricted,
	}

	decision := DecideNextContext(env, "export", contextGovernanceRules, 99)
	if decision.Outcome != ContextOutcomeConstrain {
		t.Fatalf("outcome = %q, want constrain", decision.Outcome)
	}
	if len(decision.Obligations.Obligations) != 0 {
		t.Fatalf("obligations = %#v, want none", decision.Obligations.Obligations)
	}
	if decision.PolicyDecision(false) != Deny {
		t.Fatalf("policy decision = %q, want deny", decision.PolicyDecision(false))
	}
}

func TestDecideNextContextEscalatesUnknownCombinations(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"a", "b", "c"},
		AggregateSensitivity: DataClassificationInternal,
	}

	decision := DecideNextContext(env, "read", contextGovernanceRules, 3)

	if decision.Outcome != ContextOutcomeEscalate {
		t.Fatalf("outcome = %q, want escalate", decision.Outcome)
	}
	if decision.PolicyDecision(false) != Review {
		t.Fatalf("policy decision = %q, want review", decision.PolicyDecision(false))
	}
}

func TestConstrainWithoutObligationsFailsClosed(t *testing.T) {
	decision := ContextDecision{
		Outcome:              ContextOutcomeConstrain,
		Obligations:          ContextObligationSet{},
		AggregateSensitivity: DataClassificationRestricted,
	}

	if decision.PolicyDecision(false) != Deny {
		t.Fatalf("policy decision = %q, want deny", decision.PolicyDecision(false))
	}
}

func TestSatisfiedObligationAllowsWithoutChannel(t *testing.T) {
	decision := ContextDecision{
		Outcome: ContextOutcomeConstrain,
		Obligations: ContextObligationSet{
			Obligations: []ContextObligation{{Key: "no_external_export", Satisfied: true}},
		},
		AggregateSensitivity: DataClassificationRestricted,
	}

	if decision.PolicyDecision(false) != Allow {
		t.Fatalf("policy decision = %q, want allow", decision.PolicyDecision(false))
	}
}

func TestMergeContextRestrictionsAndDelegateContextInheritParentRestrictions(t *testing.T) {
	parent := ContextEnvelope{
		EnvelopeID:           "parent-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"pii"},
		AggregateSensitivity: DataClassificationRestricted,
		Restrictions:         []string{"no_external_export"},
	}

	merged := MergeContextRestrictions(parent, []string{"no_memory_write"})
	if !reflect.DeepEqual(merged, []string{"no_external_export", "no_memory_write"}) {
		t.Fatalf("merged restrictions = %#v, want parent+child restrictions", merged)
	}

	child := DelegateContext(parent, "child-1", []string{"no_memory_write"})
	if child.ParentEnvelopeID != parent.EnvelopeID {
		t.Fatalf("parent envelope id = %q, want %q", child.ParentEnvelopeID, parent.EnvelopeID)
	}
	if !reflect.DeepEqual(child.Restrictions, []string{"no_external_export", "no_memory_write"}) {
		t.Fatalf("child restrictions = %#v, want inherited restrictions", child.Restrictions)
	}
	if child.AggregateSensitivity != parent.AggregateSensitivity {
		t.Fatalf("child sensitivity = %v, want %v", child.AggregateSensitivity, parent.AggregateSensitivity)
	}
}
