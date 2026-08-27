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

func TestNewContextEnvelopeUsesCallerSuppliedCreatedAt(t *testing.T) {
	const createdAt = "2026-07-27T08:30:00Z"

	env := NewContextEnvelope("env-1", "wf-1", createdAt)

	if env.CreatedAt != createdAt {
		t.Fatalf("created at = %q, want %q", env.CreatedAt, createdAt)
	}
	if env.AggregateSensitivity != DataClassificationPublic {
		t.Fatalf("aggregate sensitivity = %v, want public", env.AggregateSensitivity)
	}
}

func TestDataClassificationDefinedRejectsOutOfRangeValues(t *testing.T) {
	for _, classification := range []DataClassification{
		DataClassificationPublic,
		DataClassificationInternal,
		DataClassificationConfidential,
		DataClassificationRestricted,
		DataClassificationTopSecret,
	} {
		if !classification.Defined() {
			t.Fatalf("classification %d should be defined", classification)
		}
	}

	for _, classification := range []DataClassification{-1, 5, 99} {
		if classification.Defined() {
			t.Fatalf("classification %d should be undefined", classification)
		}
	}
}

func TestFoldContextJoinsLabelsAndRaisesSensitivity(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"pii"},
		AggregateSensitivity: DataClassificationInternal,
	}

	out, err := FoldContext(env, []string{"financial"}, DataClassificationConfidential)
	if err != nil {
		t.Fatalf("fold context: %v", err)
	}

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

	out, err := FoldContext(env, []string{"pii"}, DataClassificationPublic)
	if err != nil {
		t.Fatalf("fold context: %v", err)
	}

	if !reflect.DeepEqual(out.Labels, []string{"pii"}) {
		t.Fatalf("labels = %#v, want pii only", out.Labels)
	}
	if out.AggregateSensitivity != DataClassificationRestricted {
		t.Fatalf("aggregate sensitivity = %v, want restricted", out.AggregateSensitivity)
	}
}

func TestFoldContextRejectsUndefinedClassifications(t *testing.T) {
	tests := []struct {
		name           string
		envSensitivity DataClassification
		newSensitivity DataClassification
	}{
		{
			name:           "envelope",
			envSensitivity: DataClassification(-1),
			newSensitivity: DataClassificationPublic,
		},
		{
			name:           "result",
			envSensitivity: DataClassificationPublic,
			newSensitivity: DataClassification(99),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out, err := FoldContext(ContextEnvelope{
				EnvelopeID:           "env-1",
				WorkflowID:           "wf-1",
				AggregateSensitivity: test.envSensitivity,
			}, []string{"pii"}, test.newSensitivity)
			if err == nil {
				t.Fatal("fold context error = nil, want undefined-classification error")
			}
			if out.AggregateSensitivity != DataClassificationTopSecret {
				t.Fatalf(
					"fail-closed sensitivity = %v, want top_secret",
					out.AggregateSensitivity,
				)
			}
		})
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

	result, err := EvaluateAggregation(env, contextGovernanceRules, 99)
	if err != nil {
		t.Fatalf("evaluate aggregation: %v", err)
	}

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

	unknown, err := EvaluateAggregation(ContextEnvelope{
		EnvelopeID:           "env-2",
		WorkflowID:           "wf-1",
		Labels:               []string{"a", "b", "c"},
		AggregateSensitivity: DataClassificationInternal,
	}, contextGovernanceRules, 3)
	if err != nil {
		t.Fatalf("evaluate unknown aggregation: %v", err)
	}
	if !unknown.Escalate {
		t.Fatal("escalate = false, want true for unknown combination at threshold")
	}
}

func TestEvaluateAggregationRejectsInvalidClassificationsAndEmptyRules(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"a", "b", "c"},
		AggregateSensitivity: DataClassificationInternal,
	}
	tests := []struct {
		name    string
		env     ContextEnvelope
		ruleset AggregationRuleSet
	}{
		{
			name: "undefined envelope classification",
			env: ContextEnvelope{
				EnvelopeID:           "env-invalid",
				WorkflowID:           "wf-1",
				AggregateSensitivity: DataClassification(-1),
			},
			ruleset: contextGovernanceRules,
		},
		{
			name: "undefined rule classification",
			env:  env,
			ruleset: AggregationRuleSet{Rules: []AggregationRule{{
				Name:            "invalid_classification",
				AllLabels:       []string{"a"},
				SetsSensitivity: DataClassification(99),
			}}},
		},
		{
			name: "empty rule labels",
			env:  env,
			ruleset: AggregationRuleSet{Rules: []AggregationRule{{
				Name:            "matches_everything",
				AllLabels:       []string{" "},
				SetsSensitivity: DataClassificationRestricted,
			}}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := EvaluateAggregation(test.env, test.ruleset, 3)
			if err == nil {
				t.Fatal("evaluate aggregation error = nil, want validation error")
			}
			if result.AggregateSensitivity != DataClassificationTopSecret {
				t.Fatalf(
					"fail-closed sensitivity = %v, want top_secret",
					result.AggregateSensitivity,
				)
			}
			if !result.Escalate {
				t.Fatal("fail-closed escalate = false, want true")
			}
			if len(result.RulesApplied) != 0 {
				t.Fatalf("rules applied = %#v, want none", result.RulesApplied)
			}
		})
	}
}

func TestAccumulateContextFoldsAndAppliesAggregationRestrictions(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"pii"},
		AggregateSensitivity: DataClassificationInternal,
	}

	out, err := AccumulateContext(
		env,
		[]string{"financial"},
		DataClassificationConfidential,
		contextGovernanceRules,
		99,
	)
	if err != nil {
		t.Fatalf("accumulate context: %v", err)
	}

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
	env, err := AccumulateContext(ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"pii"},
		AggregateSensitivity: DataClassificationInternal,
	}, []string{"financial"}, DataClassificationConfidential, contextGovernanceRules, 99)
	if err != nil {
		t.Fatalf("accumulate context: %v", err)
	}

	decision, err := DecideNextContext(env, "export", contextGovernanceRules, 99)
	if err != nil {
		t.Fatalf("decide next context: %v", err)
	}

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

func TestDecideNextContextUsesAggregationDerivedRestrictions(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"financial", "pii"},
		AggregateSensitivity: DataClassificationInternal,
	}

	decision, err := DecideNextContext(env, "export", contextGovernanceRules, 99)
	if err != nil {
		t.Fatalf("decide next context: %v", err)
	}

	if decision.Outcome != ContextOutcomeConstrain {
		t.Fatalf("outcome = %q, want constrain", decision.Outcome)
	}
	if len(decision.Obligations.Obligations) != 1 ||
		decision.Obligations.Obligations[0].Key != "no_external_export" {
		t.Fatalf("obligations = %#v, want no_external_export", decision.Obligations.Obligations)
	}
	if decision.Reason != "action export restricted by no_external_export" {
		t.Fatalf("reason = %q, want aggregation-derived restriction", decision.Reason)
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

	decision, err := DecideNextContext(env, "export", contextGovernanceRules, 99)
	if err != nil {
		t.Fatalf("decide next context: %v", err)
	}
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

	decision, err := DecideNextContext(env, "export", contextGovernanceRules, 99)
	if err != nil {
		t.Fatalf("decide next context: %v", err)
	}
	if decision.Outcome != ContextOutcomeConstrain {
		t.Fatalf("outcome = %q, want constrain", decision.Outcome)
	}
	if len(decision.Obligations.Obligations) != 0 {
		t.Fatalf("obligations = %#v, want none", decision.Obligations.Obligations)
	}
	if decision.PolicyDecision(false) != Deny {
		t.Fatalf("policy decision = %q, want deny", decision.PolicyDecision(false))
	}
	if decision.PolicyDecision(true) != Deny {
		t.Fatalf("policy decision with empty obligation channel = %q, want deny", decision.PolicyDecision(true))
	}
}

func TestDecideNextContextEscalatesUnknownCombinations(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"a", "b", "c"},
		AggregateSensitivity: DataClassificationInternal,
	}

	decision, err := DecideNextContext(env, "read", contextGovernanceRules, 3)
	if err != nil {
		t.Fatalf("decide next context: %v", err)
	}

	if decision.Outcome != ContextOutcomeEscalate {
		t.Fatalf("outcome = %q, want escalate", decision.Outcome)
	}
	if decision.PolicyDecision(false) != Review {
		t.Fatalf("policy decision = %q, want review", decision.PolicyDecision(false))
	}
}

func TestDecideNextContextRejectsUndefinedRestrictedFloor(t *testing.T) {
	decision, err := DecideNextContextWithFloor(
		ContextEnvelope{
			EnvelopeID:           "env-1",
			WorkflowID:           "wf-1",
			AggregateSensitivity: DataClassificationInternal,
		},
		"export",
		contextGovernanceRules,
		99,
		DataClassification(-1),
	)
	if err == nil {
		t.Fatal("decide next context error = nil, want invalid-floor error")
	}
	if decision.Outcome != ContextOutcomeDeny {
		t.Fatalf("fail-closed outcome = %q, want deny", decision.Outcome)
	}
	if decision.AggregateSensitivity != DataClassificationTopSecret {
		t.Fatalf(
			"fail-closed sensitivity = %v, want top_secret",
			decision.AggregateSensitivity,
		)
	}
	if decision.PolicyDecision(true) != Deny {
		t.Fatalf(
			"fail-closed policy decision = %q, want deny",
			decision.PolicyDecision(true),
		)
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

	const childCreatedAt = "2026-07-27T08:31:00Z"
	child := DelegateContext(parent, "child-1", []string{"no_memory_write"}, childCreatedAt)
	if child.ParentEnvelopeID != parent.EnvelopeID {
		t.Fatalf("parent envelope id = %q, want %q", child.ParentEnvelopeID, parent.EnvelopeID)
	}
	if !reflect.DeepEqual(child.Restrictions, []string{"no_external_export", "no_memory_write"}) {
		t.Fatalf("child restrictions = %#v, want inherited restrictions", child.Restrictions)
	}
	if child.AggregateSensitivity != parent.AggregateSensitivity {
		t.Fatalf("child sensitivity = %v, want %v", child.AggregateSensitivity, parent.AggregateSensitivity)
	}
	if child.CreatedAt != childCreatedAt {
		t.Fatalf("child created at = %q, want %q", child.CreatedAt, childCreatedAt)
	}
}
