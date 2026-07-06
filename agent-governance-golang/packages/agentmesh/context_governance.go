// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"sort"
	"strings"
	"time"
)

// DataClassification is the shared sensitivity ladder for context governance.
type DataClassification int

const (
	DataClassificationPublic DataClassification = iota
	DataClassificationInternal
	DataClassificationConfidential
	DataClassificationRestricted
	DataClassificationTopSecret
)

// String returns the stable wire spelling of the classification.
func (dc DataClassification) String() string {
	switch dc {
	case DataClassificationPublic:
		return "public"
	case DataClassificationInternal:
		return "internal"
	case DataClassificationConfidential:
		return "confidential"
	case DataClassificationRestricted:
		return "restricted"
	case DataClassificationTopSecret:
		return "top_secret"
	default:
		return "unknown"
	}
}

// DataLabel describes classified data folded into a context envelope.
type DataLabel struct {
	Classification DataClassification `json:"classification" yaml:"classification"`
	Categories     []string           `json:"categories,omitempty" yaml:"categories,omitempty"`
	Owner          string             `json:"owner,omitempty" yaml:"owner,omitempty"`
	RetentionDays  int                `json:"retention_days,omitempty" yaml:"retention_days,omitempty"`
	Geography      string             `json:"geography,omitempty" yaml:"geography,omitempty"`
}

// ContextEnvelope is the accumulated governance state for one workflow.
//
// Treat envelopes as value objects: helpers in this file return a new envelope
// with copied slices, monotonically increasing Version, grow-only Restrictions,
// and a max-lattice AggregateSensitivity.
type ContextEnvelope struct {
	EnvelopeID           string             `json:"envelope_id" yaml:"envelope_id"`
	WorkflowID           string             `json:"workflow_id" yaml:"workflow_id"`
	Labels               []string           `json:"labels,omitempty" yaml:"labels,omitempty"`
	AggregateSensitivity DataClassification `json:"aggregate_sensitivity" yaml:"aggregate_sensitivity"`
	Restrictions         []string           `json:"restrictions,omitempty" yaml:"restrictions,omitempty"`
	Version              int                `json:"version" yaml:"version"`
	ParentEnvelopeID     string             `json:"parent_envelope_id,omitempty" yaml:"parent_envelope_id,omitempty"`
	CreatedAt            string             `json:"created_at,omitempty" yaml:"created_at,omitempty"`
}

// NewContextEnvelope creates an empty workflow-scoped context envelope.
func NewContextEnvelope(envelopeID, workflowID string) ContextEnvelope {
	return ContextEnvelope{
		EnvelopeID:           envelopeID,
		WorkflowID:           workflowID,
		AggregateSensitivity: DataClassificationPublic,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	}
}

// FoldContext returns the next envelope version after folding result labels.
func FoldContext(env ContextEnvelope, newLabels []string, newSensitivity DataClassification) ContextEnvelope {
	out := cloneContextEnvelope(env)
	out.Labels = unionTokens(out.Labels, newLabels)
	if newSensitivity > out.AggregateSensitivity {
		out.AggregateSensitivity = newSensitivity
	}
	out.Version++
	return out
}

// ApplyContextRestrictions returns the next envelope version with restrictions added.
func ApplyContextRestrictions(env ContextEnvelope, restrictions []string) ContextEnvelope {
	out := cloneContextEnvelope(env)
	out.Restrictions = unionTokens(out.Restrictions, restrictions)
	out.Version++
	return out
}

// EnvelopeReference is the opaque cross-boundary projection of a ContextEnvelope.
type EnvelopeReference struct {
	EnvelopeID  string             `json:"envelope_id" yaml:"envelope_id"`
	Sensitivity DataClassification `json:"sensitivity" yaml:"sensitivity"`
}

// ContextEnvelopeReference omits labels, restrictions, version lineage, and workflow details.
func ContextEnvelopeReference(env ContextEnvelope) EnvelopeReference {
	return EnvelopeReference{
		EnvelopeID:  env.EnvelopeID,
		Sensitivity: env.AggregateSensitivity,
	}
}

// AggregationRule raises sensitivity and adds restrictions for a label combination.
type AggregationRule struct {
	Name             string             `json:"name" yaml:"name"`
	AllLabels        []string           `json:"all_labels" yaml:"all_labels"`
	SetsSensitivity  DataClassification `json:"sets_sensitivity" yaml:"sets_sensitivity"`
	AddsRestrictions []string           `json:"adds_restrictions,omitempty" yaml:"adds_restrictions,omitempty"`
}

// AggregationRuleSet is an ordered collection of aggregation rules.
type AggregationRuleSet struct {
	Rules []AggregationRule `json:"rules" yaml:"rules"`
}

// AggregationResult is the outcome of evaluating an envelope against a rule set.
type AggregationResult struct {
	AggregateSensitivity DataClassification `json:"aggregate_sensitivity" yaml:"aggregate_sensitivity"`
	Restrictions         []string           `json:"restrictions,omitempty" yaml:"restrictions,omitempty"`
	Escalate             bool               `json:"escalate" yaml:"escalate"`
	RulesApplied         []string           `json:"rules_applied,omitempty" yaml:"rules_applied,omitempty"`
}

// EvaluateAggregation applies matching rules and escalates unknown combinations at the threshold.
func EvaluateAggregation(env ContextEnvelope, ruleset AggregationRuleSet, nCategoryThreshold int) AggregationResult {
	env = cloneContextEnvelope(env)
	sensitivity := env.AggregateSensitivity
	restrictions := cloneTokens(env.Restrictions)
	var applied []string

	for _, rule := range ruleset.Rules {
		ruleLabels := normalizeTokens(rule.AllLabels)
		if containsAllTokens(env.Labels, ruleLabels) {
			if rule.SetsSensitivity > sensitivity {
				sensitivity = rule.SetsSensitivity
			}
			restrictions = unionTokens(restrictions, rule.AddsRestrictions)
			applied = append(applied, strings.TrimSpace(rule.Name))
		}
	}

	return AggregationResult{
		AggregateSensitivity: sensitivity,
		Restrictions:         restrictions,
		Escalate:             len(applied) == 0 && len(env.Labels) >= nCategoryThreshold,
		RulesApplied:         applied,
	}
}

// ContextOutcome is the governance-level result of a context-aware decision.
type ContextOutcome string

const (
	ContextOutcomeAllow     ContextOutcome = "allow"
	ContextOutcomeConstrain ContextOutcome = "constrain"
	ContextOutcomeDeny      ContextOutcome = "deny"
	ContextOutcomeEscalate  ContextOutcome = "escalate"
)

// ContextObligation is one restriction the host must carry forward.
type ContextObligation struct {
	Key       string `json:"key" yaml:"key"`
	Satisfied bool   `json:"satisfied" yaml:"satisfied"`
}

// ContextObligationSet carries obligations and labels from a constrained decision.
type ContextObligationSet struct {
	Obligations  []ContextObligation `json:"obligations,omitempty" yaml:"obligations,omitempty"`
	ResultLabels []string            `json:"result_labels,omitempty" yaml:"result_labels,omitempty"`
}

// AllSatisfied reports whether every declared obligation is already satisfied.
func (set ContextObligationSet) AllSatisfied() bool {
	for _, obligation := range set.Obligations {
		if !obligation.Satisfied {
			return false
		}
	}
	return true
}

// ContextDecision is a context-aware decision plus any obligations it carries.
type ContextDecision struct {
	Outcome              ContextOutcome       `json:"outcome" yaml:"outcome"`
	Obligations          ContextObligationSet `json:"obligations" yaml:"obligations"`
	AggregateSensitivity DataClassification   `json:"aggregate_sensitivity" yaml:"aggregate_sensitivity"`
	Reason               string               `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// AccumulateContext folds an action result into the envelope and reruns aggregation.
func AccumulateContext(
	env ContextEnvelope,
	resultLabels []string,
	resultSensitivity DataClassification,
	ruleset AggregationRuleSet,
	nCategoryThreshold int,
) ContextEnvelope {
	folded := FoldContext(env, resultLabels, resultSensitivity)
	aggregation := EvaluateAggregation(folded, ruleset, nCategoryThreshold)
	raised := cloneContextEnvelope(folded)
	raised.AggregateSensitivity = aggregation.AggregateSensitivity
	return ApplyContextRestrictions(raised, aggregation.Restrictions)
}

// DecideNextContext gates the next action using the default Restricted sensitivity floor.
func DecideNextContext(
	env ContextEnvelope,
	action string,
	ruleset AggregationRuleSet,
	nCategoryThreshold int,
) ContextDecision {
	return DecideNextContextWithFloor(env, action, ruleset, nCategoryThreshold, DataClassificationRestricted)
}

// DecideNextContextWithFloor gates the next action against the accumulated envelope.
func DecideNextContextWithFloor(
	env ContextEnvelope,
	action string,
	ruleset AggregationRuleSet,
	nCategoryThreshold int,
	restrictedFloor DataClassification,
) ContextDecision {
	env = cloneContextEnvelope(env)
	aggregation := EvaluateAggregation(env, ruleset, nCategoryThreshold)
	if aggregation.Escalate {
		return ContextDecision{
			Outcome: ContextOutcomeEscalate,
			Obligations: ContextObligationSet{
				ResultLabels: cloneTokens(env.Labels),
			},
			AggregateSensitivity: aggregation.AggregateSensitivity,
			Reason:               "aggregation threshold crossed with no governing rule",
		}
	}

	gating := contextRestrictedActions[action]
	restrictionPresent := gating != "" && tokenSet(env.Restrictions)[gating]
	floorTriggered := gating != "" && aggregation.AggregateSensitivity >= restrictedFloor
	if restrictionPresent || floorTriggered {
		obligations := make([]ContextObligation, 0, len(env.Restrictions))
		for _, restriction := range env.Restrictions {
			obligations = append(obligations, ContextObligation{Key: restriction})
		}

		reason := "action " + action + " gated by sensitivity floor"
		if restrictionPresent {
			reason = "action " + action + " restricted by " + gating
		}
		return ContextDecision{
			Outcome: ContextOutcomeConstrain,
			Obligations: ContextObligationSet{
				Obligations:  obligations,
				ResultLabels: cloneTokens(env.Labels),
			},
			AggregateSensitivity: aggregation.AggregateSensitivity,
			Reason:               reason,
		}
	}

	return ContextDecision{
		Outcome: ContextOutcomeAllow,
		Obligations: ContextObligationSet{
			ResultLabels: cloneTokens(env.Labels),
		},
		AggregateSensitivity: aggregation.AggregateSensitivity,
	}
}

// PolicyDecision collapses a context-aware decision onto the existing policy verdicts.
func (decision ContextDecision) PolicyDecision(hasObligationChannel bool) PolicyDecision {
	switch decision.Outcome {
	case ContextOutcomeAllow:
		return Allow
	case ContextOutcomeDeny:
		return Deny
	case ContextOutcomeEscalate:
		return Review
	case ContextOutcomeConstrain:
		if hasObligationChannel {
			return Allow
		}
		if len(decision.Obligations.Obligations) > 0 && decision.Obligations.AllSatisfied() {
			return Allow
		}
		return Deny
	default:
		return Deny
	}
}

// MergeContextRestrictions returns the child's effective grow-only restrictions.
func MergeContextRestrictions(parent ContextEnvelope, childDeclared []string) []string {
	return unionTokens(parent.Restrictions, childDeclared)
}

// DelegateContext creates a child envelope that inherits parent restrictions and sensitivity.
func DelegateContext(parent ContextEnvelope, childEnvelopeID string, childDeclaredRestrictions []string) ContextEnvelope {
	parent = cloneContextEnvelope(parent)
	return ContextEnvelope{
		EnvelopeID:           childEnvelopeID,
		WorkflowID:           parent.WorkflowID,
		Labels:               cloneTokens(parent.Labels),
		AggregateSensitivity: parent.AggregateSensitivity,
		Restrictions:         MergeContextRestrictions(parent, childDeclaredRestrictions),
		ParentEnvelopeID:     parent.EnvelopeID,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	}
}

var contextRestrictedActions = map[string]string{
	"export":       "no_external_export",
	"delegate":     "no_external_delegation",
	"memory_write": "no_memory_write",
}

func cloneContextEnvelope(env ContextEnvelope) ContextEnvelope {
	out := env
	out.Labels = normalizeTokens(env.Labels)
	out.Restrictions = normalizeTokens(env.Restrictions)
	return out
}

func cloneTokens(tokens []string) []string {
	out := make([]string, len(tokens))
	copy(out, tokens)
	return out
}

func unionTokens(left []string, right []string) []string {
	set := tokenSet(left)
	for _, token := range right {
		normalized := strings.TrimSpace(token)
		if normalized != "" {
			set[normalized] = true
		}
	}
	return sortedTokens(set)
}

func normalizeTokens(tokens []string) []string {
	set := tokenSet(tokens)
	return sortedTokens(set)
}

func tokenSet(tokens []string) map[string]bool {
	set := make(map[string]bool, len(tokens))
	for _, token := range tokens {
		normalized := strings.TrimSpace(token)
		if normalized != "" {
			set[normalized] = true
		}
	}
	return set
}

func sortedTokens(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for token := range set {
		out = append(out, token)
	}
	sort.Strings(out)
	return out
}

func containsAllTokens(have []string, need []string) bool {
	haveSet := tokenSet(have)
	for _, token := range need {
		if !haveSet[token] {
			return false
		}
	}
	return true
}
