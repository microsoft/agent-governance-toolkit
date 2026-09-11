// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import "strings"

// ContextEventType is the stable wire type for context-governance audit events.
type ContextEventType string

const (
	// ContextEnvelopeCreated records creation of a context envelope.
	ContextEnvelopeCreated ContextEventType = "CONTEXT_ENVELOPE_CREATED"
	// ContextEnvelopeUpdated records a context envelope transition.
	ContextEnvelopeUpdated ContextEventType = "CONTEXT_ENVELOPE_UPDATED"
	// ContextAggregationElevated records an aggregation-driven sensitivity increase.
	ContextAggregationElevated ContextEventType = "CONTEXT_AGGREGATION_ELEVATED"
	// ContextDelegated records propagation of context into a child delegation.
	ContextDelegated ContextEventType = "CONTEXT_DELEGATED"
	// ContextRedacted records a redaction applied to governed context.
	ContextRedacted ContextEventType = "CONTEXT_REDACTED"
	// DerivedArtifactLabeled records classification of an artifact derived from context.
	DerivedArtifactLabeled ContextEventType = "DERIVED_ARTIFACT_LABELED"
)

// ContextEvent records the governance-relevant delta between two envelope versions.
// Its Classification is never lower than either envelope's aggregate sensitivity.
type ContextEvent struct {
	EventType           ContextEventType   `json:"event_type" yaml:"event_type"`
	AgentID             string             `json:"agent_id" yaml:"agent_id"`
	ContextEnvelopeID   string             `json:"context_envelope_id" yaml:"context_envelope_id"`
	PreviousSensitivity DataClassification `json:"previous_sensitivity" yaml:"previous_sensitivity"`
	NewSensitivity      DataClassification `json:"new_sensitivity" yaml:"new_sensitivity"`
	LabelsAdded         []string           `json:"labels_added" yaml:"labels_added"`
	RulesApplied        []string           `json:"rules_applied" yaml:"rules_applied"`
	RestrictionsAdded   []string           `json:"restrictions_added" yaml:"restrictions_added"`
	Classification      DataClassification `json:"classification" yaml:"classification"`
}

// ContextEventFor builds a deterministic event describing before -> after.
func ContextEventFor(
	eventType ContextEventType,
	agentID string,
	before ContextEnvelope,
	after ContextEnvelope,
	rulesApplied []string,
) ContextEvent {
	before = cloneContextEnvelope(before)
	after = cloneContextEnvelope(after)

	classification := before.AggregateSensitivity
	if after.AggregateSensitivity > classification {
		classification = after.AggregateSensitivity
	}

	return ContextEvent{
		EventType:           eventType,
		AgentID:             agentID,
		ContextEnvelopeID:   after.EnvelopeID,
		PreviousSensitivity: before.AggregateSensitivity,
		NewSensitivity:      after.AggregateSensitivity,
		LabelsAdded:         addedTokens(before.Labels, after.Labels),
		RulesApplied:        cloneTokens(rulesApplied),
		RestrictionsAdded:   addedTokens(before.Restrictions, after.Restrictions),
		Classification:      classification,
	}
}

func addedTokens(before []string, after []string) []string {
	beforeSet := tokenSet(before)
	added := make(map[string]bool)
	for _, token := range after {
		normalized := strings.TrimSpace(token)
		if normalized != "" && !beforeSet[normalized] {
			added[normalized] = true
		}
	}
	return cloneTokens(sortedTokens(added))
}
