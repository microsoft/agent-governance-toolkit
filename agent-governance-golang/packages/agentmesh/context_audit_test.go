// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestContextEventForRecordsEnvelopeDelta(t *testing.T) {
	before := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"pii"},
		AggregateSensitivity: DataClassificationConfidential,
	}
	after := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		Labels:               []string{"financial", "pii"},
		AggregateSensitivity: DataClassificationRestricted,
		Restrictions:         []string{"no_external_export"},
	}
	rulesApplied := []string{"pii_financial_restricted"}

	event := ContextEventFor(
		ContextAggregationElevated,
		"agent.customer-success",
		before,
		after,
		rulesApplied,
	)

	if event.EventType != ContextAggregationElevated {
		t.Fatalf("event type = %q, want %q", event.EventType, ContextAggregationElevated)
	}
	if event.ContextEnvelopeID != after.EnvelopeID {
		t.Fatalf("context envelope id = %q, want %q", event.ContextEnvelopeID, after.EnvelopeID)
	}
	if event.PreviousSensitivity != DataClassificationConfidential {
		t.Fatalf("previous sensitivity = %v, want confidential", event.PreviousSensitivity)
	}
	if event.NewSensitivity != DataClassificationRestricted {
		t.Fatalf("new sensitivity = %v, want restricted", event.NewSensitivity)
	}
	if !reflect.DeepEqual(event.LabelsAdded, []string{"financial"}) {
		t.Fatalf("labels added = %#v, want financial", event.LabelsAdded)
	}
	if !reflect.DeepEqual(event.RestrictionsAdded, []string{"no_external_export"}) {
		t.Fatalf("restrictions added = %#v, want no_external_export", event.RestrictionsAdded)
	}
	if !reflect.DeepEqual(event.RulesApplied, rulesApplied) {
		t.Fatalf("rules applied = %#v, want %#v", event.RulesApplied, rulesApplied)
	}
	if event.Classification != DataClassificationRestricted {
		t.Fatalf("classification = %v, want restricted", event.Classification)
	}

	rulesApplied[0] = "mutated"
	if event.RulesApplied[0] != "pii_financial_restricted" {
		t.Fatalf("event rules were mutated through caller slice: %#v", event.RulesApplied)
	}
}

func TestContextEventForKeepsHigherPreviousClassification(t *testing.T) {
	before := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		AggregateSensitivity: DataClassificationRestricted,
	}
	after := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		AggregateSensitivity: DataClassificationInternal,
	}

	event := ContextEventFor(ContextEnvelopeUpdated, "agent-1", before, after, nil)

	if event.Classification != DataClassificationRestricted {
		t.Fatalf("classification = %v, want restricted", event.Classification)
	}
}

func TestContextEventTypeWireValues(t *testing.T) {
	got := []ContextEventType{
		ContextEnvelopeCreated,
		ContextEnvelopeUpdated,
		ContextAggregationElevated,
		ContextDelegated,
		ContextRedacted,
		DerivedArtifactLabeled,
	}
	want := []ContextEventType{
		"CONTEXT_ENVELOPE_CREATED",
		"CONTEXT_ENVELOPE_UPDATED",
		"CONTEXT_AGGREGATION_ELEVATED",
		"CONTEXT_DELEGATED",
		"CONTEXT_REDACTED",
		"DERIVED_ARTIFACT_LABELED",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("event wire values = %#v, want %#v", got, want)
	}
}

func TestContextEventForSerializesEmptyDeltasAsArrays(t *testing.T) {
	env := ContextEnvelope{
		EnvelopeID:           "env-1",
		WorkflowID:           "wf-1",
		AggregateSensitivity: DataClassificationInternal,
	}
	event := ContextEventFor(ContextEnvelopeUpdated, "agent-1", env, env, nil)

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	for _, field := range []string{"labels_added", "rules_applied", "restrictions_added"} {
		values, ok := wire[field].([]any)
		if !ok {
			t.Fatalf("%s = %#v, want array", field, wire[field])
		}
		if len(values) != 0 {
			t.Fatalf("%s = %#v, want empty array", field, values)
		}
	}
}
