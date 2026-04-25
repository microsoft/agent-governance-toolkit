// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"testing"
	"time"
)

func TestSLOEngineAvailabilityObjective(t *testing.T) {
	engine, err := NewSLOEngine([]SLOObjective{{
		Name:      "availability",
		Indicator: SLOAvailability,
		Target:    0.99,
		Window:    time.Hour,
	}})
	if err != nil {
		t.Fatalf("NewSLOEngine: %v", err)
	}

	if err := engine.RecordEvent("availability", true, 10*time.Millisecond); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}
	if err := engine.RecordEvent("availability", false, 10*time.Millisecond); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}

	report, err := engine.Evaluate("availability")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if report.Met {
		t.Fatalf("report = %+v, want unmet objective", report)
	}
	if report.Actual != 0.5 {
		t.Fatalf("actual = %f, want 0.5", report.Actual)
	}
	if report.ErrorBudgetRemaining != 0 {
		t.Fatalf("error budget remaining = %f, want 0", report.ErrorBudgetRemaining)
	}
}

func TestSLOEngineLatencyObjective(t *testing.T) {
	engine, err := NewSLOEngine([]SLOObjective{{
		Name:             "latency",
		Indicator:        SLOLatency,
		Target:           0.66,
		Window:           time.Hour,
		LatencyThreshold: 100 * time.Millisecond,
	}})
	if err != nil {
		t.Fatalf("NewSLOEngine: %v", err)
	}

	for _, latency := range []time.Duration{50 * time.Millisecond, 80 * time.Millisecond, 150 * time.Millisecond} {
		if err := engine.RecordEvent("latency", true, latency); err != nil {
			t.Fatalf("RecordEvent: %v", err)
		}
	}

	report, err := engine.Evaluate("latency")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !report.Met {
		t.Fatalf("report = %+v, want met objective", report)
	}
	if report.TotalEvents != 3 {
		t.Fatalf("total events = %d, want 3", report.TotalEvents)
	}
}

func TestSLOEngineHasObjective(t *testing.T) {
	engine, err := NewSLOEngine([]SLOObjective{{
		Name:      "availability",
		Indicator: SLOAvailability,
		Target:    0.9,
		Window:    time.Minute,
	}})
	if err != nil {
		t.Fatalf("NewSLOEngine: %v", err)
	}

	if !engine.HasObjective("availability") {
		t.Fatal("expected objective to exist")
	}
	if engine.HasObjective("missing") {
		t.Fatal("unexpected objective found")
	}
}
