// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"fmt"
	"sync"
	"time"
)

// SLOIndicator describes how an SLO objective is measured.
type SLOIndicator string

const (
	SLOAvailability SLOIndicator = "availability"
	SLOLatency      SLOIndicator = "latency"
)

// SLOObjective defines a single service level objective.
type SLOObjective struct {
	Name             string
	Indicator        SLOIndicator
	Target           float64
	Window           time.Duration
	LatencyThreshold time.Duration
}

// SLOEvent records a single outcome used to evaluate an objective.
type SLOEvent struct {
	Timestamp time.Time
	Success   bool
	Latency   time.Duration
}

// SLOReport summarizes the current state of an objective.
type SLOReport struct {
	Name                 string
	Indicator            SLOIndicator
	Target               float64
	Actual               float64
	Met                  bool
	WindowStart          time.Time
	TotalEvents          int
	ErrorBudget          float64
	ErrorBudgetRemaining float64
}

// SLOEngine tracks events and evaluates SLO compliance.
type SLOEngine struct {
	mu         sync.RWMutex
	objectives map[string]SLOObjective
	events     map[string][]SLOEvent
}

// NewSLOEngine creates an engine preloaded with objectives.
func NewSLOEngine(objectives []SLOObjective) (*SLOEngine, error) {
	engine := &SLOEngine{
		objectives: make(map[string]SLOObjective, len(objectives)),
		events:     make(map[string][]SLOEvent, len(objectives)),
	}

	for _, objective := range objectives {
		if err := engine.AddObjective(objective); err != nil {
			return nil, err
		}
	}

	return engine, nil
}

// AddObjective registers a new objective with the engine.
func (e *SLOEngine) AddObjective(objective SLOObjective) error {
	if objective.Name == "" {
		return fmt.Errorf("slo objective name is required")
	}
	if objective.Target <= 0 || objective.Target > 1 {
		return fmt.Errorf("slo objective target must be between 0 and 1")
	}
	if objective.Window <= 0 {
		return fmt.Errorf("slo objective window must be positive")
	}
	if objective.Indicator != SLOAvailability && objective.Indicator != SLOLatency {
		return fmt.Errorf("unsupported slo indicator %q", objective.Indicator)
	}
	if objective.Indicator == SLOLatency && objective.LatencyThreshold <= 0 {
		return fmt.Errorf("latency slo requires a positive threshold")
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.objectives[objective.Name] = objective
	return nil
}

// HasObjective reports whether the named objective exists.
func (e *SLOEngine) HasObjective(name string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.objectives[name]
	return ok
}

// RecordEvent stores an event for the named objective.
func (e *SLOEngine) RecordEvent(name string, success bool, latency time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	objective, ok := e.objectives[name]
	if !ok {
		return fmt.Errorf("unknown slo objective %q", name)
	}

	event := SLOEvent{
		Timestamp: time.Now().UTC(),
		Success:   success,
		Latency:   latency,
	}
	e.events[name] = append(e.prunedEventsLocked(name, objective, event.Timestamp), event)
	return nil
}

// Evaluate computes the current report for the named objective.
func (e *SLOEngine) Evaluate(name string) (SLOReport, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	objective, ok := e.objectives[name]
	if !ok {
		return SLOReport{}, fmt.Errorf("unknown slo objective %q", name)
	}

	now := time.Now().UTC()
	events := e.prunedEventsLocked(name, objective, now)
	e.events[name] = events

	windowStart := now.Add(-objective.Window)
	report := SLOReport{
		Name:        objective.Name,
		Indicator:   objective.Indicator,
		Target:      objective.Target,
		WindowStart: windowStart,
		TotalEvents: len(events),
		ErrorBudget: 1 - objective.Target,
	}

	if len(events) == 0 {
		report.Actual = 1
		report.Met = true
		report.ErrorBudgetRemaining = report.ErrorBudget
		return report, nil
	}

	successes := 0
	for _, event := range events {
		switch objective.Indicator {
		case SLOAvailability:
			if event.Success {
				successes++
			}
		case SLOLatency:
			if event.Success && event.Latency <= objective.LatencyThreshold {
				successes++
			}
		}
	}

	report.Actual = float64(successes) / float64(len(events))
	report.Met = report.Actual >= objective.Target
	report.ErrorBudgetRemaining = report.ErrorBudget - maxFloat(0, 1-report.Actual)
	if report.ErrorBudgetRemaining < 0 {
		report.ErrorBudgetRemaining = 0
	}

	return report, nil
}

func (e *SLOEngine) prunedEventsLocked(name string, objective SLOObjective, now time.Time) []SLOEvent {
	events := e.events[name]
	if len(events) == 0 {
		return nil
	}

	windowStart := now.Add(-objective.Window)
	pruned := make([]SLOEvent, 0, len(events))
	for _, event := range events {
		if !event.Timestamp.Before(windowStart) {
			pruned = append(pruned, event)
		}
	}
	return pruned
}

func maxFloat(left float64, right float64) float64 {
	if left > right {
		return left
	}
	return right
}
