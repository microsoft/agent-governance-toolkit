// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"fmt"
	"sync"
	"time"
)

// LifecycleState represents an agent's current lifecycle phase.
type LifecycleState string

const (
	StateProvisioning    LifecycleState = "provisioning"
	StateActive          LifecycleState = "active"
	StateSuspended       LifecycleState = "suspended"
	StateRotating        LifecycleState = "rotating"
	StateDegraded        LifecycleState = "degraded"
	StateQuarantined     LifecycleState = "quarantined"
	StateDecommissioning LifecycleState = "decommissioning"
	StateDecommissioned  LifecycleState = "decommissioned"
)

// validTransitions defines the state machine for agent lifecycle.
var validTransitions = map[LifecycleState][]LifecycleState{
	StateProvisioning:    {StateActive, StateQuarantined, StateDecommissioning},
	StateActive:          {StateSuspended, StateRotating, StateDegraded, StateQuarantined, StateDecommissioning},
	StateSuspended:       {StateActive, StateQuarantined, StateDecommissioning},
	StateRotating:        {StateActive, StateDegraded, StateQuarantined},
	StateDegraded:        {StateActive, StateQuarantined, StateDecommissioning},
	StateQuarantined:     {StateActive, StateDecommissioning},
	StateDecommissioning: {StateDecommissioned},
	StateDecommissioned:  {},
}

// LifecycleEvent records a single state transition.
type LifecycleEvent struct {
	From        LifecycleState `json:"from"`
	To          LifecycleState `json:"to"`
	Reason      string         `json:"reason"`
	InitiatedBy string         `json:"initiated_by"`
	Timestamp   time.Time      `json:"timestamp"`
}

// LifecycleManager manages state transitions for a single agent.
type LifecycleManager struct {
	mu      sync.RWMutex
	agentID string
	state   LifecycleState
	events  []LifecycleEvent
}

// NewLifecycleManager creates a manager starting in the provisioning state.
func NewLifecycleManager(agentID string) *LifecycleManager {
	return &LifecycleManager{
		agentID: agentID,
		state:   StateProvisioning,
	}
}

// State returns the current lifecycle state.
func (m *LifecycleManager) State() LifecycleState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// Events returns a copy of the transition history.
func (m *LifecycleManager) Events() []LifecycleEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]LifecycleEvent, len(m.events))
	copy(out, m.events)
	return out
}

// Transition moves the agent to a new state if the transition is valid.
func (m *LifecycleManager) Transition(to LifecycleState, reason, initiatedBy string) (*LifecycleEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.canTransitionLocked(to) {
		return nil, fmt.Errorf("invalid transition from %s to %s", m.state, to)
	}

	event := LifecycleEvent{
		From:        m.state,
		To:          to,
		Reason:      reason,
		InitiatedBy: initiatedBy,
		Timestamp:   time.Now().UTC(),
	}
	m.state = to
	m.events = append(m.events, event)
	return &event, nil
}

// CanTransition reports whether a transition to the given state is allowed.
func (m *LifecycleManager) CanTransition(to LifecycleState) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.canTransitionLocked(to)
}

func (m *LifecycleManager) canTransitionLocked(to LifecycleState) bool {
	allowed, ok := validTransitions[m.state]
	if !ok {
		return false
	}
	for _, s := range allowed {
		if s == to {
			return true
		}
	}
	return false
}

// Activate is a convenience method to move to the active state.
func (m *LifecycleManager) Activate(reason string) (*LifecycleEvent, error) {
	return m.Transition(StateActive, reason, "system")
}

// Suspend is a convenience method to move to the suspended state.
func (m *LifecycleManager) Suspend(reason string) (*LifecycleEvent, error) {
	return m.Transition(StateSuspended, reason, "system")
}

// Quarantine is a convenience method to move to the quarantined state.
func (m *LifecycleManager) Quarantine(reason string) (*LifecycleEvent, error) {
	return m.Transition(StateQuarantined, reason, "system")
}

// Decommission is a convenience method to start decommissioning.
func (m *LifecycleManager) Decommission(reason string) (*LifecycleEvent, error) {
	return m.Transition(StateDecommissioning, reason, "system")
}
