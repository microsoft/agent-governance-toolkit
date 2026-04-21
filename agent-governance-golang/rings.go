// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import "sync"

// Ring represents an execution privilege level (0 = most privileged).
type Ring int

const (
	RingAdmin      Ring = 0
	RingStandard   Ring = 1
	RingRestricted Ring = 2
	RingSandboxed  Ring = 3
)

// RingEnforcer assigns agents to privilege rings and checks access.
type RingEnforcer struct {
	mu          sync.RWMutex
	assignments map[string]Ring
	permissions map[Ring]map[string]bool
}

// NewRingEnforcer creates an enforcer with empty assignments and no default permissions.
func NewRingEnforcer() *RingEnforcer {
	return &RingEnforcer{
		assignments: make(map[string]Ring),
		permissions: make(map[Ring]map[string]bool),
	}
}

// Assign places an agent in the specified privilege ring.
func (r *RingEnforcer) Assign(agentID string, ring Ring) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.assignments[agentID] = ring
}

// GetRing returns the ring for an agent and whether the agent is assigned.
func (r *RingEnforcer) GetRing(agentID string) (Ring, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ring, ok := r.assignments[agentID]
	return ring, ok
}

// CheckAccess returns true only if the agent's ring includes the given action.
// Unassigned agents are denied by default.
func (r *RingEnforcer) CheckAccess(agentID string, action string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ring, ok := r.assignments[agentID]
	if !ok {
		return false
	}

	perms, ok := r.permissions[ring]
	if !ok {
		return false
	}

	// Wildcard permission grants everything.
	if perms["*"] {
		return true
	}
	return perms[action]
}

// SetRingPermissions replaces the allowed actions for a given ring.
func (r *RingEnforcer) SetRingPermissions(ring Ring, allowedActions []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	perms := make(map[string]bool, len(allowedActions))
	for _, a := range allowedActions {
		perms[a] = true
	}
	r.permissions[ring] = perms
}
