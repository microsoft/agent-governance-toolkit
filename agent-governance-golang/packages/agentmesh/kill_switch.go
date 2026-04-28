// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrKillSwitchActive is returned when execution is blocked by an active kill switch.
var ErrKillSwitchActive = errors.New("kill switch active")

// KillSwitchReason captures why a kill switch was activated or cleared.
type KillSwitchReason string

const (
	KillSwitchReasonPolicyViolation      KillSwitchReason = "policy_violation"
	KillSwitchReasonSecurityIncident     KillSwitchReason = "security_incident"
	KillSwitchReasonOperatorRequest      KillSwitchReason = "operator_request"
	KillSwitchReasonErrorBudgetExhausted KillSwitchReason = "error_budget_exhausted"
)

// KillSwitchScopeKind identifies the scope affected by a kill switch.
type KillSwitchScopeKind string

const (
	KillSwitchScopeGlobal     KillSwitchScopeKind = "global"
	KillSwitchScopeAgent      KillSwitchScopeKind = "agent"
	KillSwitchScopeCapability KillSwitchScopeKind = "capability"
)

// KillSwitchScope identifies the resource targeted by a kill switch.
type KillSwitchScope struct {
	Kind  KillSwitchScopeKind `json:"kind"`
	Value string              `json:"value,omitempty"`
}

// GlobalKillSwitchScope returns the process-wide kill switch scope.
func GlobalKillSwitchScope() KillSwitchScope {
	return KillSwitchScope{Kind: KillSwitchScopeGlobal}
}

// AgentKillSwitchScope returns the kill switch scope for a specific agent.
func AgentKillSwitchScope(agentID string) KillSwitchScope {
	return KillSwitchScope{Kind: KillSwitchScopeAgent, Value: strings.TrimSpace(agentID)}
}

// CapabilityKillSwitchScope returns the kill switch scope for a specific capability.
func CapabilityKillSwitchScope(capability string) KillSwitchScope {
	return KillSwitchScope{Kind: KillSwitchScopeCapability, Value: strings.TrimSpace(capability)}
}

func normalizeKillSwitchScope(scope KillSwitchScope) KillSwitchScope {
	switch scope.Kind {
	case KillSwitchScopeGlobal:
		scope.Value = ""
	case KillSwitchScopeAgent, KillSwitchScopeCapability:
		scope.Value = strings.TrimSpace(scope.Value)
	}
	return scope
}

func (s KillSwitchScope) validate() error {
	s = normalizeKillSwitchScope(s)
	switch s.Kind {
	case KillSwitchScopeGlobal:
		return nil
	case KillSwitchScopeAgent, KillSwitchScopeCapability:
		if strings.TrimSpace(s.Value) == "" {
			return fmt.Errorf("kill switch scope %q requires a non-empty value", s.Kind)
		}
		return nil
	default:
		return fmt.Errorf("unknown kill switch scope kind %q", s.Kind)
	}
}

// String returns a stable string representation for logging and map keys.
func (s KillSwitchScope) String() string {
	s = normalizeKillSwitchScope(s)
	if s.Value == "" {
		return string(s.Kind)
	}
	return fmt.Sprintf("%s:%s", s.Kind, s.Value)
}

// KillSwitchEvent records a single activation or clear action.
type KillSwitchEvent struct {
	Active    bool             `json:"active"`
	Reason    KillSwitchReason `json:"reason"`
	Message   string           `json:"message,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
}

// KillSwitchDecision reports whether execution is permitted for a given lookup.
type KillSwitchDecision struct {
	Allowed bool             `json:"allowed"`
	Scope   *KillSwitchScope `json:"scope,omitempty"`
	Event   *KillSwitchEvent `json:"event,omitempty"`
}

// KillSwitchHistoryEntry records a scoped kill switch event.
type KillSwitchHistoryEntry struct {
	Scope KillSwitchScope `json:"scope"`
	Event KillSwitchEvent `json:"event"`
}

// KillSwitch tracks active state and the latest event for a single scope.
type KillSwitch struct {
	mu    sync.RWMutex
	event *KillSwitchEvent
}

// NewKillSwitch creates an inactive kill switch.
func NewKillSwitch() *KillSwitch {
	return &KillSwitch{}
}

// Activate marks the kill switch active and records the event.
func (s *KillSwitch) Activate(reason KillSwitchReason, message string) KillSwitchEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	event := KillSwitchEvent{
		Active:    true,
		Reason:    reason,
		Message:   strings.TrimSpace(message),
		Timestamp: time.Now().UTC(),
	}
	s.event = &event
	return event
}

// Clear marks the kill switch inactive and records the event.
func (s *KillSwitch) Clear(reason KillSwitchReason, message string) KillSwitchEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	event := KillSwitchEvent{
		Active:    false,
		Reason:    reason,
		Message:   strings.TrimSpace(message),
		Timestamp: time.Now().UTC(),
	}
	s.event = &event
	return event
}

// IsActive reports whether the kill switch is currently active.
func (s *KillSwitch) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.event != nil && s.event.Active
}

// Event returns the latest event recorded for the kill switch.
func (s *KillSwitch) Event() *KillSwitchEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneKillSwitchEvent(s.event)
}

func cloneKillSwitchEvent(event *KillSwitchEvent) *KillSwitchEvent {
	if event == nil {
		return nil
	}
	clone := *event
	return &clone
}

// KillSwitchRegistry manages scoped kill switches and their history.
type KillSwitchRegistry struct {
	mu       sync.RWMutex
	switches map[string]*KillSwitch
	history  []KillSwitchHistoryEntry
}

// NewKillSwitchRegistry creates an empty scoped kill switch registry.
func NewKillSwitchRegistry() *KillSwitchRegistry {
	return &KillSwitchRegistry{
		switches: make(map[string]*KillSwitch),
		history:  make([]KillSwitchHistoryEntry, 0),
	}
}

func (r *KillSwitchRegistry) switchFor(scope KillSwitchScope) *KillSwitch {
	key := scope.String()
	if existing, ok := r.switches[key]; ok {
		return existing
	}
	killSwitch := NewKillSwitch()
	r.switches[key] = killSwitch
	return killSwitch
}

// Activate marks the given scope blocked and records the event in registry history.
func (r *KillSwitchRegistry) Activate(scope KillSwitchScope, reason KillSwitchReason, message string) (*KillSwitchEvent, error) {
	scope = normalizeKillSwitchScope(scope)
	if err := scope.validate(); err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	event := r.switchFor(scope).Activate(reason, message)
	r.history = append(r.history, KillSwitchHistoryEntry{Scope: scope, Event: event})
	return cloneKillSwitchEvent(&event), nil
}

// Clear marks the given scope allowed again and records the event in registry history.
func (r *KillSwitchRegistry) Clear(scope KillSwitchScope, reason KillSwitchReason, message string) (*KillSwitchEvent, error) {
	scope = normalizeKillSwitchScope(scope)
	if err := scope.validate(); err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	event := r.switchFor(scope).Clear(reason, message)
	r.history = append(r.history, KillSwitchHistoryEntry{Scope: scope, Event: event})
	return cloneKillSwitchEvent(&event), nil
}

// DecisionFor resolves whether a specific agent/capability combination is currently allowed.
func (r *KillSwitchRegistry) DecisionFor(agentID string, capability string) KillSwitchDecision {
	r.mu.RLock()
	defer r.mu.RUnlock()

	scopes := []KillSwitchScope{GlobalKillSwitchScope()}
	if trimmedAgentID := strings.TrimSpace(agentID); trimmedAgentID != "" {
		scopes = append(scopes, AgentKillSwitchScope(trimmedAgentID))
	}
	if trimmedCapability := strings.TrimSpace(capability); trimmedCapability != "" {
		scopes = append(scopes, CapabilityKillSwitchScope(trimmedCapability))
	}

	for _, scope := range scopes {
		killSwitch, ok := r.switches[scope.String()]
		if !ok {
			continue
		}
		event := killSwitch.Event()
		if event != nil && event.Active {
			scopeCopy := scope
			return KillSwitchDecision{
				Allowed: false,
				Scope:   &scopeCopy,
				Event:   event,
			}
		}
	}

	return KillSwitchDecision{Allowed: true}
}

// History returns a copy of scoped kill switch events in chronological order.
func (r *KillSwitchRegistry) History() []KillSwitchHistoryEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	history := make([]KillSwitchHistoryEntry, len(r.history))
	copy(history, r.history)
	return history
}
