// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"errors"
	"testing"
)

func TestKillSwitchToggleState(t *testing.T) {
	killSwitch := NewKillSwitch()
	if killSwitch.IsActive() {
		t.Fatal("expected new kill switch to be inactive")
	}

	activated := killSwitch.Activate(KillSwitchReasonSecurityIncident, "suspicious outbound traffic")
	if !activated.Active {
		t.Fatal("expected activation event to be active")
	}
	if !killSwitch.IsActive() {
		t.Fatal("expected kill switch to be active")
	}

	cleared := killSwitch.Clear(KillSwitchReasonOperatorRequest, "incident resolved")
	if cleared.Active {
		t.Fatal("expected clear event to be inactive")
	}
	if killSwitch.IsActive() {
		t.Fatal("expected kill switch to be inactive after clear")
	}
}

func TestKillSwitchRegistryDecisionForScopedMatches(t *testing.T) {
	registry := NewKillSwitchRegistry()
	if _, err := registry.Activate(AgentKillSwitchScope("agent-42"), KillSwitchReasonPolicyViolation, "repeated policy denials"); err != nil {
		t.Fatalf("Activate agent scope: %v", err)
	}

	decision := registry.DecisionFor("agent-42", "tool.run")
	if decision.Allowed {
		t.Fatal("expected agent-scoped kill switch to deny execution")
	}
	if decision.Scope == nil || decision.Scope.Kind != KillSwitchScopeAgent || decision.Scope.Value != "agent-42" {
		t.Fatalf("unexpected scope %#v", decision.Scope)
	}
	if decision.Event == nil || !decision.Event.Active {
		t.Fatalf("expected active event, got %#v", decision.Event)
	}

	allowedDecision := registry.DecisionFor("agent-7", "tool.run")
	if !allowedDecision.Allowed {
		t.Fatalf("unexpected denial for unrelated agent: %#v", allowedDecision)
	}
}

func TestKillSwitchRegistryPrefersGlobalScope(t *testing.T) {
	registry := NewKillSwitchRegistry()
	if _, err := registry.Activate(GlobalKillSwitchScope(), KillSwitchReasonSecurityIncident, "platform containment"); err != nil {
		t.Fatalf("Activate global scope: %v", err)
	}
	if _, err := registry.Activate(AgentKillSwitchScope("agent-7"), KillSwitchReasonPolicyViolation, "agent-specific issue"); err != nil {
		t.Fatalf("Activate agent scope: %v", err)
	}

	decision := registry.DecisionFor("agent-7", "tool.run")
	if decision.Allowed {
		t.Fatal("expected global kill switch to deny execution")
	}
	if decision.Scope == nil || decision.Scope.Kind != KillSwitchScopeGlobal {
		t.Fatalf("expected global scope, got %#v", decision.Scope)
	}
}

func TestKillSwitchRegistryHistoryAndValidation(t *testing.T) {
	registry := NewKillSwitchRegistry()
	if _, err := registry.Activate(CapabilityKillSwitchScope(""), KillSwitchReasonOperatorRequest, "missing capability"); err == nil {
		t.Fatal("expected validation error for empty capability scope")
	}

	if _, err := registry.Activate(CapabilityKillSwitchScope("tool.run"), KillSwitchReasonOperatorRequest, "maintenance"); err != nil {
		t.Fatalf("Activate capability scope: %v", err)
	}
	if _, err := registry.Clear(CapabilityKillSwitchScope("tool.run"), KillSwitchReasonOperatorRequest, "maintenance complete"); err != nil {
		t.Fatalf("Clear capability scope: %v", err)
	}

	history := registry.History()
	if len(history) != 2 {
		t.Fatalf("history length = %d, want 2", len(history))
	}
	if history[0].Scope.Kind != KillSwitchScopeCapability || history[0].Scope.Value != "tool.run" {
		t.Fatalf("unexpected first history entry scope %#v", history[0].Scope)
	}
	if !history[0].Event.Active || history[1].Event.Active {
		t.Fatalf("unexpected history events %#v", history)
	}

	decision := registry.DecisionFor("agent-1", "tool.run")
	if !decision.Allowed {
		t.Fatalf("expected cleared capability to allow execution, got %#v", decision)
	}
}

func TestKillSwitchRegistryNormalizesExportedScopes(t *testing.T) {
	registry := NewKillSwitchRegistry()
	if _, err := registry.Activate(KillSwitchScope{
		Kind:  KillSwitchScopeGlobal,
		Value: "ignored",
	}, KillSwitchReasonSecurityIncident, "global containment"); err != nil {
		t.Fatalf("Activate malformed global scope: %v", err)
	}

	globalDecision := registry.DecisionFor("agent-1", "tool.run")
	if globalDecision.Allowed {
		t.Fatal("expected normalized global scope to deny execution")
	}
	if globalDecision.Scope == nil || globalDecision.Scope.Kind != KillSwitchScopeGlobal || globalDecision.Scope.Value != "" {
		t.Fatalf("unexpected normalized global scope %#v", globalDecision.Scope)
	}

	if _, err := registry.Clear(GlobalKillSwitchScope(), KillSwitchReasonOperatorRequest, "global clear"); err != nil {
		t.Fatalf("Clear normalized global scope: %v", err)
	}
	if _, err := registry.Activate(KillSwitchScope{
		Kind:  KillSwitchScopeAgent,
		Value: " agent-9 ",
	}, KillSwitchReasonPolicyViolation, "agent containment"); err != nil {
		t.Fatalf("Activate whitespace agent scope: %v", err)
	}

	agentDecision := registry.DecisionFor("agent-9", "tool.run")
	if agentDecision.Allowed {
		t.Fatal("expected normalized agent scope to deny execution")
	}
	if agentDecision.Scope == nil || agentDecision.Scope.Kind != KillSwitchScopeAgent || agentDecision.Scope.Value != "agent-9" {
		t.Fatalf("unexpected normalized agent scope %#v", agentDecision.Scope)
	}
}

func TestKillSwitchMiddlewareDeniesOperation(t *testing.T) {
	registry := NewKillSwitchRegistry()
	if _, err := registry.Activate(CapabilityKillSwitchScope("calculator"), KillSwitchReasonOperatorRequest, "tool maintenance"); err != nil {
		t.Fatalf("Activate capability scope: %v", err)
	}

	handlerCalled := false
	err := KillSwitchMiddleware(registry)(func(*GovernedOperation) error {
		handlerCalled = true
		return nil
	})(&GovernedOperation{
		AgentID:  "agent-9",
		Action:   "tool.run",
		ToolName: "calculator",
	})
	if err == nil {
		t.Fatal("expected kill switch denial")
	}
	if !errors.Is(err, ErrKillSwitchActive) {
		t.Fatalf("expected ErrKillSwitchActive, got %v", err)
	}
	if handlerCalled {
		t.Fatal("expected kill switch middleware to stop handler execution")
	}
}
