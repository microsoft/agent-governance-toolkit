// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import "testing"

func TestNewLifecycleManagerStartsProvisioning(t *testing.T) {
	lm := NewLifecycleManager("agent-1")
	if lm.State() != StateProvisioning {
		t.Errorf("expected provisioning, got %s", lm.State())
	}
}

func TestActivateFromProvisioning(t *testing.T) {
	lm := NewLifecycleManager("agent-1")
	event, err := lm.Activate("ready")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.From != StateProvisioning || event.To != StateActive {
		t.Errorf("expected provisioning->active, got %s->%s", event.From, event.To)
	}
	if lm.State() != StateActive {
		t.Errorf("expected active state, got %s", lm.State())
	}
}

func TestSuspendFromActive(t *testing.T) {
	lm := NewLifecycleManager("agent-1")
	_, _ = lm.Activate("ready")
	event, err := lm.Suspend("maintenance")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.To != StateSuspended {
		t.Errorf("expected suspended, got %s", event.To)
	}
}

func TestQuarantineFromActive(t *testing.T) {
	lm := NewLifecycleManager("agent-1")
	_, _ = lm.Activate("ready")
	event, err := lm.Quarantine("breach detected")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.To != StateQuarantined {
		t.Errorf("expected quarantined, got %s", event.To)
	}
}

func TestDecommissionFromActive(t *testing.T) {
	lm := NewLifecycleManager("agent-1")
	_, _ = lm.Activate("ready")
	event, err := lm.Decommission("end of life")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.To != StateDecommissioning {
		t.Errorf("expected decommissioning, got %s", event.To)
	}
}

func TestFullLifecycle(t *testing.T) {
	lm := NewLifecycleManager("agent-1")
	_, err := lm.Activate("provisioned")
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	_, err = lm.Decommission("retiring")
	if err != nil {
		t.Fatalf("decommission: %v", err)
	}
	_, err = lm.Transition(StateDecommissioned, "done", "admin")
	if err != nil {
		t.Fatalf("decommissioned: %v", err)
	}
	if lm.State() != StateDecommissioned {
		t.Errorf("expected decommissioned, got %s", lm.State())
	}
}

func TestInvalidTransition(t *testing.T) {
	lm := NewLifecycleManager("agent-1")
	// Cannot go directly from provisioning to suspended.
	_, err := lm.Suspend("nope")
	if err == nil {
		t.Error("expected error for invalid transition provisioning->suspended")
	}
}

func TestDecommissionedIsTerminal(t *testing.T) {
	lm := NewLifecycleManager("agent-1")
	_, _ = lm.Activate("ready")
	_, _ = lm.Decommission("retire")
	_, _ = lm.Transition(StateDecommissioned, "done", "admin")

	_, err := lm.Activate("revive")
	if err == nil {
		t.Error("expected error: decommissioned should be terminal")
	}
}

func TestCanTransition(t *testing.T) {
	lm := NewLifecycleManager("agent-1")
	if !lm.CanTransition(StateActive) {
		t.Error("should be able to transition from provisioning to active")
	}
	if lm.CanTransition(StateSuspended) {
		t.Error("should NOT be able to transition from provisioning to suspended")
	}
}

func TestEventsRecorded(t *testing.T) {
	lm := NewLifecycleManager("agent-1")
	_, _ = lm.Activate("ready")
	_, _ = lm.Suspend("pause")
	_, _ = lm.Activate("resume")

	events := lm.Events()
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[0].To != StateActive {
		t.Errorf("first event should go to active, got %s", events[0].To)
	}
	if events[1].To != StateSuspended {
		t.Errorf("second event should go to suspended, got %s", events[1].To)
	}
	if events[2].To != StateActive {
		t.Errorf("third event should go to active, got %s", events[2].To)
	}
}

func TestTransitionReason(t *testing.T) {
	lm := NewLifecycleManager("agent-1")
	event, _ := lm.Transition(StateActive, "boot complete", "operator")
	if event.Reason != "boot complete" {
		t.Errorf("expected reason 'boot complete', got %q", event.Reason)
	}
	if event.InitiatedBy != "operator" {
		t.Errorf("expected initiatedBy 'operator', got %q", event.InitiatedBy)
	}
}

func TestRotatingTransitions(t *testing.T) {
	lm := NewLifecycleManager("agent-1")
	_, _ = lm.Activate("ready")
	_, err := lm.Transition(StateRotating, "key rotation", "system")
	if err != nil {
		t.Fatalf("expected active->rotating to succeed: %v", err)
	}
	_, err = lm.Activate("rotation complete")
	if err != nil {
		t.Fatalf("expected rotating->active to succeed: %v", err)
	}
}

func TestDegradedTransitions(t *testing.T) {
	lm := NewLifecycleManager("agent-1")
	_, _ = lm.Activate("ready")
	_, err := lm.Transition(StateDegraded, "partial failure", "monitor")
	if err != nil {
		t.Fatalf("expected active->degraded to succeed: %v", err)
	}
	_, err = lm.Activate("recovered")
	if err != nil {
		t.Fatalf("expected degraded->active to succeed: %v", err)
	}
}
