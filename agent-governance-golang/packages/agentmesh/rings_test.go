// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import "testing"

func TestAssignAndGetRing(t *testing.T) {
	enforcer := NewRingEnforcer()
	enforcer.Assign("agent-1", RingAdmin)

	ring, ok := enforcer.GetRing("agent-1")
	if !ok {
		t.Fatal("expected agent to be assigned")
	}
	if ring != RingAdmin {
		t.Errorf("expected RingAdmin (0), got %d", ring)
	}
}

func TestGetRingUnassigned(t *testing.T) {
	enforcer := NewRingEnforcer()
	_, ok := enforcer.GetRing("ghost")
	if ok {
		t.Error("expected unassigned agent to return false")
	}
}

func TestCheckAccessAllowed(t *testing.T) {
	enforcer := NewRingEnforcer()
	enforcer.SetRingPermissions(RingStandard, []string{"data.read", "data.write"})
	enforcer.Assign("agent-std", RingStandard)

	if !enforcer.CheckAccess("agent-std", "data.read") {
		t.Error("expected data.read to be allowed")
	}
	if !enforcer.CheckAccess("agent-std", "data.write") {
		t.Error("expected data.write to be allowed")
	}
}

func TestCheckAccessDenied(t *testing.T) {
	enforcer := NewRingEnforcer()
	enforcer.SetRingPermissions(RingRestricted, []string{"data.read"})
	enforcer.Assign("agent-r", RingRestricted)

	if enforcer.CheckAccess("agent-r", "data.write") {
		t.Error("expected data.write to be denied for restricted ring")
	}
}

func TestDefaultDenyUnassigned(t *testing.T) {
	enforcer := NewRingEnforcer()
	enforcer.SetRingPermissions(RingAdmin, []string{"*"})

	if enforcer.CheckAccess("nobody", "anything") {
		t.Error("expected unassigned agent to be denied")
	}
}

func TestDefaultDenyNoPermissions(t *testing.T) {
	enforcer := NewRingEnforcer()
	enforcer.Assign("agent-x", RingSandboxed)

	if enforcer.CheckAccess("agent-x", "data.read") {
		t.Error("expected deny when ring has no permissions configured")
	}
}

func TestWildcardPermission(t *testing.T) {
	enforcer := NewRingEnforcer()
	enforcer.SetRingPermissions(RingAdmin, []string{"*"})
	enforcer.Assign("admin", RingAdmin)

	if !enforcer.CheckAccess("admin", "any.action.at.all") {
		t.Error("expected wildcard permission to allow any action")
	}
}

func TestReassignRing(t *testing.T) {
	enforcer := NewRingEnforcer()
	enforcer.SetRingPermissions(RingAdmin, []string{"*"})
	enforcer.SetRingPermissions(RingSandboxed, []string{})
	enforcer.Assign("agent-1", RingAdmin)

	if !enforcer.CheckAccess("agent-1", "anything") {
		t.Fatal("expected admin access initially")
	}

	enforcer.Assign("agent-1", RingSandboxed)
	if enforcer.CheckAccess("agent-1", "anything") {
		t.Error("expected sandboxed to deny after reassignment")
	}
}
