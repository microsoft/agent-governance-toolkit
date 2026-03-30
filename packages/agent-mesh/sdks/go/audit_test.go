package agentmesh

import (
	"testing"
)

func TestAuditLogAndVerify(t *testing.T) {
	al := NewAuditLogger()
	e1 := al.Log("agent-1", "data.read", Allow)
	e2 := al.Log("agent-1", "data.write", Deny)

	if e1.PreviousHash != "" {
		t.Error("first entry should have empty PreviousHash")
	}
	if e2.PreviousHash != e1.Hash {
		t.Error("second entry PreviousHash should equal first Hash")
	}
	if !al.Verify() {
		t.Error("chain should be valid")
	}
}

func TestAuditVerifyDetectsTampering(t *testing.T) {
	al := NewAuditLogger()
	al.Log("a", "x", Allow)
	al.Log("a", "y", Deny)

	// tamper
	al.entries[0].AgentID = "tampered"
	if al.Verify() {
		t.Error("chain should be invalid after tampering")
	}
}

func TestAuditGetEntriesFilter(t *testing.T) {
	al := NewAuditLogger()
	al.Log("agent-1", "read", Allow)
	al.Log("agent-2", "write", Deny)
	al.Log("agent-1", "delete", Deny)

	entries := al.GetEntries(AuditFilter{AgentID: "agent-1"})
	if len(entries) != 2 {
		t.Errorf("filtered entries = %d, want 2", len(entries))
	}

	d := Deny
	entries = al.GetEntries(AuditFilter{Decision: &d})
	if len(entries) != 2 {
		t.Errorf("deny-filtered entries = %d, want 2", len(entries))
	}
}

func TestAuditEmptyVerify(t *testing.T) {
	al := NewAuditLogger()
	if !al.Verify() {
		t.Error("empty chain should verify as true")
	}
}

func TestAuditHashesAreUnique(t *testing.T) {
	al := NewAuditLogger()
	e1 := al.Log("a", "action1", Allow)
	e2 := al.Log("a", "action2", Allow)
	if e1.Hash == e2.Hash {
		t.Error("different entries should have different hashes")
	}
}

func TestExportJSON(t *testing.T) {
	al := NewAuditLogger()
	al.Log("agent-1", "read", Allow)
	al.Log("agent-2", "write", Deny)

	jsonStr, err := al.ExportJSON()
	if err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}
	if jsonStr == "" {
		t.Error("ExportJSON returned empty string")
	}
	if len(jsonStr) < 10 {
		t.Error("ExportJSON result too short")
	}
}

func TestMaxEntriesRetention(t *testing.T) {
	al := NewAuditLogger()
	al.MaxEntries = 3

	al.Log("a1", "action1", Allow)
	al.Log("a2", "action2", Deny)
	al.Log("a3", "action3", Allow)
	al.Log("a4", "action4", Deny)

	entries := al.GetEntries(AuditFilter{})
	if len(entries) != 3 {
		t.Errorf("entries after retention = %d, want 3", len(entries))
	}
	if entries[0].AgentID != "a2" {
		t.Errorf("oldest entry agent = %q, want a2", entries[0].AgentID)
	}
}

func TestMaxEntriesVerify(t *testing.T) {
	al := NewAuditLogger()
	al.MaxEntries = 2

	al.Log("a1", "x", Allow)
	al.Log("a2", "y", Deny)
	al.Log("a3", "z", Allow)

	if !al.Verify() {
		t.Error("chain with retention eviction should still verify")
	}
}
