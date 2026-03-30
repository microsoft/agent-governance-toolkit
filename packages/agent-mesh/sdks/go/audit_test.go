package agentmesh

import (
	"fmt"
	"testing"
	"time"
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

// --- New comprehensive tests ---

func TestAuditEmptyLogVerifies(t *testing.T) {
	al := NewAuditLogger()
	if !al.Verify() {
		t.Error("empty log should verify as true")
	}
}

func TestAuditFirstEntryEmptyPreviousHash(t *testing.T) {
	al := NewAuditLogger()
	e := al.Log("agent", "action", Allow)
	if e.PreviousHash != "" {
		t.Errorf("first entry PreviousHash = %q, want empty", e.PreviousHash)
	}
}

func TestAuditChainOf100Entries(t *testing.T) {
	al := NewAuditLogger()
	for i := 0; i < 100; i++ {
		al.Log(fmt.Sprintf("agent-%d", i%5), fmt.Sprintf("action-%d", i), Allow)
	}
	if !al.Verify() {
		t.Error("chain of 100 entries should verify")
	}

	entries := al.GetEntries(AuditFilter{})
	if len(entries) != 100 {
		t.Errorf("entries count = %d, want 100", len(entries))
	}
}

func TestAuditTamperMiddleOfChain(t *testing.T) {
	al := NewAuditLogger()
	for i := 0; i < 10; i++ {
		al.Log("agent", fmt.Sprintf("action-%d", i), Allow)
	}

	// Tamper with entry in the middle
	al.entries[5].Action = "tampered-action"
	if al.Verify() {
		t.Error("chain should be invalid after tampering with middle entry")
	}
}

func TestAuditTamperPreviousHashField(t *testing.T) {
	al := NewAuditLogger()
	al.Log("agent", "action-0", Allow)
	al.Log("agent", "action-1", Allow)
	al.Log("agent", "action-2", Allow)

	// Tamper with PreviousHash of entry 2
	al.entries[2].PreviousHash = "fake-hash-value"
	if al.Verify() {
		t.Error("chain should be invalid after tampering with PreviousHash")
	}
}

func TestAuditTamperFirstEntryPreviousHash(t *testing.T) {
	al := NewAuditLogger()
	al.Log("agent", "action-0", Allow)
	al.Log("agent", "action-1", Allow)

	// Set first entry's PreviousHash to non-empty
	al.entries[0].PreviousHash = "should-be-empty"
	if al.Verify() {
		t.Error("chain should be invalid when first entry has non-empty PreviousHash")
	}
}

func TestAuditFilterByAgentIDOnly(t *testing.T) {
	al := NewAuditLogger()
	al.Log("agent-A", "read", Allow)
	al.Log("agent-B", "write", Allow)
	al.Log("agent-A", "delete", Deny)
	al.Log("agent-C", "read", Allow)
	al.Log("agent-A", "update", Review)

	entries := al.GetEntries(AuditFilter{AgentID: "agent-A"})
	if len(entries) != 3 {
		t.Errorf("agent-A entries = %d, want 3", len(entries))
	}
	for _, e := range entries {
		if e.AgentID != "agent-A" {
			t.Errorf("filtered entry has AgentID = %q, want agent-A", e.AgentID)
		}
	}
}

func TestAuditFilterByActionOnly(t *testing.T) {
	al := NewAuditLogger()
	al.Log("agent-1", "read", Allow)
	al.Log("agent-2", "write", Allow)
	al.Log("agent-3", "read", Deny)
	al.Log("agent-1", "delete", Deny)

	entries := al.GetEntries(AuditFilter{Action: "read"})
	if len(entries) != 2 {
		t.Errorf("read entries = %d, want 2", len(entries))
	}
	for _, e := range entries {
		if e.Action != "read" {
			t.Errorf("filtered entry has Action = %q, want read", e.Action)
		}
	}
}

func TestAuditFilterByDecisionOnly(t *testing.T) {
	al := NewAuditLogger()
	al.Log("a", "x", Allow)
	al.Log("b", "y", Deny)
	al.Log("c", "z", Review)
	al.Log("d", "w", Allow)

	allow := Allow
	entries := al.GetEntries(AuditFilter{Decision: &allow})
	if len(entries) != 2 {
		t.Errorf("allow entries = %d, want 2", len(entries))
	}

	review := Review
	entries = al.GetEntries(AuditFilter{Decision: &review})
	if len(entries) != 1 {
		t.Errorf("review entries = %d, want 1", len(entries))
	}
}

func TestAuditFilterMultipleCriteria(t *testing.T) {
	al := NewAuditLogger()
	al.Log("agent-A", "read", Allow)
	al.Log("agent-A", "write", Deny)
	al.Log("agent-B", "read", Allow)
	al.Log("agent-A", "read", Deny)

	deny := Deny
	entries := al.GetEntries(AuditFilter{AgentID: "agent-A", Action: "read", Decision: &deny})
	if len(entries) != 1 {
		t.Errorf("multi-criteria entries = %d, want 1", len(entries))
	}
	if len(entries) == 1 {
		if entries[0].AgentID != "agent-A" || entries[0].Action != "read" || entries[0].Decision != Deny {
			t.Error("entry doesn't match all criteria")
		}
	}
}

func TestAuditFilterMatchesNothing(t *testing.T) {
	al := NewAuditLogger()
	al.Log("agent-A", "read", Allow)
	al.Log("agent-B", "write", Deny)

	entries := al.GetEntries(AuditFilter{AgentID: "agent-C"})
	if len(entries) != 0 {
		t.Errorf("non-matching filter entries = %d, want 0", len(entries))
	}
}

func TestAuditFilterEmptyReturnsAll(t *testing.T) {
	al := NewAuditLogger()
	al.Log("a", "x", Allow)
	al.Log("b", "y", Deny)
	al.Log("c", "z", Review)

	entries := al.GetEntries(AuditFilter{})
	if len(entries) != 3 {
		t.Errorf("empty filter entries = %d, want 3", len(entries))
	}
}

func TestAuditHashDeterministic(t *testing.T) {
	// Create two entries with the same data at the same timestamp
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	e1 := &AuditEntry{
		Timestamp:    ts,
		AgentID:      "agent",
		Action:       "read",
		Decision:     Allow,
		PreviousHash: "",
	}
	e2 := &AuditEntry{
		Timestamp:    ts,
		AgentID:      "agent",
		Action:       "read",
		Decision:     Allow,
		PreviousHash: "",
	}

	h1 := computeHash(e1)
	h2 := computeHash(e2)

	if h1 != h2 {
		t.Errorf("same input should produce same hash: %q != %q", h1, h2)
	}

	// Different data produces different hash
	e3 := &AuditEntry{
		Timestamp:    ts,
		AgentID:      "other-agent",
		Action:       "read",
		Decision:     Allow,
		PreviousHash: "",
	}
	h3 := computeHash(e3)
	if h1 == h3 {
		t.Error("different input should produce different hash")
	}
}

func TestAuditEntriesChainedCorrectly(t *testing.T) {
	al := NewAuditLogger()
	e1 := al.Log("a", "action1", Allow)
	e2 := al.Log("a", "action2", Deny)
	e3 := al.Log("a", "action3", Review)

	if e1.PreviousHash != "" {
		t.Error("first entry PreviousHash should be empty")
	}
	if e2.PreviousHash != e1.Hash {
		t.Error("second entry PreviousHash should equal first Hash")
	}
	if e3.PreviousHash != e2.Hash {
		t.Error("third entry PreviousHash should equal second Hash")
	}
}

func TestAuditEntriesPreserveAllFields(t *testing.T) {
	al := NewAuditLogger()
	e := al.Log("my-agent", "my-action", Review)

	if e.AgentID != "my-agent" {
		t.Errorf("AgentID = %q, want my-agent", e.AgentID)
	}
	if e.Action != "my-action" {
		t.Errorf("Action = %q, want my-action", e.Action)
	}
	if e.Decision != Review {
		t.Errorf("Decision = %q, want review", e.Decision)
	}
	if e.Hash == "" {
		t.Error("Hash should not be empty")
	}
	if e.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestAuditFilterByTimeRange(t *testing.T) {
	al := NewAuditLogger()

	al.Log("agent", "early", Allow)
	time.Sleep(10 * time.Millisecond)
	midTime := time.Now().UTC()
	time.Sleep(10 * time.Millisecond)
	al.Log("agent", "late", Allow)

	// Filter entries after midTime
	entries := al.GetEntries(AuditFilter{StartTime: &midTime})
	if len(entries) != 1 {
		t.Errorf("after midTime entries = %d, want 1", len(entries))
	}
	if len(entries) == 1 && entries[0].Action != "late" {
		t.Errorf("expected late action, got %q", entries[0].Action)
	}
}

func TestAuditVerifyAfterMultipleTamperTypes(t *testing.T) {
	t.Run("tamper_hash", func(t *testing.T) {
		al := NewAuditLogger()
		al.Log("a", "x", Allow)
		al.Log("a", "y", Allow)
		al.entries[0].Hash = "bad-hash"
		if al.Verify() {
			t.Error("should detect hash tampering")
		}
	})

	t.Run("tamper_agent_id", func(t *testing.T) {
		al := NewAuditLogger()
		al.Log("a", "x", Allow)
		al.entries[0].AgentID = "changed"
		if al.Verify() {
			t.Error("should detect AgentID tampering")
		}
	})

	t.Run("tamper_decision", func(t *testing.T) {
		al := NewAuditLogger()
		al.Log("a", "x", Allow)
		al.entries[0].Decision = Deny
		if al.Verify() {
			t.Error("should detect Decision tampering")
		}
	})
}

func TestAuditSingleEntryVerifies(t *testing.T) {
	al := NewAuditLogger()
	al.Log("agent", "action", Allow)
	if !al.Verify() {
		t.Error("single entry chain should verify")
	}
}
