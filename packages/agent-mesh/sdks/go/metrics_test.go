// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import "testing"

func TestNewGovernanceMetrics(t *testing.T) {
	m := NewGovernanceMetrics(true)
	if !m.Enabled {
		t.Error("expected Enabled=true")
	}
	m2 := NewGovernanceMetrics(false)
	if m2.Enabled {
		t.Error("expected Enabled=false")
	}
}

func TestMetricsNoOps(t *testing.T) {
	m := NewGovernanceMetrics(true)
	// Should not panic
	m.RecordPolicyDecision("allow", 1.5)
	m.RecordTrustScore("agent-1", 750.0)
	m.RecordAuditEntry(42)
}
