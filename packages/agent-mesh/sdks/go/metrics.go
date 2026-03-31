// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

// GovernanceMetrics provides observability stubs for governance operations.
// When a real metrics backend (OpenTelemetry, Prometheus) is configured,
// replace these no-ops with real instrumentation.
type GovernanceMetrics struct {
	Enabled bool
}

// NewGovernanceMetrics creates a new metrics recorder.
func NewGovernanceMetrics(enabled bool) *GovernanceMetrics {
	return &GovernanceMetrics{Enabled: enabled}
}

// RecordPolicyDecision records a policy evaluation result.
func (m *GovernanceMetrics) RecordPolicyDecision(decision string, durationMs float64) {
	// No-op stub — replace with OTel/Prometheus when configured
}

// RecordTrustScore records a trust score update.
func (m *GovernanceMetrics) RecordTrustScore(agentID string, score float64) {
	// No-op stub
}

// RecordAuditEntry records an audit chain append.
func (m *GovernanceMetrics) RecordAuditEntry(seq uint64) {
	// No-op stub
}
