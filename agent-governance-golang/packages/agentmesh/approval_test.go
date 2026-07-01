package agentmesh

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestActionBindingDigestStableAndSensitive(t *testing.T) {
	left := ActionBinding{
		Operation: "tool.invoke",
		AgentID:   "agent-1",
		Target: ActionTarget{
			ToolName:          "sql_execute",
			ToolSchemaVersion: "1",
			Resource:          "prod-db",
		},
		Parameters: map[string]interface{}{
			"statement": "select * from accounts where id = ?",
			"values":    []interface{}{42},
		},
	}
	right := left
	right.Parameters = map[string]interface{}{
		"values":    []interface{}{42},
		"statement": "select * from accounts where id = ?",
	}

	leftDigest, err := left.Digest()
	if err != nil {
		t.Fatalf("left digest: %v", err)
	}
	rightDigest, err := right.Digest()
	if err != nil {
		t.Fatalf("right digest: %v", err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("equivalent bindings produced different digests: %s != %s", leftDigest, rightDigest)
	}

	right.Parameters["values"] = []interface{}{43}
	changedDigest, err := right.Digest()
	if err != nil {
		t.Fatalf("changed digest: %v", err)
	}
	if changedDigest == leftDigest {
		t.Fatal("changing parameters should change the action digest")
	}
}

func TestApprovalCoordinatorWebhookAllow(t *testing.T) {
	audit := NewAuditLogger()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if payload["schema_version"] != approvalSchemaVersion {
			t.Errorf("schema_version = %v, want %s", payload["schema_version"], approvalSchemaVersion)
			http.Error(w, "bad schema version", http.StatusBadRequest)
			return
		}
		if payload["approval_request_id"] == "" || payload["action_digest"] == "" {
			t.Errorf("payload missing approval binding fields: %#v", payload)
			http.Error(w, "missing binding fields", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"approval_request_id": payload["approval_request_id"],
			"action_digest":       payload["action_digest"],
			"approved":            true,
			"verified_approver":   "did:web:example.com:alice",
			"approver_kind":       "human",
			"identity_assurance":  "oidc",
			"reason":              "reviewed-production-change",
		})
	}))
	defer server.Close()

	approver, err := NewWebhookApprover(server.URL, WithWebhookResponseVerifier(verifiedApproverFromBody))
	if err != nil {
		t.Fatalf("NewWebhookApprover: %v", err)
	}
	coordinator := NewApprovalCoordinator(
		ApprovalChain{
			ChainID: "high-risk-tools",
			Version: "1",
			Stages: []ApprovalStage{
				{
					StageIndex:        0,
					ApproverKind:      ApproverHuman,
					AllowedIdentities: []string{"did:web:example.com:alice"},
					Transport:         approver,
				},
			},
		},
		WithApprovalPolicyRuleID("production-db-writes"),
		WithApprovalPolicyVersion("2026.07.01"),
		WithApprovalAuditLogger(audit),
	)

	result, err := coordinator.RequestApproval(context.Background(), productionBinding())
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if result.Decision != Allow || !result.Allowed {
		t.Fatalf("decision = %s allowed=%v, want allow true", result.Decision, result.Allowed)
	}
	if result.Resolution.Outcome != ApprovalOutcomeAllow {
		t.Fatalf("outcome = %s, want allow", result.Resolution.Outcome)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(result.Entries))
	}
	if result.Entries[0].EntryDigest == "" {
		t.Fatal("approval chain entry missing digest")
	}
	if !audit.Verify() {
		t.Fatal("approval audit chain should verify")
	}
	entries := audit.GetEntries(AuditFilter{})
	if len(entries) != 3 {
		t.Fatalf("audit entries = %d, want 3", len(entries))
	}
}

func TestApprovalCoordinatorWebhookDenyShortCircuits(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"approval_request_id": payload["approval_request_id"],
			"action_digest":       payload["action_digest"],
			"approved":            false,
			"approver":            "did:web:example.com:alice",
			"reason":              "too_risky",
		})
	}))
	defer first.Close()

	secondCalled := false
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()

	firstApprover, err := NewWebhookApprover(first.URL, WithWebhookResponseVerifier(verifiedApproverFromBody))
	if err != nil {
		t.Fatalf("first approver: %v", err)
	}
	secondApprover, err := NewWebhookApprover(second.URL, WithWebhookResponseVerifier(verifiedApproverFromBody))
	if err != nil {
		t.Fatalf("second approver: %v", err)
	}

	coordinator := NewApprovalCoordinator(ApprovalChain{
		ChainID: "two-stage",
		Version: "1",
		Stages: []ApprovalStage{
			{StageIndex: 0, AllowedIdentities: []string{"did:web:example.com:alice"}, Transport: firstApprover},
			{StageIndex: 1, AllowedIdentities: []string{"did:web:example.com:bob"}, Transport: secondApprover},
		},
	})

	result, err := coordinator.RequestApproval(context.Background(), productionBinding())
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if result.Decision != Deny || result.Resolution.Outcome != ApprovalOutcomeDeny {
		t.Fatalf("decision=%s outcome=%s, want deny", result.Decision, result.Resolution.Outcome)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(result.Entries))
	}
	if secondCalled {
		t.Fatal("deny should short-circuit before the second stage")
	}
}

func TestApprovalCoordinatorWebhookTimeoutFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	approver, err := NewWebhookApprover(server.URL, WithWebhookResponseVerifier(verifiedApproverFromBody))
	if err != nil {
		t.Fatalf("NewWebhookApprover: %v", err)
	}
	coordinator := NewApprovalCoordinator(
		ApprovalChain{
			ChainID: "timeouts",
			Version: "1",
			Stages: []ApprovalStage{
				{StageIndex: 0, AllowedIdentities: []string{"did:web:example.com:alice"}, Transport: approver},
			},
		},
		WithApprovalTimeout(10*time.Millisecond),
	)

	result, err := coordinator.RequestApproval(context.Background(), productionBinding())
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if result.Decision != Deny {
		t.Fatalf("decision = %s, want deny", result.Decision)
	}
	if result.Resolution.ReasonCode != "approval_transport_error" {
		t.Fatalf("reason = %s, want approval_transport_error", result.Resolution.ReasonCode)
	}
	if len(result.Entries) != 1 || result.Entries[0].Decision != ApprovalEntryDeny {
		t.Fatalf("timeout should produce one deny entry, got %#v", result.Entries)
	}
}

func TestWebhookBindingMismatchFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"approval_request_id": payload["approval_request_id"],
			"action_digest":       "sha256:wrong",
			"approved":            true,
			"verified_approver":   "did:web:example.com:alice",
		})
	}))
	defer server.Close()

	approver, err := NewWebhookApprover(server.URL, WithWebhookResponseVerifier(verifiedApproverFromBody))
	if err != nil {
		t.Fatalf("NewWebhookApprover: %v", err)
	}
	coordinator := NewApprovalCoordinator(ApprovalChain{
		ChainID: "binding",
		Version: "1",
		Stages: []ApprovalStage{
			{StageIndex: 0, AllowedIdentities: []string{"did:web:example.com:alice"}, Transport: approver},
		},
	})

	result, err := coordinator.RequestApproval(context.Background(), productionBinding())
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if result.Decision != Deny {
		t.Fatalf("decision = %s, want deny", result.Decision)
	}
	if result.Entries[0].ReasonCode != "action_digest_mismatch" {
		t.Fatalf("reason = %s, want action_digest_mismatch", result.Entries[0].ReasonCode)
	}
}

func TestExecuteWithGovernanceRoutesRequireApproval(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"approval_request_id": payload["approval_request_id"],
			"action_digest":       payload["action_digest"],
			"approved":            true,
			"verified_approver":   "did:web:example.com:alice",
		})
	}))
	defer server.Close()

	approver, err := NewWebhookApprover(server.URL, WithWebhookResponseVerifier(verifiedApproverFromBody))
	if err != nil {
		t.Fatalf("NewWebhookApprover: %v", err)
	}
	coordinator := NewApprovalCoordinator(ApprovalChain{
		ChainID: "client-chain",
		Version: "1",
		Stages: []ApprovalStage{
			{StageIndex: 0, AllowedIdentities: []string{"did:web:example.com:alice"}, Transport: approver},
		},
	})
	client, err := NewClient("approval-agent",
		WithPolicyRules([]PolicyRule{
			{Action: "deploy.production", Effect: Allow, MinApprovals: 1},
		}),
		WithApprovalCoordinator(coordinator),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.ExecuteWithGovernance("deploy.production", map[string]interface{}{"target": "prod"})
	if err != nil {
		t.Fatalf("ExecuteWithGovernance: %v", err)
	}
	if result.Decision != Allow || !result.Allowed {
		t.Fatalf("decision=%s allowed=%v, want allow true", result.Decision, result.Allowed)
	}
	if result.Approval == nil {
		t.Fatal("expected approval result to be attached")
	}
	if result.Approval.Request.ActionDigest == "" {
		t.Fatal("approval request missing action digest")
	}
}

func productionBinding() ActionBinding {
	return ActionBinding{
		Operation: "tool.invoke",
		AgentID:   "agent-1",
		Target: ActionTarget{
			ToolName:          "sql_execute",
			ToolSchemaVersion: "1",
			Resource:          "prod-db",
		},
		Parameters: map[string]interface{}{
			"statement": "update accounts set status = ? where id = ?",
			"values":    []interface{}{"closed", 42},
		},
	}
}

func verifiedApproverFromBody(body map[string]interface{}, _ ApprovalRequest) (string, bool) {
	identity, _ := body["verified_approver"].(string)
	return identity, identity != ""
}
