package agentmesh

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if len(entries) != 4 {
		t.Fatalf("audit entries = %d, want 4", len(entries))
	}
}

func TestCanonicalJSONDoesNotEscapeHTMLAndUsesUTF16KeyOrder(t *testing.T) {
	highBMP := "\ue000"
	supplementary := "\U00010000"

	data, err := canonicalJSON(map[string]interface{}{
		"statement":   "select '<>&' from urls",
		highBMP:       2,
		supplementary: 1,
	})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	got := string(data)
	if strings.Contains(got, `\u003c`) || strings.Contains(got, `\u003e`) || strings.Contains(got, `\u0026`) {
		t.Fatalf("canonical JSON escaped HTML characters: %s", got)
	}
	wantOrder := `"` + supplementary + `":1,"` + highBMP + `":2`
	if !strings.Contains(got, wantOrder) {
		t.Fatalf("canonical JSON key order = %s, want supplementary key before high-BMP key", got)
	}
}

func TestApprovalCoordinatorOpenSubmitValidateConsume(t *testing.T) {
	coordinator := NewApprovalCoordinator(
		ApprovalChain{
			ChainID: "manual-chain",
			Version: "1",
			Stages: []ApprovalStage{
				{StageIndex: 0, ApproverKind: ApproverHuman, AllowedIdentities: []string{"did:web:example.com:alice"}},
			},
		},
		WithApprovalPolicyVersion("2026.07.01"),
	)

	opened, err := coordinator.OpenRequest(productionBinding())
	if err != nil {
		t.Fatalf("OpenRequest: %v", err)
	}
	result, err := coordinator.SubmitEntry(opened.Request.ApprovalRequestID, 0, ApprovalVote{
		ApproverKind:      ApproverHuman,
		ApproverIdentity:  "did:web:example.com:alice",
		IdentityAssurance: "oidc",
		Decision:          ApprovalEntryAllow,
		ReasonCode:        "reviewed",
	})
	if err != nil {
		t.Fatalf("SubmitEntry: %v", err)
	}
	if result.Resolution.Outcome != ApprovalOutcomeAllow {
		t.Fatalf("outcome = %s, want allow", result.Resolution.Outcome)
	}

	check := coordinator.CheckApprovalForExecution(opened.Request.ApprovalRequestID, productionBinding())
	if !check.Allowed || check.Consumed {
		t.Fatalf("check = %#v, want allowed without consume", check)
	}
	consumed := coordinator.ValidateForExecution(opened.Request.ApprovalRequestID, productionBinding())
	if !consumed.Allowed || !consumed.Consumed {
		t.Fatalf("consume = %#v, want allowed consumed", consumed)
	}
	replay := coordinator.ValidateForExecution(opened.Request.ApprovalRequestID, productionBinding())
	if replay.Allowed || replay.ReasonCode != "approval_consumed" {
		t.Fatalf("replay = %#v, want approval_consumed deny", replay)
	}
}

func TestApprovalCoordinatorOpenRequestInvalidConfig(t *testing.T) {
	coordinator := NewApprovalCoordinator(ApprovalChain{
		Version: "1",
		Stages: []ApprovalStage{
			{StageIndex: 0, ApproverKind: ApproverHuman},
		},
	})

	result, err := coordinator.OpenRequest(productionBinding())
	if err == nil {
		t.Fatal("OpenRequest should fail when chain id is missing")
	}
	if result == nil || result.Resolution.ReasonCode != "invalid_approval_chain" {
		t.Fatalf("result = %#v, want invalid_approval_chain", result)
	}
}

func TestApprovalCoordinatorRejectsInvalidActionBinding(t *testing.T) {
	validChain := ApprovalChain{
		ChainID: "binding-validation",
		Version: "1",
		Stages: []ApprovalStage{
			{StageIndex: 0, ApproverKind: ApproverHuman},
		},
	}
	cases := []struct {
		name   string
		mutate func(*ActionBinding)
	}{
		{
			name: "missing operation",
			mutate: func(binding *ActionBinding) {
				binding.Operation = " "
			},
		},
		{
			name: "missing agent",
			mutate: func(binding *ActionBinding) {
				binding.AgentID = ""
			},
		},
		{
			name: "missing tool name",
			mutate: func(binding *ActionBinding) {
				binding.Target.ToolName = ""
			},
		},
		{
			name: "missing tool schema",
			mutate: func(binding *ActionBinding) {
				binding.Target.ToolSchemaVersion = ""
			},
		},
		{
			name: "unsupported schema",
			mutate: func(binding *ActionBinding) {
				binding.SchemaVersion = "2.0"
			},
		},
		{
			name: "nul resource",
			mutate: func(binding *ActionBinding) {
				binding.Target.Resource = "prod\x00db"
			},
		},
		{
			name: "nonfinite parameter",
			mutate: func(binding *ActionBinding) {
				binding.Parameters["amount"] = math.Inf(1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coordinator := NewApprovalCoordinator(validChain)
			binding := productionBinding()
			tc.mutate(&binding)

			result, err := coordinator.OpenRequest(binding)
			if err == nil {
				t.Fatalf("OpenRequest should reject %s", tc.name)
			}
			if result == nil || result.Resolution.ReasonCode != "invalid_action_binding" {
				t.Fatalf("result = %#v, want invalid_action_binding", result)
			}
		})
	}
}

func TestValidateForExecutionRejectsInvalidActionBinding(t *testing.T) {
	coordinator := NewApprovalCoordinator(ApprovalChain{
		ChainID: "execution-binding-validation",
		Version: "1",
		Stages: []ApprovalStage{
			{StageIndex: 0, ApproverKind: ApproverHuman, AllowedIdentities: []string{"did:web:example.com:alice"}},
		},
	})
	opened, err := coordinator.OpenRequest(productionBinding())
	if err != nil {
		t.Fatalf("OpenRequest: %v", err)
	}
	if _, err := coordinator.SubmitEntry(opened.Request.ApprovalRequestID, 0, ApprovalVote{
		ApproverKind:     ApproverHuman,
		ApproverIdentity: "did:web:example.com:alice",
		Decision:         ApprovalEntryAllow,
	}); err != nil {
		t.Fatalf("SubmitEntry: %v", err)
	}

	invalidBinding := productionBinding()
	invalidBinding.Operation = ""
	decision := coordinator.CheckApprovalForExecution(opened.Request.ApprovalRequestID, invalidBinding)
	if decision.Allowed || decision.ReasonCode != "invalid_action_binding" {
		t.Fatalf("decision = %#v, want invalid_action_binding deny", decision)
	}
}

func TestApprovalCoordinatorSubmitEntryInvalidStageIndex(t *testing.T) {
	coordinator := NewApprovalCoordinator(ApprovalChain{
		ChainID: "invalid-stage",
		Version: "1",
		Stages: []ApprovalStage{
			{StageIndex: 0, ApproverKind: ApproverHuman, AllowedIdentities: []string{"did:web:example.com:alice"}},
		},
	})
	opened, err := coordinator.OpenRequest(productionBinding())
	if err != nil {
		t.Fatalf("OpenRequest: %v", err)
	}

	result, err := coordinator.SubmitEntry(opened.Request.ApprovalRequestID, 99, ApprovalVote{
		ApproverKind:     ApproverHuman,
		ApproverIdentity: "did:web:example.com:alice",
		Decision:         ApprovalEntryAllow,
	})
	if err == nil {
		t.Fatal("SubmitEntry should reject an invalid stage index")
	}
	if result == nil || result.Resolution.ApprovalResolutionID != "" {
		t.Fatalf("result = %#v, want unresolved pending result", result)
	}
}

func TestApprovalCoordinatorSubmitEntryIsIdempotent(t *testing.T) {
	coordinator := NewApprovalCoordinator(ApprovalChain{
		ChainID: "idempotent-resubmission",
		Version: "1",
		Stages: []ApprovalStage{
			{StageIndex: 0, ApproverKind: ApproverHuman, AllowedIdentities: []string{"did:web:example.com:alice"}},
			{StageIndex: 1, ApproverKind: ApproverHuman, AllowedIdentities: []string{"did:web:example.com:bob"}},
		},
	})
	opened, err := coordinator.OpenRequest(productionBinding())
	if err != nil {
		t.Fatalf("OpenRequest: %v", err)
	}

	firstVote := ApprovalVote{
		ApproverKind:     ApproverHuman,
		ApproverIdentity: "did:web:example.com:alice",
		Decision:         ApprovalEntryAllow,
		ChainEntryID:     "ace-retry-alice",
	}
	first, err := coordinator.SubmitEntry(opened.Request.ApprovalRequestID, 0, firstVote)
	if err != nil {
		t.Fatalf("SubmitEntry first stage: %v", err)
	}
	if first.Resolution.ApprovalResolutionID != "" || len(first.Entries) != 1 {
		t.Fatalf("first result = %#v, want one entry and pending request", first)
	}

	retriedPending, err := coordinator.SubmitEntry(opened.Request.ApprovalRequestID, 0, firstVote)
	if err != nil {
		t.Fatalf("SubmitEntry pending retry: %v", err)
	}
	if len(retriedPending.Entries) != 1 || retriedPending.Entries[0].EntryDigest != first.Entries[0].EntryDigest {
		t.Fatalf("pending retry entries = %#v, want original entry only", retriedPending.Entries)
	}

	secondVote := ApprovalVote{
		ApproverKind:     ApproverHuman,
		ApproverIdentity: "did:web:example.com:bob",
		Decision:         ApprovalEntryAllow,
		ChainEntryID:     "ace-retry-bob",
	}
	resolved, err := coordinator.SubmitEntry(opened.Request.ApprovalRequestID, 1, secondVote)
	if err != nil {
		t.Fatalf("SubmitEntry second stage: %v", err)
	}
	if resolved.Resolution.Outcome != ApprovalOutcomeAllow || len(resolved.Entries) != 2 {
		t.Fatalf("resolved result = %#v, want allow with two entries", resolved)
	}

	retriedResolved, err := coordinator.SubmitEntry(opened.Request.ApprovalRequestID, 1, secondVote)
	if err != nil {
		t.Fatalf("SubmitEntry resolved retry: %v", err)
	}
	if len(retriedResolved.Entries) != 2 || retriedResolved.Resolution.ApprovalResolutionID != resolved.Resolution.ApprovalResolutionID {
		t.Fatalf("resolved retry = %#v, want original entries and resolution", retriedResolved)
	}
}

func TestApprovalCoordinatorSubmitEntryRejectsUnauthorizedApprover(t *testing.T) {
	for _, decision := range []ApprovalEntryDecision{ApprovalEntryAllow, ApprovalEntryDeny} {
		t.Run(string(decision), func(t *testing.T) {
			coordinator := NewApprovalCoordinator(ApprovalChain{
				ChainID: "unauthorized-approver",
				Version: "1",
				Stages: []ApprovalStage{
					{StageIndex: 0, ApproverKind: ApproverHuman, AllowedIdentities: []string{"did:web:example.com:alice"}},
				},
			})
			opened, err := coordinator.OpenRequest(productionBinding())
			if err != nil {
				t.Fatalf("OpenRequest: %v", err)
			}

			result, err := coordinator.SubmitEntry(opened.Request.ApprovalRequestID, 0, ApprovalVote{
				ApproverKind:     ApproverHuman,
				ApproverIdentity: "did:web:example.com:eve",
				Decision:         decision,
			})
			if err == nil || !strings.Contains(err.Error(), "not permitted") {
				t.Fatalf("SubmitEntry error = %v, want not permitted", err)
			}
			if result == nil || result.Request.Status != ApprovalPending || result.Resolution.ApprovalResolutionID != "" || len(result.Entries) != 0 {
				t.Fatalf("unauthorized result = %#v, want unchanged pending request", result)
			}

			approved, err := coordinator.SubmitEntry(opened.Request.ApprovalRequestID, 0, ApprovalVote{
				ApproverKind:     ApproverHuman,
				ApproverIdentity: "did:web:example.com:alice",
				Decision:         ApprovalEntryAllow,
			})
			if err != nil {
				t.Fatalf("SubmitEntry authorized: %v", err)
			}
			if approved.Resolution.Outcome != ApprovalOutcomeAllow {
				t.Fatalf("authorized result = %#v, want allow", approved)
			}
		})
	}
}

func TestApprovalCoordinatorRequestApprovalNoRequiredStage(t *testing.T) {
	coordinator := NewApprovalCoordinator(ApprovalChain{
		ChainID: "no-required-stage",
		Version: "1",
		Stages: []ApprovalStage{
			{StageIndex: 0, ApproverKind: ApproverHuman, Optional: true},
		},
	})

	result, err := coordinator.RequestApproval(context.Background(), productionBinding())
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if result.Decision != Deny || result.Resolution.ReasonCode != "no_required_approval_stage" {
		t.Fatalf("result = %#v, want no_required_approval_stage deny", result)
	}
}

func TestValidateForExecutionRejectsDigestPolicyAndTamper(t *testing.T) {
	store := NewInMemoryApprovalStore()
	coordinator := NewApprovalCoordinator(
		ApprovalChain{
			ChainID: "validate-chain",
			Version: "1",
			Stages: []ApprovalStage{
				{StageIndex: 0, ApproverKind: ApproverHuman, AllowedIdentities: []string{"did:web:example.com:alice"}},
			},
		},
		WithApprovalPolicyVersion("2026.07.01"),
		WithApprovalStore(store),
	)
	opened, err := coordinator.OpenRequest(productionBinding())
	if err != nil {
		t.Fatalf("OpenRequest: %v", err)
	}
	if _, err := coordinator.SubmitEntry(opened.Request.ApprovalRequestID, 0, ApprovalVote{
		ApproverKind:     ApproverHuman,
		ApproverIdentity: "did:web:example.com:alice",
		Decision:         ApprovalEntryAllow,
	}); err != nil {
		t.Fatalf("SubmitEntry: %v", err)
	}

	changedBinding := productionBinding()
	changedBinding.Parameters = map[string]interface{}{
		"statement": "update accounts set status = ? where id = ?",
		"values":    []interface{}{"closed", 43},
	}
	if decision := coordinator.CheckApprovalForExecution(opened.Request.ApprovalRequestID, changedBinding); decision.Allowed || decision.ReasonCode != "action_digest_mismatch" {
		t.Fatalf("digest mismatch decision = %#v", decision)
	}

	coordinator.policyVersion = "2026.07.02"
	if decision := coordinator.CheckApprovalForExecution(opened.Request.ApprovalRequestID, productionBinding()); decision.Allowed || decision.ReasonCode != "policy_version_mismatch" {
		t.Fatalf("policy mismatch decision = %#v", decision)
	}
	coordinator.policyVersion = "2026.07.01"

	store.mu.Lock()
	store.records[opened.Request.ApprovalRequestID].entries[0].ReasonCode = "tampered"
	store.mu.Unlock()
	if decision := coordinator.CheckApprovalForExecution(opened.Request.ApprovalRequestID, productionBinding()); decision.Allowed || decision.ReasonCode != "approval_chain_tampered" {
		t.Fatalf("tamper decision = %#v", decision)
	}
}

func TestLLMAdvisoryDoesNotSatisfyApprovalStage(t *testing.T) {
	coordinator := NewApprovalCoordinator(ApprovalChain{
		ChainID: "advisory-chain",
		Version: "1",
		Stages: []ApprovalStage{
			{StageIndex: 0, ApproverKind: ApproverLLMAdvisory},
			{StageIndex: 1, ApproverKind: ApproverHuman, AllowedIdentities: []string{"did:web:example.com:alice"}},
		},
	})

	opened, err := coordinator.OpenRequest(productionBinding())
	if err != nil {
		t.Fatalf("OpenRequest: %v", err)
	}
	afterAdvisory, err := coordinator.SubmitEntry(opened.Request.ApprovalRequestID, 0, ApprovalVote{
		ApproverKind:     ApproverLLMAdvisory,
		ApproverIdentity: "llm:reviewer",
		Decision:         ApprovalEntryAllow,
		ReasonCode:       "looks_safe",
	})
	if err != nil {
		t.Fatalf("SubmitEntry advisory: %v", err)
	}
	if afterAdvisory.Resolution.ApprovalResolutionID != "" {
		t.Fatalf("advisory entry resolved request: %#v", afterAdvisory.Resolution)
	}
	if decision := coordinator.CheckApprovalForExecution(opened.Request.ApprovalRequestID, productionBinding()); decision.Allowed || decision.ReasonCode != "approval_pending" {
		t.Fatalf("advisory execution decision = %#v, want approval_pending", decision)
	}

	final, err := coordinator.SubmitEntry(opened.Request.ApprovalRequestID, 1, ApprovalVote{
		ApproverKind:     ApproverHuman,
		ApproverIdentity: "did:web:example.com:alice",
		Decision:         ApprovalEntryAllow,
	})
	if err != nil {
		t.Fatalf("SubmitEntry human: %v", err)
	}
	if final.Resolution.Outcome != ApprovalOutcomeAllow {
		t.Fatalf("outcome = %s, want allow", final.Resolution.Outcome)
	}
}

func TestWebhookRolesSatisfyAllowedRoles(t *testing.T) {
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
			"roles":               []string{"security-reviewer"},
		})
	}))
	defer server.Close()

	approver, err := NewWebhookApprover(server.URL, WithWebhookResponseVerifier(verifiedApproverFromBody))
	if err != nil {
		t.Fatalf("NewWebhookApprover: %v", err)
	}
	coordinator := NewApprovalCoordinator(ApprovalChain{
		ChainID: "role-chain",
		Version: "1",
		Stages: []ApprovalStage{
			{StageIndex: 0, ApproverKind: ApproverHuman, AllowedRoles: []string{"security-reviewer"}, Transport: approver},
		},
	})

	result, err := coordinator.RequestApproval(context.Background(), productionBinding())
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if result.Decision != Allow {
		t.Fatalf("decision = %s, want allow", result.Decision)
	}
	if len(result.Entries) != 1 || len(result.Entries[0].Roles) != 1 || result.Entries[0].Roles[0] != "security-reviewer" {
		t.Fatalf("entry roles = %#v, want security-reviewer", result.Entries)
	}
}

func TestApprovalWebhookBlocksIMDSIPv6(t *testing.T) {
	if _, err := NewWebhookApprover("http://[fd00:ec2::254]/approve"); err == nil {
		t.Fatal("expected fd00:ec2::254 approval webhook URL to be blocked")
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

func TestExecuteWithGovernanceRetainsApprovalOnApprovalError(t *testing.T) {
	coordinator := NewApprovalCoordinator(ApprovalChain{
		Version: "1",
		Stages: []ApprovalStage{
			{StageIndex: 0, ApproverKind: ApproverHuman, AllowedIdentities: []string{"did:web:example.com:alice"}},
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
	if result.Decision != Deny || result.Allowed {
		t.Fatalf("decision=%s allowed=%v, want deny false", result.Decision, result.Allowed)
	}
	if result.Approval == nil {
		t.Fatal("approval result should be retained on approval error")
	}
	if result.Approval.Resolution.ReasonCode != "invalid_approval_chain" {
		t.Fatalf("approval reason = %s, want invalid_approval_chain", result.Approval.Resolution.ReasonCode)
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
