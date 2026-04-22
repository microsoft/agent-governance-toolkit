package agentmesh

import (
	"testing"
)

// ---- Existing tests above, new tests below ----

func TestNewClient(t *testing.T) {
	client, err := NewClient("test-agent",
		WithCapabilities([]string{"read", "write"}),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.Identity == nil {
		t.Fatal("Identity is nil")
	}
	if client.Trust == nil {
		t.Fatal("Trust is nil")
	}
	if client.Policy == nil {
		t.Fatal("Policy is nil")
	}
	if client.Audit == nil {
		t.Fatal("Audit is nil")
	}
}

func TestExecuteWithGovernanceAllow(t *testing.T) {
	client, _ := NewClient("gov-agent",
		WithPolicyRules([]PolicyRule{
			{Action: "data.read", Effect: Allow},
		}),
	)

	result, err := client.ExecuteWithGovernance("data.read", nil)
	if err != nil {
		t.Fatalf("ExecuteWithGovernance: %v", err)
	}
	if !result.Allowed {
		t.Error("expected Allowed = true")
	}
	if result.Decision != Allow {
		t.Errorf("decision = %q, want allow", result.Decision)
	}
	if result.AuditEntry == nil {
		t.Error("expected AuditEntry to be non-nil")
	}
}

func TestExecuteWithGovernanceDeny(t *testing.T) {
	client, _ := NewClient("gov-agent",
		WithPolicyRules([]PolicyRule{
			{Action: "data.delete", Effect: Deny},
		}),
	)

	result, err := client.ExecuteWithGovernance("data.delete", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Error("expected Allowed = false for denied action")
	}
}

func TestEndToEndGovernance(t *testing.T) {
	client, _ := NewClient("e2e-agent",
		WithCapabilities([]string{"data.read"}),
		WithPolicyRules([]PolicyRule{
			{Action: "data.read", Effect: Allow},
			{Action: "*", Effect: Deny},
		}),
	)

	// Allowed action
	r1, _ := client.ExecuteWithGovernance("data.read", nil)
	if !r1.Allowed {
		t.Error("data.read should be allowed")
	}

	// Denied action
	r2, _ := client.ExecuteWithGovernance("system.shutdown", nil)
	if r2.Allowed {
		t.Error("system.shutdown should be denied")
	}

	// Audit chain intact
	if !client.Audit.Verify() {
		t.Error("audit chain should verify")
	}

	// Trust score updated
	score := client.Trust.GetTrustScore(client.Identity.DID)
	if score.Overall == 0 {
		t.Error("trust score should be non-zero after interactions")
	}
}

// --- New comprehensive tests ---

func TestNewClientWithAllOptions(t *testing.T) {
	customCfg := TrustConfig{
		InitialScore:  0.7,
		DecayRate:     0.02,
		RewardFactor:  2.0,
		PenaltyFactor: 3.0,
		TierThresholds: TierThresholds{
			High:   0.9,
			Medium: 0.6,
		},
		MinInteractions: 5,
	}

	client, err := NewClient("all-opts-agent",
		WithCapabilities([]string{"read", "write", "admin"}),
		WithTrustConfig(customCfg),
		WithPolicyRules([]PolicyRule{
			{Action: "data.read", Effect: Allow},
			{Action: "*", Effect: Deny},
		}),
	)
	if err != nil {
		t.Fatalf("NewClient with all options: %v", err)
	}
	if client.Identity.DID != "did:agentmesh:all-opts-agent" {
		t.Errorf("DID = %q, want did:agentmesh:all-opts-agent", client.Identity.DID)
	}
	if len(client.Identity.Capabilities) != 3 {
		t.Errorf("Capabilities count = %d, want 3", len(client.Identity.Capabilities))
	}
	// Verify custom trust config is used (initial score should be 0.7)
	score := client.Trust.GetTrustScore("some-agent")
	if score.Overall != 0.7 {
		t.Errorf("initial trust score = %f, want 0.7 (custom config)", score.Overall)
	}
}

func TestNewClientWithCapabilitiesOnly(t *testing.T) {
	client, err := NewClient("caps-agent",
		WithCapabilities([]string{"execute", "monitor"}),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if len(client.Identity.Capabilities) != 2 {
		t.Errorf("capabilities = %d, want 2", len(client.Identity.Capabilities))
	}
	if client.Identity.Capabilities[0] != "execute" {
		t.Errorf("first capability = %q, want execute", client.Identity.Capabilities[0])
	}
}

func TestNewClientWithPolicyRulesOnly(t *testing.T) {
	rules := []PolicyRule{
		{Action: "file.read", Effect: Allow},
		{Action: "file.write", Effect: Review},
	}
	client, err := NewClient("policy-agent", WithPolicyRules(rules))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	d := client.Policy.Evaluate("file.read", nil)
	if d != Allow {
		t.Errorf("file.read decision = %q, want allow", d)
	}
	d = client.Policy.Evaluate("file.write", nil)
	if d != Review {
		t.Errorf("file.write decision = %q, want review", d)
	}
}

func TestNewClientWithTrustConfigOnly(t *testing.T) {
	cfg := TrustConfig{
		InitialScore:  0.3,
		DecayRate:     0.0,
		RewardFactor:  1.0,
		PenaltyFactor: 1.0,
		TierThresholds: TierThresholds{
			High:   0.8,
			Medium: 0.5,
		},
		MinInteractions: 1,
	}
	client, err := NewClient("trust-cfg-agent", WithTrustConfig(cfg))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	score := client.Trust.GetTrustScore(client.Identity.DID)
	if score.Overall != 0.3 {
		t.Errorf("initial score = %f, want 0.3", score.Overall)
	}
	if score.Tier != "low" {
		t.Errorf("tier = %q, want low for score 0.3", score.Tier)
	}
}

func TestNewClientNoOptions(t *testing.T) {
	client, err := NewClient("bare-agent")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.Identity == nil || client.Trust == nil || client.Policy == nil || client.Audit == nil {
		t.Fatal("all subsystems should be non-nil")
	}
	// Default trust config should yield initial score 0.5
	score := client.Trust.GetTrustScore(client.Identity.DID)
	if score.Overall != 0.5 {
		t.Errorf("default score = %f, want 0.5", score.Overall)
	}
}

func TestNewClientEmptyAgentID(t *testing.T) {
	client, err := NewClient("")
	if err != nil {
		t.Fatalf("NewClient with empty ID: %v", err)
	}
	if client.Identity.DID != "did:agentmesh:" {
		t.Errorf("DID = %q, want did:agentmesh:", client.Identity.DID)
	}
}

func TestExecuteWithGovernanceDeniedActionDecrasesTrust(t *testing.T) {
	client, _ := NewClient("deny-trust-agent",
		WithPolicyRules([]PolicyRule{
			{Action: "dangerous.action", Effect: Deny},
		}),
	)

	initialScore := client.Trust.GetTrustScore(client.Identity.DID)

	_, err := client.ExecuteWithGovernance("dangerous.action", nil)
	if err != nil {
		t.Fatalf("ExecuteWithGovernance: %v", err)
	}

	afterScore := client.Trust.GetTrustScore(client.Identity.DID)
	if afterScore.Overall >= initialScore.Overall {
		t.Errorf("trust should decrease after deny: before=%f, after=%f", initialScore.Overall, afterScore.Overall)
	}
}

func TestExecuteWithGovernanceReviewNotAllowed(t *testing.T) {
	client, _ := NewClient("review-agent",
		WithPolicyRules([]PolicyRule{
			{Action: "needs.review", Effect: Review},
		}),
	)

	result, err := client.ExecuteWithGovernance("needs.review", nil)
	if err != nil {
		t.Fatalf("ExecuteWithGovernance: %v", err)
	}
	if result.Allowed {
		t.Error("review decision should not be Allowed")
	}
	if result.Decision != Review {
		t.Errorf("decision = %q, want review", result.Decision)
	}
}

func TestExecuteWithGovernanceDefaultDeny(t *testing.T) {
	// Client with no policy rules defaults to deny
	client, _ := NewClient("no-rules-agent")

	result, err := client.ExecuteWithGovernance("any.action", nil)
	if err != nil {
		t.Fatalf("ExecuteWithGovernance: %v", err)
	}
	if result.Allowed {
		t.Error("should deny when no rules match")
	}
	if result.Decision != Deny {
		t.Errorf("decision = %q, want deny", result.Decision)
	}
}

func TestMultipleSequentialGovernanceExecutionsBuildTrust(t *testing.T) {
	client, _ := NewClient("multi-exec-agent",
		WithPolicyRules([]PolicyRule{
			{Action: "data.read", Effect: Allow},
		}),
	)

	var prevScore float64
	for i := 0; i < 5; i++ {
		result, err := client.ExecuteWithGovernance("data.read", nil)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if !result.Allowed {
			t.Errorf("iteration %d: expected allowed", i)
		}
		currentScore := client.Trust.GetTrustScore(client.Identity.DID).Overall
		if i > 0 && currentScore <= prevScore {
			t.Errorf("iteration %d: trust should increase, prev=%f, current=%f", i, prevScore, currentScore)
		}
		prevScore = currentScore
	}
}

func TestGovernanceResultFieldsPopulated(t *testing.T) {
	client, _ := NewClient("fields-agent",
		WithPolicyRules([]PolicyRule{
			{Action: "data.read", Effect: Allow},
		}),
	)

	result, err := client.ExecuteWithGovernance("data.read", map[string]interface{}{"key": "value"})
	if err != nil {
		t.Fatalf("ExecuteWithGovernance: %v", err)
	}

	// Decision field
	if result.Decision != Allow {
		t.Errorf("Decision = %q, want allow", result.Decision)
	}

	// TrustScore field
	if result.TrustScore.Overall == 0 && result.TrustScore.Tier == "" {
		t.Error("TrustScore should be populated")
	}
	if result.TrustScore.Tier == "" {
		t.Error("TrustScore.Tier should not be empty")
	}
	if result.TrustScore.Dimensions == nil {
		t.Error("TrustScore.Dimensions should not be nil")
	}

	// AuditEntry field
	if result.AuditEntry == nil {
		t.Fatal("AuditEntry should not be nil")
	}
	if result.AuditEntry.AgentID != client.Identity.DID {
		t.Errorf("AuditEntry.AgentID = %q, want %q", result.AuditEntry.AgentID, client.Identity.DID)
	}
	if result.AuditEntry.Action != "data.read" {
		t.Errorf("AuditEntry.Action = %q, want data.read", result.AuditEntry.Action)
	}
	if result.AuditEntry.Decision != Allow {
		t.Errorf("AuditEntry.Decision = %q, want allow", result.AuditEntry.Decision)
	}
	if result.AuditEntry.Hash == "" {
		t.Error("AuditEntry.Hash should not be empty")
	}

	// Allowed field matches decision
	if !result.Allowed {
		t.Error("Allowed should be true for Allow decision")
	}
}

func TestGovernanceAuditChainIntegrityAfterMixedActions(t *testing.T) {
	client, _ := NewClient("chain-agent",
		WithPolicyRules([]PolicyRule{
			{Action: "safe.action", Effect: Allow},
			{Action: "risky.action", Effect: Deny},
			{Action: "review.action", Effect: Review},
		}),
	)

	actions := []string{"safe.action", "risky.action", "review.action", "safe.action", "risky.action"}
	for _, action := range actions {
		_, err := client.ExecuteWithGovernance(action, nil)
		if err != nil {
			t.Fatalf("action %s: %v", action, err)
		}
	}

	if !client.Audit.Verify() {
		t.Error("audit chain should be valid after mixed governance executions")
	}

	entries := client.Audit.GetEntries(AuditFilter{})
	if len(entries) != 5 {
		t.Errorf("audit entries = %d, want 5", len(entries))
	}
}
