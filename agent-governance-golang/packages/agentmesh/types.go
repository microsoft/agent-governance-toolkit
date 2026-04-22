// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import "time"

// PolicyDecision represents the outcome of a policy evaluation.
type PolicyDecision string

const (
	Allow            PolicyDecision = "allow"
	Deny             PolicyDecision = "deny"
	Review           PolicyDecision = "review"
	RateLimit        PolicyDecision = "rate_limit"
	RequiresApproval PolicyDecision = "requires_approval"
)

// TrustConfig holds configuration for the TrustManager.
type TrustConfig struct {
	InitialScore    float64
	DecayRate       float64
	RewardFactor    float64
	PenaltyFactor   float64
	TierThresholds  TierThresholds
	MinInteractions int
	PersistPath     string
}

// TierThresholds defines score boundaries for trust tiers.
type TierThresholds struct {
	High   float64
	Medium float64
}

// DefaultTrustConfig returns sensible defaults.
func DefaultTrustConfig() TrustConfig {
	return TrustConfig{
		InitialScore:  0.5,
		DecayRate:     0.01,
		RewardFactor:  1.0,
		PenaltyFactor: 1.5,
		TierThresholds: TierThresholds{
			High:   0.8,
			Medium: 0.5,
		},
		MinInteractions: 3,
	}
}

// TrustVerificationResult is returned by VerifyPeer.
type TrustVerificationResult struct {
	PeerID   string
	Verified bool
	Score    TrustScore
}

// AuditFilter controls which entries are returned by GetEntries.
type AuditFilter struct {
	AgentID   string
	Action    string
	Decision  *PolicyDecision
	StartTime *time.Time
	EndTime   *time.Time
}

// GovernanceResult is the outcome of ExecuteWithGovernance.
type GovernanceResult struct {
	Decision   PolicyDecision
	TrustScore TrustScore
	AuditEntry *AuditEntry
	Allowed    bool
}

// Option configures an AgentMeshClient.
type Option func(*clientOptions)

type clientOptions struct {
	capabilities []string
	trustConfig  *TrustConfig
	policyRules  []PolicyRule
}

// WithCapabilities sets capabilities on identity generation.
func WithCapabilities(caps []string) Option {
	return func(o *clientOptions) {
		o.capabilities = caps
	}
}

// WithTrustConfig overrides the default trust configuration.
func WithTrustConfig(cfg TrustConfig) Option {
	return func(o *clientOptions) {
		o.trustConfig = &cfg
	}
}

// WithPolicyRules sets initial policy rules.
func WithPolicyRules(rules []PolicyRule) Option {
	return func(o *clientOptions) {
		o.policyRules = rules
	}
}
