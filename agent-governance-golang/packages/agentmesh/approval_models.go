// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"context"
	"sort"
	"time"
)

const approvalSchemaVersion = "1.0"

// ActionTarget identifies the tool or resource an approval-bound action will use.
type ActionTarget struct {
	ToolName          string
	ToolSchemaVersion string
	Resource          string
}

// ActionBinding is the exact executable request an approval authorizes.
type ActionBinding struct {
	SchemaVersion string
	Operation     string
	AgentID       string
	SubjectID     string
	Target        ActionTarget
	Parameters    map[string]interface{}
}

// Digest returns the sha256-prefixed canonical digest for the binding.
func (b ActionBinding) Digest() (string, error) {
	return digestCanonical(b.canonical())
}

func (b ActionBinding) canonical() map[string]interface{} {
	schemaVersion := b.SchemaVersion
	if schemaVersion == "" {
		schemaVersion = approvalSchemaVersion
	}

	var subject interface{}
	if b.SubjectID != "" {
		subject = b.SubjectID
	}

	var resource interface{}
	if b.Target.Resource != "" {
		resource = b.Target.Resource
	}

	return map[string]interface{}{
		"schema_version": schemaVersion,
		"operation":      b.Operation,
		"agent_id":       b.AgentID,
		"subject_id":     subject,
		"target": map[string]interface{}{
			"tool_name":           b.Target.ToolName,
			"tool_schema_version": b.Target.ToolSchemaVersion,
			"resource":            resource,
		},
		"parameters": clonePolicyContext(b.Parameters),
	}
}

// ApprovalStatus is the lifecycle state of an approval request.
type ApprovalStatus string

const (
	ApprovalPending   ApprovalStatus = "pending"
	ApprovalAllowed   ApprovalStatus = "allowed"
	ApprovalDenied    ApprovalStatus = "denied"
	ApprovalExpired   ApprovalStatus = "expired"
	ApprovalCancelled ApprovalStatus = "cancelled"
	ApprovalConsumed  ApprovalStatus = "consumed"
)

// ApproverKind classifies the authenticated principal behind a chain entry.
type ApproverKind string

const (
	ApproverHuman       ApproverKind = "human"
	ApproverService     ApproverKind = "service"
	ApproverLLMAdvisory ApproverKind = "llm_advisory"
)

// ApprovalEntryDecision is one approver vote on an approval request.
type ApprovalEntryDecision string

const (
	ApprovalEntryAllow ApprovalEntryDecision = "allow"
	ApprovalEntryDeny  ApprovalEntryDecision = "deny"
)

// ApprovalOutcome is the terminal result of an approval request.
type ApprovalOutcome string

const (
	ApprovalOutcomeAllow     ApprovalOutcome = "allow"
	ApprovalOutcomeDeny      ApprovalOutcome = "deny"
	ApprovalOutcomeExpired   ApprovalOutcome = "expired"
	ApprovalOutcomeCancelled ApprovalOutcome = "cancelled"
)

// ApprovalPolicyDecisionRecord captures the require_approval verdict that paused execution.
type ApprovalPolicyDecisionRecord struct {
	PolicyDecisionID     string
	Verdict              PolicyDecision
	ActionDigest         string
	PolicyRuleID         string
	PolicyVersion        string
	ApprovalChainID      string
	ApprovalChainVersion string
	DecidedAt            time.Time
}

// ApprovalRequest is a pending approval bound to one action digest.
type ApprovalRequest struct {
	ApprovalRequestID    string
	PolicyDecisionID     string
	ActionDigest         string
	AgentID              string
	SubjectID            string
	Operation            string
	TargetResource       string
	PolicyVersion        string
	ApprovalChainID      string
	ApprovalChainVersion string
	RequestedAt          time.Time
	ExpiresAt            time.Time
	Status               ApprovalStatus
	FailClosedOnTimeout  bool
}

// PresentedCanonical returns the request fields shown to an approver.
func (r ApprovalRequest) PresentedCanonical() map[string]interface{} {
	var subject interface{}
	if r.SubjectID != "" {
		subject = r.SubjectID
	}
	var target interface{}
	if r.TargetResource != "" {
		target = r.TargetResource
	}

	return map[string]interface{}{
		"approval_request_id":    r.ApprovalRequestID,
		"policy_decision_id":     r.PolicyDecisionID,
		"action_digest":          r.ActionDigest,
		"agent_id":               r.AgentID,
		"subject_id":             subject,
		"operation":              r.Operation,
		"target_resource":        target,
		"policy_version":         r.PolicyVersion,
		"approval_chain_id":      r.ApprovalChainID,
		"approval_chain_version": r.ApprovalChainVersion,
		"expires_at":             r.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
}

// InputDigest returns the canonical digest of the request fields presented to an approver.
func (r ApprovalRequest) InputDigest() (string, error) {
	return digestCanonical(r.PresentedCanonical())
}

// ApprovalVote is a transport-normalized approver decision.
type ApprovalVote struct {
	ApproverKind      ApproverKind
	ApproverIdentity  string
	IdentityAssurance string
	Decision          ApprovalEntryDecision
	ReasonCode        string
	Roles             []string
	ChainEntryID      string
}

// ApprovalChainEntry is an append-only, digest-linked approval vote.
type ApprovalChainEntry struct {
	ApprovalRequestID   string
	ChainEntryID        string
	StageIndex          int
	ApproverKind        ApproverKind
	ApproverIdentity    string
	IdentityAssurance   string
	Decision            ApprovalEntryDecision
	ReasonCode          string
	Roles               []string
	InputDigest         string
	PreviousEntryDigest string
	EntryDigest         string
	DecidedAt           time.Time
}

// Seal computes the entry digest over every field except EntryDigest.
func (e *ApprovalChainEntry) Seal() error {
	if e.ChainEntryID == "" {
		e.ChainEntryID = newApprovalID("ace")
	}
	digest, err := digestCanonical(e.canonicalWithoutDigest())
	if err != nil {
		return err
	}
	e.EntryDigest = digest
	return nil
}

func (e ApprovalChainEntry) canonicalWithoutDigest() map[string]interface{} {
	var previous interface{}
	if e.PreviousEntryDigest != "" {
		previous = e.PreviousEntryDigest
	}

	return map[string]interface{}{
		"approval_request_id":   e.ApprovalRequestID,
		"chain_entry_id":        e.ChainEntryID,
		"stage_index":           e.StageIndex,
		"approver_kind":         string(e.ApproverKind),
		"approver_identity":     e.ApproverIdentity,
		"identity_assurance":    e.IdentityAssurance,
		"decision":              string(e.Decision),
		"reason_code":           e.ReasonCode,
		"roles":                 cloneStrings(e.Roles),
		"input_digest":          e.InputDigest,
		"previous_entry_digest": previous,
		"decided_at":            e.DecidedAt.UTC().Format(time.RFC3339Nano),
	}
}

func (e ApprovalChainEntry) policyDecision() PolicyDecision {
	if e.ApproverKind == ApproverLLMAdvisory {
		return Review
	}
	if e.Decision == ApprovalEntryAllow {
		return Allow
	}
	return Deny
}

// ApprovalResolution is the terminal outcome for an approval request.
type ApprovalResolution struct {
	ApprovalResolutionID string
	ApprovalRequestID    string
	Outcome              ApprovalOutcome
	ActionDigest         string
	PolicyVersion        string
	ApprovalChainVersion string
	FinalEntryDigest     string
	ResolvedAt           time.Time
	ReasonCode           string
}

// PolicyDecision maps a terminal approval outcome back onto enforcement.
func (r ApprovalResolution) PolicyDecision() PolicyDecision {
	if r.Outcome == ApprovalOutcomeAllow {
		return Allow
	}
	return Deny
}

// ApprovalExecutionDecision is the execution-time validation result for an allowed approval.
type ApprovalExecutionDecision struct {
	ApprovalRequestID string
	Allowed           bool
	Decision          PolicyDecision
	ReasonCode        string
	Consumed          bool
}

// ApprovalTransport asks an external system for an approval vote.
type ApprovalTransport interface {
	RequestApproval(ctx context.Context, request ApprovalRequest) (ApprovalVote, error)
}

// ApprovalStage is one ordered approval-chain stage.
type ApprovalStage struct {
	StageIndex        int
	ApproverKind      ApproverKind
	AllowedIdentities []string
	AllowedRoles      []string
	Optional          bool
	Transport         ApprovalTransport
}

func (s ApprovalStage) authorizes(identity string, roles []string) bool {
	if identity != "" {
		for _, allowed := range s.AllowedIdentities {
			if identity == allowed {
				return true
			}
		}
	}
	for _, role := range roles {
		for _, allowed := range s.AllowedRoles {
			if role == allowed {
				return true
			}
		}
	}
	return false
}

func (s ApprovalStage) isAdvisory() bool {
	return s.ApproverKind == ApproverLLMAdvisory
}

// ApprovalChain is a versioned immutable approval-chain configuration.
type ApprovalChain struct {
	ChainID string
	Version string
	Stages  []ApprovalStage
}

// ApprovalResult contains the full approval path for one action.
type ApprovalResult struct {
	PolicyDecision ApprovalPolicyDecisionRecord
	Request        ApprovalRequest
	Entries        []ApprovalChainEntry
	Resolution     ApprovalResolution
	Execution      ApprovalExecutionDecision
	Decision       PolicyDecision
	Allowed        bool
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cloned := append([]string(nil), values...)
	return cloned
}

func sortedStrings(values []string) []string {
	cloned := cloneStrings(values)
	sort.Strings(cloned)
	return cloned
}
