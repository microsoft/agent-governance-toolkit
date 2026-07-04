// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

// ApprovalCoordinator resolves require_approval decisions through an ordered chain.
type ApprovalCoordinator struct {
	chain         ApprovalChain
	policyRuleID  string
	policyVersion string
	ttl           time.Duration
	timeout       time.Duration
	clock         func() time.Time
	audit         *AuditLogger
	store         ApprovalStore
}

// ApprovalCoordinatorOption configures an ApprovalCoordinator.
type ApprovalCoordinatorOption func(*ApprovalCoordinator)

// WithApprovalPolicyRuleID stamps approval records with the matched policy rule id.
func WithApprovalPolicyRuleID(ruleID string) ApprovalCoordinatorOption {
	return func(c *ApprovalCoordinator) {
		c.policyRuleID = ruleID
	}
}

// WithApprovalPolicyVersion stamps approval records with the active policy version.
func WithApprovalPolicyVersion(version string) ApprovalCoordinatorOption {
	return func(c *ApprovalCoordinator) {
		c.policyVersion = version
	}
}

// WithApprovalTTL controls how long opened approval requests remain valid.
func WithApprovalTTL(ttl time.Duration) ApprovalCoordinatorOption {
	return func(c *ApprovalCoordinator) {
		c.ttl = ttl
	}
}

// WithApprovalTimeout controls the per-stage transport timeout.
func WithApprovalTimeout(timeout time.Duration) ApprovalCoordinatorOption {
	return func(c *ApprovalCoordinator) {
		c.timeout = timeout
	}
}

// WithApprovalAuditLogger emits approval lifecycle events to an audit logger.
func WithApprovalAuditLogger(audit *AuditLogger) ApprovalCoordinatorOption {
	return func(c *ApprovalCoordinator) {
		c.audit = audit
	}
}

// WithApprovalStore sets the persistence backend for approval lifecycle records.
func WithApprovalStore(store ApprovalStore) ApprovalCoordinatorOption {
	return func(c *ApprovalCoordinator) {
		if store != nil {
			c.store = store
		}
	}
}

// WithApprovalClock injects a clock for tests.
func WithApprovalClock(clock func() time.Time) ApprovalCoordinatorOption {
	return func(c *ApprovalCoordinator) {
		if clock != nil {
			c.clock = clock
		}
	}
}

// NewApprovalCoordinator creates a coordinator for one versioned approval chain.
func NewApprovalCoordinator(chain ApprovalChain, opts ...ApprovalCoordinatorOption) *ApprovalCoordinator {
	c := &ApprovalCoordinator{
		chain:         chain,
		policyRuleID:  "unspecified",
		policyVersion: "unspecified",
		ttl:           5 * time.Minute,
		timeout:       5 * time.Minute,
		clock:         func() time.Time { return time.Now().UTC() },
		store:         NewInMemoryApprovalStore(),
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.ttl <= 0 {
		c.ttl = 5 * time.Minute
	}
	if c.timeout <= 0 {
		c.timeout = 5 * time.Minute
	}
	if c.store == nil {
		c.store = NewInMemoryApprovalStore()
	}
	return c
}

// OpenRequest records a pending approval request without collecting approver entries.
func (c *ApprovalCoordinator) OpenRequest(binding ActionBinding) (*ApprovalResult, error) {
	if c == nil {
		return nil, errors.New("approval coordinator is nil")
	}
	if c.store == nil {
		c.store = NewInMemoryApprovalStore()
	}
	if err := c.validateConfig(); err != nil {
		return c.deniedResult(binding, "invalid_approval_chain"), err
	}
	if err := binding.Validate(); err != nil {
		return c.deniedResult(binding, "invalid_action_binding"), fmt.Errorf("invalid action binding: %w", err)
	}

	now := c.clock().UTC()
	actionDigest, err := binding.Digest()
	if err != nil {
		return c.deniedResult(binding, "action_digest_error"), fmt.Errorf("computing action digest: %w", err)
	}
	policyDecision := ApprovalPolicyDecisionRecord{
		PolicyDecisionID:     newApprovalID("pd"),
		Verdict:              RequiresApproval,
		ActionDigest:         actionDigest,
		PolicyRuleID:         c.policyRuleID,
		PolicyVersion:        c.policyVersion,
		ApprovalChainID:      c.chain.ChainID,
		ApprovalChainVersion: c.chain.Version,
		DecidedAt:            now,
	}
	request := ApprovalRequest{
		ApprovalRequestID:    newApprovalID("ar"),
		PolicyDecisionID:     policyDecision.PolicyDecisionID,
		ActionDigest:         actionDigest,
		AgentID:              binding.AgentID,
		SubjectID:            binding.SubjectID,
		Operation:            binding.Operation,
		TargetResource:       binding.Target.Resource,
		PolicyVersion:        c.policyVersion,
		ApprovalChainID:      c.chain.ChainID,
		ApprovalChainVersion: c.chain.Version,
		RequestedAt:          now,
		ExpiresAt:            now.Add(c.ttl),
		Status:               ApprovalPending,
		FailClosedOnTimeout:  true,
	}
	if err := c.store.SaveRequest(policyDecision, request); err != nil {
		result := c.deniedResult(binding, "approval_store_error")
		return result, err
	}

	c.log(request.AgentID, "approval_requested:"+binding.Operation, RequiresApproval)
	return c.resultFromStore(policyDecision, request), nil
}

// SubmitEntry appends one approver entry and resolves the request when the chain is satisfied.
func (c *ApprovalCoordinator) SubmitEntry(approvalRequestID string, stageIndex int, vote ApprovalVote) (*ApprovalResult, error) {
	if c == nil {
		return nil, errors.New("approval coordinator is nil")
	}
	if c.store == nil {
		c.store = NewInMemoryApprovalStore()
	}
	policy, request, ok := c.store.GetRequest(approvalRequestID)
	if !ok {
		return nil, ErrApprovalRequestNotFound
	}
	result := c.resultFromStore(policy, request)
	if request.Status != ApprovalPending {
		return result, fmt.Errorf("approval request %s is %s", approvalRequestID, request.Status)
	}
	if !c.clock().UTC().Before(request.ExpiresAt) {
		return c.resolveRequest(approvalRequestID, ApprovalOutcomeExpired, "approval_expired")
	}

	stage, ok := c.stageByIndex(stageIndex)
	if !ok {
		return result, fmt.Errorf("approval stage %d not found", stageIndex)
	}
	if vote.Decision != ApprovalEntryAllow && vote.Decision != ApprovalEntryDeny {
		return c.appendSystemDenyAndResolve(approvalRequestID, stage, "malformed_approval_decision")
	}

	isAdvisory := stage.isAdvisory() || vote.ApproverKind == ApproverLLMAdvisory
	if vote.Decision == ApprovalEntryAllow && !isAdvisory && !stage.authorizes(vote.ApproverIdentity, vote.Roles) {
		vote.Decision = ApprovalEntryDeny
		vote.ReasonCode = "unauthorized_approver"
		if vote.ApproverIdentity == "" {
			vote.ApproverIdentity = "system:unverified-approver"
		}
	}

	entries, _ := c.store.ListEntries(approvalRequestID)
	entry, err := c.entryFromVote(request, entries, stage, vote)
	if err != nil {
		return result, err
	}
	if err := c.store.AppendEntry(entry); err != nil {
		return result, err
	}
	c.log(request.AgentID, "approval_chain_entry:"+request.Operation, entry.policyDecision())

	entries = append(entries, entry)
	if entry.ApproverKind == ApproverLLMAdvisory {
		return c.resultFromStore(policy, request), nil
	}
	if entry.Decision == ApprovalEntryDeny {
		return c.resolveRequest(approvalRequestID, ApprovalOutcomeDeny, entry.ReasonCode)
	}
	if c.requiredNonAdvisorySatisfied(entries) {
		return c.resolveRequest(approvalRequestID, ApprovalOutcomeAllow, "approved")
	}
	return c.resultFromStore(policy, request), nil
}

// ValidateForExecution revalidates and consumes an allowed approval before execution.
func (c *ApprovalCoordinator) ValidateForExecution(approvalRequestID string, binding ActionBinding) ApprovalExecutionDecision {
	return c.validateForExecution(approvalRequestID, binding, true)
}

// CheckApprovalForExecution revalidates an approval without consuming it.
func (c *ApprovalCoordinator) CheckApprovalForExecution(approvalRequestID string, binding ActionBinding) ApprovalExecutionDecision {
	return c.validateForExecution(approvalRequestID, binding, false)
}

// CancelRequest records a fail-closed cancellation for an open approval request.
func (c *ApprovalCoordinator) CancelRequest(approvalRequestID string, reason string) (*ApprovalResult, error) {
	if reason == "" {
		reason = "approval_cancelled"
	}
	return c.resolveRequest(approvalRequestID, ApprovalOutcomeCancelled, reason)
}

// RequestApproval opens a request, advances the chain, validates it for execution, and consumes it.
func (c *ApprovalCoordinator) RequestApproval(ctx context.Context, binding ActionBinding) (*ApprovalResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := c.OpenRequest(binding)
	if err != nil {
		return result, err
	}

	requiredSeen := false
	for _, stage := range c.sortedStages() {
		if !stage.Optional && !stage.isAdvisory() {
			requiredSeen = true
		}
		if stage.Optional {
			continue
		}
		if !c.clock().UTC().Before(result.Request.ExpiresAt) {
			return c.resolveRequest(result.Request.ApprovalRequestID, ApprovalOutcomeExpired, "approval_expired")
		}
		if stage.Transport == nil {
			return c.appendSystemDenyAndResolve(result.Request.ApprovalRequestID, stage, "missing_approval_transport")
		}

		stageCtx, cancel := context.WithTimeout(ctx, c.timeout)
		vote, err := stage.Transport.RequestApproval(stageCtx, result.Request)
		cancel()
		if err != nil {
			return c.appendSystemDenyAndResolve(result.Request.ApprovalRequestID, stage, "approval_transport_error")
		}

		result, err = c.SubmitEntry(result.Request.ApprovalRequestID, stage.StageIndex, vote)
		if err != nil {
			return result, err
		}
		if result.Resolution.ApprovalResolutionID == "" {
			continue
		}
		if result.Resolution.Outcome != ApprovalOutcomeAllow {
			return result, nil
		}
		return c.finalizeExecution(result, binding), nil
	}

	if !requiredSeen {
		return c.appendSystemDenyAndResolve(result.Request.ApprovalRequestID, ApprovalStage{StageIndex: 0}, "no_required_approval_stage")
	}
	return c.resolveRequest(result.Request.ApprovalRequestID, ApprovalOutcomeDeny, "approval_chain_incomplete")
}

func (c *ApprovalCoordinator) validateForExecution(approvalRequestID string, binding ActionBinding, consume bool) ApprovalExecutionDecision {
	if c == nil || c.store == nil {
		return deniedExecution(approvalRequestID, "approval_coordinator_missing")
	}
	if err := binding.Validate(); err != nil {
		return deniedExecution(approvalRequestID, "invalid_action_binding")
	}
	actionDigest, err := binding.Digest()
	if err != nil {
		return deniedExecution(approvalRequestID, "action_digest_error")
	}
	_, request, ok := c.store.GetRequest(approvalRequestID)
	if !ok {
		return deniedExecution(approvalRequestID, "approval_request_not_found")
	}
	if !c.clock().UTC().Before(request.ExpiresAt) {
		c.store.UpdateRequestStatus(approvalRequestID, ApprovalExpired)
		return deniedExecution(approvalRequestID, "approval_expired")
	}
	if request.Status != ApprovalAllowed {
		return deniedExecution(approvalRequestID, statusReason(request.Status))
	}
	resolution, ok := c.store.GetResolution(approvalRequestID)
	if !ok {
		return deniedExecution(approvalRequestID, "approval_not_resolved")
	}
	if resolution.Outcome != ApprovalOutcomeAllow {
		reason := resolution.ReasonCode
		if reason == "" {
			reason = "approval_not_allowed"
		}
		return deniedExecution(approvalRequestID, reason)
	}
	if actionDigest != request.ActionDigest || resolution.ActionDigest != request.ActionDigest {
		return deniedExecution(approvalRequestID, "action_digest_mismatch")
	}
	if c.policyVersion != request.PolicyVersion || resolution.PolicyVersion != request.PolicyVersion {
		return deniedExecution(approvalRequestID, "policy_version_mismatch")
	}
	if c.chain.ChainID != request.ApprovalChainID {
		return deniedExecution(approvalRequestID, "approval_chain_id_mismatch")
	}
	if c.chain.Version != request.ApprovalChainVersion || resolution.ApprovalChainVersion != request.ApprovalChainVersion {
		return deniedExecution(approvalRequestID, "approval_chain_version_mismatch")
	}
	entries, ok := c.store.ListEntries(approvalRequestID)
	if !ok {
		return deniedExecution(approvalRequestID, "approval_request_not_found")
	}
	if reason, valid := c.verifyEntryChain(request, resolution, entries); !valid {
		return deniedExecution(approvalRequestID, reason)
	}
	if consume {
		if _, consumed := c.store.ConsumeApproval(approvalRequestID); !consumed {
			return deniedExecution(approvalRequestID, "approval_consumed")
		}
	}
	return ApprovalExecutionDecision{
		ApprovalRequestID: approvalRequestID,
		Allowed:           true,
		Decision:          Allow,
		ReasonCode:        "approved",
		Consumed:          consume,
	}
}

func (c *ApprovalCoordinator) finalizeExecution(result *ApprovalResult, binding ActionBinding) *ApprovalResult {
	execution := c.ValidateForExecution(result.Request.ApprovalRequestID, binding)
	policy, request, ok := c.store.GetRequest(result.Request.ApprovalRequestID)
	if ok {
		result = c.resultFromStore(policy, request)
	}
	result.Execution = execution
	result.Decision = execution.Decision
	result.Allowed = execution.Allowed
	c.log(result.Request.AgentID, "approval_execution:"+result.Request.Operation, result.Decision)
	return result
}

func (c *ApprovalCoordinator) appendSystemDenyAndResolve(approvalRequestID string, stage ApprovalStage, reason string) (*ApprovalResult, error) {
	policy, request, ok := c.store.GetRequest(approvalRequestID)
	if !ok {
		return nil, ErrApprovalRequestNotFound
	}
	entries, _ := c.store.ListEntries(approvalRequestID)
	vote := ApprovalVote{
		ApproverKind:      ApproverService,
		ApproverIdentity:  "system:approval-coordinator",
		IdentityAssurance: "system",
		Decision:          ApprovalEntryDeny,
		ReasonCode:        reason,
	}
	entry, err := c.entryFromVote(request, entries, stage, vote)
	if err != nil {
		return c.resultFromStore(policy, request), err
	}
	if err := c.store.AppendEntry(entry); err != nil {
		return c.resultFromStore(policy, request), err
	}
	c.log(request.AgentID, "approval_chain_entry:"+request.Operation, Deny)
	return c.resolveRequest(approvalRequestID, ApprovalOutcomeDeny, reason)
}

func (c *ApprovalCoordinator) entryFromVote(request ApprovalRequest, entries []ApprovalChainEntry, stage ApprovalStage, vote ApprovalVote) (ApprovalChainEntry, error) {
	inputDigest, err := request.InputDigest()
	if err != nil {
		return ApprovalChainEntry{}, err
	}
	kind := vote.ApproverKind
	if kind == "" {
		kind = stage.ApproverKind
	}
	if kind == "" {
		kind = ApproverService
	}
	assurance := vote.IdentityAssurance
	if assurance == "" {
		assurance = "unspecified"
	}

	var previous string
	if len(entries) > 0 {
		previous = entries[len(entries)-1].EntryDigest
	}
	entry := ApprovalChainEntry{
		ApprovalRequestID:   request.ApprovalRequestID,
		ChainEntryID:        vote.ChainEntryID,
		StageIndex:          stage.StageIndex,
		ApproverKind:        kind,
		ApproverIdentity:    vote.ApproverIdentity,
		IdentityAssurance:   assurance,
		Decision:            vote.Decision,
		ReasonCode:          vote.ReasonCode,
		Roles:               sortedStrings(vote.Roles),
		InputDigest:         inputDigest,
		PreviousEntryDigest: previous,
		DecidedAt:           c.clock().UTC(),
	}
	if entry.ReasonCode == "" {
		entry.ReasonCode = string(entry.Decision)
	}
	if err := entry.Seal(); err != nil {
		return ApprovalChainEntry{}, err
	}
	return entry, nil
}

func (c *ApprovalCoordinator) resolveRequest(approvalRequestID string, outcome ApprovalOutcome, reason string) (*ApprovalResult, error) {
	policy, request, ok := c.store.GetRequest(approvalRequestID)
	if !ok {
		return nil, ErrApprovalRequestNotFound
	}
	if request.Status != ApprovalPending {
		return c.resultFromStore(policy, request), fmt.Errorf("approval request %s is %s", approvalRequestID, request.Status)
	}
	entries, _ := c.store.ListEntries(approvalRequestID)
	status := statusForOutcome(outcome)
	updated, ok := c.store.UpdateRequestStatus(approvalRequestID, status)
	if ok {
		request = updated
	}

	finalDigest := ""
	if len(entries) > 0 {
		finalDigest = entries[len(entries)-1].EntryDigest
	}
	resolution := ApprovalResolution{
		ApprovalResolutionID: newApprovalID("apr"),
		ApprovalRequestID:    request.ApprovalRequestID,
		Outcome:              outcome,
		ActionDigest:         request.ActionDigest,
		PolicyVersion:        request.PolicyVersion,
		ApprovalChainVersion: request.ApprovalChainVersion,
		FinalEntryDigest:     finalDigest,
		ResolvedAt:           c.clock().UTC(),
		ReasonCode:           reason,
	}
	if err := c.store.SaveResolution(resolution); err != nil {
		return c.resultFromStore(policy, request), err
	}
	result := c.resultFromStore(policy, request)
	result.Resolution = resolution
	result.Decision = resolution.PolicyDecision()
	result.Allowed = result.Decision == Allow
	c.log(request.AgentID, "approval_resolved:"+request.Operation, result.Decision)
	return result, nil
}

func (c *ApprovalCoordinator) resultFromStore(policy ApprovalPolicyDecisionRecord, request ApprovalRequest) *ApprovalResult {
	entries, _ := c.store.ListEntries(request.ApprovalRequestID)
	resolution, _ := c.store.GetResolution(request.ApprovalRequestID)
	result := &ApprovalResult{
		PolicyDecision: policy,
		Request:        request,
		Entries:        entries,
		Resolution:     resolution,
		Decision:       RequiresApproval,
	}
	if resolution.ApprovalResolutionID != "" {
		result.Decision = resolution.PolicyDecision()
		result.Allowed = result.Decision == Allow
	}
	return result
}

func (c *ApprovalCoordinator) deniedResult(binding ActionBinding, reason string) *ApprovalResult {
	now := time.Now().UTC()
	if c != nil && c.clock != nil {
		now = c.clock().UTC()
	}
	policyRuleID := "unspecified"
	policyVersion := "unspecified"
	chainID := ""
	chainVersion := ""
	if c != nil {
		policyRuleID = c.policyRuleID
		policyVersion = c.policyVersion
		chainID = c.chain.ChainID
		chainVersion = c.chain.Version
	}
	actionDigest, _ := binding.Digest()
	policyDecision := ApprovalPolicyDecisionRecord{
		PolicyDecisionID:     newApprovalID("pd"),
		Verdict:              RequiresApproval,
		ActionDigest:         actionDigest,
		PolicyRuleID:         policyRuleID,
		PolicyVersion:        policyVersion,
		ApprovalChainID:      chainID,
		ApprovalChainVersion: chainVersion,
		DecidedAt:            now,
	}
	request := ApprovalRequest{
		ApprovalRequestID:    newApprovalID("ar"),
		PolicyDecisionID:     policyDecision.PolicyDecisionID,
		ActionDigest:         actionDigest,
		AgentID:              binding.AgentID,
		SubjectID:            binding.SubjectID,
		Operation:            binding.Operation,
		TargetResource:       binding.Target.Resource,
		PolicyVersion:        policyVersion,
		ApprovalChainID:      chainID,
		ApprovalChainVersion: chainVersion,
		RequestedAt:          now,
		ExpiresAt:            now,
		Status:               ApprovalDenied,
		FailClosedOnTimeout:  true,
	}
	resolution := ApprovalResolution{
		ApprovalResolutionID: newApprovalID("apr"),
		ApprovalRequestID:    request.ApprovalRequestID,
		Outcome:              ApprovalOutcomeDeny,
		ActionDigest:         actionDigest,
		PolicyVersion:        policyVersion,
		ApprovalChainVersion: chainVersion,
		ResolvedAt:           now,
		ReasonCode:           reason,
	}
	return &ApprovalResult{
		PolicyDecision: policyDecision,
		Request:        request,
		Resolution:     resolution,
		Decision:       Deny,
		Allowed:        false,
	}
}

func (c *ApprovalCoordinator) validateConfig() error {
	if c.chain.ChainID == "" || c.chain.Version == "" {
		return errors.New("approval chain id and version are required")
	}
	if len(c.chain.Stages) == 0 {
		return errors.New("approval chain must contain at least one stage")
	}
	return nil
}

func (c *ApprovalCoordinator) sortedStages() []ApprovalStage {
	stages := append([]ApprovalStage(nil), c.chain.Stages...)
	sort.Slice(stages, func(i, j int) bool {
		return stages[i].StageIndex < stages[j].StageIndex
	})
	return stages
}

func (c *ApprovalCoordinator) stageByIndex(stageIndex int) (ApprovalStage, bool) {
	for _, stage := range c.chain.Stages {
		if stage.StageIndex == stageIndex {
			return stage, true
		}
	}
	return ApprovalStage{}, false
}

func (c *ApprovalCoordinator) requiredNonAdvisorySatisfied(entries []ApprovalChainEntry) bool {
	required := make(map[int]bool)
	for _, stage := range c.chain.Stages {
		if stage.Optional || stage.isAdvisory() {
			continue
		}
		required[stage.StageIndex] = false
	}
	if len(required) == 0 {
		return false
	}
	for _, entry := range entries {
		if entry.ApproverKind == ApproverLLMAdvisory || entry.Decision != ApprovalEntryAllow {
			continue
		}
		if _, ok := required[entry.StageIndex]; ok {
			required[entry.StageIndex] = true
		}
	}
	for _, satisfied := range required {
		if !satisfied {
			return false
		}
	}
	return true
}

func (c *ApprovalCoordinator) verifyEntryChain(request ApprovalRequest, resolution ApprovalResolution, entries []ApprovalChainEntry) (string, bool) {
	if len(entries) == 0 {
		return "approval_chain_tampered", false
	}
	inputDigest, err := request.InputDigest()
	if err != nil {
		return "approval_chain_tampered", false
	}
	previous := ""
	for _, entry := range entries {
		if entry.ApprovalRequestID != request.ApprovalRequestID {
			return "approval_chain_tampered", false
		}
		if entry.InputDigest != inputDigest {
			return "approval_chain_tampered", false
		}
		if entry.PreviousEntryDigest != previous {
			return "approval_chain_tampered", false
		}
		expectedDigest, err := digestCanonical(entry.canonicalWithoutDigest())
		if err != nil || expectedDigest != entry.EntryDigest {
			return "approval_chain_tampered", false
		}
		previous = entry.EntryDigest
	}
	if resolution.FinalEntryDigest != previous {
		return "approval_chain_tampered", false
	}
	if !c.requiredNonAdvisorySatisfied(entries) {
		return "approval_chain_incomplete", false
	}
	return "", true
}

func statusForOutcome(outcome ApprovalOutcome) ApprovalStatus {
	switch outcome {
	case ApprovalOutcomeAllow:
		return ApprovalAllowed
	case ApprovalOutcomeExpired:
		return ApprovalExpired
	case ApprovalOutcomeCancelled:
		return ApprovalCancelled
	default:
		return ApprovalDenied
	}
}

func statusReason(status ApprovalStatus) string {
	switch status {
	case ApprovalPending:
		return "approval_pending"
	case ApprovalAllowed:
		return "approved"
	case ApprovalDenied:
		return "approval_denied"
	case ApprovalExpired:
		return "approval_expired"
	case ApprovalCancelled:
		return "approval_cancelled"
	case ApprovalConsumed:
		return "approval_consumed"
	default:
		return "approval_not_allowed"
	}
}

func deniedExecution(approvalRequestID string, reason string) ApprovalExecutionDecision {
	if reason == "" {
		reason = "approval_not_allowed"
	}
	return ApprovalExecutionDecision{
		ApprovalRequestID: approvalRequestID,
		Allowed:           false,
		Decision:          Deny,
		ReasonCode:        reason,
	}
}

func (c *ApprovalCoordinator) log(agentID, action string, decision PolicyDecision) {
	if c.audit != nil {
		c.audit.Log(agentID, action, decision)
	}
}
