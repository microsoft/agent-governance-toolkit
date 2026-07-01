// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
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
	ApprovalPending ApprovalStatus = "pending"
	ApprovalAllowed ApprovalStatus = "allowed"
	ApprovalDenied  ApprovalStatus = "denied"
	ApprovalExpired ApprovalStatus = "expired"
)

// ApproverKind classifies the authenticated principal behind a chain entry.
type ApproverKind string

const (
	ApproverHuman   ApproverKind = "human"
	ApproverService ApproverKind = "service"
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
	ApprovalOutcomeAllow   ApprovalOutcome = "allow"
	ApprovalOutcomeDeny    ApprovalOutcome = "deny"
	ApprovalOutcomeExpired ApprovalOutcome = "expired"
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
	StageIndex        int
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
		"input_digest":          e.InputDigest,
		"previous_entry_digest": previous,
		"decided_at":            e.DecidedAt.UTC().Format(time.RFC3339Nano),
	}
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
	Decision       PolicyDecision
	Allowed        bool
}

// ApprovalCoordinator resolves require_approval decisions through an ordered chain.
type ApprovalCoordinator struct {
	chain         ApprovalChain
	policyRuleID  string
	policyVersion string
	ttl           time.Duration
	timeout       time.Duration
	clock         func() time.Time
	audit         *AuditLogger
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
	return c
}

// RequestApproval opens a request, advances the chain, and resolves fail-closed.
func (c *ApprovalCoordinator) RequestApproval(ctx context.Context, binding ActionBinding) (*ApprovalResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil {
		return nil, errors.New("approval coordinator is nil")
	}
	if c.chain.ChainID == "" || c.chain.Version == "" {
		return nil, errors.New("approval chain id and version are required")
	}
	if len(c.chain.Stages) == 0 {
		return nil, errors.New("approval chain must contain at least one stage")
	}

	now := c.clock().UTC()
	actionDigest, err := binding.Digest()
	if err != nil {
		return nil, fmt.Errorf("computing action digest: %w", err)
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

	result := &ApprovalResult{
		PolicyDecision: policyDecision,
		Request:        request,
	}
	c.log(request.AgentID, "approval_requested:"+binding.Operation, RequiresApproval)

	stages := append([]ApprovalStage(nil), c.chain.Stages...)
	sort.Slice(stages, func(i, j int) bool {
		return stages[i].StageIndex < stages[j].StageIndex
	})

	requiredSeen := false
	for _, stage := range stages {
		if stage.Optional {
			continue
		}
		requiredSeen = true
		if !c.clock().UTC().Before(request.ExpiresAt) {
			c.resolve(result, ApprovalOutcomeExpired, "approval_expired")
			return result, nil
		}
		if stage.Transport == nil {
			c.appendSystemDeny(result, stage, "missing_approval_transport")
			c.resolve(result, ApprovalOutcomeDeny, "missing_approval_transport")
			return result, nil
		}

		stageCtx, cancel := context.WithTimeout(ctx, c.timeout)
		vote, err := stage.Transport.RequestApproval(stageCtx, request)
		cancel()
		if err != nil {
			c.appendSystemDeny(result, stage, "approval_transport_error")
			c.resolve(result, ApprovalOutcomeDeny, "approval_transport_error")
			return result, nil
		}
		if vote.Decision != ApprovalEntryAllow && vote.Decision != ApprovalEntryDeny {
			c.appendSystemDeny(result, stage, "malformed_approval_decision")
			c.resolve(result, ApprovalOutcomeDeny, "malformed_approval_decision")
			return result, nil
		}
		if vote.Decision == ApprovalEntryAllow && !stage.authorizes(vote.ApproverIdentity, vote.Roles) {
			vote.Decision = ApprovalEntryDeny
			vote.ReasonCode = "unauthorized_approver"
			if vote.ApproverIdentity == "" {
				vote.ApproverIdentity = "system:unverified-approver"
			}
		}

		entry, err := c.entryFromVote(result, stage, vote)
		if err != nil {
			return nil, err
		}
		result.Entries = append(result.Entries, entry)
		c.log(request.AgentID, "approval_chain_entry:"+binding.Operation, entry.policyDecision())
		if entry.Decision == ApprovalEntryDeny {
			c.resolve(result, ApprovalOutcomeDeny, entry.ReasonCode)
			return result, nil
		}
	}

	if !requiredSeen {
		c.appendSystemDeny(result, ApprovalStage{StageIndex: 0}, "no_required_approval_stage")
		c.resolve(result, ApprovalOutcomeDeny, "no_required_approval_stage")
		return result, nil
	}

	c.resolve(result, ApprovalOutcomeAllow, "approved")
	return result, nil
}

func (c *ApprovalCoordinator) appendSystemDeny(result *ApprovalResult, stage ApprovalStage, reason string) {
	vote := ApprovalVote{
		StageIndex:        stage.StageIndex,
		ApproverKind:      ApproverService,
		ApproverIdentity:  "system:approval-coordinator",
		IdentityAssurance: "system",
		Decision:          ApprovalEntryDeny,
		ReasonCode:        reason,
	}
	entry, err := c.entryFromVote(result, stage, vote)
	if err == nil {
		result.Entries = append(result.Entries, entry)
		c.log(result.Request.AgentID, "approval_chain_entry:"+result.Request.Operation, Deny)
	}
}

func (c *ApprovalCoordinator) entryFromVote(result *ApprovalResult, stage ApprovalStage, vote ApprovalVote) (ApprovalChainEntry, error) {
	inputDigest, err := result.Request.InputDigest()
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
	if len(result.Entries) > 0 {
		previous = result.Entries[len(result.Entries)-1].EntryDigest
	}
	entry := ApprovalChainEntry{
		ApprovalRequestID:   result.Request.ApprovalRequestID,
		ChainEntryID:        vote.ChainEntryID,
		StageIndex:          stage.StageIndex,
		ApproverKind:        kind,
		ApproverIdentity:    vote.ApproverIdentity,
		IdentityAssurance:   assurance,
		Decision:            vote.Decision,
		ReasonCode:          vote.ReasonCode,
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

func (e ApprovalChainEntry) policyDecision() PolicyDecision {
	if e.Decision == ApprovalEntryAllow {
		return Allow
	}
	return Deny
}

func (c *ApprovalCoordinator) resolve(result *ApprovalResult, outcome ApprovalOutcome, reason string) {
	now := c.clock().UTC()
	status := ApprovalDenied
	if outcome == ApprovalOutcomeAllow {
		status = ApprovalAllowed
	}
	if outcome == ApprovalOutcomeExpired {
		status = ApprovalExpired
	}
	result.Request.Status = status

	var finalDigest string
	if len(result.Entries) > 0 {
		finalDigest = result.Entries[len(result.Entries)-1].EntryDigest
	}
	result.Resolution = ApprovalResolution{
		ApprovalResolutionID: newApprovalID("apr"),
		ApprovalRequestID:    result.Request.ApprovalRequestID,
		Outcome:              outcome,
		ActionDigest:         result.Request.ActionDigest,
		PolicyVersion:        result.Request.PolicyVersion,
		ApprovalChainVersion: result.Request.ApprovalChainVersion,
		FinalEntryDigest:     finalDigest,
		ResolvedAt:           now,
		ReasonCode:           reason,
	}
	result.Decision = result.Resolution.PolicyDecision()
	result.Allowed = result.Decision == Allow
	c.log(result.Request.AgentID, "approval_resolved:"+result.Request.Operation, result.Decision)
}

func (c *ApprovalCoordinator) log(agentID, action string, decision PolicyDecision) {
	if c.audit != nil {
		c.audit.Log(agentID, action, decision)
	}
}

// WebhookResponseVerifier verifies the authenticated approver identity in a webhook response.
type WebhookResponseVerifier func(body map[string]interface{}, request ApprovalRequest) (string, bool)

// WebhookApproverOption configures a webhook approval transport.
type WebhookApproverOption func(*WebhookApprover)

// WithWebhookHTTPClient sets the HTTP client used by a webhook approver.
func WithWebhookHTTPClient(client *http.Client) WebhookApproverOption {
	return func(a *WebhookApprover) {
		if client != nil {
			a.client = client
		}
	}
}

// WithWebhookHeaders adds outbound headers to webhook approval requests.
func WithWebhookHeaders(headers map[string]string) WebhookApproverOption {
	return func(a *WebhookApprover) {
		a.headers = make(map[string]string, len(headers))
		for k, v := range headers {
			a.headers[k] = v
		}
	}
}

// WithWebhookResponseVerifier requires approve responses to carry verified identity.
func WithWebhookResponseVerifier(verifier WebhookResponseVerifier) WebhookApproverOption {
	return func(a *WebhookApprover) {
		a.verifier = verifier
	}
}

// WebhookApprover POSTs the versioned approval request contract to an HTTP endpoint.
type WebhookApprover struct {
	url      string
	client   *http.Client
	headers  map[string]string
	verifier WebhookResponseVerifier
}

// NewWebhookApprover creates a versioned, action-bound webhook approval transport.
func NewWebhookApprover(rawURL string, opts ...WebhookApproverOption) (*WebhookApprover, error) {
	if err := validateApprovalWebhookURL(rawURL); err != nil {
		return nil, err
	}
	a := &WebhookApprover{
		url: rawURL,
		client: &http.Client{
			Timeout: 5 * time.Minute,
		},
		headers: make(map[string]string),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// RequestApproval sends the approval request and validates the binding echo.
func (a *WebhookApprover) RequestApproval(ctx context.Context, request ApprovalRequest) (ApprovalVote, error) {
	if a == nil {
		return ApprovalVote{}, errors.New("webhook approver is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	payload, err := buildWebhookApprovalPayload(request)
	if err != nil {
		return ApprovalVote{}, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return ApprovalVote{}, fmt.Errorf("marshalling approval webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(data))
	if err != nil {
		return ApprovalVote{}, fmt.Errorf("creating approval webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range a.headers {
		req.Header.Set(k, v)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return ApprovalVote{}, fmt.Errorf("calling approval webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ApprovalVote{}, fmt.Errorf("approval webhook returned status %d", resp.StatusCode)
	}

	var body map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&body); err != nil {
		return ApprovalVote{}, fmt.Errorf("decoding approval webhook response: %w", err)
	}
	return parseWebhookApprovalResponse(body, request, a.verifier), nil
}

func buildWebhookApprovalPayload(request ApprovalRequest) (map[string]interface{}, error) {
	inputDigest, err := request.InputDigest()
	if err != nil {
		return nil, err
	}
	payload := map[string]interface{}{
		"schema_version": approvalSchemaVersion,
		"type":           "approval_request",
		"input_digest":   inputDigest,
	}
	for k, v := range request.PresentedCanonical() {
		payload[k] = v
	}
	return payload, nil
}

func parseWebhookApprovalResponse(body map[string]interface{}, request ApprovalRequest, verifier WebhookResponseVerifier) ApprovalVote {
	if stringValue(body["approval_request_id"]) != request.ApprovalRequestID {
		return webhookDenyVote("webhook:binding-mismatch", "approval_request_id_mismatch")
	}
	if stringValue(body["action_digest"]) != request.ActionDigest {
		return webhookDenyVote("webhook:binding-mismatch", "action_digest_mismatch")
	}

	approved, ok := approvalResponseDecision(body)
	if !ok {
		return webhookDenyVote("webhook:malformed-response", "missing_or_malformed_decision")
	}
	reason := stringValue(body["reason"])
	if reason == "" {
		if approved {
			reason = "approved"
		} else {
			reason = "denied_by_webhook"
		}
	}

	if !approved {
		identity := stringValue(body["approver"])
		if identity == "" {
			identity = "webhook"
		}
		return ApprovalVote{
			ApproverKind:      approverKindFromString(stringValue(body["approver_kind"])),
			ApproverIdentity:  identity,
			IdentityAssurance: stringOrDefault(body["identity_assurance"], "webhook"),
			Decision:          ApprovalEntryDeny,
			ReasonCode:        reason,
			ChainEntryID:      stringValue(body["chain_entry_id"]),
		}
	}

	var identity string
	var verified bool
	if verifier != nil {
		identity, verified = verifier(body, request)
	}
	if !verified || identity == "" {
		return webhookDenyVote("webhook:unverified-approver", "unverified_approver_identity")
	}

	return ApprovalVote{
		ApproverKind:      approverKindFromString(stringValue(body["approver_kind"])),
		ApproverIdentity:  identity,
		IdentityAssurance: stringOrDefault(body["identity_assurance"], "webhook_verified"),
		Decision:          ApprovalEntryAllow,
		ReasonCode:        reason,
		ChainEntryID:      stringValue(body["chain_entry_id"]),
	}
}

func approvalResponseDecision(body map[string]interface{}) (bool, bool) {
	if approved, ok := body["approved"].(bool); ok {
		return approved, true
	}
	decision := strings.ToLower(stringValue(body["decision"]))
	switch decision {
	case "allow", "approved", "approve":
		return true, true
	case "deny", "denied", "reject", "rejected":
		return false, true
	default:
		return false, false
	}
}

func webhookDenyVote(identity, reason string) ApprovalVote {
	return ApprovalVote{
		ApproverKind:      ApproverService,
		ApproverIdentity:  identity,
		IdentityAssurance: "webhook",
		Decision:          ApprovalEntryDeny,
		ReasonCode:        reason,
	}
}

func approverKindFromString(value string) ApproverKind {
	switch strings.ToLower(value) {
	case string(ApproverHuman):
		return ApproverHuman
	default:
		return ApproverService
	}
}

func stringOrDefault(value interface{}, fallback string) string {
	s := stringValue(value)
	if s == "" {
		return fallback
	}
	return s
}

func stringValue(value interface{}) string {
	s, _ := value.(string)
	return s
}

func validateApprovalWebhookURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid approval webhook URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported approval webhook URL scheme %q", parsed.Scheme)
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return errors.New("approval webhook URL must include a host")
	}
	blockedHosts := map[string]bool{
		"169.254.169.254":          true,
		"metadata.google.internal": true,
	}
	if blockedHosts[host] {
		return fmt.Errorf("approval webhook URL host %q is blocked", host)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLinkLocalUnicast() {
		return fmt.Errorf("approval webhook URL host %q is blocked", host)
	}
	return nil
}

func digestCanonical(value interface{}) (string, error) {
	data, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalJSON(value interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, value interface{}) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case string:
		data, _ := json.Marshal(v)
		buf.Write(data)
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int:
		buf.WriteString(fmt.Sprintf("%d", v))
	case int64:
		buf.WriteString(fmt.Sprintf("%d", v))
	case int32:
		buf.WriteString(fmt.Sprintf("%d", v))
	case uint:
		buf.WriteString(fmt.Sprintf("%d", v))
	case uint64:
		buf.WriteString(fmt.Sprintf("%d", v))
	case uint32:
		buf.WriteString(fmt.Sprintf("%d", v))
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("non-finite number %v cannot be canonicalized", v)
		}
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(data)
	case float32:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("non-finite number %v cannot be canonicalized", v)
		}
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(data)
	case []interface{}:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []string:
		items := make([]interface{}, len(v))
		for i, item := range v {
			items[i] = item
		}
		return writeCanonicalJSON(buf, items)
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyData, _ := json.Marshal(key)
			buf.Write(keyData)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, v[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case map[string]string:
		m := make(map[string]interface{}, len(v))
		for key, item := range v {
			m[key] = item
		}
		return writeCanonicalJSON(buf, m)
	default:
		normalized, err := normalizeJSONValue(value)
		if err != nil {
			return fmt.Errorf("unsupported canonical JSON type %T", value)
		}
		return writeCanonicalJSON(buf, normalized)
	}
	return nil
}

func normalizeJSONValue(value interface{}) (interface{}, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var normalized interface{}
	if err := json.Unmarshal(data, &normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func newApprovalID(prefix string) string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", prefix, time.Now().UnixNano())))
		return prefix + "_" + hex.EncodeToString(sum[:8])
	}
	return prefix + "_" + hex.EncodeToString(random[:])
}
