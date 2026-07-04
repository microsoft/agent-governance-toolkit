// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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

	roles := stringSliceValue(body["roles"])
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
			Roles:             roles,
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
		Roles:             roles,
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
	case string(ApproverLLMAdvisory):
		return ApproverLLMAdvisory
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

func stringSliceValue(value interface{}) []string {
	switch v := value.(type) {
	case []string:
		return cloneStrings(v)
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
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
		"fd00:ec2::254":            true,
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
