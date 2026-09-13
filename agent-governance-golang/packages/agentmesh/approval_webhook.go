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

type approvalWebhookLookupIP func(context.Context, string) ([]net.IPAddr, error)
type approvalWebhookDial func(context.Context, string, string) (net.Conn, error)

// WebhookApproverOption configures a webhook approval transport.
type WebhookApproverOption func(*WebhookApprover)

// WithWebhookHTTPClient sets a caller-managed HTTP client used by a webhook approver.
// Callers are responsible for applying equivalent destination validation.
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
		url:     rawURL,
		client:  newApprovalWebhookHTTPClient(nil),
		headers: make(map[string]string),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

func newApprovalWebhookHTTPClient(lookup approvalWebhookLookupIP) *http.Client {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = newApprovalWebhookDialContext(lookup, dialer.DialContext)
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Minute,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func newApprovalWebhookDialContext(lookup approvalWebhookLookupIP, dial approvalWebhookDial) approvalWebhookDial {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid approval webhook address %q: %w", address, err)
		}
		resolved, err := resolveApprovalWebhookIPs(ctx, host, lookup)
		if err != nil {
			return nil, err
		}
		if len(resolved) == 0 {
			return nil, fmt.Errorf("approval webhook host %q resolved to no addresses", host)
		}
		for _, address := range resolved {
			if blockedApprovalWebhookIP(address.IP) {
				return nil, fmt.Errorf("approval webhook host %q resolved to blocked address %q", host, address.String())
			}
		}

		var dialErrors []error
		for _, address := range resolved {
			resolvedHost := address.IP.String()
			if address.Zone != "" {
				resolvedHost += "%" + address.Zone
			}
			pinnedAddress := net.JoinHostPort(resolvedHost, port)
			connection, err := dial(ctx, network, pinnedAddress)
			if err == nil {
				return connection, nil
			}
			dialErrors = append(dialErrors, fmt.Errorf("%s: %w", pinnedAddress, err))
		}
		return nil, fmt.Errorf("dialing approval webhook host %q: %w", host, errors.Join(dialErrors...))
	}
}

func resolveApprovalWebhookIPs(ctx context.Context, host string, lookup approvalWebhookLookupIP) ([]net.IPAddr, error) {
	ipHost := host
	zone := ""
	if zoneIndex := strings.LastIndex(ipHost, "%"); zoneIndex >= 0 {
		zone = ipHost[zoneIndex+1:]
		ipHost = ipHost[:zoneIndex]
	}
	if ip := net.ParseIP(ipHost); ip != nil {
		return []net.IPAddr{{IP: ip, Zone: zone}}, nil
	}
	resolved, err := lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolving approval webhook host %q: %w", host, err)
	}
	return resolved, nil
}

func blockedApprovalWebhookIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, rawIP := range []string{"168.63.129.16", "100.100.100.200"} {
		if ip.Equal(net.ParseIP(rawIP)) {
			return true
		}
	}
	return false
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
	return parseWebhookApprovalResponse(body, request, a.verifier)
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

func parseWebhookApprovalResponse(body map[string]interface{}, request ApprovalRequest, verifier WebhookResponseVerifier) (ApprovalVote, error) {
	if stringValue(body["approval_request_id"]) != request.ApprovalRequestID {
		return ApprovalVote{}, newApprovalProtocolFailure("approval_request_id_mismatch")
	}
	if stringValue(body["action_digest"]) != request.ActionDigest {
		return ApprovalVote{}, newApprovalProtocolFailure("action_digest_mismatch")
	}

	approved, ok := approvalResponseDecision(body)
	if !ok {
		return ApprovalVote{}, newApprovalProtocolFailure("missing_or_malformed_decision")
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
		}, nil
	}

	var identity string
	var verified bool
	if verifier != nil {
		identity, verified = verifier(body, request)
	}
	if !verified || identity == "" {
		return ApprovalVote{}, newApprovalProtocolFailure("unverified_approver_identity")
	}

	return ApprovalVote{
		ApproverKind:      approverKindFromString(stringValue(body["approver_kind"])),
		ApproverIdentity:  identity,
		IdentityAssurance: stringOrDefault(body["identity_assurance"], "webhook_verified"),
		Decision:          ApprovalEntryAllow,
		ReasonCode:        reason,
		Roles:             roles,
		ChainEntryID:      stringValue(body["chain_entry_id"]),
	}, nil
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

type approvalProtocolFailureError struct {
	reasonCode string
}

func newApprovalProtocolFailure(reasonCode string) error {
	return &approvalProtocolFailureError{reasonCode: reasonCode}
}

func (e *approvalProtocolFailureError) Error() string {
	return "approval transport protocol failure: " + e.reasonCode
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
	host := strings.TrimRight(strings.ToLower(parsed.Hostname()), ".")
	if host == "" {
		return errors.New("approval webhook URL must include a host")
	}
	blockedHosts := []string{
		"localhost",
		"metadata.google",
		"metadata.google.internal",
		"169.254.169.254",
		"169.254.170.2",
		"168.63.129.16",
		"100.100.100.200",
		"fd00:ec2::254",
	}
	for _, blockedHost := range blockedHosts {
		if host == blockedHost || strings.HasSuffix(host, "."+blockedHost) {
			return fmt.Errorf("approval webhook URL host %q is blocked", host)
		}
	}
	ipHost := host
	if zone := strings.LastIndex(ipHost, "%"); zone >= 0 {
		ipHost = ipHost[:zone]
	}
	if ip := net.ParseIP(ipHost); ip != nil && blockedApprovalWebhookIP(ip) {
		return fmt.Errorf("approval webhook URL host %q is blocked", host)
	}
	return nil
}
