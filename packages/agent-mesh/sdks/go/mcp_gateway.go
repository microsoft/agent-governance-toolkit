// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"errors"
	"fmt"
	"time"
)

// McpGatewayConfig wires all MCP security gates together.
type McpGatewayConfig struct {
	Authenticator   *McpSessionAuthenticator
	RateLimiter     *McpSlidingRateLimiter
	Scanner         *McpSecurityScanner
	ResponseScanner *McpResponseScanner
	Signer          *McpMessageSigner
	Audit           *AuditLogger
	Policy          McpPolicy
	Metrics         *McpMetrics
}

// McpGateway enforces authentication, rate limits, scanning, signing, and audit logging.
type McpGateway struct {
	authenticator   *McpSessionAuthenticator
	rateLimiter     *McpSlidingRateLimiter
	scanner         *McpSecurityScanner
	responseScanner *McpResponseScanner
	signer          *McpMessageSigner
	audit           *AuditLogger
	policy          McpPolicy
	metrics         *McpMetrics
}

// NewMcpGateway creates a fully wired gateway.
func NewMcpGateway(config McpGatewayConfig) (*McpGateway, error) {
	if config.Metrics == nil {
		config.Metrics = NewMcpMetrics()
	}
	if config.Authenticator == nil {
		authenticator, err := NewMcpSessionAuthenticator(McpSessionAuthenticatorConfig{})
		if err != nil {
			return nil, err
		}
		config.Authenticator = authenticator
	}
	if config.RateLimiter == nil {
		limiter, err := NewMcpSlidingRateLimiter(McpSlidingRateLimiterConfig{Metrics: config.Metrics})
		if err != nil {
			return nil, err
		}
		config.RateLimiter = limiter
	}
	if config.Scanner == nil {
		config.Scanner = NewMcpSecurityScanner(McpSecurityScannerConfig{Metrics: config.Metrics})
	}
	if config.ResponseScanner == nil {
		responseScanner, err := NewMcpResponseScanner(McpResponseScannerConfig{Metrics: config.Metrics})
		if err != nil {
			return nil, err
		}
		config.ResponseScanner = responseScanner
	}
	if config.Signer == nil {
		return nil, fmt.Errorf("%w: gateway signer is required", ErrMcpInvalidConfig)
	}
	if config.Audit == nil {
		config.Audit = NewAuditLogger()
	}
	policy := config.Policy
	if policy.DefaultDecision == "" {
		policy = DefaultMcpPolicy()
	}
	return &McpGateway{
		authenticator:   config.Authenticator,
		rateLimiter:     config.RateLimiter,
		scanner:         config.Scanner,
		responseScanner: config.ResponseScanner,
		signer:          config.Signer,
		audit:           config.Audit,
		policy:          policy,
		metrics:         config.Metrics,
	}, nil
}

// InterceptToolCall enforces auth -> rate-limit -> scan -> sign -> audit with fail-closed semantics.
func (g *McpGateway) InterceptToolCall(request McpToolCallRequest) (decision McpGatewayDecision, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			decision = g.denyDecision(request, Deny, fmt.Sprintf("gateway failed closed: %v", recovered), nil, nil, 0)
			err = fmt.Errorf("%w: gateway panic: %v", ErrMcpFailClosed, recovered)
		}
	}()
	if g == nil {
		return McpGatewayDecision{}, fmt.Errorf("%w: gateway is nil", ErrMcpFailClosed)
	}

	session, err := g.authenticator.ValidateSession(request.SessionToken)
	if err != nil {
		decision = g.denyDecision(request, Deny, err.Error(), nil, nil, 0)
		return decision, err
	}
	agentID := session.AgentID
	if request.AgentID != "" && request.AgentID != session.AgentID {
		err = fmt.Errorf("%w: request agent does not match session", ErrMcpPolicyDenied)
		decision = g.denyDecision(request, Deny, err.Error(), session, nil, 0)
		return decision, err
	}

	rateDecision, rateErr := g.rateLimiter.Allow(agentID)
	if rateErr != nil {
		decisionType := Deny
		if errors.Is(rateErr, ErrMcpRateLimited) {
			decisionType = RateLimit
		}
		decision = g.denyDecision(request, decisionType, rateErr.Error(), session, nil, rateDecision.RetryAfter)
		return decision, rateErr
	}

	threats := g.scanner.ScanTool(request.ToolName, request.ToolDescription, request.ToolSchema)
	responseScan := g.responseScanner.ScanResponse(request.Payload)
	threats = append(threats, responseScan.Threats...)
	policyDecision := g.evaluatePolicy(request.ToolName, threats)
	switch policyDecision {
	case Deny:
		err = ErrMcpPolicyDenied
		decision = g.denyDecision(request, Deny, "policy denied tool call", session, threats, 0)
		return decision, err
	case RequiresApproval:
		err = ErrMcpApprovalRequired
		decision = g.denyDecision(request, RequiresApproval, "policy requires approval", session, threats, 0)
		return decision, err
	}

	signedEnvelope, err := g.signer.Sign(McpSignedEnvelope{
		AgentID:  agentID,
		ToolName: request.ToolName,
		Payload:  responseScan.Sanitized,
	})
	if err != nil {
		decision = g.denyDecision(request, Deny, err.Error(), session, threats, 0)
		return decision, err
	}

	auditEntry := g.audit.Log(agentID, request.ToolName, Allow)
	g.metrics.RecordDecision(Allow)
	return McpGatewayDecision{
		Allowed:          true,
		Decision:         Allow,
		Threats:          threats,
		SanitizedPayload: responseScan.Sanitized,
		SignedEnvelope:   &signedEnvelope,
		Session:          session,
		AuditEntry:       auditEntry,
	}, nil
}

func (g *McpGateway) denyDecision(request McpToolCallRequest, decisionType PolicyDecision, reason string, session *McpSession, threats []McpThreat, retryAfter time.Duration) McpGatewayDecision {
	g.metrics.RecordDecision(decisionType)
	if len(threats) > 0 {
		for _, threat := range threats {
			g.metrics.RecordThreat(threat.Type)
		}
	}
	var agentID string
	if session != nil {
		agentID = session.AgentID
	}
	auditEntry := g.audit.Log(agentID, request.ToolName, decisionType)
	return McpGatewayDecision{
		Allowed:          false,
		Decision:         decisionType,
		Reason:           reason,
		Threats:          threats,
		SanitizedPayload: request.Payload,
		Session:          session,
		AuditEntry:       auditEntry,
		RetryAfter:       retryAfter,
	}
}

func (g *McpGateway) evaluatePolicy(toolName string, threats []McpThreat) PolicyDecision {
	if matchesAnyMcpPattern(g.policy.DenyPatterns, toolName) {
		return Deny
	}
	if !g.policy.AutoApprove && matchesAnyMcpPattern(g.policy.ApprovalPatterns, toolName) {
		return RequiresApproval
	}
	if len(g.policy.AllowPatterns) > 0 && !matchesAnyMcpPattern(g.policy.AllowPatterns, toolName) {
		return Deny
	}
	for _, threat := range threats {
		for _, blockedSeverity := range g.policy.BlockOnSeverities {
			if threat.Severity == blockedSeverity {
				return Deny
			}
		}
	}
	if g.policy.DefaultDecision == "" {
		return Allow
	}
	return g.policy.DefaultDecision
}

func matchesAnyMcpPattern(patterns []string, candidate string) bool {
	for _, patternValue := range patterns {
		if matchMcpPattern(patternValue, candidate) {
			return true
		}
	}
	return false
}
