// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	agentmesh "github.com/microsoft/agent-governance-toolkit/sdks/go"
)

const (
	defaultAddr    = ":8080"
	demoAgentID    = "did:mesh:demo-agent"
	maxRequestBody = 1 << 20
)

var demoHMACKey = []byte("0123456789abcdef0123456789abcdef")

type demoServer struct {
	authenticator   *agentmesh.McpSessionAuthenticator
	gateway         *agentmesh.McpGateway
	perToolLimiter  *agentmesh.McpSlidingRateLimiter
	responseScanner *agentmesh.McpResponseScanner
	redactor        *agentmesh.CredentialRedactor
	signer          *agentmesh.McpMessageSigner
	verifier        *agentmesh.McpMessageSigner
	session         agentmesh.McpSession
	logger          *log.Logger
	mux             *http.ServeMux
}

type toolCallRequest struct {
	SessionToken    string `json:"session_token"`
	ToolName        string `json:"tool_name"`
	ToolDescription string `json:"tool_description"`
	Input           string `json:"input"`
}

type toolCallResponse struct {
	Allowed           bool                     `json:"allowed"`
	Decision          agentmesh.PolicyDecision `json:"decision"`
	Reason            string                   `json:"reason,omitempty"`
	SessionExpiresAt  time.Time                `json:"session_expires_at,omitempty"`
	SanitizedInput    any                      `json:"sanitized_input,omitempty"`
	ToolOutput        any                      `json:"tool_output,omitempty"`
	GovernanceThreats []agentmesh.McpThreat    `json:"governance_threats,omitempty"`
	ResponseThreats   []agentmesh.McpThreat    `json:"response_threats,omitempty"`
	SignatureValid    bool                     `json:"signature_valid"`
}

func newDemoServer(logger *log.Logger) (*demoServer, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	metrics := agentmesh.NewMcpMetrics()
	redactor, err := agentmesh.NewCredentialRedactor(agentmesh.CredentialRedactorConfig{})
	if err != nil {
		return nil, err
	}
	responseScanner, err := agentmesh.NewMcpResponseScanner(agentmesh.McpResponseScannerConfig{
		Redactor: redactor,
		Metrics:  metrics,
	})
	if err != nil {
		return nil, err
	}
	signer, err := agentmesh.NewMcpMessageSigner(agentmesh.McpMessageSignerConfig{Key: demoHMACKey})
	if err != nil {
		return nil, err
	}
	verifier, err := agentmesh.NewMcpMessageSigner(agentmesh.McpMessageSignerConfig{Key: demoHMACKey})
	if err != nil {
		return nil, err
	}
	authenticator, err := agentmesh.NewMcpSessionAuthenticator(agentmesh.McpSessionAuthenticatorConfig{
		SessionTTL:            15 * time.Minute,
		MaxConcurrentSessions: 4,
		MaxCreationsPerWindow: 8,
		CreationWindow:        time.Minute,
	})
	if err != nil {
		return nil, err
	}
	gatewayLimiter, err := agentmesh.NewMcpSlidingRateLimiter(agentmesh.McpSlidingRateLimiterConfig{
		Window:      time.Minute,
		MaxRequests: 6,
		Metrics:     metrics,
	})
	if err != nil {
		return nil, err
	}
	perToolLimiter, err := agentmesh.NewMcpSlidingRateLimiter(agentmesh.McpSlidingRateLimiterConfig{
		Window:      time.Minute,
		MaxRequests: 2,
		Metrics:     metrics,
	})
	if err != nil {
		return nil, err
	}
	gateway, err := agentmesh.NewMcpGateway(agentmesh.McpGatewayConfig{
		Authenticator:   authenticator,
		RateLimiter:     gatewayLimiter,
		ResponseScanner: responseScanner,
		Signer:          signer,
		Policy: agentmesh.McpPolicy{
			AllowPatterns:     []string{"docs.*"},
			BlockOnSeverities: []agentmesh.McpSeverity{agentmesh.McpSeverityCritical},
			DefaultDecision:   agentmesh.Allow,
		},
		Metrics: metrics,
	})
	if err != nil {
		return nil, err
	}
	session, err := authenticator.CreateSession(demoAgentID)
	if err != nil {
		return nil, err
	}

	server := &demoServer{
		authenticator:   authenticator,
		gateway:         gateway,
		perToolLimiter:  perToolLimiter,
		responseScanner: responseScanner,
		redactor:        redactor,
		signer:          signer,
		verifier:        verifier,
		session:         session,
		logger:          logger,
		mux:             http.NewServeMux(),
	}
	server.mux.HandleFunc("/health", server.handleHealth)
	server.mux.HandleFunc("/call-tool", server.handleCallTool)
	return server, nil
}

func (s *demoServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *demoServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":             "ok",
		"demo_agent_id":      s.session.AgentID,
		"session_expires_at": s.session.ExpiresAt.UTC(),
	})
}

func (s *demoServer) handleCallTool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.logger.Printf("request=%s", s.redactor.Redact(string(body)).Sanitized)

	var req toolCallRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json payload"})
		return
	}
	if req.SessionToken == "" || req.ToolName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "session_token and tool_name are required"})
		return
	}
	if req.ToolDescription == "" {
		req.ToolDescription = "Search governance guidance"
	}

	session, err := s.authenticator.ValidateSession(req.SessionToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, toolCallResponse{
			Allowed:  false,
			Decision: agentmesh.Deny,
			Reason:   err.Error(),
		})
		return
	}
	if _, err := s.perToolLimiter.Allow(session.AgentID + ":" + req.ToolName); err != nil {
		writeJSON(w, http.StatusTooManyRequests, toolCallResponse{
			Allowed:          false,
			Decision:         agentmesh.RateLimit,
			Reason:           err.Error(),
			SessionExpiresAt: session.ExpiresAt.UTC(),
		})
		return
	}

	decision, err := s.gateway.InterceptToolCall(agentmesh.McpToolCallRequest{
		AgentID:         session.AgentID,
		SessionToken:    req.SessionToken,
		ToolName:        req.ToolName,
		ToolDescription: req.ToolDescription,
		ToolSchema:      toolSchema(),
		Payload:         map[string]any{"input": req.Input},
	})
	if err != nil {
		writeJSON(w, statusCodeForError(err), toolCallResponse{
			Allowed:           false,
			Decision:          decision.Decision,
			Reason:            decision.Reason,
			SessionExpiresAt:  session.ExpiresAt.UTC(),
			GovernanceThreats: decision.Threats,
		})
		return
	}

	safeInput := extractInput(decision.SanitizedPayload)
	toolOutput := runTool(req.ToolName, safeInput)
	scannedOutput := s.responseScanner.ScanResponse(toolOutput)

	signedOutput, err := s.signer.Sign(agentmesh.McpSignedEnvelope{
		AgentID:  session.AgentID,
		ToolName: req.ToolName,
		Payload:  scannedOutput.Sanitized,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	signatureValid := s.verifier.Verify(signedOutput) == nil
	s.logger.Printf("response=%s", s.redactor.Redact(mustJSON(scannedOutput.Sanitized)).Sanitized)

	writeJSON(w, http.StatusOK, toolCallResponse{
		Allowed:           true,
		Decision:          decision.Decision,
		SessionExpiresAt:  session.ExpiresAt.UTC(),
		SanitizedInput:    decision.SanitizedPayload,
		ToolOutput:        scannedOutput.Sanitized,
		GovernanceThreats: decision.Threats,
		ResponseThreats:   scannedOutput.Threats,
		SignatureValid:    signatureValid,
	})
}

func toolSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"input": map[string]any{
				"type": "string",
			},
		},
		"required": []string{"input"},
	}
}

func runTool(toolName, input string) any {
	switch toolName {
	case "docs.secret-demo":
		return map[string]any{
			"summary":           fmt.Sprintf("Governed answer for %q", input),
			"api_key":           "sk-demo1234567890abcdefghijklmnop",
			"connection_string": "AccountEndpoint=https://demo.example;AccountKey=super-secret",
		}
	default:
		return map[string]any{
			"summary": fmt.Sprintf("Governed answer for %q", input),
			"notes":   "Authenticate sessions, rate limit calls, scan metadata, and sign envelopes.",
		}
	}
}

func extractInput(payload any) string {
	values, ok := payload.(map[string]any)
	if !ok {
		return ""
	}
	input, _ := values["input"].(string)
	return input
}

func statusCodeForError(err error) int {
	switch {
	case errors.Is(err, agentmesh.ErrMcpRateLimited):
		return http.StatusTooManyRequests
	case errors.Is(err, agentmesh.ErrMcpSessionExpired), errors.Is(err, agentmesh.ErrMcpSessionNotFound):
		return http.StatusUnauthorized
	default:
		return http.StatusForbidden
	}
}

func mustJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(data)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func main() {
	logger := log.New(os.Stdout, "mcp-http-server ", log.LstdFlags)
	server, err := newDemoServer(logger)
	if err != nil {
		logger.Fatalf("startup failed: %v", err)
	}

	logger.Printf("listening on %s", defaultAddr)
	fmt.Printf("Demo session token: %s\n", server.session.Token)
	if err := http.ListenAndServe(defaultAddr, server); err != nil {
		logger.Fatalf("server failed: %v", err)
	}
}
